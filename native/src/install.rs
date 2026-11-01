//! Journaled, rollback-capable installation of authenticated updates.
//!
//! A transaction lives in a private directory next to the target
//! (`<parent>/.buoy-update-<key>-<random>`), so staging and every rename stay on
//! the target's filesystem. The journal is rewritten durably before and after
//! each rename; an interrupted swap is rolled back by `recover`, `prepare` or
//! `rollback`. A per-target lock file serializes prepare, handoff, the helper's
//! swap, rollback and confirmation, but is never held while the new version
//! runs, so health confirmation cannot deadlock against it.
use crate::{core, model::*};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

pub struct InstallOptions {
    pub target: PathBuf,
    /// Relative `/`-separated path of the program to relaunch inside a directory
    /// target, or empty (the binary itself, or a bundle's `CFBundleExecutable`).
    pub executable: String,
    pub arguments: Vec<String>,
}

/// Process plus a start-time identity, so a reused PID is not mistaken for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub identity: u64,
}
impl Process {
    pub fn current() -> Result<Process> {
        let pid = std::process::id();
        let identity = lookup_identity(pid)?
            .filter(|id| *id != 0)
            .ok_or("cannot capture updater process identity")?;
        Ok(Process { pid, identity })
    }
    pub fn parse(text: &str) -> Result<Process> {
        let (pid, id) = text
            .split_once(':')
            .ok_or("process must be <pid>:<identity>")?;
        Ok(Process {
            pid: pid.parse().map_err(|_| "invalid process id")?,
            identity: id.parse().map_err(|_| "invalid process identity")?,
        })
    }
    pub fn alive(&self) -> bool {
        process_running(self).unwrap_or(true)
    }
}
impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.pid, self.identity)
    }
}

/// Arguments the host passes to the detached helper's `apply` command.
pub struct HelperRequest {
    pub transaction: PathBuf,
    pub seal: String,
    pub nonce: String,
    pub parent: Process,
}

/// Environment variable set on a relaunched program, naming the transaction
/// it should `confirm` (or `rollback`) after its own health check.
pub const TRANSACTION_ENV: &str = "BUOY_UPDATE_TRANSACTION";

const PREFIX: &str = ".buoy-update-";
const JOURNAL: &str = "journal.json";
const JOURNAL_TMP: &str = "journal.tmp";
const PAYLOAD: &str = "payload";
const STAGE: &str = "stage";
const BUNDLE_STAGE: &str = "stage.app";
const BACKUP: &str = "backup";
const REJECTED: &str = "rejected";
const HELPER: &str = if cfg!(windows) {
    "buoy-update-helper.exe"
} else {
    "buoy-update-helper"
};
const MAX_ENTRIES: usize = 100_000;
const MAX_EXPANDED: u64 = 8 << 30;
const MAX_PATH: usize = 1024;
const MAX_DEPTH: usize = 64;
const MAX_JOURNAL: u64 = 16 << 20;
const MAX_ARGUMENTS: usize = 256;
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);
const PARENT_TIMEOUT: Duration = Duration::from_secs(600);
#[cfg(windows)]
const RENAME_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    File,
    Directory,
    Bundle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared,
    HandingOff,
    Accepted,
    MovingOriginal,
    OriginalMoved,
    Applied,
    RollingBack,
    RolledBack,
    Failed,
    Confirmed,
}
impl State {
    fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }
}
/// Immutable part of the journal. Its SHA-256 (the seal) travels to the helper
/// on the command line, so the helper re-verifies with the pinned key from
/// prepare rather than whatever the transaction directory later contains.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    config: Config,
    selection: Selection,
    target: String,
    kind: Kind,
    executable: String,
    arguments: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u32,
    sealed: Sealed,
    state: State,
    #[serde(default)]
    launch: Option<String>,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    relaunch: bool,
    #[serde(default)]
    helper: Option<Process>,
    #[serde(default)]
    error: String,
}

// Seals of transactions prepared by this process: handoff refuses anything else.
static SEALS: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());

fn seal(sealed: &Sealed) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(sealed).map_err(|e| e.to_string())?,
    )))
}
fn io_err(context: &str) -> impl Fn(io::Error) -> String + '_ {
    move |e| format!("{context}: {e}")
}

// ---------------------------------------------------------------------------
// Target and transaction locations

struct Location {
    path: PathBuf,
    parent: PathBuf,
    key: String,
}
impl Location {
    fn prefix(&self) -> String {
        format!("{PREFIX}{}-", self.key)
    }
    fn lock_path(&self) -> PathBuf {
        self.parent.join(format!("{PREFIX}{}.lock", self.key))
    }
}

fn location(target: &Path) -> Result<Location> {
    let text = target.to_str().ok_or("target path must be valid Unicode")?;
    if text.contains("/AppTranslocation/") {
        return Err(
            "translocated apps must be moved to their installed location before updating".into(),
        );
    }
    if std::env::var_os("FLATPAK_ID").is_some()
        || std::env::var_os("SNAP").is_some()
        || std::env::var_os("APP_SANDBOX_CONTAINER_ID").is_some()
    {
        return Err("managed or sandboxed apps require their distribution platform updater".into());
    }
    // Validate the original spelling too: verbatim Windows path handling
    // differs from ordinary paths. Never let a raw parent segment reach Win32.
    #[cfg(windows)]
    if text.split(['\\', '/']).any(|part| part == "..") {
        return Err("target path must not contain parent traversal".into());
    }
    if !target.is_absolute() {
        return Err("target path must be absolute".into());
    }
    for component in target.components() {
        match component {
            Component::ParentDir | Component::CurDir => {
                return Err("target path must be normalized".into())
            }
            #[cfg(windows)]
            Component::Prefix(prefix) => match prefix.kind() {
                std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_) => {}
                _ => return Err("target must be on a local drive".into()),
            },
            _ => {}
        }
    }
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("target has no file name")?;
    if name.starts_with(PREFIX) {
        return Err("target is an updater transaction".into());
    }
    let parent = target.parent().ok_or("target has no parent")?;
    if parent.parent().is_none() {
        return Err("target must not be a filesystem root or directly under one".into());
    }
    #[cfg(unix)]
    let mut private_prefix = false;
    for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| "target parent does not exist")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("target path must not contain symbolic links or junctions".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mode = metadata.permissions().mode();
            if !private_prefix && mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err("target ancestors must not be writable by other users without sticky protection".into());
            }
            private_prefix |= metadata.uid() == unsafe { libc::geteuid() } && mode & 0o077 == 0;
        }
    }
    if fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("target must not be a symbolic link".into());
    }
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| "cannot canonicalize target parent")?;
    let canonical = if exists(target) {
        fs::canonicalize(target).map_err(|_| "cannot canonicalize target")?
    } else {
        canonical_parent.join(name)
    };
    let text = canonical
        .to_str()
        .ok_or("target path must be valid Unicode")?;
    // Case-insensitive filesystems are the default on macOS and Windows: fold
    // the lock key so differently-cased spellings share one lock.
    let folded = if cfg!(any(windows, target_os = "macos")) {
        text.to_lowercase()
    } else {
        text.to_string()
    };
    Ok(Location {
        path: canonical,
        parent: canonical_parent,
        key: hex::encode(&Sha256::digest(folded.as_bytes())[..12]),
    })
}

fn validate_target(target: &Path) -> Result<(Location, Kind)> {
    let location = location(target)?;
    let metadata = fs::symlink_metadata(target).map_err(|_| "target does not exist")?;
    let kind = if metadata.file_type().is_symlink() {
        return Err("target must not be a symbolic link".into());
    } else if metadata.is_file() {
        Kind::File
    } else if metadata.is_dir() {
        let bundle = cfg!(target_os = "macos")
            && target
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("app"));
        if bundle {
            Kind::Bundle
        } else {
            Kind::Directory
        }
    } else {
        return Err("target must be a regular file or directory".into());
    };
    #[cfg(unix)]
    {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(
                "target must be owned by the current user (no elevation is performed)".into(),
            );
        }
        for path in [target, location.parent.as_path()] {
            let c = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| "invalid target path")?;
            if unsafe { libc::access(c.as_ptr(), libc::W_OK) } != 0 {
                return Err("target and its parent must be writable by the current user".into());
            }
        }
    }
    #[cfg(windows)]
    if metadata.permissions().readonly() && kind == Kind::File {
        return Err("target is read-only".into());
    }
    Ok((location, kind))
}

struct TargetLock(#[allow(dead_code)] File);
fn lock(location: &Location, timeout: Duration) -> Result<TargetLock> {
    let path = location.lock_path();
    #[cfg(not(windows))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&path)
            .map_err(io_err("cannot open the update lock"))?;
        file
    };
    #[cfg(windows)]
    let file = crate::security_windows::open_lock(&path)?;
    if !file
        .metadata()
        .map_err(io_err("cannot stat the update lock"))?
        .is_file()
    {
        return Err("update lock is not a regular file".into());
    }
    require_private(&path, false)?;
    let deadline = Instant::now() + timeout;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(TargetLock(file)),
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            Err(_) => return Err("another update operation holds the target lock".into()),
        }
    }
}

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(io_err("cannot sync update directory"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn sync_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(io_err("cannot stat staged path"))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(io_err("cannot scan stage"))? {
            sync_tree(&entry.map_err(io_err("cannot scan stage"))?.path())?;
        }
        sync_dir(path)?;
    } else {
        // FlushFileBuffers requires GENERIC_WRITE on Windows. A read-only
        // handle happens to suffice for fsync on Unix, but not for Windows.
        OpenOptions::new()
            .read(true)
            .write(cfg!(windows))
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(io_err("cannot sync staged file"))?;
    }
    Ok(())
}

fn require_private(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "private updater path is missing")?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err("updater path has an unsafe file type".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("updater paths must be owned by the current user and private".into());
        }
    }
    #[cfg(windows)]
    crate::security_windows::validate_private(path)?;
    Ok(())
}
fn read_journal(transaction: &Path) -> Result<Journal> {
    require_private(transaction, true)?;
    require_private(&transaction.join(JOURNAL), false)?;
    let file = core::open_regular(&transaction.join(JOURNAL))
        .map_err(|_| "transaction journal not found")?;
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read transaction journal")?;
    if bytes.len() as u64 > MAX_JOURNAL {
        return Err("transaction journal too large".into());
    }
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|_| "corrupt transaction journal")?;
    if journal.format != 1 {
        return Err("unsupported transaction journal".into());
    }
    Ok(journal)
}
fn write_journal(transaction: &Path, journal: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|e| e.to_string())?;
    let temporary = transaction.join(JOURNAL_TMP);
    let _ = fs::remove_file(&temporary);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(&temporary)
        .map_err(io_err("cannot write transaction journal"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(io_err("cannot write transaction journal"))?;
    drop(file);
    fs::rename(&temporary, transaction.join(JOURNAL))
        .map_err(io_err("cannot commit transaction journal"))?;
    sync_dir(transaction)?;
    Ok(())
}
fn set_state(transaction: &Path, journal: &mut Journal, state: State) -> Result<()> {
    journal.state = state;
    write_journal(transaction, journal)
}

/// Validate a caller-supplied transaction path and bind it to its target.
fn open_transaction(transaction: &Path) -> Result<(Journal, Location)> {
    if !transaction.is_absolute() || transaction.to_str().is_none() {
        return Err("transaction path must be absolute Unicode".into());
    }
    require_private(transaction, true)?;
    let metadata = fs::symlink_metadata(transaction).map_err(|_| "transaction not found")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("transaction must be a directory".into());
    }
    let journal = read_journal(transaction)?;
    let location = location(Path::new(&journal.sealed.target))?;
    let name = transaction
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if transaction.parent() != Some(location.parent.as_path())
        || !name.starts_with(&location.prefix())
    {
        return Err("transaction does not belong to its recorded target".into());
    }
    Ok((journal, location))
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}
#[allow(clippy::never_loop)] // retries only on Windows
fn rename(from: &Path, to: &Path) -> Result<()> {
    if exists(to) {
        return Err(format!(
            "rename destination already exists: {}",
            to.display()
        ));
    }
    #[cfg(windows)]
    let deadline = Instant::now() + RENAME_RETRY;
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            // Running images, antivirus scanners and indexers hold transient
            // sharing locks on Windows: retry for a bounded time.
            #[cfg(windows)]
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(250)),
            Err(e) => {
                return Err(format!(
                    "cannot move {} to {}: {e}",
                    from.display(),
                    to.display()
                ))
            }
        }
    }
}
/// Remove a tree without following links, restoring owner write permission
/// first so read-only directories and files do not block cleanup.
fn remove_tree(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o700 != 0o700 {
                fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
            }
        }
        for entry in fs::read_dir(path)? {
            remove_tree(&entry?.path())?;
        }
        fs::remove_dir(path)
    } else {
        #[cfg(windows)]
        if metadata.permissions().readonly() && !metadata.file_type().is_symlink() {
            let mut permissions = metadata.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions)?;
        }
        fs::remove_file(path)
    }
}
/// Remove a finished transaction. The backup is deleted only after an explicit
/// confirmation; any other state with a backup present keeps the journal.
fn cleanup(transaction: &Path, state: State) {
    for name in [PAYLOAD, STAGE, BUNDLE_STAGE, REJECTED, JOURNAL_TMP, HELPER] {
        let _ = remove_tree(&transaction.join(name));
    }
    if state == State::Confirmed {
        if remove_tree(&transaction.join(BACKUP)).is_err() {
            return;
        }
    } else if exists(&transaction.join(BACKUP)) {
        return;
    }
    if fs::remove_file(transaction.join(JOURNAL)).is_ok() || !exists(&transaction.join(JOURNAL)) {
        let _ = remove_tree(transaction);
    }
}

// ---------------------------------------------------------------------------
// Authentication and archive validation

/// Re-verify the signed envelope and that the selected asset is a member of
/// an eligible release in it.
fn native_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        value => value,
    }
}
fn authenticate(config: &Config, selection: &Selection) -> Result<()> {
    if config.platform != std::env::consts::OS || config.arch != native_arch() {
        return Err("installation platform and architecture must match the running host".into());
    }
    let canonical = core::select(config, &selection.envelope)?
        .ok_or("selection is not an eligible authenticated update")?;
    if serde_json::to_value(&canonical).map_err(|e| e.to_string())?
        != serde_json::to_value(selection).map_err(|e| e.to_string())?
    {
        return Err("asset is not the selected authenticated update".into());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Raw,
    Zip,
    TarGz,
}
fn format(asset: &Asset) -> Result<Format> {
    let format = match asset.format.as_str() {
        "raw" | "binary" => Format::Raw,
        "zip" => Format::Zip,
        "tar.gz" | "tgz" => Format::TarGz,
        _ => return Err("unsupported asset format (use raw, zip or tar.gz)".into()),
    };
    if format == Format::Raw && !asset.entry.is_empty() {
        return Err("raw assets cannot name an archive entry".into());
    }
    Ok(format)
}

fn valid_component(c: &str) -> Result<()> {
    let stem = c
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if c.is_empty()
        || c == "."
        || c == ".."
        || c.len() > 255
        || c.ends_with('.')
        || c.ends_with(' ')
        || reserved
        || c.chars()
            .any(|ch| (ch as u32) < 0x20 || ch == '\u{7f}' || "<>:\"/\\|?*".contains(ch))
    {
        return Err(format!("unsafe or non-portable path component {c:?}"));
    }
    Ok(())
}
/// Split an archive member name into validated components; empty means root.
fn split_entry(name: &str) -> Result<Vec<String>> {
    if name.is_empty()
        || name.len() > MAX_PATH
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(format!("unsafe archive path {name:?}"));
    }
    let mut components = Vec::new();
    for c in name.strip_suffix('/').unwrap_or(name).split('/') {
        if c == "." {
            continue;
        }
        valid_component(c).map_err(|e| format!("{e} in archive path {name:?}"))?;
        components.push(c.to_string());
    }
    if components.len() > MAX_DEPTH {
        return Err("archive path too deep".into());
    }
    Ok(components)
}
fn relative(path: &str) -> Result<Vec<String>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let parts = split_entry(path)?;
    if parts.is_empty() {
        return Err(format!("invalid relative path {path:?}"));
    }
    Ok(parts)
}
/// Links are allowed only as `../`* followed by plain names, with no more
/// `..` than the link's depth below the installed root. Because no `..` may
/// follow a name, a chain of such links can never climb out of the root.
fn check_link(target: &str, depth: usize) -> Result<()> {
    if target.is_empty()
        || target.len() > MAX_PATH
        || target.starts_with('/')
        || target.contains('\\')
        || target.contains('\0')
    {
        return Err(format!("unsafe symbolic link target {target:?}"));
    }
    let mut ups = 0;
    let mut descended = false;
    for c in target.strip_suffix('/').unwrap_or(target).split('/') {
        match c {
            "." => {}
            ".." if !descended => ups += 1,
            ".." => return Err(format!("symbolic link target {target:?} is not confined")),
            _ => {
                valid_component(c)?;
                descended = true;
            }
        }
    }
    if ups > depth {
        return Err(format!(
            "symbolic link target {target:?} escapes the update"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Node {
    Dir,
    File,
    Link,
}
struct CancelRead<'a, R> {
    inner: R,
    cancel: &'a Arc<AtomicBool>,
}
impl<R: Read> Read for CancelRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        cancelled(self.cancel).map_err(io::Error::other)?;
        self.inner.read(buf)
    }
}
#[cfg(unix)]
fn file_mode(mode: Option<u32>) -> u32 {
    // Keep execute bits; never setuid/setgid/sticky or group/other write.
    mode.map_or(0o644, |m| (m & 0o755) | 0o600)
}
#[cfg(unix)]
fn dir_mode(mode: Option<u32>) -> u32 {
    mode.map_or(0o755, |m| (m & 0o755) | 0o700)
}

fn create_stage_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

/// Streams archive members into the stage, keeping only the selected entry.
struct Extractor<'a> {
    stage: PathBuf,
    entry: Vec<String>,
    cancel: &'a Arc<AtomicBool>,
    count: usize,
    bytes: u64,
    seen: HashMap<String, (String, Node)>,
    created: HashSet<Vec<String>>,
    root: Option<Node>,
    dir_modes: Vec<(PathBuf, Option<u32>)>,
    links: Vec<(PathBuf, String)>,
}
impl<'a> Extractor<'a> {
    fn new(stage: PathBuf, entry: &str, cancel: &'a Arc<AtomicBool>) -> Result<Self> {
        Ok(Extractor {
            stage,
            entry: relative(entry)?,
            cancel,
            count: 0,
            bytes: 0,
            seen: HashMap::new(),
            created: HashSet::new(),
            root: None,
            dir_modes: Vec::new(),
            links: Vec::new(),
        })
    }
    fn root_dir(&mut self) -> Result<()> {
        match self.root {
            Some(Node::Dir) => Ok(()),
            Some(_) => Err("archive entry is not a directory".into()),
            None => {
                create_stage_directory(&self.stage).map_err(io_err("cannot create stage"))?;
                self.root = Some(Node::Dir);
                Ok(())
            }
        }
    }
    fn dir(&mut self, rel: &[String]) -> Result<()> {
        if self.created.contains(rel) {
            return Ok(());
        }
        let path = rel.iter().fold(self.stage.clone(), |p, c| p.join(c));
        // create_dir fails on anything already present, including names that
        // collide only under the filesystem's Unicode normalization.
        create_stage_directory(&path).map_err(|e| {
            format!(
                "colliding or unwritable archive path {}: {e}",
                rel.join("/")
            )
        })?;
        self.created.insert(rel.to_vec());
        Ok(())
    }
    fn add(
        &mut self,
        name: &str,
        node: Node,
        mode: Option<u32>,
        data: &mut dyn Read,
        link: Option<&str>,
    ) -> Result<()> {
        cancelled(self.cancel)?;
        self.count += 1;
        if self.count > MAX_ENTRIES {
            return Err("archive has too many entries".into());
        }
        let components = split_entry(name)?;
        if components.is_empty() {
            return if node == Node::Dir {
                Ok(())
            } else {
                Err("archive root must be a directory".into())
            };
        }
        for i in 1..=components.len() {
            let exact = components[..i].join("/");
            let this = if i == components.len() {
                node
            } else {
                Node::Dir
            };
            match self.seen.get(&exact.to_lowercase()) {
                Some((seen, kind)) if *seen == exact && *kind == Node::Dir && this == Node::Dir => {
                }
                Some(_) => {
                    return Err(format!(
                        "duplicate or case-colliding archive path {exact:?}"
                    ))
                }
                None => {
                    self.seen.insert(exact.to_lowercase(), (exact, this));
                }
            }
        }
        if components.len() < self.entry.len() || components[..self.entry.len()] != self.entry[..] {
            return Ok(()); // validated, but outside the selected entry
        }
        let rel = components[self.entry.len()..].to_vec();
        let path = rel.iter().fold(self.stage.clone(), |p, c| p.join(c));
        if rel.is_empty() && node == Node::Link {
            return Err("selected archive entry must not be a symbolic link".into());
        }
        if !rel.is_empty() {
            self.root_dir()?;
            for i in 1..rel.len() {
                self.dir(&rel[..i])?;
            }
        }
        match node {
            Node::Dir => {
                if rel.is_empty() {
                    self.root_dir()?
                } else {
                    self.dir(&rel)?
                }
                self.dir_modes.push((path, mode));
            }
            Node::File => {
                if rel.is_empty() {
                    if self.root.is_some() {
                        return Err("selected archive entry is duplicated".into());
                    }
                    self.root = Some(Node::File);
                }
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                let mut file = options.open(&path).map_err(|e| {
                    format!(
                        "colliding or unwritable archive path {}: {e}",
                        rel.join("/")
                    )
                })?;
                let remaining = MAX_EXPANDED - self.bytes;
                let mut reader = CancelRead {
                    inner: data.take(remaining + 1),
                    cancel: self.cancel,
                };
                let written = io::copy(&mut reader, &mut file).map_err(|e| {
                    if e.to_string() == "cancelled" {
                        "cancelled".to_string()
                    } else {
                        format!("cannot extract archive: {e}")
                    }
                })?;
                if written > remaining {
                    return Err("archive expands beyond the size limit".into());
                }
                self.bytes += written;
                file.sync_all()
                    .map_err(io_err("cannot flush extracted file"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(file_mode(mode)))
                        .map_err(io_err("cannot set file mode"))?;
                }
            }
            Node::Link => {
                let target = link.ok_or("symbolic link has no target")?;
                check_link(target, rel.len() - 1)?;
                if cfg!(windows) {
                    return Err("archives with symbolic links are not supported on Windows".into());
                }
                self.links.push((path, target.to_string()));
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.root.is_none() {
            return Err("archive entry not found".into());
        }
        // Links are created last so no extracted member is ever written through one.
        #[cfg(unix)]
        for (path, target) in &self.links {
            std::os::unix::fs::symlink(target, path)
                .map_err(io_err("cannot create symbolic link"))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut modes = HashMap::new();
            if self.root == Some(Node::Dir) {
                modes.insert(self.stage.clone(), None);
            }
            for rel in &self.created {
                modes.insert(
                    rel.iter()
                        .fold(self.stage.clone(), |path, part| path.join(part)),
                    None,
                );
            }
            for (path, mode) in self.dir_modes {
                modes.insert(path, mode);
            }
            let mut dir_modes: Vec<_> = modes.into_iter().collect();
            dir_modes.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
            for (path, mode) in &dir_modes {
                fs::set_permissions(path, fs::Permissions::from_mode(dir_mode(*mode)))
                    .map_err(io_err("cannot set directory mode"))?;
            }
        }
        Ok(())
    }
}

/// Bound every decompressed tar byte, including skipped members and metadata.
struct ArchiveRead<'a, R> {
    inner: R,
    remaining: u64,
    cancel: &'a Arc<AtomicBool>,
}
impl<R: Read> Read for ArchiveRead<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        cancelled(self.cancel).map_err(io::Error::other)?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut extra = [0u8; 1];
            if self.inner.read(&mut extra)? == 0 {
                return Ok(0);
            }
            return Err(io::Error::other("archive expands beyond the size limit"));
        }
        let limit = output.len().min(self.remaining as usize);
        let count = self.inner.read(&mut output[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}
fn extract_tar(file: File, extractor: &mut Extractor) -> Result<()> {
    let decoded = flate2::read::MultiGzDecoder::new(BufReader::new(file));
    let bounded = ArchiveRead {
        inner: decoded,
        remaining: MAX_EXPANDED + MAX_ENTRIES as u64 * 1024,
        cancel: extractor.cancel,
    };
    let mut archive = tar::Archive::new(bounded);
    // Raw iteration prevents tar from allocating unbounded GNU/PAX metadata
    // before our checks. Apply bounded path/link extensions ourselves.
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    let mut pax: Option<HashMap<String, String>> = None;
    let mut declared = 0u64;
    let mut entries = 0usize;
    for entry in archive
        .entries()
        .map_err(|_| "invalid tar.gz archive")?
        .raw(true)
    {
        cancelled(extractor.cancel)?;
        let mut entry = entry.map_err(|_| "invalid or oversized tar.gz archive")?;
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err("archive has too many entries".into());
        }
        let kind = entry.header().entry_type();
        let size = entry.size();
        declared = declared.checked_add(size).ok_or("archive size overflow")?;
        if declared > MAX_EXPANDED {
            return Err("archive expands beyond the size limit".into());
        }
        if kind.is_gnu_longname()
            || kind.is_gnu_longlink()
            || kind.is_pax_local_extensions()
            || kind.is_pax_global_extensions()
        {
            if size > 65536 {
                return Err("tar metadata is too large".into());
            }
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|_| "invalid tar metadata")?;
            if kind.is_gnu_longname() || kind.is_gnu_longlink() {
                if data.len() > MAX_PATH + 1 {
                    return Err("tar path is too long".into());
                }
                if data.last() == Some(&0) {
                    data.pop();
                }
                let value = String::from_utf8(data).map_err(|_| "tar path is not UTF-8")?;
                let destination = if kind.is_gnu_longname() {
                    &mut long_name
                } else {
                    &mut long_link
                };
                if destination.replace(value).is_some() {
                    return Err("duplicate tar path extension".into());
                }
            } else {
                let mut values = HashMap::new();
                for extension in tar::PaxExtensions::new(&data) {
                    let extension = extension.map_err(|_| "invalid PAX metadata")?;
                    let key = extension.key().map_err(|_| "invalid PAX key")?;
                    let value = extension.value().map_err(|_| "invalid PAX value")?;
                    if key.starts_with("GNU.sparse.")
                        || values.insert(key.to_string(), value.to_string()).is_some()
                    {
                        return Err("unsupported or duplicate PAX metadata".into());
                    }
                }
                if kind.is_pax_global_extensions() {
                    if ["path", "linkpath", "size"]
                        .iter()
                        .any(|key| values.contains_key(*key))
                    {
                        return Err("global PAX path/size overrides are unsupported".into());
                    }
                } else if pax.replace(values).is_some() {
                    return Err("duplicate PAX header".into());
                }
            }
            continue;
        }
        let node = match kind {
            tar::EntryType::Regular | tar::EntryType::Continuous => Node::File,
            tar::EntryType::Directory => Node::Dir,
            tar::EntryType::Symlink => Node::Link,
            _ => return Err("archive contains hard links or special files".into()),
        };
        let mut metadata = pax.take().unwrap_or_default();
        if let Some(value) = metadata.remove("size") {
            if value.parse::<u64>().ok() != Some(size) {
                return Err("PAX size must match the tar member header".into());
            }
        }
        let name = metadata.remove("path").or(long_name.take()).unwrap_or(
            String::from_utf8(entry.path_bytes().into_owned())
                .map_err(|_| "archive path is not UTF-8")?,
        );
        let raw_link = entry
            .link_name_bytes()
            .map(|bytes| {
                String::from_utf8(bytes.into_owned()).map_err(|_| "link target is not UTF-8")
            })
            .transpose()?;
        let link = metadata
            .remove("linkpath")
            .or(long_link.take())
            .or(raw_link);
        if node != Node::Link && link.is_some() {
            return Err("non-symlink member has a link target".into());
        }
        let mode = entry.header().mode().ok();
        extractor.add(&name, node, mode, &mut entry, link.as_deref())?;
    }
    if long_name.is_some() || long_link.is_some() || pax.is_some() {
        return Err("tar extension has no following member".into());
    }
    Ok(())
}
fn extract_zip(file: File, extractor: &mut Extractor) -> Result<()> {
    let mut archive =
        zip::ZipArchive::new(BufReader::new(file)).map_err(|_| "invalid zip archive")?;
    if archive.len() > MAX_ENTRIES {
        return Err("archive has too many entries".into());
    }
    let mut declared = 0u64;
    for i in 0..archive.len() {
        let mut member = archive
            .by_index(i)
            .map_err(|e| format!("unsupported zip member: {e}"))?;
        declared = declared
            .checked_add(member.size())
            .ok_or("archive size overflow")?;
        if declared > MAX_EXPANDED {
            return Err("archive expands beyond the size limit".into());
        }
        let name = member
            .name()
            .map_err(|_| "invalid zip member name")?
            .into_owned();
        let mode = member.unix_mode();
        let node = match mode.map(|m| m & 0o170000) {
            None | Some(0) => {
                if name.ends_with('/') {
                    Node::Dir
                } else {
                    Node::File
                }
            }
            Some(0o040000) => Node::Dir,
            Some(0o100000) => Node::File,
            Some(0o120000) => Node::Link,
            Some(_) => return Err("archive contains special files".into()),
        };
        if node != Node::Dir && name.ends_with('/') {
            return Err("archive member type does not match its name".into());
        }
        if node == Node::Link {
            let mut target = String::new();
            (&mut member)
                .take(MAX_PATH as u64 + 1)
                .read_to_string(&mut target)
                .map_err(|_| "invalid link target")?;
            extractor.add(&name, node, mode, &mut io::empty(), Some(&target))?;
        } else {
            extractor.add(&name, node, mode, &mut member, None)?;
        }
    }
    Ok(())
}

fn hash_handle(file: &mut File, asset: &Asset, cancel: &Arc<AtomicBool>) -> Result<()> {
    let expected = hex::decode(&asset.sha256).map_err(|_| "invalid SHA-256 hex")?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot read payload")?;
    let mut hash = Sha256::new();
    let mut reader = CancelRead {
        inner: (&mut *file).take(asset.size + 1),
        cancel,
    };
    let total = io::copy(&mut reader, &mut hash).map_err(|e| e.to_string())?;
    if total != asset.size || hash.finalize().as_slice() != expected.as_slice() {
        return Err("payload size or SHA-256 mismatch".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot read payload")?;
    Ok(())
}

fn resolve(root: &Path, rel: &[String]) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for c in rel {
        path.push(c);
        if fs::symlink_metadata(&path)
            .map_err(|_| "relaunch executable not found")?
            .file_type()
            .is_symlink()
        {
            return Err("relaunch executable path must not contain symbolic links".into());
        }
    }
    Ok(path)
}
fn check_executable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "relaunch executable not found")?;
    if !metadata.is_file() {
        return Err("relaunch executable must be a regular file".into());
    }
    #[cfg(unix)]
    if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o100 == 0 {
        return Err("relaunch executable is not executable".into());
    }
    Ok(())
}

fn stage_path(transaction: &Path, kind: Kind) -> PathBuf {
    transaction.join(if kind == Kind::Bundle {
        BUNDLE_STAGE
    } else {
        STAGE
    })
}
/// Verify the private payload by handle and (re)extract a fresh stage from it.
/// Returns the relative program to relaunch, `Some("")` for the target itself.
fn stage(sealed: &Sealed, transaction: &Path, cancel: &Arc<AtomicBool>) -> Result<Option<String>> {
    let asset = &sealed.selection.asset;
    let format = format(asset)?;
    let staged = stage_path(transaction, sealed.kind);
    remove_tree(&staged).map_err(io_err("cannot clear stage"))?;
    let mut payload = core::open_regular(&transaction.join(PAYLOAD))
        .map_err(|_| "transaction payload missing")?;
    hash_handle(&mut payload, asset, cancel)?;
    let target = Path::new(&sealed.target);
    match format {
        Format::Raw => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            let mut output = options
                .open(&staged)
                .map_err(io_err("cannot create stage"))?;
            let mut reader = CancelRead {
                inner: (&mut payload).take(asset.size),
                cancel,
            };
            io::copy(&mut reader, &mut output).map_err(|e| e.to_string())?;
            output.sync_all().map_err(io_err("cannot flush stage"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::symlink_metadata(target)
                    .map(|m| m.permissions().mode())
                    .unwrap_or(0o755);
                output
                    .set_permissions(fs::Permissions::from_mode(file_mode(Some(mode))))
                    .map_err(io_err("cannot set stage mode"))?;
            }
        }
        Format::Zip | Format::TarGz => {
            let mut extractor = Extractor::new(staged.clone(), &asset.entry, cancel)?;
            if format == Format::Zip {
                extract_zip(payload, &mut extractor)?
            } else {
                extract_tar(payload, &mut extractor)?
            }
            extractor.finish()?;
        }
    }
    cancelled(cancel)?;
    let metadata = fs::symlink_metadata(&staged).map_err(|_| "stage missing")?;
    let staged_kind = if metadata.is_file() {
        Kind::File
    } else if metadata.is_dir() {
        Kind::Directory
    } else {
        Kind::File
    };
    if (sealed.kind == Kind::File) != (staged_kind == Kind::File)
        || metadata.file_type().is_symlink()
    {
        return Err(
            "update type does not match the installed target (file versus directory)".into(),
        );
    }
    let executable = relative(&sealed.executable)?;
    let launch = match sealed.kind {
        Kind::File if executable.is_empty() => Some(String::new()),
        Kind::File => return Err("a single-file target cannot name a relaunch executable".into()),
        Kind::Directory if executable.is_empty() => None,
        Kind::Directory => Some(sealed.executable.clone()),
        Kind::Bundle => {
            let bundle_executable = bundle_check(&sealed.config, &staged, target)?;
            Some(if executable.is_empty() {
                format!("Contents/MacOS/{bundle_executable}")
            } else {
                sealed.executable.clone()
            })
        }
    };
    if let Some(rel) = &launch {
        check_executable(&resolve(&staged, &relative(rel)?)?)?;
    }
    sync_tree(&staged)?;
    Ok(launch)
}

#[cfg(target_os = "macos")]
fn tool(program: &str, args: &[&std::ffi::OsStr]) -> Result<(bool, String)> {
    let output = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text))
}
/// The staged bundle must carry `config.app_id` and satisfy the installed
/// bundle's designated code requirement (same identifier and signing team).
#[cfg(target_os = "macos")]
fn bundle_check(config: &Config, staged: &Path, target: &Path) -> Result<String> {
    use std::ffi::OsStr;
    let plist = staged.join("Contents").join("Info.plist");
    if !fs::symlink_metadata(&plist).is_ok_and(|m| m.is_file()) {
        return Err("staged bundle has no Contents/Info.plist".into());
    }
    let read = |key: &str| -> Result<String> {
        let command = format!("Print :{key}");
        let (ok, out) = tool(
            "/usr/libexec/PlistBuddy",
            &[OsStr::new("-c"), OsStr::new(&command), plist.as_os_str()],
        )?;
        let value = out.trim_end_matches('\n').to_string();
        if !ok || value.is_empty() {
            Err(format!("staged bundle has no {key}"))
        } else {
            Ok(value)
        }
    };
    if read("CFBundleIdentifier")? != config.app_id {
        return Err("staged bundle identifier does not match app_id".into());
    }
    let executable = read("CFBundleExecutable")?;
    valid_component(&executable)?;
    let (ok, out) = tool(
        "/usr/bin/codesign",
        &[OsStr::new("-d"), OsStr::new("-r-"), target.as_os_str()],
    )?;
    let requirement = out
        .lines()
        .find_map(|line| {
            line.trim_start_matches(['#', ' '])
                .strip_prefix("designated => ")
        })
        .map(str::trim)
        .unwrap_or("");
    if !ok || requirement.is_empty() || requirement.contains("cdhash") {
        return Err(
            "installed bundle has no stable code signing identity (ad-hoc or unsigned)".into(),
        );
    }
    let requirement = format!("={requirement}");
    let (ok, _) = tool(
        "/usr/bin/codesign",
        &[
            OsStr::new("--verify"),
            OsStr::new("--deep"),
            OsStr::new("--strict"),
            OsStr::new("-R"),
            OsStr::new(&requirement),
            staged.as_os_str(),
        ],
    )?;
    if !ok {
        return Err(
            "staged bundle signature does not satisfy the installed app's code requirement".into(),
        );
    }
    Ok(executable)
}
#[cfg(not(target_os = "macos"))]
fn bundle_check(_: &Config, _: &Path, _: &Path) -> Result<String> {
    Err("application bundles are only supported on macOS".into())
}

// ---------------------------------------------------------------------------
// Process identity and detached launch

#[cfg(target_os = "linux")]
fn lookup_identity(pid: u32) -> Result<Option<u64>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot inspect parent process".into()),
    };
    let fields: Vec<_> = stat
        .get(stat.rfind(')').ok_or("invalid process record")? + 1..)
        .ok_or("invalid process record")?
        .split_whitespace()
        .collect();
    if matches!(fields.first(), Some(&"Z") | Some(&"X")) {
        return Ok(None);
    }
    Ok(Some(
        fields
            .get(19)
            .ok_or("missing process start time")?
            .parse()
            .map_err(|_| "invalid process start time")?,
    ))
}
#[cfg(target_os = "macos")]
fn lookup_identity(pid: u32) -> Result<Option<u64>> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let result = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if result == size {
        if info.pbi_status == 5 {
            return Ok(None);
        }
        return Ok(Some(
            info.pbi_start_tvsec
                .wrapping_mul(1_000_000)
                .wrapping_add(info.pbi_start_tvusec),
        ));
    }
    let probe = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if probe != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(None)
    } else {
        Err("cannot inspect parent process identity".into())
    }
}
#[cfg(windows)]
fn handle_identity(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<u64> {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    unsafe {
        let mut times = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        let [created, exited, kernel, user] = &mut times;
        if GetProcessTimes(handle, created, exited, kernel, user) == 0 {
            return Err("cannot inspect Windows process start time".into());
        }
        Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
    }
}
#[cfg(windows)]
fn lookup_identity(pid: u32) -> Result<Option<u64>> {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return if GetLastError() == ERROR_INVALID_PARAMETER {
                Ok(None)
            } else {
                Err("cannot inspect Windows parent process".into())
            };
        }
        let result = handle_identity(handle);
        CloseHandle(handle);
        result.map(Some)
    }
}
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn lookup_identity(_: u32) -> Result<Option<u64>> {
    Err("process identity is unsupported on this platform".into())
}
#[cfg(test)]
fn identity(pid: u32) -> Option<u64> {
    lookup_identity(pid).ok().flatten()
}
#[cfg(not(windows))]
fn process_running(process: &Process) -> Result<bool> {
    if process.pid == 0 || process.identity == 0 {
        return Err("missing process identity".into());
    }
    Ok(lookup_identity(process.pid)?.is_some_and(|identity| identity == process.identity))
}
#[cfg(windows)]
fn process_running(process: &Process) -> Result<bool> {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    if process.pid == 0 || process.identity == 0 {
        return Err("missing process identity".into());
    }
    unsafe {
        let handle = OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process.pid,
        );
        if handle.is_null() {
            return if GetLastError() == ERROR_INVALID_PARAMETER {
                Ok(false)
            } else {
                Err("cannot inspect Windows process".into())
            };
        }
        let result = (|| {
            if handle_identity(handle)? != process.identity {
                return Ok(false);
            }
            match WaitForSingleObject(handle, 0) {
                WAIT_TIMEOUT => Ok(true),
                WAIT_OBJECT_0 => Ok(false),
                _ => Err("cannot inspect Windows process exit".into()),
            }
        })();
        CloseHandle(handle);
        result
    }
}
#[cfg(windows)]
fn wait_for_exit(process: &Process, timeout: Duration) -> Result<()> {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    if process.pid == 0 || process.identity == 0 {
        return Err("missing parent process identity".into());
    }
    unsafe {
        let handle = OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process.pid,
        );
        if handle.is_null() {
            return if GetLastError() == ERROR_INVALID_PARAMETER {
                Ok(())
            } else {
                Err("cannot wait on Windows parent process".into())
            };
        }
        let result = (|| {
            if handle_identity(handle)? != process.identity {
                return Ok(());
            }
            match WaitForSingleObject(handle, timeout.as_millis().min(u32::MAX as u128 - 1) as u32)
            {
                WAIT_OBJECT_0 => Ok(()),
                WAIT_TIMEOUT => Err("the application did not exit; update abandoned".into()),
                _ => Err("cannot wait on Windows parent process".into()),
            }
        })();
        CloseHandle(handle);
        result
    }
}
#[cfg(unix)]
fn wait_for_exit(process: &Process, timeout: Duration) -> Result<()> {
    if process.pid == 0 || process.identity == 0 {
        return Err("missing parent process identity".into());
    }
    wait_with_probe(timeout, || process_running(process))
}

#[cfg(unix)]
fn wait_with_probe(timeout: Duration, mut probe: impl FnMut() -> Result<bool>) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut inspection_error: Option<(Instant, String)> = None;
    loop {
        match probe() {
            Ok(false) => return Ok(()),
            Ok(true) => inspection_error = None,
            Err(error) => {
                // macOS process inspection can be temporarily unavailable during
                // exit. Keep the state uncertain and retry; an error never means
                // the process exited, and persistent denial still fails closed.
                let failure = inspection_error.get_or_insert((Instant::now(), error));
                if failure.0.elapsed() >= Duration::from_secs(2) {
                    return Err(failure.1.clone());
                }
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(inspection_error
                .map(|(_, error)| error)
                .unwrap_or_else(|| "the application did not exit; update abandoned".into()));
        }
        thread::sleep(Duration::from_millis(50).min(deadline.saturating_duration_since(now)));
    }
}

/// Spawn without a shell, detached from the caller's session/console so the
/// child survives the host exiting.
fn spawn_detached(
    program: &Path,
    args: &[&std::ffi::OsStr],
    configure: impl Fn(&mut Command),
) -> io::Result<Child> {
    let build = || {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure(&mut command);
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        command
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        // Leave the host's job object when permitted, so closing it does not
        // kill the helper; fall back when the job forbids breakaway.
        let mut command = build();
        command.creation_flags(
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
        );
        if let Ok(child) = command.spawn() {
            return Ok(child);
        }
        let mut command = build();
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        command.spawn()
    }
    #[cfg(not(windows))]
    build().spawn()
}
fn reap(mut child: Child) {
    let _ = thread::Builder::new()
        .name("buoy-update-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn relaunch(transaction: &Path, journal: &Journal) -> Result<()> {
    let target = Path::new(&journal.sealed.target);
    let rel = journal
        .launch
        .as_deref()
        .ok_or("no relaunch executable is available")?;
    let program = resolve(target, &relative(rel)?)?;
    check_executable(&program)?;
    let args: Vec<&std::ffi::OsStr> = journal
        .sealed
        .arguments
        .iter()
        .map(std::ffi::OsStr::new)
        .collect();
    let directory = target.parent().unwrap_or(target).to_path_buf();
    let child = spawn_detached(&program, &args, |c| {
        c.current_dir(&directory).env(TRANSACTION_ENV, transaction);
    })
    .map_err(io_err("cannot relaunch"))?;
    drop(child); // the helper exits next; the program is reparented
    Ok(())
}

// ---------------------------------------------------------------------------
// Transaction lifecycle

fn transactions(location: &Location) -> Result<Vec<PathBuf>> {
    let prefix = location.prefix();
    let mut found = Vec::new();
    for entry in fs::read_dir(&location.parent).map_err(io_err("cannot scan target directory"))? {
        let entry = entry.map_err(io_err("cannot scan target directory"))?;
        let is_dir = entry
            .file_type()
            .is_ok_and(|t| t.is_dir() && !t.is_symlink());
        if is_dir
            && entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// Roll back whatever part of a swap happened. Idempotent and resumable: it
/// trusts the filesystem over the journal where they can disagree after a crash.
fn rollback_locked(transaction: &Path, journal: &mut Journal) -> Result<()> {
    let target = PathBuf::from(&journal.sealed.target);
    let backup = transaction.join(BACKUP);
    let rejected = transaction.join(REJECTED);
    match journal.state {
        State::RolledBack => Ok(()),
        State::Confirmed => Err("transaction is already confirmed".into()),
        State::Accepted if journal.helper.is_some_and(|h| h.alive()) => {
            Err("an update helper is still waiting on this transaction".into())
        }
        State::Prepared | State::HandingOff | State::Accepted | State::Failed
            if !exists(&backup) =>
        {
            set_state(transaction, journal, State::RolledBack)
        }
        _ => {
            if !exists(&backup) {
                if exists(&target)
                    && matches!(journal.state, State::MovingOriginal | State::RollingBack)
                {
                    return set_state(transaction, journal, State::RolledBack);
                }
                return Err("backup missing: the transaction cannot be rolled back".into());
            }
            set_state(transaction, journal, State::RollingBack)?;
            if exists(&target) {
                rename(&target, &rejected)?;
                sync_dir(transaction)?;
                sync_dir(&location(&target)?.parent)?;
            }
            rename(&backup, &target)?;
            sync_dir(&location(&target)?.parent)?;
            set_state(transaction, journal, State::RolledBack)
        }
    }
}

/// Under the target lock: roll back interrupted swaps, drop finished or stale
/// transactions and report whether an update is pending. With `supersede`,
/// unused prepared transactions are discarded for a new one.
fn recover_locked(location: &Location, supersede: bool) -> Result<usize> {
    let mut pending = 0;
    let mut recovered = 0;
    for transaction in transactions(location)? {
        if require_private(&transaction, true).is_err() {
            continue;
        }
        let mut journal = match read_journal(&transaction) {
            Ok(j)
                if self::location(Path::new(&j.sealed.target))
                    .is_ok_and(|recorded| recorded.key == location.key) =>
            {
                j
            }
            Ok(_) => continue,
            Err(_) => {
                // No journal under the lock: an abandoned prepare or a partial cleanup.
                if !exists(&transaction.join(BACKUP)) {
                    let _ = remove_tree(&transaction);
                }
                continue;
            }
        };
        let stale_handoff = journal.state == State::HandingOff
            && fs::metadata(transaction.join(JOURNAL))
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_none_or(|age| age > ACCEPT_TIMEOUT * 3);
        match journal.state {
            State::RolledBack | State::Confirmed | State::Failed => {
                cleanup(&transaction, journal.state)
            }
            State::Prepared if supersede => cleanup(&transaction, State::RolledBack),
            State::Prepared => {}
            State::HandingOff if stale_handoff => cleanup(&transaction, State::RolledBack),
            State::Accepted if !journal.helper.is_some_and(|h| h.alive()) => {
                cleanup(&transaction, State::RolledBack)
            }
            State::HandingOff | State::Accepted | State::Applied => pending += 1,
            State::MovingOriginal | State::OriginalMoved | State::RollingBack => {
                rollback_locked(&transaction, &mut journal)?;
                cleanup(&transaction, journal.state);
                recovered += 1;
            }
        }
    }
    if supersede && pending > 0 {
        return Err(
            "another update is in progress or awaiting confirmation for this target".into(),
        );
    }
    Ok(recovered)
}

struct PrivateDirectory {
    path: PathBuf,
    retained: bool,
}
impl PrivateDirectory {
    fn new(parent: &Path, prefix: &str) -> Result<Self> {
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let path = parent.join(format!("{prefix}{}", hex::encode(random)));
        #[cfg(windows)]
        crate::security_windows::create_directory(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(io_err("cannot create private transaction directory"))?;
        }
        Ok(Self {
            path,
            retained: false,
        })
    }
    fn keep(mut self) -> PathBuf {
        self.retained = true;
        self.path.clone()
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        if !self.retained {
            let _ = remove_tree(&self.path);
        }
    }
}

/// Validate, copy, verify and stage an authenticated download next to the target.
pub fn prepare(
    config: &Config,
    download: &Downloaded,
    options: &InstallOptions,
    cancel: &Arc<AtomicBool>,
) -> Result<PathBuf> {
    cancelled(cancel)?;
    core::validate_config(config)?;
    let selection = &download.selection;
    format(&selection.asset)?;
    relative(&options.executable)?;
    if options.arguments.len() > MAX_ARGUMENTS
        || options
            .arguments
            .iter()
            .any(|a| a.contains('\0') || a.len() > 32768)
    {
        return Err("invalid relaunch arguments".into());
    }
    authenticate(config, selection)?;
    core::verify_file(&download.path, &selection.asset, cancel)?;
    let location = location(&options.target)?;
    let _lock = lock(&location, LOCK_TIMEOUT)?;
    recover_locked(&location, true)?;
    let (location, kind) = validate_target(&location.path)?;
    let mut stored = config.clone();
    // The pinned key and policy are kept; credentials are not written to disk.
    match &mut stored.source {
        Source::Manifest { token, .. } | Source::Github { token, .. } => token.clear(),
    }
    let sealed = Sealed {
        config: stored,
        selection: selection.clone(),
        target: location
            .path
            .to_str()
            .ok_or("target path must be valid Unicode")?
            .to_string(),
        kind,
        executable: options.executable.clone(),
        arguments: options.arguments.clone(),
    };
    let directory = PrivateDirectory::new(&location.parent, &location.prefix())?;
    let transaction = directory.path.clone();
    require_private(&transaction, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = fs::metadata(&transaction).map_err(|e| e.to_string())?.dev();
        let b = fs::symlink_metadata(&location.path)
            .map_err(|e| e.to_string())?
            .dev();
        if a != b {
            return Err("target is a mount point; staging must share its filesystem".into());
        }
    }
    {
        let mut input = core::open_regular(&download.path).map_err(|_| "cannot open download")?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(transaction.join(PAYLOAD))
            .map_err(io_err("cannot copy payload"))?;
        let mut reader = CancelRead {
            inner: (&mut input).take(selection.asset.size + 1),
            cancel,
        };
        io::copy(&mut reader, &mut output).map_err(|e| e.to_string())?;
        output.sync_all().map_err(io_err("cannot flush payload"))?;
    }
    let launch = stage(&sealed, &transaction, cancel)?;
    let digest = seal(&sealed)?;
    let journal = Journal {
        format: 1,
        sealed,
        state: State::Prepared,
        launch,
        nonce: String::new(),
        relaunch: false,
        helper: None,
        error: String::new(),
    };
    write_journal(&transaction, &journal)?;
    let transaction = directory.keep();
    let mut seals = SEALS.lock().unwrap_or_else(|e| e.into_inner());
    seals.retain(|(p, _)| p != &transaction);
    seals.push((transaction.clone(), digest));
    Ok(transaction)
}

fn copy_helper(helper: &Path, destination: &Path) -> Result<()> {
    if !helper.is_absolute() || !fs::symlink_metadata(helper).is_ok_and(|m| m.is_file()) {
        return Err("helper must be an absolute path to a regular file".into());
    }
    remove_tree(destination).map_err(io_err("cannot replace helper copy"))?;
    // A plain byte copy: no extended attributes (such as quarantine) follow it.
    let mut input = core::open_regular(helper).map_err(|_| "cannot open helper")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o700);
    let mut output = options
        .open(destination)
        .map_err(io_err("cannot copy helper"))?;
    io::copy(&mut Read::by_ref(&mut input).take(512 << 20), &mut output)
        .map_err(io_err("cannot copy helper"))?;
    output.sync_all().map_err(io_err("cannot copy helper"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(io_err("cannot mark helper executable"))?;
    }
    Ok(())
}

/// Copy the helper out of the target tree, start it detached and wait until it
/// accepts the transaction. The caller must then exit; the helper waits for it.
pub fn handoff(transaction: &Path, helper: &Path, relaunch: bool) -> Result<()> {
    handoff_for(transaction, helper, relaunch, Process::current()?)
}
fn handoff_for(transaction: &Path, helper: &Path, relaunch: bool, parent: Process) -> Result<()> {
    let digest = SEALS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(p, _)| p == transaction)
        .map(|(_, s)| s.clone())
        .ok_or("transaction was not prepared by this process")?;
    let (_, location) = open_transaction(transaction)?;
    let copy = transaction.join(HELPER);
    let nonce = {
        let _lock = lock(&location, LOCK_TIMEOUT)?;
        let mut journal = read_journal(transaction)?;
        if seal(&journal.sealed)? != digest {
            return Err("transaction journal was modified".into());
        }
        if journal.state != State::Prepared {
            return Err("transaction is not prepared".into());
        }
        if relaunch && journal.launch.is_none() {
            return Err("relaunch needs an executable for a directory target".into());
        }
        let (_, kind) = validate_target(&location.path)?;
        if kind != journal.sealed.kind {
            return Err("target changed type since prepare".into());
        }
        copy_helper(helper, &copy)?;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        journal.nonce = hex::encode(bytes);
        journal.relaunch = relaunch;
        journal.helper = None;
        journal.error.clear();
        set_state(transaction, &mut journal, State::HandingOff)?;
        journal.nonce
    };
    let reset = |error: String| -> String {
        if let Ok(_lock) = lock(&location, LOCK_TIMEOUT) {
            if let Ok(mut journal) = read_journal(transaction) {
                if journal.state == State::HandingOff && journal.nonce == nonce {
                    journal.error = error.clone();
                    let _ = set_state(transaction, &mut journal, State::Prepared);
                }
            }
        }
        error
    };
    let parent_text = parent.to_string();
    let args = [
        std::ffi::OsStr::new("apply"),
        transaction.as_os_str(),
        "--seal".as_ref(),
        digest.as_ref(),
        "--nonce".as_ref(),
        nonce.as_ref(),
        "--parent".as_ref(),
        parent_text.as_ref(),
    ];
    let directory = location.parent.clone();
    let mut child = spawn_detached(&copy, &args, |c| {
        c.current_dir(&directory);
    })
    .map_err(|e| reset(format!("cannot start update helper: {e}")))?;
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        let journal = read_journal(transaction).ok();
        match journal.as_ref().map(|j| (j.state, j.nonce == nonce)) {
            Some((State::HandingOff, true)) | None => {}
            Some((State::Accepted, true)) => {
                reap(child);
                return Ok(());
            }
            _ => {
                let _ = child.kill();
                reap(child);
                return Err(journal
                    .map(|j| j.error)
                    .filter(|e| !e.is_empty())
                    .unwrap_or_else(|| "update helper rejected the transaction".into()));
            }
        }
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        if exited || Instant::now() >= deadline {
            // Decide under the lock so a late acceptance is never lost.
            let _lock = lock(&location, LOCK_TIMEOUT)?;
            let mut journal = read_journal(transaction)?;
            if journal.state == State::Accepted && journal.nonce == nonce {
                reap(child);
                return Ok(());
            }
            let _ = child.kill();
            reap(child);
            journal.error = "update helper did not accept the transaction".into();
            set_state(transaction, &mut journal, State::Prepared)?;
            return Err(journal.error);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Helper entry point: accept, wait for the host to exit, then re-verify,
/// restage, swap and optionally relaunch.
pub fn run_helper(request: &HelperRequest) -> Result<()> {
    let location = accept(request)?;
    if let Err(error) = wait_for_exit(&request.parent, PARENT_TIMEOUT) {
        let _lock = lock(&location, LOCK_TIMEOUT)?;
        let mut journal = read_journal(&request.transaction)?;
        if journal.state == State::Accepted && journal.nonce == request.nonce {
            journal.error = error.clone();
            set_state(&request.transaction, &mut journal, State::Failed)?;
        }
        return Err(error);
    }
    apply(request, &location)
}
fn accept(request: &HelperRequest) -> Result<Location> {
    let (_, location) = open_transaction(&request.transaction)?;
    let _lock = lock(&location, LOCK_TIMEOUT)?;
    let mut journal = read_journal(&request.transaction)?;
    if seal(&journal.sealed)? != request.seal
        || journal.nonce != request.nonce
        || journal.state != State::HandingOff
    {
        return Err("transaction does not match this handoff".into());
    }
    journal.helper = Some(Process::current()?);
    set_state(&request.transaction, &mut journal, State::Accepted)?;
    Ok(location)
}
fn apply(request: &HelperRequest, location: &Location) -> Result<()> {
    let transaction = &request.transaction;
    let lock = lock(location, LOCK_TIMEOUT)?;
    let mut journal = read_journal(transaction)?;
    if seal(&journal.sealed)? != request.seal
        || journal.nonce != request.nonce
        || journal.state != State::Accepted
    {
        return Err("transaction does not match this handoff".into());
    }
    let never = Arc::new(AtomicBool::new(false));
    // Everything prepare checked is checked again now that the host has exited,
    // and the stage is rebuilt from the re-hashed payload, so files substituted
    // in the transaction directory meanwhile are never installed.
    let verified = (|| -> Result<Option<String>> {
        let (_, kind) = validate_target(&location.path)?;
        if kind != journal.sealed.kind {
            return Err("target changed type since prepare".into());
        }
        core::validate_config(&journal.sealed.config)?;
        authenticate(&journal.sealed.config, &journal.sealed.selection)?;
        stage(&journal.sealed, transaction, &never)
    })();
    let launch = match verified {
        Ok(launch) => launch,
        Err(error) => {
            let _ = remove_tree(&stage_path(transaction, journal.sealed.kind));
            journal.error = error.clone();
            set_state(transaction, &mut journal, State::Failed)?;
            drop(lock);
            if journal.relaunch {
                let _ = relaunch(transaction, &journal);
            }
            return Err(error);
        }
    };
    journal.launch = launch;
    let target = &location.path;
    set_state(transaction, &mut journal, State::MovingOriginal)?;
    if let Err(error) = rename(target, &transaction.join(BACKUP)) {
        journal.error = error.clone();
        set_state(transaction, &mut journal, State::Failed)?;
        drop(lock);
        if journal.relaunch {
            let _ = relaunch(transaction, &journal);
        }
        return Err(error);
    }
    // Persist the destination's backup entry before the old parent entry is
    // flushed away; the write-ahead journal remains recoverable at every step.
    sync_dir(transaction)?;
    sync_dir(&location.parent)?;
    set_state(transaction, &mut journal, State::OriginalMoved)?;
    if let Err(error) = rename(&stage_path(transaction, journal.sealed.kind), target) {
        let restored = rollback_locked(transaction, &mut journal);
        journal.error = error.clone();
        let _ = write_journal(transaction, &journal);
        drop(lock);
        if restored.is_ok() && journal.relaunch {
            let _ = relaunch(transaction, &journal);
        }
        return Err(error);
    }
    sync_dir(&location.parent)?;
    set_state(transaction, &mut journal, State::Applied)?;
    let _ = fs::remove_file(transaction.join(PAYLOAD));
    drop(lock);
    if journal.relaunch {
        if let Err(error) = relaunch(transaction, &journal) {
            let _lock = self::lock(location, LOCK_TIMEOUT)?;
            let mut current = read_journal(transaction)?;
            if current.state == State::Applied {
                current.error = error.clone();
                write_journal(transaction, &current)?;
            }
            return Err(error);
        }
    }
    Ok(())
}

/// Restore the retained backup (or discard an unapplied transaction).
pub fn rollback(transaction: &Path) -> Result<()> {
    let (_, location) = open_transaction(transaction)?;
    let _lock = lock(&location, LOCK_TIMEOUT)?;
    let mut journal = read_journal(transaction)?;
    rollback_locked(transaction, &mut journal)?;
    cleanup(transaction, journal.state);
    Ok(())
}

/// Commit an applied update after the new version's health check; deletes the backup.
pub fn confirm(transaction: &Path) -> Result<()> {
    let (_, location) = open_transaction(transaction)?;
    let _lock = lock(&location, LOCK_TIMEOUT)?;
    let mut journal = read_journal(transaction)?;
    match journal.state {
        State::Applied => set_state(transaction, &mut journal, State::Confirmed)?,
        State::Confirmed => {}
        state => {
            return Err(format!(
                "transaction is {}, not awaiting confirmation",
                state.name()
            ))
        }
    }
    cleanup(transaction, State::Confirmed);
    Ok(())
}

/// Roll back interrupted swaps for a target and clear finished transactions.
/// Applied-but-unconfirmed updates are left for `confirm` or `rollback`.
pub fn recover(target: &Path) -> Result<usize> {
    let location = location(target)?;
    let _lock = lock(&location, LOCK_TIMEOUT)?;
    recover_locked(&location, false)
}

/// The journal state (and last error, if any) of a transaction.
pub fn status(transaction: &Path) -> Result<(String, String)> {
    let (journal, _) = open_transaction(transaction)?;
    Ok((journal.state.name(), journal.error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    fn never() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
    fn config() -> Config {
        Config {
            app_id: "example.app".into(),
            current_version: "1.0.0".into(),
            platform: std::env::consts::OS.into(),
            arch: native_arch().into(),
            channel: "stable".into(),
            source: Source::Manifest {
                url: "https://updates.example/manifest".into(),
                token: "secret".into(),
            },
            public_key: hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            allow_http_loopback: false,
            timeout_seconds: 2,
            max_download_bytes: 1 << 20,
            minimum_sequence: 0,
        }
    }
    fn signed(asset: &Asset) -> Selection {
        let manifest = Manifest {
            schema: 1,
            app_id: "example.app".into(),
            sequence: 4,
            expires: 9_007_199_254_740_991,
            releases: vec![Release {
                version: "2.0.0".into(),
                channel: "stable".into(),
                notes: "n".into(),
                assets: vec![asset.clone()],
            }],
        };
        let payload = serde_json::to_vec(&manifest).unwrap();
        let envelope = Envelope {
            payload: STANDARD.encode(&payload),
            signature: hex::encode(SigningKey::from_bytes(&[7; 32]).sign(&payload).to_bytes()),
        };
        Selection {
            version: "2.0.0".into(),
            notes: "n".into(),
            sequence: 4,
            asset: asset.clone(),
            envelope,
        }
    }
    fn download(bytes: &[u8], format: &str, entry: &str) -> Downloaded {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payload");
        fs::write(&path, bytes).unwrap();
        let asset = Asset {
            platform: std::env::consts::OS.into(),
            arch: native_arch().into(),
            url: "https://updates.example/a".into(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            format: format.into(),
            entry: entry.into(),
        };
        Downloaded {
            directory,
            path,
            selection: signed(&asset),
        }
    }
    /// Raw tar header so hostile names bypass the tar builder's own checks.
    fn tar_gz(entries: &[(&str, tar::EntryType, u32, &[u8], &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (name, kind, mode, data, link) in entries {
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.as_old_mut().linkname[..link.len()].copy_from_slice(link.as_bytes());
            header.set_entry_type(*kind);
            header.set_mode(*mode);
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }
    fn zip_file(build: impl FnOnce(&mut zip::ZipWriter<io::Cursor<Vec<u8>>>)) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        build(&mut writer);
        writer.finish().unwrap().into_inner()
    }
    fn options() -> zip::write::SimpleFileOptions {
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
    }
    fn extract(bytes: &[u8], format: Format, entry: &str) -> (tempfile::TempDir, Result<()>) {
        let directory = tempfile::tempdir().unwrap();
        let payload = directory.path().join("p");
        fs::write(&payload, bytes).unwrap();
        let cancel = never();
        let result = (|| {
            let mut extractor = Extractor::new(directory.path().join("out"), entry, &cancel)?;
            let file = File::open(&payload).unwrap();
            if format == Format::Zip {
                extract_zip(file, &mut extractor)?
            } else {
                extract_tar(file, &mut extractor)?
            }
            extractor.finish()
        })();
        (directory, result)
    }
    /// A canonical (symlink-free) scratch directory, with spaces and Unicode.
    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let directory = private_tempdir().unwrap();
        let root = fs::canonicalize(directory.path())
            .unwrap()
            .join("Prog files ü");
        fs::create_dir(&root).unwrap();
        (directory, root)
    }
    fn accept_and_apply(transaction: &Path) -> Result<()> {
        let journal = read_journal(transaction).unwrap();
        let mut journal2 = journal.clone();
        journal2.nonce = "n0".into();
        set_state(transaction, &mut journal2, State::HandingOff).unwrap();
        let request = HelperRequest {
            transaction: transaction.into(),
            seal: seal(&journal.sealed).unwrap(),
            nonce: "n0".into(),
            parent: Process {
                pid: 0,
                identity: 0,
            },
        };
        let location = accept(&request)?;
        apply(&request, &location)
    }

    #[test]
    fn rejects_traversal_and_unportable_names() {
        for name in [
            "../evil",
            "a/../../evil",
            "/abs",
            "a\\b",
            "a//b",
            "con.txt",
            "a/b:c",
            "trailing.",
            "x\u{1}",
        ] {
            let bytes = tar_gz(&[(name, tar::EntryType::Regular, 0o644, b"x", "")]);
            assert!(extract(&bytes, Format::TarGz, "").1.is_err(), "{name}");
        }
        let bytes = zip_file(|w| {
            w.start_file("../evil", options()).unwrap();
            w.write_all(b"x").unwrap();
        });
        assert!(extract(&bytes, Format::Zip, "").1.is_err());
    }

    #[test]
    fn rejects_collisions_links_and_special_files() {
        let collide = tar_gz(&[
            ("App/a", tar::EntryType::Regular, 0o644, b"1", ""),
            ("App/A", tar::EntryType::Regular, 0o644, b"2", ""),
        ]);
        assert!(extract(&collide, Format::TarGz, "")
            .1
            .unwrap_err()
            .contains("colliding"));
        let duplicate = tar_gz(&[
            ("a", tar::EntryType::Regular, 0o644, b"1", ""),
            ("a", tar::EntryType::Regular, 0o644, b"2", ""),
        ]);
        assert!(extract(&duplicate, Format::TarGz, "").1.is_err());
        for (kind, link) in [
            (tar::EntryType::Link, "a"),
            (tar::EntryType::Fifo, ""),
            (tar::EntryType::Char, ""),
        ] {
            let bytes = tar_gz(&[
                ("a", tar::EntryType::Regular, 0o644, b"", ""),
                ("b", kind, 0o644, b"", link),
            ]);
            assert!(extract(&bytes, Format::TarGz, "").1.is_err());
        }
        for link in ["/etc/passwd", "../../x", "a/../../x", "a/../b", ""] {
            let bytes = tar_gz(&[("d/l", tar::EntryType::Symlink, 0o777, b"", link)]);
            assert!(extract(&bytes, Format::TarGz, "").1.is_err(), "{link}");
        }
        // Confined to the archive but not to the selected entry.
        let bytes = tar_gz(&[
            ("App/f", tar::EntryType::Regular, 0o644, b"", ""),
            ("App/l", tar::EntryType::Symlink, 0o777, b"", "../outside"),
        ]);
        assert!(extract(&bytes, Format::TarGz, "App").1.is_err());
        // A file may not be written beneath a link.
        let bytes = tar_gz(&[
            ("l", tar::EntryType::Symlink, 0o777, b"", "d"),
            ("l/x", tar::EntryType::Regular, 0o644, b"", ""),
        ]);
        assert!(extract(&bytes, Format::TarGz, "").1.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn extracts_entry_with_modes_and_framework_links() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = tar_gz(&[
            ("./", tar::EntryType::Directory, 0o755, b"", ""),
            ("README", tar::EntryType::Regular, 0o644, b"outside", ""),
            ("Dist/App.app/", tar::EntryType::Directory, 0o2777, b"", ""),
            (
                "Dist/App.app/bin/run me",
                tar::EntryType::Regular,
                0o4755,
                b"#!",
                "",
            ),
            (
                "Dist/App.app/data.txt",
                tar::EntryType::Regular,
                0o666,
                b"data",
                "",
            ),
            (
                "Dist/App.app/F.framework/Versions/A/F",
                tar::EntryType::Regular,
                0o755,
                b"lib",
                "",
            ),
            (
                "Dist/App.app/F.framework/Versions/Current",
                tar::EntryType::Symlink,
                0o777,
                b"",
                "A",
            ),
            (
                "Dist/App.app/F.framework/F",
                tar::EntryType::Symlink,
                0o777,
                b"",
                "Versions/Current/F",
            ),
            (
                "Dist/App.app/bin/up",
                tar::EntryType::Symlink,
                0o777,
                b"",
                "../data.txt",
            ),
        ]);
        let (directory, result) = extract(&bytes, Format::TarGz, "Dist/App.app");
        result.unwrap();
        let out = directory.path().join("out");
        assert!(!out.join("README").exists());
        let mode = |p: &str| {
            fs::symlink_metadata(out.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("bin/run me"), 0o755);
        assert_eq!(mode("data.txt"), 0o644);
        assert_eq!(mode(""), 0o755);
        assert_eq!(fs::read(out.join("F.framework/F")).unwrap(), b"lib");
        assert_eq!(fs::read(out.join("bin/up")).unwrap(), b"data");
        assert!(extract(&bytes, Format::TarGz, "Dist/Missing.app")
            .1
            .unwrap_err()
            .contains("not found"));
    }

    #[cfg(unix)]
    #[test]
    fn extracts_zip_with_symlink_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = zip_file(|w| {
            w.add_directory("pkg/", options()).unwrap();
            w.start_file("pkg/tool", options().unix_permissions(0o6755))
                .unwrap();
            w.write_all(b"bin").unwrap();
            w.add_symlink("pkg/alias", "tool", options()).unwrap();
        });
        let (directory, result) = extract(&bytes, Format::Zip, "pkg");
        result.unwrap();
        let out = directory.path().join("out");
        assert_eq!(
            fs::symlink_metadata(out.join("tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert_eq!(fs::read_link(out.join("alias")).unwrap(), Path::new("tool"));
        let escape = zip_file(|w| w.add_symlink("pkg/alias", "../../x", options()).unwrap());
        assert!(extract(&escape, Format::Zip, "pkg").1.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn substituted_payload_symlinks_never_authorize_installation() {
        let (_guard, root) = scratch();
        let target = root.join("my tool");
        fs::write(&target, b"old").unwrap();
        fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let downloaded = download(b"new", "raw", "");
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: vec![],
        };
        let transaction = prepare(&config(), &downloaded, &options, &never()).unwrap();
        // Identical signed bytes must not bypass the no-follow policy.
        let replacement = root.join("replacement");
        fs::write(&replacement, b"new").unwrap();
        fs::remove_file(transaction.join(PAYLOAD)).unwrap();
        std::os::unix::fs::symlink(&replacement, transaction.join(PAYLOAD)).unwrap();
        assert!(accept_and_apply(&transaction).is_err());
        assert_eq!(status(&transaction).unwrap().0, "failed");
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read(&replacement).unwrap(), b"new");
        fs::remove_file(&downloaded.path).unwrap();
        std::os::unix::fs::symlink(&replacement, &downloaded.path).unwrap();
        assert!(prepare(&config(), &downloaded, &options, &never()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
    }

    #[test]
    fn raw_update_applies_rolls_back_and_confirms() {
        let (_guard, root) = scratch();
        let target = root.join("my tool");
        fs::write(&target, b"old").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let download = download(b"new", "raw", "");
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: vec!["a b".into()],
        };
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        assert!(!fs::read_to_string(transaction.join(JOURNAL))
            .unwrap()
            .contains("secret"));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(
            prepare(&config(), &download, &options, &never()).is_ok(),
            "an unused prepared transaction is superseded"
        );
        assert!(!transaction.exists());
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        accept_and_apply(&transaction).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&target).unwrap().permissions())
                & 0o777,
            0o755
        );
        assert_eq!(status(&transaction).unwrap().0, "applied");
        assert!(
            prepare(&config(), &download, &options, &never()).is_err(),
            "unconfirmed update blocks another"
        );
        rollback(&transaction).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!transaction.exists());

        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        accept_and_apply(&transaction).unwrap();
        assert!(
            transaction.join(BACKUP).exists(),
            "backup kept until confirmation"
        );
        confirm(&transaction).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!transaction.exists());
        assert!(rollback(&transaction).is_err());
    }

    #[test]
    fn directory_update_restages_and_rejects_tampering() {
        let (_guard, root) = scratch();
        let target = root.join("App Dir");
        fs::create_dir_all(target.join("bin")).unwrap();
        fs::write(target.join("bin/app"), b"old").unwrap();
        let archive = tar_gz(&[
            ("App/bin/app", tar::EntryType::Regular, 0o755, b"new", ""),
            ("App/ünï.txt", tar::EntryType::Regular, 0o644, b"u", ""),
        ]);
        let download = download(&archive, "tar.gz", "App");
        let options = InstallOptions {
            target: target.clone(),
            executable: "bin/app".into(),
            arguments: vec![],
        };

        // A substituted stage is discarded: the helper rebuilds it from the payload.
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        fs::write(transaction.join(STAGE).join("bin/app"), b"evil").unwrap();
        accept_and_apply(&transaction).unwrap();
        assert_eq!(fs::read(target.join("bin/app")).unwrap(), b"new");
        assert!(target.join("ünï.txt").exists());
        rollback(&transaction).unwrap();
        assert_eq!(fs::read(target.join("bin/app")).unwrap(), b"old");

        // A tampered payload fails verification and leaves the target alone.
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        let mut payload = fs::read(transaction.join(PAYLOAD)).unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 1;
        fs::write(transaction.join(PAYLOAD), payload).unwrap();
        assert!(accept_and_apply(&transaction)
            .unwrap_err()
            .contains("mismatch"));
        assert_eq!(fs::read(target.join("bin/app")).unwrap(), b"old");
        assert_eq!(status(&transaction).unwrap().0, "failed");

        // A modified sealed journal (another key, say) is refused by the helper.
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        let mut journal = read_journal(&transaction).unwrap();
        let sealed = seal(&journal.sealed).unwrap();
        journal.sealed.config.public_key = hex::encode([9u8; 32]);
        journal.nonce = "n0".into();
        set_state(&transaction, &mut journal, State::HandingOff).unwrap();
        let request = HelperRequest {
            transaction: transaction.clone(),
            seal: sealed,
            nonce: "n0".into(),
            parent: Process {
                pid: 0,
                identity: 0,
            },
        };
        assert!(accept(&request).is_err());
    }

    #[test]
    fn rejects_bad_targets_and_mismatched_assets() {
        let (_guard, root) = scratch();
        let file = root.join("tool");
        fs::write(&file, b"old").unwrap();
        let raw = download(b"new", "raw", "");
        let options = |target: PathBuf, executable: &str| InstallOptions {
            target,
            executable: executable.into(),
            arguments: vec![],
        };
        assert!(prepare(&config(), &raw, &options("relative".into(), ""), &never()).is_err());
        assert!(prepare(
            &config(),
            &raw,
            &options(root.join("missing"), ""),
            &never()
        )
        .is_err());
        assert!(prepare(
            &config(),
            &raw,
            &options(
                PathBuf::from(format!(
                    "{}{sep}x{sep}..{sep}tool",
                    root.display(),
                    sep = std::path::MAIN_SEPARATOR
                )),
                ""
            ),
            &never()
        )
        .is_err());
        assert!(prepare(&config(), &raw, &options(file.clone(), "../x"), &never()).is_err());
        assert!(
            prepare(&config(), &raw, &options(file.clone(), "bin"), &never()).is_err(),
            "file target cannot name an executable"
        );
        #[cfg(unix)]
        {
            let link = root.join("link");
            std::os::unix::fs::symlink(&root, &link).unwrap();
            assert!(prepare(&config(), &raw, &options(link.join("tool"), ""), &never()).is_err());
            assert!(prepare(
                &config(),
                &raw,
                &options(Path::new("/tool").into(), ""),
                &never()
            )
            .is_err());
        }
        let directory = root.join("dir");
        fs::create_dir(&directory).unwrap();
        assert!(prepare(&config(), &raw, &options(directory, ""), &never())
            .unwrap_err()
            .contains("type"));
        // Asset not in the signed manifest.
        let mut forged = download(b"new", "raw", "");
        forged.selection.asset.url = "https://evil.example/a".into();
        assert!(
            prepare(&config(), &forged, &options(file.clone(), ""), &never())
                .unwrap_err()
                .contains("authenticated")
        );
        // Wrong download contents.
        let tampered = download(b"new", "raw", "");
        fs::write(&tampered.path, b"bad").unwrap();
        assert!(prepare(&config(), &tampered, &options(file.clone(), ""), &never()).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"old");
    }

    #[test]
    fn recovers_interrupted_swaps() {
        let (_guard, root) = scratch();
        let target = root.join("App");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("v"), b"old").unwrap();
        let archive = tar_gz(&[("v", tar::EntryType::Regular, 0o644, b"new", "")]);
        let download = download(&archive, "tar.gz", "");
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: vec![],
        };
        for crash_after_second_rename in [false, true] {
            let transaction = prepare(&config(), &download, &options, &never()).unwrap();
            let mut journal = read_journal(&transaction).unwrap();
            set_state(&transaction, &mut journal, State::MovingOriginal).unwrap();
            fs::rename(&target, transaction.join(BACKUP)).unwrap();
            if crash_after_second_rename {
                set_state(&transaction, &mut journal, State::OriginalMoved).unwrap();
                fs::rename(transaction.join(STAGE), &target).unwrap();
            }
            assert_eq!(recover(&target).unwrap(), 1);
            assert_eq!(fs::read(target.join("v")).unwrap(), b"old");
            assert!(!transaction.exists());
        }
    }

    // Run only in a subprocess whose stdin is owned by HeldProcess. EOF is
    // the release signal, so scheduling delays cannot make it exit too early.
    #[test]
    #[ignore = "subprocess fixture"]
    fn held_process_fixture() {
        assert_eq!(std::env::var("UPDATEKIT_HELD_PROCESS").as_deref(), Ok("1"));
        std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).unwrap();
    }

    struct HeldProcess(std::process::Child);

    impl HeldProcess {
        fn spawn() -> Self {
            Self(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "install::tests::held_process_fixture", "--ignored"])
                    .env("UPDATEKIT_HELD_PROCESS", "1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }

        fn process(&self) -> Process {
            Process {
                pid: self.0.id(),
                identity: identity(self.0.id()).expect("held child has a process identity"),
            }
        }

        fn release(&mut self) {
            drop(self.0.stdin.take());
            assert!(self.0.wait().unwrap().success());
        }
    }

    impl Drop for HeldProcess {
        fn drop(&mut self) {
            // Reap the child even when an assertion unwinds before release.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn process_identity_tracks_exit() {
        let me = Process::current().unwrap();
        assert!(me.alive());
        assert_eq!(Process::parse(&me.to_string()).unwrap(), me);
        let mut child = HeldProcess::spawn();
        let process = child.process();
        assert_ne!(process.identity, 0);
        assert!(process_running(&process).unwrap());
        assert!(wait_for_exit(&process, Duration::from_millis(20)).is_err());
        child.release();
        assert!(!process_running(&process).unwrap());
        assert!(wait_for_exit(&process, Duration::from_secs(5)).is_ok());
    }

    /// End to end through the real helper binary, when cargo has built it.
    #[cfg(unix)]
    #[test]
    fn helper_handoff_relaunches_with_exact_arguments() {
        let Some(helper) = std::env::current_exe()
            .ok()
            .and_then(|p| Some(p.parent()?.parent()?.join(HELPER)))
            .filter(|p| p.exists())
        else {
            eprintln!("skipping: helper binary not built");
            return;
        };
        let (_guard, root) = scratch();
        let target = root.join("my app");
        let out = root.join("out file");
        fs::write(&target, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let script = format!(
            "#!/bin/sh\nprintf '%s|' \"$@\" \"${TRANSACTION_ENV}\" > '{}'\n",
            out.display()
        );
        let download = download(script.as_bytes(), "raw", "");
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: vec!["one two".into(), "$HOME".into()],
        };
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        let mut parent = HeldProcess::spawn();
        let process = parent.process();
        handoff_for(&transaction, &helper, true, process).unwrap();
        assert_eq!(status(&transaction).unwrap().0, "accepted");
        assert_eq!(fs::read(&target).unwrap(), b"#!/bin/sh\nexit 0\n");
        assert!(!out.exists(), "relaunch must wait for the parent to exit");
        parent.release();
        let expected = format!("one two|$HOME|{}|", transaction.display());
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if fs::read_to_string(&out).ok().as_deref() == Some(expected.as_str())
                && status(&transaction).unwrap().0 == "applied"
            {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(fs::read_to_string(&out).unwrap(), expected);
        assert_eq!(status(&transaction).unwrap().0, "applied");
        confirm(&transaction).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn recovery_refuses_nonprivate_transactions() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, root) = scratch();
        let target = root.join("app");
        fs::write(&target, b"old").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: vec![],
        };
        let transaction = prepare(
            &config(),
            &download(b"new", "binary", ""),
            &options,
            &never(),
        )
        .unwrap();
        fs::write(transaction.join(BACKUP), b"malicious").unwrap();
        let mut journal = read_journal(&transaction).unwrap();
        set_state(&transaction, &mut journal, State::MovingOriginal).unwrap();
        fs::set_permissions(&transaction, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(rollback(&transaction).is_err());
        assert_eq!(recover(&target).unwrap(), 0);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700)).unwrap();
        remove_tree(&transaction).unwrap();
    }
    #[test]
    fn rejects_oversized_tar_metadata_before_allocating() {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongName);
        header.set_size(65537);
        header.set_cksum();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(header.as_bytes()).unwrap();
        let bytes = encoder.finish().unwrap();
        assert!(extract(&bytes, Format::TarGz, "")
            .1
            .unwrap_err()
            .contains("metadata"));
    }
    #[test]
    fn rejects_oversized_tar_member_outside_selected_entry() {
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..7].copy_from_slice(b"outside");
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(MAX_EXPANDED + 1);
        header.set_cksum();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(header.as_bytes()).unwrap();
        let bytes = encoder.finish().unwrap();
        assert!(extract(&bytes, Format::TarGz, "App")
            .1
            .unwrap_err()
            .contains("size limit"));
    }
    #[cfg(unix)]
    #[test]
    fn implicit_archive_directories_are_not_group_writable() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = tar_gz(&[("App/bin/tool", tar::EntryType::Regular, 0o755, b"app", "")]);
        let (directory, result) = extract(&bytes, Format::TarGz, "App");
        result.unwrap();
        for path in [
            directory.path().join("out"),
            directory.path().join("out/bin"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
    #[test]
    fn target_aliases_share_one_transaction_lock() {
        let (_guard, root) = scratch();
        let target = root.join("app");
        fs::write(&target, b"app").unwrap();
        let normal = location(&target).unwrap();
        let alias = location(&root.join(".").join("app")).unwrap();
        assert_eq!(normal.key, alias.key);
        assert_eq!(normal.path, alias.path);
        let repeated = PathBuf::from(format!("{}//app", root.display()));
        assert_eq!(normal.key, location(&repeated).unwrap().key);
    }
    #[test]
    fn unknown_process_identity_never_authorizes_replacement() {
        let unknown = Process {
            pid: std::process::id(),
            identity: 0,
        };
        assert!(process_running(&unknown).is_err());
        assert!(unknown.alive());
        assert!(wait_for_exit(&unknown, Duration::from_millis(1)).is_err());
    }
    #[test]
    fn prepare_recovers_a_missing_target_before_validation() {
        let (_guard, root) = scratch();
        let target = root.join("app");
        fs::write(&target, b"old").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let download = download(b"new", "binary", "");
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: vec![],
        };
        let transaction = prepare(&config(), &download, &options, &never()).unwrap();
        let mut journal = read_journal(&transaction).unwrap();
        set_state(&transaction, &mut journal, State::MovingOriginal).unwrap();
        fs::rename(&target, transaction.join(BACKUP)).unwrap();
        assert!(!target.exists());
        let next = prepare(&config(), &download, &options, &never()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"old");
        rollback(&next).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn windows_parent_probe() {
        if !std::env::args().any(|arg| arg == "--exact") {
            return;
        }
        let Some(wait) = std::env::var_os("BUOY_TEST_PARENT_WAIT") else {
            return;
        };
        let wait = PathBuf::from(wait);
        fs::write(wait.with_extension("ready"), b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !wait.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(wait.exists());
    }
    #[cfg(windows)]
    #[test]
    fn windows_relaunch_probe() {
        if !std::env::args().any(|arg| arg == "--exact") {
            return;
        }
        let Some(transaction) = std::env::var_os(TRANSACTION_ENV) else {
            return;
        };
        let path = PathBuf::from(&transaction).join("probe.json");
        let arguments: Vec<_> = std::env::args().collect();
        let record =
            serde_json::json!({"arguments":arguments,"process":Process::current().unwrap()});
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::rename(temporary, path).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn windows_helper_waits_for_running_image_and_relaunches() {
        let executable = std::env::current_exe().unwrap();
        let helper = executable.parent().unwrap().parent().unwrap().join(HELPER);
        assert!(
            helper.is_file(),
            "build the helper binary before running Windows integration tests"
        );
        let (_guard, root) = scratch();
        let target = root.join("my app.exe");
        let bytes = fs::read(&executable).unwrap();
        fs::write(&target, &bytes).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&target)
            .unwrap()
            .write_all(b"old-overlay")
            .unwrap();
        let wait = root.join("parent.wait");
        let mut parent = Command::new(&target)
            .args([
                "--exact",
                "install::tests::windows_parent_probe",
                "--nocapture",
            ])
            .env("BUOY_TEST_PARENT_WAIT", &wait)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !wait.with_extension("ready").exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(wait.with_extension("ready").exists());
        let download = download(&bytes, "binary", "");
        let mut config = config();
        config.max_download_bytes = bytes.len() as u64 + 1;
        let arguments = vec![
            "--exact".into(),
            "install::tests::windows_relaunch_probe".into(),
            "--nocapture".into(),
            "--skip".into(),
            "one two".into(),
            "--skip".into(),
            "$HOME".into(),
        ];
        let options = InstallOptions {
            target: target.clone(),
            executable: String::new(),
            arguments: arguments.clone(),
        };
        let transaction = prepare(&config, &download, &options, &never()).unwrap();
        let process = Process {
            pid: parent.id(),
            identity: lookup_identity(parent.id()).unwrap().unwrap(),
        };
        handoff_for(&transaction, &helper, true, process).unwrap();
        assert_ne!(
            fs::read(&target).unwrap(),
            bytes,
            "the running image must remain untouched before parent exit"
        );
        fs::write(&wait, b"exit").unwrap();
        assert!(parent.wait().unwrap().success());
        let probe = transaction.join("probe.json");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !probe.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let record: serde_json::Value = serde_json::from_slice(&fs::read(&probe).unwrap()).unwrap();
        let actual: Vec<String> = serde_json::from_value(record["arguments"].clone()).unwrap();
        let process: Process = serde_json::from_value(record["process"].clone()).unwrap();
        wait_for_exit(&process, Duration::from_secs(20)).unwrap();
        assert_eq!(&actual[1..], arguments.as_slice());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(status(&transaction).unwrap().0, "applied");
        confirm(&transaction).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn transient_parent_inspection_failure_is_retried_without_authorizing_exit() {
        let mut calls = 0;
        wait_with_probe(Duration::from_secs(1), || {
            calls += 1;
            if calls == 1 {
                Err("cannot inspect parent process identity".into())
            } else if calls == 2 {
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
    }
    #[cfg(unix)]
    #[test]
    fn persistent_parent_inspection_failure_still_fails_closed() {
        let error = wait_with_probe(
            Duration::from_millis(10),
            || Err("inspection denied".into()),
        )
        .unwrap_err();
        assert_eq!(error, "inspection denied");
    }
}
