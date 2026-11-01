//! Headless updater C ABI. Workers own their data and never call the host runtime.
pub mod core;
pub mod install;
pub mod model;
#[cfg(windows)]
mod security_windows;

use model::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone, Serialize)]
struct Snapshot {
    state: String,
    busy: bool,
    error: String,
    bytes: u64,
    total: u64,
    sequence: u64,
    release: Value,
    download_path: String,
    transaction_path: String,
    transaction_state: String,
    transaction_error: String,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            busy: false,
            error: String::new(),
            bytes: 0,
            total: 0,
            sequence: 0,
            release: Value::Null,
            download_path: String::new(),
            transaction_path: String::new(),
            transaction_state: String::new(),
            transaction_error: String::new(),
        }
    }
}
struct Data {
    config: Option<Config>,
    selection: Option<Selection>,
    download: Option<Arc<Downloaded>>,
    transaction: Option<PathBuf>,
    snapshot: Snapshot,
}
struct Session {
    data: Mutex<Data>,
    busy: AtomicBool,
    cancel: Arc<AtomicBool>,
}
struct Handle {
    session: Arc<Session>,
    text: CString,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Check {},
    LoadManifest {
        envelope: Envelope,
    },
    Download {},
    Adopt {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
    },
    Save {
        path: PathBuf,
    },
    Prepare {
        target: PathBuf,
        #[serde(default)]
        executable: String,
        #[serde(default)]
        arguments: Vec<String>,
    },
    Install {
        helper_path: PathBuf,
        #[serde(default)]
        relaunch: bool,
    },
    Rollback {
        transaction_path: PathBuf,
    },
    Confirm {
        transaction_path: PathBuf,
    },
    Recover {
        target: PathBuf,
    },
    Inspect {
        transaction_path: PathBuf,
    },
}
fn lock(session: &Session) -> std::sync::MutexGuard<'_, Data> {
    session.data.lock().unwrap_or_else(|e| e.into_inner())
}
fn checked_text<'a>(value: *const c_char) -> Result<&'a str> {
    if value.is_null() {
        return Err("Missing UTF-8 argument".into());
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| "Invalid UTF-8 argument".into())
}
fn describe(selection: &Selection) -> Value {
    json!({"version":selection.version,"notes":selection.notes,"sequence":selection.sequence})
}
fn selected(session: &Session) -> Result<Selection> {
    lock(session)
        .selection
        .clone()
        .ok_or_else(|| "Select an authenticated update first".into())
}
fn downloaded(session: &Session) -> Result<Arc<Downloaded>> {
    lock(session)
        .download
        .clone()
        .ok_or_else(|| "Download an update first".into())
}
fn done(session: &Session, state: &str) {
    lock(session).snapshot.state = state.into();
}
fn execute(session: &Arc<Session>, action: Action) -> Result<()> {
    let config = lock(session)
        .config
        .clone()
        .ok_or("Invalid updater configuration")?;
    match action {
        Action::Check {} | Action::LoadManifest { .. } => {
            {
                let mut data = lock(session);
                data.selection = None;
                data.download = None;
                data.transaction = None;
                data.snapshot.release = Value::Null;
                data.snapshot.download_path.clear();
                data.snapshot.transaction_path.clear();
            }
            let (selection, sequence) = match action {
                Action::Check {} => core::check_detailed(&config, &session.cancel)?,
                Action::LoadManifest { envelope } => {
                    let sequence = core::verify_envelope(&config, &envelope)?.sequence;
                    (core::select(&config, &envelope)?, sequence)
                }
                _ => unreachable!(),
            };
            let mut data = lock(session);
            data.snapshot.state = if selection.is_some() {
                "available"
            } else {
                "current"
            }
            .into();
            data.snapshot.release = selection.as_ref().map(describe).unwrap_or(Value::Null);
            data.snapshot.sequence = sequence;
            data.selection = selection;
        }
        Action::Download {} => {
            let selection = selected(session)?;
            let progress_session = session.clone();
            let result = core::download(
                &config,
                &selection,
                &session.cancel,
                &move |bytes, total| {
                    let mut data = lock(&progress_session);
                    data.snapshot.bytes = bytes;
                    data.snapshot.total = total;
                },
            )?;
            let mut data = lock(session);
            data.snapshot.download_path = result.path.to_string_lossy().into_owned();
            data.download = Some(Arc::new(result));
            data.transaction = None;
            data.snapshot.transaction_path.clear();
            data.snapshot.state = "downloaded".into();
        }
        Action::Adopt { path } => {
            let selection = selected(session)?;
            let mut input = core::open_regular(&path)?;
            core::verify_open_file(&mut input, &selection.asset, &session.cancel)?;
            use std::io::{Seek, SeekFrom};
            input
                .seek(SeekFrom::Start(0))
                .map_err(|_| "Cannot seek local update")?;
            let directory = private_tempdir()?;
            let destination = directory.path().join("payload");
            {
                use std::io::{Read, Write};
                let mut output =
                    std::fs::File::create(&destination).map_err(|_| "Cannot copy local update")?;
                let mut received = 0u64;
                let mut buffer = [0; 65536];
                loop {
                    cancelled(&session.cancel)?;
                    let n = input
                        .read(&mut buffer)
                        .map_err(|_| "Cannot read local update")?;
                    if n == 0 {
                        break;
                    }
                    received += n as u64;
                    if received > selection.asset.size {
                        return Err("Local update exceeds declared size".into());
                    }
                    output
                        .write_all(&buffer[..n])
                        .map_err(|_| "Cannot copy local update")?;
                }
                output.sync_all().map_err(|_| "Cannot sync local update")?;
            }
            core::verify_file(&destination, &selection.asset, &session.cancel)?;
            let mut data = lock(session);
            data.snapshot.download_path = destination.to_string_lossy().into_owned();
            data.download = Some(Arc::new(Downloaded {
                directory,
                path: destination,
                selection,
            }));
            data.transaction = None;
            data.snapshot.transaction_path.clear();
            data.snapshot.state = "downloaded".into();
        }
        Action::Verify { path } => {
            core::verify_file(&path, &selected(session)?.asset, &session.cancel)?;
            done(session, "verified");
        }
        Action::Save { path } => {
            let download = downloaded(session)?;
            core::verify_file(&download.path, &download.selection.asset, &session.cancel)?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| "Cannot create download destination (it must not exist)")?;
            let result = (|| -> Result<()> {
                use std::io::{Read, Write};
                let mut input =
                    std::fs::File::open(&download.path).map_err(|_| "Cannot open download")?;
                let mut buffer = [0; 65536];
                loop {
                    cancelled(&session.cancel)?;
                    let n = input
                        .read(&mut buffer)
                        .map_err(|_| "Download read failed")?;
                    if n == 0 {
                        break;
                    }
                    output
                        .write_all(&buffer[..n])
                        .map_err(|_| "Download save failed")?;
                }
                output.sync_all().map_err(|_| "Download sync failed")?;
                core::verify_file(&path, &download.selection.asset, &session.cancel)
            })();
            if result.is_err() {
                drop(output);
                let _ = std::fs::remove_file(&path);
            }
            result?;
            done(session, "saved");
        }
        Action::Prepare {
            target,
            executable,
            arguments,
        } => {
            let download = downloaded(session)?;
            let transaction = install::prepare(
                &config,
                &download,
                &install::InstallOptions {
                    target,
                    executable,
                    arguments,
                },
                &session.cancel,
            )?;
            let mut data = lock(session);
            data.snapshot.transaction_path = transaction.to_string_lossy().into_owned();
            data.transaction = Some(transaction);
            data.snapshot.state = "prepared".into();
        }
        Action::Install {
            helper_path,
            relaunch,
        } => {
            let transaction = lock(session)
                .transaction
                .clone()
                .ok_or("Prepare an installation first")?;
            install::handoff(&transaction, &helper_path, relaunch)?;
            done(session, "handed_off");
        }
        Action::Rollback { transaction_path } => {
            install::rollback(&transaction_path)?;
            done(session, "rolled_back");
        }
        Action::Recover { target } => {
            install::recover(&target)?;
            done(session, "recovered");
        }
        Action::Inspect { transaction_path } => {
            let (state, error) = install::status(&transaction_path)?;
            let mut data = lock(session);
            data.snapshot.transaction_path = transaction_path.to_string_lossy().into_owned();
            data.snapshot.transaction_state = state;
            data.snapshot.transaction_error = error;
            data.snapshot.state = "inspected".into();
        }
        Action::Confirm { transaction_path } => {
            install::confirm(&transaction_path)?;
            done(session, "confirmed");
        }
    }
    Ok(())
}

/// All handles and returned text are confined to one caller thread. Snapshot text is
/// borrowed until the next snapshot or delete; the host must copy it immediately.
/// # Safety
/// Non-null pointers must refer to live handles or NUL-terminated input buffers
/// created for this API. Confine handle access to one thread; do not use a handle
/// after deletion. Copy borrowed snapshot text before the next snapshot or delete.
#[no_mangle]
pub unsafe extern "C" fn bup_new(configuration: *const c_char) -> *mut std::ffi::c_void {
    std::panic::catch_unwind(|| {
        let parsed = checked_text(configuration)
            .and_then(|text| {
                serde_json::from_str::<Config>(text)
                    .map_err(|_| "Malformed updater configuration".into())
            })
            .and_then(|config| {
                core::validate_config(&config)?;
                Ok(config)
            });
        let mut snapshot = Snapshot::default();
        let config = match parsed {
            Ok(c) => Some(c),
            Err(e) => {
                snapshot.state = "failed".into();
                snapshot.error = e;
                None
            }
        };
        Box::into_raw(Box::new(Handle {
            session: Arc::new(Session {
                data: Mutex::new(Data {
                    config,
                    selection: None,
                    download: None,
                    transaction: None,
                    snapshot,
                }),
                busy: AtomicBool::new(false),
                cancel: Arc::new(AtomicBool::new(false)),
            }),
            text: CString::new("{}").unwrap(),
        }))
        .cast()
    })
    .unwrap_or(std::ptr::null_mut())
}
/// # Safety
/// Non-null pointers must refer to live handles or NUL-terminated input buffers
/// created for this API. Confine handle access to one thread; do not use a handle
/// after deletion. Copy borrowed snapshot text before the next snapshot or delete.
#[no_mangle]
pub unsafe extern "C" fn bup_start(handle: *mut std::ffi::c_void, request: *const c_char) -> i64 {
    if handle.is_null() {
        return 0;
    }
    std::panic::catch_unwind(|| {
        let handle = &*(handle as *mut Handle);
        let action = match checked_text(request).and_then(|text| {
            serde_json::from_str::<Action>(text).map_err(|_| "Malformed updater action".into())
        }) {
            Ok(a) => a,
            Err(_) => return 0,
        };
        let session = &handle.session;
        if session
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return 0;
        }
        session.cancel.store(false, Ordering::Release);
        {
            let mut data = lock(session);
            data.snapshot.state = match &action {
                Action::Check {} => "checking",
                Action::LoadManifest { .. } => "checking",
                Action::Download {} => "downloading",
                Action::Adopt { .. } => "verifying",
                Action::Verify { .. } => "verifying",
                Action::Save { .. } => "saving",
                Action::Prepare { .. } => "preparing",
                Action::Install { .. } => "handing_off",
                Action::Rollback { .. } => "rolling_back",
                Action::Confirm { .. } => "confirming",
                Action::Recover { .. } => "recovering",
                Action::Inspect { .. } => "inspecting",
            }
            .into();
            data.snapshot.busy = true;
            data.snapshot.error.clear();
            data.snapshot.bytes = 0;
            data.snapshot.total = 0;
        }
        let worker = session.clone();
        let started = std::thread::Builder::new()
            .name("buoy-updater".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    execute(&worker, action)
                }))
                .unwrap_or_else(|_| Err("Updater worker failed".into()));
                {
                    let mut data = lock(&worker);
                    if let Err(error) = result {
                        data.snapshot.state = if error == "cancelled" {
                            "cancelled"
                        } else {
                            "failed"
                        }
                        .into();
                        data.snapshot.error = error;
                    }
                    worker.busy.store(false, Ordering::Release);
                    data.snapshot.busy = false;
                }
            });
        if started.is_err() {
            session.busy.store(false, Ordering::Release);
            let mut data = lock(session);
            data.snapshot.busy = false;
            data.snapshot.state = "failed".into();
            data.snapshot.error = "Cannot start updater worker".into();
            return 0;
        }
        1
    })
    .unwrap_or(0)
}
/// # Safety
/// Non-null pointers must refer to live handles or NUL-terminated input buffers
/// created for this API. Confine handle access to one thread; do not use a handle
/// after deletion. Copy borrowed snapshot text before the next snapshot or delete.
#[no_mangle]
pub unsafe extern "C" fn bup_snapshot(handle: *mut std::ffi::c_void) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let handle = &mut *(handle as *mut Handle);
    let snapshot = lock(&handle.session).snapshot.clone();
    handle.text =
        CString::new(serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into())).unwrap();
    handle.text.as_ptr()
}
/// # Safety
/// Non-null pointers must refer to live handles or NUL-terminated input buffers
/// created for this API. Confine handle access to one thread; do not use a handle
/// after deletion. Copy borrowed snapshot text before the next snapshot or delete.
#[no_mangle]
pub unsafe extern "C" fn bup_cancel(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        (&*(handle as *mut Handle))
            .session
            .cancel
            .store(true, Ordering::Release);
    }
}
/// # Safety
/// Non-null pointers must refer to live handles or NUL-terminated input buffers
/// created for this API. Confine handle access to one thread; do not use a handle
/// after deletion. Copy borrowed snapshot text before the next snapshot or delete.
#[no_mangle]
pub unsafe extern "C" fn bup_delete(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        let handle = Box::from_raw(handle as *mut Handle);
        handle.session.cancel.store(true, Ordering::Release);
    }
}
