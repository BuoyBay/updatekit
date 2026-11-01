use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc};

pub type Result<T> = std::result::Result<T, String>;
pub type Progress = dyn Fn(u64, u64) + Send + Sync;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub app_id: String,
    pub current_version: String,
    pub platform: String,
    pub arch: String,
    #[serde(default = "stable")]
    pub channel: String,
    pub source: Source,
    pub public_key: String,
    #[serde(default)]
    pub allow_http_loopback: bool,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "max_size")]
    pub max_download_bytes: u64,
    #[serde(default)]
    pub minimum_sequence: u64,
}
fn stable() -> String {
    "stable".into()
}
fn timeout() -> u64 {
    120
}
fn max_size() -> u64 {
    1024 * 1024 * 1024
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Manifest {
        url: String,
        #[serde(default)]
        token: String,
    },
    Github {
        owner: String,
        repository: String,
        #[serde(default = "api")]
        api_url: String,
        #[serde(default = "manifest_name")]
        manifest_asset: String,
        #[serde(default)]
        token: String,
        #[serde(default = "history_limit")]
        max_releases: usize,
    },
}
fn history_limit() -> usize {
    20
}
fn api() -> String {
    "https://api.github.com".into()
}
fn manifest_name() -> String {
    "update-manifest.json".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u64,
    pub app_id: String,
    pub sequence: u64,
    pub expires: u64,
    pub releases: Vec<Release>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub version: String,
    #[serde(default = "stable")]
    pub channel: String,
    #[serde(default)]
    pub notes: String,
    pub assets: Vec<Asset>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub platform: String,
    pub arch: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    #[serde(default)]
    pub entry: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Selection {
    pub version: String,
    pub notes: String,
    pub sequence: u64,
    pub asset: Asset,
    pub envelope: Envelope,
}
#[derive(Debug)]
pub struct Downloaded {
    pub directory: tempfile::TempDir,
    pub path: PathBuf,
    pub selection: Selection,
}
pub fn cancelled(cancel: &Arc<AtomicBool>) -> Result<()> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        Err("cancelled".into())
    } else {
        Ok(())
    }
}

/// A private temporary directory; tempfile's default follows the process umask.
pub fn private_tempdir() -> Result<tempfile::TempDir> {
    let parent = std::env::temp_dir();
    #[cfg(windows)]
    crate::security_windows::validate_private(&parent)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix("buoy-update-download-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let directory = builder
        .tempdir_in(&parent)
        .map_err(|_| "cannot create private download directory")?;
    #[cfg(windows)]
    crate::security_windows::validate_private(directory.path())?;
    Ok(directory)
}
