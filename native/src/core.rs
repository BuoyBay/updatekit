//! Authenticated update discovery and bounded, origin-scoped downloads.
use crate::model::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, LOCATION};
use semver::Version;
use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

const METADATA_LIMIT: usize = 4 * 1024 * 1024;
const DISCOVERY_LIMIT: usize = 64 * 1024 * 1024;
const MAX_PAGES: usize = 100;
const MAX_REDIRECTS: usize = 5;

// Deserialize recursively before converting into the contract types: serde_json's
// Value parser otherwise silently overwrites duplicate object members.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut map = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if map.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let Unique(value) = a.next_value()?;
                    map.insert(key, value);
                }
                Ok(Unique(Value::Object(map)))
            }
        }
        d.deserialize_any(V)
    }
}
fn json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let Unique(value) = serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    serde_json::from_value(value).map_err(|e| format!("invalid metadata: {e}"))
}
fn checked_url(config: &Config, raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| "invalid URL")?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false, // Numeric loopback only: no DNS rebinding of localhost.
    };
    if !(url.scheme() == "https"
        || (url.scheme() == "http" && config.allow_http_loopback && loopback))
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("URL must use HTTPS (or explicitly enabled numeric loopback HTTP), without credentials or fragment".into());
    }
    Ok(url)
}
fn key(config: &Config) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(&config.public_key)
        .map_err(|_| "invalid public key hex")?
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 public key")?;
    if key.is_weak() {
        return Err("weak Ed25519 public key".into());
    }
    Ok(key)
}
fn source(config: &Config) -> (&str, &str) {
    match &config.source {
        Source::Manifest { url, token } => (url, token),
        Source::Github { api_url, token, .. } => (api_url, token),
    }
}
pub fn validate_config(config: &Config) -> Result<()> {
    if [
        &config.app_id,
        &config.platform,
        &config.arch,
        &config.channel,
    ]
    .iter()
    .any(|s| s.trim().is_empty())
    {
        return Err("app_id, platform, arch and channel are required".into());
    }
    Version::parse(&config.current_version).map_err(|_| "invalid current version")?;
    key(config)?;
    if config.timeout_seconds == 0
        || config.timeout_seconds > 3600
        || config.max_download_bytes == 0
        || config.max_download_bytes > 9007199254740991
        || config.minimum_sequence > 9007199254740991
    {
        return Err("timeout must be 1..3600 seconds and download limit must be positive".into());
    }
    let (raw, token) = source(config);
    let url = checked_url(config, raw)?;
    reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "invalid token header")?;
    if let Source::Github {
        owner,
        repository,
        manifest_asset,
        max_releases,
        ..
    } = &config.source
    {
        for component in [owner, repository] {
            if component.is_empty()
                || component == "."
                || component == ".."
                || !component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err("invalid GitHub owner or repository".into());
            }
        }
        if manifest_asset.is_empty()
            || url.query().is_some()
            || *max_releases == 0
            || *max_releases > 10000
        {
            return Err("invalid GitHub source".into());
        }
    }
    Ok(())
}
fn client(config: &Config) -> Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(config.timeout_seconds))
        .connect_timeout(Duration::from_secs(config.timeout_seconds.min(10)))
        .user_agent("buoy-updatekit/0.1")
        .build()
        .map_err(|_| "cannot initialize HTTP client".into())
}
fn get(
    config: &Config,
    client: &Client,
    raw: &str,
    binary: bool,
    cancel: &Arc<AtomicBool>,
) -> Result<Response> {
    let mut url = checked_url(config, raw)?;
    let (origin, token) = source(config);
    let origin = checked_url(config, origin)?.origin();
    let mut authenticated = url.origin() == origin;
    for hop in 0..=MAX_REDIRECTS {
        cancelled(cancel)?;
        let mut request = client.get(url.clone()).header(
            ACCEPT,
            if binary {
                "application/octet-stream"
            } else {
                "application/json"
            },
        );
        if authenticated && !token.is_empty() {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request.send().map_err(|_| "HTTP request failed")?;
        cancelled(cancel)?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if hop == MAX_REDIRECTS {
                return Err("too many redirects".into());
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("invalid redirect location")?;
            let next = url.join(location).map_err(|_| "invalid redirect URL")?;
            let next = checked_url(config, next.as_str())?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err("HTTPS downgrade redirect".into());
            }
            authenticated &= next.origin() == origin;
            url = next;
        } else if response.status() == reqwest::StatusCode::OK {
            return Ok(response);
        } else {
            return Err(format!(
                "unexpected HTTP status {}",
                response.status().as_u16()
            ));
        }
    }
    unreachable!()
}
fn metadata(
    config: &Config,
    client: &Client,
    url: &str,
    binary: bool,
    cancel: &Arc<AtomicBool>,
    budget: &mut usize,
) -> Result<Vec<u8>> {
    let mut response = get(config, client, url, binary, cancel)?;
    let limit = METADATA_LIMIT.min(*budget);
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err("metadata size limit exceeded".into());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0; 16384];
    loop {
        cancelled(cancel)?;
        let n = response
            .read(&mut buffer)
            .map_err(|_| "metadata read failed")?;
        cancelled(cancel)?;
        if n == 0 {
            break;
        }
        if n > limit - bytes.len() {
            return Err("metadata size limit exceeded".into());
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    *budget -= bytes.len();
    Ok(bytes)
}
fn authenticate(config: &Config, envelope: &Envelope) -> Result<Manifest> {
    validate_config(config)?;
    if envelope.payload.len() > METADATA_LIMIT || envelope.signature.len() != 128 {
        return Err("invalid envelope size".into());
    }
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| "invalid payload base64")?;
    let signature = hex::decode(&envelope.signature).map_err(|_| "invalid signature hex")?;
    let signature = Signature::from_slice(&signature).map_err(|_| "invalid signature length")?;
    key(config)?
        .verify_strict(&payload, &signature)
        .map_err(|_| "signature verification failed")?;
    let manifest: Manifest = json(&payload)?;
    if manifest.schema != 1
        || manifest.app_id != config.app_id
        || manifest.sequence > 9007199254740991
        || manifest.expires > 9007199254740991
    {
        return Err("manifest schema, application or numeric range rejected".into());
    }
    Ok(manifest)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock before Unix epoch")?
        .as_secs())
}
pub fn verify_envelope(config: &Config, envelope: &Envelope) -> Result<Manifest> {
    let manifest = authenticate(config, envelope)?;
    if manifest.sequence < config.minimum_sequence || manifest.expires <= now()? {
        return Err("manifest sequence or expiry rejected".into());
    }
    Ok(manifest)
}
pub fn select(config: &Config, envelope: &Envelope) -> Result<Option<Selection>> {
    let manifest = verify_envelope(config, envelope)?;
    let current = Version::parse(&config.current_version).map_err(|_| "invalid current version")?;
    let mut best: Option<(Version, Selection)> = None;
    for release in manifest.releases {
        let Ok(version) = Version::parse(&release.version) else { continue; };
        if release.channel != config.channel
            || !version.cmp_precedence(&current).is_gt()
            || (config.channel == "stable" && !version.pre.is_empty())
        {
            continue;
        }
        let mut targets = HashSet::new();
        for asset in release.assets {
            if !targets.insert((asset.platform.clone(), asset.arch.clone())) {
                return Err("ambiguous assets for release target".into());
            }
            if asset.platform != config.platform || asset.arch != config.arch {
                continue;
            }
            validate_asset(config, &asset)?;
            if best
                .as_ref()
                .is_none_or(|(v, _)| version.cmp_precedence(v).is_gt())
            {
                best = Some((
                    version.clone(),
                    Selection {
                        version: release.version.clone(),
                        notes: release.notes.clone(),
                        sequence: manifest.sequence,
                        asset,
                        envelope: envelope.clone(),
                    },
                ));
            }
        }
    }
    Ok(best.map(|(_, selection)| selection))
}
fn validate_asset(config: &Config, asset: &Asset) -> Result<()> {
    checked_url(config, &asset.url)?;
    if asset.size > config.max_download_bytes {
        return Err("asset exceeds download limit".into());
    }
    digest(asset)?;
    Ok(())
}
fn digest(asset: &Asset) -> Result<[u8; 32]> {
    hex::decode(&asset.sha256)
        .map_err(|_| "invalid SHA-256 hex")?
        .try_into()
        .map_err(|_| "SHA-256 must be 32 bytes".into())
}
#[derive(Deserialize)]
struct GithubRelease {
    #[serde(default)]
    draft: bool,
    assets: Vec<GithubAsset>,
}
#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    url: String,
}

pub fn check(config: &Config, cancel: &Arc<AtomicBool>) -> Result<Option<Selection>> {
    Ok(check_detailed(config, cancel)?.0)
}
pub fn check_detailed(
    config: &Config,
    cancel: &Arc<AtomicBool>,
) -> Result<(Option<Selection>, u64)> {
    validate_config(config)?;
    cancelled(cancel)?;
    let client = client(config)?;
    let mut budget = DISCOVERY_LIMIT;
    match &config.source {
        Source::Manifest { url, .. } => {
            let envelope = json(&metadata(config, &client, url, false, cancel, &mut budget)?)?;
            let sequence = verify_envelope(config, &envelope)?.sequence;
            let result = select(config, &envelope)?;
            cancelled(cancel)?;
            Ok((result, sequence))
        }
        Source::Github {
            owner,
            repository,
            api_url,
            manifest_asset,
            max_releases,
            ..
        } => {
            let mut best: Option<Selection> = None;
            let mut highest_sequence = 0;
            let mut seen = HashSet::new();
            let mut scanned = 0usize;
            for page in 1..=MAX_PAGES {
                let mut url = checked_url(config, api_url)?;
                url.set_path(&format!(
                    "{}/repos/{owner}/{repository}/releases",
                    url.path().trim_end_matches('/')
                ));
                url.query_pairs_mut()
                    .append_pair("per_page", "100")
                    .append_pair("page", &page.to_string());
                let releases: Vec<GithubRelease> = json(&metadata(
                    config,
                    &client,
                    url.as_str(),
                    false,
                    cancel,
                    &mut budget,
                )?)?;
                let done = releases.len() < 100;
                for release in releases {
                    if scanned >= *max_releases {
                        return Ok((best, highest_sequence));
                    }
                    scanned += 1;
                    if release.draft {
                        continue;
                    }
                    let matches: Vec<_> = release
                        .assets
                        .into_iter()
                        .filter(|a| a.name == *manifest_asset)
                        .collect();
                    if matches.len() > 1 {
                        return Err("duplicate GitHub manifest asset".into());
                    }
                    for asset in matches {
                        if !seen.insert(asset.url.clone()) {
                            continue;
                        }
                        let envelope = json(&metadata(
                            config,
                            &client,
                            &asset.url,
                            true,
                            cancel,
                            &mut budget,
                        )?)?;
                        // Historic releases retain their original manifests. Authenticate
                        // them, but skip expired/replayed publications instead of allowing
                        // old metadata to block an otherwise fresh newer release.
                        let publication = authenticate(config, &envelope)?;
                        if publication.expires <= now()?
                            || publication.sequence < config.minimum_sequence
                        {
                            continue;
                        }
                        let applicable = publication.releases.iter().any(|release| {
                            release.channel == config.channel
                                && Version::parse(&release.version)
                                    .is_ok_and(|v| config.channel != "stable" || v.pre.is_empty())
                                && release.assets.iter().any(|asset| {
                                    asset.platform == config.platform && asset.arch == config.arch
                                })
                        });
                        if !applicable {
                            continue;
                        }
                        highest_sequence = highest_sequence.max(publication.sequence);
                        if best
                            .as_ref()
                            .is_some_and(|old| old.sequence < highest_sequence)
                        {
                            best = None;
                        }
                        if let Some(selection) = select(config, &envelope)? {
                            if selection.sequence < highest_sequence {
                                continue;
                            }
                            let replace = match &best {
                                None => true,
                                Some(old) => Version::parse(&selection.version)
                                    .unwrap()
                                    .cmp_precedence(&Version::parse(&old.version).unwrap())
                                    .is_gt(),
                            };
                            if replace {
                                best = Some(selection);
                            }
                        }
                    }
                }
                cancelled(cancel)?;
                if done {
                    return Ok((best, highest_sequence));
                }
            }
            Err("GitHub pagination limit exceeded".into())
        }
    }
}
pub fn download(
    config: &Config,
    selection: &Selection,
    cancel: &Arc<AtomicBool>,
    progress: &Progress,
) -> Result<Downloaded> {
    cancelled(cancel)?;
    let verified = select(config, &selection.envelope)?.ok_or("selection is no longer eligible")?;
    // Compare all selection fields, including notes and asset entry/format, to
    // authenticated metadata; callers cannot substitute a URL or install path.
    if serde_json::to_value(&verified).map_err(|e| e.to_string())?
        != serde_json::to_value(selection).map_err(|e| e.to_string())?
    {
        return Err("selection does not match authenticated metadata".into());
    }
    let asset = &selection.asset;
    let client = client(config)?;
    let mut response = get(config, &client, &asset.url, true, cancel)?;
    if response.content_length().is_some_and(|n| n != asset.size) {
        return Err("asset content length mismatch".into());
    }
    let directory = private_tempdir()?;
    let path = directory.path().join("payload");
    let mut file = File::create(&path).map_err(|_| "cannot create download file")?;
    let mut total = 0u64;
    let mut buffer = [0; 65536];
    progress(0, asset.size);
    loop {
        cancelled(cancel)?;
        let n = response
            .read(&mut buffer)
            .map_err(|_| "asset read failed")?;
        cancelled(cancel)?;
        if n == 0 {
            break;
        }
        if n as u64 > asset.size - total {
            return Err("asset exceeds declared size".into());
        }
        file.write_all(&buffer[..n])
            .map_err(|_| "asset write failed")?;
        total += n as u64;
        progress(total, asset.size);
    }
    if total != asset.size {
        return Err("asset size mismatch".into());
    }
    file.sync_all().map_err(|_| "cannot flush download")?;
    drop(file);
    verify_file(&path, asset, cancel)?;
    Ok(Downloaded {
        directory,
        path,
        selection: selection.clone(),
    })
}
pub fn verify_file(path: &Path, asset: &Asset, cancel: &Arc<AtomicBool>) -> Result<()> {
    cancelled(cancel)?;
    let mut file = open_regular(path)?;
    verify_open_file(&mut file, asset, cancel)
}
/// Open without blocking on FIFOs or following a substituted final symlink.
pub fn open_regular(path: &Path) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|_| "cannot open regular asset")?;
    if !file.metadata().map_err(|_| "cannot stat asset")?.is_file() {
        return Err("asset is not a regular file".into());
    }
    Ok(file)
}
pub fn verify_open_file(file: &mut File, asset: &Asset, cancel: &Arc<AtomicBool>) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    cancelled(cancel)?;
    let expected = digest(asset)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot seek asset")?;
    let metadata = file.metadata().map_err(|_| "cannot stat asset")?;
    if !metadata.is_file() || metadata.len() != asset.size {
        return Err("asset size or file type mismatch".into());
    }
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0; 65536];
    loop {
        cancelled(cancel)?;
        let n = file.read(&mut buffer).map_err(|_| "asset read failed")?;
        if n == 0 {
            break;
        }
        if n as u64 > asset.size - total {
            return Err("asset exceeds declared size".into());
        }
        total += n as u64;
        hash.update(&buffer[..n]);
    }
    cancelled(cancel)?;
    if total != asset.size || hash.finalize().as_slice() != expected {
        return Err("asset size or SHA-256 mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        net::TcpListener,
        sync::{atomic::Ordering, Mutex},
        thread,
    };

    fn config() -> Config {
        Config {
            app_id: "example.app".into(),
            current_version: "1.0.0".into(),
            platform: "linux".into(),
            arch: "x86_64".into(),
            channel: "stable".into(),
            source: Source::Manifest {
                url: "https://updates.example/manifest".into(),
                token: String::new(),
            },
            public_key: hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            allow_http_loopback: false,
            timeout_seconds: 2,
            max_download_bytes: 1024,
            minimum_sequence: 3,
        }
    }
    fn cancel() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
    fn asset() -> Asset {
        Asset {
            platform: "linux".into(),
            arch: "x86_64".into(),
            url: "https://updates.example/app".into(),
            size: 3,
            sha256: hex::encode(Sha256::digest(b"abc")),
            format: "raw".into(),
            entry: String::new(),
        }
    }
    fn manifest() -> Manifest {
        Manifest {
            schema: 1,
            app_id: "example.app".into(),
            sequence: 3,
            expires: now().unwrap() + 86400,
            releases: vec![Release {
                version: "2.0.0".into(),
                channel: "stable".into(),
                notes: "fixture".into(),
                assets: vec![asset()],
            }],
        }
    }
    fn sign_bytes(payload: &[u8]) -> Envelope {
        Envelope {
            payload: STANDARD.encode(payload),
            signature: hex::encode(SigningKey::from_bytes(&[7; 32]).sign(payload).to_bytes()),
        }
    }
    fn sign(m: &Manifest) -> Envelope {
        sign_bytes(&serde_json::to_vec(m).unwrap())
    }
    // Local fixtures use literal numeric loopback and one connection per response.
    fn serve(responses: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
        serve_with(|_| responses)
    }
    fn serve_with(
        build: impl FnOnce(&str) -> Vec<String>,
    ) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let responses = build(&url);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let handle = thread::spawn(move || {
            for response in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "fixture never requested"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                // Winsock may inherit the listener's nonblocking mode.
                // The fixture uses blocking reads with a bounded timeout.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 65536);
                }
                received
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (url, requests, handle)
    }
    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
    fn local_config(url: &str) -> Config {
        let mut c = config();
        c.allow_http_loopback = true;
        c.source = Source::Manifest {
            url: url.into(),
            token: "secret-fixture".into(),
        };
        c
    }
    #[test]
    fn signed_envelope_and_policy() {
        let c = config();
        let m = manifest();
        assert_eq!(verify_envelope(&c, &sign(&m)).unwrap().sequence, 3);
        for changed in [
            Manifest {
                schema: 2,
                ..manifest()
            },
            Manifest {
                app_id: "other".into(),
                ..manifest()
            },
            Manifest {
                sequence: 2,
                ..manifest()
            },
            Manifest {
                expires: 1,
                ..manifest()
            },
        ] {
            assert!(verify_envelope(&c, &sign(&changed)).is_err());
        }
        let mut envelope = sign(&m);
        envelope.payload = STANDARD.encode(b"{}");
        assert!(verify_envelope(&c, &envelope).is_err());
        let mut c = c;
        c.public_key = hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert!(verify_envelope(&c, &sign(&m)).is_err());
    }
    #[test]
    fn rejects_duplicate_keys_recursively_and_trailing_json() {
        for raw in [r#"{"a":1,"a":2}"#, r#"{"x":[{"a":1,"\u0061":2}]}"#, "{} {}"] {
            assert!(json::<Value>(raw.as_bytes()).is_err());
        }
        let raw = serde_json::to_string(&manifest()).unwrap().replacen(
            "\"schema\":1",
            "\"schema\":1,\"schema\":1",
            1,
        );
        assert!(verify_envelope(&config(), &sign_bytes(raw.as_bytes()))
            .unwrap_err()
            .contains("duplicate"));
        assert!(json::<Envelope>(br#"{"payload":"a","signature":"b","payload":"c"}"#).is_err());
    }
    #[test]
    fn highest_compatible_semver_and_exact_channel() {
        let mut m = manifest();
        for (version, channel, arch) in [
            ("10.0.0", "stable", "x86_64"),
            ("11.0.0", "Stable", "x86_64"),
            ("20.0.0", "stable", "arm64"),
            ("9.9.9", "stable", "x86_64"),
            ("10.0.0-rc.1", "stable", "x86_64"),
        ] {
            let mut a = asset();
            a.arch = arch.into();
            m.releases.push(Release {
                version: version.into(),
                channel: channel.into(),
                notes: String::new(),
                assets: vec![a],
            });
        }
        assert_eq!(
            select(&config(), &sign(&m)).unwrap().unwrap().version,
            "10.0.0"
        );
        let mut c = config();
        c.current_version = "10.0.0+local".into();
        assert!(select(&c, &sign(&m)).unwrap().is_none());
    }
    #[test]
    fn url_and_key_validation() {
        let mut c = config();
        for url in [
            "http://updates.example/a",
            "file:///tmp/a",
            "https://user:pass@example.com/a",
            "https://example.com/#x",
            "http://127.0.0.1/a",
        ] {
            assert!(checked_url(&c, url).is_err(), "{url}");
        }
        c.allow_http_loopback = true;
        assert!(checked_url(&c, "http://127.0.0.1/a").is_ok());
        assert!(checked_url(&c, "http://[::1]/a").is_ok());
        assert!(checked_url(&c, "http://localhost/a").is_err());
        c.public_key.clear();
        assert!(validate_config(&c).is_err());
    }
    #[test]
    fn verifies_file_digest_size_and_cancellation() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        let flag = cancel();
        verify_file(f.path(), &asset(), &flag).unwrap();
        let mut a = asset();
        a.sha256 = "00".repeat(32);
        assert!(verify_file(f.path(), &a, &flag).is_err());
        a = asset();
        a.size = 2;
        assert!(verify_file(f.path(), &a, &flag).is_err());
        flag.store(true, Ordering::Relaxed);
        assert_eq!(
            verify_file(f.path(), &asset(), &flag).unwrap_err(),
            "cancelled"
        );
    }
    #[test]
    fn rejects_tampered_selection_before_network() {
        let c = config();
        let s = select(&c, &sign(&manifest())).unwrap().unwrap();
        let mut mutations = vec![s.clone(); 5];
        mutations[0].asset.url = "https://evil.example/a".into();
        mutations[1].asset.entry = "../escape".into();
        mutations[2].version = "99.0.0".into();
        mutations[3].sequence += 1;
        mutations[4].notes = "fake".into();
        for mutation in mutations {
            assert!(download(&c, &mutation, &cancel(), &|_, _| {})
                .unwrap_err()
                .contains("selection"));
        }
    }
    #[test]
    fn redirects_strip_credentials_and_send_octet_stream() {
        let (target, target_requests, target_handle) = serve(vec![ok("abc")]);
        let redirect = format!("HTTP/1.1 302 Found\r\nLocation: {target}/asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (origin, origin_requests, origin_handle) = serve(vec![redirect]);
        let c = local_config(&origin);
        let mut m = manifest();
        m.releases[0].assets[0].url = origin;
        let s = select(&c, &sign(&m)).unwrap().unwrap();
        let result = download(&c, &s, &cancel(), &|_, _| {}).unwrap();
        assert_eq!(std::fs::read(&result.path).unwrap(), b"abc");
        origin_handle.join().unwrap();
        target_handle.join().unwrap();
        assert!(origin_requests.lock().unwrap()[0]
            .to_lowercase()
            .contains("authorization: bearer secret-fixture"));
        let target_request = target_requests.lock().unwrap()[0].to_lowercase();
        assert!(!target_request.contains("authorization:"));
        assert!(target_request.contains("accept: application/octet-stream"));
    }
    #[test]
    fn streamed_overflow_and_progress_cancellation() {
        for (response, should_cancel) in [
            (
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcd".to_string(),
                false,
            ),
            (ok("abc"), true),
        ] {
            let (url, _, handle) = serve(vec![response]);
            let c = local_config(&url);
            let mut m = manifest();
            m.releases[0].assets[0].url = url;
            let s = select(&c, &sign(&m)).unwrap().unwrap();
            let flag = cancel();
            let callback_flag = flag.clone();
            let err = download(&c, &s, &flag, &move |_, _| {
                if should_cancel {
                    callback_flag.store(true, Ordering::Relaxed);
                }
            })
            .unwrap_err();
            assert!(
                err.contains(if should_cancel {
                    "cancelled"
                } else {
                    "declared size"
                }),
                "{err}"
            );
            handle.join().unwrap();
        }
    }
    #[test]
    fn metadata_cap_and_redirect_bound() {
        let (url, _, handle) = serve(vec![format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            METADATA_LIMIT + 1
        )]);
        assert!(check(&local_config(&url), &cancel())
            .unwrap_err()
            .contains("size limit"));
        handle.join().unwrap();
        let response = "HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
        let (url, _, handle) = serve(vec![response; MAX_REDIRECTS + 1]);
        assert!(check(&local_config(&url), &cancel())
            .unwrap_err()
            .contains("too many redirects"));
        handle.join().unwrap();
    }
    #[test]
    fn github_paginates_and_fetches_exact_private_manifest_asset() {
        let envelope = serde_json::to_string(&sign(&manifest())).unwrap();
        let first: Vec<_> = (0..100)
            .map(|_| serde_json::json!({"draft": false, "assets": []}))
            .collect();
        let (url, requests, handle) = serve_with(|origin| {
            let second = serde_json::json!([{"draft":false,"assets":[
                {"name":"update-manifest.json.bak","url":"https://invalid.example/no"},
                {"name":"update-manifest.json","url":format!("{origin}/private-asset")}
            ]}]);
            vec![
                ok(&serde_json::to_string(&first).unwrap()),
                ok(&second.to_string()),
                ok(&envelope),
            ]
        });
        let mut c = local_config(&url);
        c.source = Source::Github {
            owner: "owner".into(),
            repository: "repo".into(),
            api_url: url,
            manifest_asset: "update-manifest.json".into(),
            token: "secret-fixture".into(),
            max_releases: 200,
        };
        assert_eq!(check(&c, &cancel()).unwrap().unwrap().version, "2.0.0");
        handle.join().unwrap();
        let requests = requests.lock().unwrap();
        assert!(requests[0].contains("/repos/owner/repo/releases?per_page=100&page=1"));
        assert!(requests[1].contains("page=2"));
        let req = requests[2].to_lowercase();
        assert!(req.contains("accept: application/octet-stream"));
        assert!(req.contains("authorization: bearer secret-fixture"));
    }
    #[test]
    fn stable_channel_skips_prereleases_and_rejects_ambiguous_assets() {
        let mut m = manifest();
        m.releases[0].version = "99.0.0-rc.1".into();
        assert!(select(&config(), &sign(&m)).unwrap().is_none());
        m.releases[0].version = "2.0.0".into();
        m.releases[0].assets.push(asset());
        assert!(select(&config(), &sign(&m))
            .unwrap_err()
            .contains("ambiguous"));
    }
    #[test]
    fn github_ignores_authenticated_stale_history() {
        let fresh = serde_json::to_string(&sign(&manifest())).unwrap();
        let mut old = manifest();
        old.expires = 1;
        old.sequence = 1;
        let stale = serde_json::to_string(&sign(&old)).unwrap();
        let (url, _, handle) = serve_with(|origin| {
            let releases = serde_json::json!([
                {"assets":[{"name":"update-manifest.json","url":format!("{origin}/new")}]},
                {"assets":[{"name":"update-manifest.json","url":format!("{origin}/old")}]}
            ]);
            vec![ok(&releases.to_string()), ok(&fresh), ok(&stale)]
        });
        let mut c = local_config(&url);
        c.source = Source::Github {
            owner: "owner".into(),
            repository: "repo".into(),
            api_url: url,
            manifest_asset: "update-manifest.json".into(),
            token: String::new(),
            max_releases: 200,
        };
        assert_eq!(check(&c, &cancel()).unwrap().unwrap().version, "2.0.0");
        handle.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("fifo");
        let raw = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        assert!(verify_file(&fifo, &asset(), &cancel()).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn github_floor_is_consistent_with_target_selection() {
        let mut arm = manifest();
        arm.sequence = 12;
        arm.releases[0].assets[0].arch = "arm64".into();
        let mut x86 = manifest();
        x86.sequence = 11;
        let arm = serde_json::to_string(&sign(&arm)).unwrap();
        let x86 = serde_json::to_string(&sign(&x86)).unwrap();
        let (url, _, handle) = serve_with(|origin| {
            let releases = serde_json::json!([
                {"assets":[{"name":"update-manifest.json","url":format!("{origin}/arm")}]},
                {"assets":[{"name":"update-manifest.json","url":format!("{origin}/x86")}]}
            ]);
            vec![ok(&releases.to_string()), ok(&arm), ok(&x86)]
        });
        let mut c = local_config(&url);
        c.source = Source::Github {
            owner: "owner".into(),
            repository: "repo".into(),
            api_url: url,
            manifest_asset: "update-manifest.json".into(),
            token: String::new(),
            max_releases: 200,
        };
        let (selection, floor) = check_detailed(&c, &cancel()).unwrap();
        assert_eq!(floor, 11);
        c.minimum_sequence = floor;
        verify_envelope(&c, &selection.unwrap().envelope).unwrap();
        handle.join().unwrap();
    }
    #[test]
    fn github_history_limit_bounds_public_requests() {
        let fresh = serde_json::to_string(&sign(&manifest())).unwrap();
        let (url, requests, handle) = serve_with(|origin| {
            let releases = serde_json::json!([
                {"assets":[{"name":"update-manifest.json","url":format!("{origin}/fresh")}]},
                {"assets":[{"name":"update-manifest.json","url":"https://invalid.example/must-not-fetch"}]}
            ]);
            vec![ok(&releases.to_string()), ok(&fresh)]
        });
        let mut c = local_config(&url);
        c.source = Source::Github {
            owner: "owner".into(),
            repository: "repo".into(),
            api_url: url,
            manifest_asset: "update-manifest.json".into(),
            token: String::new(),
            max_releases: 1,
        };
        assert!(check(&c, &cancel()).unwrap().is_some());
        handle.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}
