//! Signed, fixed-origin updates. No runtime endpoint or payload-path input.
#![cfg_attr(not(windows), allow(dead_code))]
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

#[path = "updater/delivery.rs"]
mod delivery;
#[path = "updater/health.rs"]
mod health;
pub(crate) mod interlock;
#[path = "updater/tray_cmd.rs"]
mod tray_cmd;
pub use health::{health, MonitorHealth, TaskHealth, UpdateHealth};

#[cfg(target_os = "linux")]
#[path = "updater/linux.rs"]
pub mod linux;
#[cfg(windows)]
#[path = "updater/windows.rs"]
mod windows;
/// Fixed at compile time: each build reads only its own operating system's and
/// architecture's feed.
#[cfg(all(
    target_arch = "aarch64",
    not(any(target_os = "linux", target_os = "macos"))
))]
mod arch {
    pub const TARGET: &str = "windows-aarch64";
    #[cfg(test)]
    pub const OTHER_TARGET: &str = "windows-x86_64";
    pub const SETUP_TAG: &str = "windows-arm64";
    pub const SETUP_SUFFIXES: &[&str] = &["-setup.exe"];
    pub const STABLE_FEED: &str = "releases/stable-arm64.json";
    pub const CANDIDATE_FEED: &str = "releases/candidate-arm64.json";
    pub const DELIVERY_FEED: &str = "releases/delivery-arm64.json";
    pub const DELIVERY_FLOOR: &str = "delivery-floor-arm64.json";
}
#[cfg(all(
    not(target_arch = "aarch64"),
    not(any(target_os = "linux", target_os = "macos"))
))]
mod arch {
    pub const TARGET: &str = "windows-x86_64";
    #[cfg(test)]
    pub const OTHER_TARGET: &str = "windows-aarch64";
    pub const SETUP_TAG: &str = "windows-x64";
    pub const SETUP_SUFFIXES: &[&str] = &["-setup.exe"];
    pub const STABLE_FEED: &str = "releases/stable.json";
    pub const CANDIDATE_FEED: &str = "releases/candidate.json";
    pub const DELIVERY_FEED: &str = "releases/delivery.json";
    pub const DELIVERY_FLOOR: &str = "delivery-floor.json";
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod arch {
    pub const TARGET: &str = "linux-aarch64";
    #[cfg(test)]
    pub const OTHER_TARGET: &str = "linux-x86_64";
    pub const SETUP_TAG: &str = "linux-arm64";
    pub const SETUP_SUFFIXES: &[&str] = &[".deb", ".rpm"];
    pub const STABLE_FEED_DEB: &str = "releases/stable-linux-arm64-deb.json";
    pub const STABLE_FEED_RPM: &str = "releases/stable-linux-arm64-rpm.json";
    pub const CANDIDATE_FEED: &str = "releases/candidate-linux-arm64.json";
    pub const DELIVERY_FEED: &str = "releases/delivery-linux-arm64.json";
    pub const DELIVERY_FLOOR: &str = "delivery-floor-linux-arm64.json";
}
#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
mod arch {
    pub const TARGET: &str = "linux-x86_64";
    #[cfg(test)]
    pub const OTHER_TARGET: &str = "linux-aarch64";
    pub const SETUP_TAG: &str = "linux-x64";
    pub const SETUP_SUFFIXES: &[&str] = &[".deb", ".rpm"];
    pub const STABLE_FEED_DEB: &str = "releases/stable-linux-x64-deb.json";
    pub const STABLE_FEED_RPM: &str = "releases/stable-linux-x64-rpm.json";
    pub const CANDIDATE_FEED: &str = "releases/candidate-linux-x64.json";
    pub const DELIVERY_FEED: &str = "releases/delivery-linux-x64.json";
    pub const DELIVERY_FLOOR: &str = "delivery-floor-linux-x64.json";
}
#[cfg(target_os = "macos")]
mod arch {
    pub const TARGET: &str = "macos-universal";
    #[cfg(test)]
    pub const OTHER_TARGET: &str = "linux-x86_64";
    pub const SETUP_TAG: &str = "macos-universal";
    pub const SETUP_SUFFIXES: &[&str] = &[".dmg"];
    pub const STABLE_FEED: &str = "releases/stable-macos.json";
    pub const CANDIDATE_FEED: &str = "releases/candidate-macos.json";
    pub const DELIVERY_FEED: &str = "releases/delivery-macos.json";
    pub const DELIVERY_FLOOR: &str = "delivery-floor-macos.json";
}
// The highest-seen floor is shared by every build on one computer, so moving from
// the x64 build to the native arm64 build keeps its history.
fn known_target(target: &str) -> bool {
    matches!(
        target,
        "windows-x86_64" | "windows-aarch64" | "linux-x86_64" | "linux-aarch64" | "macos-universal"
    )
}
/// The first name this build accepts.
#[cfg(test)]
fn setup_filename(version: &str) -> String {
    format!(
        "secblitz-{version}-{}{}",
        arch::SETUP_TAG,
        arch::SETUP_SUFFIXES[0]
    )
}
fn is_setup_filename(version: &str, filename: &str) -> bool {
    arch::SETUP_SUFFIXES
        .iter()
        .any(|suffix| filename == format!("secblitz-{version}-{}{suffix}", arch::SETUP_TAG))
}
const MANIFEST_LIMIT: usize = 16 * 1024;
const INSTALLER_LIMIT: u64 = 64 * 1024 * 1024;
const SKEW: u64 = 600;
const FLOOR_LIMIT: usize = 4096;

// Separate from display status: a new check must not erase an installer's
// uncertain lifetime or a failed post-install health check. `null` is the
// durably resolved state; missing is allowed only for pre-upgrade installations.
const ATTEMPT_LIMIT: usize = 4096;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InstallPhase {
    Started,
    Exited,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InstallHealth {
    LegacyV1,
    DeliveryV1,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallAttempt {
    schema: u32,
    version: String,
    before: UpdateHealth,
    health: InstallHealth,
    phase: InstallPhase,
}
fn parse_attempt(bytes: &[u8]) -> Result<Option<InstallAttempt>> {
    ensure!(bytes.len() <= ATTEMPT_LIMIT, "Install attempt too large");
    let attempt: Option<InstallAttempt> = serde_json::from_slice(bytes)?;
    if let Some(a) = &attempt {
        ensure!(
            a.schema == 1
                && a.before.schema == 1
                && stable(&a.version)? > stable(&a.before.version)?,
            "Invalid install attempt"
        );
    }
    Ok(attempt)
}
pub(crate) fn install_idle(bytes: &[u8]) -> Result<()> {
    ensure!(
        parse_attempt(bytes)?.is_none(),
        "Deferred: updater installation requires completion/health verification"
    );
    Ok(())
}

/// Read-only interlock for other subsystems. Caller must own and retain the
/// exclusive root engine.lock. Both uncertain setup and unverified zero exits
/// veto other work; only the updater's own recovery path may resolve them.
pub fn ensure_install_idle(shared_engine_lock: &std::fs::File) -> Result<()> {
    #[cfg(windows)]
    {
        windows::ensure_install_idle(shared_engine_lock)
    }
    #[cfg(not(windows))]
    {
        let _ = shared_engine_lock;
        anyhow::bail!("Updater installation interlock requires Windows")
    }
}

// Shared by the three leaf inspectors. Uses existing native paths only; the
// guard keeps the protected base/ancestors pinned for the entire inspection.
#[cfg(windows)]
pub(crate) use windows::LockedEngineRoot;
#[cfg(windows)]
pub(crate) fn inspect_engine_lock(held: &std::fs::File) -> Result<LockedEngineRoot> {
    windows::inspect_engine_lock(held)
}

fn finish_attempt(
    attempt: &InstallAttempt,
    validate: impl FnOnce(&InstallAttempt) -> Result<()>,
    publish: impl FnOnce(&str) -> Result<UpdateOutcome>,
    clear: impl FnOnce() -> Result<()>,
) -> Result<UpdateOutcome> {
    ensure!(attempt.phase == InstallPhase::Exited,
        "Previous installer completion is unconfirmed; retained install-attempt.json requires review");
    validate(attempt)?;
    let outcome = publish(&attempt.version)?;
    clear()?;
    Ok(outcome)
}

// Only staged payloads, never floors, identity or attempt records. The
// running worker is its own image, so only a later check can remove it.
fn leftover_files(attempt: Option<&InstallAttempt>, from_worker: bool) -> &'static [&'static str] {
    match (attempt, from_worker) {
        (Some(_), _) => &[],
        (None, true) => &["update-installer.exe", "update-manifest.json"],
        (None, false) => &[
            "update-installer.exe",
            "update-manifest.json",
            "update-worker.exe",
        ],
    }
}

// Trusted local state, not a new wire format. Freshness applies to incoming
// signed manifests, never to this durable record of previously seen releases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseFloor {
    schema: u32,
    version: String,
    sha256: String,
    target: String,
    published_at: u64,
    expires_at: u64,
}
fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse_floor(bytes: &[u8]) -> Result<ReleaseFloor> {
    ensure!(bytes.len() <= FLOOR_LIMIT, "Release floor too large");
    let floor: ReleaseFloor = serde_json::from_slice(bytes).context("Invalid release floor")?;
    stable(&floor.version)?;
    ensure!(
        floor.schema == 1
            && known_target(&floor.target)
            && valid_hash(&floor.sha256)
            && floor.expires_at > floor.published_at
            && floor.expires_at - floor.published_at <= 90 * 86400,
        "Invalid release floor fields"
    );
    Ok(floor)
}
// m must already have passed verify(). No installed-image hash is invented:
// the release hash identifies the signed installer, not secblitz.exe.
fn advance_floor(
    m: &Manifest,
    current: &str,
    previous: Option<&ReleaseFloor>,
) -> Result<ReleaseFloor> {
    newer(m, current)?;
    if let Some(previous) = previous {
        let version = stable(&m.version)?;
        let seen = stable(&previous.version)?;
        ensure!(version >= seen, "Previously seen release rollback rejected");
        if version == seen && m.target == previous.target {
            ensure!(
                m.sha256 == previous.sha256,
                "Published release content changed"
            );
            ensure!(
                m.published_at >= previous.published_at && m.expires_at >= previous.expires_at,
                "Previously seen release metadata rollback rejected"
            );
        }
    }
    Ok(ReleaseFloor {
        schema: 1,
        version: m.version.clone(),
        sha256: m.sha256.clone(),
        target: m.target.clone(),
        published_at: m.published_at,
        expires_at: m.expires_at,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpdateOutcome {
    NotConfigured,
    UpToDate,
    DeferredBusy,
    DeferredRollout { version: String },
    NotPublished,
    WorkerStarted { version: String },
    Installed { version: String },
    Available { version: String },
    Failed { reason: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateStatus {
    pub checked_at: u64,
    pub result: UpdateOutcome,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    version: String,
    filename: String,
    sha256: String,
    size: u64,
    published_at: u64,
    expires_at: u64,
    target: String,
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System clock precedes Unix epoch")?
        .as_secs())
}
fn origin(text: &str) -> Result<Option<reqwest::Url>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let url = reqwest::Url::parse(text)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && !text.contains('\\'),
        "Invalid compiled update origin"
    );
    Ok(Some(url))
}
fn config() -> Result<Option<reqwest::Url>> {
    origin(
        option_env!("SECBLITZ_UPDATE_ORIGIN")
            .unwrap_or(include_str!("../assets/update-origin.txt")),
    )
}
fn key() -> Result<[u8; 32]> {
    let bytes = hex::decode(include_str!("../assets/update-public-key.hex").trim())
        .context("Invalid embedded update public key")?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        eprintln!("{} bytes", v.len());
        anyhow::anyhow!("Embedded update public key must be 32 bytes")
    })
}
/// The feed answered 404: nothing has been published there. Reads like any other failed request.
#[derive(Debug)]
struct FeedMissing;
impl std::fmt::Display for FeedMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Manifest HTTP request failed")
    }
}
impl std::error::Error for FeedMissing {}
fn fetch_manifest(client: &reqwest::blocking::Client, url: reqwest::Url) -> Result<Vec<u8>> {
    let response = client.get(url).send()?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(FeedMissing.into());
    }
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Manifest HTTP request failed"
    );
    let mut bytes = Vec::new();
    response
        .take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MANIFEST_LIMIT, "Manifest too large");
    Ok(bytes)
}
fn stable(text: &str) -> Result<Version> {
    let v = Version::parse(text)?;
    ensure!(
        v.pre.is_empty() && v.build.is_empty() && v.to_string() == text,
        "Update version must be canonical stable semver"
    );
    Ok(v)
}
fn verify(bytes: &[u8], key: &[u8; 32], time: u64) -> Result<Manifest> {
    let payload = verified_payload(bytes, key)?;
    let m: Manifest = serde_json::from_slice(&payload)?;
    validate_manifest(&m, time)?;
    Ok(m)
}
fn verified_payload(bytes: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= MANIFEST_LIMIT, "Manifest too large");
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    let payload = STANDARD.decode(envelope.payload)?;
    ensure!(payload.len() <= 8192, "Signed payload too large");
    let signature = Signature::from_slice(&STANDARD.decode(envelope.signature)?)?;
    VerifyingKey::from_bytes(key)?
        .verify_strict(&payload, &signature)
        .context("Update signature rejected")?;
    Ok(payload)
}
fn validate_manifest(m: &Manifest, time: u64) -> Result<()> {
    ensure!(
        m.schema == 1 && m.target == arch::TARGET,
        "Unsupported update target/schema"
    );
    stable(&m.version)?;
    ensure!(
        is_setup_filename(&m.version, &m.filename),
        "Invalid installer filename"
    );
    ensure!(valid_hash(&m.sha256), "Invalid SHA-256");
    ensure!(
        m.size > 0 && m.size <= INSTALLER_LIMIT,
        "Invalid installer size"
    );
    ensure!(
        m.published_at <= time.saturating_add(SKEW)
            && m.expires_at > m.published_at
            && m.expires_at - m.published_at <= 90 * 86400
            && time <= m.expires_at.saturating_add(SKEW),
        "Expired update or invalid system clock/validity"
    );
    Ok(())
}
fn newer(m: &Manifest, current: &str) -> Result<bool> {
    let release = stable(&m.version)?;
    let current = stable(current)?;
    ensure!(release >= current, "Update downgrade rejected");
    Ok(release > current)
}
// Buffer before creating any installer file: unverified network bytes never reach disk.
fn installer(mut reader: impl Read, m: &Manifest) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.by_ref().take(m.size + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == m.size, "Installer size mismatch");
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == m.sha256,
        "Installer hash mismatch"
    );
    Ok(bytes)
}
pub fn check_and_stage() -> Result<UpdateOutcome> {
    #[cfg(windows)]
    {
        windows::check_and_stage()
    }
    #[cfg(not(windows))]
    {
        Ok(UpdateOutcome::NotConfigured)
    }
}
pub fn install_staged() -> Result<UpdateOutcome> {
    #[cfg(windows)]
    {
        windows::install_staged()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("Update installation requires Windows")
    }
}
pub fn status() -> Result<UpdateStatus> {
    #[cfg(windows)]
    {
        windows::status()
    }
    #[cfg(target_os = "linux")]
    {
        linux::status(&crate::linux::cmd::RealSys)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Ok(UpdateStatus {
            checked_at: now()?,
            result: UpdateOutcome::NotConfigured,
        })
    }
}

#[cfg(test)]
#[path = "updater/delivery_tests.rs"]
mod delivery_tests;
#[cfg(test)]
#[path = "updater/tests.rs"]
mod tests;
