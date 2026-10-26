//! Updates on Linux. The background check runs as root, verifies the signed feed with the same rules as on Windows and
//! keeps its result in the private `Updates` folder. When the Secblitz repository is set up, the system's software
//! updater installs the new version; otherwise the helper installs the package the feed names, after checking its size
//! and hash against the signed feed.
use super::*;
use crate::linux::cmd::Sys;
use anyhow::bail;
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const FOLDER: &str = "Updates";
const STATUS: &str = "update-status.json";
const FLOOR: &str = "release-floor.json";
const LOCK: &str = "update.lock";

pub const APT_SOURCE: &str = "/etc/apt/sources.list.d/secblitz.sources";
pub const DNF_SOURCE: &str = "/etc/yum.repos.d/secblitz.repo";
pub const TIMER: &str = "secblitz-monitor.timer";

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const APT_GET: &str = "/usr/bin/apt-get";
const DNF: &str = "/usr/bin/dnf";
const INSTALL_UNIT: &str = "--unit=secblitz-update";

pub const NOT_ROOT: &str = "Secblitz's background check only runs as part of the system.";
pub const BY_SOFTWARE_APP: &str =
    "Your software app keeps Secblitz up to date. Open it and install the waiting update there.";
pub const WRONG_PACKAGE: &str = "This update is not made for your kind of Linux. Download the latest Secblitz from our website.";
pub const ALREADY_INSTALLING: &str =
    "Secblitz is already installing an update. Give it a few minutes.";
pub const START_FAILED: &str = "Secblitz could not start the update. Try again, or download the latest Secblitz from our website.";
pub const TIMER_FAILED: &str =
    "Secblitz could not change the background check. Try again in a moment.";
pub const BUSY: &str = "Secblitz is already looking for updates. Try again in a moment.";
const CHECK_FAILED: &str = "Update check failed";

/// Every sentence this file can show a person, for the translation tests.
pub const SENTENCES: [&str; 7] = [
    NOT_ROOT,
    BY_SOFTWARE_APP,
    WRONG_PACKAGE,
    ALREADY_INSTALLING,
    START_FAILED,
    TIMER_FAILED,
    BUSY,
];

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn require_root() -> Result<()> {
    ensure!(is_root(), NOT_ROOT);
    Ok(())
}

/// The private folder for update state, made when it is missing. It is trusted only after the same ownership and
/// permission checks as the state folder itself.
fn folder_at(state: &Path, owner_uid: u32, trusted_root: &Path) -> Result<PathBuf> {
    let dir = state.join(FOLDER);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            crate::platform::unix::create_private_dir(&dir)?
        }
        Err(e) => return Err(e.into()),
    }
    crate::platform::unix::check_private_dir_from(&dir, owner_uid, trusted_root)
        .context("Secblitz cannot trust its update folder, so it will not use it.")?;
    Ok(dir)
}

fn folder() -> Result<PathBuf> {
    folder_at(&crate::platform::state_dir()?, 0, Path::new("/"))
}

/// One check or install at a time. `None` means another one holds the lock.
fn lock(dir: &Path) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(LOCK))
        .context("Cannot open the update lock")?;
    ensure!(file.metadata()?.is_file(), "The update lock is not a file");
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(e) if e.kind() == fs2::lock_contended_error().kind() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn read_floor(sys: &dyn Sys, dir: &Path) -> Result<Option<ReleaseFloor>> {
    sys.read(&dir.join(FLOOR))?
        .map(|bytes| parse_floor(&bytes))
        .transpose()
}

/// Saved before anything is downloaded, so a failed download cannot make the check forget a newer signed release.
fn remember_release(sys: &dyn Sys, dir: &Path, m: &Manifest, current: &str) -> Result<()> {
    let previous = read_floor(sys, dir)?;
    let floor = advance_floor(m, current, previous.as_ref())?;
    if previous.as_ref() != Some(&floor) {
        let bytes = serde_json::to_vec(&floor)?;
        ensure!(bytes.len() <= FLOOR_LIMIT, "Release floor too large");
        sys.write_atomic(&dir.join(FLOOR), &bytes, 0o600)?;
    }
    Ok(())
}

fn record(sys: &dyn Sys, dir: &Path, result: UpdateOutcome, at: u64) -> Result<UpdateOutcome> {
    let status = UpdateStatus {
        checked_at: at,
        result: result.clone(),
    };
    sys.write_atomic(&dir.join(STATUS), &serde_json::to_vec(&status)?, 0o600)?;
    Ok(result)
}

fn read_status(sys: &dyn Sys, dir: &Path) -> Result<UpdateStatus> {
    match sys.read(&dir.join(STATUS))? {
        None => Ok(UpdateStatus {
            checked_at: 0,
            result: UpdateOutcome::NotConfigured,
        }),
        Some(bytes) => {
            ensure!(bytes.len() <= ATTEMPT_LIMIT, "Update status too large");
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
}

/// Verifies the signed feed, keeps the highest release seen and writes what the person should be told.
fn evaluate(
    sys: &dyn Sys,
    dir: &Path,
    feed: &[u8],
    key: &[u8; 32],
    time: u64,
    current: &str,
) -> Result<(Manifest, UpdateOutcome)> {
    let m = verify(feed, key, time)?;
    remember_release(sys, dir, &m, current)?;
    let outcome = if newer(&m, current)? {
        UpdateOutcome::Available {
            version: m.version.clone(),
        }
    } else {
        UpdateOutcome::UpToDate
    };
    record(sys, dir, outcome.clone(), time)?;
    Ok((m, outcome))
}

fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()?)
}

/// The repository file is how the person's software app learns about new versions of Secblitz.
pub fn repository_configured(sys: &dyn Sys) -> bool {
    [APT_SOURCE, DNF_SOURCE]
        .iter()
        .any(|path| matches!(sys.read(Path::new(path)), Ok(Some(_))))
}

/// Looks at the signed feed and records the result. Root only; this is what the daily timer runs.
pub fn check(sys: &dyn Sys) -> Result<UpdateOutcome> {
    let Some(origin) = config()? else {
        return Ok(UpdateOutcome::NotConfigured);
    };
    require_root()?;
    let dir = folder()?;
    let Some(_lock) = lock(&dir)? else {
        return Ok(UpdateOutcome::DeferredBusy);
    };
    let result = (|| {
        let feed = fetch_manifest(&client()?, origin.join(arch::STABLE_FEED)?)?;
        evaluate(sys, &dir, &feed, &key()?, now()?, env!("CARGO_PKG_VERSION"))
            .map(|(_, outcome)| outcome)
    })();
    if result.is_err() {
        let _ = record(
            sys,
            &dir,
            UpdateOutcome::Failed {
                reason: CHECK_FAILED.into(),
            },
            now().unwrap_or(0),
        );
    }
    result
}

/// What the last check found. Root only: the folder is private.
pub fn status(sys: &dyn Sys) -> Result<UpdateStatus> {
    if config()?.is_none() {
        return Ok(UpdateStatus {
            checked_at: now()?,
            result: UpdateOutcome::NotConfigured,
        });
    }
    require_root()?;
    read_status(sys, &folder()?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Package {
    Deb,
    Rpm,
}

impl Package {
    fn of(filename: &str) -> Result<Self> {
        if filename.ends_with(".deb") {
            Ok(Self::Deb)
        } else if filename.ends_with(".rpm") {
            Ok(Self::Rpm)
        } else {
            bail!(WRONG_PACKAGE)
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Self::Deb => APT_GET,
            Self::Rpm => DNF,
        }
    }
}

/// The install runs in a unit of its own, outside the helper: the new package restarts the helper, which would stop an
/// install the helper itself had started.
fn install_args(package: Package, file: &str) -> Vec<&str> {
    let mut args = vec!["--quiet", "--collect", "--no-block", INSTALL_UNIT];
    if package == Package::Deb {
        args.push("--setenv=DEBIAN_FRONTEND=noninteractive");
    }
    args.extend(["--", package.tool(), "install", "-y", file]);
    args
}

fn start_install(sys: &dyn Sys, dir: &Path, m: &Manifest, bytes: &[u8]) -> Result<()> {
    let package = Package::of(&m.filename)?;
    let path = dir.join(&m.filename);
    sys.write_atomic(&path, bytes, 0o600)?;
    let file = path.to_str().context(START_FAILED)?;
    let out = sys.run(SYSTEMD_RUN, &install_args(package, file))?;
    if !out.success() {
        eprintln!("The update could not be started: {}", out.stderr.trim());
        if out.stderr.contains("already") {
            bail!(ALREADY_INSTALLING);
        }
        bail!(START_FAILED);
    }
    Ok(())
}

/// Packages from earlier updates that are no longer needed.
fn clear_old_packages(dir: &Path, keep: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let package =
            name.starts_with("secblitz-") && (name.ends_with(".deb") || name.ends_with(".rpm"));
        if package && name != keep {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn install_from(
    sys: &dyn Sys,
    dir: &Path,
    feed: &[u8],
    key: &[u8; 32],
    time: u64,
    current: &str,
    download: impl FnOnce(&Manifest) -> Result<Box<dyn Read>>,
    tool_present: impl FnOnce(Package) -> bool,
) -> Result<UpdateOutcome> {
    let (m, outcome) = evaluate(sys, dir, feed, key, time, current)?;
    if !matches!(outcome, UpdateOutcome::Available { .. }) {
        return Ok(outcome);
    }
    ensure!(!repository_configured(sys), BY_SOFTWARE_APP);
    let package = Package::of(&m.filename)?;
    if !tool_present(package) {
        bail!(WRONG_PACKAGE);
    }
    let bytes = installer(download(&m)?, &m)?;
    clear_old_packages(dir, &m.filename);
    start_install(sys, dir, &m, &bytes)?;
    record(
        sys,
        dir,
        UpdateOutcome::WorkerStarted {
            version: m.version.clone(),
        },
        time,
    )
}

/// Installs the version the signed feed names when no repository looks after Secblitz. Root only.
pub fn install(sys: &dyn Sys) -> Result<UpdateOutcome> {
    let Some(origin) = config()? else {
        return Ok(UpdateOutcome::NotConfigured);
    };
    require_root()?;
    let dir = folder()?;
    let Some(_lock) = lock(&dir)? else {
        bail!(BUSY);
    };
    let started = Instant::now();
    let client = client()?;
    let feed = fetch_manifest(&client, origin.join(arch::STABLE_FEED)?)?;
    install_from(
        sys,
        &dir,
        &feed,
        &key()?,
        now()?,
        env!("CARGO_PKG_VERSION"),
        |m| {
            let left = Duration::from_secs(120)
                .checked_sub(started.elapsed())
                .context("Update download deadline exceeded")?;
            let response = client
                .get(origin.join(&format!("downloads/{}", m.filename))?)
                .timeout(left)
                .send()?;
            ensure!(
                response.status().is_success(),
                "Installer HTTP request failed"
            );
            Ok(Box::new(response) as Box<dyn Read>)
        },
        |package| Path::new(package.tool()).exists(),
    )
}

/// Turns the daily background check on or off. Both use fixed arguments.
pub fn set_monitor_timer(sys: &dyn Sys, on: bool) -> Result<()> {
    let action = if on { "enable" } else { "disable" };
    let out = sys.run(SYSTEMCTL, &[action, "--now", TIMER])?;
    if !out.success() {
        eprintln!("systemctl {action} failed: {}", out.stderr.trim());
        bail!(TIMER_FAILED);
    }
    Ok(())
}

pub fn monitor_timer_on(sys: &dyn Sys) -> Result<bool> {
    let out = sys.run(SYSTEMCTL, &["is-enabled", TIMER])?;
    Ok(out.success() && out.stdout.trim().starts_with("enabled"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::cmd::fake::FakeSys;
    use ed25519_dalek::{Signer, SigningKey};
    use std::os::unix::fs::PermissionsExt;

    const NOW: u64 = 1500;

    fn package_name(version: &str, suffix: &str) -> String {
        format!("secblitz-{version}-{}{suffix}", arch::SETUP_TAG)
    }

    fn signed_feed(version: &str, suffix: &str, body: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "version": version,
            "filename": package_name(version, suffix),
            "sha256": hex::encode(Sha256::digest(body)),
            "size": body.len(),
            "published_at": 1000,
            "expires_at": 2000,
            "target": arch::TARGET,
        }))
        .unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "payload": STANDARD.encode(&payload),
            "signature": STANDARD.encode(key.sign(&payload).to_bytes()),
        }))
        .unwrap();
        (bytes, key.verifying_key().to_bytes())
    }

    fn reply(sys: &FakeSys, suffix: &str, dir: &Path) {
        let file = dir.join(package_name("9.0.0", suffix));
        let file = file.to_str().unwrap();
        let package = if suffix == ".deb" {
            Package::Deb
        } else {
            Package::Rpm
        };
        sys.reply(SYSTEMD_RUN, &install_args(package, file), 0, "");
    }

    fn body() -> &'static [u8] {
        b"package bytes"
    }

    fn run(
        sys: &FakeSys,
        dir: &Path,
        suffix: &str,
        served: &'static [u8],
        tool: bool,
    ) -> Result<UpdateOutcome> {
        let (feed, key) = signed_feed("9.0.0", suffix, body());
        install_from(
            sys,
            dir,
            &feed,
            &key,
            NOW,
            "1.0.0",
            |_| Ok(Box::new(served) as Box<dyn Read>),
            |_| tool,
        )
    }

    #[test]
    fn a_newer_signed_release_is_recorded_as_waiting() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        let (feed, key) = signed_feed("9.0.0", ".deb", body());
        let (_, outcome) = evaluate(&sys, dir, &feed, &key, NOW, "1.0.0").unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome::Available {
                version: "9.0.0".into()
            }
        );
        let saved = read_status(&sys, dir).unwrap();
        assert_eq!(saved.checked_at, NOW);
        assert_eq!(saved.result, outcome);
        assert!(read_floor(&sys, dir).unwrap().is_some());
        let (_, same) = evaluate(&sys, dir, &feed, &key, NOW, "9.0.0").unwrap();
        assert_eq!(same, UpdateOutcome::UpToDate);
    }

    #[test]
    fn no_status_yet_reads_as_nothing_checked() {
        let sys = FakeSys::default();
        let saved = read_status(&sys, Path::new("/state/Updates")).unwrap();
        assert_eq!(saved.checked_at, 0);
        assert_eq!(saved.result, UpdateOutcome::NotConfigured);
    }

    #[test]
    fn a_feed_with_a_bad_signature_or_an_old_version_changes_nothing() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        let (feed, _) = signed_feed("9.0.0", ".deb", body());
        let other = SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes();
        assert!(evaluate(&sys, dir, &feed, &other, NOW, "1.0.0").is_err());
        assert!(sys.files.borrow().is_empty());
        let (feed, key) = signed_feed("9.0.0", ".deb", body());
        assert!(evaluate(&sys, dir, &feed, &key, 5000, "1.0.0").is_err());
        assert!(sys.files.borrow().is_empty());
        assert!(evaluate(&sys, dir, &feed, &key, NOW, "10.0.0").is_err());
        assert!(sys.files.borrow().is_empty());
    }

    #[test]
    fn a_release_older_than_one_already_seen_is_refused() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        let (newer_feed, key) = signed_feed("9.0.0", ".deb", body());
        evaluate(&sys, dir, &newer_feed, &key, NOW, "1.0.0").unwrap();
        let (older_feed, key) = signed_feed("8.0.0", ".deb", body());
        assert!(evaluate(&sys, dir, &older_feed, &key, NOW, "1.0.0").is_err());
    }

    #[test]
    fn the_repository_is_found_by_either_source_file() {
        let sys = FakeSys::default();
        assert!(!repository_configured(&sys));
        sys.file(APT_SOURCE, b"Types: deb");
        assert!(repository_configured(&sys));
        let sys = FakeSys::default();
        sys.file(DNF_SOURCE, b"[secblitz]");
        assert!(repository_configured(&sys));
    }

    #[test]
    fn with_the_repository_set_up_the_package_is_never_downloaded() {
        let sys = FakeSys::default();
        sys.file(APT_SOURCE, b"Types: deb");
        let (feed, key) = signed_feed("9.0.0", ".deb", body());
        let error = install_from(
            &sys,
            Path::new("/state/Updates"),
            &feed,
            &key,
            NOW,
            "1.0.0",
            |_| panic!("the repository installs this one"),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(format!("{error:#}"), BY_SOFTWARE_APP);
    }

    #[test]
    fn a_package_that_differs_from_the_signed_feed_is_never_written() {
        for served in [&b"package bytez"[..], b"short", b"package bytes and more"] {
            let sys = FakeSys::default();
            let dir = Path::new("/state/Updates");
            reply(&sys, ".deb", dir);
            assert!(run(&sys, dir, ".deb", served, true).is_err());
            assert!(!sys
                .files
                .borrow()
                .contains_key(&dir.join(package_name("9.0.0", ".deb"))));
            assert!(sys.calls.borrow().is_empty());
        }
    }

    #[test]
    fn a_matching_deb_is_installed_by_apt_in_its_own_unit() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        reply(&sys, ".deb", dir);
        let outcome = run(&sys, dir, ".deb", body(), true).unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome::WorkerStarted {
                version: "9.0.0".into()
            }
        );
        assert_eq!(
            sys.files
                .borrow()
                .get(&dir.join(package_name("9.0.0", ".deb")))
                .map(Vec::as_slice),
            Some(body())
        );
        let calls = sys.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("/usr/bin/systemd-run --quiet --collect --no-block --unit=secblitz-update --setenv=DEBIAN_FRONTEND=noninteractive -- /usr/bin/apt-get install -y /state/Updates/secblitz-9.0.0-"));
        drop(calls);
        assert_eq!(
            read_status(&sys, dir).unwrap().result,
            UpdateOutcome::WorkerStarted {
                version: "9.0.0".into()
            }
        );
    }

    #[test]
    fn a_matching_rpm_is_installed_by_dnf() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        reply(&sys, ".rpm", dir);
        run(&sys, dir, ".rpm", body(), true).unwrap();
        let calls = sys.calls.borrow();
        assert!(calls[0].contains(" -- /usr/bin/dnf install -y /state/Updates/secblitz-9.0.0-"));
        assert!(!calls[0].contains("DEBIAN_FRONTEND"));
    }

    #[test]
    fn a_package_for_another_kind_of_linux_is_not_installed() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        let error = run(&sys, dir, ".rpm", body(), false).unwrap_err();
        assert_eq!(format!("{error:#}"), WRONG_PACKAGE);
        assert!(sys.calls.borrow().is_empty());
    }

    #[test]
    fn an_install_that_is_already_running_says_so() {
        let sys = FakeSys::default();
        let dir = Path::new("/state/Updates");
        let file = dir.join(package_name("9.0.0", ".deb"));
        let args = install_args(Package::Deb, file.to_str().unwrap());
        sys.replies.borrow_mut().insert(
            format!("{SYSTEMD_RUN} {}", args.join(" ")),
            crate::linux::cmd::Output {
                status: 1,
                stdout: String::new(),
                stderr: "Unit secblitz-update.service was already loaded".into(),
            },
        );
        let error = run(&sys, dir, ".deb", body(), true).unwrap_err();
        assert_eq!(format!("{error:#}"), ALREADY_INSTALLING);
    }

    #[test]
    fn the_background_check_is_turned_on_and_off_with_fixed_arguments() {
        let sys = FakeSys::default();
        sys.reply(SYSTEMCTL, &["enable", "--now", TIMER], 0, "");
        sys.reply(SYSTEMCTL, &["disable", "--now", TIMER], 0, "");
        set_monitor_timer(&sys, true).unwrap();
        set_monitor_timer(&sys, false).unwrap();
        assert_eq!(
            *sys.calls.borrow(),
            [
                "/usr/bin/systemctl enable --now secblitz-monitor.timer",
                "/usr/bin/systemctl disable --now secblitz-monitor.timer"
            ]
        );
        let failing = FakeSys::default();
        failing.reply(SYSTEMCTL, &["enable", "--now", TIMER], 1, "");
        let error = set_monitor_timer(&failing, true).unwrap_err();
        assert_eq!(format!("{error:#}"), TIMER_FAILED);
    }

    #[test]
    fn the_timer_counts_as_on_only_when_enabled() {
        let on = FakeSys::default();
        on.reply(SYSTEMCTL, &["is-enabled", TIMER], 0, "enabled\n");
        assert!(monitor_timer_on(&on).unwrap());
        let off = FakeSys::default();
        off.reply(SYSTEMCTL, &["is-enabled", TIMER], 1, "disabled\n");
        assert!(!monitor_timer_on(&off).unwrap());
    }

    fn private(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn owner() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn the_update_folder_is_made_private_and_a_loose_one_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("top");
        std::fs::create_dir(&top).unwrap();
        private(&top);
        let dir = folder_at(&top, owner(), &top).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0);
        folder_at(&top, owner(), &top).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(folder_at(&top, owner(), &top).is_err());
    }

    #[test]
    fn a_link_in_place_of_the_update_folder_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("top");
        std::fs::create_dir(&top).unwrap();
        private(&top);
        let real = top.join("real");
        std::fs::create_dir(&real).unwrap();
        private(&real);
        std::os::unix::fs::symlink(&real, top.join(FOLDER)).unwrap();
        assert!(folder_at(&top, owner(), &top).is_err());
    }

    #[test]
    fn only_one_check_holds_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let first = lock(tmp.path()).unwrap();
        assert!(first.is_some());
        assert!(lock(tmp.path()).unwrap().is_none());
        drop(first);
        assert!(lock(tmp.path()).unwrap().is_some());
    }

    #[test]
    fn old_packages_are_cleared_and_other_files_are_kept() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "secblitz-1.0.0-linux-x64.deb",
            "secblitz-2.0.0-linux-x64.deb",
            "secblitz-1.0.0-linux-x64.rpm",
            STATUS,
            FLOOR,
        ] {
            std::fs::write(tmp.path().join(name), b"x").unwrap();
        }
        clear_old_packages(tmp.path(), "secblitz-2.0.0-linux-x64.deb");
        let mut left: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, [FLOOR, "secblitz-2.0.0-linux-x64.deb", STATUS]);
    }
}
