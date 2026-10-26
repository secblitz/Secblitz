//! Plain-words mapping from raw engine errors to the sentences and reasons the GUI shows.
pub const ERR_USE_WINDOWS_UPDATE: &str =
    "Updates can't be installed from this account. Sign in to Windows with a different administrator account, or ask the person who manages this computer, then open Secblitz again. You can also install them in Windows Update.";
pub const ERR_UNAVAILABLE: &str =
    "This isn't available on this computer. Check for a newer version of Secblitz, or use Windows Settings instead.";
pub const ERR_SETTINGS_BLOCK: &str =
    "Your computer's settings don't allow this. If someone else manages this computer, ask them to allow it, then try again.";
pub const ERR_CHANGED: &str =
    "The list of updates changed. Press Check again, look over the updates, then install them.";
pub const ERR_RESTART: &str = "Restart your computer, then try again.";
pub const ERR_BUSY: &str = "Windows is busy with another task. Try again in a few minutes.";
pub const ERR_POWER: &str = "Plug your computer in, then try again.";
pub const ERR_DISK: &str = "Free up at least 5 GB on your system drive, then try again.";
pub const ERR_METERED: &str =
    "You're on a connection with a data limit. Connect to a network without one, then try again.";
pub const ERR_NOT_READY: &str = "Your computer isn't ready for this right now. Plug it in, save your work, restart if Windows is waiting, then try again.";
pub const ERR_EARLIER: &str =
    "An earlier repair or update still needs to be checked. Restart Secblitz and try again.";
pub const ERR_NETWORK: &str =
    "We couldn't reach Windows Update. Check your internet connection and try again.";
pub const ERR_GENERAL: &str = "We couldn't finish this. Try again in a few minutes. If it keeps happening, restart your computer and check for a Secblitz update.";
pub const ERR_REOPEN: &str = "Reopen Secblitz from its shortcut and try again.";

/// False when trying again cannot help (the GUI should show a different next
/// step instead of Retry). For `ERR_USE_WINDOWS_UPDATE` the next step is an
/// "Open Windows Update" button (`advice::NextStep::OpenWindowsUpdate`).
pub fn is_retryable(note: &str) -> bool {
    !matches!(
        note,
        ERR_USE_WINDOWS_UPDATE | ERR_UNAVAILABLE | ERR_SETTINGS_BLOCK | ERR_REOPEN
    )
}

pub fn suggests_windows_update(note: &str) -> bool {
    note == ERR_USE_WINDOWS_UPDATE
}

/// Map a raw engine error to one calm sentence (translation key).
///
/// Short words are matched as whole words, so "lock" does not fire on
/// "blocked" or "clock" and "source" does not fire on "resource". Policy is
/// checked before busy/network because a message such as "blocked by policy"
/// will never succeed on a retry.
pub fn friendly_error(raw: &str) -> &'static str {
    let r = raw.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| r.contains(n));
    let words: Vec<&str> = r
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|w| !w.is_empty())
        .collect();
    let word = |needles: &[&str]| words.iter().any(|w| needles.contains(w));
    // Deliberate security property: only a real, interactive split-token
    // administrator may install updates (the built-in Administrator may not).
    if has(&["split-token"]) {
        ERR_USE_WINDOWS_UPDATE
    } else if has(&["changed since they were reviewed"]) {
        ERR_CHANGED
    } else if has(&["requires windows", "not implemented", "unsupported"]) {
        ERR_UNAVAILABLE
    } else if has(&["reboot", "restart"]) {
        ERR_RESTART
    } else if has(&[
        "servicing is busy",
        "servicing process is active",
        "engine.lock is busy",
    ]) {
        ERR_BUSY
    } else if has(&["not plugged in", "ac power"]) {
        ERR_POWER
    } else if has(&["low disk space", "insufficient system storage"]) {
        ERR_DISK
    } else if has(&["metered"]) {
        ERR_METERED
    } else if has(&["update source", "user update policy"]) {
        ERR_SETTINGS_BLOCK
    } else if has(&["deferred", "readiness", "not ready", "stale", "ac/storage"]) {
        ERR_NOT_READY
    } else if has(&["unresolved", "independent verification", "interrupted"]) {
        ERR_EARLIER
    } else if word(&["policy", "opt-in", "managed", "ownership"]) || has(&["not enabled"]) {
        ERR_SETTINGS_BLOCK
    } else if word(&["busy", "lock", "locked", "contention"])
        || has(&[
            "another operation",
            "another install",
            "another update",
            "another instance",
            "another servicing",
            "already running",
        ])
    {
        ERR_BUSY
    } else if word(&["network", "offline", "internet", "source"])
        || words
            .iter()
            .any(|w| w.starts_with("0x8024") || w.starts_with("0x8007"))
        || has(&["timed out"])
    {
        ERR_NETWORK
    } else if has(&["elevation", "elevated", "administrator", "interactive"])
        || r == "unavailable"
        || has(&["broker", "launcher did not answer"])
    {
        ERR_REOPEN
    } else {
        ERR_GENERAL
    }
}

/// The plain reason this sign-in cannot run Windows updates, or `None` when it
/// can. Every refusal of the probe is about the account or desktop session, so
/// the advice is always to use another administrator account or Windows Update.
pub fn updates_account_note(probe: anyhow::Result<()>) -> Option<&'static str> {
    probe.err().map(|_| ERR_USE_WINDOWS_UPDATE)
}

/// The first thing that would stop a repair or an update from starting, using
/// only facts that are known. Unknown facts do not block; the engine checks
/// them again before it starts.
pub fn start_blocker(r: &secblitz::model::Readiness) -> Option<&'static str> {
    use secblitz::model::Probe;
    if matches!(r.windows_update_reboot, Probe::Known(true)) {
        return Some(ERR_RESTART);
    }
    if matches!(&r.power, Probe::Known(p) if p.ac_connected == Some(false)) {
        return Some(ERR_POWER);
    }
    let low = matches!(&r.system_volume, Probe::Known(v) if v.read_only || v.available_bytes < 5 * 1024 * 1024 * 1024)
        || matches!(&r.journal_volume, Probe::Known(v) if v.read_only || v.available_bytes < 64 * 1024 * 1024);
    low.then_some(ERR_DISK)
}

pub fn check_start_blocker() -> Option<&'static str> {
    start_blocker(&secblitz::readiness::collect())
}

pub fn why_for_note(note: &str) -> &'static str {
    match note {
        ERR_USE_WINDOWS_UPDATE => "Windows only lets Secblitz install updates from a standard administrator account, and this account can't. Sign in with a different administrator account, or ask the person who manages this computer, then open Secblitz again.",
        ERR_UNAVAILABLE => "This version of Windows doesn't support this feature, so Secblitz can't do it here.",
        ERR_SETTINGS_BLOCK => "A setting on this computer, often set by a workplace or school, stops Secblitz from doing this.",
        ERR_CHANGED => "Windows found different updates from the ones you looked at, so nothing was installed.",
        ERR_REOPEN => "Secblitz was started in a way that doesn't allow this. Opening it from its shortcut fixes that.",
        ERR_RESTART => "Windows has changes waiting that need a restart before it can carry on.",
        ERR_BUSY => "Windows is running its own update or maintenance work. This usually ends within a few minutes.",
        ERR_POWER => "Updates need your computer to be plugged in, so it can't switch off part way through.",
        ERR_DISK => "Windows needs room on your system drive to download and set up updates.",
        ERR_METERED => "Windows treats this connection as one with a data limit, so large downloads are held back.",
        ERR_NOT_READY => "Windows isn't in a state where it can safely make changes yet.",
        ERR_EARLIER => "A job that was running earlier didn't finish cleanly, and Secblitz wants to check it first.",
        ERR_NETWORK => "Secblitz couldn't connect to the internet. Your connection may be off or very slow.",
        _ => "Something unexpected stopped this. Nothing was damaged. Restart your computer and try again, and check for a Secblitz update if it keeps happening.",
    }
}

pub const WHY_BITWARDEN_UNAVAILABLE: &str = "Windows only lets Secblitz install apps from a standard administrator account, and this account can't. Get Bitwarden from bitwarden.com instead.";
pub const WHY_BITWARDEN_OFFLINE: &str =
    "Secblitz couldn't connect to the internet. Check your connection, then press Retry.";

pub fn bitwarden_why(raw: &str) -> &'static str {
    if friendly_error(raw) == ERR_NETWORK {
        WHY_BITWARDEN_OFFLINE
    } else {
        friendly_why(raw)
    }
}

pub fn friendly_why(raw: &str) -> &'static str {
    why_for_note(friendly_error(raw))
}

#[cfg(test)]
pub(super) fn assert_no_dev_terms(text: &str) {
    let lower = text.to_ascii_lowercase();
    for banned in [
        "dism",
        "sfc",
        "registry",
        "digest",
        "journal",
        "transaction",
        "provisioned",
        "exit code",
        "elevated",
        "broker",
        "powershell",
        "control",
        "attention",
        "compliant",
    ] {
        assert!(!lower.contains(banned), "{text:?} contains {banned:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::maintenance::{install_why, repair_why, InstallResult, RepairResult};

    #[test]
    fn update_check_reasons_get_their_own_next_step() {
        let wrap = |why: &str| {
            format!("Patching subprocess failed; verification only (exit 0x1): Exact patching stopped (0x80131501): {why}; inspect protected record and verify, never replay")
        };
        for (why, want) in [
            ("Another servicing worker is active", ERR_BUSY),
            ("AC power not confirmed", ERR_POWER),
            ("Insufficient system storage", ERR_DISK),
            ("Metered/unknown network", ERR_METERED),
            (
                "Default update source is not unmanaged Windows Update",
                ERR_SETTINGS_BLOCK,
            ),
            ("Pending reboot; owner action required", ERR_RESTART),
        ] {
            assert_eq!(friendly_error(&wrap(why)), want, "{why}");
        }
    }

    #[test]
    fn friendly_errors_hide_developer_text() {
        for raw in [
            "Deferred: AC/storage/reboot/servicing readiness not confirmed",
            "Deferred: Windows is waiting for a restart",
            "Deferred: Windows servicing is busy",
            "Deferred: not plugged in",
            "Deferred: low disk space",
            "Owner opt-in expired",
            "Operations worker ended or result already consumed",
            "Owner-initiated reboot has not occurred",
            "Maintenance execution requires 64-bit Windows",
            "The remote name could not be resolved: network offline",
            "something unexpected",
            "Request blocked by policy",
            "Not enough resource on the clock",
        ] {
            let text = friendly_error(raw);
            assert!(text.len() > 10);
            assert_no_dev_terms(text);
        }
        assert_eq!(
            friendly_error("Owner-initiated reboot has not occurred"),
            ERR_RESTART
        );
        let raw = "Interactive split-token administrator required; service/over-the-shoulder elevation unsupported";
        assert_eq!(friendly_error(raw), ERR_USE_WINDOWS_UPDATE);
        assert_no_dev_terms(friendly_error(raw));
        assert!(!is_retryable(friendly_error(raw)));
        assert!(suggests_windows_update(friendly_error(raw)));
        assert!(is_retryable(friendly_error(
            "The file is locked by another operation"
        )));
        assert_eq!(
            friendly_error("Request blocked by policy"),
            ERR_SETTINGS_BLOCK
        );
        for (raw, text) in [
            ("Deferred: Windows is waiting for a restart", ERR_RESTART),
            ("Deferred: Windows servicing is busy", ERR_BUSY),
            ("Deferred: a Windows servicing process is active", ERR_BUSY),
            ("Deferred: shared engine.lock is busy", ERR_BUSY),
            ("Deferred: not plugged in", ERR_POWER),
            ("Deferred: low disk space", ERR_DISK),
        ] {
            assert_eq!(friendly_error(raw), text);
        }
        let raw = "Started inside another program's process job; reopen Secblitz interactively";
        assert_eq!(friendly_error(raw), ERR_REOPEN);
        assert!(!is_retryable(ERR_REOPEN));
        assert_eq!(
            friendly_error("Not enough resource on the clock"),
            ERR_GENERAL
        );
        assert_eq!(
            friendly_error("The file is locked by another operation"),
            ERR_BUSY
        );
    }

    #[test]
    fn start_blocker_names_only_known_problems() {
        use secblitz::model::{PowerReadiness, Probe, Readiness, VolumeReadiness};
        let gb = 1024u64 * 1024 * 1024;
        let vol = |bytes| {
            Probe::Known(VolumeReadiness {
                available_bytes: bytes,
                read_only: false,
            })
        };
        let good = Readiness {
            system_volume: vol(50 * gb),
            journal_volume: vol(50 * gb),
            power: Probe::Known(PowerReadiness {
                ac_connected: Some(true),
                battery_percent: None,
                battery_present: Some(false),
            }),
            windows_update_reboot: Probe::Known(false),
        };
        assert_eq!(start_blocker(&good), None);
        assert_eq!(start_blocker(&Readiness::default()), None);
        let mut r = good.clone();
        r.windows_update_reboot = Probe::Known(true);
        assert_eq!(start_blocker(&r), Some(ERR_RESTART));
        let mut r = good.clone();
        r.power = Probe::Known(PowerReadiness {
            ac_connected: Some(false),
            battery_percent: Some(40),
            battery_present: Some(true),
        });
        assert_eq!(start_blocker(&r), Some(ERR_POWER));
        let mut r = good.clone();
        r.system_volume = vol(gb);
        assert_eq!(start_blocker(&r), Some(ERR_DISK));
        let mut r = good;
        r.journal_volume = vol(0);
        assert_eq!(start_blocker(&r), Some(ERR_DISK));
    }

    #[test]
    fn account_note_matches_the_engine_wording() {
        assert_eq!(updates_account_note(Ok(())), None);
        let split = anyhow::anyhow!("Interactive split-token administrator required; service/over-the-shoulder elevation unsupported");
        assert_eq!(
            updates_account_note(Err(split)),
            Some(ERR_USE_WINDOWS_UPDATE)
        );
        let shoulder = anyhow::anyhow!("Elevated caller is not the original desktop user");
        assert_eq!(
            updates_account_note(Err(shoulder)),
            Some(ERR_USE_WINDOWS_UPDATE)
        );
    }

    #[test]
    fn split_token_text_tells_the_person_what_to_do() {
        let raw = "Interactive split-token administrator required; service/over-the-shoulder elevation unsupported";
        let note = friendly_error(raw);
        assert!(note.contains("administrator account"));
        assert!(note.contains("open Secblitz again"));
        assert_no_dev_terms(note);
        assert_no_dev_terms(friendly_why(raw));
        assert!(!friendly_why(raw).to_ascii_lowercase().contains("token"));
    }

    #[test]
    fn more_details_never_echo_raw_text() {
        for raw in [
            "Interactive split-token administrator required; service/over-the-shoulder elevation unsupported",
            "HRESULT 0x80131501 from C:\\ProgramData\\x.json",
            "something unexpected",
            "The updates changed since they were reviewed; look again",
        ] {
            let why = friendly_why(raw);
            assert!(why.len() > 20);
            assert!(!why.contains("0x") && !why.contains("HRESULT") && !why.contains("C:\\"));
        }
        assert_eq!(
            friendly_why("something unexpected"),
            why_for_note(ERR_GENERAL)
        );
        assert_eq!(
            friendly_error("The updates changed since they were reviewed; look again"),
            ERR_CHANGED
        );
        for why in [
            bitwarden_why("Offline"),
            WHY_BITWARDEN_OFFLINE,
            WHY_BITWARDEN_UNAVAILABLE,
        ] {
            assert!(!why.contains("Windows Update"));
            assert!(!why.contains("unexpected"));
        }
        assert_eq!(bitwarden_why("Offline"), WHY_BITWARDEN_OFFLINE);
        assert_eq!(bitwarden_why("WinGet timed out"), WHY_BITWARDEN_OFFLINE);
        assert_eq!(bitwarden_why("something odd"), why_for_note(ERR_GENERAL));
        assert!(WHY_BITWARDEN_UNAVAILABLE.contains("bitwarden.com"));
        assert_eq!(
            friendly_why("Scan failed: network unreachable"),
            why_for_note(ERR_NETWORK)
        );
        assert_eq!(
            friendly_why("scan blocked by policy"),
            why_for_note(ERR_SETTINGS_BLOCK)
        );
        assert_eq!(
            friendly_why("Defender update: restart required"),
            why_for_note(ERR_RESTART)
        );
        assert!(why_for_note(ERR_USE_WINDOWS_UPDATE).contains("different administrator"));
        assert!(repair_why(RepairResult::CouldNotFinish, Some(ERR_BUSY)).contains("maintenance"));
        assert!(install_why(InstallResult::NeedsRestart, None).contains("Restart"));
    }
}
