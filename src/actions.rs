//! Explicit user-selected advisory actions, separate from reversible controls.
//! Calling `run` is the authorization boundary: callers obtain consent first.
use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    UpdateDefender,
    QuickScan,
    StartMonitoring,
    OpenWindowsUpdate,
    OpenWindowsSecurity,
    OpenSignInSettings,
    OpenEncryptionSettings,
    OpenTamperProtection,
    OpenProtectionHistory,
    OpenProtectionHistoryList,
    OpenAppBrowserControl,
    OpenOptionalFeatures,
    OpenAccounts,
    OpenCoreIsolation,
    OpenFirewall,
    OpenDeviceSecurity,
    OpenWorkAccounts,
    OpenRecovery,
    OpenRemoteDesktop,
    OpenFindMyDevice,
    OpenBitLocker,
    OpenWifi,
    OpenNetwork,
    OpenBackup,
    OpenStorage,
    OpenInstalledApps,
    OpenTaskbar,
    OpenReportProblem,
    OpenSuggestFeature,
    OpenPrivacyPolicy,
    OpenRecoveryKey,
    OpenDownloadPage,
    OpenDesktopPrivacy,
}

pub const REPORT_PROBLEM_URL: &str =
    "https://github.com/secblitz/Secblitz/issues/new?template=bug_report.yml";
pub const SUGGEST_FEATURE_URL: &str =
    "https://github.com/secblitz/Secblitz/issues/new?template=feature_request.yml";
pub const PRIVACY_POLICY_URL: &str = "https://secblitz.lol/privacy.html";
pub const RECOVERY_KEY_URL: &str = "https://aka.ms/myrecoverykey";
pub const DOWNLOAD_PAGE_URL: &str = "https://secblitz.lol/#download";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionResult {
    pub status: String,
    pub detail: String,
}

#[cfg(windows)]
#[path = "actions/windows.rs"]
mod windows;

#[path = "actions/linux.rs"]
mod linux;

/// SHUTDOWN_RESTART (0x4) | SHUTDOWN_INSTALL_UPDATES (0x40). No force flags, so programs with unsaved work can still stay open.
#[cfg(any(windows, test))]
const RESTART_FLAGS: u32 = 0x0000_0004 | 0x0000_0040;
/// SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_SECURITYFIX |
/// SHTDN_REASON_FLAG_PLANNED: a planned restart for a security update.
#[cfg(any(windows, test))]
const RESTART_REASON: u32 = 0x0002_0000 | 0x0000_0012 | 0x8000_0000;

pub fn restart_for_updates() -> Result<()> {
    #[cfg(windows)]
    {
        windows::restart_for_updates()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("Restarting needs Windows")
    }
}

#[cfg(windows)]
pub fn split_token_elevated() -> Result<bool> {
    windows::split_token_elevated()
}

/// Opened through control.exe by absolute path; the name below is the only argument.
const BITLOCKER_CONTROL: &str = "Microsoft.BitLockerDriveEncryption";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Uri(&'static str),
    Control(&'static str),
}

// No user-supplied URI, arguments, executable, or PowerShell is accepted.
// ms-settings: addresses are listed on Microsoft Learn ("Launch Windows
// Settings"); windowsdefender: addresses are the Windows Security app's own
// page links (coreisolation, network, devicesecurity, threatsettings, threat,
// appbrowser).
fn target(action: Action) -> Option<Target> {
    use Target::{Control, Uri};
    Some(match action {
        Action::OpenWindowsUpdate => Uri("ms-settings:windowsupdate"),
        Action::OpenWindowsSecurity => Uri("ms-settings:windowsdefender"),
        Action::OpenSignInSettings => Uri("ms-settings:signinoptions"),
        Action::OpenEncryptionSettings => Uri("ms-settings:deviceencryption"),
        Action::OpenTamperProtection => Uri("windowsdefender://threatsettings"),
        Action::OpenProtectionHistory => Uri("windowsdefender://threat"),
        Action::OpenProtectionHistoryList => Uri("windowsdefender://history"),
        Action::OpenAppBrowserControl => Uri("windowsdefender://appbrowser"),
        Action::OpenOptionalFeatures => Uri("ms-settings:optionalfeatures"),
        Action::OpenAccounts => Uri("ms-settings:otherusers"),
        Action::OpenCoreIsolation => Uri("windowsdefender://coreisolation"),
        Action::OpenFirewall => Uri("windowsdefender://network"),
        Action::OpenDeviceSecurity => Uri("windowsdefender://devicesecurity"),
        Action::OpenWorkAccounts => Uri("ms-settings:workplace"),
        Action::OpenRecovery => Uri("ms-settings:recovery"),
        Action::OpenRemoteDesktop => Uri("ms-settings:remotedesktop"),
        Action::OpenFindMyDevice => Uri("ms-settings:findmydevice"),
        Action::OpenWifi => Uri("ms-settings:network-wifi"),
        Action::OpenNetwork => Uri("ms-settings:network"),
        Action::OpenBackup => Uri("ms-settings:backup"),
        Action::OpenStorage => Uri("ms-settings:storagesense"),
        Action::OpenInstalledApps => Uri("ms-settings:appsfeatures"),
        Action::OpenTaskbar => Uri("ms-settings:taskbar"),
        Action::OpenReportProblem => Uri(REPORT_PROBLEM_URL),
        Action::OpenSuggestFeature => Uri(SUGGEST_FEATURE_URL),
        Action::OpenPrivacyPolicy => Uri(PRIVACY_POLICY_URL),
        Action::OpenRecoveryKey => Uri(RECOVERY_KEY_URL),
        Action::OpenDownloadPage => Uri(DOWNLOAD_PAGE_URL),
        Action::OpenBitLocker => Control(BITLOCKER_CONTROL),
        _ => return None,
    })
}

#[cfg(test)]
fn settings_uri(action: Action) -> Option<&'static str> {
    match target(action) {
        Some(Target::Uri(uri)) => Some(uri),
        _ => None,
    }
}

/// Only the elevated half of a split (UAC) token is refused: it has a normal-rights twin that could plant a protocol handler. A full-token administrator has none.
#[cfg(any(windows, test))]
fn validate_settings_request(uri: &str, split_elevated: bool) -> Result<()> {
    anyhow::ensure!(
        matches!(
            uri,
            "ms-settings:windowsupdate"
                | "ms-settings:windowsdefender"
                | "ms-settings:signinoptions"
                | "ms-settings:deviceencryption"
                | "windowsdefender://threatsettings"
                | "windowsdefender://threat"
                | "windowsdefender://history"
                | "windowsdefender://appbrowser"
                | "ms-settings:optionalfeatures"
                | "ms-settings:otherusers"
                | "windowsdefender://coreisolation"
                | "windowsdefender://network"
                | "windowsdefender://devicesecurity"
                | REPORT_PROBLEM_URL
                | SUGGEST_FEATURE_URL
                | PRIVACY_POLICY_URL
                | RECOVERY_KEY_URL
                | DOWNLOAD_PAGE_URL
                | "ms-settings:workplace"
                | "ms-settings:recovery"
                | "ms-settings:remotedesktop"
                | "ms-settings:findmydevice"
                | "ms-settings:network-wifi"
                | "ms-settings:network"
                | "ms-settings:backup"
                | "ms-settings:storagesense"
                | "ms-settings:appsfeatures"
                | "ms-settings:taskbar"
        ),
        "Unknown settings URI"
    );
    // An allowlisted URI still resolves through user-writable protocol handlers.
    // Never dispatch it with the elevated half of a split token.
    anyhow::ensure!(
        !split_elevated,
        "Open Settings from the non-elevated interactive application"
    );
    Ok(())
}

#[cfg(any(windows, test))]
fn validate_control_request(name: &str, split_elevated: bool) -> Result<()> {
    anyhow::ensure!(name == BITLOCKER_CONTROL, "Unknown control panel item");
    anyhow::ensure!(
        !split_elevated,
        "Open Settings from the non-elevated interactive application"
    );
    Ok(())
}

/// Blocking, explicitly selected action. Errors never imply that in-flight
/// Defender work stopped. Settings dispatch does not verify remediation.
pub fn run(action: Action) -> Result<ActionResult> {
    if action == Action::OpenDesktopPrivacy {
        linux::open_privacy()?;
        return Ok(ActionResult {
            status: "opened".into(),
            detail: "The desktop's Privacy settings were asked to open. No fix is claimed.".into(),
        });
    }
    if let Some(target) = target(action) {
        #[cfg(windows)]
        windows::open(target)?;
        #[cfg(not(windows))]
        {
            let _ = target;
            anyhow::bail!("Settings actions require Windows");
        }
        #[cfg(windows)]
        return Ok(ActionResult {
            status: "opened".into(),
            detail: "Windows accepted the settings-page request. Page availability and security settings are not verified; no fix is claimed.".into(),
        });
    }
    let (status, detail) = match action {
        Action::UpdateDefender => {
            crate::platform::support_action("defender_update")?;
            ("returned", "Defender's signature-update command returned successfully using its configured sources. This does not establish that signatures are the latest available.")
        }
        Action::QuickScan => {
            crate::platform::support_action("defender_quickscan")?;
            ("returned", "Defender's quick-scan command returned successfully. Completion and threat status are not independently verified; review Windows Security for results.")
        }
        Action::StartMonitoring => {
            if crate::service::query_status()?.state == crate::service::MonitorState::NotInstalled {
                crate::service::install()?;
            }
            crate::service::start().context("Monitor startup failed; the installed service was retained. Check service status before retrying")?;
            ("running", "SCM reports SecblitzMonitor Running. Monitoring is read-only; this does not verify report freshness or machine health.")
        }
        _ => anyhow::bail!("Settings actions require Windows"),
    };
    Ok(ActionResult {
        status: status.into(),
        detail: detail.into(),
    })
}

pub use crate::platform::{RenewalOutcome, RenewalRefusal, ThreatRemoval};

/// One way only: it cannot be undone, and the PC is never restarted. Callers ask first.
pub fn start_secure_boot_renewal() -> Result<RenewalOutcome> {
    crate::platform::start_secure_boot_renewal()
}

/// What Defender removes goes to quarantine; only its own counts are returned, never a claim of safety.
pub fn remove_threats() -> Result<ThreatRemoval> {
    crate::platform::remove_threats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_is_a_planned_security_fix_restart_that_forces_nothing() {
        // SHUTDOWN_RESTART only: no SHUTDOWN_FORCE_OTHERS (0x1), FORCE_SELF (0x2)
        // or power-off flags, so unsaved work can still stop the restart.
        assert_eq!(RESTART_FLAGS, 0x44);
        assert_eq!(RESTART_FLAGS & 0x3, 0, "no force flags");
        assert_eq!(RESTART_REASON & 0x8000_0000, 0x8000_0000, "planned");
        assert_eq!(
            RESTART_REASON & 0x00FF_0000,
            0x0002_0000,
            "operating system"
        );
        assert_eq!(RESTART_REASON & 0xFFFF, 0x12, "security fix");
        #[cfg(not(windows))]
        assert!(restart_for_updates().is_err());
    }

    #[test]
    fn settings_allowlist_is_closed() {
        for (action, uri) in [
            (Action::OpenWindowsUpdate, "ms-settings:windowsupdate"),
            (Action::OpenWindowsSecurity, "ms-settings:windowsdefender"),
            (Action::OpenSignInSettings, "ms-settings:signinoptions"),
            (
                Action::OpenEncryptionSettings,
                "ms-settings:deviceencryption",
            ),
            (
                Action::OpenTamperProtection,
                "windowsdefender://threatsettings",
            ),
            (Action::OpenProtectionHistory, "windowsdefender://threat"),
            (
                Action::OpenProtectionHistoryList,
                "windowsdefender://history",
            ),
            (
                Action::OpenAppBrowserControl,
                "windowsdefender://appbrowser",
            ),
            (Action::OpenOptionalFeatures, "ms-settings:optionalfeatures"),
            (Action::OpenAccounts, "ms-settings:otherusers"),
            (Action::OpenCoreIsolation, "windowsdefender://coreisolation"),
            (Action::OpenFirewall, "windowsdefender://network"),
            (
                Action::OpenDeviceSecurity,
                "windowsdefender://devicesecurity",
            ),
            (Action::OpenWorkAccounts, "ms-settings:workplace"),
            (Action::OpenRecovery, "ms-settings:recovery"),
            (Action::OpenRemoteDesktop, "ms-settings:remotedesktop"),
            (Action::OpenFindMyDevice, "ms-settings:findmydevice"),
            (Action::OpenWifi, "ms-settings:network-wifi"),
            (Action::OpenNetwork, "ms-settings:network"),
            (Action::OpenBackup, "ms-settings:backup"),
            (Action::OpenStorage, "ms-settings:storagesense"),
            (Action::OpenInstalledApps, "ms-settings:appsfeatures"),
            (Action::OpenTaskbar, "ms-settings:taskbar"),
            (Action::OpenReportProblem, REPORT_PROBLEM_URL),
            (Action::OpenSuggestFeature, SUGGEST_FEATURE_URL),
            (Action::OpenPrivacyPolicy, PRIVACY_POLICY_URL),
            (Action::OpenRecoveryKey, RECOVERY_KEY_URL),
            (Action::OpenDownloadPage, DOWNLOAD_PAGE_URL),
        ] {
            assert_eq!(settings_uri(action), Some(uri));
            validate_settings_request(uri, false).unwrap();
            assert!(validate_settings_request(uri, true).is_err());
        }
        assert_eq!(
            target(Action::OpenBitLocker),
            Some(Target::Control("Microsoft.BitLockerDriveEncryption"))
        );
        validate_control_request("Microsoft.BitLockerDriveEncryption", false).unwrap();
        assert!(validate_control_request("Microsoft.BitLockerDriveEncryption", true).is_err());
        for bad in [
            "",
            "Microsoft.System",
            "microsoft.bitlockerdriveencryption",
            "Microsoft.BitLockerDriveEncryption ",
            "Microsoft.BitLockerDriveEncryption & calc.exe",
        ] {
            assert!(validate_control_request(bad, false).is_err(), "{bad}");
        }
        for action in [
            Action::UpdateDefender,
            Action::QuickScan,
            Action::StartMonitoring,
        ] {
            assert_eq!(settings_uri(action), None);
        }
    }

    #[test]
    fn settings_boundary_rejects_executables_and_unlisted_uris() {
        for uri in [
            "",
            "cmd.exe",
            "https://example.com",
            "ms-settings:",
            "MS-SETTINGS:windowsupdate",
            "ms-settings:windowsupdate ",
            "ms-settings:windowsupdate\0",
            "ms-settings:windowsupdate & calc.exe",
            "windowsdefender://",
            "windowsdefender://threat/",
            "windowsdefender://history/",
            "WINDOWSDEFENDER://history",
            "WINDOWSDEFENDER://threat",
            "windowsdefender://threat&calc.exe",
            "ms-settings:otherusers ",
            "windowsdefender://coreisolation/",
            "ms-settings:remotedesktop?x",
            "ms-settings:recovery ",
            "WINDOWSDEFENDER://network",
            "ms-settings:network/",
            "ms-settings:Network",
        ] {
            for elevated in [false, true] {
                assert!(validate_settings_request(uri, elevated).is_err());
            }
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_actions_fail_without_claiming_success() {
        for action in [
            Action::UpdateDefender,
            Action::QuickScan,
            Action::StartMonitoring,
            Action::OpenWindowsUpdate,
            Action::OpenWindowsSecurity,
            Action::OpenSignInSettings,
            Action::OpenEncryptionSettings,
            Action::OpenTamperProtection,
            Action::OpenProtectionHistory,
            Action::OpenProtectionHistoryList,
            Action::OpenAppBrowserControl,
            Action::OpenOptionalFeatures,
            Action::OpenAccounts,
            Action::OpenCoreIsolation,
            Action::OpenFirewall,
            Action::OpenDeviceSecurity,
            Action::OpenWorkAccounts,
            Action::OpenRecovery,
            Action::OpenRemoteDesktop,
            Action::OpenFindMyDevice,
            Action::OpenBitLocker,
            Action::OpenWifi,
            Action::OpenNetwork,
            Action::OpenBackup,
            Action::OpenStorage,
            Action::OpenInstalledApps,
            Action::OpenTaskbar,
            Action::OpenReportProblem,
            Action::OpenSuggestFeature,
            Action::OpenPrivacyPolicy,
            Action::OpenRecoveryKey,
        ] {
            assert!(run(action).is_err());
        }
    }
}
