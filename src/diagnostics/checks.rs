//! Detect-only checks: read typed facts, return assessments, mutate nothing.
//! Facts carry counts and fixed categories only, never paths, names or contents.
use super::rules::{a, boolean};
use super::*;
use Status::*;

/// One servicing line. `builds` are the OS build numbers that line can report;
/// a display version and build that disagree are never assessed.
struct Release {
    version: &'static str,
    builds: &'static [u32],
    consumer_end: &'static str,
    managed_end: Option<&'static str>,
}

/// Source: Microsoft Lifecycle, Windows 11 Home and Pro / Enterprise and Education
/// release pages, and the Windows 10 Home and Pro lifecycle page. Update this table
/// (and `RELEASE_TABLE_REVIEWED`) when Microsoft publishes new releases.
const RELEASES: &[Release] = &[
    Release {
        version: "21H2",
        builds: &[19044],
        consumer_end: "2023-06-13",
        managed_end: Some("2024-06-11"),
    },
    Release {
        version: "22H2",
        builds: &[19045],
        consumer_end: "2025-10-14",
        managed_end: Some("2025-10-14"),
    },
    Release {
        version: "21H2",
        builds: &[22000],
        consumer_end: "2023-10-10",
        managed_end: Some("2024-10-08"),
    },
    Release {
        version: "22H2",
        builds: &[22621],
        consumer_end: "2024-10-08",
        managed_end: Some("2025-10-14"),
    },
    Release {
        version: "23H2",
        builds: &[22631],
        consumer_end: "2025-11-12",
        managed_end: Some("2026-11-10"),
    },
    Release {
        version: "24H2",
        builds: &[26100],
        consumer_end: "2026-10-14",
        managed_end: Some("2027-10-12"),
    },
    Release {
        version: "25H2",
        builds: &[26100, 26200],
        consumer_end: "2027-10-13",
        managed_end: Some("2028-10-10"),
    },
    Release {
        version: "26H1",
        builds: &[28000],
        consumer_end: "2028-03-15",
        managed_end: None,
    },
    Release {
        version: "26H2",
        builds: &[28000, 28100],
        consumer_end: "2028-10-10",
        managed_end: None,
    },
];
pub const RELEASE_TABLE_REVIEWED: &str = "2026-10-05";
pub const SUPPORT_WARNING_DAYS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseSupport {
    Ended { days_ago: i64 },
    Ends { days_left: i64 },
    NotAssessed,
}

fn edition_is_consumer(edition: &str) -> Option<bool> {
    if edition.starts_with("Core") || edition.starts_with("Professional") {
        Some(true)
    } else if matches!(edition, "EnterpriseS" | "EnterpriseSN") || edition.starts_with("IoT") {
        None // LTSC and IoT lifecycles differ
    } else if edition.starts_with("Enterprise") || edition.starts_with("Education") {
        Some(false)
    } else {
        None
    }
}

fn civil_days(date: &str) -> Option<i64> {
    let mut parts = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

pub fn release_support(version: &str, build: u32, edition: &str, today: i64) -> ReleaseSupport {
    let Some(consumer) = edition_is_consumer(edition) else {
        return ReleaseSupport::NotAssessed;
    };
    let Some(release) = RELEASES
        .iter()
        .find(|r| r.version == version && r.builds.contains(&build))
    else {
        return ReleaseSupport::NotAssessed;
    };
    let end = if consumer {
        Some(release.consumer_end)
    } else {
        release.managed_end
    };
    let Some(end) = end.and_then(civil_days) else {
        return ReleaseSupport::NotAssessed;
    };
    if today >= end {
        ReleaseSupport::Ended {
            days_ago: today - end,
        }
    } else {
        ReleaseSupport::Ends {
            days_left: end - today,
        }
    }
}

fn today_days() -> Option<i64> {
    now().map(|s| (s / 86_400) as i64)
}

pub(super) fn os_support(v: &OsSupport) -> Vec<Assessment> {
    os_support_at(v, today_days())
}

pub(super) fn os_support_at(v: &OsSupport, today: Option<i64>) -> Vec<Assessment> {
    let id = "os.feature_release_support";
    let (Some(version), Some(build), Some(edition), Some(today)) = (
        v.display_version.known(),
        v.build.known(),
        v.edition_id.known(),
        today,
    ) else {
        return vec![a(id, Unknown, "Windows version, build or edition could not be read, so the support end date is not assessed.")];
    };
    let (status, detail) = match release_support(version, *build, edition, today) {
        ReleaseSupport::Ended { days_ago } => (Attention, format!("Windows {version} stopped receiving security updates {days_ago} day(s) ago for this edition. Move to a supported release in Windows Update.")),
        ReleaseSupport::Ends { days_left } if days_left <= SUPPORT_WARNING_DAYS => (Attention, format!("Windows {version} stops receiving security updates in {days_left} day(s) for this edition. Install the newest release in Windows Update.")),
        ReleaseSupport::Ends { days_left } => (Healthy, format!("Windows {version} is supported for another {days_left} day(s) for this edition.")),
        ReleaseSupport::NotAssessed => (Informational, format!("Windows {version} (build {build}) with this edition is not in the compiled support table (reviewed {RELEASE_TABLE_REVIEWED}); no support claim is made.")),
    };
    vec![a(id, status, detail)]
}

pub(super) fn secure_boot_certs(v: &SecureBootCerts) -> Vec<Assessment> {
    use super::{Blocker, Renewal};
    let id = "boot.secure_boot_certs";
    let (status, detail) = match Renewal::of(v) {
        Renewal::NotApplicable => (Informational, "Secure Boot is off or unavailable, so the certificate renewal does not apply."),
        Renewal::Done => (Healthy, "The 2023 Secure Boot certificate update is reported as complete."),
        Renewal::VirtualPc => (Informational, "This is a virtual computer. The certificate renewal belongs to the program that runs it, so Secblitz leaves it alone."),
        Renewal::Started => (Attention, "The Secure Boot certificate renewal has started. It finishes after the next restart."),
        Renewal::Offer { .. } => (Attention, "The 2011 Secure Boot certificates have not been replaced by the 2023 ones. Secblitz can start the renewal after you agree; it cannot be undone."),
        Renewal::Blocked(Blocker::MakerUpdate) => (Attention, "Windows logged a failed or blocked Secure Boot certificate update. The computer maker may need to release a firmware update first."),
        Renewal::Blocked(Blocker::TaskOff) => (Attention, "The Windows job that renews the Secure Boot certificates is missing or switched off. Install all Windows updates, then check again."),
        Renewal::Blocked(Blocker::OtherSystem) => (Attention, "Another operating system is in the startup list, so Secblitz does not renew the Secure Boot certificates for you."),
        Renewal::Blocked(Blocker::NotChecked) => (Attention, "No sign that the 2011 Secure Boot certificates were replaced by the 2023 ones, and the renewal could not be checked safely. Install all Windows updates and check the computer maker's firmware guidance."),
        Renewal::Unknown => (Unknown, "Secure Boot certificate renewal state could not be read."),
    };
    vec![a(id, status, detail)]
}

pub(super) fn defender_protection(v: &DefenderProtection) -> Vec<Assessment> {
    let normal = v.running_mode.known().map(String::as_str) == Some("Normal");
    let mode_known = v.running_mode.known().is_some();
    let other_av = |id: &str| {
        a(id, Informational, "Another antivirus (or passive mode) is in charge, so Windows Defender scan and threat state is not assessed.")
    };
    let mut out = Vec::new();

    out.push(if mode_known && !normal {
        other_av("defender.threats")
    } else {
        let status = match (v.active_threats.known(), v.recent_detections.known()) {
            (Some(n), _) if *n > 0 => Attention,
            (Some(0), Some(0)) => Healthy,
            (Some(0), Some(_)) => Informational,
            _ => Unknown,
        };
        a("defender.threats", status, "Counts of active and last-30-day detections only; threat names, file paths and user folders are never collected. An active threat means Windows Security has not finished handling it.")
    });

    let feature = v.tamper_feature_value.known();
    let tamper_status = match (v.tamper_protected.known(), feature) {
        (Some(true), _) => Healthy,
        (Some(false), _) => Attention,
        (None, Some(5)) => Healthy,
        (None, Some(4)) => Attention,
        _ => Unknown,
    };
    out.push(a("defender.tamper_protection", tamper_status, "Tamper Protection stops malware and unapproved tools from switching off antivirus settings. It can only be turned on in Windows Security; this tool never writes the setting."));

    out.push(if mode_known && !normal {
        other_av("defender.exclusions_risky")
    } else {
        let status = match (v.risky_exclusion_count.known(), v.exclusion_count.known()) {
            (Some(n), _) if *n > 0 => Attention,
            (Some(0), Some(0)) => Healthy,
            (Some(0), Some(_)) => Informational,
            _ => Unknown,
        };
        a("defender.exclusions_risky", status, "Counts only. Risky means drive roots, Windows or user folders, Downloads, Temp, program types such as exe/dll/script, or command tools. Exclusion paths and names are never collected, and an unreadable (masked) list stays unknown.")
    });

    out.push(if mode_known && !normal {
        other_av("defender.scan_age")
    } else {
        let status = match v.quick_scan_age_days.known() {
            Some(days) if *days == u32::MAX || *days > 7 => Attention,
            Some(_) => Healthy,
            None => Unknown,
        };
        a("defender.scan_age", status, "Days since the last quick scan; a value of never or over seven days merits a scan. Nothing is scanned or removed by this check.")
    });
    out
}

pub(super) fn smartscreen(v: &SmartScreen) -> Vec<Assessment> {
    let mut out = Vec::new();
    let apps = match (v.apps_off_local.known(), v.apps_off_policy.known()) {
        (Some(true), _) | (_, Some(true)) => Attention,
        (Some(false), Some(false)) => Healthy,
        _ => Unknown,
    };
    out.push(a("smartscreen.apps", apps, "App and file reputation warnings are off by local setting or by a policy value. When a policy value is present, whoever manages this computer may have set it on purpose."));
    let browser = match (v.edge_off_policy.known(), v.chrome_off_policy.known()) {
        (Some(true), _) | (_, Some(true)) => Attention,
        (Some(false), Some(false)) => Healthy,
        _ => Unknown,
    };
    out.push(a("smartscreen.browser_policy", browser, "A browser policy value turns off dangerous-site checks in Edge or Chrome. Values are only reported; nothing is deleted."));
    let sac = match v.smart_app_control.known().map(String::as_str) {
        Some("On" | "Evaluation" | "Off" | "Absent") => Informational,
        _ => Unknown,
    };
    out.push(a("smart_app_control.state", sac, "Smart App Control state (On, Evaluation, Off or not present). Once off it cannot be turned back on without reinstalling Windows, so this tool never changes it."));
    out
}

pub(super) fn update_policy(v: &UpdatePolicy) -> Vec<Assessment> {
    let mut out = vec![boolean("update.paused", &v.paused, false, "Windows Update pause or delay is active; updates resume after the pause ends or when resumed in Settings.")];
    out.push(a("update.drivers_excluded", match v.drivers_excluded.known() { Some(true) => Informational, Some(false) => Healthy, None => Unknown }, "Driver updates are excluded from Windows quality updates by policy. This is often deliberate and is reported for information only."));
    let reboot = match (v.reboot_pending.known(), v.uptime_days.known()) {
        (Some(true), Some(days)) if *days >= 7 => Attention,
        (Some(true), _) => Informational,
        (Some(false), _) => Healthy,
        _ => Unknown,
    };
    out.push(a("update.reboot_overdue", reboot, "A restart is waiting to finish installing updates and the computer has been up for a week or more. Fast Startup does not count as a restart, and nothing is restarted automatically."));
    out
}

pub(super) fn legacy_features(v: &LegacyFeatures) -> Vec<Assessment> {
    vec![boolean("ps.v2_engine", &v.powershell_v2_enabled, false, "The deprecated Windows PowerShell 2.0 engine lacks modern logging and malware scanning hooks and is a common downgrade-attack target. A missing feature counts as removed; nothing is changed by this check.")]
}

pub(super) fn hosts_file(v: &HostsFile) -> Vec<Assessment> {
    let size = v.size_bytes.known();
    let bad = [
        v.sensitive_redirect_count.known(),
        v.sensitive_block_count.known(),
    ];
    let status =
        if bad.iter().any(|n| n.is_some_and(|n| *n > 0)) || size.is_some_and(|s| *s > 1_048_576) {
            Attention
        } else if bad.contains(&None) || size.is_none() {
            Unknown
        } else if v.redirect_count.known().is_some_and(|n| *n > 0) {
            Informational
        } else if v.redirect_count.known().is_some() {
            Healthy
        } else {
            Unknown
        };
    vec![a("net.hosts_file", status, "Counts only. Attention means a name for Microsoft, a bank or a security product is sent to another address, an update or antivirus name is blocked, or the file is over 1 MB. No host names, addresses or contents are collected.")]
}

pub(super) fn persistence(v: &Persistence) -> Vec<Assessment> {
    let wmi = match v.wmi_consumers.known() {
        Some(0) => Healthy,
        Some(_) => Attention,
        None => Unknown,
    };
    let unquoted = match (
        v.unquoted_service_paths_writable.known(),
        v.unquoted_service_paths.known(),
    ) {
        (Some(n), _) if *n > 0 => Attention,
        (Some(0), Some(0)) => Healthy,
        (Some(0), Some(_)) => Informational,
        _ => Unknown,
    };
    vec![
        a("persistence.wmi_subscriptions", wmi, "Count of WMI command or script event consumers, which can run programs in the background without a visible startup entry. Some management and hardware tools use them legitimately; names and commands are never collected."),
        a("services.unquoted_paths", unquoted, "Services whose program path contains spaces without quotes. It matters only if a standard user can write into one of the folders Windows would try first; counts only, no service names or paths."),
    ]
}

pub(super) fn account_hygiene(v: &AccountHygiene) -> Vec<Assessment> {
    vec![
        a("accounts.stale_enabled", match v.stale_enabled_accounts.known() { Some(0) => Healthy, Some(_) => Attention, None => Unknown }, "Enabled local accounts that have not signed in for 180 days, excluding built-in accounts. Names are never collected."),
    ]
}

pub(super) fn sharing(v: &Sharing) -> Vec<Assessment> {
    let exposed = match (v.broad_access_shares.known(), v.share_count.known()) {
        (Some(n), _) if *n > 0 => Attention,
        (Some(0), Some(0)) => Healthy,
        (Some(0), Some(_)) => Informational,
        _ => Unknown,
    };
    let encryption = match (v.share_count.known(), v.encrypt_data.known()) {
        (Some(0), _) => Healthy,
        (Some(_), Some(true)) => Healthy,
        (Some(_), Some(false)) => Informational,
        _ => Unknown,
    };
    vec![
        a("smb.shares_exposed", exposed, "Non-default shared folders, and how many grant Change or Full access to Everyone, Anonymous or Guests. Share names and paths are never collected."),
        a("smb.server_encryption", encryption, "Whether file-sharing traffic is encrypted when folders are shared. Informational only: turning it on breaks older devices."),
    ]
}

pub(super) fn firewall_rules(v: &FirewallRules) -> Vec<Assessment> {
    let status = match (
        v.risky_inbound_allow_rules.known(),
        v.user_folder_inbound_allow_rules.known(),
    ) {
        (Some(n), _) if *n > 0 => Attention,
        (Some(0), Some(0)) => Healthy,
        (Some(0), Some(_)) => Informational,
        _ => Unknown,
    };
    vec![a("firewall.user_dir_inbound_allow", status, "Enabled inbound allow rules for programs in Downloads, Desktop, Temp or Public folders count as risky; other personal-folder programs are informational. Program paths are never collected.")]
}

pub(super) fn account_setup(v: &AccountSetup) -> Vec<Assessment> {
    let daily = match v.current_user_is_admin.known() {
        Some(true) => Attention,
        Some(false) => Healthy,
        None => Unknown,
    };
    let find = match v.find_my_device.known().map(String::as_str) {
        Some("On") => Healthy,
        Some("Off") => Attention,
        // Desktops and local-only accounts do not apply; a laptop whose setting this
        // Windows build does not report is not judged either way.
        Some("NotApplicable" | "Unreported") => Informational,
        _ => Unknown,
    };
    vec![
        a("accounts.daily_admin", daily, "The account running this tool is directly a member of the local Administrators group. Nested groups are not followed, so a standard-looking account stays unknown. Nothing is demoted or changed; names are never collected."),
        a("accounts.find_my_device", find, "Find my device is checked on laptops signed in with a Microsoft account. Where the setting cannot be read with confidence the result stays unknown; nothing is changed."),
    ]
}

pub(super) fn windows_hello(v: &WindowsHello) -> Vec<Assessment> {
    vec![boolean("accounts.hello_configured", &v.pin_set, true, "Whether a Windows Hello PIN or biometric sign-in is set up for this account, read from the single NgcSet line of the Windows device-registration report. Password sign-in is never turned off by this tool.")]
}

pub(super) fn kernel_stack(vbs: &Vbs) -> Option<Assessment> {
    let id = "vbs.kernel_stack_protection";
    let running_hvci = vbs.running_services.known().is_some_and(|s| s.contains(&2));
    Some(match vbs.kernel_shadow_stacks.known().map(String::as_str) {
        Some("On") => a(id, Healthy, "Kernel-mode hardware-enforced stack protection is switched on."),
        Some("Off") if running_hvci => a(id, Attention, "Kernel-mode hardware-enforced stack protection is off although Memory integrity is running. Whether your computer supports it is not tested; the Windows Security toggle shows that. Nothing is changed by this check."),
        Some("Off") => a(id, Informational, "Kernel-mode hardware-enforced stack protection is off. It needs Memory integrity running first; nothing is changed by this check."),
        Some("Absent") => return None,
        _ => a(id, Unknown, "Kernel-mode stack protection state could not be read."),
    })
}

pub(super) fn dns_encryption(v: &DnsEncryption) -> Vec<Assessment> {
    let status = match (
        v.dns_servers.known(),
        v.encrypted_dns_servers.known(),
        v.upgradeable_dns_servers.known(),
    ) {
        (Some(0), _, _) => Unknown,
        (Some(total), Some(encrypted), _) if total == encrypted => Healthy,
        (Some(_), Some(0), Some(upgradeable)) if *upgradeable > 0 => Attention,
        (Some(_), Some(_), Some(_)) => Informational,
        _ => Unknown,
    };
    vec![a("net.dns_encryption", status, "Counts only. Attention means a DNS provider that supports encrypted lookups is in use but its lookups are not encrypted yet. Router-provided or other DNS servers are informational, because changing DNS can break parental filters and sign-in pages; this tool never changes DNS.")]
}

pub(super) fn wifi_security(v: &WifiSecurity) -> Vec<Assessment> {
    let (status, detail) = match v.current_network.known().map(String::as_str) {
        Some("Strong") => (Healthy, "The connected Wi-Fi network uses modern WPA2 or WPA3 security."),
        Some("None") => (Informational, "No Wi-Fi network is connected, or this computer has no Wi-Fi."),
        Some("Open") => (Attention, "The connected Wi-Fi network has no password protection. On your own router, turn on WPA2 or WPA3; on a public network avoid private sign-ins."),
        Some("Wep") => (Attention, "The connected Wi-Fi network uses WEP, which can be broken in minutes. The fix is on the router: switch to WPA2 or WPA3."),
        Some("Old") => (Attention, "The connected Wi-Fi network uses old WPA or TKIP security. The fix is on the router: switch to WPA2 or WPA3 with AES."),
        _ => (Unknown, "The security type of the connected Wi-Fi network could not be read with confidence."),
    };
    vec![a(
        "net.wifi_security",
        status,
        format!("{detail} The network name and address are never collected."),
    )]
}

pub(super) fn autostart(v: &Autostart) -> Vec<Assessment> {
    let flagged = [v.risky_unsigned.known(), v.suspicious_command.known()];
    let status = if flagged.iter().any(|n| n.is_some_and(|n| *n > 0)) {
        Attention
    } else if flagged.iter().all(|n| *n == Some(&0)) && v.entries_checked.known().is_some() {
        Healthy
    } else {
        Unknown
    };
    vec![a("persistence.run_and_tasks", status, "Counts only. Start-up entries (Run keys, Startup folders, non-Microsoft scheduled tasks) are flagged when the program sits in Temp, Downloads, Public or the Roaming folder root and is not signed, or when a command hides an encoded script or downloads from the internet. Names and paths are never collected.")]
}

pub(super) fn run_history(v: &RunHistory) -> Vec<Assessment> {
    let counts = [
        v.encoded_command.known(),
        v.web_script.known(),
        v.mshta.known(),
        v.download_tool.known(),
        v.hidden_window.known(),
    ];
    let status = match v.suspicious_entries.known() {
        Some(n) if *n > 0 => Attention,
        Some(0) if v.entries_checked.known().is_some() && counts.iter().all(Option::is_some) => {
            Healthy
        }
        _ => Unknown,
    };
    vec![a("clickfix.run_history", status, "Counts only. The Run box history of the signed-in user is sorted into fixed kinds of commands that fake check pages ask people to paste: encoded or hidden PowerShell, text run as code, mshta and download helpers. Command text is never kept and nothing is deleted.")]
}

pub(super) fn documentation(id: &str) -> Option<&'static str> {
    Some(match id {
        "os.feature_release_support" => "https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro",
        "boot.secure_boot_certs" => "https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance",
        "defender.tamper_protection" => "https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection",
        "defender.threats" | "defender.scan_age" => "https://learn.microsoft.com/powershell/module/defender/get-mpthreat",
        "defender.exclusions_risky" => "https://learn.microsoft.com/defender-endpoint/configure-exclusions-microsoft-defender-antivirus",
        "smartscreen.apps" | "smartscreen.browser_policy" => "https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/",
        "smart_app_control.state" => "https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview",
        "update.paused" | "update.drivers_excluded" | "update.reboot_overdue" => "https://learn.microsoft.com/windows/deployment/update/waas-wu-settings",
        "ps.v2_engine" => "https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/",
        "net.hosts_file" => "https://learn.microsoft.com/troubleshoot/windows-client/networking/reset-hosts-file-back-to-default",
        "persistence.wmi_subscriptions" => "https://learn.microsoft.com/windows/win32/wmisdk/receiving-a-wmi-event",
        "services.unquoted_paths" => "https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw",
        "firewall.user_dir_inbound_allow" => "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/",
        "vbs.kernel_stack_protection" => "https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
        "accounts.hello_configured" => "https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/",
        "accounts.find_my_device" => "https://support.microsoft.com/windows/find-and-lock-a-lost-windows-device-890bf25e-b8ba-d3fe-8253-e98a18f03e1e",
        "net.dns_encryption" => "https://learn.microsoft.com/windows-server/networking/dns/doh-client-support",
        "net.wifi_security" => "https://learn.microsoft.com/windows/win32/api/wlanapi/ns-wlanapi-wlan_security_attributes",
        "persistence.run_and_tasks" => "https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys",
        "clickfix.run_history" => "https://www.microsoft.com/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/",
        _ => return None,
    })
}

pub(super) fn guidance(id: &str) -> Option<&'static str> {
    Some(match id {
        "os.feature_release_support" => "Install the newest Windows release through Windows Update after a backup; never silently. Skip when on a metered connection or with little free disk space.",
        "boot.secure_boot_certs" => "Install all pending Windows updates, then check the computer maker's firmware update page. Keep the BitLocker recovery key safe first. Secblitz can start the renewal on a computer that allows it, only after you agree, and it cannot be undone.",
        "defender.tamper_protection" => "Open Windows Security, Virus and threat protection settings, and turn Tamper Protection on. If a work or school account controls it, ask them.",
        "defender.threats" => "Open Windows Security, Protection history, and follow the steps for each active item. Do not delete files by hand.",
        "defender.scan_age" => "Run a quick scan from Windows Security. This tool never starts a full scan on its own.",
        "defender.exclusions_risky" => "Review the exclusions in Windows Security and remove any you do not recognise. Games and developer tools may have been excluded on purpose; removal is always a separate, confirmed step.",
        "smartscreen.apps" | "smartscreen.browser_policy" => "Open Windows Security, App and browser control, and turn reputation-based protection on. A policy value set by an organization must be changed by them.",
        "smart_app_control.state" => "Information only. Smart App Control cannot be turned back on once off, so it is never changed here.",
        "update.paused" | "update.reboot_overdue" => "Open Windows Update, resume or turn on updates and restart when it is convenient. If an organization controls updates, coordinate with them.",
        "update.drivers_excluded" => "Information only; confirm the exclusion is intended.",
        "ps.v2_engine" => "Remove the Windows PowerShell 2.0 feature in Windows Features unless an old script needs it.",
        "net.hosts_file" => "Secblitz can turn off only the redirect lines and undo it exactly. Otherwise have someone you trust review the hosts file. Do not paste its contents into public forums.",
        "persistence.wmi_subscriptions" => "Ask an IT-savvy helper to review WMI event consumers before removing anything; some management tools create them.",
        "services.unquoted_paths" => "Secblitz can quote the path for you when it is safe, and undo it exactly. Otherwise ask the software vendor or an IT-savvy helper to correct it.",
        "accounts.daily_admin" => "Create a standard account for daily use and keep this administrator account for installing software. Nothing is changed for you.",
        "accounts.hello_configured" => "Open Settings, Accounts, Sign-in options and add a PIN or Windows Hello. This tool never sets one for you.",
        "accounts.find_my_device" => "Open Settings, Privacy and security, Find my device and turn it on, so a lost laptop can be located and locked.",
        "vbs.kernel_stack_protection" => "Open Protection in Secblitz: it turns this on only when your computer supports it and it is safe. To look yourself, open Windows Security, then Device security, then Core isolation details.",
        "vbs.memory_integrity" => "Open Protection in Secblitz: it turns this on only when your computer supports it and every driver looks compatible. To look yourself, open Windows Security, then Device security, then Core isolation details.",
        "net.dns_encryption" => "Open Settings, Network and internet, your connection, DNS server assignment, and choose encrypted lookups. Your DNS servers are never changed by this tool.",
        "net.wifi_security" => "Change the Wi-Fi security on your router to WPA2 or WPA3 (AES). On a public network, avoid banking and passwords.",
        "persistence.run_and_tasks" => "Secblitz can switch off flagged start-up items and scheduled tasks without deleting them, and undo it exactly. Otherwise open Task Manager, Startup apps, and switch off ones you do not know.",
        "clickfix.run_history" => "Run a full virus scan, then change your passwords from another device. This check never deletes the Run history.",
        "accounts.stale_enabled" => "Review old accounts in Settings and remove the ones nobody uses.",
        "smb.shares_exposed" | "smb.server_encryption" => "Stop sharing folders you do not need and avoid Everyone access. Encryption can break older devices.",
        "firewall.user_dir_inbound_allow" => "Secblitz can switch off (not delete) those inbound allow rules and undo it exactly. Otherwise review them in Windows Security and remove ones you do not recognise. Multiplayer games may need some.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(date: &str) -> i64 {
        civil_days(date).unwrap()
    }

    #[test]
    fn civil_days_matches_known_epochs() {
        assert_eq!(day("1970-01-01"), 0);
        assert_eq!(day("2000-03-01"), 11_017);
        assert_eq!(day("2026-10-14") - day("2026-10-05"), 9);
        assert_eq!(civil_days("2026-13-01"), None);
        assert_eq!(civil_days("nonsense"), None);
    }

    #[test]
    fn every_table_date_parses() {
        for r in RELEASES {
            assert!(civil_days(r.consumer_end).is_some(), "{}", r.version);
            if let Some(m) = r.managed_end {
                assert!(civil_days(m).is_some(), "{}", r.version);
            }
        }
    }

    #[test]
    fn home_pro_24h2_ends_on_documented_date() {
        let end = day("2026-10-14");
        assert_eq!(
            release_support("24H2", 26100, "Core", end - 9),
            ReleaseSupport::Ends { days_left: 9 }
        );
        assert_eq!(
            release_support("24H2", 26100, "Professional", end),
            ReleaseSupport::Ended { days_ago: 0 }
        );
        assert_eq!(
            release_support("24H2", 26100, "CoreSingleLanguage", end + 30),
            ReleaseSupport::Ended { days_ago: 30 }
        );
    }

    #[test]
    fn enterprise_uses_its_own_dates_and_ltsc_is_not_assessed() {
        let consumer_end = day("2026-10-14");
        assert_eq!(
            release_support("24H2", 26100, "Enterprise", consumer_end + 1),
            ReleaseSupport::Ends {
                days_left: day("2027-10-12") - consumer_end - 1
            }
        );
        assert_eq!(
            release_support("24H2", 26100, "Education", consumer_end),
            ReleaseSupport::Ends {
                days_left: day("2027-10-12") - consumer_end
            }
        );
        assert_eq!(
            release_support("24H2", 26100, "EnterpriseS", consumer_end),
            ReleaseSupport::NotAssessed
        );
        assert_eq!(
            release_support("24H2", 26100, "IoTEnterpriseS", consumer_end),
            ReleaseSupport::NotAssessed
        );
        assert_eq!(
            release_support("26H1", 28000, "Enterprise", consumer_end),
            ReleaseSupport::NotAssessed
        );
    }

    #[test]
    fn mismatched_or_unknown_releases_are_not_assessed() {
        let today = day("2026-10-05");
        assert_eq!(
            release_support("24H2", 22631, "Core", today),
            ReleaseSupport::NotAssessed
        );
        assert_eq!(
            release_support("27H1", 29000, "Core", today),
            ReleaseSupport::NotAssessed
        );
        assert_eq!(
            release_support("24H2", 26100, "", today),
            ReleaseSupport::NotAssessed
        );
        assert_eq!(
            release_support("23H2", 22631, "Professional", today),
            ReleaseSupport::Ended {
                days_ago: today - day("2025-11-12")
            }
        );
        assert_eq!(
            release_support("22H2", 19045, "Core", today),
            ReleaseSupport::Ended {
                days_ago: today - day("2025-10-14")
            }
        );
        assert_eq!(
            release_support("25H2", 26200, "Core", today),
            ReleaseSupport::Ends {
                days_left: day("2027-10-13") - today
            }
        );
    }

    fn known<T: Clone>(v: T) -> Reading<T> {
        Reading::Known(v)
    }

    #[test]
    fn support_finding_thresholds() {
        let facts = |version: &str, build, edition: &str| OsSupport {
            display_version: known(version.into()),
            build: known(build),
            edition_id: known(edition.into()),
        };
        let at = |v: &OsSupport, date: &str| os_support_at(v, Some(day(date)))[0].status;
        let v24 = facts("24H2", 26100, "Professional");
        assert_eq!(at(&v24, "2026-08-01"), Healthy);
        assert_eq!(at(&v24, "2026-08-15"), Attention); // 60 days before 2026-10-14
        assert_eq!(at(&v24, "2026-10-05"), Attention);
        assert_eq!(at(&v24, "2026-10-20"), Attention);
        assert_eq!(at(&facts("26H2", 28100, "Core"), "2026-10-05"), Healthy);
        assert_eq!(at(&facts("99H9", 1, "Core"), "2026-10-05"), Informational);
        assert_eq!(
            os_support_at(&OsSupport::default(), Some(0))[0].status,
            Unknown
        );
        assert_eq!(os_support_at(&v24, None)[0].status, Unknown);
    }

    #[test]
    fn secure_boot_certificate_states() {
        let base = SecureBootCerts {
            update_completed_event: known(false),
            update_staged_event: known(false),
            update_error_event: known(false),
            servicing_status: known("Absent".into()),
            ca2023_in_db: known(false),
            secure_boot_enabled: known(true),
            maker_blocked_event: known(false),
            available_updates: known(0),
            servicing_error: known(0),
            capable: known(0),
            task_state: known("Ready".into()),
            is_vm: known(false),
            bitlocker_on: known(false),
            other_os: known(false),
        };
        let status = |v: &SecureBootCerts| secure_boot_certs(v)[0].status;
        assert_eq!(status(&base), Attention);
        let mut v = base.clone();
        v.update_completed_event = known(true);
        assert_eq!(status(&v), Healthy);
        let mut v = base.clone();
        v.servicing_status = known("Updated".into());
        assert_eq!(status(&v), Healthy);
        let mut v = base.clone();
        v.ca2023_in_db = known(true);
        assert_eq!(status(&v), Healthy);
        let mut v = base.clone();
        v.update_error_event = known(true);
        assert_eq!(status(&v), Attention);
        let mut v = base.clone();
        v.secure_boot_enabled = known(false);
        assert_eq!(status(&v), Informational);
        let mut v = base;
        v.update_completed_event = Reading::Unknown(UnknownReason::Unavailable);
        v.ca2023_in_db = Reading::Unknown(UnknownReason::Unavailable);
        assert_eq!(status(&v), Unknown);
    }

    #[test]
    fn documentation_and_guidance_cover_every_rule_id() {
        for id in [
            "os.feature_release_support",
            "boot.secure_boot_certs",
            "defender.tamper_protection",
            "defender.threats",
            "defender.scan_age",
            "defender.exclusions_risky",
            "smartscreen.apps",
            "smartscreen.browser_policy",
            "smart_app_control.state",
            "update.paused",
            "update.drivers_excluded",
            "update.reboot_overdue",
            "ps.v2_engine",
            "net.hosts_file",
            "persistence.wmi_subscriptions",
            "services.unquoted_paths",
            "accounts.stale_enabled",
            "accounts.daily_admin",
            "accounts.hello_configured",
            "accounts.find_my_device",
            "vbs.kernel_stack_protection",
            "net.dns_encryption",
            "net.wifi_security",
            "persistence.run_and_tasks",
            "clickfix.run_history",
            "smb.shares_exposed",
            "smb.server_encryption",
            "firewall.user_dir_inbound_allow",
        ] {
            let existing_area = id.starts_with("accounts.") || id.starts_with("smb.");
            assert!(
                existing_area || documentation(id).is_some_and(|u| u.starts_with("https://")),
                "{id}"
            );
            assert!(guidance(id).is_some(), "{id}");
        }
    }
}
