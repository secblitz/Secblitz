use super::*;

pub(super) fn aggregate(statuses: impl Iterator<Item = Status>) -> Status {
    let values: Vec<_> = statuses.collect();
    if values.contains(&Status::Attention) {
        Status::Attention
    } else if values.is_empty() || values.contains(&Status::Unknown) {
        Status::Unknown
    } else if values.iter().all(|s| *s == Status::Unsupported) {
        Status::Unsupported
    } else if values.contains(&Status::Unsupported) {
        Status::Unknown
    } else if values.contains(&Status::Healthy) {
        Status::Healthy
    } else {
        Status::Informational
    }
}

pub(super) fn management(probes: &[Diagnostic]) -> ManagementStatus {
    let Some(Evidence::Management(m)) = probes
        .iter()
        .find(|p| p.id == ProbeId::Management)
        .and_then(|p| p.evidence.as_ref())
    else {
        return ManagementStatus::Unknown;
    };
    if m.domain_joined.known() == Some(&true) || m.mdm_registered.known() == Some(&true) {
        return ManagementStatus::Managed;
    }
    let indicators = [
        &m.cloud_join_indicator,
        &m.defender_policy_values,
        &m.update_policy_values,
        &m.policy_manager_values,
    ];
    if indicators.iter().any(|v| v.known() == Some(&true)) {
        return ManagementStatus::PolicyPresent;
    }
    if indicators.iter().all(|v| v.known() == Some(&false))
        && m.domain_joined.known() == Some(&false)
        && m.mdm_registered.known() == Some(&false)
    {
        ManagementStatus::NoIndicatorsObserved
    } else {
        ManagementStatus::Unknown
    }
}

fn reference(id: &str) -> RuleReference {
    let url = match id.split('.').next().unwrap_or("") {
        "update" => "https://learn.microsoft.com/windows/win32/wua_sdk/using-the-windows-update-agent-api",
        "defender" => "https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-compatibility",
        "asr" => "https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference",
        "cfa" => "https://learn.microsoft.com/defender-endpoint/controlled-folders",
        "management" => "https://learn.microsoft.com/windows/client-management/mdm/",
        "boot" | "tpm" => "https://learn.microsoft.com/windows/security/hardware-security/",
        "bitlocker" => "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/",
        "vbs" => "https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
        "winre" => "https://learn.microsoft.com/windows-hardware/manufacture/desktop/reagentc-command-line-options",
        "accounts" => "https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts",
        "remote" => "https://learn.microsoft.com/windows-server/administration/performance-tuning/role/remote-desktop/session-hosts",
        "smb" => "https://learn.microsoft.com/windows-server/storage/file-server/smb-security",
        "software" => "https://learn.microsoft.com/lifecycle/",
        "browser" => "https://developer.chrome.com/docs/extensions/reference/manifest",
        "storage" => "https://learn.microsoft.com/powershell/module/storage/get-storagereliabilitycounter",
        "ntfs" => "https://learn.microsoft.com/windows/win32/cimwin32prov/win32-volume",
        "backup" => "https://learn.microsoft.com/windows-server/storage/file-server/volume-shadow-copy-service",
        "net" => "https://learn.microsoft.com/windows/security/operating-system-security/network-security/",
        "persistence" => "https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys",
        "proxy" => "https://learn.microsoft.com/windows/win32/api/winhttp/nf-winhttp-winhttpgetdefaultproxyconfiguration",
        "vpn" => "https://learn.microsoft.com/powershell/module/vpnclient/get-vpnconnection",
        "permissions" => "https://learn.microsoft.com/windows/win32/secauthz/accesscheck-function",
        _ => "https://learn.microsoft.com/windows/security/",
    };
    let url = super::checks::documentation(id).unwrap_or(url);
    RuleReference {
        id: id.into(),
        revision: 1,
        mapping_version: RULE_MAPPING_VERSION.into(),
        documentation: vec![url.into()],
    }
}
pub(super) fn a(id: &str, status: Status, detail: impl Into<String>) -> Assessment {
    Assessment {
        status,
        detail: detail.into(),
        rule: reference(id),
    }
}
pub(super) fn unavailable_assessment(probe: &Diagnostic) -> Assessment {
    a(
        "diagnostics.availability",
        probe.status,
        format!(
            "{:?} produced no evidence: {:?}. No healthy state is inferred.",
            probe.id, probe.failure
        ),
    )
}
pub(super) fn boolean(id: &str, value: &Reading<bool>, desired: bool, detail: &str) -> Assessment {
    a(
        id,
        match value.known() {
            Some(v) if *v == desired => Status::Healthy,
            Some(_) => Status::Attention,
            None => Status::Unknown,
        },
        detail,
    )
}
fn inventory<T>(id: &str, value: &Reading<Inventory<T>>, detail: &str) -> Assessment {
    a(
        id,
        match value.known() {
            Some(v) if !v.truncated => Status::Informational,
            _ => Status::Unknown,
        },
        detail,
    )
}

const DAY: u64 = 86_400;
const UPDATE_MAX_AGE_DAYS: u64 = 35;
const BACKUP_MAX_AGE_DAYS: u64 = 45;

/// Age of the newest plausible timestamp, in whole days. Zero and future dates
/// (clock errors) are ignored rather than trusted.
fn newest_age_days(dates: impl Iterator<Item = u64>, now: u64) -> Option<u64> {
    dates
        .filter(|d| *d > 0 && *d <= now + DAY)
        .max()
        .map(|d| now.saturating_sub(d) / DAY)
}

/// Freshness from local Windows Update history only: the newest successful
/// install whose title looks like a quality update. History proves what was
/// installed, not that nothing newer is available.
pub(super) fn update_freshness(
    entries: Option<&[UpdateEvent]>,
    now: Option<u64>,
) -> (Status, String) {
    let (Some(entries), Some(now)) = (entries, now) else {
        return (
            Status::Unknown,
            "Windows Update history could not be read, so recent updates are unknown.".into(),
        );
    };
    let age = newest_age_days(
        entries
            .iter()
            .filter(|e| e.operation == 1 && e.result_code == 2 && e.quality_title_hint)
            .map(|e| e.date_unix_seconds),
        now,
    );
    match age {
        Some(days) if days <= UPDATE_MAX_AGE_DAYS => (Status::Healthy, format!("The latest successful quality update in Windows Update history was installed {days} day(s) ago. History does not prove nothing newer is waiting.")),
        Some(days) => (Status::Attention, format!("No recent security update found: the latest successful quality update in history was installed {days} days ago (more than {UPDATE_MAX_AGE_DAYS}).")),
        None => (Status::Attention, "No recent security update found in Windows Update history (quality updates are recognized by English titles; other languages may not match).".into()),
    }
}

/// Everything the backup probe could read. A `None` means that source could
/// not be read, which is different from "read and found nothing".
pub(super) struct BackupSources<'a> {
    pub events: Option<&'a [BackupEvent]>,
    pub shadow_copies: Option<u32>,
    pub file_history_last: Option<u64>,
    pub onedrive_folders: Option<u32>,
    pub file_history_drive_plugged_in: Option<bool>,
}

fn days_ago(days: u64) -> String {
    match days {
        0 => "today".into(),
        1 => "1 day ago".into(),
        n => format!("{n} days ago"),
    }
}

/// Backup evidence from Windows Backup events, File History and OneDrive
/// folder backup, plus same-PC restore points. None of it proves what is
/// covered or that a restore works, so this is never more than "a backup was
/// seen", and a source that cannot be read is never counted as a backup.
pub(super) fn backup_coverage(src: &BackupSources, now: Option<u64>) -> (Status, String) {
    let shadows = match src.shadow_copies {
        Some(0) => "No restore points on this computer.",
        Some(_) => {
            "This computer has restore points, but those live on the same drive and are not a backup."
        }
        None => "Restore points could not be counted.",
    };
    let Some(now) = now else {
        return (
            Status::Unknown,
            "Backup history could not be read, so backups are unknown.".into(),
        );
    };
    let mut seen: Vec<(u64, &str)> = Vec::new();
    if let Some(days) = src
        .events
        .and_then(|e| newest_age_days(e.iter().map(|x| x.date_unix_seconds), now))
    {
        seen.push((days, "Windows Backup"));
    }
    if let Some(days) = src
        .file_history_last
        .and_then(|t| newest_age_days(std::iter::once(t), now))
    {
        seen.push((days, "File History"));
    }
    let onedrive = match src.onedrive_folders {
        Some(0) => " OneDrive does not back up Documents, Pictures or Desktop.".to_string(),
        Some(n) => format!(" OneDrive backs up {n} of Documents, Pictures and Desktop."),
        None => String::new(),
    };
    let unplug = if src.file_history_drive_plugged_in == Some(true) {
        " Unplug your backup drive when it's not backing up. Ransomware can scramble a drive that stays plugged in."
    } else {
        ""
    };
    seen.sort();
    if let Some((days, name)) = seen.first() {
        let line = format!(
            "Last backup: {} ({name}).{onedrive} {shadows}{unplug}",
            days_ago(*days)
        );
        let note = " What it covers and whether a restore works are not tested.";
        return if *days <= BACKUP_MAX_AGE_DAYS {
            (Status::Healthy, format!("{line}{note}"))
        } else {
            (Status::Attention, format!("No recent backup found. {line}"))
        };
    }
    if src.onedrive_folders.is_some_and(|n| n > 0) {
        return (
            Status::Informational,
            format!("No backup time could be read.{onedrive} {shadows}{unplug}"),
        );
    }
    let unreadable = src.events.is_none() && src.file_history_last.is_none();
    if unreadable {
        return (
            Status::Unknown,
            "Backup history could not be read, so backups are unknown.".into(),
        );
    }
    (
        Status::Attention,
        format!("No backup found.{onedrive} Backup tools other than Windows Backup, File History and OneDrive are not checked. {shadows}{unplug}"),
    )
}

pub(super) fn assess(probe: &Diagnostic) -> Vec<Assessment> {
    use Status::*;
    let mut out = Vec::new();
    match probe.evidence.as_ref().unwrap() {
        Evidence::UpdateCache(v) => {
            let status = match (v.result_code.known(), v.missing.known()) {
                (Some(2), Some(items)) if items.items.iter().any(|u| u.quality_classification) => Attention,
                (Some(2), Some(items)) if !items.truncated => Informational,
                _ => Unknown,
            };
            out.push(a("update.cached_quality", status, "Missing security/update-rollup/critical software updates, including hidden entries, are classified by WUA category GUIDs. These can include Microsoft application updates. An empty offline cache does not establish that Windows is up to date."));
            out.push(inventory("update.cache_coverage", &v.missing, "Offline metadata may be stale or absent; only the first 512 missing software updates are inspected."));
        }
        Evidence::UpdateHistory(v) => {
            out.push(inventory("update.history_coverage", &v.entries, "At most 256 history records. Quality classification from localized titles is a hint; histories do not expose update categories."));
            let status = match v.entries.known() {
                Some(x) if x.items.iter().any(|e| e.operation == 1 && matches!(e.result_code, 3..=5)) => Attention,
                Some(x) if x.items.iter().any(|e| !matches!(e.operation, 1..=2) || e.result_code > 5) => Unknown,
                Some(_) => Informational,
                None => Unknown,
            };
            let (freshness, detail) = update_freshness(v.entries.known().map(|x| x.items.as_slice()), super::now());
            out.push(a("update.freshness", freshness, detail));
            out.push(a("update.failed_install", status, "Failed, aborted or partially successful installation entries need review, including entries with a quality-update title hint. A later success may supersede a failure; unresolved failure is not inferred."));
        }
        Evidence::DefenderHealth(v) => {
            for (id, fact) in [("service", &v.service_enabled), ("antivirus", &v.antivirus_enabled), ("realtime", &v.realtime_enabled), ("behavior", &v.behavior_enabled), ("ioav", &v.ioav_enabled), ("network_inspection", &v.nis_enabled)] {
                out.push(boolean(&format!("defender.{id}"), fact, true, "Reported Defender effective health. Passive mode or a third-party provider must be reviewed before interpreting disabled components; nothing is enabled automatically."));
            }
            out.push(a("defender.mode", match v.running_mode.known().map(String::as_str) {
                Some("Normal") => Healthy,
                Some("Passive Mode" | "SxS Passive Mode" | "EDR Block Mode") => Informational,
                _ => Unknown,
            }, "Reported antivirus running mode; competing provider registrations are reported separately and are not proof of provider health."));
            out.push(a("defender.signatures", match (v.signatures_out_of_date.known(), v.signatures_age_days.known()) {
                (Some(true), _) => Attention,
                (_, Some(days)) if *days != u32::MAX && *days > 7 => Attention,
                (Some(false), Some(0..=7)) => Healthy,
                _ => Unknown,
            }, "Out-of-date flag or more than seven days of signature age merits review. Unknown age is not fresh signatures."));
        }
        Evidence::DefenderPolicy(v) => {
            out.push(inventory("asr.inventory", &v.asr, "Reported ASR configuration; an absent rule is not evidence of enforced protection."));
            if let Some(rules) = v.asr.known() {
                if rules.items.is_empty() { out.push(a("asr.configured", Attention, "No explicit ASR rules were returned; review applicability and compatibility before configuring a baseline.")); }
                for rule in &rules.items {
                    let (status, mode) = match rule.mode { 0 => (Attention, "disabled"), 1 => (Informational, "block"), 2 => (Attention, "audit"), 6 => (Attention, "warn"), _ => (Unknown, "unrecognized") };
                    out.push(a("asr.configured", status, format!("ASR {} reports {mode} mode. Configuration is not proof that every rule prerequisite or runtime enforcement is satisfied.", rule.id)));
                }
            }
            out.push(a("cfa.configured", match v.cfa_mode.known() { Some(0 | 2 | 4) => Attention, Some(1 | 3) => Informational, _ => Unknown }, "CFA modes: 0 disabled, 1 enabled, 2 audit, 3 block disk modification only, 4 audit disk modification only. Partial disk modes do not imply folder protection."));
            out.push(a("asr.effective", Unknown, "ASR/CFA preference readback alone cannot prove runtime enforcement, exclusions, cloud prerequisites or policy precedence."));
        }
        Evidence::SecurityProviders(v) => {
            out.push(inventory("defender.providers", &v.antivirus, "Antivirus registrations are inventory, not effective protection. ProductState is preserved without undocumented bit decoding."));
            out.push(inventory("defender.firewall_providers", &v.firewall, "Third-party firewall registrations are inventory; no application paths are collected or executed."));
            if v.antivirus.known().is_some_and(|x| x.items.is_empty()) { out.push(a("defender.provider_absence", Attention, "No antivirus registration was returned. Confirm Windows Security provider health; server editions may lack SecurityCenter2.")); }
        }
        Evidence::Management(_) => {
            let status = management(std::slice::from_ref(probe));
            out.push(a("management.authority", if status == ManagementStatus::Unknown { Unknown } else { Informational }, format!("Management evidence: {status:?}. Policy indicators may be local or stale; absence of these indicators does not authorize changes or prove the machine unmanaged.")));
        }
        Evidence::SecureBoot(v) => out.push(boolean("boot.secure_boot", &v.enabled, true, "UEFI Secure Boot query; unavailable firmware support or access remains unknown.")),
        Evidence::Tpm(v) => {
            for (id, fact) in [("present", &v.present), ("ready", &v.ready), ("enabled", &v.enabled), ("activated", &v.activated)] { out.push(boolean(&format!("tpm.{id}"), fact, true, "TPM reported state; no initialization, clearing or ownership change is attempted.")); }
        }
        Evidence::BitLocker(v) => {
            out.push(inventory("bitlocker.inventory", &v.volumes, "Volume ordinals only; recovery keys, protectors, mount paths and escrow data are not collected."));
            if let Some(volumes) = v.volumes.known() {
                if volumes.items.is_empty() { out.push(a("bitlocker.protection", Unknown, "No volumes returned; encryption coverage is unknown.")); }
                for (i, vol) in volumes.items.iter().enumerate() {
                    out.push(a("bitlocker.protection", match (vol.protection_status.known(), vol.volume_status.known(), vol.encryption_percentage.known()) {
                        (Some(0), _, _) => Attention,
                        (Some(1), Some(1), Some(100)) => Healthy,
                        (Some(1), Some(0..=5), Some(0..=100)) => Attention,
                        _ => Unknown,
                    }, format!("Volume {i}: protection must be on and encryption complete. Suspended protection is not secure merely because bytes remain encrypted.")));
                }
            }
            out.push(a("bitlocker.recovery", Unknown, "Recovery-key availability and escrow are not assessed. Preserve recovery access before any future firmware or encryption change."));
        }
        Evidence::Vbs(v) => {
            out.push(a("vbs.running", match v.status.known() { Some(2) => Healthy, Some(0 | 1) => Attention, _ => Unknown }, "DeviceGuard VBS status distinguishes disabled, configured but not running, and running."));
            out.push(a("vbs.memory_integrity", match v.running_services.known() { Some(s) if s.iter().any(|n| *n > 7) => Unknown, Some(s) if s.contains(&2) => Healthy, Some(_) => Attention, _ => Unknown }, "HVCI/memory integrity must be listed in running services (code 2); configured services alone are insufficient."));
            out.extend(super::checks::kernel_stack(v));
        }
        Evidence::WinRe(v) => out.push(boolean("winre.enabled", &v.enabled, true, "REAgentC reported status only. Enabled WinRE is not evidence that recovery media boots or a restore succeeds.")),
        Evidence::Accounts(v) => {
            out.push(a("accounts.admin_membership", match v.administrator_count.known() { Some(0) => Unknown, Some(_) => Informational, None => Unknown }, "Direct built-in Administrators group member count only; nested groups, enabled state and the original user's effective token are not inferred."));
            out.push(boolean("accounts.guest", &v.guest_enabled, false, "Built-in Guest account identified by RID 501, independent of localized or renamed account names."));
        }
        Evidence::RemoteAccess(v) => {
            out.push(boolean("remote.rdp", &v.rdp_denied, true, "RDP connection acceptance configuration. An enabled service may be intentional; confirm a need and boundary before changing it."));
            out.push(boolean("remote.nla", &v.rdp_nla_required, true, "RDP NLA configuration; effective reachability and resultant policy are not proven by this registry preference."));
            for (id, f, desired) in [("smb.v1", &v.smb1_enabled, false), ("smb.server_signing", &v.smb_server_signing_required, true), ("smb.client_signing", &v.smb_client_signing_required, true), ("smb.guest", &v.smb_guest_logons_enabled, false)] { out.push(boolean(id, f, desired, "SMB reported configuration. Legacy printers/NAS may require migration; do not silently allow SMB1, unsigned SMB or guest access.")); }
        }
        Evidence::Software(v) => {
            out.push(inventory("software.inventory", &v.applications, "Machine uninstall registrations are not authenticated package identities or a vulnerability scan."));
            if let Some(apps) = v.applications.known() {
                for app in &apps.items {
                    if let SupportAssessment::KnownEndOfSupport { ended_on, reference } = super::support_assessment(app) {
                        let mut assessment = a("software.end_of_support", Attention, format!("{} ({}) matches a product whose vendor support ended {ended_on}. Verify the registration and plan removal or replacement.", app.name, app.version));
                        assessment.rule.documentation.push(reference);
                        out.push(assessment);
                    }
                }
            }
            out.push(a("software.support_coverage", Unknown, "Products outside the exact end-of-support mapping have unassessed support; installed version numbers are not guessed to be current or supported."));
        }
        Evidence::BrowserExtensions(v) => {
            out.push(inventory("browser.inventory", &v.extensions, "Bounded original-user extension inventory. Chromium version directories can include stale copies; installation does not establish enabled state."));
            if let Some(exts) = v.extensions.known() {
                for extension in &exts.items {
                    if extension.broad_host_access.known() == Some(&true) || extension.native_messaging.known() == Some(&true) { out.push(a("browser.permissions", Attention, format!("{:?} extension {} declares broad host access or native messaging. Review necessity and publisher; this is not a malware verdict.", extension.browser, extension_label(extension)))); }
                }
            }
        }
        Evidence::Storage(v) => {
            out.push(inventory("storage.inventory", &v.disks, "Disk health and reliability counters are provider-reported, not a surface scan or prediction of remaining lifetime."));
            if let Some(disks) = v.disks.known() {
                if disks.items.is_empty() { out.push(a("storage.health", Unknown, "No physical disks returned.")); }
                for (i, disk) in disks.items.iter().enumerate() {
                    out.push(a("storage.health", match disk.health_status.known() { Some(0) => Healthy, Some(1 | 2) => Attention, _ => Unknown }, format!("Disk {i}: reported health status.")));
                    out.push(a("storage.reliability", match (disk.read_errors_uncorrected.known(), disk.write_errors_uncorrected.known(), disk.wear_percent.known()) {
                        (Some(r), Some(w), _) if *r > 0 || *w > 0 => Attention,
                        (_, _, Some(100)) => Attention,
                        (Some(0), Some(0), Some(0..=99)) => Informational,
                        _ => Unknown,
                    }, format!("Disk {i}: uncorrected errors and wear counters. Missing/sentinel counters are unknown; zero errors is not proof of disk reliability.")));
                }
            }
        }
        Evidence::Ntfs(v) => {
            out.push(inventory("ntfs.inventory", &v.volumes, "Local fixed volumes only; no chkdsk, repair, labels or private mount paths."));
            if let Some(volumes) = v.volumes.known() {
                if volumes.items.is_empty() { out.push(a("ntfs.dirty", Unknown, "No local fixed volumes returned.")); }
                for (i, volume) in volumes.items.iter().enumerate() {
                    if volume.filesystem.known().map(String::as_str) == Some("NTFS") { out.push(boolean("ntfs.dirty", &volume.dirty, false, &format!("Volume {i}: NTFS dirty-bit state; a clear bit does not prove filesystem integrity."))); }
                    else { out.push(a("ntfs.dirty", if volume.filesystem.known().is_some() { Unsupported } else { Unknown }, format!("Volume {i}: NTFS assessment not applicable or filesystem unknown."))); }
                    out.push(a("ntfs.free_space", match (volume.free_bytes.known(), volume.capacity_bytes.known()) {
                        (Some(f), Some(c)) if *c > 0 && f <= c => if *f < 5 * 1024 * 1024 * 1024 || (*f as u128) * 100 < (*c as u128) * 5 { Attention } else { Healthy },
                        _ => Unknown,
                    }, format!("Volume {i}: attention below 5 GiB or 5 percent free; this is an operational threshold, not a universal update requirement.")));
                }
            }
        }
        Evidence::Backup(v) => {
            out.push(a("backup.shadow_copies", if v.shadow_copy_count.known().is_some() { Informational } else { Unknown }, "Local shadow copies are same-device recovery evidence, not an independent backup."));
            out.push(inventory("backup.events", &v.success_events, "At most 64 Windows Backup success event timestamps from the last 90 days. Success-event evidence does not identify protected data or prove restore viability."));
            let (coverage, detail) = backup_coverage(
                &BackupSources {
                    events: v.success_events.known().map(|x| x.items.as_slice()),
                    shadow_copies: v.shadow_copy_count.known().copied(),
                    file_history_last: v.file_history_last_unix_seconds.known().copied(),
                    onedrive_folders: v.onedrive_folders.known().copied(),
                    file_history_drive_plugged_in: v
                        .file_history_drive_removable_connected
                        .known()
                        .copied(),
                },
                super::now(),
            );
            out.push(a("backup.coverage", coverage, detail));
        }
        Evidence::Adapters(v) => {
            out.push(inventory("network.adapters", &v.adapters, "Operational state without interface names, hardware identifiers or addresses; virtual adapters do not imply a VPN."));
            if let Some(adapters) = v.adapters.known() {
                out.push(a("network.link", if adapters.items.is_empty() || adapters.items.iter().any(|x| !matches!(x.operational_status.known(), Some(1..=7))) { Unknown } else { Informational }, "Link state is not an Internet connectivity or security test. A disconnected adapter may be intentional."));
            }
        }
        Evidence::Dns(v) => {
            out.push(inventory("dns.configuration", &v.interfaces, "Server counts only. DNS destinations, queries and suffixes are not collected; no resolution or DNS-leak test is performed."));
            if let Some(interfaces) = v.interfaces.known() {
                out.push(a("dns.address_family", if interfaces.items.iter().all(|i| matches!(i.address_family, 2 | 23)) { Informational } else { Unknown }, "Only Windows AF_INET and AF_INET6 entries are recognized; configured counts do not prove DNS availability, trust or encryption."));
            }
        }
        Evidence::Proxy(v) => out.push(a("proxy.machine_default", if v.default_mode.known().is_some() { Informational } else { Unknown }, "Machine WinHTTP default mode only; endpoint and bypass strings are freed without inspection. Per-user, auto-discovery and per-application overrides are not inferred.")),
        Evidence::Vpn(v) => out.push(inventory("vpn.machine_connections", &v.connections, "Built-in all-user VPN status and split-tunnel flags only. Third-party and per-user VPNs, traffic routing and leak protection are not assessed.")),
        Evidence::Permissions(v) => {
            out.push(inventory("permissions.inventory", &v.services, "Existing fixed-service DACL audit; candidate broad-principal rights, not an effective AccessCheck."));
            if let Some(services) = v.services.known() {
                for service in &services.items { out.push(a("permissions.service", if service.status == Healthy { Unknown } else { service.status }, format!("{}: limited broad-principal ACE assessment; unknown/complex ACE semantics must not be treated as safe.", service.service))); }
            }
            out.push(a("permissions.effective_access", Unknown, "Effective permissions depend on tokens, deny/conditional ACEs, ownership and other objects; no complete effective-access claim is made."));
        }
        Evidence::OsSupport(v) => out.extend(super::checks::os_support(v)),
        Evidence::SecureBootCerts(v) => out.extend(super::checks::secure_boot_certs(v)),
        Evidence::DefenderProtection(v) => out.extend(super::checks::defender_protection(v)),
        Evidence::SmartScreen(v) => out.extend(super::checks::smartscreen(v)),
        Evidence::UpdatePolicy(v) => out.extend(super::checks::update_policy(v)),
        Evidence::LegacyFeatures(v) => out.extend(super::checks::legacy_features(v)),
        Evidence::HostsFile(v) => out.extend(super::checks::hosts_file(v)),
        Evidence::Persistence(v) => out.extend(super::checks::persistence(v)),
        Evidence::AccountHygiene(v) => out.extend(super::checks::account_hygiene(v)),
        Evidence::Sharing(v) => out.extend(super::checks::sharing(v)),
        Evidence::FirewallRules(v) => out.extend(super::checks::firewall_rules(v)),
        Evidence::AccountSetup(v) => out.extend(super::checks::account_setup(v)),
        Evidence::WindowsHello(v) => out.extend(super::checks::windows_hello(v)),
        Evidence::DnsEncryption(v) => out.extend(super::checks::dns_encryption(v)),
        Evidence::WifiSecurity(v) => out.extend(super::checks::wifi_security(v)),
        Evidence::Autostart(v) => out.extend(super::checks::autostart(v)),
        Evidence::RunHistory(v) => out.extend(super::checks::run_history(v)),
    }
    // A healthy subset must not turn a partially unreadable probe into Healthy.
    // Walk the typed serialization (never raw/native input) so newly added facts
    // inherit this invariant even before a dedicated recommendation is added.
    fn unknown_facts(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Object(fields)
                if fields.get("state").and_then(serde_json::Value::as_str) == Some("Unknown") =>
            {
                1
            }
            serde_json::Value::Object(fields) => fields.values().map(unknown_facts).sum(),
            serde_json::Value::Array(items) => items.iter().map(unknown_facts).sum(),
            _ => 0,
        }
    }
    let missing = serde_json::to_value(probe.evidence.as_ref().unwrap())
        .map(|v| unknown_facts(&v))
        .unwrap_or(1);
    if missing > 0 {
        out.push(a("diagnostics.evidence_completeness", Unknown, format!("{missing} typed fact(s) in this probe are unavailable, invalid or unassessed. Partial evidence is retained; unreadable facts are not healthy by default.")));
    }
    out
}

fn compatibility(needs: &CompatibilityNeeds, profile: Profile) -> Vec<String> {
    let mut notes = Vec::new();
    if needs.printers {
        notes.push("Printers: verify signed drivers and authenticated modern protocols; replace incompatible devices rather than broadly disabling SMB or firewall protections.".into());
    }
    if needs.nas {
        notes.push("NAS: check SMB2/3, signing, authenticated accounts and offline backup compatibility; do not silently enable SMB1 or guest access.".into());
    }
    if needs.vpn {
        notes.push("VPN: validate vendor support, routes and DNS with the administrator before tightening policy; preserve required VPN operation without broad bypasses.".into());
    }
    if needs.games || profile == Profile::Gaming {
        notes.push("Games: test anti-cheat and signed drivers against VBS/HVCI and ASR; keep protections, measure actual impact and seek vendor fixes rather than global exclusions.".into());
    }
    if needs.development || profile == Profile::Development {
        notes.push("Development: test compilers, debuggers, containers and virtualization with ASR/CFA; use isolated workspaces and narrowly reviewed exceptions rather than blanket developer-folder exclusions.".into());
    }
    notes
}

pub(super) fn recommendation(
    a: &Assessment,
    profile: Profile,
    management: ManagementStatus,
    needs: &CompatibilityNeeds,
) -> Recommendation {
    let area = a.rule.id.split('.').next().unwrap_or("");
    let area_guidance = match area {
        "update" => "Review Windows Update history and the organization's update channel; a separately authorized online check is needed for current applicability. Do not reset services or policy based on cached evidence.",
        "defender" => "Review Windows Security and the active provider's supported health console. Reconcile passive mode, tamper protection and management before proposing any change.",
        "asr" | "cfa" => "Review rule applicability and effective policy with the security owner; stage audit and compatibility testing before approved enforcement. Do not automatically enable rules or add broad exclusions.",
        "boot" | "tpm" | "bitlocker" | "winre" => "Confirm recovery access and vendor firmware guidance before any separately approved change. Never clear a TPM, expose a recovery key, or infer a verified restore from configuration.",
        "vbs" => "Review supported firmware and signed-driver compatibility; investigate configured-but-not-running state and test workloads before approved changes. Do not disable isolation for performance by default.",
        "backup" => "Identify important data, document off-device backup coverage and retention, then arrange an explicit restore test. Record restore evidence separately from settings and success events.",
        "storage" | "ntfs" => "Preserve a current independent backup; review storage-vendor health and Windows events. Plan any repair separately; this collector performs no repair or surface scan.",
        "software" => "Verify the registered product with its vendor, then plan a supported update or replacement. Unmapped products remain unassessed, not supported by assumption.",
        "smb" | "remote" | "accounts" => "Confirm who needs administrative or remote access and restrict unnecessary exposure through a separately reviewed change; retain required authenticated printer/NAS and remote-support workflows.",
        "permissions" => "Review the fixed service's DACL with its owner and a token-aware access evaluation. Candidate ALLOW bits alone do not prove effective exploitation or authorize repair.",
        "browser" => "Review the original user's installed extension publishers, necessity and permissions; remove unwanted extensions only with explicit user authorization.",
        _ => "Resolve the missing or ambiguous evidence with the relevant Windows or vendor console before making a security claim or proposing changes.",
    };
    let guidance = super::checks::guidance(&a.rule.id).unwrap_or(area_guidance);
    Recommendation {
        rule: a.rule.clone(), profile, reason: a.detail.clone(),
        guidance: format!("{guidance} {}", match management {
            ManagementStatus::Managed | ManagementStatus::PolicyPresent => "Management/policy evidence is present: coordinate with the policy owner and do not override policy.",
            ManagementStatus::Unknown => "Management authority is unknown; establish ownership and effective policy before changes.",
            ManagementStatus::NoIndicatorsObserved => "No inspected management indicators were observed; this is not authorization to change protections.",
        }),
        management, compatibility_notes: compatibility(needs, profile),
    }
}

pub(super) fn profile_recommendations(
    profile: Profile,
    management: ManagementStatus,
    needs: &CompatibilityNeeds,
) -> Vec<Recommendation> {
    let detail = match profile {
        Profile::Everyday => "Everyday: prioritize current supported software, functioning antivirus, encryption recovery access and an independently restorable backup; keep workload-required protections enabled.",
        Profile::Gaming => "Gaming: retain the Everyday baseline; assess measured anti-cheat/driver compatibility rather than disabling Defender, VBS, firewall or update services for speculative performance.",
        Profile::Development => "Development: retain the Everyday baseline; isolate untrusted builds, use least-privilege daily accounts, and review ASR/CFA against actual compiler/container workflows.",
        Profile::HigherSecurity => "HigherSecurity: prioritize verified Secure Boot, TPM-backed encryption, running VBS/HVCI, reduced remote exposure and an evaluated ASR/CFA block baseline, with staged compatibility and recovery testing.",
    };
    vec![recommendation(
        &a("profile.baseline", Status::Informational, detail),
        profile,
        management,
        needs,
    )]
}

fn extension_label(extension: &BrowserExtension) -> String {
    if extension.name.is_empty() {
        extension.id.clone()
    } else {
        format!("\"{}\" ({})", extension.name, extension.id)
    }
}
