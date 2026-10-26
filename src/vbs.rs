//! Safety decisions for Memory integrity (`vbs.memory_integrity`) and Kernel-mode Hardware-enforced Stack Protection (`vbs.kernel_stack_protection`). Pure and host-testable; Windows facts come from `platform/windows.rs` and `platform/vbs.ps1`.
//! Sources (Microsoft Learn): HypervisorEnforcedCodeIntegrity `Enabled`/`WasEnabledBy` (2 lets the Windows Security switch behave normally) and `Locked` (never written here); Win32_DeviceGuard AvailableSecurityProperties (1 hypervisor, 2 Secure Boot), SecurityServicesConfigured/Running (2 memory integrity, 5 stack protection, 6 its audit mode).
//! Driver rules: no section both writable and executable, section alignment a multiple of 0x1000, import address table not in an executable section. Other causes (runtime executable allocations) are invisible in a file, so the scan can only rule drivers out, never prove one works.
//! Stack protection needs memory integrity and shadow stacks (Intel CET or AMD). Event IDs 3111 and 3074 are in Microsoft-Windows-CodeIntegrity/Operational.

mod cpu;
mod pe;

pub use cpu::{cpu_has_shadow_stacks, cpu_hypervisor_vendor};
pub use pe::{scan_pe, PeProblem};

use crate::model::{CheckStatus, Finding};
use serde::Deserialize;

pub const MEMORY_INTEGRITY: &str = "vbs.memory_integrity";
pub const STACK_PROTECTION: &str = "vbs.kernel_stack_protection";

pub fn is_vbs_check_id(id: &str) -> bool {
    id == MEMORY_INTEGRITY || id == STACK_PROTECTION
}

// Exact "not offered" reasons. advice.rs knows each one and shows a calm line.
pub const NOT_SUPPORTED: &str =
    "Not offered: this computer's hardware or firmware does not support it";
pub const LOCKED: &str = "Not offered: it is locked in your computer's firmware";
pub const DRIVER: &str = "Not offered: a driver on this computer may not work with it";
pub const DRIVERS_UNREADABLE: &str = "Not offered: we could not check this computer's drivers";
pub const ALREADY_ON: &str = "Not offered: it is already running";
pub const NEEDS_MEMORY_INTEGRITY: &str = "Not offered: it needs memory integrity running first";
pub const NEEDS_RESTART: &str =
    "Not offered: restart your computer to finish memory integrity first";
pub const NO_SHADOW_STACKS: &str = "Not offered: this computer's processor does not support it";
pub const UNREADABLE: &str = "Not offered: we could not check this computer's protection support";
pub const SET_BY_HAND: &str =
    "Not offered: this computer's virtualization security was set up by hand";
pub const OLD_WINDOWS: &str = "Not offered: this version of Windows does not support it";

pub fn is_driver_reason(reason: &str) -> bool {
    reason
        .strip_prefix(DRIVER)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(": "))
}

pub const MEMORY_INTEGRITY_NOT_RUNNING: &str = "Memory integrity not running";
pub const STACK_NOT_RUNNING: &str = "Kernel stack protection not running";
pub const DEVICE_BLOCKED: &str = "A device may not be working";
pub const BLOCKED_PREFIX: &str = "blocked: ";
/// The finding detail carries the start-up time (Unix seconds) so the engine
/// can tell "restarted since the change" from "still waiting for a restart".
pub const BOOT_PREFIX: &str = "boot: ";
/// The engine adds this when the control's change is the newest one that can
/// be undone, so "Undo" really undoes it and nothing else.
pub const UNDO_READY: &str = "undo: latest";

pub fn finding_control(title: &str) -> Option<&'static str> {
    match title {
        MEMORY_INTEGRITY_NOT_RUNNING | DEVICE_BLOCKED => Some(MEMORY_INTEGRITY),
        STACK_NOT_RUNNING => Some(STACK_PROTECTION),
        _ => None,
    }
}

pub fn boot_from_detail(detail: &str) -> Option<i64> {
    let rest = detail.split_once(BOOT_PREFIX)?.1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

pub fn split_batches(ids: &[String]) -> Vec<Vec<String>> {
    let mut batches = Vec::new();
    let ordinary: Vec<String> = ids
        .iter()
        .filter(|i| !is_vbs_check_id(i))
        .cloned()
        .collect();
    if !ordinary.is_empty() {
        batches.push(ordinary);
    }
    for id in ids.iter().filter(|i| is_vbs_check_id(i)) {
        batches.push(vec![id.clone()]);
    }
    batches
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverFile {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRow {
    pub name: String,
    pub kind: u32,
    pub start: u32,
    pub image: Option<String>,
}

/// Turn a service's image setting into an absolute path. Handles the forms
/// Windows writes: `\SystemRoot\...`, `%SystemRoot%\...`, `\??\C:\...`,
/// `system32\drivers\x.sys` (relative to the Windows folder) and `C:\...`.
/// Anything else is None: the caller must treat that as "could not check".
pub fn resolve_image(raw: &str, windows: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    // Keep only the file: some entries carry arguments after the name. The
    // name ends at ".sys" followed by the end, a space or a quote, so a
    // folder such as `Foo.System` is never cut in the middle.
    let text = if let Some(quoted) = trimmed.strip_prefix('"') {
        quoted.split('"').next()?
    } else {
        let lower = trimmed.to_ascii_lowercase();
        let mut end = None;
        for (at, _) in lower.match_indices(".sys") {
            let next = lower[at + 4..].chars().next();
            if next.is_none_or(|c| c.is_whitespace() || c == '"') {
                end = Some(at + 4);
                break;
            }
        }
        trimmed.get(..end?)?
    };
    let text = text.trim();
    if !text.to_ascii_lowercase().ends_with(".sys") {
        return None;
    }
    let windows = windows.trim_end_matches('\\');
    let lower = text.to_ascii_lowercase();
    let full = if let Some(rest) = text.strip_prefix(r"\??\") {
        rest.to_owned()
    } else if lower.starts_with(r"\systemroot\") {
        format!("{windows}\\{}", &text[12..])
    } else if lower.starts_with("%systemroot%\\") {
        format!("{windows}\\{}", &text[13..])
    } else if text.len() > 2 && text.as_bytes()[1] == b':' && text.as_bytes()[2] == b'\\' {
        text.to_owned()
    } else if !text.starts_with('\\') && !text.contains(':') {
        format!("{windows}\\{text}")
    } else {
        return None;
    };
    let bytes = full.as_bytes();
    let absolute =
        bytes.len() > 7 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    (absolute && !full.split('\\').any(|part| part == "..")).then_some(full)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DriverList {
    pub files: Vec<DriverFile>,
    pub unresolved: Vec<String>,
}

pub fn driver_files(services: &[ServiceRow], loaded: &[String], windows: &str) -> DriverList {
    let mut out = DriverList::default();
    let mut push = |name: &str, path: String| {
        let lower = path.to_ascii_lowercase();
        if !lower.ends_with(".sys")
            || out
                .files
                .iter()
                .any(|d| d.path.to_ascii_lowercase() == lower)
        {
            return;
        }
        out.files.push(DriverFile {
            name: file_name(&path)
                .or_else(|| safe_name(name))
                .unwrap_or_else(|| "driver".into()),
            path,
        });
    };
    for service in services {
        if !matches!(service.kind, 1 | 2) || service.start > 3 {
            continue;
        }
        let path = match &service.image {
            Some(image) => resolve_image(image, windows),
            None => Some(format!(
                "{}\\System32\\drivers\\{}.sys",
                windows.trim_end_matches('\\'),
                service.name
            )),
        };
        match path {
            Some(path) => push(&service.name, path),
            None => out
                .unresolved
                .push(safe_name(&service.name).unwrap_or_else(|| "driver".into())),
        }
    }
    // Loaded modules include .exe and .dll files (the kernel itself): only
    // drivers are scanned, and those are skipped on purpose.
    for module in loaded {
        if let Some(path) = resolve_image(module, windows) {
            push("", path);
        }
    }
    out
}

fn file_name(path: &str) -> Option<String> {
    let name = path.rsplit('\\').next()?;
    safe_name(name)
}

pub fn safe_name(name: &str) -> Option<String> {
    let ok = !name.is_empty()
        && name.chars().count() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    ok.then(|| name.to_owned())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scan {
    pub flagged: Vec<(String, Vec<PeProblem>)>,
    pub unreadable: Vec<String>,
}

/// Scan every driver whose image exists. A missing file is not a problem (the
/// driver cannot load); one that cannot be read is reported, never assumed fine.
pub fn scan_files(files: &[DriverFile], read: &dyn Fn(&str) -> std::io::Result<Vec<u8>>) -> Scan {
    let mut scan = Scan::default();
    for file in files {
        match read(&file.path) {
            Ok(bytes) => {
                let problems = scan_pe(&bytes);
                if !problems.is_empty() {
                    scan.flagged.push((file.name.clone(), problems));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => scan.unreadable.push(file.name.clone()),
        }
    }
    scan
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Facts {
    pub available: Vec<u32>,
    pub required: Vec<u32>,
    pub configured: Vec<u32>,
    pub running: Vec<u32>,
    pub virt_firmware: Option<bool>,
    /// Win32_DeviceGuard VirtualizationBasedSecurityStatus: 2 means running.
    pub vbs_status: Option<u32>,
    pub build: Option<u32>,
    pub lock_vbs: Option<u32>,
    pub lock_hvci: Option<u32>,
    pub lock_stack: Option<u32>,
    /// DeviceGuard `Mandatory`: Windows refuses to start without VBS.
    pub mandatory: Option<u32>,
    pub enable_vbs: Option<u32>,
    pub require_platform: Option<u32>,
    pub enabled_hvci: Option<u32>,
    pub enabled_stack: Option<u32>,
    pub boot_unix: Option<i64>,
    pub blocked: Vec<String>,
    /// Win32_ComputerSystem HypervisorPresent; the only hypervisor fact on arm64.
    pub hypervisor_present: Option<bool>,
    /// Vendor the processor reports for the hypervisor it runs under, filled
    /// in by the caller from CPUID (not by the script). None: no hypervisor.
    #[serde(skip)]
    pub hypervisor_vendor: Option<String>,
}

pub const MICROSOFT_HV: &str = "Microsoft Hv";

/// Needs a hypervisor and Secure Boot, and either Windows' own hypervisor in use or no hypervisor with virtualization on in the firmware. Another vendor's hypervisor (a virtual machine) never counts.
pub fn hardware_supports(facts: &Facts) -> bool {
    if !(facts.available.contains(&1) && facts.available.contains(&2)) {
        return false;
    }
    match facts.hypervisor_vendor.as_deref() {
        Some(MICROSOFT_HV) => true,
        Some(_) => facts.vbs_status == Some(2),
        None => facts.virt_firmware == Some(true) || facts.vbs_status == Some(2),
    }
}

/// First build of Windows 11 22H2, which added kernel-mode stack protection.
pub const STACK_PROTECTION_BUILD: u32 = 22621;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Offer,
    NotOffered(String),
}

fn no(reason: &str) -> Decision {
    Decision::NotOffered(reason.to_owned())
}

pub fn driver_reason(scan: &Scan) -> Option<String> {
    if !scan.flagged.is_empty() {
        let mut names: Vec<&str> = scan.flagged.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        let text = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
        return Some(format!("{DRIVER}: {text}"));
    }
    (!scan.unreadable.is_empty()).then(|| DRIVERS_UNREADABLE.to_owned())
}

fn set_up_by_hand(facts: &Facts) -> Option<&'static str> {
    if facts.mandatory == Some(1) || facts.enable_vbs == Some(0) {
        return Some(SET_BY_HAND);
    }
    let missing_required = facts.required.iter().any(|p| !facts.available.contains(p));
    let platform_needs_dma =
        facts.require_platform.is_some_and(|v| v & 2 != 0) && !facts.available.contains(&3);
    (missing_required || platform_needs_dma).then_some(NOT_SUPPORTED)
}

/// Decide whether a fix may be offered. `scan` runs the driver scan and is
/// only called when every cheaper check has passed.
pub fn decide(
    id: &str,
    facts: &Facts,
    shadow_stack_cpu: bool,
    scan: &mut dyn FnMut() -> Scan,
) -> Decision {
    let locked = facts.lock_vbs == Some(1)
        || if id == STACK_PROTECTION {
            facts.lock_stack == Some(1)
        } else {
            facts.lock_hvci == Some(1)
        };
    if id == STACK_PROTECTION {
        if facts.running.contains(&5) {
            return no(ALREADY_ON);
        }
        if locked {
            return no(LOCKED);
        }
        if facts.build.is_some_and(|b| b < STACK_PROTECTION_BUILD) {
            return no(OLD_WINDOWS);
        }
        if !hardware_supports(facts) && !facts.running.contains(&2) {
            return no(NOT_SUPPORTED);
        }
        if !shadow_stack_cpu {
            return no(NO_SHADOW_STACKS);
        }
        if let Some(reason) = set_up_by_hand(facts) {
            return no(reason);
        }
        if !facts.running.contains(&2) {
            return if facts.configured.contains(&2) {
                no(NEEDS_RESTART)
            } else {
                no(NEEDS_MEMORY_INTEGRITY)
            };
        }
        return Decision::Offer;
    }
    if id != MEMORY_INTEGRITY {
        return no(UNREADABLE);
    }
    if facts.running.contains(&2) {
        return no(ALREADY_ON);
    }
    if locked {
        return no(LOCKED);
    }
    if !hardware_supports(facts) {
        return no(NOT_SUPPORTED);
    }
    if let Some(reason) = set_up_by_hand(facts) {
        return no(reason);
    }
    match driver_reason(&scan()) {
        Some(reason) => Decision::NotOffered(reason),
        None => Decision::Offer,
    }
}

pub fn restarted_since(written_unix: Option<i64>, boot_unix: Option<i64>) -> bool {
    matches!((written_unix, boot_unix), (Some(w), Some(b)) if w <= b)
}

/// Candidate findings for the check after a restart. They only say what the
/// PC reports now (plus the start-up time); the engine keeps one only when
/// Secblitz made the change, the PC has restarted since, and says whether
/// undoing it is the next undo.
pub fn verification(facts: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(boot) = facts.boot_unix else {
        return out;
    };
    let names: Vec<String> = facts
        .blocked
        .iter()
        .filter_map(|n| safe_name(n))
        .take(5)
        .collect();
    let detail = |base: &str| {
        let mut text = format!("{base} {BOOT_PREFIX}{boot}.");
        if !names.is_empty() {
            text.push_str(&format!(" {BLOCKED_PREFIX}{}", names.join(", ")));
        }
        text
    };
    let memory_integrity_running = facts.running.contains(&2);
    if facts.enabled_hvci == Some(1) && !memory_integrity_running {
        out.push(Finding {
            title: MEMORY_INTEGRITY_NOT_RUNNING.into(),
            status: CheckStatus::Attention,
            detail: detail("Memory integrity is configured but not running."),
        });
    } else if facts.enabled_hvci == Some(1) && memory_integrity_running && !names.is_empty() {
        out.push(Finding {
            title: DEVICE_BLOCKED.into(),
            status: CheckStatus::Attention,
            detail: detail("Windows refused a driver while memory integrity was on."),
        });
    } else if facts.enabled_stack == Some(1)
        && memory_integrity_running
        && !facts.running.contains(&5)
    {
        out.push(Finding {
            title: STACK_NOT_RUNNING.into(),
            status: CheckStatus::Attention,
            detail: detail("Kernel stack protection is configured but not running."),
        });
    }
    out
}

pub fn blocked_names(detail: &str) -> Option<String> {
    let rest = detail.split_once(BLOCKED_PREFIX)?.1;
    let names: Vec<String> = rest
        .split(',')
        .filter_map(|n| safe_name(n.trim()))
        .take(5)
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

pub fn reason_names(reason: &str) -> Option<String> {
    let rest = reason.strip_prefix(DRIVER)?.strip_prefix(": ")?;
    let cleaned: String = rest
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ',' | ' '))
        .collect();
    (!cleaned.is_empty() && cleaned == rest && rest.len() <= 200).then(|| rest.to_owned())
}

#[cfg(test)]
mod tests {
    use super::pe::tests::{build, Pe};
    use super::*;

    #[test]
    fn images_resolve_to_absolute_paths_in_every_form_windows_writes() {
        let w = r"C:\Windows";
        for (raw, want) in [
            (
                r"\SystemRoot\System32\drivers\a.sys",
                Some(r"C:\Windows\System32\drivers\a.sys"),
            ),
            (
                r"%SystemRoot%\system32\drivers\a.sys",
                Some(r"C:\Windows\system32\drivers\a.sys"),
            ),
            (
                r"System32\drivers\a.sys",
                Some(r"C:\Windows\System32\drivers\a.sys"),
            ),
            (r"\??\D:\x\a.sys", Some(r"D:\x\a.sys")),
            (r#""D:\x y\a.sys""#, Some(r"D:\x y\a.sys")),
            (r"D:\x\a.sys -flag", Some(r"D:\x\a.sys")),
            // A ".sys" inside a folder name is not the end of the file name.
            (
                r"C:\Tools\Foo.System\drv.sys",
                Some(r"C:\Tools\Foo.System\drv.sys"),
            ),
            (r"C:\Tools\a.sys.exe", None),
            (r"\Windows\System32\drivers\a.sys", None),
            (
                r"\SYSTEMROOT\SYSTEM32\A.SYS",
                Some(r"C:\Windows\SYSTEM32\A.SYS"),
            ),
            (r"\Device\HarddiskVolume3\a.sys", None),
            (r"C:\a.exe", None),
            (r"C:\x\..\a.sys", None),
            (r"\\server\share\a.sys", None),
            ("", None),
            ("a\0.sys", None),
        ] {
            assert_eq!(resolve_image(raw, w).as_deref(), want, "{raw}");
        }
    }

    #[test]
    fn the_driver_list_covers_configured_and_loaded_drivers_once_each() {
        let svc = |name: &str, kind, start, image: Option<&str>| ServiceRow {
            name: name.into(),
            kind,
            start,
            image: image.map(Into::into),
        };
        let services = vec![
            svc("boot", 1, 0, Some(r"\SystemRoot\System32\drivers\boot.sys")),
            svc("auto", 1, 2, None),
            svc("fs", 2, 3, Some(r"system32\drivers\fs.sys")),
            svc("off", 1, 4, Some(r"system32\drivers\off.sys")),
            svc("svc", 16, 2, Some(r"C:\x\svc.exe")),
            svc("odd", 1, 3, Some(r"\Device\x\odd.sys")),
        ];
        let loaded = vec![
            r"\SystemRoot\system32\ntoskrnl.exe".to_owned(),
            r"\SystemRoot\System32\drivers\BOOT.SYS".to_owned(),
            r"\??\C:\Windows\System32\drivers\extra.sys".to_owned(),
        ];
        let list = driver_files(&services, &loaded, r"C:\Windows\");
        let names: Vec<&str> = list.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["boot.sys", "auto.sys", "fs.sys", "extra.sys"]);
        // A configured driver whose file cannot be located is never skipped
        // quietly: it is listed so the check says "could not check".
        assert_eq!(list.unresolved, ["odd"]);
        let odd = driver_files(
            &[svc("bad name;", 1, 3, Some(r"\Device\x\a.sys"))],
            &[],
            r"C:\Windows",
        );
        assert_eq!(odd.unresolved, ["driver"]);
    }

    fn read_from(
        map: Vec<(&'static str, std::io::Result<Vec<u8>>)>,
    ) -> impl Fn(&str) -> std::io::Result<Vec<u8>> {
        let map = std::cell::RefCell::new(map);
        move |path: &str| {
            let mut m = map.borrow_mut();
            let i = m.iter().position(|(p, _)| *p == path).expect(path);
            let (_, r) = m.remove(i);
            r
        }
    }

    #[test]
    fn scanning_flags_bad_drivers_skips_missing_ones_and_reports_unreadable_ones() {
        let files: Vec<DriverFile> = ["good", "bad", "gone", "locked"]
            .iter()
            .map(|n| DriverFile {
                name: format!("{n}.sys"),
                path: (*n).into(),
            })
            .collect();
        let bad = build(&Pe {
            alignment: 0x200,
            ..Pe::default()
        });
        let read = read_from(vec![
            ("good", Ok(build(&Pe::default()))),
            ("bad", Ok(bad)),
            (
                "gone",
                Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            ),
            (
                "locked",
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            ),
        ]);
        let scan = scan_files(&files, &read);
        assert_eq!(
            scan.flagged,
            vec![("bad.sys".to_owned(), vec![PeProblem::SectionAlignment])]
        );
        assert_eq!(scan.unreadable, vec!["locked.sys".to_owned()]);
    }

    fn supported() -> Facts {
        Facts {
            available: vec![1, 2, 3, 7],
            virt_firmware: Some(true),
            build: Some(26100),
            ..Facts::default()
        }
    }

    fn clean() -> Scan {
        Scan::default()
    }

    fn decide_with(id: &str, facts: &Facts, cpu: bool, scan: Scan) -> Decision {
        decide(id, facts, cpu, &mut || scan.clone())
    }

    #[test]
    fn memory_integrity_is_offered_only_when_every_safety_check_passes() {
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &supported(), false, clean()),
            Decision::Offer
        );
        let mut f = supported();
        f.running = vec![2];
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, false, clean()),
            no(ALREADY_ON)
        );
        for set in [
            |f: &mut Facts| f.lock_vbs = Some(1),
            |f: &mut Facts| f.lock_hvci = Some(1),
        ] {
            let mut f = supported();
            set(&mut f);
            assert_eq!(
                decide_with(MEMORY_INTEGRITY, &f, false, clean()),
                no(LOCKED)
            );
        }
        let mut f = supported();
        f.lock_vbs = Some(0);
        f.lock_hvci = Some(0);
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, false, clean()),
            Decision::Offer
        );
    }

    #[test]
    fn missing_hardware_support_reads_as_a_calm_not_offered() {
        let f = Facts::default();
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, true, clean()),
            no(NOT_SUPPORTED)
        );
        for broken in [
            |f: &mut Facts| f.available = vec![2],
            |f: &mut Facts| f.available = vec![1],
            |f: &mut Facts| f.virt_firmware = Some(false),
            |f: &mut Facts| f.virt_firmware = None,
            // A virtual machine's own hypervisor (VirtualBox, VMware) never
            // counts, even when it passes virtualization through.
            |f: &mut Facts| f.hypervisor_vendor = Some("VBoxVBoxVBox".into()),
            |f: &mut Facts| {
                f.hypervisor_vendor = Some("VMwareVMware".into());
                f.virt_firmware = None;
            },
        ] {
            let mut f = supported();
            broken(&mut f);
            assert_eq!(
                decide_with(MEMORY_INTEGRITY, &f, true, clean()),
                no(NOT_SUPPORTED)
            );
        }
        let mut f = supported();
        f.virt_firmware = None;
        f.hypervisor_vendor = Some(MICROSOFT_HV.into());
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, false, clean()),
            Decision::Offer
        );
        let mut f = supported();
        f.virt_firmware = None;
        f.vbs_status = Some(2);
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, false, clean()),
            Decision::Offer
        );
    }

    #[test]
    fn the_driver_scan_runs_last_and_names_the_drivers() {
        let mut ran = false;
        let f = Facts::default();
        let d = decide(MEMORY_INTEGRITY, &f, true, &mut || {
            ran = true;
            Scan::default()
        });
        assert_eq!(d, no(NOT_SUPPORTED));
        assert!(
            !ran,
            "the scan must not run when the hardware already rules it out"
        );

        let scan = Scan {
            flagged: vec![
                ("old.sys".into(), vec![PeProblem::SectionAlignment]),
                ("older.sys".into(), vec![PeProblem::ImportTableExecutable]),
                ("old.sys".into(), vec![PeProblem::NotAnImage]),
            ],
            unreadable: vec![],
        };
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &supported(), true, scan),
            Decision::NotOffered(format!("{DRIVER}: old.sys, older.sys"))
        );
        let many = Scan {
            flagged: (0..8)
                .map(|n| (format!("d{n}.sys"), vec![PeProblem::NotAnImage]))
                .collect(),
            unreadable: vec![],
        };
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &supported(), true, many),
            Decision::NotOffered(format!("{DRIVER}: d0.sys, d1.sys, d2.sys, d3.sys, d4.sys"))
        );
        let unreadable = Scan {
            flagged: vec![],
            unreadable: vec!["x.sys".into()],
        };
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &supported(), true, unreadable),
            no(DRIVERS_UNREADABLE)
        );
    }

    #[test]
    fn stack_protection_needs_memory_integrity_running_and_a_capable_processor() {
        let mut f = supported();
        assert_eq!(
            decide_with(STACK_PROTECTION, &Facts::default(), true, clean()),
            no(NOT_SUPPORTED)
        );
        assert_eq!(
            decide_with(STACK_PROTECTION, &f, false, clean()),
            no(NO_SHADOW_STACKS)
        );
        assert_eq!(
            decide_with(STACK_PROTECTION, &f, true, clean()),
            no(NEEDS_MEMORY_INTEGRITY)
        );
        f.configured = vec![2];
        assert_eq!(
            decide_with(STACK_PROTECTION, &f, true, clean()),
            no(NEEDS_RESTART)
        );
        f.running = vec![2];
        assert_eq!(
            decide_with(STACK_PROTECTION, &f, false, clean()),
            no(NO_SHADOW_STACKS)
        );
        assert_eq!(
            decide_with(STACK_PROTECTION, &f, true, clean()),
            Decision::Offer
        );
        let mut old = f.clone();
        old.build = Some(19045);
        assert_eq!(
            decide_with(STACK_PROTECTION, &old, true, clean()),
            no(OLD_WINDOWS)
        );
        old.build = Some(STACK_PROTECTION_BUILD);
        assert_eq!(
            decide_with(STACK_PROTECTION, &old, true, clean()),
            Decision::Offer
        );
        let mut locked = f.clone();
        locked.lock_stack = Some(1);
        assert_eq!(
            decide_with(STACK_PROTECTION, &locked, true, clean()),
            no(LOCKED)
        );
        let mut locked = f.clone();
        locked.lock_vbs = Some(1);
        assert_eq!(
            decide_with(STACK_PROTECTION, &locked, true, clean()),
            no(LOCKED)
        );
        let mut other = f.clone();
        other.lock_hvci = Some(1);
        assert_eq!(
            decide_with(STACK_PROTECTION, &other, true, clean()),
            Decision::Offer
        );
        let mut on = f.clone();
        on.running = vec![2, 5];
        assert_eq!(
            decide_with(STACK_PROTECTION, &on, true, clean()),
            no(ALREADY_ON)
        );
        let mut audit = f;
        audit.running = vec![2, 6];
        assert_eq!(
            decide_with(STACK_PROTECTION, &audit, true, clean()),
            Decision::Offer
        );
        let mut ran = false;
        let mut g = supported();
        g.running = vec![2];
        decide(STACK_PROTECTION, &g, true, &mut || {
            ran = true;
            Scan::default()
        });
        assert!(!ran);
        assert_eq!(decide_with("other.id", &g, true, clean()), no(UNREADABLE));
    }

    #[test]
    fn a_restart_is_only_claimed_with_both_times_known() {
        assert!(restarted_since(Some(100), Some(200)));
        assert!(restarted_since(Some(100), Some(100)));
        assert!(!restarted_since(Some(200), Some(100)));
        assert!(!restarted_since(None, Some(100)));
        assert!(!restarted_since(Some(100), None));
    }

    #[test]
    fn a_setting_that_is_not_running_is_reported_with_the_start_time_and_drivers() {
        let mut f = supported();
        f.enabled_hvci = Some(1);
        f.boot_unix = Some(1000);
        f.blocked = vec![
            "bad.sys".into(),
            "not ok;rm.sys".into(),
            "second.sys".into(),
        ];
        let out = verification(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, MEMORY_INTEGRITY_NOT_RUNNING);
        assert_eq!(out[0].status, CheckStatus::Attention);
        assert_eq!(
            blocked_names(&out[0].detail).unwrap(),
            "bad.sys, second.sys"
        );
        assert_eq!(boot_from_detail(&out[0].detail), Some(1000));
        assert_eq!(finding_control(&out[0].title), Some(MEMORY_INTEGRITY));
        f.blocked.clear();
        let out = verification(&f);
        assert_eq!(blocked_names(&out[0].detail), None);
        f.boot_unix = None;
        assert!(verification(&f).is_empty());
        f.boot_unix = Some(1000);
        f.running = vec![2];
        assert!(verification(&f).is_empty());
        f.running.clear();
        f.enabled_hvci = Some(0);
        assert!(verification(&f).is_empty());
    }

    #[test]
    fn a_driver_blocked_while_memory_integrity_runs_is_reported_too() {
        let mut f = supported();
        f.enabled_hvci = Some(1);
        f.running = vec![2];
        f.boot_unix = Some(1000);
        f.blocked = vec!["pen.sys".into()];
        let out = verification(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, DEVICE_BLOCKED);
        assert_eq!(finding_control(DEVICE_BLOCKED), Some(MEMORY_INTEGRITY));
        assert_eq!(blocked_names(&out[0].detail).unwrap(), "pen.sys");
        f.enabled_hvci = Some(0);
        assert!(verification(&f).is_empty());
    }

    #[test]
    fn stack_protection_is_only_checked_while_memory_integrity_runs() {
        let mut f = supported();
        f.enabled_stack = Some(1);
        f.running = vec![2];
        f.boot_unix = Some(1000);
        let out = verification(&f);
        assert_eq!(out[0].title, STACK_NOT_RUNNING);
        assert_eq!(finding_control(STACK_NOT_RUNNING), Some(STACK_PROTECTION));
        f.running = vec![2, 5];
        assert!(verification(&f).is_empty());
        f.running.clear();
        f.enabled_hvci = Some(1);
        let out = verification(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, MEMORY_INTEGRITY_NOT_RUNNING);
    }

    #[test]
    fn settings_made_on_purpose_or_that_cannot_work_are_never_offered() {
        for set in [
            |f: &mut Facts| f.mandatory = Some(1),
            |f: &mut Facts| f.enable_vbs = Some(0),
        ] {
            let mut f = supported();
            set(&mut f);
            assert_eq!(
                decide_with(MEMORY_INTEGRITY, &f, true, clean()),
                no(SET_BY_HAND)
            );
            f.running = vec![2];
            assert_eq!(
                decide_with(STACK_PROTECTION, &f, true, clean()),
                no(SET_BY_HAND)
            );
        }
        let mut f = supported();
        f.require_platform = Some(3);
        f.available = vec![1, 2];
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, true, clean()),
            no(NOT_SUPPORTED)
        );
        f.available = vec![1, 2, 3];
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, true, clean()),
            Decision::Offer
        );
        let mut f = supported();
        f.required = vec![1, 2, 4];
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, true, clean()),
            no(NOT_SUPPORTED)
        );
        let mut f = supported();
        f.mandatory = Some(0);
        f.enable_vbs = Some(1);
        f.require_platform = Some(1);
        f.required = vec![1, 2];
        assert_eq!(
            decide_with(MEMORY_INTEGRITY, &f, true, clean()),
            Decision::Offer
        );
    }

    #[test]
    fn one_selection_is_split_so_each_core_protection_is_its_own_batch() {
        let ids: Vec<String> = ["a", STACK_PROTECTION, "b", MEMORY_INTEGRITY]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            split_batches(&ids),
            vec![
                vec!["a".to_owned(), "b".to_owned()],
                vec![STACK_PROTECTION.to_owned()],
                vec![MEMORY_INTEGRITY.to_owned()],
            ]
        );
        assert_eq!(split_batches(&ids[..1]), vec![vec!["a".to_owned()]]);
        assert!(split_batches(&[]).is_empty());
    }

    #[test]
    fn names_shown_to_people_are_always_plain() {
        assert_eq!(safe_name("a-b_1.sys").as_deref(), Some("a-b_1.sys"));
        for bad in ["", "a b.sys", "a;b", "x\u{202e}.sys", &"a".repeat(65)] {
            assert_eq!(safe_name(bad), None, "{bad}");
        }
        assert_eq!(
            reason_names(&format!("{DRIVER}: a.sys, b.sys")).as_deref(),
            Some("a.sys, b.sys")
        );
        assert_eq!(reason_names(DRIVER), None);
        assert_eq!(reason_names(&format!("{DRIVER}: <b>x</b>")), None);
        assert_eq!(reason_names("Not offered: something else: a.sys"), None);
        assert_eq!(blocked_names("no names here"), None);
        assert_eq!(blocked_names("x blocked: a;b"), None);
    }

    #[test]
    fn facts_decode_from_the_script_and_tolerate_missing_fields() {
        let f: Facts = serde_json::from_str(
            r#"{"available":[1,2],"running":[],"virtFirmware":true,"lockVbs":null,
                "enabledHvci":1,"bootUnix":1700000000,"blocked":["a.sys"],"extra":1}"#,
        )
        .unwrap();
        assert_eq!(f.available, vec![1, 2]);
        assert_eq!(f.virt_firmware, Some(true));
        assert_eq!(f.lock_vbs, None);
        assert_eq!(f.enabled_hvci, Some(1));
        assert_eq!(f.boot_unix, Some(1_700_000_000));
        let empty: Facts = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, Facts::default());
    }

    #[test]
    fn reasons_are_plain_and_stable() {
        for r in [
            NOT_SUPPORTED,
            LOCKED,
            DRIVER,
            DRIVERS_UNREADABLE,
            ALREADY_ON,
            NEEDS_MEMORY_INTEGRITY,
            NEEDS_RESTART,
            NO_SHADOW_STACKS,
            UNREADABLE,
            SET_BY_HAND,
            OLD_WINDOWS,
        ] {
            assert!(r.starts_with("Not offered: "));
            assert!(!r.contains('—'));
            assert!(r.len() < 90, "{r}");
        }
        assert!(
            is_vbs_check_id(MEMORY_INTEGRITY)
                && is_vbs_check_id(STACK_PROTECTION)
                && !is_vbs_check_id("vbs.running")
        );
    }
}
