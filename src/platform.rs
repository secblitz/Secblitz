//! Windows platform boundary. No caller-provided PowerShell or registry paths are accepted.
use crate::model::{Backend, Control};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Both 64-bit builds are supported: x86_64, and native arm64 on Windows on ARM.
pub const NATIVE_64: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

#[cfg(windows)]
#[path = "platform/windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{run_dism_json, run_json};

#[cfg(windows)]
pub mod security;

#[cfg(unix)]
#[path = "platform/unix.rs"]
pub mod unix;

/// Explicitly selected support operation, never a reversible hardening control.
/// No scripts, paths, sources, scan arguments, or arbitrary IDs are accepted.
pub fn support_action(id: &str) -> Result<()> {
    validate_support_id(id)?;
    #[cfg(windows)]
    {
        windows::support_action(id)
    }
    #[cfg(not(windows))]
    {
        bail!("Defender support actions require Windows")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatRemoval {
    pub found: u32,
    pub removed: u32,
    pub left: u32,
}

/// Defender's own remediation (removed threats go to quarantine). No path, name or argument is accepted.
pub fn remove_threats() -> Result<ThreatRemoval> {
    #[cfg(windows)]
    {
        windows::remove_threats()
    }
    #[cfg(not(windows))]
    {
        bail!("Defender support actions require Windows")
    }
}

/// Why the renewal was not started. Nothing was written when one of these comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalRefusal {
    NotUefi,
    SecureBootOff,
    AlreadyUpdated,
    AlreadyStarted,
    VirtualMachine,
    MakerBlocked,
    TaskMissing,
    TaskDisabled,
    OtherSystem,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// `confirmed` is true when Windows was seen picking the request up.
    Started {
        confirmed: bool,
    },
    Refused(RenewalRefusal),
}

/// Asks Windows to renew the Secure Boot certificates. It cannot be undone and never restarts the PC.
pub fn start_secure_boot_renewal() -> Result<RenewalOutcome> {
    #[cfg(windows)]
    {
        windows::start_secure_boot_renewal()
    }
    #[cfg(not(windows))]
    {
        bail!("The startup security renewal needs Windows")
    }
}

#[cfg(any(windows, test))]
fn parse_renewal_reply(reply: &Value) -> Result<RenewalOutcome> {
    let unclear = || anyhow::anyhow!("Windows did not say whether the renewal started");
    let object = reply
        .as_object()
        .filter(|o| o.get("ok") == Some(&json!(true)))
        .ok_or_else(unclear)?;
    match object.get("result").and_then(Value::as_str) {
        Some("started") if object.len() == 5 => {
            let flag = |key: &str| object.get(key).and_then(Value::as_bool);
            let (Some(confirmed), Some(task_started)) = (flag("confirmed"), flag("task_started"))
            else {
                return Err(unclear());
            };
            object
                .get("available_updates")
                .and_then(Value::as_u64)
                .ok_or_else(unclear)?;
            Ok(RenewalOutcome::Started {
                confirmed: confirmed && task_started,
            })
        }
        Some("refused") if object.len() == 3 => {
            let reason = match object.get("reason").and_then(Value::as_str) {
                Some("not_uefi") => RenewalRefusal::NotUefi,
                Some("secure_boot_off") => RenewalRefusal::SecureBootOff,
                Some("already_updated") => RenewalRefusal::AlreadyUpdated,
                Some("already_started") => RenewalRefusal::AlreadyStarted,
                Some("virtual_machine") => RenewalRefusal::VirtualMachine,
                Some("maker_blocked") => RenewalRefusal::MakerBlocked,
                Some("task_missing") => RenewalRefusal::TaskMissing,
                Some("task_disabled") => RenewalRefusal::TaskDisabled,
                Some("other_system") => RenewalRefusal::OtherSystem,
                Some("unreadable") => RenewalRefusal::Unreadable,
                _ => return Err(unclear()),
            };
            Ok(RenewalOutcome::Refused(reason))
        }
        _ => Err(unclear()),
    }
}

#[cfg(any(windows, test))]
fn renewal_script() -> Result<String> {
    Ok(format!(
        "$inputJson=$null\n{}\n$supportId='secureboot_renewal'\n{}\n{}",
        backend_definitions()?,
        include_str!("platform/secureboot.ps1"),
        include_str!("actions/secureboot.ps1")
    ))
}

/// Exactly `{"ok":true,"found":n,"removed":n,"left":n}` with consistent counts.
#[cfg(any(windows, test))]
fn parse_threat_reply(reply: &Value) -> Result<ThreatRemoval> {
    let object = reply
        .as_object()
        .filter(|o| o.len() == 4 && o.get("ok") == Some(&json!(true)))
        .ok_or_else(|| anyhow::anyhow!("Windows Security did not say what it removed"))?;
    let count = |key: &str| -> Result<u32> {
        object
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= 100_000)
            .ok_or_else(|| anyhow::anyhow!("Windows Security did not say what it removed"))
    };
    let (found, removed, left) = (count("found")?, count("removed")?, count("left")?);
    if removed > found {
        bail!("Windows Security did not say what it removed");
    }
    Ok(ThreatRemoval {
        found,
        removed,
        left,
    })
}

#[cfg(any(windows, test))]
fn threats_script() -> Result<String> {
    Ok(format!(
        "$inputJson=$null\n{}\n$supportId='defender_remove_threats'\n{}",
        backend_definitions()?,
        include_str!("actions/defender.ps1")
    ))
}

fn validate_support_id(id: &str) -> Result<()> {
    if !matches!(id, "defender_update" | "defender_quickscan") {
        bail!("Unknown support action id");
    }
    Ok(())
}

// Reuse the compiled backend's module bootstrap and policy helper definitions,
// but never its control dispatcher. Exact delimiter changes fail closed.
#[cfg(any(windows, test))]
fn backend_definitions() -> Result<&'static str> {
    let source = include_str!("platform/backend.ps1");
    let delimiter = "\ntry {\n    switch -CaseSensitive ($action) {";
    let (definitions, _) = source
        .split_once(delimiter)
        .ok_or_else(|| anyhow::anyhow!("Embedded backend dispatcher boundary changed"))?;
    if source.matches(delimiter).count() != 1 {
        bail!("Ambiguous embedded backend dispatcher boundary");
    }
    Ok(definitions)
}

#[cfg(any(windows, test))]
fn support_script(id: &str) -> Result<String> {
    validate_support_id(id)?;
    Ok(format!(
        "$inputJson=$null\n{}\n$supportId='{id}'\n{}",
        backend_definitions()?,
        include_str!("actions/defender.ps1")
    ))
}

/// A PowerShell expression that evaluates to `text`. Data travels as base64, never as script
/// source: doubling quotes is not enough, PowerShell also treats U+2018 to U+201B as quotes.
#[cfg(any(windows, test))]
fn ps_text(text: &str) -> String {
    use base64::Engine as _;
    format!(
        "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')))",
        base64::engine::general_purpose::STANDARD.encode(text)
    )
}

#[cfg(any(windows, test))]
fn hardening_script(action: &str, id: &str, value: Option<&Value>) -> Result<String> {
    let spec = crate::hardening::spec(id).ok_or_else(|| anyhow::anyhow!("Unknown control id"))?;
    let input = match (action, value) {
        ("observe", None) => "$null".to_string(),
        ("write", Some(v)) => {
            spec.validate(v)?;
            ps_text(&v.to_string())
        }
        _ => bail!("Invalid platform action arguments"),
    };
    Ok(format!(
        "$action='{action}'\n$id='{id}'\n$inputJson={input}\n$hardeningSpecJson={}\n{}\n{}\n{}",
        ps_text(&spec.script_json()),
        backend_definitions()?,
        include_str!("platform/hardening.handled.ps1"),
        include_str!("platform/hardening.ps1")
    ))
}

/// Recheck management/policy authority for one of the two fixed service-DACL
/// controls. The native wrapper must call this for observation eligibility and
/// immediately before every write (including restore); success is not cached.
/// Owner/ACL validation, elevation and mutation verification belong to that wrapper.
pub fn permission_gate(id: &str) -> Result<()> {
    validate_permission_id(id)?;
    #[cfg(windows)]
    {
        windows::permission_gate(id)
    }
    #[cfg(not(windows))]
    {
        bail!("Service permission eligibility requires Windows")
    }
}

fn validate_permission_id(id: &str) -> Result<()> {
    if !matches!(
        id,
        "permissions.service.bits" | "permissions.service.wuauserv"
    ) {
        bail!("Unknown service permission control id");
    }
    Ok(())
}

#[cfg_attr(not(windows), allow(dead_code))]
fn validate_request(action: &str, id: Option<&str>, value: Option<&Value>) -> Result<()> {
    match action {
        "permission_gate" if value.is_none() => {
            validate_permission_id(id.ok_or_else(|| anyhow::anyhow!("Missing control id"))?)
        }
        "machine" | "findings" if id.is_none() && value.is_none() => Ok(()),
        "observe" | "write" => {
            let id = id.ok_or_else(|| anyhow::anyhow!("Missing control id"))?;
            if !controls().iter().any(|c| c.id == id) {
                bail!("Unknown control id");
            }
            match (action, value) {
                ("observe", None) => Ok(()),
                ("write", Some(value)) => validate_value(id, value),
                _ => bail!("Invalid platform action arguments"),
            }
        }
        _ => bail!("Invalid platform action arguments"),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn validate_permission_reply(reply: &Value) -> Result<()> {
    if reply != &json!({"ok":true}) {
        bail!("Service permission gate was not acknowledged");
    }
    Ok(())
}

pub fn backend() -> Result<Box<dyn Backend>> {
    #[cfg(windows)]
    {
        windows::backend()
    }
    #[cfg(not(windows))]
    {
        bail!(
            "Secblitz requires 64-bit Windows 10/11; this platform cannot assess or change Windows"
        )
    }
}

/// This x64 build is running through emulation on a PC with an ARM processor,
/// where the native arm64 build is available.
pub fn x64_on_arm() -> bool {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        windows::x64_on_arm()
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        false
    }
}

/// Windows Home, which has no BitLocker settings of its own.
pub fn windows_home() -> bool {
    #[cfg(windows)]
    {
        static HOME: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *HOME.get_or_init(windows::windows_home)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn is_elevated() -> Result<bool> {
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
    #[cfg(not(windows))]
    {
        bail!("Elevation is only supported on Windows")
    }
}

/// Elevation for paths that can safely fall back to doing nothing privileged: a failed query counts as not elevated.
pub fn is_elevated_or_false() -> bool {
    is_elevated().unwrap_or(false)
}

/// Fails unless this process is elevated; a failed elevation query is an error too.
pub fn require_admin(what: &str) -> Result<()> {
    if !is_elevated()? {
        bail!("{what}");
    }
    Ok(())
}

#[cfg(windows)]
pub use windows::{enclosing_job, enclosing_job_contains, own_temp_dir, EnclosingJob};

/// Servicing never runs inside another program's job (it could be killed mid-repair); callers check first.
pub fn ensure_own_process_tree() -> Result<()> {
    #[cfg(windows)]
    {
        anyhow::ensure!(
            windows::enclosing_job()? != EnclosingJob::Locked,
            "Started inside another program's process job; reopen Secblitz interactively"
        );
    }
    Ok(())
}

pub fn elevate(args: &[String]) -> Result<()> {
    #[cfg(windows)]
    {
        windows::elevate(args)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        bail!("Elevation is only supported on Windows")
    }
}

/// GUI-owned data (score log, app prefs, app clean-up journal, dev status file)
/// lives in the `App` namespace inside the protected state directory. The engine
/// treats it as opaque, like `operations` and `Patching`; journal entries must
/// never be written next to the WAL files themselves.
pub const APP_BACKUPS: &str = "AppBackups";
/// Web protection's folder, inside the state directory. The filter service
/// (LocalService) must read it and write in its `Data` folder, so it cannot
/// have the journal's administrators-only permissions. The state directory
/// check makes sure it is a real folder owned by administrators and then
/// leaves it alone: no journal is ever read from or written to it.
pub const WEB_PROTECTION: &str = "Filter";
pub const UPDATES: &str = "Updates";
/// What the Linux fixes write down so an undo can put things back exactly, inside the state directory. Never a journal.
pub const LINUX_NOTES: &str = "Linux";

pub fn app_dir() -> Result<PathBuf> {
    let dir = app_root()?.join("App");
    match std::fs::symlink_metadata(&dir) {
        Ok(m) => anyhow::ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "The app data folder is not a plain directory"
        ),
        #[cfg(unix)]
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => unix::create_private_dir(&dir)?,
        #[cfg(not(unix))]
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&dir)?,
        Err(e) => return Err(e.into()),
    }
    Ok(dir)
}

/// On Linux the window runs as the person, who cannot open the root-only state folder, so the
/// window's own data stays in their private folder at home.
fn app_root() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if !unix::is_root() {
        return crate::linux::person::own_state_dir();
    }
    state_dir()
}

pub fn state_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        windows::state_dir()
    }
    #[cfg(unix)]
    {
        unix::state_dir()
    }
    #[cfg(not(any(windows, unix)))]
    {
        bail!("The protected journal directory is only available on Windows")
    }
}

/// A new folder inside the state folder that only SYSTEM and Administrators can open.
pub fn create_private_dir(path: &std::path::Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::create_private_dir(path)
    }
    #[cfg(unix)]
    {
        unix::create_private_dir(path)
    }
    #[cfg(not(any(windows, unix)))]
    {
        std::fs::create_dir(path)?;
        Ok(())
    }
}

/// A machine registry DWORD repair; `target` is the value the control restores.
struct RegistryRepair {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    target: u32,
    reboot: bool,
}

const REGISTRY_REPAIRS: [RegistryRepair; 4] = [
    RegistryRepair {
        id: "installer.always_install_elevated",
        title: "Disable always-elevated MSI installation",
        description: "Repair only machine AlwaysInstallElevated=1. The machine setting breaks the vulnerable machine/user conjunction; preserve HKCU, absent values and normal administrator-authorized installs.",
        target: 0,
        reboot: false,
    },
    RegistryRepair {
        id: "lsa.restrict_anonymous_sam",
        title: "Restrict anonymous SAM enumeration",
        description: "Repair only RestrictAnonymousSAM=0. Require authentication for account enumeration; legacy anonymous enumeration workflows may be affected. Preserve absent values and other LSA settings.",
        target: 1,
        reboot: false,
    },
    RegistryRepair {
        id: "lsa.limit_blank_password_use",
        title: "Limit blank-password accounts to console logon",
        description: "Repair only LimitBlankPasswordUse=0. Block remote logons using blank local passwords while preserving physical console logon. Preserve absent values; no passwords are inspected or changed.",
        target: 1,
        reboot: false,
    },
    RegistryRepair {
        id: "wdigest.use_logon_credential",
        title: "Disable WDigest plaintext credential caching",
        description: "Repair only UseLogonCredential=1. Preserve absent values (safe on supported Windows). Readback verifies stored configuration, not running LSASS; restart/sign-out may be needed for existing sessions. Legacy Digest SSO may require credentials.",
        target: 0,
        reboot: true,
    },
];

// Targets and restoration values describe raw preferences. Independently verified
// firewall effective status lives only in Observation metadata, never before-images.
// Registry restoration includes absence rather than inventing a previous value.
#[cfg_attr(not(windows), allow(dead_code))]
fn controls() -> Vec<Control> {
    let mut out = Vec::new();
    for (id, title) in [
        ("defender.realtime", "Defender real-time protection"),
        ("defender.behavior", "Defender behavior monitoring"),
        ("defender.ioav", "Defender downloaded-file scanning"),
        ("defender.archive", "Defender archive scanning"),
    ] {
        out.push(Control { id: id.into(), title: title.into(), description: "Enable the core Defender preference only on an unmanaged device with no competing antivirus. Preserve exclusions and other preferences.".into(), target: json!(false), reboot: false });
    }
    for profile in ["domain", "private", "public"] {
        for (suffix, title, target) in [
            ("enabled", "Enable firewall", json!(true)),
            (
                "inbound",
                "Block unsolicited inbound traffic",
                json!("Block"),
            ),
        ] {
            out.push(Control {
                id: format!("firewall.{profile}.{suffix}"),
                title: format!("{title} ({profile})"),
                description:
                    "Preserve all firewall rules and outbound policy. Unmanaged devices only."
                        .into(),
                target,
                reboot: false,
            });
        }
    }
    out.push(Control { id: "uac.enabled".into(), title: "Enable UAC".into(), description: "Repair an explicitly disabled EnableLUA value; preserve absent or already enabled settings.".into(), target: json!({"present":true,"value":1}), reboot: true });
    out.push(Control {
        id: "uac.consent".into(),
        title: "Require administrator consent".into(),
        description: "Repair consent mode 0 to Windows default 5. Preserve every nonzero mode."
            .into(),
        target: json!({"present":true,"value":5}),
        reboot: false,
    });
    for RegistryRepair {
        id,
        title,
        description,
        target,
        reboot,
    } in REGISTRY_REPAIRS
    {
        out.push(Control {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            target: json!({"present":true,"value":target}),
            reboot,
        });
    }
    for spec in crate::hardening::all() {
        out.push(Control {
            id: spec.id.into(),
            title: spec.title.into(),
            description: spec.description.into(),
            target: spec.catalog_target(),
            reboot: spec.reboot,
        });
    }
    out
}

pub fn control_ids() -> Vec<String> {
    controls().into_iter().map(|c| c.id).collect()
}

#[cfg_attr(not(windows), allow(dead_code))]
fn validate_value(id: &str, value: &Value) -> Result<()> {
    if let Some(spec) = crate::hardening::spec(id) {
        return spec.validate(value);
    }
    let control = controls()
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| anyhow::anyhow!("Unknown control id"))?;
    if id.starts_with("defender.") || id.ends_with(".enabled") && id.starts_with("firewall.") {
        if !value.is_boolean() {
            bail!("{} requires a JSON boolean", control.id);
        }
    } else if id.starts_with("firewall.") {
        if !matches!(value.as_str(), Some("Block" | "Allow" | "NotConfigured")) {
            bail!("Invalid inbound action");
        }
    } else {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RegistryValue {
            present: bool,
            value: Option<u32>,
        }
        let v: RegistryValue = serde_json::from_value(value.clone())?;
        // Require both keys, including an explicit null for an absent value.
        if value.as_object().map(|o| o.len()) != Some(2) || value.get("value").is_none() {
            bail!("Registry state must contain exactly present and value");
        }
        if v.present {
            let max = if id == "uac.consent" { 5 } else { 1 };
            if !matches!(v.value, Some(n) if n <= max) {
                bail!("Invalid registry DWORD");
            }
        } else if v.value.is_some() {
            bail!("Absent registry value must be null");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulation_on_an_arm_pc_is_only_detected_on_windows() {
        #[cfg(not(windows))]
        assert!(!x64_on_arm());
    }

    #[test]
    fn firewall_observation_wire_contract_preserves_raw_values() {
        use crate::model::{
            validate_observation, Authority, EffectiveFirewall, InboundAction, Observation,
        };
        for profile in ["domain", "private", "public"] {
            for (raw, effective) in [("NotConfigured", "block"), ("Allow", "allow")] {
                let id = format!("firewall.{profile}.inbound");
                let observation: Observation = serde_json::from_value(json!({
                    "value": raw, "eligible": true, "reason": "Eligible unmanaged local preference",
                    "authority": "local", "effective": {"kind": "inbound", "value": effective}
                }))
                .unwrap();
                validate_value(&id, &observation.value).unwrap();
                validate_observation(&id, &observation).unwrap();
                assert_eq!(observation.value, json!(raw));
                assert_eq!(observation.authority, Some(Authority::Local));
                assert_eq!(
                    observation.effective,
                    Some(EffectiveFirewall::Inbound(if effective == "block" {
                        InboundAction::Block
                    } else {
                        InboundAction::Allow
                    }))
                );
                assert!(
                    validate_observation(&format!("firewall.{profile}.enabled"), &observation)
                        .is_err()
                );
                assert!(validate_observation("uac.enabled", &observation).is_err());
            }
        }
        for authority in ["managed", "unknown"] {
            let mut observation: Observation = serde_json::from_value(json!({
                "value": "Allow", "eligible": false, "reason": "assessment only",
                "authority": authority, "effective": {"kind": "inbound", "value": "block"}
            }))
            .unwrap();
            validate_observation("firewall.public.inbound", &observation).unwrap();
            observation.eligible = true;
            assert!(validate_observation("firewall.public.inbound", &observation).is_err());
        }
        for evidence in [
            json!({"kind":"enabled","value":"true"}),
            json!({"kind":"enabled","value":1}),
            json!({"kind":"inbound","value":"NotConfigured"}),
            json!({"kind":"inbound","value":"Block"}),
            json!({"kind":"unknown","value":false}),
        ] {
            assert!(serde_json::from_value::<Observation>(json!({
                "value": "NotConfigured", "eligible": false, "reason": "fixture",
                "authority": "unknown", "effective": evidence
            }))
            .is_err());
        }
        let legacy: Observation = serde_json::from_value(json!({
            "value": {"present":false,"value":null}, "eligible":false,
            "reason":"Preserving absent or nonzero UAC preference"
        }))
        .unwrap();
        assert!(legacy.effective.is_none() && legacy.authority.is_none());
        validate_observation("uac.enabled", &legacy).unwrap();
    }
    #[test]
    fn support_operations_are_isolated_and_exact() {
        for id in ["defender_update", "defender_quickscan"] {
            let script = support_script(id).unwrap();
            assert!(!script.contains("switch -CaseSensitive ($action)"));
            assert!(script.contains("function CheckScopedPolicy"));
            assert!(script.contains("function MdmRegistered"));
            assert!(validate_request(id, None, None).is_err());
            assert!(validate_request("support", Some(id), None).is_err());
            assert!(validate_request("write", Some(id), Some(&json!(false))).is_err());
        }
        for id in [
            "",
            "defender.realtime",
            "Defender_update",
            "defender_update ",
            "defender_quickscan\0",
            "defender_update'; exit",
        ] {
            assert!(support_script(id).is_err());
            assert!(support_action(id).is_err());
        }
    }
    #[test]
    fn secure_boot_renewal_is_its_own_fixed_script_that_checks_before_it_writes() {
        let script = renewal_script().unwrap();
        assert!(script.contains("$supportId='secureboot_renewal'"));
        assert!(script.contains("function CheckScopedPolicy"));
        assert!(script.contains("function SbIsVirtualMachine"));
        assert!(!script.contains("switch -CaseSensitive ($action)"));
        let gate = script.find("$reason = RenewalRefusal").unwrap();
        let write = script.find("        WriteAvailableUpdates 0x5944").unwrap();
        let start = script.find("Start-ScheduledTask -TaskPath").unwrap();
        assert!(gate < write && write < start);
        assert_eq!(script.matches("WriteAvailableUpdates 0x5944").count(), 1);
        for never in [
            "HighConfidenceOptOut",
            "MicrosoftUpdateManagedOptIn",
            "Restart-Computer",
            "shutdown",
            "Suspend-BitLocker",
            "manage-bde",
        ] {
            assert!(!script.contains(never), "{never}");
        }
        assert!(support_script("secureboot_renewal").is_err());
        assert!(support_action("secureboot_renewal").is_err());
        assert!(
            validate_request("write", Some("secureboot_renewal"), Some(&json!(false))).is_err()
        );
        #[cfg(not(windows))]
        assert!(start_secure_boot_renewal().is_err());
    }

    #[test]
    fn the_renewal_reply_must_be_exact() {
        let started = |confirmed, task| json!({"ok": true, "result": "started", "confirmed": confirmed, "task_started": task, "available_updates": 22788});
        assert_eq!(
            parse_renewal_reply(&started(true, true)).unwrap(),
            RenewalOutcome::Started { confirmed: true }
        );
        assert_eq!(
            parse_renewal_reply(&started(true, false)).unwrap(),
            RenewalOutcome::Started { confirmed: false }
        );
        assert_eq!(
            parse_renewal_reply(&started(false, true)).unwrap(),
            RenewalOutcome::Started { confirmed: false }
        );
        for (word, reason) in [
            ("not_uefi", RenewalRefusal::NotUefi),
            ("secure_boot_off", RenewalRefusal::SecureBootOff),
            ("already_updated", RenewalRefusal::AlreadyUpdated),
            ("already_started", RenewalRefusal::AlreadyStarted),
            ("virtual_machine", RenewalRefusal::VirtualMachine),
            ("maker_blocked", RenewalRefusal::MakerBlocked),
            ("task_missing", RenewalRefusal::TaskMissing),
            ("task_disabled", RenewalRefusal::TaskDisabled),
            ("other_system", RenewalRefusal::OtherSystem),
            ("unreadable", RenewalRefusal::Unreadable),
        ] {
            assert_eq!(
                parse_renewal_reply(&json!({"ok": true, "result": "refused", "reason": word}))
                    .unwrap(),
                RenewalOutcome::Refused(reason)
            );
        }
        for bad in [
            json!({"ok": true}),
            json!({"ok": false, "result": "refused", "reason": "unreadable"}),
            json!({"ok": true, "result": "refused", "reason": "because"}),
            json!({"ok": true, "result": "refused"}),
            json!({"ok": true, "result": "refused", "reason": "unreadable", "extra": 1}),
            json!({"ok": true, "result": "started", "confirmed": true, "task_started": true}),
            json!({"ok": true, "result": "started", "confirmed": "yes", "task_started": true, "available_updates": 1}),
            json!({"ok": true, "result": "started", "confirmed": true, "task_started": true, "available_updates": -1}),
            json!({"ok": true, "result": "done"}),
            json!("started"),
        ] {
            assert!(parse_renewal_reply(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn threat_removal_is_its_own_fixed_script_and_an_exact_reply() {
        let script = threats_script().unwrap();
        assert!(script.contains("$supportId='defender_remove_threats'"));
        assert!(script.contains("Remove-MpThreat -ErrorAction Stop"));
        assert!(!script.contains("switch -CaseSensitive ($action)"));
        assert!(script.contains("function CheckScopedPolicy"));
        let gate = script.find("function CheckScopedPolicy").unwrap();
        let call = script
            .find("    CheckScopedPolicy 'defender.support'")
            .unwrap();
        let remove = script.find("Remove-MpThreat -ErrorAction Stop").unwrap();
        assert!(gate < call && call < remove);
        // It is not one of the plain support actions and is never a control id.
        assert!(support_script("defender_remove_threats").is_err());
        assert!(support_action("defender_remove_threats").is_err());
        assert!(validate_request(
            "write",
            Some("defender_remove_threats"),
            Some(&json!(false))
        )
        .is_err());

        let ok = json!({"ok": true, "found": 3, "removed": 2, "left": 1});
        assert_eq!(
            parse_threat_reply(&ok).unwrap(),
            ThreatRemoval {
                found: 3,
                removed: 2,
                left: 1
            }
        );
        parse_threat_reply(&json!({"ok": true, "found": 0, "removed": 0, "left": 0})).unwrap();
        for bad in [
            json!({"ok": true}),
            json!({"ok": false, "found": 1, "removed": 1, "left": 0}),
            json!({"ok": true, "found": 1, "removed": 2, "left": 0}),
            json!({"ok": true, "found": -1, "removed": 0, "left": 0}),
            json!({"ok": true, "found": 1.5, "removed": 0, "left": 0}),
            json!({"ok": true, "found": "1", "removed": 0, "left": 0}),
            json!({"ok": true, "found": 1, "removed": 1, "left": 0, "extra": 1}),
            json!({"ok": true, "found": 100001, "removed": 0, "left": 0}),
            json!([true]),
            json!(null),
        ] {
            assert!(parse_threat_reply(&bad).is_err(), "accepted {bad}");
        }
        #[cfg(not(windows))]
        assert!(remove_threats().is_err());
    }
    #[test]
    fn permission_gate_is_an_exact_isolated_action() {
        assert_eq!(controls().len(), 16 + crate::hardening::all().len());
        for id in ["permissions.service.bits", "permissions.service.wuauserv"] {
            validate_request("permission_gate", Some(id), None).unwrap();
            assert!(validate_request("permission_gate", Some(id), Some(&Value::Null)).is_err());
            for action in ["observe", "write", "machine", "findings"] {
                assert!(validate_request(action, Some(id), None).is_err());
                assert!(validate_request(action, Some(id), Some(&json!({"ok":true}))).is_err());
            }
            assert!(validate_value(id, &json!({"present":true,"value":1})).is_err());
        }
        for id in [
            "",
            "bits",
            "permissions.service.BITS",
            "permissions.service.spooler",
            "permissions.service.bits ",
            "permissions.service.bits' ; exit",
            "permissions.service.bits\0",
        ] {
            assert!(validate_request("permission_gate", Some(id), None).is_err());
            assert!(permission_gate(id).is_err());
        }
        for control in controls() {
            assert!(validate_request("permission_gate", Some(&control.id), None).is_err());
            validate_request("observe", Some(&control.id), None).unwrap();
            if !crate::hardening::spec(&control.id).is_some_and(|s| s.dynamic()) {
                validate_request("write", Some(&control.id), Some(&control.target)).unwrap();
            }
        }
        assert!(validate_request("permission_gate", None, None).is_err());
        assert!(
            validate_request("Permission_Gate", Some("permissions.service.bits"), None).is_err()
        );
        validate_permission_reply(&json!({"ok":true})).unwrap();
        for bad in [
            Value::Null,
            json!(true),
            json!({}),
            json!({"ok":false}),
            json!({"ok":"true"}),
            json!({"ok":1}),
            json!({"ok":true,"extra":0}),
        ] {
            assert!(validate_permission_reply(&bad).is_err());
        }
    }
    #[test]
    fn privilege_controls_have_exact_binary_journal_contracts() {
        for (id, target, reboot) in [
            ("installer.always_install_elevated", 0, false),
            ("lsa.restrict_anonymous_sam", 1, false),
            ("lsa.limit_blank_password_use", 1, false),
            ("wdigest.use_logon_credential", 0, true),
        ] {
            let control = controls().into_iter().find(|c| c.id == id).unwrap();
            assert_eq!(control.target, json!({"present":true,"value":target}));
            assert_eq!(control.reboot, reboot);
            for original in [
                json!({"present":false,"value":null}),
                json!({"present":true,"value":0}),
                json!({"present":true,"value":1}),
            ] {
                validate_value(id, &original).unwrap();
            }
            for bad in [
                json!({"present":true,"value":2}),
                json!({"present":true,"value":5}),
                json!({"present":true,"value":-1}),
                json!({"present":true,"value":1.0}),
                json!({"present":true,"value":true}),
                json!({"present":true,"value":"1"}),
                json!({"present":true,"value":null}),
                json!({"present":false,"value":0}),
                json!({"present":false}),
                json!({"present":0,"value":null}),
                json!({"present":true,"value":1,"path":"HKCU"}),
            ] {
                assert!(validate_value(id, &bad).is_err(), "{id} accepted {bad}");
            }
        }
    }
    #[test]
    fn hardening_controls_are_cataloged_with_restart_flags_and_wire_validation() {
        let ids: Vec<_> = controls().into_iter().map(|c| c.id).collect();
        for spec in crate::hardening::all() {
            let c = controls().into_iter().find(|c| c.id == spec.id).unwrap();
            assert_eq!(c.reboot, spec.reboot, "{}", spec.id);
            assert!(ids.contains(&spec.id.to_string()));
            validate_request("observe", Some(spec.id), None).unwrap();
            assert!(
                validate_request("observe", Some(spec.id), Some(&json!({"items":{}}))).is_err()
            );
            assert!(validate_request("write", Some(spec.id), Some(&json!(true))).is_err());
            assert!(validate_request(
                "write",
                Some(spec.id),
                Some(&json!({"present":true,"value":1}))
            )
            .is_err());
        }
        for restart in [
            "lsa.run_as_ppl",
            "net.llmnr",
            "autorun.disabled",
            "ntlm.lm_compat_level",
            "lsa.restrict_anonymous",
        ] {
            assert!(crate::hardening::spec(restart).unwrap().reboot, "{restart}");
        }
        assert!(!crate::hardening::spec("defender.pua").unwrap().reboot);
    }

    #[test]
    fn ps_text_is_quote_free_and_round_trips() {
        use base64::Engine as _;
        for text in [
            "",
            "plain",
            "it's",
            "\u{2018}\u{2019}\u{201A}\u{201B}",
            "{\"a\":\"\u{e9}\"}",
        ] {
            let expr = ps_text(text);
            let inner = expr
                .strip_prefix("([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('")
                .and_then(|r| r.strip_suffix("')))"))
                .unwrap();
            assert!(inner.is_ascii() && !inner.contains('\''));
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(inner)
                .unwrap();
            assert_eq!(String::from_utf8(bytes).unwrap(), text);
        }
    }

    #[test]
    fn hardening_scripts_embed_only_the_compiled_spec_and_escape_values() {
        for spec in crate::hardening::all() {
            let observe = hardening_script("observe", spec.id, None).unwrap();
            assert!(observe.starts_with(&format!(
                "$action='observe'\n$id='{}'\n$inputJson=$null\n",
                spec.id
            )));
            assert!(observe.contains(&format!(
                "$hardeningSpecJson={}\n",
                ps_text(&spec.script_json())
            )));
            assert!(observe.contains("function HWrite"));
            assert!(observe.contains("function Gate("));
            assert_eq!(
                observe.matches("switch -CaseSensitive ($action)").count(),
                1
            );
            assert!(hardening_script("write", spec.id, None).is_err());
            assert!(hardening_script("observe", spec.id, Some(&json!({"items":{}}))).is_err());
        }
        assert!(hardening_script("observe", "uac.enabled", None).is_err());
        assert!(hardening_script("findings", "net.llmnr", None).is_err());
        assert!(hardening_script("write", "net.llmnr", Some(&json!({"items":{"x":1}}))).is_err());
        // No quote in a Wi-Fi name can end a PowerShell literal: ASCII or the
        // typographic ones PowerShell also accepts, as in "Joe’s iPhone".
        for name in [
            "Joe's '; Remove-Item x; '",
            "Joe\u{2019}s iPhone",
            "\u{2018};x;\u{2019}\u{201A}\u{201B}",
        ] {
            let wifi = json!({"items": {name: 0}});
            let script = hardening_script("write", "wifi.risky_profiles", Some(&wifi)).unwrap();
            assert!(script.contains(&format!("$inputJson={}\n", ps_text(&wifi.to_string()))));
            let head = &script[..script.find("$hardeningSpecJson").unwrap()];
            assert!(head.is_ascii() && !head.contains(name), "{head}");
        }
        // Double quotes are rejected outright (they would break netsh-style quoting).
        assert!(hardening_script(
            "write",
            "wifi.risky_profiles",
            Some(&json!({"items": {"a\"b": 0}}))
        )
        .is_err());
    }

    #[test]
    fn powershell_tamper_exemptions_match_the_catalog() {
        let source = include_str!("platform/backend.ps1");
        let start = source.find("function TamperExempt").unwrap();
        let body = &source[start..source[start..].find("\n}\n").unwrap() + start];
        let mut listed: Vec<&str> = body
            .split('\'')
            .filter(|s| s.starts_with("defender."))
            .collect();
        listed.sort_unstable();
        let mut compiled: Vec<&str> = crate::hardening::all()
            .iter()
            .filter(|s| s.gate.tamper_exempt)
            .map(|s| s.id)
            .collect();
        compiled.sort_unstable();
        assert_eq!(listed, compiled);
    }

    #[test]
    fn fixed_targets_validate() {
        for c in controls() {
            if crate::hardening::spec(&c.id).is_some_and(|s| s.dynamic()) {
                // Derived per before-image; the catalog holds a sentinel.
                assert!(validate_value(&c.id, &c.target).is_err());
                continue;
            }
            validate_value(&c.id, &c.target).unwrap();
        }
    }
    #[test]
    fn restoration_values_are_strict() {
        for bad in [json!(0), json!("false"), Value::Null, json!({"value":true})] {
            assert!(validate_value("defender.realtime", &bad).is_err());
        }
        for bad in [
            json!({"present":true,"value":6}),
            json!({"present":true,"value":-1}),
            json!({"present":true,"value":1.0}),
            json!({"present":false,"value":0}),
            json!({"present":false}),
            json!({"present":true,"value":1,"extra":0}),
        ] {
            assert!(validate_value("uac.consent", &bad).is_err());
        }
        assert!(validate_value("uac.enabled", &json!({"present":true,"value":2})).is_err());
        assert!(validate_value("uac.enabled", &json!({"present":false,"value":null})).is_ok());
        for n in 0..=5 {
            assert!(validate_value("uac.consent", &json!({"present":true,"value":n})).is_ok());
        }
        assert!(validate_value("firewall.public.inbound", &json!("Allow")).is_ok());
        assert!(validate_value("firewall.public.inbound", &json!("block")).is_err());
        assert!(validate_value("defender.realtime; exit", &json!(false)).is_err());
    }

    #[test]
    fn all_control_ids_reject_untyped_or_executable_input() {
        for control in controls() {
            for value in [
                Value::Null,
                json!([]),
                json!("'; Start-Process cmd; '"),
                json!({"present":true,"value":"0"}),
            ] {
                assert!(
                    validate_value(&control.id, &value).is_err(),
                    "{} accepted {value}",
                    control.id
                );
            }
            if crate::hardening::is_hardening_check_id(&control.id) {
                continue;
            }
            if control.id.starts_with("defender.")
                || control.id.starts_with("firewall.") && control.id.ends_with(".enabled")
            {
                for value in [json!(true), json!(false)] {
                    validate_value(&control.id, &value).unwrap();
                }
            }
            if control.id.ends_with(".inbound") {
                for value in [json!("Block"), json!("Allow"), json!("NotConfigured")] {
                    validate_value(&control.id, &value).unwrap();
                }
            }
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn a_failed_elevation_check_never_counts_as_administrator() {
        assert!(is_elevated().is_err());
        assert!(require_admin("Changing things needs administrator rights").is_err());
    }
    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_never_advertises_a_backend_or_state_directory() {
        assert!(backend().is_err());
        assert!(is_elevated().is_err());
        assert!(elevate(&[]).is_err());
        // A machine with Secblitz installed has the real private folder, which is rightly trusted.
        #[cfg(unix)]
        let installed = std::path::Path::new(unix::state_path()).exists();
        #[cfg(not(unix))]
        let installed = false;
        assert!(installed || state_dir().is_err());
        assert!(permission_gate("permissions.service.bits").is_err());
        assert!(permission_gate("permissions.service.wuauserv").is_err());
    }
}
