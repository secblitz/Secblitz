//! Fixed control catalog: compiled targets, value domains and eligibility rules. Journal data never names its own targets.

use crate::model::{
    Authority, CheckStatus, Control, EffectiveFirewall, InboundAction, Observation,
};
use crate::os::Os;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
const WINDOWS_FIXED_IDS: [&str; 18] = [
    "defender.realtime",
    "defender.behavior",
    "defender.ioav",
    "defender.archive",
    "firewall.domain.enabled",
    "firewall.private.enabled",
    "firewall.public.enabled",
    "firewall.domain.inbound",
    "firewall.private.inbound",
    "firewall.public.inbound",
    "uac.enabled",
    "uac.consent",
    "installer.always_install_elevated",
    "wdigest.use_logon_credential",
    "lsa.restrict_anonymous_sam",
    "lsa.limit_blank_password_use",
    "permissions.service.bits",
    "permissions.service.wuauserv",
];

/// Every control id compiled in for `os`. macOS has none yet.
pub fn ids(os: Os) -> Vec<&'static str> {
    match os {
        Os::Windows => crate::hardening::all()
            .iter()
            .map(|s| s.id)
            .chain(WINDOWS_FIXED_IDS)
            .collect(),
        Os::Linux => crate::linux::catalog::specs()
            .iter()
            .map(|s| s.id)
            .collect(),
        Os::Macos => Vec::new(),
    }
}

/// The compiled target for `id` on `os`. A control of another system is as unknown as one that does not exist.
pub(super) fn target_in(os: Os, id: &str) -> Result<Value> {
    match os {
        Os::Windows => target(id),
        Os::Linux => match crate::linux::catalog::spec(id) {
            Some(spec) => Ok(spec.catalog_target()),
            None => bail!("Unknown control id: {id}"),
        },
        Os::Macos => bail!("Unknown control id: {id}"),
    }
}

// Kept here rather than trusting Backend or serialized Control data. This is
// intentionally the same typed domain as platform.rs and the fixed service
// controls in permissions.rs; journal data cannot name arbitrary objects.
pub(super) fn target(id: &str) -> Result<Value> {
    if let Some(spec) = crate::hardening::spec(id) {
        return Ok(spec.catalog_target());
    }
    Ok(match id {
        "defender.realtime" | "defender.behavior" | "defender.ioav" | "defender.archive" => {
            json!(false)
        }
        "firewall.domain.enabled" | "firewall.private.enabled" | "firewall.public.enabled" => {
            json!(true)
        }
        "firewall.domain.inbound" | "firewall.private.inbound" | "firewall.public.inbound" => {
            json!("Block")
        }
        "uac.enabled" => json!({"present": true, "value": 1}),
        "uac.consent" => json!({"present": true, "value": 5}),
        "installer.always_install_elevated" | "wdigest.use_logon_credential" => {
            json!({"present": true, "value": 0})
        }
        "lsa.restrict_anonymous_sam" | "lsa.limit_blank_password_use" => {
            json!({"present": true, "value": 1})
        }
        "permissions.service.bits" | "permissions.service.wuauserv" => {
            json!("service-dacl-repair-v1")
        }
        _ => bail!("Unknown control id: {id}"),
    })
}

pub(super) fn permission_control(id: &str) -> bool {
    matches!(
        id,
        "permissions.service.bits" | "permissions.service.wuauserv"
    )
}

pub(super) fn machine_registry_control(id: &str) -> bool {
    matches!(
        id,
        "installer.always_install_elevated"
            | "lsa.restrict_anonymous_sam"
            | "lsa.limit_blank_password_use"
            | "wdigest.use_logon_credential"
    )
}

/// Catalog targets are fixed. Only the two compiled service IDs derive a write
/// value from an exact, validated before-image; the sentinel is never written.
pub(super) fn target_for(id: &str, before: &Value) -> Result<Value> {
    if let Some(spec) = crate::linux::catalog::spec(id) {
        return spec.derive_target(before);
    }
    if let Some(spec) = crate::hardening::spec(id) {
        return spec.derive_target(before);
    }
    let fixed = target(id)?;
    if permission_control(id) {
        validate_value(id, before)?;
        let repaired = crate::permissions::repair_target(id, before)?;
        validate_value(id, &repaired)?;
        Ok(repaired)
    } else {
        Ok(fixed)
    }
}

pub(super) fn validate_value(id: &str, value: &Value) -> Result<()> {
    if let Some(spec) = crate::linux::catalog::spec(id) {
        return spec.validate(value);
    }
    if let Some(spec) = crate::hardening::spec(id) {
        return spec.validate(value);
    }
    let expected = target(id)?;
    if permission_control(id) {
        return crate::permissions::validate_value(id, value);
    } else if expected.is_boolean() {
        ensure!(value.is_boolean(), "Invalid boolean preference for {id}");
    } else if expected.is_string() {
        ensure!(
            matches!(value.as_str(), Some("Block" | "Allow" | "NotConfigured")),
            "Invalid inbound preference"
        );
    } else {
        let obj = value.as_object().context("Invalid UAC preference")?;
        ensure!(
            obj.len() == 2 && obj.contains_key("present") && obj.contains_key("value"),
            "Invalid UAC fields"
        );
        match obj["present"].as_bool() {
            Some(false) => ensure!(
                obj["value"].is_null(),
                "Absent UAC preference must have null value"
            ),
            Some(true) => {
                let max = if id == "uac.consent" { 5 } else { 1 };
                ensure!(
                    obj["value"].as_u64().is_some_and(|n| n <= max),
                    "Invalid UAC DWORD"
                );
            }
            None => bail!("Invalid UAC presence flag"),
        }
    }
    Ok(())
}

/// Dynamic hardening controls (firewall rules, saved Wi-Fi networks) observe
/// whatever exists now; comparisons against a journaled state must only look at
/// the keys that were journaled. Everything else is returned unchanged.
pub(super) fn scope(id: &str, observed: &Value, template: Option<&Value>) -> Value {
    match (crate::hardening::spec(id), template) {
        (Some(spec), Some(template)) => spec.view(observed, template),
        _ => observed.clone(),
    }
}

/// A recorded (journaled or derived) state, seen through what exists now.
/// Controls that compare their recorded items exactly keep every one of them,
/// including items that are no longer listed (switched-off accounts, removed
/// share entries); the others only keep what still exists.
pub(super) fn recorded_scope(id: &str, recorded: &Value, observed: &Value) -> Value {
    match crate::hardening::spec(id) {
        Some(spec) if spec.exact_recorded() => recorded.clone(),
        _ => scope(id, recorded, Some(observed)),
    }
}

pub(super) fn firewall_control(id: &str) -> bool {
    matches!(
        id,
        "firewall.domain.enabled"
            | "firewall.private.enabled"
            | "firewall.public.enabled"
            | "firewall.domain.inbound"
            | "firewall.private.inbound"
            | "firewall.public.inbound"
    )
}

/// Assessment only. Never use this predicate to replace a durable raw original
/// or expected raw value during owned-control comparison or rollback.
pub(super) fn firewall_protected(o: &Observation) -> Result<bool> {
    let authority = o.authority.context("Firewall authority is unavailable")?;
    if authority != Authority::Local || !o.eligible {
        return Ok(false);
    }
    let effective = o
        .effective
        .context("Effective firewall evidence is unavailable")?;
    match effective {
        EffectiveFirewall::Enabled(enabled) => {
            ensure!(
                o.value.as_bool() == Some(enabled),
                "Firewall evidence contradicts the local preference"
            );
            Ok(enabled)
        }
        EffectiveFirewall::Inbound(action) => {
            ensure!(
                o.value == "NotConfigured"
                    || (o.value == "Block" && action == InboundAction::Block)
                    || (o.value == "Allow" && action == InboundAction::Allow),
                "Firewall evidence contradicts the local preference"
            );
            Ok(action == InboundAction::Block)
        }
    }
}

pub(super) fn assessment_status(id: &str, o: &Observation) -> Result<CheckStatus> {
    if let Some(spec) = crate::linux::catalog::spec(id) {
        if spec.nothing_to_protect(&o.value) {
            return Ok(CheckStatus::Skipped);
        }
        return Ok(if !spec.any_unsafe(&o.value) {
            CheckStatus::Compliant
        } else if apply_eligible(id, o) {
            CheckStatus::Attention
        } else {
            CheckStatus::Skipped
        });
    }
    if firewall_control(id) {
        return Ok(if firewall_protected(o)? {
            CheckStatus::Compliant
        } else if apply_eligible(id, o) {
            CheckStatus::Attention
        } else {
            CheckStatus::Skipped
        });
    }
    if permission_control(id) && !o.eligible {
        return Ok(CheckStatus::Skipped);
    }
    if let Some(spec) = crate::hardening::spec(id) {
        if spec.nothing_to_protect(&o.value) {
            return Ok(CheckStatus::Skipped);
        }
        return Ok(if !spec.any_unsafe(&o.value) {
            CheckStatus::Compliant
        } else if apply_eligible(id, o) {
            CheckStatus::Attention
        } else {
            CheckStatus::Skipped
        });
    }
    Ok(if o.value == target_for(id, &o.value)? {
        CheckStatus::Compliant
    } else if apply_eligible(id, o) {
        CheckStatus::Attention
    } else {
        CheckStatus::Skipped
    })
}

pub(super) fn apply_eligible(id: &str, o: &Observation) -> bool {
    if !o.eligible {
        return false;
    }
    if let Some(spec) = crate::linux::catalog::spec(id) {
        return spec.any_unsafe(&o.value);
    }
    if firewall_control(id) {
        return o.authority == Some(Authority::Local) && matches!(firewall_protected(o), Ok(false));
    }
    if let Some(spec) = crate::hardening::spec(id) {
        return spec.any_unsafe(&o.value);
    }
    // Registry absence and nonzero UAC modes are not repair requests, even if a
    // backend accidentally advertises them as eligible. Binary originals must
    // be the explicit unsafe value, never an invented default for absence.
    if machine_registry_control(id) {
        let unsafe_value = if matches!(
            id,
            "installer.always_install_elevated" | "wdigest.use_logon_credential"
        ) {
            1
        } else {
            0
        };
        o.value == json!({"present":true,"value":unsafe_value})
    } else if matches!(id, "uac.enabled" | "uac.consent") {
        o.value == json!({"present":true,"value":0})
    } else {
        true
    }
}

pub(super) fn restore_eligible(c: &Control, o: &Observation) -> bool {
    if firewall_control(&c.id) {
        return o.eligible && o.authority == Some(Authority::Local);
    }
    o.eligible
        || (matches!(c.id.as_str(), "uac.enabled" | "uac.consent")
        && o.value == c.target
        // This exact platform reason is emitted only after Gate succeeds.
        // A management/capability error replaces it and must never be bypassed.
        && o.reason == "Preserving absent or nonzero UAC preference")
        || (machine_registry_control(&c.id)
            && o.value == c.target
            && o.reason == "Preserving absent or already-safe machine preference")
}

/// The control that must be put back before this one can be, because Windows only keeps this one on while the other is on.
pub(super) fn undo_first(id: &str) -> Option<&'static str> {
    (id == crate::vbs::MEMORY_INTEGRITY).then_some(crate::vbs::STACK_PROTECTION)
}
