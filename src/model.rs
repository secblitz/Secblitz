use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub description: String,
    pub target: serde_json::Value,
    pub reboot: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EffectiveFirewall {
    Enabled(bool),
    Inbound(InboundAction),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InboundAction {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Local,
    Managed,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Observation {
    pub value: serde_json::Value,
    pub eligible: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<EffectiveFirewall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Authority>,
    /// Display only, never mutation authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<ItemLabel>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemLabel {
    pub kind: String,
    pub name: String,
    /// The item's own name in its control, for kinds the person can pick from.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    /// Comma separated reasons from [`ItemLabel::WHY`] that explain why it is listed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
}

impl ItemLabel {
    pub const KINDS: [&'static str; 12] = [
        "service",
        "rule",
        "startup",
        "task",
        "hosts",
        "account",
        "share",
        "addon",
        "app",
        "skip_missing",
        "skip_shadow",
        "more",
    ];
    pub const WHY: [&'static str; 2] = ["sites", "programs"];
    pub const MAX_ITEMS: usize = 64;
    pub const MAX_NAME: usize = 120;

    /// Backend text is untrusted display data: keep only known kinds, strip
    /// control characters, bound the length and the number of items.
    pub fn clean(labels: &[ItemLabel]) -> Vec<ItemLabel> {
        labels
            .iter()
            .filter(|l| Self::KINDS.contains(&l.kind.as_str()))
            .filter_map(|l| {
                let name: String = l
                    .name
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(Self::MAX_NAME)
                    .collect();
                let name = name.trim().to_owned();
                let key = if l.kind == "addon" && crate::hardening::addon_name_ok(&l.key) {
                    l.key.clone()
                } else {
                    String::new()
                };
                let why: Vec<&str> = l.why.split(',').filter(|w| Self::WHY.contains(w)).collect();
                (!name.is_empty() && (l.kind != "addon" || !key.is_empty())).then(|| ItemLabel {
                    kind: l.kind.clone(),
                    name,
                    key,
                    why: if l.kind == "addon" {
                        why.join(",")
                    } else {
                        String::new()
                    },
                })
            })
            .take(Self::MAX_ITEMS)
            .collect()
    }
}

/// Validates typed evidence at both native decoding and the engine boundary. Missing evidence never proves effective protection.
pub fn validate_observation(id: &str, obs: &Observation) -> anyhow::Result<()> {
    validate_observation_for(crate::os::Os::Windows, id, obs)
}

/// Typed firewall evidence belongs to the Windows catalog only; any other system's controls must carry none.
pub fn validate_observation_for(
    os: crate::os::Os,
    id: &str,
    obs: &Observation,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    let windows = os == crate::os::Os::Windows;
    let enabled = windows
        && matches!(
            id,
            "firewall.domain.enabled" | "firewall.private.enabled" | "firewall.public.enabled"
        );
    let inbound = windows
        && matches!(
            id,
            "firewall.domain.inbound" | "firewall.private.inbound" | "firewall.public.inbound"
        );
    ensure!(
        (enabled || inbound) || (obs.effective.is_none() && obs.authority.is_none()),
        "Firewall evidence is invalid for this control"
    );
    ensure!(
        match obs.effective {
            None => true,
            Some(EffectiveFirewall::Enabled(_)) => enabled,
            Some(EffectiveFirewall::Inbound(_)) => inbound,
        },
        "Firewall evidence does not match the control"
    );
    ensure!(
        !obs.eligible || !matches!(obs.authority, Some(Authority::Managed | Authority::Unknown)),
        "Nonlocal firewall authority cannot be eligible"
    );
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum Probe<T> {
    Known(T),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeReadiness {
    pub available_bytes: u64,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowerReadiness {
    pub ac_connected: Option<bool>,
    pub battery_percent: Option<u8>,
    pub battery_present: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Readiness {
    pub system_volume: Probe<VolumeReadiness>,
    pub journal_volume: Probe<VolumeReadiness>,
    pub power: Probe<PowerReadiness>,
    pub windows_update_reboot: Probe<bool>,
}

impl Readiness {
    /// Unknown probes and informational power/reboot signals do not block; undo keeps its own gates.
    pub fn blocks_repairs(&self) -> bool {
        matches!(&self.system_volume, Probe::Known(v) if v.read_only)
            || matches!(&self.journal_volume, Probe::Known(v) if v.read_only || v.available_bytes == 0)
    }
}

/// Outcome and finding status. Unrecognised text from disk or the backend is kept as `Other` so saved reports still load.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CheckStatus {
    Ok,
    Info,
    Attention,
    Review,
    #[default]
    Unknown,
    Compliant,
    Pending,
    Applied,
    Restored,
    Unchanged,
    Skipped,
    Error,
    Conflict,
    Other(String),
}

impl CheckStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Attention => "attention",
            Self::Review => "review",
            Self::Unknown => "unknown",
            Self::Compliant => "compliant",
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Restored => "restored",
            Self::Unchanged => "unchanged",
            Self::Skipped => "skipped",
            Self::Error => "error",
            Self::Conflict => "conflict",
            Self::Other(s) => s,
        }
    }
}

impl From<&str> for CheckStatus {
    fn from(s: &str) -> Self {
        match s {
            "ok" => Self::Ok,
            "info" => Self::Info,
            "attention" => Self::Attention,
            "review" => Self::Review,
            "unknown" => Self::Unknown,
            "compliant" => Self::Compliant,
            "pending" => Self::Pending,
            "applied" => Self::Applied,
            "restored" => Self::Restored,
            "unchanged" => Self::Unchanged,
            "skipped" => Self::Skipped,
            "error" => Self::Error,
            "conflict" => Self::Conflict,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for CheckStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CheckStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|s| Self::from(s.as_str()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub status: CheckStatus,
    pub detail: String,
}

pub trait Backend {
    fn machine_id(&mut self) -> anyhow::Result<String>;
    fn controls(&self) -> Vec<Control>;
    fn observe(&mut self, id: &str) -> anyhow::Result<Observation>;
    fn observe_many(&mut self, ids: &[&str]) -> Vec<anyhow::Result<Observation>> {
        ids.iter().map(|id| self.observe(id)).collect()
    }
    fn write(&mut self, id: &str, value: &serde_json::Value) -> anyhow::Result<()>;
    fn findings(&mut self) -> anyhow::Result<Vec<Finding>>;
    fn readiness(&mut self) -> Readiness {
        Readiness::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn check_status_round_trips_every_value_and_keeps_unknown_text() {
        for s in [
            "ok",
            "info",
            "attention",
            "review",
            "unknown",
            "compliant",
            "pending",
            "applied",
            "restored",
            "unchanged",
            "skipped",
            "error",
            "conflict",
        ] {
            let v: CheckStatus = serde_json::from_value(json!(s)).unwrap();
            assert!(!matches!(v, CheckStatus::Other(_)), "{s}");
            assert_eq!(v.as_str(), s);
            assert_eq!(serde_json::to_value(&v).unwrap(), json!(s));
        }
        let v: CheckStatus = serde_json::from_value(json!("from_the_future")).unwrap();
        assert_eq!(v, CheckStatus::Other("from_the_future".into()));
        assert_eq!(serde_json::to_value(&v).unwrap(), json!("from_the_future"));
        let f: Finding =
            serde_json::from_value(json!({"title":"t","status":"review","detail":"d"})).unwrap();
        assert_eq!(f.status, CheckStatus::Review);
    }

    #[test]
    fn firewall_evidence_is_typed_control_scoped_and_never_grants_eligibility() {
        for profile in ["domain", "private", "public"] {
            for (suffix, raw, evidence, wrong) in [
                (
                    "enabled",
                    json!(true),
                    EffectiveFirewall::Enabled(true),
                    EffectiveFirewall::Inbound(InboundAction::Block),
                ),
                (
                    "inbound",
                    json!("NotConfigured"),
                    EffectiveFirewall::Inbound(InboundAction::Block),
                    EffectiveFirewall::Enabled(true),
                ),
            ] {
                let id = format!("firewall.{profile}.{suffix}");
                let mut obs = Observation {
                    value: raw,
                    eligible: true,
                    effective: Some(evidence),
                    authority: Some(Authority::Local),
                    ..Default::default()
                };
                validate_observation(&id, &obs).unwrap();
                for foreign in [
                    "defender.realtime",
                    "firewall.other.inbound",
                    "permissions.service.bits",
                ] {
                    assert!(validate_observation(foreign, &obs).is_err());
                }
                obs.effective = Some(wrong);
                assert!(validate_observation(&id, &obs).is_err());
                obs.effective = Some(evidence);
                for authority in [Authority::Managed, Authority::Unknown] {
                    obs.authority = Some(authority);
                    assert!(validate_observation(&id, &obs).is_err());
                    obs.eligible = false;
                    validate_observation(&id, &obs).unwrap();
                    obs.eligible = true;
                }
                obs.effective = None;
                obs.authority = None;
                validate_observation(&id, &obs).unwrap();
            }
        }
    }

    #[test]
    fn evidence_serialization_rejects_untyped_payloads_and_defaults_to_unknown() {
        let old: Observation = serde_json::from_value(
            json!({"value":"NotConfigured","eligible":true,"reason":"local"}),
        )
        .unwrap();
        assert!(old.effective.is_none() && old.authority.is_none());
        assert!(serde_json::to_value(&old)
            .unwrap()
            .get("effective")
            .is_none());
        assert_eq!(
            serde_json::to_value(EffectiveFirewall::Inbound(InboundAction::Block)).unwrap(),
            json!({"kind":"inbound","value":"block"})
        );
        for bad in [
            json!({"kind":"inbound","value":"Block"}),
            json!({"kind":"enabled","value":"true"}),
            json!({"kind":"inbound","value":"NotConfigured"}),
            json!({"kind":"inbound","value":"block","command":"execute"}),
        ] {
            assert!(serde_json::from_value::<EffectiveFirewall>(bad).is_err());
        }
        assert_eq!(
            serde_json::to_value(Readiness::default()).unwrap(),
            json!({
                "system_volume":{"status":"unknown"}, "journal_volume":{"status":"unknown"},
                "power":{"status":"unknown"}, "windows_update_reboot":{"status":"unknown"}
            })
        );
    }
}
