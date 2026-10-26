//! Compiled catalog of the extended hardening controls.
//! The same table drives the engine, the platform wire validation and the PowerShell backend, which receives the spec as JSON from [`Spec::script_json`] so Rust and PowerShell cannot disagree about what is safe.
//! A write only moves a key between an unsafe original and its fixed value ([`fix_of`]); safe keys are never touched and a key that drifted to anything else blocks the write. Absent values equal to Windows' own safe default count as protected. Journal data names only keys of this table (or, for dynamic controls, keys that pass a strict name check and exist at write time).
mod specs;
pub(crate) use specs::{set, text};
#[cfg(test)]
mod tests;

use serde_json::{json, Map, Value};
use specs::SPECS;

#[derive(Clone, Copy, Debug)]
pub enum Rule {
    /// Safe when the value is in `safe` (or absent and `absent_safe`).
    /// Repair writes `fix`; `None` removes the value.
    Set {
        safe: &'static [u32],
        absent_safe: bool,
        fix: Option<u32>,
    },
    /// A text (REG_SZ) value, compared exactly. `Key::max` is the longest accepted text in characters.
    Text {
        safe: &'static [&'static str],
        absent_safe: bool,
        fix: Option<&'static str>,
    },
    /// Firewall rule exposure: bit 8 = enabled, bit 4 = applies on the Public
    /// profile, bits 1|2 = Domain|Private. Unsafe when enabled on Public.
    Exposure,
}

#[derive(Clone, Copy, Debug)]
pub struct Key {
    pub name: &'static str,
    pub path: &'static str,
    /// Registry value name when it differs from `name` ("" = same as `name`).
    /// Lets one control hold the same value under several keys.
    pub value: &'static str,
    pub rule: Rule,
    pub max: u32,
    pub allowed: &'static [u32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Registry,
    DefenderPref,
    DefenderAsr,
    Lockout,
    BuiltinAdmin,
    FirewallExposure,
    WifiProfiles,
    NetbiosAdapters,
    FirewallOutbound,
    /// System-wide exploit protection (DEP, SEHOP, ASLR, CFG): 0 off, 1 on, 2 default.
    ExploitMitigations,
    /// Windows PowerShell 2.0 optional feature: 1 installed, 0 removed or absent.
    PowerShellV2,
    LegacyServices,
    LockOnWake,
    /// Windows Update pause markers (minutes since 1970, 0 = nothing to resume).
    UpdatePause,
    SmartScreen,
    DefenderExclusions,
    /// Winlogon `AutoAdminLogon`, a text value ("1" on, "0" off, absent = off).
    /// Only this one value is ever written; the saved password is never read.
    WinlogonAutoLogon,
    /// The old SMB1 file-sharing optional feature and its client and server
    /// parts (1 enabled, 0 disabled or absent). Turned off without removing
    /// the files, so undo can turn exactly the same parts back on.
    SmbFeature,
    /// Dynamic: services whose program path is unquoted (1), quoted by us (0),
    /// or quoted by us and changed since (2). The exact original is kept in
    /// Secblitz-owned state.
    UnquotedServices,
    /// Dynamic: inbound allow rules for programs in Downloads, Desktop or Temp
    /// (1 enabled, 0 switched off by us, 2 switched off by us and changed since).
    UserDirFirewall,
    /// One key, `hosts`: redirects of trusted names (1), commented out by us
    /// (0), commented out by us and changed since (2).
    HostsFile,
    /// Dynamic: risky start-up entries and scheduled tasks (1 enabled, 0 switched
    /// off by us, 2 switched off by us and changed since).
    StartupItems,
    StaleAccounts,
    /// Dynamic: one broad grant (Everyone, Anonymous or Guests) on a shared
    /// folder's permission list (1 present, 0 removed).
    ShareGrants,
    /// The Windows recovery tools (Windows RE): 1 on, 0 off. Read from the
    /// `InstallState` of `%windir%\System32\Recovery\ReAgent.xml`, the file
    /// REAgentC itself keeps, so the reading never depends on the display
    /// language and needs no helper program. Changed only with the inbox
    /// `ReAgentc.exe /enable` and `/disable`.
    RecoveryTools,
    /// Read from the Wi-Fi service setting, never from tool display text.
    WifiRandomAddress,
    /// Dynamic: Chrome and Edge add-ons that can read every site or talk to
    /// other programs (1 on, 0 turned off by us through the browser's block
    /// list, 2 turned off by us and changed since). Only the add-ons the person
    /// picks are ever looked at (see [`Spec::narrow`]).
    BrowserExtensions,
    /// Dynamic: programs that folder protection watched or blocked while changing files
    /// (0 not allowed yet), and the ones Secblitz allowed (1).
    CfaAllowedApps,
}

pub const ITEM_FIXED: u32 = 0;
pub const ITEM_FLAGGED: u32 = 1;
pub const ITEM_CHANGED: u32 = 2;
const HANDLED_SAFE: &[u32] = &[ITEM_FIXED, ITEM_CHANGED];
pub const ADDON_PREFIXES: [&str; 2] = ["chromium:chrome:", "chromium:edge:"];
pub const STARTUP_PREFIXES: [&str; 6] = [
    "run-machine:",
    "run-machine32:",
    "run-user:",
    "folder-machine:",
    "folder-user:",
    "task:",
];

#[derive(Clone, Copy, Debug)]
pub struct Gate {
    pub areas: &'static [&'static str],
    pub pattern: &'static str,
    /// Defender controls only: tamper protection does not block strengthening
    /// these (non tamper-protected) preferences.
    pub tamper_exempt: bool,
    pub secedit: bool,
    pub own_policy_key: &'static str,
    /// Values other controls of this program keep in the same policy key. They
    /// are not somebody else's management, so they never block this control.
    pub shared_values: &'static [&'static str],
    pub policy_values: &'static [(&'static str, &'static str)],
}

#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub source: Source,
    pub reboot: bool,
    pub ask: bool,
    pub keys: &'static [Key],
    pub gate: Gate,
}

/// What a person is told before agreeing to a fix, derived from the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notices {
    pub managed: bool,
    pub restart: bool,
    pub undoable: bool,
}

const BROWSER_POLICY_ROOTS: [&str; 4] = [
    r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
    r"HKLM:\SOFTWARE\Policies\Google\Chrome",
    r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox",
    r"HKLM:\SOFTWARE\Policies\BraveSoftware",
];

fn is_browser_policy(path: &str) -> bool {
    BROWSER_POLICY_ROOTS.iter().any(|root| {
        path.len() >= root.len()
            && path.is_char_boundary(root.len())
            && path[..root.len()].eq_ignore_ascii_case(root)
            && matches!(path.as_bytes().get(root.len()), None | Some(b'\\'))
    })
}

/// A fix that only removes policy values leaves no "managed" notice behind.
fn writes_a_value(rule: &Rule) -> bool {
    matches!(
        rule,
        Rule::Set { fix: Some(_), .. } | Rule::Text { fix: Some(_), .. }
    )
}

pub fn notices(spec: &Spec) -> Notices {
    Notices {
        managed: spec.source == Source::BrowserExtensions
            || spec
                .keys
                .iter()
                .any(|k| is_browser_policy(k.path) && writes_a_value(&k.rule)),
        restart: spec.reboot,
        undoable: true,
    }
}

pub fn all() -> &'static [Spec] {
    SPECS
}

pub fn spec(id: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|s| s.id == id)
}

pub fn is_hardening_check_id(id: &str) -> bool {
    spec(id).is_some()
}

pub fn is_ask_check_id(id: &str) -> bool {
    spec(id).is_some_and(|s| s.ask)
}

pub fn is_safe(rule: Rule, v: Option<u32>) -> bool {
    match (rule, v) {
        (Rule::Set { absent_safe, .. }, None) => absent_safe,
        (Rule::Set { safe, .. }, Some(n)) => safe.contains(&n),
        (Rule::Exposure, Some(n)) => !(n & 8 != 0 && n & 4 != 0),
        (Rule::Exposure, None) => false,
        (Rule::Text { .. }, _) => false,
    }
}

pub fn fix_of(rule: Rule, v: Option<u32>) -> Option<u32> {
    if is_safe(rule, v) {
        return v;
    }
    match (rule, v) {
        (Rule::Set { fix, .. }, _) => fix,
        (Rule::Exposure, Some(n)) => Some(if n & 3 == 0 { n & !8 } else { n & !4 }),
        (Rule::Exposure, None) => None,
        (Rule::Text { .. }, _) => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Absent,
    Num(u32),
    Text(String),
}

impl Item {
    fn from_json(v: &Value) -> anyhow::Result<Item> {
        use anyhow::Context;
        Ok(match v {
            Value::Null => Item::Absent,
            Value::Number(n) => {
                let n = n.as_u64().and_then(|n| u32::try_from(n).ok());
                Item::Num(n.context("Invalid hardening DWORD")?)
            }
            Value::String(s) => Item::Text(s.clone()),
            _ => anyhow::bail!("Invalid hardening item value"),
        })
    }

    fn to_json(&self) -> Value {
        match self {
            Item::Absent => Value::Null,
            Item::Num(n) => Value::from(*n),
            Item::Text(s) => Value::from(s.as_str()),
        }
    }
}

/// A value of the wrong kind is never safe.
pub fn item_is_safe(rule: Rule, v: &Item) -> bool {
    match (rule, v) {
        (Rule::Text { absent_safe, .. }, Item::Absent) => absent_safe,
        (Rule::Text { safe, .. }, Item::Text(s)) => safe.contains(&s.as_str()),
        (Rule::Text { .. }, Item::Num(_)) => false,
        (_, Item::Text(_)) => false,
        (_, Item::Absent) => is_safe(rule, None),
        (_, Item::Num(n)) => is_safe(rule, Some(*n)),
    }
}

pub fn item_fix(rule: Rule, v: &Item) -> Item {
    if item_is_safe(rule, v) {
        return v.clone();
    }
    match rule {
        Rule::Text { fix, .. } => fix.map_or(Item::Absent, |t| Item::Text(t.to_string())),
        _ => match v {
            Item::Num(n) => fix_of(rule, Some(*n)).map_or(Item::Absent, Item::Num),
            _ => fix_of(rule, None).map_or(Item::Absent, Item::Num),
        },
    }
}

/// The fixed values of a control whose keys are all known ahead of time.
pub(crate) fn fixed_target(keys: &[Key]) -> Value {
    let mut items = Map::new();
    for k in keys {
        let fixed = match k.rule {
            Rule::Set { fix, .. } => fix.map_or(Value::Null, Value::from),
            Rule::Text { fix, .. } => fix.map_or(Value::Null, Value::from),
            Rule::Exposure => Value::Null,
        };
        items.insert(k.name.into(), fixed);
    }
    json!({ "items": items })
}

/// Reads a control's `{"items": {...}}` value, rejecting anything that is not a legal setting of one of its keys.
/// With `required` set, exactly that many keys must be present.
pub(crate) fn parse_items<'k>(
    id: &str,
    value: &Value,
    key: impl Fn(&str) -> Option<&'k Key>,
    required: Option<usize>,
) -> anyhow::Result<Vec<(String, Item)>> {
    use anyhow::{ensure, Context};
    let obj = value
        .as_object()
        .context("Invalid hardening state: expected an object")?;
    ensure!(
        obj.len() == 1,
        "Invalid hardening state: expected exactly one items field"
    );
    let items = obj
        .get("items")
        .and_then(Value::as_object)
        .context("Invalid hardening state: items must be an object")?;
    ensure!(items.len() <= 256, "Too many hardening items");
    let mut out = Vec::new();
    for (name, v) in items {
        let key = key(name).with_context(|| format!("Unknown hardening item for {id}"))?;
        let parsed = Item::from_json(v)?;
        match (&parsed, key.rule) {
            (Item::Absent, Rule::Exposure) => anyhow::bail!("Exposure state cannot be absent"),
            (Item::Absent, _) => {}
            (Item::Text(t), Rule::Text { .. }) => {
                ensure!(text_ok(t, key.max), "Hardening text is not a legal setting");
            }
            (Item::Text(_), _) | (Item::Num(_), Rule::Text { .. }) => {
                anyhow::bail!("Hardening item has the wrong kind of value")
            }
            (Item::Num(n), _) => {
                ensure!(*n <= key.max, "Hardening value out of range");
                ensure!(
                    key.allowed.is_empty() || key.allowed.contains(n),
                    "Hardening value is not a legal setting"
                );
            }
        }
        out.push((name.clone(), parsed));
    }
    if let Some(count) = required {
        ensure!(
            out.len() == count,
            "Hardening state must contain every item"
        );
    }
    Ok(out)
}

/// The value a before-image moves to: each unsafe key to its fix, safe keys unchanged.
pub(crate) fn derive_items<'k>(
    parsed: Vec<(String, Item)>,
    key: impl Fn(&str) -> Option<&'k Key>,
) -> anyhow::Result<Value> {
    let mut items = Map::new();
    for (name, v) in parsed {
        let key = key(&name).expect("parsed key exists");
        items.insert(name, item_fix(key.rule, &v).to_json());
    }
    Ok(json!({ "items": items }))
}

/// Plain single-line text, so a journaled original can be written back exactly.
fn text_ok(s: &str, max: u32) -> bool {
    s.chars().count() <= max as usize && !s.chars().any(char::is_control)
}

fn key_name_ok(source: Source, name: &str) -> bool {
    match source {
        Source::FirewallExposure => {
            (name.starts_with("FPS-") || name.starts_with("NETDIS-"))
                && name.len() <= 96
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        }
        Source::NetbiosAdapters | Source::WifiRandomAddress => {
            name.len() == 38
                && name.starts_with('{')
                && name.ends_with('}')
                && name[1..37]
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == '-')
                && name[1..37].matches('-').count() == 4
        }
        Source::WifiProfiles => {
            !name.is_empty()
                && name.chars().count() <= 64
                && !name.chars().any(|c| c.is_control() || c == '"')
                && name.trim() == name
        }
        Source::LegacyServices => LEGACY_SERVICES.contains(&name),
        Source::DefenderExclusions => {
            let rest = ["path:", "ext:", "proc:"]
                .iter()
                .find_map(|p| name.strip_prefix(p));
            rest.is_some_and(|r| !r.is_empty())
                && name.chars().count() <= 300
                && !name.chars().any(|c| c.is_control() || c == '"')
                && name.trim() == name
        }
        Source::UnquotedServices => {
            // Service key names: up to 256 characters, no path separators or wildcards.
            !name.is_empty()
                && name.chars().count() <= 256
                && name.trim() == name
                && !name.chars().any(|c| {
                    c.is_control() || matches!(c, '"' | '\\' | '/' | '*' | '?' | '[' | ']')
                })
        }
        Source::UserDirFirewall => {
            !name.is_empty()
                && name.chars().count() <= 200
                && name.trim() == name
                // Wildcards would let one name match many rules.
                && !name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '[' | ']'))
        }
        Source::HostsFile => name == "hosts",
        Source::StartupItems => {
            let rest = STARTUP_PREFIXES.iter().find_map(|p| name.strip_prefix(p));
            rest.is_some_and(|r| {
                !r.is_empty()
                    && (!name.starts_with("task:") || r.starts_with('\\'))
                    && !r.ends_with('\\')
            }) && name.chars().count() <= 260
                && name.trim() == name
                && !name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '[' | ']'))
        }
        Source::StaleAccounts => stale_account_name_ok(name),
        Source::ShareGrants => share_grant_name_ok(name),
        Source::BrowserExtensions => addon_name_ok(name),
        Source::CfaAllowedApps => cfa_app_name_ok(name),
        _ => false,
    }
}

/// `chromium:<chrome|edge>:<extension id>`: Chromium extension ids are 32 letters from a to p.
pub fn addon_name_ok(name: &str) -> bool {
    ADDON_PREFIXES
        .iter()
        .find_map(|p| name.strip_prefix(p))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)))
}

/// A local account SID with a user-created RID (1000 and up): never the
/// built-in Administrator, Guest, DefaultAccount or WDAGUtilityAccount.
fn stale_account_name_ok(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
        && !parts[3].starts_with('0')
        && parts[3]
            .parse::<u64>()
            .is_ok_and(|rid| (1000..=u64::from(u32::MAX)).contains(&rid))
}

/// Programs that run other programs or scripts: allowing one would let anything
/// it starts change protected files.
pub const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
];

/// `app:<drive letter path to one .exe>`: no wildcards, variables, network
/// paths, relative parts or script hosts.
fn cfa_app_name_ok(name: &str) -> bool {
    let Some(path) = name.strip_prefix("app:") else {
        return false;
    };
    let b = path.as_bytes();
    if path.chars().count() > 260
        || path.len() < 7
        || !(b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || path.trim() != path
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '<' | '>' | '|' | '%' | '/'))
        || path[2..].contains(':')
    {
        return false;
    }
    let mut parts = path[3..].split('\\').peekable();
    let mut leaf = "";
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." || part.trim_end() != part {
            return false;
        }
        if parts.peek().is_none() {
            leaf = part;
        }
    }
    let leaf = leaf.to_ascii_lowercase();
    leaf.ends_with(".exe") && leaf.len() > 4 && !SCRIPT_HOSTS.contains(&leaf.as_str())
}

pub const BROAD_SIDS: &[&str] = &["S-1-1-0", "S-1-5-7", "S-1-5-32-546"];
pub const BROAD_RIGHTS: &[&str] = &["Change", "Full"];

/// `<share name>|<SID>|<right>`: one entry of a share's permission list.
/// Windows share names cannot hold `|`, quotes or control characters. The
/// built-in shares (C$, ADMIN$, IPC$, print$, drive shares) are never named;
/// a hidden share the person made themselves (ending in `$`) can be.
fn share_grant_name_ok(name: &str) -> bool {
    let parts: Vec<&str> = name.split('|').collect();
    let [share, sid, right] = parts[..] else {
        return false;
    };
    !share.is_empty()
        && share.chars().count() <= 80
        && !builtin_share(share)
        && share.trim() == share
        && !share.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '"' | '/'
                        | '\\'
                        | '['
                        | ']'
                        | ':'
                        | '<'
                        | '>'
                        | '+'
                        | '='
                        | ';'
                        | ','
                        | '?'
                        | '*'
                )
        })
        && BROAD_SIDS.contains(&sid)
        && BROAD_RIGHTS.contains(&right)
}

fn builtin_share(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    if matches!(up.as_str(), "ADMIN$" | "IPC$" | "PRINT$") {
        return true;
    }
    let b = up.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b'$'
}

pub const LEGACY_SERVICES: &[&str] = &[
    "RemoteRegistry",
    "WinRM",
    "sshd",
    "TlntSvr",
    "FTPSVC",
    "W3SVC",
    "SNMP",
];

impl Spec {
    /// Turned on for each device found, so with no device there is nothing to
    /// protect and an empty reading is not a protected one.
    pub fn nothing_to_protect(&self, value: &Value) -> bool {
        self.source == Source::WifiRandomAddress
            && self.parse(value).is_ok_and(|items| items.is_empty())
    }

    pub fn dynamic(&self) -> bool {
        matches!(
            self.source,
            Source::FirewallExposure
                | Source::WifiProfiles
                | Source::NetbiosAdapters
                | Source::WifiRandomAddress
                | Source::LegacyServices
                | Source::DefenderExclusions
                | Source::UnquotedServices
                | Source::UserDirFirewall
                | Source::HostsFile
                | Source::StartupItems
                | Source::StaleAccounts
                | Source::ShareGrants
                | Source::BrowserExtensions
                | Source::CfaAllowedApps
        )
    }

    /// Whether the person names the items to change. Without a choice nothing is
    /// ever written, so applying every control at once cannot touch them.
    pub fn needs_choice(&self) -> bool {
        self.source == Source::BrowserExtensions
    }

    /// Whether items found later are changed in a batch of their own, next to
    /// the batches already recorded.
    pub fn adds_batches(&self) -> bool {
        self.source == Source::BrowserExtensions
    }

    pub fn item_name_ok(&self, name: &str) -> bool {
        self.dynamic() && key_name_ok(self.source, name)
    }

    /// An observation reduced to the named items. Items that are not named are
    /// left out of the record altogether.
    pub fn narrow(&self, observed: &Value, names: &[String]) -> Value {
        let Some(items) = observed.get("items").and_then(Value::as_object) else {
            return observed.clone();
        };
        let kept: Map<String, Value> = items
            .iter()
            .filter(|(k, _)| names.contains(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        json!({ "items": kept })
    }

    /// Whether `observed` holds an item that still needs changing and is not part of `recorded`.
    pub fn has_unrecorded_unsafe(&self, observed: &Value, recorded: &Value) -> bool {
        self.unsafe_item(observed, recorded, false)
    }

    /// Whether an item of `recorded` needs changing again in `observed`.
    pub fn has_recorded_unsafe(&self, observed: &Value, recorded: &Value) -> bool {
        self.unsafe_item(observed, recorded, true)
    }

    fn unsafe_item(&self, observed: &Value, recorded: &Value, in_record: bool) -> bool {
        let (Some(o), Some(r)) = (
            observed.get("items").and_then(Value::as_object),
            recorded.get("items").and_then(Value::as_object),
        ) else {
            return false;
        };
        o.iter().any(|(k, v)| {
            r.contains_key(k) == in_record
                && self.key(k).is_some_and(|key| {
                    Item::from_json(v).is_ok_and(|item| !item_is_safe(key.rule, &item))
                })
        })
    }

    fn key(&self, name: &str) -> Option<&Key> {
        if self.dynamic() {
            key_name_ok(self.source, name).then(|| &self.keys[0])
        } else {
            self.keys.iter().find(|k| k.name == name)
        }
    }

    /// The target recorded in the catalog. Dynamic controls derive their target
    /// from each before-image, so the catalog holds a fixed sentinel.
    pub fn catalog_target(&self) -> Value {
        if self.dynamic() {
            return json!("derived-items-v1");
        }
        fixed_target(self.keys)
    }

    fn parse(&self, value: &Value) -> anyhow::Result<Vec<(String, Item)>> {
        parse_items(
            self.id,
            value,
            |name| self.key(name),
            (!self.dynamic()).then_some(self.keys.len()),
        )
    }

    pub fn validate(&self, value: &Value) -> anyhow::Result<()> {
        self.parse(value).map(|_| ())
    }

    pub fn any_unsafe(&self, value: &Value) -> bool {
        self.parse(value).is_ok_and(|items| {
            items
                .iter()
                .any(|(n, v)| self.key(n).is_some_and(|k| !item_is_safe(k.rule, v)))
        })
    }

    pub fn derive_target(&self, before: &Value) -> anyhow::Result<Value> {
        derive_items(self.parse(before)?, |name| self.key(name))
    }

    /// Controls whose recorded items are compared exactly as journaled (never
    /// narrowed by what is observed now): the observation is narrowed to them
    /// instead, with vanished items read as "0" (see [`Spec::view`]).
    pub fn exact_recorded(&self) -> bool {
        matches!(
            self.source,
            Source::StaleAccounts | Source::ShareGrants | Source::CfaAllowedApps
        )
    }

    /// Restrict an observation to the keys of a journaled template. Fixed
    /// controls observe exactly their keys, so only dynamic ones are narrowed:
    /// a Wi-Fi network or firewall rule that appeared after the fix must not
    /// make undo of the recorded ones look like drift.
    pub fn view(&self, observed: &Value, template: &Value) -> Value {
        if !self.dynamic() {
            return observed.clone();
        }
        let (Some(o), Some(t)) = (
            observed.get("items").and_then(Value::as_object),
            template.get("items").and_then(Value::as_object),
        ) else {
            return observed.clone();
        };
        if self.exact_recorded() {
            // Exactly the recorded items: an account that was switched off or a
            // share entry that was removed is simply no longer listed, which
            // is "0". Items that appeared since belong to somebody else's
            // change and are never looked at, so they cannot block an undo.
            let items: Map<String, Value> = t
                .keys()
                .map(|k| (k.clone(), o.get(k).cloned().unwrap_or_else(|| json!(0))))
                .collect();
            return json!({ "items": items });
        }
        if self.source == Source::DefenderExclusions {
            // A removed exclusion is simply no longer listed: that is "0".
            // Nothing is filtered out (the engine passes either side as the
            // template), so a new risky entry makes undo stop as a conflict.
            let mut items = o.clone();
            for k in t.keys() {
                items.entry(k.clone()).or_insert_with(|| json!(0));
            }
            return json!({ "items": items });
        }
        let items: Map<String, Value> = o
            .iter()
            .filter(|(k, _)| t.contains_key(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        json!({ "items": items })
    }

    pub fn script_json(&self) -> String {
        let keys: Vec<Value> = self
            .keys
            .iter()
            .map(|k| {
                let (kind, safe, absent_safe, fix) = match k.rule {
                    Rule::Set {
                        safe,
                        absent_safe,
                        fix,
                    } => ("set", json!(safe), absent_safe, json!(fix)),
                    Rule::Text {
                        safe,
                        absent_safe,
                        fix,
                    } => ("text", json!(safe), absent_safe, json!(fix)),
                    Rule::Exposure => ("exposure", json!([]), false, Value::Null),
                };
                json!({
                    "name": k.name, "path": k.path,
                    "valueName": if k.value.is_empty() { k.name } else { k.value },
                    "rule": kind, "safe": safe,
                    "absentSafe": absent_safe, "fix": fix, "max": k.max,
                })
            })
            .collect();
        let g = &self.gate;
        json!({
            "id": self.id,
            "source": format!("{:?}", self.source),
            "dynamic": self.dynamic(),
            "reboot": self.reboot,
            "keys": keys,
            "gate": {
                "areas": g.areas, "pattern": g.pattern, "tamperExempt": g.tamper_exempt,
                "secedit": g.secedit, "ownPolicyKey": g.own_policy_key,
                "sharedValues": g.shared_values,
                "policyValues": g.policy_values.iter()
                    .map(|(p, n)| json!({"path": p, "name": n})).collect::<Vec<_>>(),
            },
        })
        .to_string()
    }
}
