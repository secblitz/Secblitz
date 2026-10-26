//! The compiled Linux catalog. Every control is a fixed list of named keys with u32 or short text values; the rules are
//! the same `hardening::Rule` ones the Windows table uses. A fix only moves a key from a recorded unsafe value to its
//! fixed value, and the backend chooses the mechanism. Journal data can only name an id listed here.
//!
//! Value shapes, one line per id: every value is `{"items": {<key>: <u32 | text | null>}}`; null is "not present".

use crate::hardening::{self, set, Item, Key};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Changed by the root helper.
    System,
    /// Changed by the app itself, in the person's own session.
    Person,
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxSpec {
    pub id: &'static str,
    pub scope: Scope,
    /// Optional: never pre-selected, the person has to ask for it.
    pub ask: bool,
    pub reboot: bool,
    pub keys: &'static [Key],
}

const fn text(
    name: &'static str,
    safe: &'static [&'static str],
    absent_safe: bool,
    fix: Option<&'static str>,
) -> Key {
    hardening::text(name, "", safe, absent_safe, fix)
}

const fn flag(name: &'static str, absent_safe: bool) -> Key {
    set(name, "", &[0], absent_safe, Some(0), 1)
}

const fn on(name: &'static str) -> Key {
    set(name, "", &[1], false, Some(1), 1)
}

const SPECS: &[LinuxSpec] = &[
    // enabled "yes"/"no"; incoming "deny"/"reject"/"allow": the policy for connections from other computers.
    LinuxSpec {
        id: "linux.firewall",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            text("enabled", &["yes"], false, Some("yes")),
            text("incoming", &["deny", "reject"], false, Some("deny")),
        ],
    },
    // open_ranges: the wide port ranges of the Fedora Workstation zone as text such as "1025-65535/tcp 1025-65535/udp"; null when none.
    LinuxSpec {
        id: "linux.fedora_open_ports",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[text("open_ranges", &[], true, None)],
    },
    // unattended: days between automatic security updates, 0 off.
    LinuxSpec {
        id: "linux.auto_updates",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set(
            "unattended",
            "",
            &[1, 2, 3, 4, 5, 6, 7],
            false,
            Some(1),
            365,
        )],
    },
    // enabled: 1 when the SSH server runs or starts at boot.
    LinuxSpec {
        id: "linux.ssh_server",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("enabled", true)],
    },
    // password: 1 when passwords may be used to sign in over SSH; root_login: "yes", "no", "prohibit-password" or "forced-commands-only".
    LinuxSpec {
        id: "linux.ssh_password",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            flag("password", false),
            text(
                "root_login",
                &["no", "prohibit-password", "forced-commands-only"],
                false,
                Some("prohibit-password"),
            ),
        ],
    },
    // samba: 1 when the Windows file sharing service is enabled.
    LinuxSpec {
        id: "linux.file_sharing",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("samba", true)],
    },
    // gdm_automatic: GDM's AutomaticLoginEnable as "true" or "false"; lightdm_user: LightDM's autologin-user, null when off.
    LinuxSpec {
        id: "linux.autologin",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            text("gdm_automatic", &["false"], true, Some("false")),
            text("lightdm_user", &[], true, None),
        ],
    },
    // allow_guest: LightDM's allow-guest as "true" or "false"; null when LightDM is not in use.
    LinuxSpec {
        id: "linux.guest",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[text("allow_guest", &["false"], true, Some("false"))],
    },
    // The running kernel settings: kptr_restrict 0-2, dmesg_restrict 0-1, protected_* 0-2 (hardlinks and symlinks 0-1).
    LinuxSpec {
        id: "linux.kernel_protections",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            set("kptr_restrict", "", &[1, 2], false, Some(1), 2),
            on("dmesg_restrict"),
            on("protected_hardlinks"),
            on("protected_symlinks"),
            set("protected_fifos", "", &[1, 2], false, Some(1), 2),
            set("protected_regular", "", &[1, 2], false, Some(2), 2),
        ],
    },
    // apport: 1 when Ubuntu's crash reporting is enabled.
    LinuxSpec {
        id: "linux.crash_reports",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("apport", true)],
    },
    // countme: 1 when a Fedora repository counts this computer.
    LinuxSpec {
        id: "linux.countme",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("countme", true)],
    },
    // enabled: 1 when NetworkManager checks the internet connection with an outside address.
    LinuxSpec {
        id: "linux.connectivity_check",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("enabled", true)],
    },
    // cloned_mac: the Wi-Fi address policy for new connections: "preserve", "permanent", "random" or "stable".
    LinuxSpec {
        id: "linux.wifi_mac",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[text(
            "cloned_mac",
            &["stable", "random"],
            false,
            Some("stable"),
        )],
    },
    // lock_enabled: 1 when the screen locks; idle_never: 1 when the screen never goes idle (idle-delay 0), fixed to 300 seconds.
    LinuxSpec {
        id: "linux.screen_lock",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[on("lock_enabled"), flag("idle_never", false)],
    },
    // rdp, vnc: 1 when GNOME Remote Desktop accepts that kind of connection.
    LinuxSpec {
        id: "linux.remote_desktop",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[flag("rdp", true), flag("vnc", true)],
    },
    // keep_forever: 1 when recent files are remembered with no age limit; fixed to 30 days.
    LinuxSpec {
        id: "linux.recent_files",
        scope: Scope::Person,
        ask: true,
        reboot: false,
        keys: &[flag("keep_forever", false)],
    },
    // show_on_lock: 1 when notification text shows on the lock screen.
    LinuxSpec {
        id: "linux.lock_previews",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[flag("show_on_lock", true)],
    },
    // shared: 1 when any Ubuntu Insights source may send data.
    LinuxSpec {
        id: "linux.ubuntu_insights",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[flag("shared", true)],
    },
];

pub fn specs() -> &'static [LinuxSpec] {
    SPECS
}

pub fn spec(id: &str) -> Option<&'static LinuxSpec> {
    SPECS.iter().find(|s| s.id == id)
}

impl LinuxSpec {
    fn key(&self, name: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.name == name)
    }

    pub fn catalog_target(&self) -> Value {
        hardening::fixed_target(self.keys)
    }

    fn parse(&self, value: &Value) -> anyhow::Result<Vec<(String, Item)>> {
        hardening::parse_items(self.id, value, |n| self.key(n), Some(self.keys.len()))
    }

    pub fn validate(&self, value: &Value) -> anyhow::Result<()> {
        self.parse(value).map(|_| ())
    }

    pub fn any_unsafe(&self, value: &Value) -> bool {
        self.parse(value).is_ok_and(|items| {
            items.iter().any(|(n, v)| {
                self.key(n)
                    .is_some_and(|k| !hardening::item_is_safe(k.rule, v))
            })
        })
    }

    pub fn derive_target(&self, before: &Value) -> anyhow::Result<Value> {
        hardening::derive_items(self.parse(before)?, |n| self.key(n))
    }

    /// Every key is always read, so there is nothing to narrow.
    pub fn view(&self, observed: &Value, _template: &Value) -> Value {
        observed.clone()
    }

    /// A control that is not on this computer is skipped by the backend, not read as protected.
    pub fn nothing_to_protect(&self, _value: &Value) -> bool {
        false
    }

    pub fn exact_recorded(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::Os;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_never_a_windows_id() {
        let mut seen = HashSet::new();
        for s in specs() {
            assert!(s.id.starts_with("linux."), "{}", s.id);
            assert!(seen.insert(s.id), "{} appears twice", s.id);
            assert!(!s.keys.is_empty(), "{}", s.id);
        }
        for windows in crate::engine::catalog::ids(Os::Windows) {
            assert!(spec(windows).is_none(), "{windows}");
        }
        assert_eq!(specs().len(), 18);
    }

    #[test]
    fn the_plan_scopes_and_optional_controls_are_as_agreed() {
        let person = [
            "linux.screen_lock",
            "linux.remote_desktop",
            "linux.recent_files",
            "linux.lock_previews",
            "linux.ubuntu_insights",
        ];
        let optional = [
            "linux.fedora_open_ports",
            "linux.connectivity_check",
            "linux.wifi_mac",
            "linux.recent_files",
        ];
        for s in specs() {
            let want = if person.contains(&s.id) {
                Scope::Person
            } else {
                Scope::System
            };
            assert_eq!(s.scope, want, "{}", s.id);
            assert_eq!(s.ask, optional.contains(&s.id), "{}", s.id);
            assert!(!s.reboot, "{}", s.id);
        }
    }

    #[test]
    fn every_target_is_a_valid_value_with_every_key_present() {
        for s in specs() {
            let target = s.catalog_target();
            s.validate(&target)
                .unwrap_or_else(|e| panic!("{}: {e}", s.id));
            let items = target["items"].as_object().unwrap();
            assert_eq!(items.len(), s.keys.len(), "{}", s.id);
            assert!(
                !s.any_unsafe(&target),
                "{}: the fixed value is unsafe",
                s.id
            );
        }
    }

    #[test]
    fn key_names_are_unique_within_a_control() {
        for s in specs() {
            let names: HashSet<_> = s.keys.iter().map(|k| k.name).collect();
            assert_eq!(names.len(), s.keys.len(), "{}", s.id);
        }
    }

    #[test]
    fn a_value_with_a_missing_unknown_or_mistyped_key_is_refused() {
        let firewall = spec("linux.firewall").unwrap();
        let good = json!({"items": {"enabled": "no", "incoming": "allow"}});
        firewall.validate(&good).unwrap();
        for bad in [
            json!({"items": {"enabled": "no"}}),
            json!({"items": {"enabled": "no", "incoming": "allow", "extra": "x"}}),
            json!({"items": {"enabled": 1, "incoming": "allow"}}),
            json!({"enabled": "no", "incoming": "allow"}),
            json!(true),
            json!({"items": {"enabled": "no\nyes", "incoming": "allow"}}),
        ] {
            assert!(firewall.validate(&bad).is_err(), "{bad}");
        }
        let kernel = spec("linux.kernel_protections").unwrap();
        let mut value = kernel.catalog_target();
        value["items"]["kptr_restrict"] = json!(3);
        assert!(kernel.validate(&value).is_err());
    }

    #[test]
    fn a_fix_moves_only_the_unsafe_keys_to_their_fixed_value() {
        let firewall = spec("linux.firewall").unwrap();
        let before = json!({"items": {"enabled": "no", "incoming": "reject"}});
        assert!(firewall.any_unsafe(&before));
        assert_eq!(
            firewall.derive_target(&before).unwrap(),
            json!({"items": {"enabled": "yes", "incoming": "reject"}})
        );

        let kernel = spec("linux.kernel_protections").unwrap();
        let before = json!({"items": {
            "kptr_restrict": 0, "dmesg_restrict": 1, "protected_hardlinks": 1,
            "protected_symlinks": 1, "protected_fifos": 0, "protected_regular": 1
        }});
        assert_eq!(
            kernel.derive_target(&before).unwrap(),
            json!({"items": {
                "kptr_restrict": 1, "dmesg_restrict": 1, "protected_hardlinks": 1,
                "protected_symlinks": 1, "protected_fifos": 1, "protected_regular": 1
            }})
        );
    }

    #[test]
    fn absent_values_follow_each_keys_own_rule() {
        let ssh = spec("linux.ssh_server").unwrap();
        assert!(!ssh.any_unsafe(&json!({"items": {"enabled": null}})));
        assert!(ssh.any_unsafe(&json!({"items": {"enabled": 1}})));
        let fw = spec("linux.firewall").unwrap();
        assert!(fw.any_unsafe(&json!({"items": {"enabled": null, "incoming": "deny"}})));
        let autologin = spec("linux.autologin").unwrap();
        assert!(
            !autologin.any_unsafe(&json!({"items": {"gdm_automatic": null, "lightdm_user": null}}))
        );
        let before = json!({"items": {"gdm_automatic": "true", "lightdm_user": "sam"}});
        assert_eq!(
            autologin.derive_target(&before).unwrap(),
            json!({"items": {"gdm_automatic": "false", "lightdm_user": null}})
        );
    }

    #[test]
    fn the_engine_catalog_lists_exactly_these_ids_for_linux() {
        let listed = crate::engine::catalog::ids(Os::Linux);
        let own: Vec<&str> = specs().iter().map(|s| s.id).collect();
        assert_eq!(listed, own);
    }
}
