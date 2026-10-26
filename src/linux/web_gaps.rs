//! Ways around web protection on Linux, found by reading files only: browsers told to look sites up on their own, other
//! settings that add lookup servers after Secblitz's, and VPN connections. Nothing here changes anything.

use super::controls::browsers::{chromium_sites, firefox_programs};
use crate::filter::gaps::{compute, Facts, Gap};
use serde_json::Value;

const FIREFOX_POLICY_FILES: [&str; 5] = [
    "/etc/firefox/policies/policies.json",
    "/usr/lib/firefox/distribution/policies.json",
    "/usr/lib64/firefox/distribution/policies.json",
    "/usr/lib/firefox-esr/distribution/policies.json",
    "/usr/share/firefox/distribution/policies.json",
];
const RESOLVED_DIRS: [&str; 3] = [
    "/etc/systemd/resolved.conf.d",
    "/run/systemd/resolved.conf.d",
    "/usr/lib/systemd/resolved.conf.d",
];
const NETWORK_CLASS: &str = "/sys/class/net";
/// Interface names that VPN programs create. A bridge or virtual machine interface is not one.
const VPN_PREFIXES: [&str; 9] = [
    "tun",
    "wg",
    "ppp",
    "tailscale",
    "nordlynx",
    "proton",
    "mullvad",
    "ipsec",
    "vpn",
];

/// Reads the computer, or stands in for it in tests.
pub trait Probe {
    /// The file's text, or `None` when it is missing or cannot be read.
    fn text(&self, path: &str) -> Option<String>;
    /// The names in a folder, sorted; a missing folder has none.
    fn names(&self, dir: &str) -> Vec<String>;
    fn present(&self, path: &str) -> bool;
}

fn json_names(probe: &dyn Probe, dir: &str) -> Vec<String> {
    probe
        .names(dir)
        .into_iter()
        .filter(|n| n.ends_with(".json"))
        .collect()
}

/// `Some(true)` when Firefox's policy turns its own lookups on, `None` when a policy file cannot be understood.
fn firefox_bypasses(probe: &dyn Probe) -> Option<bool> {
    for path in FIREFOX_POLICY_FILES {
        let Some(text) = probe.text(path) else {
            continue;
        };
        let doc: Value = serde_json::from_str(&text).ok()?;
        if let Some(enabled) = doc
            .get("policies")
            .and_then(|p| p.get("DNSOverHTTPS"))
            .and_then(|d| d.get("Enabled"))
        {
            return Some(enabled == &Value::Bool(true));
        }
    }
    Some(false)
}

/// The mode the files give a Chrome-family browser, the way the browser reads the folder: by file name, the last wins.
fn chromium_mode(probe: &dyn Probe, managed: &str) -> Option<Option<String>> {
    let mut mode = None;
    for name in json_names(probe, managed) {
        let Some(text) = probe.text(&format!("{managed}/{name}")) else {
            continue;
        };
        let doc: Value = serde_json::from_str(&text).ok()?;
        if let Some(value) = doc.get("DnsOverHttpsMode").and_then(Value::as_str) {
            mode = Some(value.to_owned());
        }
    }
    Some(mode)
}

fn browser_bypasses(probe: &dyn Probe) -> Option<bool> {
    let mut bypass = false;
    if firefox_programs().iter().any(|p| probe.present(p)) || probe.present("/etc/firefox") {
        bypass |= firefox_bypasses(probe)?;
    }
    for site in chromium_sites() {
        let installed =
            probe.present(site.policies) || site.programs.iter().any(|p| probe.present(p));
        if installed {
            bypass |= matches!(
                chromium_mode(probe, site.managed)?.as_deref(),
                Some("automatic" | "secure")
            );
        }
    }
    Some(bypass)
}

/// The name Secblitz gives its own lookup setting. Settings that sort after it add servers to its list.
pub const OUR_DROPIN_NAME: &str = "95-secblitz-web-protection.conf";

fn adds_servers(text: &str) -> bool {
    let mut resolve = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            resolve = line.eq_ignore_ascii_case("[Resolve]");
        } else if resolve {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim().eq_ignore_ascii_case("DNS") && !value.trim().is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

fn other_rule(probe: &dyn Probe) -> bool {
    let mut by_name = std::collections::BTreeMap::new();
    for dir in RESOLVED_DIRS {
        for name in probe.names(dir) {
            if name.ends_with(".conf") && name.as_str() > OUR_DROPIN_NAME {
                by_name.insert(name.clone(), format!("{dir}/{name}"));
            }
        }
    }
    by_name
        .values()
        .any(|path| probe.text(path).is_some_and(|t| adds_servers(&t)))
}

pub fn is_vpn_interface(name: &str, operstate: &str) -> bool {
    let name = name.to_ascii_lowercase();
    VPN_PREFIXES.iter().any(|p| name.starts_with(p)) && operstate.trim() != "down"
}

fn vpn_active(probe: &dyn Probe) -> Option<bool> {
    let names = probe.names(NETWORK_CLASS);
    if names.is_empty() {
        return None;
    }
    Some(names.iter().any(|name| {
        let state = probe
            .text(&format!("{NETWORK_CLASS}/{name}/operstate"))
            .unwrap_or_default();
        is_vpn_interface(name, &state)
    }))
}

pub fn gaps(probe: &dyn Probe) -> Option<Vec<Gap>> {
    compute(&Facts {
        browser_bypasses: browser_bypasses(probe),
        other_rule: Some(other_rule(probe)),
        vpn: vpn_active(probe),
    })
}

struct RealProbe;

const READ_CAP: u64 = 256 * 1024;

impl Probe for RealProbe {
    fn text(&self, path: &str) -> Option<String> {
        use std::io::Read;
        let file = std::fs::File::open(path).ok()?;
        let mut bytes = Vec::new();
        file.take(READ_CAP + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > READ_CAP {
            return None;
        }
        String::from_utf8(bytes).ok()
    }

    fn names(&self, dir: &str) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

    fn present(&self, path: &str) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }
}

pub fn check() -> Option<Vec<Gap>> {
    gaps(&RealProbe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Fixture {
        files: BTreeMap<String, String>,
    }

    impl Fixture {
        fn with(mut self, path: &str, text: &str) -> Self {
            self.files.insert(path.into(), text.into());
            self
        }

        /// A computer with one wired connection and no browsers.
        fn quiet() -> Self {
            Fixture::default()
                .with("/sys/class/net/lo/operstate", "unknown\n")
                .with("/sys/class/net/enp1s0/operstate", "up\n")
        }
    }

    impl Probe for Fixture {
        fn text(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn names(&self, dir: &str) -> Vec<String> {
            let prefix = format!("{dir}/");
            let mut names: Vec<String> = self
                .files
                .keys()
                .filter_map(|p| p.strip_prefix(&prefix))
                .map(|rest| rest.split('/').next().unwrap_or("").to_owned())
                .collect();
            names.sort();
            names.dedup();
            names
        }

        fn present(&self, path: &str) -> bool {
            self.files.contains_key(path)
                || self
                    .files
                    .keys()
                    .any(|f| f.starts_with(&format!("{path}/")))
        }
    }

    #[test]
    fn a_quiet_computer_has_no_gaps() {
        assert_eq!(gaps(&Fixture::quiet()), Some(Vec::new()));
    }

    #[test]
    fn a_computer_with_no_network_folder_cannot_be_told() {
        assert_eq!(gaps(&Fixture::default()), None);
    }

    #[test]
    fn firefox_told_to_look_sites_up_itself_is_a_gap() {
        let on = r#"{"policies":{"DNSOverHTTPS":{"Enabled":true,"Fallback":true}}}"#;
        let fixture = Fixture::quiet()
            .with("/usr/bin/firefox", "")
            .with("/etc/firefox/policies/policies.json", on);
        assert_eq!(gaps(&fixture), Some(vec![Gap::BrowserSecureDns]));
        let off = r#"{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}"#;
        let fixture = Fixture::quiet()
            .with("/usr/bin/firefox", "")
            .with("/etc/firefox/policies/policies.json", off);
        assert_eq!(gaps(&fixture), Some(Vec::new()));
    }

    #[test]
    fn firefox_with_no_policy_or_a_policy_about_something_else_is_no_gap() {
        let other = r#"{"policies":{"DisableTelemetry":true}}"#;
        for fixture in [
            Fixture::quiet().with("/usr/bin/firefox", ""),
            Fixture::quiet()
                .with("/usr/bin/firefox", "")
                .with("/etc/firefox/policies/policies.json", other),
        ] {
            assert_eq!(gaps(&fixture), Some(Vec::new()));
        }
    }

    #[test]
    fn firefox_is_found_by_its_program_folder_even_with_no_launcher() {
        let on = r#"{"policies":{"DNSOverHTTPS":{"Enabled":true}}}"#;
        let fixture = Fixture::default()
            .with("/sys/class/net/enp1s0/operstate", "up\n")
            .with("/usr/lib/firefox/distribution/policies.json", on);
        assert_eq!(gaps(&fixture), Some(vec![Gap::BrowserSecureDns]));
        let fixture = Fixture::quiet();
        assert_eq!(gaps(&fixture), Some(Vec::new()));
    }

    #[test]
    fn the_first_firefox_file_that_speaks_of_lookups_decides() {
        let quiet = r#"{"policies":{"DisableTelemetry":true}}"#;
        let on = r#"{"policies":{"DNSOverHTTPS":{"Enabled":true}}}"#;
        let fixture = Fixture::quiet()
            .with("/usr/bin/firefox", "")
            .with("/etc/firefox/policies/policies.json", quiet)
            .with("/usr/lib/firefox/distribution/policies.json", on);
        assert_eq!(gaps(&fixture), Some(vec![Gap::BrowserSecureDns]));
    }

    #[test]
    fn the_policy_secblitz_writes_for_private_lookups_in_browsers_is_a_gap() {
        for (programs, managed) in [
            (
                "/usr/bin/google-chrome-stable",
                "/etc/opt/chrome/policies/managed",
            ),
            ("/usr/bin/chromium", "/etc/chromium/policies/managed"),
            ("/usr/bin/brave-browser", "/etc/brave/policies/managed"),
            (
                "/opt/microsoft/msedge/msedge",
                "/etc/opt/edge/policies/managed",
            ),
        ] {
            let fixture = Fixture::quiet().with(programs, "").with(
                &format!("{managed}/secblitz.json"),
                r#"{"DnsOverHttpsMode":"automatic"}"#,
            );
            assert_eq!(
                gaps(&fixture),
                Some(vec![Gap::BrowserSecureDns]),
                "{managed}"
            );
        }
    }

    #[test]
    fn a_chrome_family_policy_folder_is_read_by_name_and_the_last_file_wins() {
        let managed = "/etc/opt/chrome/policies/managed";
        let fixture = Fixture::quiet()
            .with("/opt/google/chrome/chrome", "")
            .with(
                &format!("{managed}/a.json"),
                r#"{"DnsOverHttpsMode":"secure"}"#,
            )
            .with(
                &format!("{managed}/b.json"),
                r#"{"DnsOverHttpsMode":"off"}"#,
            );
        assert_eq!(gaps(&fixture), Some(Vec::new()));
        let fixture = fixture.with(
            &format!("{managed}/c.json"),
            r#"{"DnsOverHttpsMode":"secure"}"#,
        );
        assert_eq!(gaps(&fixture), Some(vec![Gap::BrowserSecureDns]));
    }

    #[test]
    fn a_policy_folder_counts_as_the_browser_being_there_but_a_stray_file_does_not() {
        let fixture = Fixture::quiet().with(
            "/etc/opt/chrome/policies/managed/secblitz.json",
            r#"{"DnsOverHttpsMode":"secure"}"#,
        );
        assert_eq!(gaps(&fixture), Some(vec![Gap::BrowserSecureDns]));
        let fixture = Fixture::quiet().with(
            "/etc/opt/chrome/other.json",
            r#"{"DnsOverHttpsMode":"secure"}"#,
        );
        assert_eq!(gaps(&fixture), Some(Vec::new()));
    }

    #[test]
    fn a_policy_file_nobody_can_read_leaves_the_answer_open() {
        let fixture = Fixture::quiet()
            .with("/usr/bin/chromium", "")
            .with("/etc/chromium/policies/managed/broken.json", "{not json");
        assert_eq!(gaps(&fixture), None);
        let fixture = fixture.with("/sys/class/net/wg0/operstate", "unknown\n");
        assert_eq!(gaps(&fixture), Some(vec![Gap::Vpn]));
    }

    #[test]
    fn vpn_connections_are_found_by_the_names_programs_give_them() {
        for name in [
            "tun0",
            "wg0",
            "ppp0",
            "tailscale0",
            "nordlynx",
            "proton0",
            "vpn1",
        ] {
            assert!(is_vpn_interface(name, "unknown"), "{name}");
            assert!(is_vpn_interface(name, "up"), "{name}");
            assert!(!is_vpn_interface(name, "down"), "{name} down");
        }
        for name in [
            "lo", "enp1s0", "wlan0", "docker0", "virbr0", "veth1a2b", "tap0", "br-1234",
        ] {
            assert!(!is_vpn_interface(name, "up"), "{name}");
        }
        let fixture = Fixture::quiet().with("/sys/class/net/tun0/operstate", "unknown\n");
        assert_eq!(gaps(&fixture), Some(vec![Gap::Vpn]));
        let fixture = Fixture::quiet().with("/sys/class/net/wg0/operstate", "down\n");
        assert_eq!(gaps(&fixture), Some(Vec::new()));
    }

    #[test]
    fn a_later_setting_that_adds_servers_is_found_but_earlier_ones_are_not() {
        let later = "[Resolve]\nDNS=1.1.1.1\n";
        let fixture = Fixture::quiet().with("/etc/systemd/resolved.conf.d/99-mine.conf", later);
        assert_eq!(gaps(&fixture), Some(vec![Gap::OtherDnsRule]));
        let fixture = Fixture::quiet()
            .with("/etc/systemd/resolved.conf.d/10-mine.conf", later)
            .with(
                "/run/systemd/resolved.conf.d/95-secblitz-web-protection.conf",
                later,
            );
        assert_eq!(gaps(&fixture), Some(Vec::new()));
        let reset = "[Resolve]\nDNS=\n";
        let fixture = Fixture::quiet().with("/usr/lib/systemd/resolved.conf.d/99-x.conf", reset);
        assert_eq!(gaps(&fixture), Some(Vec::new()));
        let elsewhere = "[Network]\nDNS=1.1.1.1\n";
        let fixture = Fixture::quiet().with("/etc/systemd/resolved.conf.d/99-x.conf", elsewhere);
        assert_eq!(gaps(&fixture), Some(Vec::new()));
    }

    #[test]
    fn every_gap_that_is_found_is_listed() {
        let fixture = Fixture::quiet()
            .with("/usr/bin/firefox", "")
            .with(
                "/etc/firefox/policies/policies.json",
                r#"{"policies":{"DNSOverHTTPS":{"Enabled":true}}}"#,
            )
            .with(
                "/etc/systemd/resolved.conf.d/99-x.conf",
                "[Resolve]\nDNS=9.9.9.9\n",
            )
            .with("/sys/class/net/wg0/operstate", "unknown\n");
        assert_eq!(
            gaps(&fixture),
            Some(vec![Gap::BrowserSecureDns, Gap::OtherDnsRule, Gap::Vpn])
        );
    }
}
