//! Ways a site can still get around Web protection, found by reading the PC
//! only. Nothing here changes a setting.

use serde::{Deserialize, Serialize};

use super::adapters::AdapterInfo;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gap {
    BrowserSecureDns,
    OtherDnsRule,
    Vpn,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Firefox,
}

impl Browser {
    pub const ALL: [Browser; 4] = [
        Browser::Chrome,
        Browser::Edge,
        Browser::Brave,
        Browser::Firefox,
    ];

    /// The file name Windows lists the browser under in App Paths.
    pub fn app_path_name(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome.exe",
            Browser::Edge => "msedge.exe",
            Browser::Brave => "brave.exe",
            Browser::Firefox => "firefox.exe",
        }
    }
}

/// What a browser's lookup policy holds. `mode` is the text of
/// `DnsOverHttpsMode` for Chrome, Edge and Brave; `enabled` and `locked` are
/// the Firefox numbers.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct BrowserPolicy {
    pub mode: Option<String>,
    pub enabled: Option<u32>,
    pub locked: Option<u32>,
}

/// Whether the browser is told to use the PC's own lookups, the same values
/// the `browser.dns_bypass` fix writes.
pub fn browser_uses_pc_lookups(browser: Browser, policy: &BrowserPolicy) -> bool {
    match browser {
        Browser::Firefox => policy.enabled == Some(0) && policy.locked == Some(1),
        _ => policy.mode.as_deref() == Some("off"),
    }
}

/// A rule for every name (`.`) or with no name, which would compete with ours.
pub fn rule_covers_everything(namespaces: &[String]) -> bool {
    namespaces.iter().any(|n| matches!(n.trim(), "" | "."))
}

const VPN_DRIVERS: &[&str] = &[
    "wireguard",
    "wintun",
    "openvpn",
    "tap-windows",
    "nordlynx",
    "anyconnect",
    "cisco secure client",
    "fortinet",
    "globalprotect",
    "pangp",
    "protonvpn",
    "mullvad",
    "expressvpn",
    "surfshark",
    "windscribe",
    "pritunl",
    "softether",
    "vpn client",
    "virtual private network",
];

const NOT_VPN: &[&str] = &["teredo", "6to4", "isatap", "ip-https"];

const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_TUNNEL: u32 = 131;

/// An adapter that is up, has a DNS server of its own and looks like a VPN by
/// its type or by the name of its driver.
pub fn is_vpn_adapter(adapter: &AdapterInfo) -> bool {
    if !adapter.has_dns {
        return false;
    }
    let name = adapter.name.to_ascii_lowercase();
    if NOT_VPN.iter().any(|n| name.contains(n)) {
        return false;
    }
    matches!(adapter.if_type, IF_TYPE_PPP | IF_TYPE_TUNNEL)
        || VPN_DRIVERS.iter().any(|d| name.contains(d))
}

/// What was found on the PC. A check that could not run is `None`.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct Facts {
    pub browser_bypasses: Option<bool>,
    pub other_rule: Option<bool>,
    pub vpn: Option<bool>,
}

/// Every gap that was found, even when another check could not run. `None`
/// when nothing was found and some check could not run: the app then claims
/// neither that everything is covered nor that something is missing.
pub fn compute(facts: &Facts) -> Option<Vec<Gap>> {
    let mut gaps = Vec::new();
    if facts.browser_bypasses == Some(true) {
        gaps.push(Gap::BrowserSecureDns);
    }
    if facts.other_rule == Some(true) {
        gaps.push(Gap::OtherDnsRule);
    }
    if facts.vpn == Some(true) {
        gaps.push(Gap::Vpn);
    }
    let unknown = [facts.browser_bypasses, facts.other_rule, facts.vpn]
        .iter()
        .any(Option::is_none);
    (!gaps.is_empty() || !unknown).then_some(gaps)
}

/// Where a browser installs for one user only, under that user's profile
/// folder. Those installs leave nothing in App Paths for a signed-out user.
pub fn per_user_install_path(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => r"AppData\Local\Google\Chrome\Application\chrome.exe",
        Browser::Edge => r"AppData\Local\Microsoft\Edge\Application\msedge.exe",
        Browser::Brave => r"AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe",
        Browser::Firefox => r"AppData\Local\Mozilla Firefox\firefox.exe",
    }
}

pub fn vpn_active(adapters: &[AdapterInfo]) -> bool {
    adapters.iter().any(is_vpn_adapter)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::filter::adapters;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
        HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, RRF_RT_REG_DWORD,
        RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
    };

    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const OUR_RULE: &str = "{0EE85A24-B573-4712-97FF-CC4BC51D8757}";
    const APP_PATHS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
    const LOCAL_RULES: &str =
        r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    const GROUP_RULES: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
    const MAX_SUBKEYS: u32 = 512;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by `open` and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    enum Opened {
        Key(Key),
        Missing,
        Failed,
    }

    fn open(root: HKEY, path: &str, view: u32) -> Opened {
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and `key` is a valid out pointer.
        let status =
            unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, KEY_READ | view, &mut key) };
        match status {
            0 => Opened::Key(Key(key)),
            ERROR_FILE_NOT_FOUND => Opened::Missing,
            _ => Opened::Failed,
        }
    }

    fn subkeys(key: &Key) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for index in 0..MAX_SUBKEYS {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            // SAFETY: `name` and `len` describe the same buffer.
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            match status {
                0 => out.push(String::from_utf16_lossy(&name[..len as usize])),
                ERROR_NO_MORE_ITEMS => return Some(out),
                _ => return None,
            }
        }
        None
    }

    enum Value {
        Found(Vec<u16>),
        Missing,
        Failed,
    }

    fn value(key: &Key, name: &str, flags: u32) -> Value {
        let mut buf = vec![0u16; 2048];
        for _ in 0..4 {
            let mut bytes = (buf.len() * 2) as u32;
            // SAFETY: `buf` and `bytes` describe the same buffer.
            let status = unsafe {
                RegGetValueW(
                    key.0,
                    std::ptr::null(),
                    wide(name).as_ptr(),
                    flags,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut bytes,
                )
            };
            match status {
                0 => {
                    buf.truncate(bytes as usize / 2);
                    return Value::Found(buf);
                }
                ERROR_FILE_NOT_FOUND => return Value::Missing,
                ERROR_MORE_DATA => buf.resize(bytes as usize / 2 + 1, 0),
                _ => return Value::Failed,
            }
        }
        Value::Failed
    }

    fn raw_value(key: &Key, name: &str, flags: u32) -> Option<Vec<u16>> {
        match value(key, name, flags) {
            Value::Found(buf) => Some(buf),
            _ => None,
        }
    }

    fn read_text(key: &Key, name: &str) -> Option<String> {
        let buf = raw_value(key, name, RRF_RT_REG_SZ)?;
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    fn read_number(key: &Key, name: &str) -> Option<u32> {
        let buf = raw_value(key, name, RRF_RT_REG_DWORD)?;
        (buf.len() >= 2).then(|| u32::from(buf[0]) | (u32::from(buf[1]) << 16))
    }

    /// A missing value is an empty list; a value that exists but cannot be
    /// read is `None`.
    fn read_list(key: &Key, name: &str) -> Option<Vec<String>> {
        let buf = match value(key, name, RRF_RT_REG_MULTI_SZ) {
            Value::Found(buf) => buf,
            Value::Missing => return Some(Vec::new()),
            Value::Failed => return None,
        };
        Some(
            buf.split(|c| *c == 0)
                .filter(|p| !p.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
        )
    }

    fn installed(browser: Browser) -> Option<bool> {
        let path = format!(r"{APP_PATHS}\{}", browser.app_path_name());
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            match open(HKEY_LOCAL_MACHINE, &path, view) {
                Opened::Key(_) => return Some(true),
                Opened::Missing => {}
                Opened::Failed => return None,
            }
        }
        // Per-user installs only show in the profiles that are signed in.
        let Opened::Key(users) = open(HKEY_USERS, "", 0) else {
            return None;
        };
        for sid in subkeys(&users)? {
            if sid.ends_with("_Classes") {
                continue;
            }
            if let Opened::Key(_) = open(HKEY_USERS, &format!(r"{sid}\{path}"), 0) {
                return Some(true);
            }
        }
        // Profiles that are not signed in have no loaded registry, so look
        // for the browser's own folder in each of them.
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let profiles = std::fs::read_dir(format!(r"{drive}\Users")).ok()?;
        for profile in profiles {
            let profile = profile.ok()?.path();
            if profile.join(per_user_install_path(browser)).is_file() {
                return Some(true);
            }
        }
        Some(false)
    }

    fn policy(browser: Browser) -> Option<BrowserPolicy> {
        let path = match browser {
            Browser::Chrome => r"SOFTWARE\Policies\Google\Chrome",
            Browser::Edge => r"SOFTWARE\Policies\Microsoft\Edge",
            Browser::Brave => r"SOFTWARE\Policies\BraveSoftware\Brave",
            Browser::Firefox => r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
        };
        match open(HKEY_LOCAL_MACHINE, path, KEY_WOW64_64KEY) {
            Opened::Missing => Some(BrowserPolicy::default()),
            Opened::Failed => None,
            Opened::Key(key) => Some(if browser == Browser::Firefox {
                BrowserPolicy {
                    enabled: read_number(&key, "Enabled"),
                    locked: read_number(&key, "Locked"),
                    ..BrowserPolicy::default()
                }
            } else {
                BrowserPolicy {
                    mode: read_text(&key, "DnsOverHttpsMode"),
                    ..BrowserPolicy::default()
                }
            }),
        }
    }

    fn browser_bypasses() -> Option<bool> {
        let mut bypass = false;
        for browser in Browser::ALL {
            if installed(browser)? && !browser_uses_pc_lookups(browser, &policy(browser)?) {
                bypass = true;
            }
        }
        Some(bypass)
    }

    /// Only a rule for every name counts. Narrower rules, such as a company's
    /// own domain, win for those names only and are normal on work PCs.
    fn other_rule() -> Option<bool> {
        for path in [LOCAL_RULES, GROUP_RULES] {
            let key = match open(HKEY_LOCAL_MACHINE, path, KEY_WOW64_64KEY) {
                Opened::Key(key) => key,
                Opened::Missing => continue,
                Opened::Failed => return None,
            };
            for name in subkeys(&key)? {
                if name.eq_ignore_ascii_case(OUR_RULE) {
                    continue;
                }
                let Opened::Key(rule) = open(
                    HKEY_LOCAL_MACHINE,
                    &format!(r"{path}\{name}"),
                    KEY_WOW64_64KEY,
                ) else {
                    return None;
                };
                if rule_covers_everything(&read_list(&rule, "Name")?) {
                    return Some(true);
                }
            }
        }
        Some(false)
    }

    pub fn check() -> Option<Vec<Gap>> {
        compute(&Facts {
            browser_bypasses: browser_bypasses(),
            other_rule: other_rule(),
            vpn: adapters::active_adapters().map(|a| vpn_active(&a)),
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn check() -> Option<Vec<Gap>> {
        #[cfg(target_os = "linux")]
        {
            crate::linux::web_gaps::check()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// Reads the PC for ways around Web protection. `None` when it cannot tell.
pub fn check() -> Option<Vec<Gap>> {
    imp::check()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(if_type: u32, name: &str, has_dns: bool) -> AdapterInfo {
        AdapterInfo {
            if_type,
            name: name.into(),
            has_dns,
        }
    }

    fn policy(mode: Option<&str>, enabled: Option<u32>, locked: Option<u32>) -> BrowserPolicy {
        BrowserPolicy {
            mode: mode.map(String::from),
            enabled,
            locked,
        }
    }

    #[test]
    fn chromium_browsers_need_the_mode_off() {
        for b in [Browser::Chrome, Browser::Edge, Browser::Brave] {
            assert!(browser_uses_pc_lookups(b, &policy(Some("off"), None, None)));
            assert!(!browser_uses_pc_lookups(b, &policy(None, None, None)));
            assert!(!browser_uses_pc_lookups(
                b,
                &policy(Some("secure"), None, None)
            ));
            assert!(!browser_uses_pc_lookups(
                b,
                &policy(Some("automatic"), None, None)
            ));
        }
    }

    #[test]
    fn firefox_needs_disabled_and_locked() {
        let f = Browser::Firefox;
        assert!(browser_uses_pc_lookups(f, &policy(None, Some(0), Some(1))));
        assert!(!browser_uses_pc_lookups(f, &policy(None, Some(0), None)));
        assert!(!browser_uses_pc_lookups(f, &policy(None, Some(0), Some(0))));
        assert!(!browser_uses_pc_lookups(f, &policy(None, Some(1), Some(1))));
        assert!(!browser_uses_pc_lookups(f, &BrowserPolicy::default()));
    }

    #[test]
    fn only_rules_for_every_name_compete_with_ours() {
        let names = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(rule_covers_everything(&names(&["."])));
        assert!(rule_covers_everything(&names(&[".corp.example", "."])));
        assert!(rule_covers_everything(&names(&[""])));
        assert!(!rule_covers_everything(&names(&[
            ".corp.example",
            "intranet"
        ])));
        assert!(!rule_covers_everything(&[]));
    }

    #[test]
    fn vpns_are_found_by_type_or_driver_but_only_with_their_own_dns() {
        assert!(is_vpn_adapter(&adapter(23, "WAN Miniport (PPP)", true)));
        assert!(is_vpn_adapter(&adapter(6, "WireGuard Tunnel", true)));
        assert!(is_vpn_adapter(&adapter(
            6,
            "TAP-Windows Adapter V9 OpenVPN",
            true
        )));
        assert!(is_vpn_adapter(&adapter(
            53,
            "Cisco AnyConnect Secure Mobility",
            true
        )));
        assert!(!is_vpn_adapter(&adapter(6, "WireGuard Tunnel", false)));
        assert!(!is_vpn_adapter(&adapter(
            6,
            "Intel Ethernet Connection",
            true
        )));
        assert!(!is_vpn_adapter(&adapter(71, "Wi-Fi", true)));
        assert!(!is_vpn_adapter(&adapter(
            131,
            "Teredo Tunneling Pseudo-Interface",
            true
        )));
        assert!(!is_vpn_adapter(&adapter(
            131,
            "Microsoft IP-HTTPS Platform Adapter",
            true
        )));
    }

    #[test]
    fn gaps_come_out_in_a_fixed_order() {
        let all = Facts {
            browser_bypasses: Some(true),
            other_rule: Some(true),
            vpn: Some(true),
        };
        assert_eq!(
            compute(&all),
            Some(vec![Gap::BrowserSecureDns, Gap::OtherDnsRule, Gap::Vpn])
        );
        let none = Facts {
            browser_bypasses: Some(false),
            other_rule: Some(false),
            vpn: Some(false),
        };
        assert_eq!(compute(&none), Some(Vec::new()));
    }

    #[test]
    fn a_check_that_failed_means_no_answer_unless_a_gap_was_found() {
        let ok = Facts {
            browser_bypasses: Some(false),
            other_rule: Some(false),
            vpn: Some(false),
        };
        for broken in [
            Facts {
                browser_bypasses: None,
                ..ok.clone()
            },
            Facts {
                other_rule: None,
                ..ok.clone()
            },
            Facts {
                vpn: None,
                ..ok.clone()
            },
        ] {
            assert_eq!(compute(&broken), None);
        }
        let found_one = Facts {
            vpn: Some(true),
            other_rule: None,
            ..ok.clone()
        };
        assert_eq!(compute(&found_one), Some(vec![Gap::Vpn]));
        let browser_and_broken_vpn = Facts {
            browser_bypasses: Some(true),
            vpn: None,
            ..ok
        };
        assert_eq!(
            compute(&browser_and_broken_vpn),
            Some(vec![Gap::BrowserSecureDns])
        );
    }

    #[test]
    fn per_user_installs_live_under_the_profile() {
        for b in Browser::ALL {
            let p = per_user_install_path(b);
            assert!(p.starts_with(r"AppData\Local\"));
            assert!(p.ends_with(b.app_path_name()));
        }
    }
}
