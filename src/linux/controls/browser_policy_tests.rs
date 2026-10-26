//! The nine browser policy checks against the files of real installs: each fix is followed by a check and an undo, and
//! the undo must leave every file and folder, including the ones Secblitz made, exactly as it was.

use super::browser_policies::Ctl;
use super::sim::Sim;
use super::{NO_RECORD, UNRECOGNISED};
use crate::engine::assessment;
use crate::linux::backend::LinuxBackend;
use crate::linux::catalog::spec;
use crate::model::{Backend, CheckStatus};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const MEMO: &str = "/var/lib/secblitz/Linux";
const POLICIES: &str = "/etc/firefox/policies/policies.json";
const CHROME_DIR: &str = "/etc/opt/chrome/policies/managed";
const NEW: [Ctl; 8] = [
    Ctl::Tracking,
    Ctl::AdTopics,
    Ctl::Sponsored,
    Ctl::SafeBrowsing,
    Ctl::PasswordLeaks,
    Ctl::Background,
    Ctl::Suggestions,
    Ctl::EncryptedDns,
];

fn backend(sim: &Sim) -> LinuxBackend<Sim> {
    LinuxBackend::new(sim.clone(), MEMO.into())
}

fn computers() -> [(&'static str, Sim); 3] {
    [
        ("ubuntu-26.04", Sim::fixture("ubuntu-26.04")),
        ("fedora-44", Sim::fixture("fedora-44")),
        ("mint-22.3", Sim::fixture("mint-22.3")),
    ]
}

fn value(sim: &Sim, ctl: Ctl) -> Value {
    backend(sim).observe(ctl.id()).unwrap().value
}

fn status(sim: &Sim, ctl: Ctl) -> CheckStatus {
    assessment(ctl.id(), &backend(sim).observe(ctl.id()).unwrap()).unwrap()
}

fn fix(sim: &Sim, ctl: Ctl) {
    let mut b = backend(sim);
    let before = b.observe(ctl.id()).unwrap().value;
    let target = spec(ctl.id()).unwrap().derive_target(&before).unwrap();
    b.write(ctl.id(), &target).unwrap();
}

fn undo(sim: &Sim, ctl: Ctl, before: &Value) {
    backend(sim).write(ctl.id(), before).unwrap();
}

fn json_of(sim: &Sim, path: &str) -> Value {
    serde_json::from_str(&sim.text(path).unwrap()).unwrap()
}

type Snapshot = (BTreeMap<String, String>, BTreeMap<String, String>);

/// Every file and every folder the computer has, for a byte for byte comparison.
fn snapshot(sim: &Sim) -> Snapshot {
    let files = sim
        .files
        .borrow()
        .iter()
        .map(|(p, b)| {
            (
                p.display().to_string(),
                String::from_utf8_lossy(b).into_owned(),
            )
        })
        .collect();
    let dirs = sim
        .kv
        .borrow()
        .iter()
        .filter(|(k, _)| k.starts_with("dir:"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (files, dirs)
}

fn same(a: &Snapshot, b: &Snapshot, what: &str) {
    for (x, y) in [(&a.0, &b.0), (&a.1, &b.1)] {
        for key in x.keys().chain(y.keys()) {
            assert_eq!(x.get(key), y.get(key), "{what}: {key}");
        }
    }
}

fn without_firefox(sim: &Sim) {
    sim.files
        .borrow_mut()
        .retain(|p, _| !p.to_string_lossy().contains("firefox"));
    sim.kv
        .borrow_mut()
        .retain(|k, _| !k.starts_with("dir:/etc/firefox"));
}

fn chrome(sim: &Sim) {
    sim.file("/opt/google/chrome/chrome", "");
}

fn edge(sim: &Sim) {
    sim.file("/opt/microsoft/msedge/msedge", "");
}

#[test]
fn a_fresh_install_of_each_distribution_shows_what_its_firefox_does() {
    for (name, sim) in computers() {
        for (ctl, want) in [
            (
                Ctl::Tracking,
                json!({"items": {"firefox": 1, "chromium": null}}),
            ),
            (Ctl::Sponsored, json!({"items": {"firefox": 1}})),
            (
                Ctl::SafeBrowsing,
                json!({"items": {"firefox": 0, "chromium": null}}),
            ),
            (
                Ctl::Suggestions,
                json!({"items": {"firefox": 1, "chromium": null}}),
            ),
            (
                Ctl::EncryptedDns,
                json!({"items": {"firefox": 1, "chromium": null}}),
            ),
        ] {
            assert_eq!(value(&sim, ctl), want, "{name} {}", ctl.id());
            let expected = if ctl == Ctl::SafeBrowsing {
                CheckStatus::Compliant
            } else {
                CheckStatus::Attention
            };
            assert_eq!(status(&sim, ctl), expected, "{name} {}", ctl.id());
        }
        for ctl in [Ctl::AdTopics, Ctl::PasswordLeaks, Ctl::Background] {
            let o = backend(&sim).observe(ctl.id()).unwrap();
            assert!(!o.eligible, "{name} {}", ctl.id());
            assert_eq!(o.reason, super::browsers::NO_CHROMIUM);
            assert_eq!(o.value, json!({"items": {"chromium": null}}));
        }
    }
}

#[test]
fn only_the_optional_ones_ask_first() {
    for ctl in NEW {
        let asks = matches!(ctl, Ctl::Suggestions | Ctl::EncryptedDns);
        assert_eq!(spec(ctl.id()).unwrap().ask, asks, "{}", ctl.id());
    }
}

#[test]
fn each_check_is_fixed_and_undone_on_every_distribution_with_every_browser_present() {
    for (name, sim) in computers() {
        chrome(&sim);
        edge(&sim);
        sim.file("/usr/bin/brave-browser", "");
        for ctl in NEW {
            let before_files = snapshot(&sim);
            let before = value(&sim, ctl);
            fix(&sim, ctl);
            assert_eq!(
                status(&sim, ctl),
                CheckStatus::Compliant,
                "{name} {}",
                ctl.id()
            );
            undo(&sim, ctl, &before);
            same(
                &snapshot(&sim),
                &before_files,
                &format!("{name} {}", ctl.id()),
            );
            assert_eq!(value(&sim, ctl), before, "{name} {}", ctl.id());
        }
    }
}

#[test]
fn the_firefox_policies_are_written_with_their_documented_names_and_values() {
    let sim = Sim::fixture("ubuntu-26.04");
    for ctl in [
        Ctl::Tracking,
        Ctl::Sponsored,
        Ctl::Suggestions,
        Ctl::EncryptedDns,
    ] {
        fix(&sim, ctl);
    }
    assert_eq!(
        json_of(&sim, POLICIES),
        json!({"policies": {
            "EnableTrackingProtection": {"Value": true, "Cryptomining": true, "Fingerprinting": true},
            "FirefoxHome": {"SponsoredTopSites": false, "SponsoredPocket": false},
            "FirefoxSuggest": {"SponsoredSuggestions": false},
            "SearchSuggestEnabled": false,
            "DNSOverHTTPS": {"Enabled": true, "Fallback": true}
        }})
    );
    assert!(sim.text(POLICIES).unwrap().ends_with("}\n"));
}

#[test]
fn the_chromium_policies_are_written_with_their_documented_names_and_values() {
    let sim = Sim::fixture("fedora-44");
    chrome(&sim);
    for ctl in NEW {
        if ctl.chromium() {
            fix(&sim, ctl);
        }
    }
    assert_eq!(
        json_of(&sim, &format!("{CHROME_DIR}/secblitz.json")),
        json!({
            "BlockThirdPartyCookies": true,
            "PrivacySandboxAdTopicsEnabled": false,
            "PrivacySandboxSiteEnabledAdsEnabled": false,
            "PrivacySandboxAdMeasurementEnabled": false,
            "PrivacySandboxPromptEnabled": false,
            "PasswordLeakDetectionEnabled": true,
            "BackgroundModeEnabled": false,
            "SearchSuggestEnabled": false,
            "DnsOverHttpsMode": "automatic"
        })
    );
}

#[test]
fn the_nine_can_be_undone_in_any_order_and_the_last_undo_leaves_nothing_behind() {
    for reverse in [false, true] {
        for (name, sim) in computers() {
            chrome(&sim);
            let start = snapshot(&sim);
            let mut done = Vec::new();
            for ctl in NEW {
                let before = value(&sim, ctl);
                fix(&sim, ctl);
                done.push((ctl, before));
            }
            if reverse {
                done.reverse();
            }
            let count = done.len();
            for (i, (ctl, before)) in done.into_iter().enumerate() {
                undo(&sim, ctl, &before);
                if i + 1 < count {
                    assert_ne!(snapshot(&sim), start, "{name} {i}");
                }
            }
            same(
                &snapshot(&sim),
                &start,
                &format!("{name} reverse={reverse}"),
            );
        }
    }
}

const ADMIN: &str = "{\r\n\t\"policies\": {\r\n\t\t\"DisableAppUpdate\": true,\r\n\t\t\"FirefoxHome\": {\"Locked\": true, \"SponsoredTopSites\": true, \"Highlights\": false},\r\n\t\t\"DNSOverHTTPS\": {\"Enabled\": false, \"Locked\": true, \"ProviderURL\": \"https://dns.example/query\"},\r\n\t\t\"EnableTrackingProtection\": {\"Value\": true, \"Locked\": true}\r\n\t}\r\n}";

#[test]
fn objects_the_administrator_wrote_are_merged_not_replaced_and_come_back_byte_for_byte() {
    let sim = Sim::fixture("fedora-44");
    sim.file(POLICIES, ADMIN);
    let start = snapshot(&sim);
    let mut done = Vec::new();
    for ctl in [Ctl::Sponsored, Ctl::EncryptedDns, Ctl::Tracking] {
        let before = value(&sim, ctl);
        fix(&sim, ctl);
        done.push((ctl, before));
    }
    let doc = json_of(&sim, POLICIES);
    let p = &doc["policies"];
    assert_eq!(p["DisableAppUpdate"], true);
    assert_eq!(
        p["FirefoxHome"],
        json!({"Locked": true, "SponsoredTopSites": false, "Highlights": false, "SponsoredPocket": false})
    );
    assert_eq!(
        p["DNSOverHTTPS"],
        json!({"Enabled": true, "Locked": true, "ProviderURL": "https://dns.example/query", "Fallback": true})
    );
    assert_eq!(
        p["EnableTrackingProtection"],
        json!({"Value": true, "Locked": true, "Cryptomining": true, "Fingerprinting": true})
    );
    for (ctl, before) in done {
        undo(&sim, ctl, &before);
    }
    assert_eq!(sim.text(POLICIES).unwrap(), ADMIN);
    same(&snapshot(&sim), &start, "start");
}

#[test]
fn a_dangerous_site_warning_that_a_policy_turned_off_is_turned_back_on() {
    let sim = Sim::fixture("mint-22.3");
    chrome(&sim);
    let firefox = r#"{"policies": {"Preferences": {"browser.safebrowsing.malware.enabled": {"Value": false, "Status": "user"}, "general.smoothScroll": {"Value": false, "Status": "default"}}}}"#;
    let chrome_file = format!("{CHROME_DIR}/10-mine.json");
    sim.file(POLICIES, firefox);
    sim.file(&chrome_file, r#"{"SafeBrowsingProtectionLevel": 0}"#);
    let start = snapshot(&sim);
    let before = value(&sim, Ctl::SafeBrowsing);
    assert_eq!(before, json!({"items": {"firefox": 1, "chromium": 1}}));
    assert_eq!(status(&sim, Ctl::SafeBrowsing), CheckStatus::Attention);
    fix(&sim, Ctl::SafeBrowsing);
    assert_eq!(status(&sim, Ctl::SafeBrowsing), CheckStatus::Compliant);
    let prefs = &json_of(&sim, POLICIES)["policies"]["Preferences"];
    assert_eq!(
        prefs["browser.safebrowsing.malware.enabled"],
        json!({"Value": true, "Status": "locked"})
    );
    assert_eq!(
        prefs["browser.safebrowsing.phishing.enabled"],
        json!({"Value": true, "Status": "locked"})
    );
    assert_eq!(prefs["general.smoothScroll"]["Value"], false);
    assert_eq!(
        json_of(&sim, &format!("{CHROME_DIR}/secblitz.json")),
        json!({"SafeBrowsingProtectionLevel": 1})
    );
    assert_eq!(
        sim.text(&chrome_file).unwrap(),
        r#"{"SafeBrowsingProtectionLevel": 0}"#
    );
    undo(&sim, Ctl::SafeBrowsing, &before);
    same(&snapshot(&sim), &start, "start");
}

#[test]
fn the_dangerous_site_warning_counts_as_on_when_absent_or_stronger() {
    let sim = Sim::fixture("ubuntu-26.04");
    chrome(&sim);
    assert_eq!(status(&sim, Ctl::SafeBrowsing), CheckStatus::Compliant);
    sim.file(
        &format!("{CHROME_DIR}/20-strong.json"),
        r#"{"SafeBrowsingProtectionLevel": 2}"#,
    );
    assert_eq!(status(&sim, Ctl::SafeBrowsing), CheckStatus::Compliant);
    let before = snapshot(&sim);
    backend(&sim)
        .write(
            Ctl::SafeBrowsing.id(),
            &json!({"items": {"firefox": 0, "chromium": 0}}),
        )
        .unwrap();
    same(&snapshot(&sim), &before, "before");
}

#[test]
fn settings_other_tools_already_made_are_left_alone() {
    let sim = Sim::fixture("ubuntu-26.04");
    chrome(&sim);
    sim.file(
        &format!("{CHROME_DIR}/10-mine.json"),
        r#"{"BlockThirdPartyCookies": true, "DnsOverHttpsMode": "secure"}"#,
    );
    sim.file(
        POLICIES,
        r#"{"policies": {"DNSOverHTTPS": {"Enabled": true, "Locked": true}, "EnableTrackingProtection": {"Value": true, "Cryptomining": true, "Fingerprinting": true}}}"#,
    );
    for ctl in [Ctl::Tracking, Ctl::EncryptedDns] {
        assert_eq!(status(&sim, ctl), CheckStatus::Compliant, "{}", ctl.id());
        let before = snapshot(&sim);
        backend(&sim)
            .write(ctl.id(), &json!({"items": {"firefox": 0, "chromium": 0}}))
            .unwrap();
        same(&snapshot(&sim), &before, ctl.id());
    }
}

#[test]
fn a_check_shows_only_where_a_browser_that_supports_it_is_installed() {
    let sim = Sim::fixture("ubuntu-26.04");
    let o = backend(&sim).observe(Ctl::PasswordLeaks.id()).unwrap();
    assert_eq!(o.reason, super::browsers::NO_CHROMIUM);
    chrome(&sim);
    assert!(
        backend(&sim)
            .observe(Ctl::PasswordLeaks.id())
            .unwrap()
            .eligible
    );
    without_firefox(&sim);
    let o = backend(&sim).observe(Ctl::Sponsored.id()).unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, super::browsers::NO_FIREFOX);
    let o = backend(&sim).observe(Ctl::Tracking.id()).unwrap();
    assert!(o.eligible);
    assert_eq!(o.value, json!({"items": {"firefox": null, "chromium": 1}}));
    let sim = Sim::fixture("ubuntu-26.04");
    without_firefox(&sim);
    let o = backend(&sim).observe(Ctl::Tracking.id()).unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, super::browsers::NO_BROWSER);
}

#[test]
fn edge_gets_the_settings_it_understands_in_its_own_folder() {
    let sim = Sim::fixture("fedora-44");
    without_firefox(&sim);
    edge(&sim);
    for ctl in [Ctl::Data, Ctl::SafeBrowsing, Ctl::PasswordLeaks] {
        let o = backend(&sim).observe(ctl.id()).unwrap();
        assert!(!o.eligible, "{}", ctl.id());
        let reason = if ctl == Ctl::PasswordLeaks {
            super::browsers::NO_CHROMIUM
        } else {
            super::browsers::NO_BROWSER
        };
        assert_eq!(o.reason, reason);
    }
    let start = snapshot(&sim);
    let before = value(&sim, Ctl::Background);
    assert_eq!(before, json!({"items": {"chromium": 1}}));
    fix(&sim, Ctl::Background);
    assert_eq!(
        json_of(&sim, "/etc/opt/edge/policies/managed/secblitz.json"),
        json!({"BackgroundModeEnabled": false})
    );
    assert_eq!(status(&sim, Ctl::Background), CheckStatus::Compliant);
    undo(&sim, Ctl::Background, &before);
    same(&snapshot(&sim), &start, "start");
    assert!(!sim.has("/etc/opt/edge/policies/managed/secblitz.json"));
}

#[test]
fn the_folders_fedora_already_has_are_kept_and_the_ones_we_made_are_removed() {
    let sim = Sim::fixture("fedora-44");
    sim.file("/usr/bin/chromium-browser", "");
    assert!(!sim.get("dir:/etc/chromium").is_empty());
    let before = value(&sim, Ctl::Background);
    fix(&sim, Ctl::Background);
    assert!(sim.has("/etc/chromium-browser/policies/managed/secblitz.json"));
    assert!(!sim.get("dir:/etc/chromium-browser/policies").is_empty());
    undo(&sim, Ctl::Background, &before);
    assert!(sim.get("dir:/etc/chromium-browser").is_empty());
    assert!(!sim.get("dir:/etc/chromium").is_empty());
}

#[test]
fn a_file_of_ours_that_someone_else_edited_into_nonsense_is_never_overwritten() {
    let sim = Sim::fixture("ubuntu-26.04");
    chrome(&sim);
    let path = format!("{CHROME_DIR}/secblitz.json");
    for bad in ["not json", "[1]", ""] {
        sim.file(&path, bad);
        let err = backend(&sim)
            .write(Ctl::Background.id(), &json!({"items": {"chromium": 0}}))
            .unwrap_err();
        assert_eq!(err.to_string(), UNRECOGNISED, "{bad:?}");
        assert_eq!(sim.text(&path).unwrap(), bad);
        backend(&sim)
            .write(Ctl::Background.id(), &json!({"items": {"chromium": 1}}))
            .unwrap();
        assert_eq!(sim.text(&path).unwrap(), bad);
    }
}

#[test]
fn a_firefox_policy_file_that_is_not_understood_is_never_touched() {
    let sim = Sim::fixture("mint-22.3");
    for bad in ["not json", "[1, 2]", r#"{"policies": 3}"#] {
        sim.file(POLICIES, bad);
        for ctl in [Ctl::Tracking, Ctl::Sponsored, Ctl::EncryptedDns] {
            let o = backend(&sim).observe(ctl.id()).unwrap();
            assert!(!o.eligible, "{bad:?}");
            assert_eq!(o.reason, UNRECOGNISED);
            assert!(backend(&sim)
                .write(
                    ctl.id(),
                    &json!({"items": {"firefox": 0, "chromium": null}})
                )
                .is_err());
            assert_eq!(sim.text(POLICIES).unwrap(), bad);
        }
    }
}

#[test]
fn an_undo_without_a_record_changes_nothing() {
    let sim = Sim::fixture("fedora-44");
    sim.file(POLICIES, ADMIN);
    let before = snapshot(&sim);
    for ctl in [Ctl::Tracking, Ctl::Sponsored, Ctl::EncryptedDns] {
        let undo_all = json!({"items": {"firefox": 1, "chromium": null}});
        let want = if ctl == Ctl::Sponsored {
            json!({"items": {"firefox": 1}})
        } else {
            undo_all
        };
        let err = backend(&sim).write(ctl.id(), &want).unwrap_err();
        assert_eq!(err.to_string(), NO_RECORD, "{}", ctl.id());
        same(&snapshot(&sim), &before, "before");
    }
}

#[test]
fn a_value_that_is_not_a_flag_is_refused() {
    let sim = Sim::fixture("ubuntu-26.04");
    let mut b = backend(&sim);
    assert!(b
        .write(Ctl::Sponsored.id(), &json!({"items": {"firefox": 2}}))
        .is_err());
    assert!(b
        .write(Ctl::Sponsored.id(), &json!({"items": {"firefox": "yes"}}))
        .is_err());
    assert!(!sim.has(POLICIES));
}
