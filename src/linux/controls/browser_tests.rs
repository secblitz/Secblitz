//! The browser privacy controls against the files of real installs: each fix is followed by a check and an undo, and the
//! undo must leave every file and folder exactly as it was.

use super::sim::Sim;
use super::{NO_RECORD, UNRECOGNISED};
use crate::engine::assessment;
use crate::linux::backend::LinuxBackend;
use crate::linux::catalog::spec;
use crate::model::{Backend, CheckStatus};
use serde_json::{json, Value};

const MEMO: &str = "/var/lib/secblitz/Linux";
const DATA: &str = "linux.browser_data_collection";
const HTTPS: &str = "linux.browser_https_only";
const POLICIES: &str = "/etc/firefox/policies/policies.json";
const CHROME_FILE: &str = "/etc/opt/chrome/policies/managed/secblitz.json";

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

fn value(sim: &Sim, id: &str) -> Value {
    backend(sim).observe(id).unwrap().value
}

fn status(sim: &Sim, id: &str) -> CheckStatus {
    assessment(id, &backend(sim).observe(id).unwrap()).unwrap()
}

fn fix(sim: &Sim, id: &str) {
    let mut b = backend(sim);
    let before = b.observe(id).unwrap().value;
    let target = spec(id).unwrap().derive_target(&before).unwrap();
    b.write(id, &target).unwrap();
}

fn undo(sim: &Sim, id: &str, before: &Value) {
    backend(sim).write(id, before).unwrap();
}

fn made(sim: &Sim, folder: &str) -> bool {
    !sim.get(&format!("dir:{folder}")).is_empty()
}

fn chrome(sim: &Sim) {
    sim.file("/opt/google/chrome/chrome", "");
}

fn json_of(sim: &Sim, path: &str) -> Value {
    serde_json::from_str(&sim.text(path).unwrap()).unwrap()
}

#[test]
fn a_fresh_install_of_each_distribution_shares_usage_data() {
    for (name, sim) in computers() {
        assert_eq!(
            value(&sim, DATA),
            json!({"items": {"firefox": 1, "chromium": null}}),
            "{name}"
        );
        assert_eq!(status(&sim, DATA), CheckStatus::Attention, "{name}");
        assert_eq!(
            value(&sim, HTTPS),
            json!({"items": {"firefox": 1}}),
            "{name}"
        );
        assert_eq!(status(&sim, HTTPS), CheckStatus::Attention, "{name}");
    }
}

#[test]
fn data_sharing_is_switched_off_with_a_new_file_and_undo_takes_everything_away() {
    for (name, sim) in computers() {
        let had_folder = made(&sim, "/etc/firefox");
        let before = value(&sim, DATA);
        fix(&sim, DATA);
        let text = sim.text(POLICIES).unwrap();
        assert_eq!(
            json_of(&sim, POLICIES),
            json!({"policies": {"DisableTelemetry": true, "DisableFirefoxStudies": true}}),
            "{name}"
        );
        assert!(text.ends_with("}\n"), "{name}");
        assert_eq!(
            value(&sim, DATA),
            json!({"items": {"firefox": 0, "chromium": null}}),
            "{name}"
        );
        assert_eq!(status(&sim, DATA), CheckStatus::Compliant, "{name}");
        assert!(made(&sim, "/etc/firefox/policies"), "{name}");
        undo(&sim, DATA, &before);
        assert!(!sim.has(POLICIES), "{name}");
        assert_eq!(made(&sim, "/etc/firefox"), had_folder, "{name}");
        assert!(!made(&sim, "/etc/firefox/policies"), "{name}");
        assert_eq!(value(&sim, DATA), before, "{name}");
    }
}

#[test]
fn secure_connections_only_is_set_and_undone_on_each_distribution() {
    for (name, sim) in computers() {
        let had_folder = made(&sim, "/etc/firefox");
        let before = value(&sim, HTTPS);
        fix(&sim, HTTPS);
        assert_eq!(
            json_of(&sim, POLICIES),
            json!({"policies": {"HttpsOnlyMode": "enabled"}}),
            "{name}"
        );
        assert_eq!(status(&sim, HTTPS), CheckStatus::Compliant, "{name}");
        undo(&sim, HTTPS, &before);
        assert!(!sim.has(POLICIES), "{name}");
        assert_eq!(made(&sim, "/etc/firefox"), had_folder, "{name}");
        assert_eq!(value(&sim, HTTPS), before, "{name}");
    }
}

const ADMIN: &str = "{\r\n\t\"policies\": {\r\n\t\t\"DisableAppUpdate\": true,\r\n\t\t\"DisableTelemetry\": false\r\n\t}\r\n}";

#[test]
fn an_existing_policy_file_keeps_its_other_settings_and_comes_back_byte_for_byte() {
    let sim = Sim::fixture("fedora-44");
    sim.file(POLICIES, ADMIN);
    let before = value(&sim, DATA);
    fix(&sim, DATA);
    assert_eq!(
        json_of(&sim, POLICIES),
        json!({"policies": {
            "DisableAppUpdate": true, "DisableTelemetry": true, "DisableFirefoxStudies": true
        }})
    );
    undo(&sim, DATA, &before);
    assert_eq!(sim.text(POLICIES).unwrap(), ADMIN);
    assert!(!sim.ran("/usr/bin/mkdir -m 0755 /etc/firefox"));
    assert!(!sim.ran("/usr/bin/rmdir /etc/firefox/policies"));
}

#[test]
fn the_two_firefox_settings_can_be_undone_in_any_order() {
    for first_undone in [DATA, HTTPS] {
        let sim = Sim::fixture("ubuntu-26.04");
        sim.file(POLICIES, ADMIN);
        let (data, https) = (value(&sim, DATA), value(&sim, HTTPS));
        fix(&sim, DATA);
        fix(&sim, HTTPS);
        let doc = json_of(&sim, POLICIES);
        assert_eq!(doc["policies"]["HttpsOnlyMode"], "enabled");
        assert_eq!(doc["policies"]["DisableTelemetry"], true);
        let second = if first_undone == DATA { HTTPS } else { DATA };
        let before = |id| if id == DATA { &data } else { &https };
        undo(&sim, first_undone, before(first_undone));
        let left = json_of(&sim, POLICIES);
        assert_eq!(left["policies"]["DisableAppUpdate"], true);
        assert_eq!(
            left["policies"].get("HttpsOnlyMode").is_some(),
            first_undone == DATA
        );
        assert_ne!(sim.text(POLICIES).unwrap(), ADMIN);
        undo(&sim, second, before(second));
        assert_eq!(sim.text(POLICIES).unwrap(), ADMIN, "{first_undone}");
        assert!(!sim.has("/var/lib/secblitz/Linux/browser_firefox_origin.bin"));
    }
}

#[test]
fn settings_the_administrator_already_made_are_left_alone() {
    let sim = Sim::fixture("mint-22.3");
    let both = r#"{"policies": {"DisableTelemetry": true, "DisableFirefoxStudies": true, "HttpsOnlyMode": "force_enabled"}}"#;
    sim.file(POLICIES, both);
    assert_eq!(status(&sim, DATA), CheckStatus::Compliant);
    assert_eq!(status(&sim, HTTPS), CheckStatus::Compliant);
    backend(&sim)
        .write(DATA, &json!({"items": {"firefox": 0, "chromium": null}}))
        .unwrap();
    assert_eq!(sim.text(POLICIES).unwrap(), both);
    assert!(!sim.has("/var/lib/secblitz/Linux/browser_firefox_data.txt"));
}

#[test]
fn a_policy_file_that_is_not_understood_is_never_touched() {
    let sim = Sim::fixture("ubuntu-26.04");
    for bad in ["not json", "[1, 2]", r#"{"policies": 3}"#, ""] {
        sim.file(POLICIES, bad);
        for (id, fixed) in [
            (DATA, json!({"items": {"firefox": 0, "chromium": null}})),
            (HTTPS, json!({"items": {"firefox": 0}})),
        ] {
            let o = backend(&sim).observe(id).unwrap();
            assert!(!o.eligible, "{bad:?}");
            assert_eq!(o.reason, UNRECOGNISED);
            assert!(backend(&sim).write(id, &fixed).is_err(), "{bad:?}");
            assert_eq!(sim.text(POLICIES).unwrap(), bad);
        }
    }
}

#[test]
fn an_undo_without_a_record_changes_nothing() {
    let sim = Sim::fixture("fedora-44");
    sim.file(POLICIES, ADMIN);
    let err = backend(&sim)
        .write(DATA, &json!({"items": {"firefox": 1, "chromium": null}}))
        .unwrap_err();
    assert_eq!(err.to_string(), NO_RECORD);
    assert_eq!(sim.text(POLICIES).unwrap(), ADMIN);
}

#[test]
fn no_browser_means_the_checks_are_not_offered() {
    let sim = Sim::fixture("ubuntu-26.04");
    sim.files
        .borrow_mut()
        .remove(std::path::Path::new("/snap/bin/firefox"));
    let mut b = backend(&sim);
    let o = b.observe(DATA).unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, super::browsers::NO_BROWSER);
    assert_eq!(
        o.value,
        json!({"items": {"firefox": null, "chromium": null}})
    );
    let o = b.observe(HTTPS).unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, super::browsers::NO_FIREFOX);
    assert_eq!(status(&sim, DATA), CheckStatus::Compliant);
}

#[test]
fn chrome_data_sharing_is_switched_off_with_a_file_of_our_own_and_undone() {
    let sim = Sim::fixture("ubuntu-26.04");
    chrome(&sim);
    let before = value(&sim, DATA);
    assert_eq!(before, json!({"items": {"firefox": 1, "chromium": 1}}));
    fix(&sim, DATA);
    assert_eq!(
        json_of(&sim, CHROME_FILE),
        json!({"MetricsReportingEnabled": false, "UrlKeyedAnonymizedDataCollectionEnabled": false})
    );
    assert_eq!(
        value(&sim, DATA),
        json!({"items": {"firefox": 0, "chromium": 0}})
    );
    assert!(sim.has(POLICIES));
    undo(&sim, DATA, &before);
    assert!(!sim.has(CHROME_FILE));
    assert!(!sim.has(POLICIES));
    assert!(!made(&sim, "/etc/opt/chrome"));
    assert!(!made(&sim, "/etc/opt/chrome/policies/managed"));
    assert_eq!(value(&sim, DATA), before);
}

#[test]
fn the_chromium_family_is_found_by_its_policy_folder_or_its_program() {
    let sim = Sim::fixture("fedora-44");
    assert_eq!(
        value(&sim, DATA)["items"]["chromium"],
        serde_json::Value::Null
    );
    sim.set("dir:/etc/chromium/policies", "1");
    sim.file("/usr/bin/brave-browser", "");
    sim.file("/usr/bin/chromium-browser", "");
    let before = value(&sim, DATA);
    assert_eq!(before["items"]["chromium"], 1);
    fix(&sim, DATA);
    for folder in ["chromium", "brave", "chromium-browser"] {
        assert!(
            sim.has(&format!("/etc/{folder}/policies/managed/secblitz.json")),
            "{folder}"
        );
    }
    assert!(!sim.has(CHROME_FILE));
    undo(&sim, DATA, &before);
    for folder in ["chromium", "brave", "chromium-browser"] {
        assert!(!sim.has(&format!("/etc/{folder}/policies/managed/secblitz.json")));
    }
    assert!(made(&sim, "/etc/chromium/policies"));
    assert!(!made(&sim, "/etc/chromium/policies/managed"));
    assert!(!made(&sim, "/etc/brave"));
    assert!(!made(&sim, "/etc/brave/policies"));
}

#[test]
fn files_of_the_administrator_in_a_chromium_folder_stay_and_can_make_it_safe() {
    let sim = Sim::fixture("mint-22.3");
    chrome(&sim);
    let mine = "/etc/opt/chrome/policies/managed/10-mine.json";
    sim.file(
        mine,
        r#"{"MetricsReportingEnabled": false, "HomepageLocation": "https://example.org"}"#,
    );
    let before = value(&sim, DATA);
    assert_eq!(before["items"]["chromium"], 1);
    fix(&sim, DATA);
    assert!(sim.has(CHROME_FILE));
    undo(&sim, DATA, &before);
    assert!(sim.has(mine));
    assert!(!sim.has(CHROME_FILE));

    sim.file(
        mine,
        r#"{"MetricsReportingEnabled": false, "UrlKeyedAnonymizedDataCollectionEnabled": false}"#,
    );
    assert_eq!(value(&sim, DATA)["items"]["chromium"], 0);
    fix(&sim, DATA);
    assert!(!sim.has(CHROME_FILE));
}

#[test]
fn a_later_file_that_turns_sharing_back_on_wins_the_way_the_browser_reads_it() {
    let sim = Sim::fixture("ubuntu-26.04");
    chrome(&sim);
    sim.file(
        "/etc/opt/chrome/policies/managed/zz.json",
        r#"{"MetricsReportingEnabled": true}"#,
    );
    fix(&sim, DATA);
    assert_eq!(value(&sim, DATA)["items"]["chromium"], 1);
}

#[test]
fn a_value_that_is_not_a_flag_is_refused() {
    let sim = Sim::fixture("ubuntu-26.04");
    let mut b = backend(&sim);
    assert!(b.write(HTTPS, &json!({"items": {"firefox": 2}})).is_err());
    assert!(b
        .write(HTTPS, &json!({"items": {"firefox": "yes"}}))
        .is_err());
    assert!(!sim.has(POLICIES));
}
