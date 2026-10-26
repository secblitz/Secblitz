//! The clock, printing, Ubuntu news and snap update controls against the output recorded on real Ubuntu 26.04, Fedora 44
//! and Linux Mint 22.3 installs.

use super::*;
use crate::linux::controls::services as svc;
use std::path::Path;

const DISTROS: [&str; 3] = ["ubuntu-26.04", "fedora-44", "mint-22.3"];
const BROWSED_CONF: &str = "/etc/cups/cups-browsed.conf";
const BROWSED_MEMO: &str = "/var/lib/secblitz/Linux/printer-finder-file.txt";

/// The programs and services each recorded install had.
fn recorded(name: &str) -> Sim {
    let sim = Sim::fixture(name);
    for tool in ["/usr/bin/timedatectl", "/usr/sbin/cupsctl", "/usr/bin/date"] {
        sim.tool(tool);
    }
    sim.file("/etc/machine-id", "0123456789abcdef\n");
    match name {
        "ubuntu-26.04" => {
            sim.tool("/usr/bin/pro").tool("/usr/bin/snap");
            sim.unit("cups-browsed.service", "enabled", true);
        }
        "fedora-44" => {
            sim.unit("cups-browsed.service", "disabled", false);
        }
        _ => {
            sim.unit("cups-browsed.service", "enabled", false);
        }
    }
    sim
}

fn mark(sim: &Sim, key: &str, from: &str, to: &str) {
    let text = sim.get(key);
    assert!(text.contains(from), "{key} has no {from}");
    sim.set(key, &text.replace(from, to));
}

fn restarts(sim: &Sim) -> usize {
    sim.calls
        .borrow()
        .iter()
        .filter(|c| *c == "/usr/bin/systemctl try-restart cups-browsed.service")
        .count()
}

#[test]
fn the_clock_is_read_and_set_on_every_recorded_install() {
    for name in DISTROS {
        let sim = recorded(name);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.time_sync"),
            json!({"items": {"ntp": 1}}),
            "{name}"
        );
        assert_eq!(
            status(&mut b, "linux.time_sync"),
            CheckStatus::Compliant,
            "{name}"
        );
        mark(&sim, "rec.timedatectl", "\nNTP=yes", "\nNTP=no");
        let before_text = sim.get("rec.timedatectl");
        let (before, fixed) = cycle(&sim, "linux.time_sync");
        assert_eq!(before, json!({"items": {"ntp": 0}}), "{name}");
        assert_eq!(fixed, json!({"items": {"ntp": 1}}), "{name}");
        assert!(sim.ran("/usr/bin/timedatectl set-ntp true"), "{name}");
        assert!(sim.ran("/usr/bin/timedatectl set-ntp false"), "{name}");
        assert_eq!(sim.get("rec.timedatectl"), before_text, "{name}");
    }
}

#[test]
fn a_clock_that_cannot_use_the_internet_is_not_offered() {
    let sim = recorded("ubuntu-26.04");
    mark(&sim, "rec.timedatectl", "CanNTP=yes", "CanNTP=no");
    mark(&sim, "rec.timedatectl", "\nNTP=yes", "\nNTP=no");
    let mut b = backend(&sim);
    let o = b.observe("linux.time_sync").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, svc::NO_TIME_SYNC);
    assert!(skipped(&mut b, "linux.time_sync"));
    assert!(b
        .write("linux.time_sync", &json!({"items": {"ntp": 1}}))
        .is_err());
    assert!(!sim.ran("/usr/bin/timedatectl set-ntp true"));

    let gone = recorded("fedora-44");
    gone.tools.borrow_mut().remove("/usr/bin/timedatectl");
    let o = backend(&gone).observe("linux.time_sync").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, svc::NO_TIME_SYNC);
}

#[test]
fn printer_sharing_reads_safe_on_every_recorded_install() {
    for name in DISTROS {
        let sim = recorded(name);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.printer_sharing"),
            json!({"items": {"share_printers": 0, "remote_admin": 0, "remote_any": 0}}),
            "{name}"
        );
        assert_eq!(
            status(&mut b, "linux.printer_sharing"),
            CheckStatus::Compliant,
            "{name}"
        );
    }
}

#[test]
fn shared_printers_are_switched_off_and_exactly_those_come_back() {
    for name in DISTROS {
        let sim = recorded(name);
        mark(
            &sim,
            "rec.cupsctl",
            "_share_printers=0",
            "_share_printers=1",
        );
        mark(&sim, "rec.cupsctl", "_remote_any=0", "_remote_any=1");
        let before_text = sim.get("rec.cupsctl");
        let (before, fixed) = cycle(&sim, "linux.printer_sharing");
        assert_eq!(
            before,
            json!({"items": {"share_printers": 1, "remote_admin": 0, "remote_any": 1}}),
            "{name}"
        );
        assert_eq!(
            fixed,
            json!({"items": {"share_printers": 0, "remote_admin": 0, "remote_any": 0}}),
            "{name}"
        );
        assert!(
            sim.ran("/usr/sbin/cupsctl --no-share-printers --no-remote-any"),
            "{name}"
        );
        assert!(
            sim.ran("/usr/sbin/cupsctl --share-printers --remote-any"),
            "{name}"
        );
        assert_eq!(sim.get("rec.cupsctl"), before_text, "{name}");
    }
}

#[test]
fn a_computer_without_the_printing_tool_is_not_offered_printer_sharing() {
    let sim = recorded("mint-22.3");
    sim.tools.borrow_mut().remove("/usr/sbin/cupsctl");
    let mut b = backend(&sim);
    let o = b.observe("linux.printer_sharing").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, svc::NO_PRINTING);
    let off = json!({"items": {"share_printers": 0, "remote_admin": 0, "remote_any": 0}});
    assert!(b.write("linux.printer_sharing", &off).is_err());
}

#[test]
fn nothing_is_run_when_printer_sharing_is_already_off() {
    let sim = recorded("ubuntu-26.04");
    let off = json!({"items": {"share_printers": 0, "remote_admin": 0, "remote_any": 0}});
    backend(&sim).write("linux.printer_sharing", &off).unwrap();
    assert!(sim.calls.borrow().iter().all(|c| !c.contains("--")));
}

#[test]
fn the_printer_finder_is_safe_as_recorded_on_every_install() {
    for name in DISTROS {
        let sim = recorded(name);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.printer_discovery"),
            json!({"items": {"cups_protocol": 0}}),
            "{name}"
        );
        assert_eq!(
            status(&mut b, "linux.printer_discovery"),
            CheckStatus::Compliant,
            "{name}"
        );
    }
}

#[test]
fn the_old_printer_protocol_leaves_its_line_and_the_file_comes_back_byte_for_byte() {
    for (name, original) in [
        ("ubuntu-26.04", "BrowseRemoteProtocols dnssd cups\n"),
        (
            "mint-22.3",
            "# Written by hand\n\tBrowseRemoteProtocols  CUPS dnssd\r\nBrowseLocalProtocols dnssd",
        ),
    ] {
        let sim = recorded(name);
        sim.unit("cups-browsed.service", "enabled", true);
        sim.file(BROWSED_CONF, original);
        let (before, fixed) = cycle(&sim, "linux.printer_discovery");
        assert_eq!(before, json!({"items": {"cups_protocol": 1}}), "{name}");
        assert_eq!(fixed, json!({"items": {"cups_protocol": 0}}), "{name}");
        assert_eq!(sim.text(BROWSED_CONF).unwrap(), original, "{name}");
        assert_eq!(restarts(&sim), 2, "{name}");
        assert!(!sim.has(BROWSED_MEMO), "{name}");
    }
}

#[test]
fn only_the_printer_finder_line_is_rewritten() {
    let sim = recorded("ubuntu-26.04");
    sim.file(
        BROWSED_CONF,
        "BrowseRemoteProtocols dnssd cups\nBrowsePoll host\n",
    );
    let mut b = backend(&sim);
    let fixed = json!({"items": {"cups_protocol": 0}});
    b.write("linux.printer_discovery", &fixed).unwrap();
    assert_eq!(
        sim.text(BROWSED_CONF).unwrap(),
        "BrowseRemoteProtocols dnssd\nBrowsePoll host\n"
    );
    sim.file(BROWSED_CONF, "BrowseRemoteProtocols cups\n");
    b.write("linux.printer_discovery", &fixed).unwrap();
    assert_eq!(
        sim.text(BROWSED_CONF).unwrap(),
        "BrowseRemoteProtocols none\n"
    );
}

#[test]
fn the_printer_finder_only_counts_when_it_is_switched_on() {
    let sim = recorded("fedora-44");
    sim.file(BROWSED_CONF, "BrowseRemoteProtocols cups\n");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.printer_discovery"),
        json!({"items": {"cups_protocol": 0}})
    );
    sim.unit("cups-browsed.service", "disabled", true);
    assert_eq!(
        value(&mut b, "linux.printer_discovery"),
        json!({"items": {"cups_protocol": 1}})
    );
}

#[test]
fn the_printer_finder_is_not_offered_without_its_unit_file_or_line() {
    let sim = recorded("ubuntu-26.04");
    sim.units.borrow_mut().remove("cups-browsed.service");
    let o = backend(&sim).observe("linux.printer_discovery").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, svc::NO_PRINTER_FINDER);

    let sim = recorded("ubuntu-26.04");
    sim.files.borrow_mut().remove(Path::new(BROWSED_CONF));
    let o = backend(&sim).observe("linux.printer_discovery").unwrap();
    assert!(!o.eligible);

    let sim = recorded("ubuntu-26.04");
    sim.file(BROWSED_CONF, "# BrowseRemoteProtocols cups\n");
    let o = backend(&sim).observe("linux.printer_discovery").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, svc::NO_PRINTER_FINDER);
}

#[test]
fn the_printer_finder_is_not_changed_back_without_its_record() {
    let sim = recorded("ubuntu-26.04");
    let original = "BrowseRemoteProtocols dnssd cups\n";
    sim.file(BROWSED_CONF, original);
    let mut b = backend(&sim);
    b.write(
        "linux.printer_discovery",
        &json!({"items": {"cups_protocol": 0}}),
    )
    .unwrap();
    sim.files.borrow_mut().remove(Path::new(BROWSED_MEMO));
    let fixed_text = sim.text(BROWSED_CONF).unwrap();
    assert!(b
        .write(
            "linux.printer_discovery",
            &json!({"items": {"cups_protocol": 1}})
        )
        .is_err());
    assert_eq!(sim.text(BROWSED_CONF).unwrap(), fixed_text);
}

#[test]
fn ubuntu_news_is_read_fixed_and_put_back_exactly() {
    let sim = recorded("ubuntu-26.04");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.ubuntu_news"),
        json!({"items": {"apt_news": 1, "motd_news": null}})
    );
    assert_eq!(status(&mut b, "linux.ubuntu_news"), CheckStatus::Attention);
    let pro = sim.get("rec.pro");
    let (before, fixed) = cycle(&sim, "linux.ubuntu_news");
    assert_eq!(before["items"]["apt_news"], 1);
    assert_eq!(fixed, json!({"items": {"apt_news": 0, "motd_news": null}}));
    assert!(sim.ran("/usr/bin/pro config set apt_news=false"));
    assert!(sim.ran("/usr/bin/pro config set apt_news=true"));
    assert_eq!(sim.get("rec.pro"), pro);
    assert!(!sim.has("/etc/default/motd-news"));
}

#[test]
fn the_sign_in_news_file_comes_back_byte_for_byte() {
    let original = "# Set to 0 to disable\r\nENABLED=1\nURL=\"https://motd.ubuntu.com\"";
    let sim = recorded("ubuntu-26.04");
    sim.file("/etc/default/motd-news", original);
    let (before, fixed) = cycle(&sim, "linux.ubuntu_news");
    assert_eq!(before, json!({"items": {"apt_news": 1, "motd_news": 1}}));
    assert_eq!(fixed, json!({"items": {"apt_news": 0, "motd_news": 0}}));
    assert_eq!(sim.text("/etc/default/motd-news").unwrap(), original);

    let sim = recorded("ubuntu-26.04");
    sim.file("/etc/default/motd-news", original);
    mark(
        &sim,
        "rec.pro",
        "apt_news                       True",
        "apt_news                       False",
    );
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.ubuntu_news"),
        json!({"items": {"apt_news": 0, "motd_news": 1}})
    );
    let target = json!({"items": {"apt_news": 0, "motd_news": 0}});
    b.write("linux.ubuntu_news", &target).unwrap();
    assert_eq!(
        sim.text("/etc/default/motd-news").unwrap(),
        "# Set to 0 to disable\r\nENABLED=0\nURL=\"https://motd.ubuntu.com\""
    );
    assert!(!sim.ran("/usr/bin/pro config set apt_news=false"));
}

#[test]
fn ubuntu_news_is_only_offered_on_ubuntu_and_a_missing_tool_is_not_a_problem() {
    let offered = |name: &str| -> Vec<String> {
        backend(&recorded(name))
            .controls()
            .into_iter()
            .map(|c| c.id)
            .collect()
    };
    for name in ["fedora-44", "mint-22.3"] {
        let ids = offered(name);
        assert!(!ids.iter().any(|i| i == "linux.ubuntu_news"), "{name}");
        assert!(ids.iter().any(|i| i == "linux.time_sync"), "{name}");
    }
    assert!(offered("ubuntu-26.04")
        .iter()
        .any(|i| i == "linux.ubuntu_news"));

    let sim = recorded("ubuntu-26.04");
    sim.tools.borrow_mut().remove("/usr/bin/pro");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.ubuntu_news"),
        json!({"items": {"apt_news": null, "motd_news": null}})
    );
    assert_eq!(status(&mut b, "linux.ubuntu_news"), CheckStatus::Compliant);
}

#[test]
fn a_hold_in_the_past_a_short_one_or_none_is_not_a_hold() {
    let sim = recorded("ubuntu-26.04");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.snap_updates"),
        json!({"items": {"held": 0}})
    );
    assert_eq!(status(&mut b, "linux.snap_updates"), CheckStatus::Compliant);
    for held in ["2026-10-29T11:04:48Z\n", "2026-11-02T11:04:48Z\n", ""] {
        sim.set("rec.snap-hold", held);
        assert_eq!(
            value(&mut b, "linux.snap_updates"),
            json!({"items": {"held": 0}}),
            "{held}"
        );
    }
    sim.set("rec.snap-hold", "2026-11-02T11:04:49Z\n");
    assert_eq!(
        value(&mut b, "linux.snap_updates"),
        json!({"items": {"held": 1}})
    );
}

#[test]
fn a_long_hold_is_removed_and_the_exact_hold_comes_back() {
    for held in [
        "forever\n",
        "2026-12-24T08:30:00.123456789Z\n",
        "2026-11-30T00:00:00+01:00\n",
    ] {
        let sim = recorded("ubuntu-26.04");
        sim.set("rec.snap-hold", held);
        let (before, fixed) = cycle(&sim, "linux.snap_updates");
        assert_eq!(before, json!({"items": {"held": 1}}), "{held}");
        assert_eq!(fixed, json!({"items": {"held": 0}}), "{held}");
        assert!(sim.ran("/usr/bin/snap unset system refresh.hold"), "{held}");
        let restore = format!("/usr/bin/snap set system refresh.hold={}", held.trim());
        assert!(sim.ran(&restore), "{held}");
        assert_eq!(sim.get("rec.snap-hold"), held, "{held}");
    }
}

#[test]
fn a_computer_without_the_app_store_is_not_offered_the_hold_check() {
    for name in ["fedora-44", "mint-22.3"] {
        let sim = recorded(name);
        let o = backend(&sim).observe("linux.snap_updates").unwrap();
        assert!(!o.eligible, "{name}");
        assert_eq!(o.reason, svc::NO_SNAP_STORE, "{name}");
    }
    let sim = recorded("ubuntu-26.04");
    sim.fail("/usr/bin/snap get");
    let o = backend(&sim).observe("linux.snap_updates").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, svc::NO_SNAP_STORE);
}

#[test]
fn a_hold_nobody_can_read_is_left_alone() {
    let sim = recorded("ubuntu-26.04");
    sim.set("rec.snap-hold", "someday\n");
    let mut b = backend(&sim);
    let o = b.observe("linux.snap_updates").unwrap();
    assert!(!o.eligible);
    assert!(b
        .write("linux.snap_updates", &json!({"items": {"held": 0}}))
        .is_err());
    assert!(!sim.ran("/usr/bin/snap unset system refresh.hold"));
}

#[test]
fn a_value_with_the_wrong_keys_changes_nothing() {
    let sim = recorded("ubuntu-26.04");
    let mut b = backend(&sim);
    for (id, bad) in [
        ("linux.time_sync", json!({"items": {"ntp": 2}})),
        (
            "linux.printer_sharing",
            json!({"items": {"share_printers": 0}}),
        ),
        (
            "linux.printer_discovery",
            json!({"items": {"cups_protocol": "cups"}}),
        ),
        ("linux.ubuntu_news", json!({"items": {"apt_news": 0}})),
        (
            "linux.snap_updates",
            json!({"items": {"held": 0, "extra": 1}}),
        ),
    ] {
        assert!(b.write(id, &bad).is_err(), "{id}");
    }
    assert!(sim
        .calls
        .borrow()
        .iter()
        .all(|c| !c.contains(" set") && !c.contains("--")));
}
