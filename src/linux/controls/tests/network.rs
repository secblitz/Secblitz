//! The network and program protections against the recorded installs.

use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

const PTRACE_FILE: &str = "/etc/sysctl.d/90-secblitz-ptrace.conf";
const REDIRECT_FILE: &str = "/etc/sysctl.d/90-secblitz-network-redirects.conf";
const LLMNR_FILE: &str = "/etc/systemd/resolved.conf.d/90-secblitz.conf";
const REDIRECT_MEMO: &str = "/var/lib/secblitz/Linux/network_redirects.txt";

fn resolved(sim: Sim) -> Sim {
    sim.unit("systemd-resolved.service", "enabled", true);
    sim.tool("/usr/bin/resolvectl");
    sim
}

/// Ubuntu and Mint build the resolver so that it never answers; the recorded installs say `Global: no`.
fn quiet(sim: Sim) -> Sim {
    sim.set("resolved.built", "no");
    resolved(sim)
}

fn snapshot(sim: &Sim) -> BTreeMap<PathBuf, String> {
    sim.files
        .borrow()
        .iter()
        .map(|(p, b)| (p.clone(), String::from_utf8_lossy(b).into_owned()))
        .collect()
}

fn assert_same(sim: &Sim, before: &BTreeMap<PathBuf, String>) {
    let now = snapshot(sim);
    for path in before.keys().chain(now.keys()) {
        assert_eq!(before.get(path), now.get(path), "{}", path.display());
    }
}

fn fix(sim: &Sim, id: &str) -> Value {
    let mut b = backend(sim);
    let before = value(&mut b, id);
    let fixed = spec(id).unwrap().derive_target(&before).unwrap();
    b.write(id, &fixed).unwrap();
    fixed
}

#[test]
fn the_new_controls_are_system_controls_that_are_not_optional() {
    for id in ["linux.ptrace", "linux.network_redirects", "linux.llmnr"] {
        let s = spec(id).unwrap();
        assert_eq!(s.scope, Scope::System, "{id}");
        assert!(!s.ask, "{id}");
    }
}

#[test]
fn looking_inside_programs_reads_as_each_install_has_it() {
    for (sim, scope, compliant) in [
        (ubuntu(), 1, true),
        (linuxmint(), 1, true),
        (fedora(), 0, false),
    ] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.ptrace"),
            json!({"items": {"ptrace_scope": scope}})
        );
        assert_eq!(
            status(&mut b, "linux.ptrace") == CheckStatus::Compliant,
            compliant
        );
    }
}

#[test]
fn looking_inside_programs_is_fixed_kept_and_put_back() {
    let sim = fedora();
    let before = snapshot(&sim);
    let (was, fixed) = cycle(&sim, "linux.ptrace");
    assert_eq!(was, json!({"items": {"ptrace_scope": 0}}));
    assert_eq!(fixed, json!({"items": {"ptrace_scope": 1}}));
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.yama.ptrace_scope=1"));
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.yama.ptrace_scope=0"));
    assert_same(&sim, &before);

    let mut b = backend(&sim);
    b.write("linux.ptrace", &fixed).unwrap();
    assert_eq!(
        sim.text(PTRACE_FILE).unwrap(),
        "# Written by Secblitz. Delete this file to go back to how it was.\nkernel.yama.ptrace_scope = 1\n"
    );
    assert!(!sim.has("/etc/sysctl.d/90-secblitz.conf"));
    assert_eq!(status(&mut b, "linux.ptrace"), CheckStatus::Compliant);
    b.write("linux.ptrace", &was).unwrap();
    assert!(!sim.has(PTRACE_FILE));
}

#[test]
fn a_stricter_rule_than_the_fix_is_left_alone() {
    for scope in ["2\n", "3\n"] {
        let sim = fedora();
        sim.file("/proc/sys/kernel/yama/ptrace_scope", scope);
        let mut b = backend(&sim);
        assert_eq!(status(&mut b, "linux.ptrace"), CheckStatus::Compliant);
    }
}

#[test]
fn without_the_yama_module_looking_inside_programs_is_not_offered() {
    let sim = ubuntu();
    sim.files
        .borrow_mut()
        .remove(std::path::Path::new("/proc/sys/kernel/yama/ptrace_scope"));
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.ptrace"),
        json!({"items": {"ptrace_scope": null}})
    );
    assert_eq!(status(&mut b, "linux.ptrace"), CheckStatus::Compliant);
}

#[test]
fn the_kernel_protections_file_is_not_touched_by_the_new_controls() {
    let sim = fedora();
    sim.file("/proc/sys/kernel/kptr_restrict", "0\n");
    cycle(&sim, "linux.kernel_protections");
    fix(&sim, "linux.ptrace");
    assert!(!sim.has("/etc/sysctl.d/90-secblitz.conf"));
    assert!(sim.has(PTRACE_FILE));
}

#[test]
fn redirects_read_as_unsafe_on_every_install() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.network_redirects"),
            json!({"items": {"accept_redirects": 1, "send_redirects": 1}})
        );
        assert_eq!(
            status(&mut b, "linux.network_redirects"),
            CheckStatus::Attention
        );
    }
}

#[test]
fn redirects_are_turned_off_everywhere_kept_and_put_back_exactly() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.network_redirects");
        assert_eq!(
            was,
            json!({"items": {"accept_redirects": 1, "send_redirects": 1}})
        );
        assert_eq!(
            fixed,
            json!({"items": {"accept_redirects": 0, "send_redirects": 0}})
        );
        assert_same(&sim, &before);
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/all/accept_redirects=0"));
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/enp1s0/send_redirects=0"));
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv6/conf/default/accept_redirects=0"));
        assert!(!sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/lo/accept_redirects=0"));
    }
}

#[test]
fn the_redirects_file_names_all_default_and_every_connection() {
    let sim = ubuntu();
    fix(&sim, "linux.network_redirects");
    assert_eq!(
        sim.text(REDIRECT_FILE).unwrap(),
        "# Written by Secblitz. Delete this file to go back to how it was.\n\
         net.ipv4.conf.all.accept_redirects = 0\n\
         net.ipv4.conf.default.accept_redirects = 0\n\
         net.ipv4.conf.*.accept_redirects = 0\n\
         net.ipv6.conf.all.accept_redirects = 0\n\
         net.ipv6.conf.default.accept_redirects = 0\n\
         net.ipv6.conf.*.accept_redirects = 0\n\
         net.ipv4.conf.all.send_redirects = 0\n\
         net.ipv4.conf.default.send_redirects = 0\n\
         net.ipv4.conf.*.send_redirects = 0\n"
    );
    assert!(sim.has(REDIRECT_MEMO));
    assert!(!sim.has("/etc/sysctl.d/90-secblitz.conf"));
    let mut b = backend(&sim);
    assert_eq!(
        status(&mut b, "linux.network_redirects"),
        CheckStatus::Compliant
    );
}

#[test]
fn one_connection_that_follows_redirects_is_enough_to_be_unsafe() {
    let sim = ubuntu();
    for family in ["ipv4", "ipv6"] {
        for name in ["all", "default"] {
            sim.file(
                &format!("/proc/sys/net/{family}/conf/{name}/accept_redirects"),
                "0\n",
            );
        }
        sim.file(
            &format!("/proc/sys/net/{family}/conf/enp1s0/accept_redirects"),
            "0\n",
        );
        sim.file(
            &format!("/proc/sys/net/{family}/conf/lo/accept_redirects"),
            "1\n",
        );
    }
    for name in ["all", "default", "enp1s0"] {
        sim.file(
            &format!("/proc/sys/net/ipv4/conf/{name}/send_redirects"),
            "0\n",
        );
    }
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.network_redirects"),
        json!({"items": {"accept_redirects": 0, "send_redirects": 0}})
    );
    assert_eq!(
        status(&mut b, "linux.network_redirects"),
        CheckStatus::Compliant
    );
    sim.file("/proc/sys/net/ipv6/conf/wlp2s0/accept_redirects", "1\n");
    assert_eq!(
        value(&mut b, "linux.network_redirects"),
        json!({"items": {"accept_redirects": 1, "send_redirects": 0}})
    );
}

#[test]
fn only_the_values_that_were_on_are_written_back_and_a_mixed_state_is_restored_exactly() {
    let sim = fedora();
    sim.file("/proc/sys/net/ipv4/conf/all/accept_redirects", "0\n");
    sim.file("/proc/sys/net/ipv4/conf/default/accept_redirects", "0\n");
    sim.file("/proc/sys/net/ipv6/conf/all/accept_redirects", "0\n");
    sim.file("/proc/sys/net/ipv6/conf/default/accept_redirects", "0\n");
    sim.file("/proc/sys/net/ipv6/conf/enp1s0/accept_redirects", "0\n");
    for name in ["all", "default", "enp1s0"] {
        sim.file(
            &format!("/proc/sys/net/ipv4/conf/{name}/send_redirects"),
            "0\n",
        );
    }
    let before = snapshot(&sim);
    let (was, fixed) = cycle(&sim, "linux.network_redirects");
    assert_eq!(
        was,
        json!({"items": {"accept_redirects": 1, "send_redirects": 0}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"accept_redirects": 0, "send_redirects": 0}})
    );
    assert_same(&sim, &before);
    assert!(sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/enp1s0/accept_redirects=0"));
    assert!(!sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/all/accept_redirects=0"));
}

#[test]
fn a_connection_that_went_away_is_not_written_back_and_a_new_one_is_left_as_it_is() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.network_redirects");
    let fixed = fix(&sim, "linux.network_redirects");
    for family in ["ipv4", "ipv6"] {
        for key in ["accept_redirects", "send_redirects"] {
            sim.files.borrow_mut().remove(std::path::Path::new(&format!(
                "/proc/sys/net/{family}/conf/enp1s0/{key}"
            )));
        }
    }
    sim.file("/proc/sys/net/ipv4/conf/wlp2s0/accept_redirects", "0\n");
    b.write("linux.network_redirects", &was).unwrap();
    assert_eq!(
        sim.text("/proc/sys/net/ipv4/conf/all/accept_redirects")
            .unwrap(),
        "1\n"
    );
    assert!(!sim.has("/proc/sys/net/ipv4/conf/enp1s0/accept_redirects"));
    assert_eq!(
        sim.text("/proc/sys/net/ipv4/conf/wlp2s0/accept_redirects")
            .unwrap(),
        "0\n"
    );
    assert!(!sim.has(REDIRECT_FILE));
    assert!(!sim.has(REDIRECT_MEMO));
    assert_eq!(fixed["items"]["accept_redirects"], 0);
}

#[test]
fn a_second_fix_keeps_the_first_record_when_a_new_connection_appears() {
    let sim = ubuntu();
    fix(&sim, "linux.network_redirects");
    sim.file("/proc/sys/net/ipv4/conf/wlp2s0/accept_redirects", "1\n");
    let memo = sim.text(REDIRECT_MEMO).unwrap();
    let mut b = backend(&sim);
    let fixed = spec("linux.network_redirects")
        .unwrap()
        .derive_target(&value(&mut b, "linux.network_redirects"))
        .unwrap();
    b.write("linux.network_redirects", &fixed).unwrap();
    let after = sim.text(REDIRECT_MEMO).unwrap();
    assert!(after.starts_with(&memo));
    assert!(after.contains("/proc/sys/net/ipv4/conf/wlp2s0/accept_redirects 1\n"));
}

#[test]
fn undoing_redirects_without_a_record_changes_nothing() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.network_redirects");
    let before = snapshot(&sim);
    let err = b.write("linux.network_redirects", &was).unwrap_err();
    assert_eq!(err.to_string(), NO_RECORD);
    assert_same(&sim, &before);
}

#[test]
fn a_damaged_record_is_refused_and_nothing_is_written() {
    for line in [
        "/etc/passwd 1",
        "/proc/sys/net/ipv4/conf/../../../kernel/kptr_restrict 1",
        "/proc/sys/net/ipv4/conf/all/accept_redirects x",
        "/proc/sys/net/ipv4/conf/all/forwarding 1",
        "no spaces",
    ] {
        let sim = ubuntu();
        let mut b = backend(&sim);
        let was = value(&mut b, "linux.network_redirects");
        fix(&sim, "linux.network_redirects");
        sim.file(REDIRECT_MEMO, &format!("{line}\n"));
        let calls = sim.calls.borrow().len();
        assert!(b.write("linux.network_redirects", &was).is_err(), "{line}");
        assert_eq!(sim.calls.borrow().len(), calls, "{line}");
    }
}

#[test]
fn redirects_are_not_offered_when_the_computer_has_no_such_settings() {
    let sim = ubuntu();
    sim.files
        .borrow_mut()
        .retain(|p, _| !p.starts_with("/proc/sys/net"));
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.network_redirects"),
        json!({"items": {"accept_redirects": null, "send_redirects": null}})
    );
    assert_eq!(
        status(&mut b, "linux.network_redirects"),
        CheckStatus::Compliant
    );
}

#[test]
fn forwarding_is_never_touched() {
    let sim = ubuntu();
    sim.file("/proc/sys/net/ipv4/conf/all/forwarding", "1\n");
    fix(&sim, "linux.network_redirects");
    assert_eq!(
        sim.text("/proc/sys/net/ipv4/conf/all/forwarding").unwrap(),
        "1\n"
    );
    assert!(!sim.calls.borrow().iter().any(|c| c.contains("forwarding")));
}

#[test]
fn name_lookups_read_as_open_on_fedora_and_closed_on_ubuntu_and_mint() {
    let mut b = backend(&resolved(fedora()));
    assert_eq!(
        value(&mut b, "linux.llmnr"),
        json!({"items": {"llmnr": "yes"}})
    );
    assert_eq!(status(&mut b, "linux.llmnr"), CheckStatus::Attention);
    for sim in [quiet(ubuntu()), quiet(linuxmint())] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.llmnr"),
            json!({"items": {"llmnr": "no"}})
        );
        assert_eq!(status(&mut b, "linux.llmnr"), CheckStatus::Compliant);
    }
}

#[test]
fn a_resolver_that_cannot_be_asked_is_not_read_as_safe() {
    let sim = resolved(fedora());
    sim.fail("/usr/bin/resolvectl llmnr");
    let o = backend(&sim).observe("linux.llmnr");
    assert!(o.is_err() || !o.unwrap().eligible);
}

#[test]
fn name_lookups_are_closed_by_a_file_of_their_own_and_opened_again_by_removing_it() {
    for sim in [
        resolved(ubuntu()),
        resolved(fedora()),
        resolved(linuxmint()),
    ] {
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.llmnr");
        assert_eq!(was, json!({"items": {"llmnr": "yes"}}));
        assert_eq!(fixed, json!({"items": {"llmnr": "no"}}));
        assert_same(&sim, &before);
        assert!(sim.ran("/usr/bin/systemctl try-restart systemd-resolved.service"));
    }
    let sim = resolved(fedora());
    fix(&sim, "linux.llmnr");
    assert_eq!(
        sim.text(LLMNR_FILE).unwrap(),
        "# Written by Secblitz. Delete this file to go back to how it was.\n[Resolve]\nLLMNR=no\n"
    );
}

#[test]
fn the_value_is_read_the_way_the_resolver_reads_it() {
    let sim = resolved(ubuntu());
    let mut b = backend(&sim);
    let word = |b: &mut LinuxBackend<Sim>| value(b, "linux.llmnr")["items"]["llmnr"].clone();

    sim.file(
        "/etc/systemd/resolved.conf",
        "[Resolve]\n#LLMNR=yes\nLLMNR=resolve\n",
    );
    assert_eq!(word(&mut b), json!("resolve"));
    assert_eq!(status(&mut b, "linux.llmnr"), CheckStatus::Attention);

    sim.file(
        "/usr/lib/systemd/resolved.conf.d/10-vendor.conf",
        "[Resolve]\nLLMNR=no\n",
    );
    assert_eq!(word(&mut b), json!("no"));
    assert_eq!(status(&mut b, "linux.llmnr"), CheckStatus::Compliant);

    sim.file(
        "/etc/systemd/resolved.conf.d/10-vendor.conf",
        "[Resolve]\nLLMNR=true\n",
    );
    assert_eq!(word(&mut b), json!("yes"));

    sim.file(
        "/run/systemd/resolved.conf.d/05-run.conf",
        "[Resolve]\nLLMNR=off\n",
    );
    assert_eq!(word(&mut b), json!("yes"));
    sim.file(
        "/run/systemd/resolved.conf.d/90-run.conf",
        "[Resolve]\nLLMNR=off\n",
    );
    assert_eq!(word(&mut b), json!("no"));
}

#[test]
fn a_setting_the_resolver_does_not_know_is_left_alone() {
    let sim = resolved(ubuntu());
    sim.file("/etc/systemd/resolved.conf", "[Resolve]\nLLMNR=maybe\n");
    let mut b = backend(&sim);
    let o = b.observe("linux.llmnr").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, UNRECOGNISED);
}

#[test]
fn a_later_file_that_turns_it_back_on_is_reported_and_our_file_is_taken_out_again() {
    let sim = resolved(fedora());
    sim.file(
        "/etc/systemd/resolved.conf.d/99-site.conf",
        "[Resolve]\nLLMNR=yes\n",
    );
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let fixed = json!({"items": {"llmnr": "no"}});
    assert!(b.write("linux.llmnr", &fixed).is_err());
    assert_same(&sim, &before);
    assert!(!sim.ran("/usr/bin/systemctl try-restart systemd-resolved.service"));
}

#[test]
fn name_lookups_are_not_offered_when_the_built_in_resolver_is_not_in_use() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.llmnr"),
        json!({"items": {"llmnr": null}})
    );
    assert_eq!(status(&mut b, "linux.llmnr"), CheckStatus::Compliant);
    let sim = ubuntu();
    sim.unit("systemd-resolved.service", "enabled", false);
    assert_eq!(
        value(&mut backend(&sim), "linux.llmnr"),
        json!({"items": {"llmnr": null}})
    );
}

#[test]
fn a_failed_restart_is_reported_as_a_failed_change() {
    let sim = resolved(fedora());
    sim.fail("/usr/bin/systemctl try-restart");
    let mut b = backend(&sim);
    let err = b
        .write("linux.llmnr", &json!({"items": {"llmnr": "no"}}))
        .unwrap_err();
    assert_eq!(err.to_string(), CHANGE_FAILED);
}

#[test]
fn only_the_known_words_are_accepted_for_name_lookups() {
    let s = spec("linux.llmnr").unwrap();
    for word in ["yes", "resolve", "no"] {
        s.validate(&json!({"items": {"llmnr": word}})).unwrap();
    }
    for bad in ["maybe", "No", "no\nyes", "true"] {
        assert!(
            s.validate(&json!({"items": {"llmnr": bad}})).is_err(),
            "{bad}"
        );
    }
    assert!(!s.any_unsafe(&json!({"items": {"llmnr": "no"}})));
    assert!(s.any_unsafe(&json!({"items": {"llmnr": "resolve"}})));
    assert!(s.validate(&json!({"items": {"llmnr": 1}})).is_err());
}

#[test]
fn the_engine_fixes_and_undoes_all_three_through_the_journal() {
    let sim = resolved(fedora());
    let dir = tempfile::tempdir().unwrap();
    let notes = dir.path().join(crate::platform::LINUX_NOTES);
    std::fs::create_dir(&notes).unwrap();
    let mut engine =
        Engine::open_for(Os::Linux, dir.path().to_path_buf(), Box::new(backend(&sim))).unwrap();
    let ids: Vec<String> = ["linux.ptrace", "linux.network_redirects", "linux.llmnr"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let before = snapshot(&sim);
    let applied = engine.apply_selected(&ids, |_| {}).unwrap();
    for id in &ids {
        let r = applied.results.iter().find(|r| &r.id == id).unwrap();
        assert_eq!(r.status, CheckStatus::Applied, "{id}: {}", r.detail);
    }
    assert!(sim.has(PTRACE_FILE) && sim.has(REDIRECT_FILE) && sim.has(LLMNR_FILE));
    let undone = engine.revert(|_| {}).unwrap();
    for id in &ids {
        let r = undone.results.iter().find(|r| &r.id == id).unwrap();
        assert_eq!(r.status, CheckStatus::Restored, "{id}: {}", r.detail);
    }
    assert_same(&sim, &before);
}
