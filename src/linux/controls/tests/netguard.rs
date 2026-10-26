//! The network guards against the recorded installs: every fix is followed by a check and an undo that must leave the
//! files and the running values exactly as they were.

use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

const NOTE: &str = "# Written by Secblitz. Delete this file to go back to how it was.\n";
const RP_FILE: &str = "/etc/sysctl.d/90-secblitz-fake-sources.conf";
const SYN_FILE: &str = "/etc/sysctl.d/90-secblitz-flood-protection.conf";
const SR_FILE: &str = "/etc/sysctl.d/90-secblitz-source-routing.conf";
const BC_FILE: &str = "/etc/sysctl.d/90-secblitz-broadcast-pings.conf";
const TA_FILE: &str = "/etc/sysctl.d/90-secblitz-ipv6-privacy.conf";
const NM_TA_FILE: &str = "/etc/NetworkManager/conf.d/90-secblitz-ipv6-privacy.conf";
const NM_NAME_FILE: &str = "/etc/NetworkManager/conf.d/90-secblitz-computer-name.conf";
const DOT_FILE: &str = "/etc/systemd/resolved.conf.d/90-secblitz-dns.conf";
const LLMNR_FILE: &str = "/etc/systemd/resolved.conf.d/90-secblitz.conf";
const AVAHI_FILE: &str = "/etc/avahi/avahi-daemon.conf";
const FOLDER: &str = "dir:/etc/systemd/resolved.conf.d";
const RESTART_RESOLVED: &str = "/usr/bin/systemctl try-restart systemd-resolved.service";
const RESTART_AVAHI: &str = "/usr/bin/systemctl try-restart avahi-daemon.service";
const RELOAD_NM: &str = "/usr/bin/systemctl reload NetworkManager.service";

fn resolved(sim: Sim) -> Sim {
    sim.unit("systemd-resolved.service", "enabled", true);
    sim.tool("/usr/bin/resolvectl");
    sim
}

fn avahi(sim: Sim) -> Sim {
    sim.unit("avahi-daemon.service", "enabled", true);
    sim
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

fn proc(sim: &Sim, path: &str) -> String {
    sim.text(&format!("/proc/sys/{path}"))
        .unwrap_or_else(|| panic!("no {path}"))
        .trim()
        .to_string()
}

fn set_proc(sim: &Sim, path: &str, value: &str) {
    sim.file(&format!("/proc/sys/{path}"), &format!("{value}\n"));
}

fn item(b: &mut LinuxBackend<Sim>, id: &str, key: &str) -> Value {
    value(b, id)["items"][key].clone()
}

#[test]
fn the_new_network_controls_are_system_controls_and_only_three_are_optional() {
    let ask = [
        "linux.computer_name_sent",
        "linux.encrypted_dns",
        "linux.announce_name",
    ];
    for id in [
        "linux.fake_sources",
        "linux.flood_protection",
        "linux.source_routing",
        "linux.broadcast_pings",
        "linux.ipv6_privacy",
        "linux.computer_name_sent",
        "linux.encrypted_dns",
        "linux.announce_name",
        "linux.old_network_services",
    ] {
        let s = spec(id).unwrap();
        assert_eq!(s.scope, Scope::System, "{id}");
        assert_eq!(s.ask, ask.contains(&id), "{id}");
    }
}

#[test]
fn the_kernel_checks_read_as_each_install_really_shows_them() {
    for (sim, name) in [
        (ubuntu(), "ubuntu"),
        (fedora(), "fedora"),
        (linuxmint(), "mint"),
    ] {
        let mut b = backend(&sim);
        for (id, key, want) in [
            ("linux.fake_sources", "rp_filter", 2),
            ("linux.flood_protection", "syncookies", 1),
            ("linux.source_routing", "accept_source_route", 0),
            ("linux.broadcast_pings", "ignore_broadcasts", 1),
        ] {
            assert_eq!(item(&mut b, id, key), json!(want), "{name} {id}");
            assert_eq!(status(&mut b, id), CheckStatus::Compliant, "{name} {id}");
        }
    }
}

#[test]
fn fedora_is_protected_from_fake_senders_through_the_default_and_each_connection() {
    let sim = fedora();
    assert_eq!(proc(&sim, "net/ipv4/conf/all/rp_filter"), "0");
    let mut b = backend(&sim);
    assert_eq!(item(&mut b, "linux.fake_sources", "rp_filter"), json!(2));
}

#[test]
fn mint_follows_no_source_routes_because_the_shared_value_is_off() {
    let sim = linuxmint();
    assert_eq!(proc(&sim, "net/ipv4/conf/default/accept_source_route"), "1");
    assert_eq!(proc(&sim, "net/ipv4/conf/enp1s0/accept_source_route"), "1");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.source_routing"),
        json!({"items": {"accept_source_route": 0}})
    );
    assert_eq!(
        status(&mut b, "linux.source_routing"),
        CheckStatus::Compliant
    );
}

#[test]
fn the_higher_of_the_shared_and_own_value_counts_for_sender_checks() {
    let sim = ubuntu();
    set_proc(&sim, "net/ipv4/conf/all/rp_filter", "0");
    set_proc(&sim, "net/ipv4/conf/default/rp_filter", "0");
    let mut b = backend(&sim);
    assert_eq!(item(&mut b, "linux.fake_sources", "rp_filter"), json!(0));
    assert_eq!(status(&mut b, "linux.fake_sources"), CheckStatus::Attention);
    set_proc(&sim, "net/ipv4/conf/all/rp_filter", "1");
    assert_eq!(item(&mut b, "linux.fake_sources", "rp_filter"), json!(1));
    assert_eq!(status(&mut b, "linux.fake_sources"), CheckStatus::Compliant);
}

#[test]
fn a_connection_that_follows_source_routes_needs_the_shared_value_on_too() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    set_proc(&sim, "net/ipv4/conf/enp1s0/accept_source_route", "1");
    assert_eq!(
        item(&mut b, "linux.source_routing", "accept_source_route"),
        json!(0)
    );
    set_proc(&sim, "net/ipv4/conf/all/accept_source_route", "1");
    assert_eq!(
        item(&mut b, "linux.source_routing", "accept_source_route"),
        json!(1)
    );
    set_proc(&sim, "net/ipv4/conf/all/accept_source_route", "0");
    set_proc(&sim, "net/ipv6/conf/all/accept_source_route", "1");
    set_proc(&sim, "net/ipv6/conf/default/accept_source_route", "1");
    assert_eq!(
        item(&mut b, "linux.source_routing", "accept_source_route"),
        json!(1)
    );
}

#[test]
fn only_the_connections_own_value_counts_for_temporary_addresses() {
    let mut b = backend(&linuxmint());
    assert_eq!(item(&mut b, "linux.ipv6_privacy", "use_tempaddr"), json!(2));
    assert_eq!(status(&mut b, "linux.ipv6_privacy"), CheckStatus::Compliant);
    let sim = linuxmint();
    set_proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr", "0");
    let mut b = backend(&sim);
    assert_eq!(item(&mut b, "linux.ipv6_privacy", "use_tempaddr"), json!(0));
    set_proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr", "2");
    set_proc(&sim, "net/ipv6/conf/all/use_tempaddr", "0");
    assert_eq!(item(&mut b, "linux.ipv6_privacy", "use_tempaddr"), json!(2));
}

#[test]
fn temporary_addresses_read_as_off_on_fedora_and_on_one_ubuntu_connection() {
    for sim in [fedora(), ubuntu()] {
        let mut b = backend(&sim);
        assert_eq!(item(&mut b, "linux.ipv6_privacy", "use_tempaddr"), json!(0));
        assert_eq!(status(&mut b, "linux.ipv6_privacy"), CheckStatus::Attention);
    }
    assert_eq!(
        proc(&ubuntu(), "net/ipv6/conf/all/use_tempaddr"),
        "2",
        "the shared value alone does not protect a connection"
    );
}

#[test]
fn sender_checks_are_fixed_kept_and_put_back_exactly() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        set_proc(&sim, "net/ipv4/conf/all/rp_filter", "0");
        set_proc(&sim, "net/ipv4/conf/default/rp_filter", "0");
        set_proc(&sim, "net/ipv4/conf/enp1s0/rp_filter", "0");
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.fake_sources");
        assert_eq!(was, json!({"items": {"rp_filter": 0}}));
        assert_eq!(fixed, json!({"items": {"rp_filter": 2}}));
        assert_same(&sim, &before);
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/all/rp_filter=2"));
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/enp1s0/rp_filter=2"));
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/enp1s0/rp_filter=0"));
        assert!(!sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/lo/rp_filter=2"));
    }
}

#[test]
fn the_sender_file_names_all_default_and_every_connection_with_the_loose_value() {
    let sim = ubuntu();
    set_proc(&sim, "net/ipv4/conf/all/rp_filter", "0");
    set_proc(&sim, "net/ipv4/conf/default/rp_filter", "0");
    set_proc(&sim, "net/ipv4/conf/enp1s0/rp_filter", "0");
    cycle_fixed(&sim, "linux.fake_sources");
    assert_eq!(
        sim.text(RP_FILE).unwrap(),
        format!(
            "{NOTE}net.ipv4.conf.all.rp_filter = 2\nnet.ipv4.conf.default.rp_filter = 2\nnet.ipv4.conf.*.rp_filter = 2\n"
        )
    );
    let mut b = backend(&sim);
    assert_eq!(status(&mut b, "linux.fake_sources"), CheckStatus::Compliant);
}

fn cycle_fixed(sim: &Sim, id: &str) -> Value {
    let mut b = backend(sim);
    let before = value(&mut b, id);
    let fixed = spec(id).unwrap().derive_target(&before).unwrap();
    b.write(id, &fixed).unwrap();
    fixed
}

#[test]
fn a_connection_someone_made_strict_is_never_loosened() {
    let sim = ubuntu();
    set_proc(&sim, "net/ipv4/conf/all/rp_filter", "0");
    set_proc(&sim, "net/ipv4/conf/default/rp_filter", "0");
    set_proc(&sim, "net/ipv4/conf/enp1s0/rp_filter", "1");
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    assert_eq!(item(&mut b, "linux.fake_sources", "rp_filter"), json!(0));
    cycle_fixed(&sim, "linux.fake_sources");
    assert_eq!(proc(&sim, "net/ipv4/conf/enp1s0/rp_filter"), "1");
    assert_eq!(proc(&sim, "net/ipv4/conf/default/rp_filter"), "2");
    assert_eq!(proc(&sim, "net/ipv4/conf/all/rp_filter"), "0");
    assert_eq!(
        sim.text(RP_FILE).unwrap(),
        format!("{NOTE}net.ipv4.conf.default.rp_filter = 2\n")
    );
    let mut b = backend(&sim);
    b.write("linux.fake_sources", &json!({"items": {"rp_filter": 0}}))
        .unwrap();
    assert_same(&sim, &before);
}

#[test]
fn sender_checks_on_a_connection_that_was_never_unprotected_change_nothing() {
    let sim = fedora();
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    b.write("linux.fake_sources", &json!({"items": {"rp_filter": 2}}))
        .unwrap();
    assert_same(&sim, &before);
    assert!(!sim.calls.borrow().iter().any(|c| c.contains("sysctl")));
}

#[test]
fn a_stricter_value_than_the_fix_is_not_a_finding() {
    let sim = fedora();
    set_proc(&sim, "net/ipv4/conf/all/rp_filter", "1");
    let mut b = backend(&sim);
    assert_eq!(status(&mut b, "linux.fake_sources"), CheckStatus::Compliant);
    assert!(b
        .write("linux.fake_sources", &json!({"items": {"rp_filter": 1}}))
        .is_err());
}

#[test]
fn flood_protection_is_fixed_kept_and_put_back_exactly() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        set_proc(&sim, "net/ipv4/tcp_syncookies", "0");
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.flood_protection");
        assert_eq!(was, json!({"items": {"syncookies": 0}}));
        assert_eq!(fixed, json!({"items": {"syncookies": 1}}));
        assert_same(&sim, &before);
        assert!(sim.ran("/usr/sbin/sysctl -w net.ipv4.tcp_syncookies=1"));
        assert!(sim.ran("/usr/sbin/sysctl -w net.ipv4.tcp_syncookies=0"));
    }
    let sim = ubuntu();
    set_proc(&sim, "net/ipv4/tcp_syncookies", "0");
    cycle_fixed(&sim, "linux.flood_protection");
    assert_eq!(
        sim.text(SYN_FILE).unwrap(),
        format!("{NOTE}net.ipv4.tcp_syncookies = 1\n")
    );
}

#[test]
fn flood_protection_that_is_always_on_is_left_alone() {
    let sim = ubuntu();
    set_proc(&sim, "net/ipv4/tcp_syncookies", "2");
    let mut b = backend(&sim);
    assert_eq!(
        status(&mut b, "linux.flood_protection"),
        CheckStatus::Compliant
    );
}

#[test]
fn calls_to_the_whole_network_are_fixed_kept_and_put_back_exactly() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        set_proc(&sim, "net/ipv4/icmp_echo_ignore_broadcasts", "0");
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.broadcast_pings");
        assert_eq!(was, json!({"items": {"ignore_broadcasts": 0}}));
        assert_eq!(fixed, json!({"items": {"ignore_broadcasts": 1}}));
        assert_same(&sim, &before);
    }
    let sim = fedora();
    set_proc(&sim, "net/ipv4/icmp_echo_ignore_broadcasts", "0");
    cycle_fixed(&sim, "linux.broadcast_pings");
    assert_eq!(
        sim.text(BC_FILE).unwrap(),
        format!("{NOTE}net.ipv4.icmp_echo_ignore_broadcasts = 1\n")
    );
}

#[test]
fn a_computer_without_these_kernel_files_is_not_offered_them() {
    let sim = ubuntu();
    sim.files
        .borrow_mut()
        .retain(|p, _| !p.starts_with("/proc/sys/net"));
    let mut b = backend(&sim);
    for (id, key) in [
        ("linux.fake_sources", "rp_filter"),
        ("linux.flood_protection", "syncookies"),
        ("linux.source_routing", "accept_source_route"),
        ("linux.broadcast_pings", "ignore_broadcasts"),
        ("linux.ipv6_privacy", "use_tempaddr"),
    ] {
        assert_eq!(item(&mut b, id, key), json!(null), "{id}");
        assert_eq!(status(&mut b, id), CheckStatus::Compliant, "{id}");
    }
}

fn open_source_routes(sim: &Sim) {
    for family in ["ipv4", "ipv6"] {
        for name in ["all", "default", "enp1s0"] {
            set_proc(
                sim,
                &format!("net/{family}/conf/{name}/accept_source_route"),
                "1",
            );
        }
    }
}

#[test]
fn source_routes_are_switched_off_everywhere_kept_and_put_back_exactly() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        open_source_routes(&sim);
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.source_routing");
        assert_eq!(was, json!({"items": {"accept_source_route": 1}}));
        assert_eq!(fixed, json!({"items": {"accept_source_route": 0}}));
        assert_same(&sim, &before);
        for path in [
            "net/ipv4/conf/all",
            "net/ipv4/conf/default",
            "net/ipv4/conf/enp1s0",
            "net/ipv6/conf/all",
            "net/ipv6/conf/enp1s0",
        ] {
            assert!(
                sim.ran(&format!("/usr/sbin/sysctl -w {path}/accept_source_route=0")),
                "{path}"
            );
        }
        assert!(!sim.ran("/usr/sbin/sysctl -w net/ipv4/conf/lo/accept_source_route=0"));
    }
}

#[test]
fn the_source_route_file_covers_both_address_families() {
    let sim = ubuntu();
    open_source_routes(&sim);
    cycle_fixed(&sim, "linux.source_routing");
    assert_eq!(
        sim.text(SR_FILE).unwrap(),
        format!(
            "{NOTE}net.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv4.conf.*.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\nnet.ipv6.conf.*.accept_source_route = 0\n"
        )
    );
}

#[test]
fn an_undo_without_a_record_leaves_the_computer_as_it_is() {
    let sim = ubuntu();
    open_source_routes(&sim);
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let err = b
        .write(
            "linux.source_routing",
            &json!({"items": {"accept_source_route": 1}}),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), NO_RECORD);
    assert_same(&sim, &before);
}

#[test]
fn a_record_that_names_something_else_is_refused_before_anything_runs() {
    for line in [
        "/proc/sys/kernel/randomize_va_space 0",
        "/proc/sys/net/ipv4/conf/enp1s0/rp_filter 0",
        "/proc/sys/net/ipv4/conf/../accept_source_route 1",
        "/proc/sys/net/ipv4/conf/all/accept_source_route/x 1",
        "/proc/sys/net/ipv4/conf/all/accept_source_route one",
        "no spaces",
    ] {
        let sim = ubuntu();
        open_source_routes(&sim);
        let mut b = backend(&sim);
        let was = value(&mut b, "linux.source_routing");
        cycle_fixed(&sim, "linux.source_routing");
        sim.file(
            "/var/lib/secblitz/Linux/source_routing.txt",
            &format!("{line}\n"),
        );
        let calls = sim.calls.borrow().len();
        assert!(b.write("linux.source_routing", &was).is_err(), "{line}");
        assert_eq!(sim.calls.borrow().len(), calls, "{line}");
        assert!(sim.has(SR_FILE), "{line}");
    }
}

#[test]
fn temporary_addresses_are_turned_on_for_every_connection_and_the_network_program() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        set_proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr", "0");
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.ipv6_privacy");
        assert_eq!(was, json!({"items": {"use_tempaddr": 0}}));
        assert_eq!(fixed, json!({"items": {"use_tempaddr": 2}}));
        assert_same(&sim, &before);
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv6/conf/enp1s0/use_tempaddr=2"));
        assert!(sim.ran("/usr/sbin/sysctl -w net/ipv6/conf/enp1s0/use_tempaddr=0"));
        assert!(!sim.ran("/usr/sbin/sysctl -w net/ipv6/conf/lo/use_tempaddr=2"));
        assert!(!sim.has(NM_TA_FILE));
    }
}

#[test]
fn the_files_for_temporary_addresses_and_the_reload_leave_connections_up() {
    let sim = fedora();
    cycle_fixed(&sim, "linux.ipv6_privacy");
    assert_eq!(
        sim.text(TA_FILE).unwrap(),
        format!(
            "{NOTE}net.ipv6.conf.all.use_tempaddr = 2\nnet.ipv6.conf.default.use_tempaddr = 2\nnet.ipv6.conf.*.use_tempaddr = 2\n"
        )
    );
    assert_eq!(
        sim.text(NM_TA_FILE).unwrap(),
        format!("{NOTE}[connection]\nipv6.ip6-privacy=2\n")
    );
    assert!(sim.ran(RELOAD_NM));
    assert_eq!(
        sim.state("NetworkManager.service"),
        ("enabled".into(), true)
    );
    assert!(!sim
        .calls
        .borrow()
        .iter()
        .any(|c| c.contains("restart") || c.contains("nmcli")));
    assert_eq!(proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr"), "2");
    assert_eq!(proc(&sim, "net/ipv6/conf/lo/use_tempaddr"), "-1");
    assert_eq!(proc(&sim, "net/ipv6/conf/all/use_tempaddr"), "0");
    let mut b = backend(&sim);
    assert_eq!(status(&mut b, "linux.ipv6_privacy"), CheckStatus::Compliant);
    b.write("linux.ipv6_privacy", &json!({"items": {"use_tempaddr": 0}}))
        .unwrap();
    assert!(!sim.has(TA_FILE) && !sim.has(NM_TA_FILE));
    assert_eq!(proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr"), "0");
}

#[test]
fn temporary_addresses_without_the_network_program_still_work() {
    let sim = fedora();
    sim.files
        .borrow_mut()
        .remove(&PathBuf::from("/etc/NetworkManager/NetworkManager.conf"));
    let before = snapshot(&sim);
    cycle(&sim, "linux.ipv6_privacy");
    assert_same(&sim, &before);
    assert!(!sim.ran(RELOAD_NM));
}

#[test]
fn a_connection_that_was_set_to_prefer_public_addresses_is_put_back() {
    let sim = linuxmint();
    set_proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr", "1");
    let before = snapshot(&sim);
    let (was, _) = cycle(&sim, "linux.ipv6_privacy");
    assert_eq!(was, json!({"items": {"use_tempaddr": 1}}));
    assert_same(&sim, &before);
}

#[test]
fn a_second_fix_keeps_the_first_records_so_one_undo_puts_everything_back() {
    let sim = fedora();
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.ipv6_privacy");
    let fixed = json!({"items": {"use_tempaddr": 2}});
    b.write("linux.ipv6_privacy", &fixed).unwrap();
    set_proc(&sim, "net/ipv6/conf/enp1s0/use_tempaddr", "0");
    b.write("linux.ipv6_privacy", &fixed).unwrap();
    b.write("linux.ipv6_privacy", &was).unwrap();
    assert_same(&sim, &before);
}

#[test]
fn the_computer_name_is_sent_everywhere_by_default() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.computer_name_sent"),
            json!({"items": {"sends": 1}})
        );
        assert_eq!(
            status(&mut b, "linux.computer_name_sent"),
            CheckStatus::Attention
        );
    }
}

#[test]
fn the_computer_name_stops_being_sent_without_dropping_a_connection() {
    for sim in [ubuntu(), fedora(), linuxmint()] {
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.computer_name_sent");
        assert_eq!(was, json!({"items": {"sends": 1}}));
        assert_eq!(fixed, json!({"items": {"sends": 0}}));
        assert_same(&sim, &before);
        assert!(sim.ran(RELOAD_NM));
        assert!(!sim
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("restart") || c.contains("nmcli") || c.contains("stop")));
    }
    let sim = fedora();
    cycle_fixed(&sim, "linux.computer_name_sent");
    assert_eq!(
        sim.text(NM_NAME_FILE).unwrap(),
        format!(
            "{NOTE}[connection]\nipv4.dhcp-send-hostname=false\nipv6.dhcp-send-hostname=false\n"
        )
    );
}

#[test]
fn the_computer_name_is_not_offered_without_the_network_program() {
    let sim = ubuntu();
    sim.files
        .borrow_mut()
        .remove(&PathBuf::from("/etc/NetworkManager/NetworkManager.conf"));
    let mut b = backend(&sim);
    let o = b.observe("linux.computer_name_sent").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, NO_NETWORK_MANAGER);
    assert!(b
        .write("linux.computer_name_sent", &json!({"items": {"sends": 0}}))
        .is_err());
    assert!(!sim.has(NM_NAME_FILE));
}

#[test]
fn a_setting_the_network_program_does_not_know_is_left_alone() {
    let sim = ubuntu();
    sim.file(
        "/etc/NetworkManager/conf.d/50-site.conf",
        "[connection]\nipv4.dhcp-send-hostname=sometimes\n",
    );
    let o = backend(&sim).observe("linux.computer_name_sent").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, UNRECOGNISED);
}

#[test]
fn a_later_file_that_sends_the_name_again_is_reported_and_our_file_is_taken_out() {
    let sim = ubuntu();
    sim.file(
        "/etc/NetworkManager/conf.d/99-site.conf",
        "[connection]\nipv4.dhcp-send-hostname=true\n",
    );
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let err = b
        .write("linux.computer_name_sent", &json!({"items": {"sends": 0}}))
        .unwrap_err();
    assert_eq!(err.to_string(), CHANGE_FAILED);
    assert_same(&sim, &before);
    assert!(!sim.ran(RELOAD_NM));
}

#[test]
fn a_name_that_one_file_already_stopped_sending_is_read_as_protected() {
    let sim = ubuntu();
    sim.file(
        "/etc/NetworkManager/conf.d/50-site.conf",
        "[connection]\nipv4.dhcp-send-hostname=no\nipv6.dhcp-send-hostname=0\n",
    );
    let mut b = backend(&sim);
    assert_eq!(
        status(&mut b, "linux.computer_name_sent"),
        CheckStatus::Compliant
    );
}

#[test]
fn website_lookups_read_as_not_scrambled_on_every_install() {
    for sim in [
        resolved(ubuntu()),
        resolved(fedora()),
        resolved(linuxmint()),
    ] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.encrypted_dns"),
            json!({"items": {"dns_over_tls": "no"}})
        );
        assert_eq!(
            status(&mut b, "linux.encrypted_dns"),
            CheckStatus::Attention
        );
    }
}

#[test]
fn website_lookups_are_not_offered_without_the_built_in_resolver() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.encrypted_dns"),
        json!({"items": {"dns_over_tls": null}})
    );
    assert_eq!(
        status(&mut b, "linux.encrypted_dns"),
        CheckStatus::Compliant
    );
    let sim = ubuntu();
    sim.unit("systemd-resolved.service", "enabled", false);
    assert_eq!(
        value(&mut backend(&sim), "linux.encrypted_dns"),
        json!({"items": {"dns_over_tls": null}})
    );
}

#[test]
fn website_lookups_are_scrambled_by_a_file_of_their_own_and_the_resolver_is_restarted() {
    for sim in [
        resolved(ubuntu()),
        resolved(fedora()),
        resolved(linuxmint()),
    ] {
        let before = snapshot(&sim);
        assert!(sim.get(FOLDER).is_empty());
        let (was, fixed) = cycle(&sim, "linux.encrypted_dns");
        assert_eq!(was, json!({"items": {"dns_over_tls": "no"}}));
        assert_eq!(fixed, json!({"items": {"dns_over_tls": "opportunistic"}}));
        assert_same(&sim, &before);
        assert!(
            sim.get(FOLDER).is_empty(),
            "the folder Secblitz made is gone"
        );
        assert!(!sim.has("/var/lib/secblitz/Linux/llmnr-folder.txt"));
        assert!(sim.ran(RESTART_RESOLVED));
    }
    let sim = resolved(ubuntu());
    cycle_fixed(&sim, "linux.encrypted_dns");
    assert_eq!(
        sim.text(DOT_FILE).unwrap(),
        format!("{NOTE}[Resolve]\nDNSOverTLS=opportunistic\n")
    );
}

#[test]
fn the_running_value_is_read_back_after_the_resolver_restarts() {
    let sim = resolved(fedora());
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.encrypted_dns");
    let fixed = json!({"items": {"dns_over_tls": "opportunistic"}});
    b.write("linux.encrypted_dns", &fixed).unwrap();
    assert_eq!(sim.get("resolved.dot.running"), "opportunistic");
    b.write("linux.encrypted_dns", &was).unwrap();
    assert_eq!(sim.get("resolved.dot.running"), "built");
    assert_eq!(value(&mut b, "linux.encrypted_dns"), was);
}

#[test]
fn an_undo_whose_restart_never_happened_does_not_read_as_done() {
    let sim = resolved(fedora());
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.encrypted_dns");
    b.write(
        "linux.encrypted_dns",
        &json!({"items": {"dns_over_tls": "opportunistic"}}),
    )
    .unwrap();
    sim.fail("/usr/bin/systemctl try-restart");
    assert!(b.write("linux.encrypted_dns", &was).is_err());
    assert_eq!(sim.get("resolved.dot.running"), "opportunistic");
}

#[test]
fn the_resolver_folder_is_made_when_missing_and_kept_when_it_was_there() {
    let sim = resolved(fedora());
    sim.set(FOLDER, "1");
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.encrypted_dns");
    b.write(
        "linux.encrypted_dns",
        &json!({"items": {"dns_over_tls": "opportunistic"}}),
    )
    .unwrap();
    b.write("linux.encrypted_dns", &was).unwrap();
    assert!(!sim.get(FOLDER).is_empty(), "a folder that was there stays");
}

#[test]
fn the_shared_folder_goes_only_when_the_last_resolver_file_is_gone() {
    for dns_first in [true, false] {
        let sim = resolved(fedora());
        let mut b = backend(&sim);
        let llmnr_was = value(&mut b, "linux.llmnr");
        let dns_was = value(&mut b, "linux.encrypted_dns");
        let llmnr_fixed = json!({"items": {"llmnr": "no"}});
        let dns_fixed = json!({"items": {"dns_over_tls": "opportunistic"}});
        if dns_first {
            b.write("linux.encrypted_dns", &dns_fixed).unwrap();
            b.write("linux.llmnr", &llmnr_fixed).unwrap();
        } else {
            b.write("linux.llmnr", &llmnr_fixed).unwrap();
            b.write("linux.encrypted_dns", &dns_fixed).unwrap();
        }
        assert!(sim.has(LLMNR_FILE) && sim.has(DOT_FILE));
        assert!(!sim.get(FOLDER).is_empty());
        let (first, first_was, second, second_was) = if dns_first {
            ("linux.encrypted_dns", &dns_was, "linux.llmnr", &llmnr_was)
        } else {
            ("linux.llmnr", &llmnr_was, "linux.encrypted_dns", &dns_was)
        };
        b.write(first, first_was).unwrap();
        assert!(
            !sim.get(FOLDER).is_empty(),
            "the folder stays while the other file is in it"
        );
        assert!(
            sim.has("/var/lib/secblitz/Linux/llmnr-folder.txt"),
            "the note that Secblitz made it stays"
        );
        assert!(sim.has(LLMNR_FILE) || sim.has(DOT_FILE));
        b.write(second, second_was).unwrap();
        assert!(sim.get(FOLDER).is_empty(), "dns_first={dns_first}");
        assert!(!sim.has("/var/lib/secblitz/Linux/llmnr-folder.txt"));
        assert!(!sim.has(LLMNR_FILE) && !sim.has(DOT_FILE));
    }
}

#[test]
fn a_later_file_that_turns_scrambling_off_is_reported_and_everything_is_taken_back() {
    let sim = resolved(fedora());
    sim.file(
        "/etc/systemd/resolved.conf.d/99-site.conf",
        "[Resolve]\nDNSOverTLS=no\n",
    );
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let err = b
        .write(
            "linux.encrypted_dns",
            &json!({"items": {"dns_over_tls": "opportunistic"}}),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), CHANGE_FAILED);
    assert_same(&sim, &before);
    assert_eq!(sim.get("resolved.dot.running"), "no");
}

#[test]
fn a_failed_restart_is_reported_and_leaves_no_file_of_ours() {
    let sim = resolved(fedora());
    sim.fail("/usr/bin/systemctl try-restart");
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let err = b
        .write(
            "linux.encrypted_dns",
            &json!({"items": {"dns_over_tls": "opportunistic"}}),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), CHANGE_FAILED);
    assert_same(&sim, &before);
    assert!(sim.get(FOLDER).is_empty());
}

#[test]
fn website_lookups_are_read_the_way_the_resolver_reads_them() {
    let sim = resolved(ubuntu());
    let mut b = backend(&sim);
    let word = |b: &mut LinuxBackend<Sim>| item(b, "linux.encrypted_dns", "dns_over_tls");
    sim.file(
        "/etc/systemd/resolved.conf",
        "[Resolve]\n#DNSOverTLS=yes\nDNSOverTLS=opportunistic\n",
    );
    assert_eq!(word(&mut b), json!("opportunistic"));
    assert_eq!(
        status(&mut b, "linux.encrypted_dns"),
        CheckStatus::Compliant
    );
    sim.file(
        "/usr/lib/systemd/resolved.conf.d/10-vendor.conf",
        "[Resolve]\nDNSOverTLS=true\n",
    );
    assert_eq!(word(&mut b), json!("yes"));
    sim.file(
        "/etc/systemd/resolved.conf.d/20-site.conf",
        "[Resolve]\nDNSOverTLS=off\n",
    );
    assert_eq!(word(&mut b), json!("no"));
}

#[test]
fn a_lookup_setting_the_resolver_does_not_know_is_left_alone() {
    let sim = resolved(ubuntu());
    sim.file(
        "/etc/systemd/resolved.conf",
        "[Resolve]\nDNSOverTLS=maybe\n",
    );
    let o = backend(&sim).observe("linux.encrypted_dns").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, UNRECOGNISED);
}

#[test]
fn only_the_known_words_are_accepted_for_website_lookups() {
    let s = spec("linux.encrypted_dns").unwrap();
    for word in ["yes", "opportunistic", "no"] {
        s.validate(&json!({"items": {"dns_over_tls": word}}))
            .unwrap();
    }
    for bad in ["maybe", "Yes", "no\nyes", "true"] {
        assert!(
            s.validate(&json!({"items": {"dns_over_tls": bad}}))
                .is_err(),
            "{bad}"
        );
    }
    assert!(!s.any_unsafe(&json!({"items": {"dns_over_tls": "yes"}})));
    assert!(s.any_unsafe(&json!({"items": {"dns_over_tls": "no"}})));
    let mut b = backend(&resolved(fedora()));
    assert!(b
        .write(
            "linux.encrypted_dns",
            &json!({"items": {"dns_over_tls": "yes"}})
        )
        .is_err());
}

#[test]
fn announcing_reads_as_on_on_every_install_with_the_announcer_running() {
    for sim in [avahi(ubuntu()), avahi(fedora()), avahi(linuxmint())] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.announce_name"),
            json!({"items": {"announcing": 1}})
        );
        assert_eq!(
            status(&mut b, "linux.announce_name"),
            CheckStatus::Attention
        );
    }
}

#[test]
fn announcing_is_not_offered_when_the_announcer_is_off_or_missing() {
    let mut b = backend(&ubuntu());
    assert_eq!(
        value(&mut b, "linux.announce_name"),
        json!({"items": {"announcing": null}})
    );
    let sim = ubuntu();
    sim.unit("avahi-daemon.service", "disabled", false);
    assert_eq!(
        value(&mut backend(&sim), "linux.announce_name"),
        json!({"items": {"announcing": null}})
    );
    let sim = avahi(ubuntu());
    sim.files.borrow_mut().remove(&PathBuf::from(AVAHI_FILE));
    assert_eq!(
        status(&mut backend(&sim), "linux.announce_name"),
        CheckStatus::Compliant
    );
}

#[test]
fn announcing_is_switched_off_with_one_line_and_put_back_byte_for_byte() {
    for sim in [avahi(ubuntu()), avahi(fedora()), avahi(linuxmint())] {
        let before = snapshot(&sim);
        let original = sim.text(AVAHI_FILE).unwrap();
        let (was, fixed) = cycle(&sim, "linux.announce_name");
        assert_eq!(was, json!({"items": {"announcing": 1}}));
        assert_eq!(fixed, json!({"items": {"announcing": 0}}));
        assert_same(&sim, &before);
        assert_eq!(sim.text(AVAHI_FILE).unwrap(), original);
        assert!(sim.ran(RESTART_AVAHI));
    }
    let sim = avahi(ubuntu());
    let original = sim.text(AVAHI_FILE).unwrap();
    cycle_fixed(&sim, "linux.announce_name");
    let now = sim.text(AVAHI_FILE).unwrap();
    assert_eq!(
        now,
        original.replace(
            "publish-workstation=no\n",
            "publish-workstation=no\ndisable-publishing=yes\n"
        )
    );
}

#[test]
fn an_edit_someone_else_made_to_the_announcer_file_is_not_overwritten_by_the_undo() {
    let sim = avahi(fedora());
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.announce_name");
    b.write("linux.announce_name", &json!({"items": {"announcing": 0}}))
        .unwrap();
    sim.file(
        AVAHI_FILE,
        &format!("{}\n[server]\nuse-ipv6=no\n", sim.text(AVAHI_FILE).unwrap()),
    );
    let edited = snapshot(&sim);
    let err = b.write("linux.announce_name", &was).unwrap_err();
    assert_eq!(err.to_string(), UNRECOGNISED);
    assert_same(&sim, &edited);
}

#[test]
fn a_failed_announcer_restart_puts_the_original_file_back() {
    let sim = avahi(ubuntu());
    sim.fail(RESTART_AVAHI);
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let err = b
        .write("linux.announce_name", &json!({"items": {"announcing": 0}}))
        .unwrap_err();
    assert_eq!(err.to_string(), CHANGE_FAILED);
    assert_same(&sim, &before);
}

#[test]
fn announcing_that_is_already_off_is_left_alone() {
    let sim = avahi(ubuntu());
    set_file(&sim, AVAHI_FILE, |t| {
        t.replace("#disable-publishing=no", "disable-publishing=yes")
    });
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    assert_eq!(
        status(&mut b, "linux.announce_name"),
        CheckStatus::Compliant
    );
    b.write("linux.announce_name", &json!({"items": {"announcing": 0}}))
        .unwrap();
    assert_same(&sim, &before);
    assert!(!sim.ran(RESTART_AVAHI));
}

fn old_services(sim: &Sim) {
    sim.unit("telnet.socket", "enabled", true)
        .unit("vsftpd.service", "enabled", true)
        .unit("rpcbind.socket", "disabled", false)
        .unit("rpcbind.service", "indirect", true)
        .unit("snmpd.service", "disabled", false)
        .unit("sshd.service", "enabled", true);
}

#[test]
fn old_services_that_are_not_installed_or_not_on_read_as_protected() {
    for sim in [ubuntu(), linuxmint()] {
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.old_network_services"),
            json!({"items": {"enabled": 0}})
        );
        assert_eq!(
            status(&mut b, "linux.old_network_services"),
            CheckStatus::Compliant
        );
    }
    let sim = fedora();
    sim.unit("rpcbind.service", "disabled", false)
        .unit("rpcbind.socket", "disabled", false)
        .unit("nfs-server.service", "disabled", false);
    assert_eq!(
        status(&mut backend(&sim), "linux.old_network_services"),
        CheckStatus::Compliant
    );
}

#[test]
fn old_services_are_stopped_and_switched_off_and_each_state_is_put_back() {
    let sim = fedora();
    old_services(&sim);
    let before = snapshot(&sim);
    let units = sim.units.borrow().clone();
    let (was, fixed) = cycle(&sim, "linux.old_network_services");
    assert_eq!(was, json!({"items": {"enabled": 1}}));
    assert_eq!(fixed, json!({"items": {"enabled": 0}}));
    assert_eq!(*sim.units.borrow(), units);
    assert_same(&sim, &before);
    for call in [
        "/usr/bin/systemctl disable --now telnet.socket",
        "/usr/bin/systemctl disable --now vsftpd.service",
        "/usr/bin/systemctl stop rpcbind.service",
    ] {
        assert!(sim.ran(call), "{call}");
    }
}

#[test]
fn units_that_are_not_on_the_list_or_not_on_are_never_touched() {
    let sim = fedora();
    old_services(&sim);
    cycle(&sim, "linux.old_network_services");
    for untouched in ["sshd.service", "snmpd.service", "rpcbind.socket"] {
        assert!(
            !sim.calls
                .borrow()
                .iter()
                .any(|c| c.contains(&format!(" {untouched}")) && !c.contains("is-")),
            "{untouched}"
        );
    }
}

#[test]
fn an_old_service_that_only_started_after_the_fix_is_not_switched_on_by_the_undo() {
    let sim = fedora();
    old_services(&sim);
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.old_network_services");
    b.write(
        "linux.old_network_services",
        &json!({"items": {"enabled": 0}}),
    )
    .unwrap();
    sim.unit("snmpd.service", "enabled", true);
    b.write("linux.old_network_services", &was).unwrap();
    assert_eq!(sim.state("snmpd.service"), ("enabled".into(), true));
    assert_eq!(sim.state("telnet.socket"), ("enabled".into(), true));
}

#[test]
fn a_record_that_names_a_unit_outside_the_list_is_refused() {
    let sim = fedora();
    old_services(&sim);
    let mut b = backend(&sim);
    let was = value(&mut b, "linux.old_network_services");
    b.write(
        "linux.old_network_services",
        &json!({"items": {"enabled": 0}}),
    )
    .unwrap();
    sim.file(
        "/var/lib/secblitz/Linux/old_network_services.txt",
        "sshd.service 1 1\n",
    );
    let calls = sim.calls.borrow().len();
    assert!(b.write("linux.old_network_services", &was).is_err());
    assert_eq!(sim.calls.borrow().len(), calls);
    let mut b = backend(&fedora());
    let err = b
        .write(
            "linux.old_network_services",
            &json!({"items": {"enabled": 1}}),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), NO_RECORD);
}

#[test]
fn the_engine_fixes_and_undoes_all_nine_through_the_journal() {
    let sim = avahi(resolved(fedora()));
    old_services(&sim);
    for name in ["all", "default", "enp1s0"] {
        set_proc(&sim, &format!("net/ipv4/conf/{name}/rp_filter"), "0");
    }
    open_source_routes(&sim);
    set_proc(&sim, "net/ipv4/tcp_syncookies", "0");
    set_proc(&sim, "net/ipv4/icmp_echo_ignore_broadcasts", "0");
    let dir = tempfile::tempdir().unwrap();
    let notes = dir.path().join(crate::platform::LINUX_NOTES);
    std::fs::create_dir(&notes).unwrap();
    let mut engine =
        Engine::open_for(Os::Linux, dir.path().to_path_buf(), Box::new(backend(&sim))).unwrap();
    let ids: Vec<String> = [
        "linux.fake_sources",
        "linux.flood_protection",
        "linux.source_routing",
        "linux.broadcast_pings",
        "linux.ipv6_privacy",
        "linux.computer_name_sent",
        "linux.encrypted_dns",
        "linux.announce_name",
        "linux.old_network_services",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let before = snapshot(&sim);
    let applied = engine.apply_selected(&ids, |_| {}).unwrap();
    for id in &ids {
        let r = applied.results.iter().find(|r| &r.id == id).unwrap();
        assert_eq!(r.status, CheckStatus::Applied, "{id}: {}", r.detail);
    }
    let undone = engine.revert(|_| {}).unwrap();
    for id in &ids {
        let r = undone.results.iter().find(|r| &r.id == id).unwrap();
        assert_eq!(r.status, CheckStatus::Restored, "{id}: {}", r.detail);
    }
    assert_same(&sim, &before);
    assert_eq!(
        item(&mut backend(&sim), "linux.encrypted_dns", "dns_over_tls"),
        json!("no")
    );
    assert!(sim.get(FOLDER).is_empty());
}
