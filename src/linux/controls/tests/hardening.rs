//! The memory, crash, protocol, processor and account protections against the recorded installs.

use super::*;
use crate::linux::controls::hardening as h;
use std::collections::BTreeMap;
use std::path::PathBuf;

const SHUFFLE_FILE: &str = "/etc/sysctl.d/90-secblitz-memory-shuffle.conf";
const BPF_FILE: &str = "/etc/sysctl.d/90-secblitz-bpf.conf";
const TERMINAL_FILE: &str = "/etc/sysctl.d/90-secblitz-terminal-drivers.conf";
const DUMP_FILE: &str = "/etc/sysctl.d/90-secblitz-crash-memory.conf";
const SANDBOX_FILE: &str = "/etc/sysctl.d/90-secblitz-app-sandbox.conf";
const COREDUMP_FOLDER: &str = "/etc/systemd/coredump.conf.d";
const COREDUMP_FILE: &str = "/etc/systemd/coredump.conf.d/90-secblitz.conf";
const RARE_FILE: &str = "/etc/modprobe.d/90-secblitz-rare-network.conf";
const NOTE: &str = "# Written by Secblitz. Delete this file to go back to how it was.\n";

const IDS: [&str; 9] = [
    "linux.memory_shuffle",
    "linux.bpf_hardening",
    "linux.terminal_drivers",
    "linux.crash_memory",
    "linux.crash_files",
    "linux.rare_protocols",
    "linux.app_sandbox_limits",
    "linux.processor_updates",
    "linux.root_account",
];

/// The programs and packages these controls use, as the recorded installs have them.
fn ready(sim: Sim, family: &str) -> Sim {
    for tool in [
        "/usr/sbin/modinfo",
        "/usr/bin/passwd",
        "/usr/bin/dpkg-query",
        "/usr/bin/apt-get",
        "/usr/bin/rpm",
        "/usr/bin/dnf",
    ] {
        sim.tool(tool);
    }
    if family == "fedora" {
        sim.package("microcode_ctl", true, "");
        sim.package("linux-firmware", true, "");
    } else {
        sim.package("amd64-microcode", true, "");
        sim.package("intel-microcode", true, "");
    }
    sim
}

fn ubuntu_h() -> Sim {
    ready(ubuntu(), "debian")
}

fn fedora_h() -> Sim {
    ready(fedora(), "fedora")
}

fn mint_h() -> Sim {
    ready(linuxmint(), "debian")
}

fn snapshot(sim: &Sim) -> BTreeMap<PathBuf, String> {
    sim.files
        .borrow()
        .iter()
        .map(|(p, b)| (p.clone(), String::from_utf8_lossy(b).into_owned()))
        .collect()
}

fn folders(sim: &Sim) -> Vec<String> {
    sim.kv
        .borrow()
        .keys()
        .filter(|k| k.starts_with("dir:"))
        .cloned()
        .collect()
}

fn packages(sim: &Sim) -> BTreeMap<String, String> {
    sim.kv
        .borrow()
        .iter()
        .filter(|(k, _)| k.starts_with("pkg:"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn assert_same(sim: &Sim, before: &BTreeMap<PathBuf, String>) {
    let now = snapshot(sim);
    for path in before.keys().chain(now.keys()) {
        assert_eq!(before.get(path), now.get(path), "{}", path.display());
    }
}

fn fixed_value(b: &mut LinuxBackend<Sim>, id: &str) -> Value {
    let before = value(b, id);
    spec(id).unwrap().derive_target(&before).unwrap()
}

fn proc_number(sim: &Sim, path: &str) -> String {
    sim.text(&format!("/proc/sys/{path}"))
        .unwrap()
        .trim()
        .to_string()
}

fn set_proc(sim: &Sim, path: &str, value: &str) {
    sim.file(&format!("/proc/sys/{path}"), &format!("{value}\n"));
}

fn lock_root_open(sim: &Sim) {
    let text = sim.text("/etc/shadow").unwrap();
    sim.file(
        "/etc/shadow",
        &text.replacen("root:!:", "root:$y$j9T$rootplaceholder:", 1),
    );
}

#[test]
fn the_new_controls_are_system_controls_and_only_the_root_account_is_optional() {
    for id in IDS {
        let s = spec(id).unwrap();
        assert_eq!(s.scope, Scope::System, "{id}");
        assert_eq!(s.ask, id == "linux.root_account", "{id}");
        assert!(!s.reboot, "{id}");
    }
}

#[test]
fn each_distribution_lists_only_the_controls_that_mean_something_there() {
    let listed = |sim: &Sim| {
        backend(sim)
            .controls()
            .into_iter()
            .map(|c| c.id)
            .filter(|id| IDS.contains(&id.as_str()))
            .collect::<Vec<_>>()
    };
    let ubuntu = listed(&ubuntu_h());
    let fedora = listed(&fedora_h());
    let mint = listed(&mint_h());
    assert_eq!(ubuntu.len(), 8);
    assert!(ubuntu.contains(&"linux.app_sandbox_limits".to_string()));
    assert!(!ubuntu.contains(&"linux.crash_files".to_string()));
    assert_eq!(fedora.len(), 8);
    assert!(fedora.contains(&"linux.crash_files".to_string()));
    assert!(!fedora.contains(&"linux.app_sandbox_limits".to_string()));
    assert_eq!(mint.len(), 8);
    assert!(mint.contains(&"linux.crash_files".to_string()));
    assert!(!mint.contains(&"linux.app_sandbox_limits".to_string()));
}

/// What each recorded install shows for each control, with whether it may be touched at all.
#[test]
fn every_control_reads_as_each_recorded_install_has_it() {
    use CheckStatus::{Attention as A, Compliant as C};
    type Row = Option<(CheckStatus, bool)>;
    let table: [(&str, [Row; 3]); 9] = [
        (
            "linux.memory_shuffle",
            [Some((C, true)), Some((C, true)), Some((C, true))],
        ),
        (
            "linux.bpf_hardening",
            [Some((A, true)), Some((A, true)), Some((A, true))],
        ),
        (
            "linux.terminal_drivers",
            [Some((C, true)), Some((A, true)), Some((A, true))],
        ),
        (
            "linux.crash_memory",
            [Some((A, false)), Some((A, true)), Some((A, true))],
        ),
        (
            "linux.crash_files",
            [None, Some((A, true)), Some((A, true))],
        ),
        (
            "linux.rare_protocols",
            [Some((A, true)), Some((A, true)), Some((A, true))],
        ),
        ("linux.app_sandbox_limits", [Some((C, true)), None, None]),
        (
            "linux.processor_updates",
            [Some((C, true)), Some((C, true)), Some((C, true))],
        ),
        (
            "linux.root_account",
            [Some((C, true)), Some((C, true)), Some((C, true))],
        ),
    ];
    for (id, expected) in table {
        for (sim, row) in [ubuntu_h(), fedora_h(), mint_h()].into_iter().zip(expected) {
            let Some((want, eligible)) = row else {
                let listed = backend(&sim).controls().into_iter().any(|c| c.id == id);
                assert!(!listed, "{id} should not be offered here");
                continue;
            };
            let mut b = backend(&sim);
            let observed = b.observe(id).unwrap();
            assert_eq!(observed.eligible, eligible, "{id}");
            assert_eq!(assessment(id, &observed).unwrap(), want, "{id}");
        }
    }
}

#[test]
fn the_recorded_values_are_what_the_installs_have() {
    let mut u = backend(&ubuntu_h());
    let mut f = backend(&fedora_h());
    let mut m = backend(&mint_h());
    assert_eq!(
        value(&mut u, "linux.bpf_hardening"),
        json!({"items": {"unprivileged_bpf_disabled": 2, "jit_harden": 0}})
    );
    for b in [&mut u, &mut f, &mut m] {
        assert_eq!(
            value(b, "linux.memory_shuffle"),
            json!({"items": {"randomize_va_space": 2}})
        );
        assert_eq!(
            value(b, "linux.crash_memory"),
            json!({"items": {"suid_dumpable": 2}})
        );
        assert_eq!(
            value(b, "linux.processor_updates"),
            json!({"items": {"installed": 1}})
        );
        assert_eq!(
            value(b, "linux.root_account"),
            json!({"items": {"usable": 0}})
        );
    }
    assert_eq!(
        value(&mut u, "linux.terminal_drivers"),
        json!({"items": {"ldisc_autoload": 0}})
    );
    assert_eq!(
        value(&mut f, "linux.terminal_drivers"),
        json!({"items": {"ldisc_autoload": 1}})
    );
    assert_eq!(
        value(&mut u, "linux.app_sandbox_limits"),
        json!({"items": {"restricted": 1}})
    );
    assert_eq!(
        value(&mut f, "linux.app_sandbox_limits"),
        json!({"items": {"restricted": null}})
    );
    assert_eq!(
        value(&mut m, "linux.app_sandbox_limits"),
        json!({"items": {"restricted": 0}})
    );
}

#[test]
fn the_memory_layout_is_fixed_kept_after_a_restart_and_put_back() {
    for weak in ["0", "1"] {
        let sim = ubuntu_h();
        set_proc(&sim, "kernel/randomize_va_space", weak);
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.memory_shuffle");
        assert_eq!(
            was,
            json!({"items": {"randomize_va_space": weak.parse::<u32>().unwrap()}})
        );
        assert_eq!(fixed, json!({"items": {"randomize_va_space": 2}}));
        assert!(sim.ran("/usr/sbin/sysctl -w kernel.randomize_va_space=2"));
        assert_same(&sim, &before);

        let mut b = backend(&sim);
        b.write("linux.memory_shuffle", &fixed).unwrap();
        assert_eq!(
            sim.text(SHUFFLE_FILE).unwrap(),
            format!("{NOTE}kernel.randomize_va_space = 2\n")
        );
        sim.restart_computer();
        assert_eq!(
            status(&mut b, "linux.memory_shuffle"),
            CheckStatus::Compliant
        );
        b.write("linux.memory_shuffle", &was).unwrap();
        assert!(!sim.has(SHUFFLE_FILE));
        assert_same(&sim, &before);
    }
}

#[test]
fn a_computer_that_is_already_fine_is_left_without_a_file() {
    let sim = fedora_h();
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.memory_shuffle");
    b.write("linux.memory_shuffle", &fixed).unwrap();
    assert!(!sim.has(SHUFFLE_FILE));
    assert!(!sim.ran("/usr/sbin/sysctl -w kernel.randomize_va_space=2"));
}

#[test]
fn the_bpf_fix_hardens_the_compiler_and_never_touches_the_switch_that_is_already_shut() {
    for sim in [ubuntu_h(), fedora_h(), mint_h()] {
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.bpf_hardening");
        assert_eq!(
            was,
            json!({"items": {"unprivileged_bpf_disabled": 2, "jit_harden": 0}})
        );
        assert_eq!(
            fixed,
            json!({"items": {"unprivileged_bpf_disabled": 2, "jit_harden": 2}})
        );
        assert!(sim.ran("/usr/sbin/sysctl -w net.core.bpf_jit_harden=2"));
        assert!(!sim
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("unprivileged_bpf_disabled")));
        assert_same(&sim, &before);
        let mut b = backend(&sim);
        b.write("linux.bpf_hardening", &fixed).unwrap();
        assert_eq!(
            sim.text(BPF_FILE).unwrap(),
            format!("{NOTE}net.core.bpf_jit_harden = 2\n")
        );
    }
}

#[test]
fn a_switch_that_was_shut_for_good_is_only_ever_read() {
    let sim = ubuntu_h();
    set_proc(&sim, "kernel/unprivileged_bpf_disabled", "1");
    let before = snapshot(&sim);
    let (was, fixed) = cycle(&sim, "linux.bpf_hardening");
    assert_eq!(
        was,
        json!({"items": {"unprivileged_bpf_disabled": 1, "jit_harden": 0}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"unprivileged_bpf_disabled": 1, "jit_harden": 2}})
    );
    assert!(!sim
        .calls
        .borrow()
        .iter()
        .any(|c| c.contains("unprivileged_bpf_disabled")));
    assert_same(&sim, &before);
}

#[test]
fn an_open_bpf_switch_is_moved_to_the_value_that_can_be_taken_back() {
    let sim = fedora_h();
    set_proc(&sim, "kernel/unprivileged_bpf_disabled", "0");
    let before = snapshot(&sim);
    let (was, fixed) = cycle(&sim, "linux.bpf_hardening");
    assert_eq!(
        was,
        json!({"items": {"unprivileged_bpf_disabled": 0, "jit_harden": 0}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"unprivileged_bpf_disabled": 2, "jit_harden": 2}})
    );
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.unprivileged_bpf_disabled=2"));
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.unprivileged_bpf_disabled=0"));
    assert!(!sim.ran("/usr/sbin/sysctl -w kernel.unprivileged_bpf_disabled=1"));
    assert_same(&sim, &before);
}

#[test]
fn shutting_the_bpf_switch_for_good_is_refused() {
    let sim = ubuntu_h();
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let wanted = json!({"items": {"unprivileged_bpf_disabled": 1, "jit_harden": 2}});
    let e = b.write("linux.bpf_hardening", &wanted).unwrap_err();
    assert_eq!(e.to_string(), UNRECOGNISED);
    assert_same(&sim, &before);
    assert!(!sim.ran("/usr/sbin/sysctl -w kernel.unprivileged_bpf_disabled=1"));
}

#[test]
fn old_terminal_drivers_are_closed_kept_and_opened_again() {
    for sim in [fedora_h(), mint_h()] {
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.terminal_drivers");
        assert_eq!(was, json!({"items": {"ldisc_autoload": 1}}));
        assert_eq!(fixed, json!({"items": {"ldisc_autoload": 0}}));
        assert!(sim.ran("/usr/sbin/sysctl -w dev.tty.ldisc_autoload=0"));
        assert_same(&sim, &before);
        let mut b = backend(&sim);
        b.write("linux.terminal_drivers", &fixed).unwrap();
        assert_eq!(
            sim.text(TERMINAL_FILE).unwrap(),
            format!("{NOTE}dev.tty.ldisc_autoload = 0\n")
        );
        sim.restart_computer();
        assert_eq!(proc_number(&sim, "dev/tty/ldisc_autoload"), "0");
        b.write("linux.terminal_drivers", &was).unwrap();
        sim.restart_computer();
        assert_eq!(proc_number(&sim, "dev/tty/ldisc_autoload"), "1");
    }
}

#[test]
fn memory_of_crashed_programs_is_fixed_and_wins_over_the_systems_own_file_at_the_next_start() {
    for sim in [fedora_h(), mint_h()] {
        let before = snapshot(&sim);
        let (was, fixed) = cycle(&sim, "linux.crash_memory");
        assert_eq!(was, json!({"items": {"suid_dumpable": 2}}));
        assert_eq!(fixed, json!({"items": {"suid_dumpable": 0}}));
        assert_same(&sim, &before);

        let mut b = backend(&sim);
        b.write("linux.crash_memory", &fixed).unwrap();
        assert_eq!(
            sim.text(DUMP_FILE).unwrap(),
            format!("{NOTE}fs.suid_dumpable = 0\n")
        );
        sim.restart_computer();
        assert_eq!(proc_number(&sim, "fs/suid_dumpable"), "0");
        assert_eq!(status(&mut b, "linux.crash_memory"), CheckStatus::Compliant);
        b.write("linux.crash_memory", &was).unwrap();
        sim.restart_computer();
        assert_eq!(proc_number(&sim, "fs/suid_dumpable"), "2");
        assert_same(&sim, &before);
    }
}

#[test]
fn ubuntus_crash_reports_set_their_own_value_after_the_files_so_the_check_does_not_touch_it() {
    let sim = ubuntu_h();
    let mut b = backend(&sim);
    let observed = b.observe("linux.crash_memory").unwrap();
    assert!(!observed.eligible);
    assert_eq!(observed.reason, h::CRASH_REPORTS_NEED_IT);
    assert!(skipped(&mut b, "linux.crash_memory"));

    // What would happen if a file were written anyway: the reports set 2 again when they start.
    sim.file(DUMP_FILE, &format!("{NOTE}fs.suid_dumpable = 0\n"));
    set_proc(&sim, "fs/suid_dumpable", "0");
    sim.restart_computer();
    assert_eq!(proc_number(&sim, "fs/suid_dumpable"), "2");
}

#[test]
fn with_crash_reports_off_the_memory_check_applies_to_ubuntu_too() {
    let sim = ubuntu_h();
    sim.file("/etc/default/apport", "enabled=0\n");
    sim.unit("apport.service", "disabled", false);
    set_proc(&sim, "kernel/core_pattern", "core");
    let mut b = backend(&sim);
    assert!(b.observe("linux.crash_memory").unwrap().eligible);
    let before = snapshot(&sim);
    let (was, fixed) = cycle(&sim, "linux.crash_memory");
    assert_eq!(was, json!({"items": {"suid_dumpable": 2}}));
    assert_eq!(fixed, json!({"items": {"suid_dumpable": 0}}));
    assert_same(&sim, &before);
    b.write("linux.crash_memory", &fixed).unwrap();
    sim.restart_computer();
    assert_eq!(proc_number(&sim, "fs/suid_dumpable"), "0");
}

#[test]
fn a_file_read_later_that_sets_the_value_again_stops_the_fix_before_anything_changes() {
    for (file, line) in [
        ("/etc/sysctl.d/99-local.conf", "fs.suid_dumpable = 2\n"),
        ("/etc/sysctl.d/99-local.conf", "fs/suid_dumpable=1\n"),
        ("/usr/lib/sysctl.d/99-vendor.conf", "fs.suid_dumpable=2\n"),
        ("/etc/sysctl.conf", "fs.suid_dumpable=2\n"),
    ] {
        let sim = fedora_h();
        sim.file(file, line);
        let before = snapshot(&sim);
        let mut b = backend(&sim);
        let fixed = fixed_value(&mut b, "linux.crash_memory");
        let e = b.write("linux.crash_memory", &fixed).unwrap_err();
        assert_eq!(e.to_string(), h::OVERRIDDEN, "{file} {line}");
        assert_same(&sim, &before);
        assert!(!sim.ran("/usr/sbin/sysctl -w fs.suid_dumpable=0"));
    }
}

#[test]
fn a_later_file_that_agrees_or_comes_earlier_does_not_stop_the_fix() {
    for (file, line) in [
        ("/etc/sysctl.d/99-local.conf", "fs.suid_dumpable = 0\n"),
        ("/etc/sysctl.d/99-local.conf", "# fs.suid_dumpable = 2\n"),
        ("/etc/sysctl.d/10-local.conf", "fs.suid_dumpable = 1\n"),
        ("/etc/sysctl.d/99-local.conf", "kernel.sysrq = 1\n"),
    ] {
        let sim = fedora_h();
        sim.file(file, line);
        let mut b = backend(&sim);
        let fixed = fixed_value(&mut b, "linux.crash_memory");
        b.write("linux.crash_memory", &fixed).unwrap();
        assert_eq!(proc_number(&sim, "fs/suid_dumpable"), "0", "{file} {line}");
    }
}

#[test]
fn a_symbolic_link_in_the_settings_folder_is_read_through_the_old_main_file() {
    let sim = fedora_h();
    sim.file("/etc/sysctl.d/99-sysctl.conf", "");
    sim.set("link:/etc/sysctl.d/99-sysctl.conf", "1");
    sim.file("/etc/sysctl.conf", "fs.suid_dumpable = 1\n");
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.crash_memory");
    let e = b.write("linux.crash_memory", &fixed).unwrap_err();
    assert_eq!(e.to_string(), h::OVERRIDDEN);
}

#[test]
fn the_sandbox_rule_is_fixed_kept_and_put_back_on_ubuntu() {
    let sim = ubuntu_h();
    set_proc(&sim, "kernel/apparmor_restrict_unprivileged_userns", "0");
    let before = snapshot(&sim);
    let (was, fixed) = cycle(&sim, "linux.app_sandbox_limits");
    assert_eq!(was, json!({"items": {"restricted": 0}}));
    assert_eq!(fixed, json!({"items": {"restricted": 1}}));
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.apparmor_restrict_unprivileged_userns=1"));
    assert_same(&sim, &before);
    let mut b = backend(&sim);
    b.write("linux.app_sandbox_limits", &fixed).unwrap();
    assert_eq!(
        sim.text(SANDBOX_FILE).unwrap(),
        format!("{NOTE}kernel.apparmor_restrict_unprivileged_userns = 1\n")
    );
    sim.restart_computer();
    assert_eq!(
        proc_number(&sim, "kernel/apparmor_restrict_unprivileged_userns"),
        "1"
    );
}

#[test]
fn linux_mint_and_fedora_are_never_offered_the_sandbox_rule() {
    for sim in [mint_h(), fedora_h()] {
        let ids: Vec<String> = backend(&sim).controls().into_iter().map(|c| c.id).collect();
        assert!(!ids.contains(&"linux.app_sandbox_limits".to_string()));
    }
    let mint = mint_h();
    assert_eq!(
        proc_number(&mint, "kernel/apparmor_restrict_unprivileged_userns"),
        "0"
    );
    assert!(mint.has("/etc/sysctl.d/20-apparmor-mint.conf"));
}

#[test]
fn saved_crash_files_are_stopped_with_a_file_in_a_folder_made_for_it_and_both_go_on_undo() {
    for sim in [fedora_h(), mint_h()] {
        let before = snapshot(&sim);
        let folders_before = folders(&sim);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.crash_files"),
            json!({"items": {"stored": 1}})
        );
        let (was, fixed) = cycle(&sim, "linux.crash_files");
        assert_eq!(fixed, json!({"items": {"stored": 0}}));
        assert_same(&sim, &before);
        assert_eq!(folders(&sim), folders_before);

        b.write("linux.crash_files", &fixed).unwrap();
        assert_eq!(
            sim.text(COREDUMP_FILE).unwrap(),
            format!("{NOTE}[Coredump]\nStorage=none\n")
        );
        assert!(folders(&sim).contains(&format!("dir:{COREDUMP_FOLDER}")));
        assert!(sim.has("/var/lib/secblitz/Linux/coredump-folder.txt"));
        assert_eq!(status(&mut b, "linux.crash_files"), CheckStatus::Compliant);
        b.write("linux.crash_files", &was).unwrap();
        assert!(!sim.has(COREDUMP_FILE));
        assert!(!sim.has("/var/lib/secblitz/Linux/coredump-folder.txt"));
        assert_eq!(folders(&sim), folders_before);
        assert_same(&sim, &before);
    }
}

#[test]
fn a_crash_files_folder_that_was_already_there_stays_and_so_does_what_others_put_in_it() {
    let sim = fedora_h();
    sim.set(&format!("dir:{COREDUMP_FOLDER}"), "1");
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.crash_files");
    b.write("linux.crash_files", &fixed).unwrap();
    assert!(!sim.has("/var/lib/secblitz/Linux/coredump-folder.txt"));
    b.write("linux.crash_files", &json!({"items": {"stored": 1}}))
        .unwrap();
    assert!(folders(&sim).contains(&format!("dir:{COREDUMP_FOLDER}")));

    let sim = fedora_h();
    let mut b = backend(&sim);
    b.write("linux.crash_files", &fixed).unwrap();
    sim.file(
        &format!("{COREDUMP_FOLDER}/50-theirs.conf"),
        "[Coredump]\nCompress=no\n",
    );
    b.write("linux.crash_files", &json!({"items": {"stored": 1}}))
        .unwrap();
    assert!(!sim.has(COREDUMP_FILE));
    assert!(sim.has(&format!("{COREDUMP_FOLDER}/50-theirs.conf")));
    assert!(!sim.has("/var/lib/secblitz/Linux/coredump-folder.txt"));
}

#[test]
fn crash_files_someone_else_already_turned_off_read_as_protected() {
    let sim = fedora_h();
    sim.set(&format!("dir:{COREDUMP_FOLDER}"), "1");
    sim.file(
        &format!("{COREDUMP_FOLDER}/10-theirs.conf"),
        "[Coredump]\nStorage=none\n",
    );
    let mut b = backend(&sim);
    assert_eq!(status(&mut b, "linux.crash_files"), CheckStatus::Compliant);
    sim.file(
        &format!("{COREDUMP_FOLDER}/20-theirs.conf"),
        "[Coredump]\nStorage=journal\n",
    );
    assert_eq!(status(&mut b, "linux.crash_files"), CheckStatus::Attention);
}

#[test]
fn a_later_crash_file_that_keeps_dumps_stops_the_fix_and_leaves_nothing_behind() {
    let sim = fedora_h();
    sim.set(&format!("dir:{COREDUMP_FOLDER}"), "1");
    sim.file(
        &format!("{COREDUMP_FOLDER}/99-keep.conf"),
        "[Coredump]\nStorage=external\n",
    );
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.crash_files");
    let e = b.write("linux.crash_files", &fixed).unwrap_err();
    assert_eq!(e.to_string(), CHANGE_FAILED);
    assert_same(&sim, &before);
}

#[test]
fn a_failed_crash_folder_leaves_nothing_behind() {
    let sim = fedora_h();
    sim.fail("/usr/bin/mkdir");
    let before = snapshot(&sim);
    let folders_before = folders(&sim);
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.crash_files");
    assert!(b.write("linux.crash_files", &fixed).is_err());
    assert_same(&sim, &before);
    assert_eq!(folders(&sim), folders_before);
}

#[test]
fn crash_files_are_only_offered_where_the_system_catcher_handles_crashes() {
    let sim = ubuntu_h();
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.crash_files"),
        json!({"items": {"stored": null}})
    );
    let sim = fedora_h();
    set_proc(&sim, "kernel/core_pattern", "core");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.crash_files"),
        json!({"items": {"stored": null}})
    );
    let sim = fedora_h();
    sim.set(&format!("dir:{COREDUMP_FOLDER}"), "1");
    sim.file(
        &format!("{COREDUMP_FOLDER}/10-odd.conf"),
        "[Coredump]\nStorage=somewhere\n",
    );
    let mut b = backend(&sim);
    assert!(!b.observe("linux.crash_files").unwrap().eligible);
}

#[test]
fn rare_protocols_get_a_file_that_blocks_exactly_what_is_not_blocked_yet() {
    for (sim, lines) in [
        (
            ubuntu_h(),
            "install sctp /bin/false\ninstall tipc /bin/false\n",
        ),
        (
            fedora_h(),
            "install sctp /bin/false\ninstall tipc /bin/false\n",
        ),
        (
            mint_h(),
            "install dccp /bin/false\ninstall sctp /bin/false\ninstall tipc /bin/false\n",
        ),
    ] {
        let before = snapshot(&sim);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.rare_protocols"),
            json!({"items": {"open": 1}})
        );
        let (was, fixed) = cycle(&sim, "linux.rare_protocols");
        assert_eq!(fixed, json!({"items": {"open": 0}}));
        assert_same(&sim, &before);

        b.write("linux.rare_protocols", &fixed).unwrap();
        assert_eq!(sim.text(RARE_FILE).unwrap(), format!("{NOTE}{lines}"));
        assert_eq!(
            status(&mut b, "linux.rare_protocols"),
            CheckStatus::Compliant
        );
        b.write("linux.rare_protocols", &was).unwrap();
        assert!(!sim.has(RARE_FILE));
        assert_same(&sim, &before);
        assert!(!sim
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("sbin/modprobe") || c.contains("rmmod")));
    }
}

#[test]
fn a_protocol_that_is_already_blocked_or_missing_is_left_out_of_the_file() {
    let sim = ubuntu_h();
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.rare_protocols");
    b.write("linux.rare_protocols", &fixed).unwrap();
    let text = sim.text(RARE_FILE).unwrap();
    assert!(
        !text.contains("rds"),
        "Ubuntu turns rds off in its own file"
    );
    assert!(!text.contains("dccp"), "this kernel has no dccp");

    let sim = fedora_h();
    sim.file(
        "/etc/modprobe.d/local.conf",
        "install tipc /bin/true\nblacklist sctp\n",
    );
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.rare_protocols");
    b.write("linux.rare_protocols", &fixed).unwrap();
    assert_eq!(
        sim.text(RARE_FILE).unwrap(),
        format!("{NOTE}install sctp /bin/false\n")
    );
}

#[test]
fn a_protocol_that_is_in_use_is_never_touched() {
    let sim = fedora_h();
    sim.file(
        "/proc/modules",
        "sctp 1024000 3 - Live 0x0000000000000000\nlibcrc32c 12288 1 sctp, Live 0x0\n",
    );
    let mut b = backend(&sim);
    let fixed = fixed_value(&mut b, "linux.rare_protocols");
    b.write("linux.rare_protocols", &fixed).unwrap();
    assert_eq!(
        sim.text(RARE_FILE).unwrap(),
        format!("{NOTE}install tipc /bin/false\n")
    );

    let sim = fedora_h();
    sim.file(
        "/proc/modules",
        "sctp 1 3 - Live 0x0\ntipc 1 0 - Live 0x0\n",
    );
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.rare_protocols"),
        json!({"items": {"open": 0}})
    );
    assert_eq!(
        status(&mut b, "linux.rare_protocols"),
        CheckStatus::Compliant
    );
}

#[test]
fn without_the_module_tool_rare_protocols_are_not_judged() {
    let sim = fedora_h();
    sim.tools.borrow_mut().remove("/usr/sbin/modinfo");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.rare_protocols"),
        json!({"items": {"open": null}})
    );
    assert_eq!(
        status(&mut b, "linux.rare_protocols"),
        CheckStatus::Compliant
    );
    let fixed = json!({"items": {"open": 0}});
    assert!(b.write("linux.rare_protocols", &fixed).is_err());
    assert!(!sim.has(RARE_FILE));
}

#[test]
fn a_second_fix_of_rare_protocols_rewrites_the_same_file() {
    let sim = mint_h();
    let mut b = backend(&sim);
    let fixed = json!({"items": {"open": 0}});
    b.write("linux.rare_protocols", &fixed).unwrap();
    let once = sim.text(RARE_FILE).unwrap();
    b.write("linux.rare_protocols", &fixed).unwrap();
    assert_eq!(sim.text(RARE_FILE).unwrap(), once);
}

#[test]
fn only_the_package_for_this_processor_counts_on_debian_based_systems() {
    let sim = ubuntu_h();
    sim.package("amd64-microcode", false, "");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.processor_updates"),
        json!({"items": {"installed": 0}}),
        "the Intel package is installed, but this processor is an AMD one"
    );
    sim.package("amd64-microcode", true, "");
    sim.package("intel-microcode", false, "");
    assert_eq!(
        value(&mut b, "linux.processor_updates"),
        json!({"items": {"installed": 1}})
    );
}

#[test]
fn on_fedora_either_package_counts() {
    let sim = fedora_h();
    sim.package("microcode_ctl", false, "");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.processor_updates"),
        json!({"items": {"installed": 1}})
    );
    sim.package("linux-firmware", false, "");
    assert_eq!(
        value(&mut b, "linux.processor_updates"),
        json!({"items": {"installed": 0}})
    );
}

#[test]
fn a_missing_processor_package_is_installed_with_what_it_brings_and_exactly_that_is_removed() {
    for (sim, vendor, package, brings) in [
        (ubuntu_h(), "AuthenticAMD", "amd64-microcode", ""),
        (mint_h(), "GenuineIntel", "intel-microcode", "iucode-tool"),
        (
            fedora_h(),
            "GenuineIntel",
            "microcode_ctl",
            "microcode-data",
        ),
        (
            fedora_h(),
            "AuthenticAMD",
            "linux-firmware",
            "amd-ucode-firmware",
        ),
    ] {
        sim.file(
            "/proc/cpuinfo",
            &format!("processor\t: 0\nvendor_id\t: {vendor}\nmodel name\t: A Processor\n"),
        );
        for name in [
            "amd64-microcode",
            "intel-microcode",
            "microcode_ctl",
            "linux-firmware",
        ] {
            if sim.installed(name) {
                sim.package(name, false, "");
            }
        }
        sim.package(package, false, brings);
        sim.package("iucode-tool", false, "");
        sim.package("microcode-data", false, "");
        sim.package("amd-ucode-firmware", false, "");
        sim.package("unrelated", true, "");
        let packages_before = packages(&sim);
        let files_before = snapshot(&sim);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.processor_updates"),
            json!({"items": {"installed": 0}}),
            "{package}"
        );
        assert_eq!(
            status(&mut b, "linux.processor_updates"),
            CheckStatus::Attention
        );
        let (was, fixed) = cycle(&sim, "linux.processor_updates");
        assert_eq!(fixed, json!({"items": {"installed": 1}}));
        assert_eq!(packages(&sim), packages_before);
        assert_same(&sim, &files_before);

        b.write("linux.processor_updates", &fixed).unwrap();
        assert!(sim.installed(package));
        if !brings.is_empty() {
            assert!(sim.installed(brings), "{brings} comes with {package}");
        }
        assert!(sim.installed("unrelated"));
        let record = sim
            .text("/var/lib/secblitz/Linux/processor-updates.txt")
            .unwrap();
        assert!(record.lines().any(|l| l == package), "{record}");
        b.write("linux.processor_updates", &was).unwrap();
        assert_eq!(packages(&sim), packages_before);
        assert!(!sim.has("/var/lib/secblitz/Linux/processor-updates.txt"));
    }
}

#[test]
fn a_package_that_was_already_there_is_not_part_of_what_an_undo_removes() {
    let sim = mint_h();
    sim.file(
        "/proc/cpuinfo",
        "processor\t: 0\nvendor_id\t: GenuineIntel\n",
    );
    sim.package("amd64-microcode", false, "");
    sim.package("intel-microcode", false, "iucode-tool");
    sim.package("iucode-tool", true, "");
    let mut b = backend(&sim);
    b.write(
        "linux.processor_updates",
        &json!({"items": {"installed": 1}}),
    )
    .unwrap();
    let record = sim
        .text("/var/lib/secblitz/Linux/processor-updates.txt")
        .unwrap();
    assert_eq!(record, "intel-microcode\n");
    b.write(
        "linux.processor_updates",
        &json!({"items": {"installed": 0}}),
    )
    .unwrap();
    assert!(sim.installed("iucode-tool"));
    assert!(!sim.installed("intel-microcode"));
}

#[test]
fn an_install_that_would_change_other_software_is_refused_before_anything_runs() {
    for (key, wanted) in [
        ("upgrades:amd64-microcode", "initramfs-tools"),
        ("replaces:amd64-microcode", "old-microcode"),
    ] {
        let sim = ubuntu_h();
        sim.package("amd64-microcode", false, "");
        sim.package("intel-microcode", false, "");
        sim.set(key, wanted);
        let before = snapshot(&sim);
        let mut b = backend(&sim);
        let e = b
            .write(
                "linux.processor_updates",
                &json!({"items": {"installed": 1}}),
            )
            .unwrap_err();
        assert_eq!(e.to_string(), h::PACKAGE_REFUSED, "{key}");
        assert_same(&sim, &before);
        assert!(!sim.ran("/usr/bin/apt-get install -y amd64-microcode"));
        assert!(!sim.installed("amd64-microcode"));
    }
    let sim = fedora_h();
    sim.package("microcode_ctl", false, "");
    sim.package("linux-firmware", false, "");
    sim.set("upgrades:linux-firmware", "glibc");
    let mut b = backend(&sim);
    let e = b
        .write(
            "linux.processor_updates",
            &json!({"items": {"installed": 1}}),
        )
        .unwrap_err();
    assert_eq!(e.to_string(), h::PACKAGE_REFUSED);
    assert!(!sim.ran("/usr/bin/dnf install -y linux-firmware"));
}

#[test]
fn an_offline_install_leaves_nothing_behind() {
    let sim = ubuntu_h();
    sim.package("amd64-microcode", false, "");
    sim.package("intel-microcode", false, "");
    sim.set("apt.offline", "1");
    let before = snapshot(&sim);
    let packages_before = packages(&sim);
    let mut b = backend(&sim);
    let e = b
        .write(
            "linux.processor_updates",
            &json!({"items": {"installed": 1}}),
        )
        .unwrap_err();
    assert_eq!(e.to_string(), h::PACKAGE_FAILED);
    assert_same(&sim, &before);
    assert_eq!(packages(&sim), packages_before);
}

#[test]
fn an_undo_that_would_take_other_software_with_it_is_refused() {
    let sim = ubuntu_h();
    sim.package("amd64-microcode", false, "");
    sim.package("intel-microcode", false, "");
    let mut b = backend(&sim);
    b.write(
        "linux.processor_updates",
        &json!({"items": {"installed": 1}}),
    )
    .unwrap();
    sim.package("their-tool", true, "");
    sim.set("needs:amd64-microcode", "their-tool");
    let e = b
        .write(
            "linux.processor_updates",
            &json!({"items": {"installed": 0}}),
        )
        .unwrap_err();
    assert_eq!(e.to_string(), h::PACKAGE_UNDO_REFUSED);
    assert!(sim.installed("amd64-microcode"));
    assert!(sim.installed("their-tool"));
    assert!(sim.has("/var/lib/secblitz/Linux/processor-updates.txt"));
}

#[test]
fn an_undo_without_a_record_changes_nothing() {
    let sim = ubuntu_h();
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let e = b
        .write(
            "linux.processor_updates",
            &json!({"items": {"installed": 0}}),
        )
        .unwrap_err();
    assert_eq!(e.to_string(), NO_RECORD);
    assert_same(&sim, &before);
    assert!(sim.installed("amd64-microcode"));
}

#[test]
fn without_the_package_tool_the_processor_check_is_not_judged() {
    let sim = ubuntu_h();
    sim.tools.borrow_mut().remove("/usr/bin/dpkg-query");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.processor_updates"),
        json!({"items": {"installed": null}})
    );
    assert_eq!(
        status(&mut b, "linux.processor_updates"),
        CheckStatus::Compliant
    );
    let sim = ubuntu_h();
    sim.file("/proc/cpuinfo", "processor\t: 0\nCPU implementer\t: 0x41\n");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.processor_updates"),
        json!({"items": {"installed": null}})
    );
}

#[test]
fn the_root_account_is_locked_and_unlocked_exactly() {
    for (sim, mark) in [(ubuntu_h(), "!"), (mint_h(), "!"), (fedora_h(), "!!")] {
        lock_root_open(&sim);
        let before = snapshot(&sim);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.root_account"),
            json!({"items": {"usable": 1}})
        );
        assert_eq!(status(&mut b, "linux.root_account"), CheckStatus::Attention);
        let (was, fixed) = cycle(&sim, "linux.root_account");
        assert_eq!(was, json!({"items": {"usable": 1}}));
        assert_eq!(fixed, json!({"items": {"usable": 0}}));
        assert_same(&sim, &before);

        b.write("linux.root_account", &fixed).unwrap();
        let locked = sim.text("/etc/shadow").unwrap();
        assert!(
            locked.starts_with(&format!("root:{mark}$y$j9T$rootplaceholder:")),
            "{locked}"
        );
        assert!(sim.ran("/usr/bin/passwd -l root"));
        b.write("linux.root_account", &was).unwrap();
        assert!(sim.ran("/usr/bin/passwd -u root"));
        assert_same(&sim, &before);
    }
}

#[test]
fn the_root_account_is_never_locked_when_nobody_else_can_act_as_an_administrator() {
    for (group_file, name) in [("sudo", "ubuntu"), ("wheel", "fedora")] {
        let sim = if name == "ubuntu" {
            ubuntu_h()
        } else {
            fedora_h()
        };
        lock_root_open(&sim);
        let group = sim.text("/etc/group").unwrap();
        let emptied: String = group
            .lines()
            .map(|l| {
                if l.starts_with(&format!("{group_file}:")) {
                    format!("{}:\n", l.rsplit_once(':').unwrap().0)
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        sim.file("/etc/group", &emptied);
        let before = snapshot(&sim);
        let mut b = backend(&sim);
        let observed = b.observe("linux.root_account").unwrap();
        assert!(!observed.eligible);
        assert_eq!(observed.reason, h::NO_OTHER_ADMIN);
        assert!(skipped(&mut b, "linux.root_account"));
        let e = b
            .write("linux.root_account", &json!({"items": {"usable": 0}}))
            .unwrap_err();
        assert_eq!(e.to_string(), h::NO_OTHER_ADMIN);
        assert_same(&sim, &before);
        assert!(!sim.ran("/usr/bin/passwd -l root"));
    }
}

#[test]
fn an_administrator_who_cannot_sign_in_does_not_count_as_a_way_back() {
    for hash in ["!", "*", "!$y$j9T$x", ""] {
        let sim = ubuntu_h();
        lock_root_open(&sim);
        let shadow = sim.text("/etc/shadow").unwrap();
        sim.file(
            "/etc/shadow",
            &shadow.replace("tester:$y$j9T$placeholder:", &format!("tester:{hash}:")),
        );
        let mut b = backend(&sim);
        assert!(
            !b.observe("linux.root_account").unwrap().eligible,
            "{hash:?}"
        );
    }
    let sim = ubuntu_h();
    lock_root_open(&sim);
    let group = sim.text("/etc/group").unwrap();
    sim.file(
        "/etc/group",
        &group.replace("sudo:x:27:tester", "sudo:x:27:ghost"),
    );
    let mut b = backend(&sim);
    assert!(!b.observe("linux.root_account").unwrap().eligible);
}

#[test]
fn a_second_account_with_the_administrator_group_as_its_main_group_counts() {
    let sim = ubuntu_h();
    lock_root_open(&sim);
    let group = sim.text("/etc/group").unwrap();
    sim.file(
        "/etc/group",
        &group.replace("sudo:x:27:tester", "sudo:x:27:"),
    );
    let passwd = sim.text("/etc/passwd").unwrap();
    sim.file(
        "/etc/passwd",
        &passwd.replace("tester:x:1000:1000", "tester:x:1000:27"),
    );
    let mut b = backend(&sim);
    assert!(b.observe("linux.root_account").unwrap().eligible);
}

#[test]
fn a_root_account_with_no_password_at_all_is_left_to_the_accounts_finding() {
    let sim = ubuntu_h();
    let shadow = sim.text("/etc/shadow").unwrap();
    sim.file("/etc/shadow", &shadow.replacen("root:!:", "root::", 1));
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.root_account"),
        json!({"items": {"usable": null}})
    );
}

#[test]
fn a_root_account_that_cannot_be_unlocked_reports_a_plain_failure() {
    let sim = ubuntu_h();
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let e = b
        .write("linux.root_account", &json!({"items": {"usable": 1}}))
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        CHANGE_FAILED,
        "nothing is left of the old password to bring back"
    );
    assert_same(&sim, &before);
    let sim = ubuntu_h();
    sim.fail("/usr/bin/passwd -l");
    lock_root_open(&sim);
    let before = snapshot(&sim);
    let mut b = backend(&sim);
    let e = b
        .write("linux.root_account", &json!({"items": {"usable": 0}}))
        .unwrap_err();
    assert_eq!(e.to_string(), CHANGE_FAILED);
    assert_same(&sim, &before);
}

#[test]
fn without_the_password_tool_the_root_account_is_not_judged() {
    let sim = ubuntu_h();
    sim.tools.borrow_mut().remove("/usr/bin/passwd");
    lock_root_open(&sim);
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.root_account"),
        json!({"items": {"usable": null}})
    );
}

#[test]
fn another_account_with_the_all_powerful_number_is_reported() {
    use crate::advice::EXTRA_ADMIN_ACCOUNTS as T;
    for sim in [ubuntu(), fedora(), real_mint()] {
        let f = finding(&sim, T).unwrap();
        assert_eq!(f.status, CheckStatus::Ok);
        assert_eq!(f.detail, findings::ONE_ALL_POWERFUL);
    }
    for extra in [
        "toor:x:0:0:backdoor:/root:/bin/sh\n",
        "admin2::0:0::/:/bin/sh\n",
    ] {
        let sim = ubuntu();
        let passwd = sim.text("/etc/passwd").unwrap();
        sim.file("/etc/passwd", &format!("{passwd}{extra}"));
        let f = finding(&sim, T).unwrap();
        assert_eq!(f.status, CheckStatus::Attention, "{extra}");
        assert_eq!(f.detail, findings::EXTRA_ALL_POWERFUL);
    }
    let sim = ubuntu();
    let passwd = sim.text("/etc/passwd").unwrap();
    sim.file(
        "/etc/passwd",
        &format!("{passwd}svc:x:10000:0:not zero id:/:/bin/false\nroot2:x:1:0::/:/bin/sh\n"),
    );
    assert_eq!(status_of(&sim, T), Some(CheckStatus::Ok));
    drop_file(&sim, "/etc/passwd");
    assert_eq!(status_of(&sim, T), None);
}

#[test]
fn a_value_outside_each_controls_range_is_refused_before_anything_runs() {
    let sim = fedora_h();
    let mut b = backend(&sim);
    for (id, key, bad) in [
        ("linux.memory_shuffle", "randomize_va_space", 3),
        ("linux.terminal_drivers", "ldisc_autoload", 2),
        ("linux.crash_memory", "suid_dumpable", 3),
        ("linux.root_account", "usable", 2),
        ("linux.rare_protocols", "open", 2),
    ] {
        let wanted = json!({"items": {key: bad}});
        assert!(b.write(id, &wanted).is_err(), "{id}");
    }
    assert!(sim.calls.borrow().is_empty());
}
