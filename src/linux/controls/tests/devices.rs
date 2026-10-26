//! Bluetooth at start, the installed programs report and the three findings about who can make changes, programs open to
//! the network and memory saved to the drive, against files and output recorded on real Ubuntu 26.04, Fedora 44 and Linux
//! Mint 22.3 installs.

use super::*;
use crate::advice::{ADMIN_ACCOUNTS, OPEN_PROGRAMS, SWAP_PROTECTION};
use crate::linux::controls::devices as dev;
use crate::linux::controls::findings as f;

const DISTROS: [&str; 3] = ["ubuntu-26.04", "fedora-44", "mint-22.3"];
const BLUETOOTH: &str = "/etc/bluetooth/main.conf";
const BLUETOOTH_MEMO: &str = "/var/lib/secblitz/Linux/bluetooth-file.txt";
const SURVEY: &str = "/etc/popularity-contest.conf";
const SURVEY_TOOL: &str = "/usr/sbin/popularity-contest";
const SURVEY_MEMO: &str = "/var/lib/secblitz/Linux/usage-survey-file.txt";
const TESTER: &str = "tester";

/// The conffile that popularity-contest installs, with the answer given at install time.
fn survey_text(answer: &str) -> String {
    format!(
        "# Config file for Debian's popularity-contest package.\n#\n# To change this file, use:\n#        dpkg-reconfigure popularity-contest\n#\n# You can also edit it by hand, if you so desire.\n#\n# The package version is not in this file.\n\nMY_HOSTID=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nPARTICIPATE=\"{answer}\"\nUSE_HTTP=\"no\" # always use http to submit (instead of smtp)\nDAY=\"3\"\n"
    )
}

fn recorded(name: &str) -> Sim {
    let sim = Sim::fixture(name);
    sim.unit("bluetooth.service", "enabled", true);
    sim.file("/etc/machine-id", "0123456789abcdef\n");
    sim
}

fn ids(b: &LinuxBackend<Sim>) -> Vec<String> {
    b.controls().into_iter().map(|c| c.id).collect()
}

fn started_or_stopped(sim: &Sim) -> bool {
    sim.calls.borrow().iter().any(|c| {
        c.contains("bluetooth")
            && ["restart", "start", "stop", "disable", "enable", "reload"]
                .iter()
                .any(|verb| {
                    c.contains(&format!("systemctl {verb}"))
                        || c.contains(&format!("systemctl try-{verb}"))
                })
    })
}

#[test]
fn bluetooth_reads_as_switching_on_at_start_on_every_recorded_install() {
    for name in DISTROS {
        let sim = recorded(name);
        let mut b = backend(&sim);
        assert_eq!(
            value(&mut b, "linux.bluetooth_autostart"),
            json!({"items": {"auto_enable": 1}}),
            "{name}"
        );
        assert_eq!(
            status(&mut b, "linux.bluetooth_autostart"),
            CheckStatus::Attention,
            "{name}"
        );
        assert!(
            ids(&b).contains(&"linux.bluetooth_autostart".to_string()),
            "{name}"
        );
        assert!(spec("linux.bluetooth_autostart").unwrap().ask);
    }
}

#[test]
fn switching_bluetooth_off_at_start_changes_one_line_restarts_nothing_and_undo_restores_the_file() {
    for name in DISTROS {
        let sim = recorded(name);
        let original = sim.text(BLUETOOTH).unwrap();
        let expected = if name == "mint-22.3" {
            original.replacen("\nAutoEnable=true\n", "\nAutoEnable=false\n", 1)
        } else {
            original.replacen("[Policy]\n", "[Policy]\nAutoEnable=false\n", 1)
        };
        assert_ne!(expected, original, "{name}");
        let mut b = backend(&sim);
        let before = value(&mut b, "linux.bluetooth_autostart");
        let fixed = spec("linux.bluetooth_autostart")
            .unwrap()
            .derive_target(&before)
            .unwrap();
        assert_eq!(fixed, json!({"items": {"auto_enable": 0}}), "{name}");
        b.write("linux.bluetooth_autostart", &fixed).unwrap();
        assert_eq!(sim.text(BLUETOOTH).unwrap(), expected, "{name}");
        assert_eq!(
            status(&mut b, "linux.bluetooth_autostart"),
            CheckStatus::Compliant,
            "{name}"
        );
        assert!(sim.has(BLUETOOTH_MEMO), "{name}");
        b.write("linux.bluetooth_autostart", &before).unwrap();
        assert_eq!(sim.text(BLUETOOTH).unwrap(), original, "{name}");
        assert!(!sim.has(BLUETOOTH_MEMO), "{name}");
        assert!(
            !started_or_stopped(&sim),
            "{name}: {:?}",
            sim.calls.borrow()
        );
    }
}

#[test]
fn a_second_fix_does_not_replace_the_record_of_the_first() {
    let sim = recorded("ubuntu-26.04");
    let original = sim.text(BLUETOOTH).unwrap();
    let mut b = backend(&sim);
    let off = json!({"items": {"auto_enable": 0}});
    b.write("linux.bluetooth_autostart", &off).unwrap();
    let memo = sim.text(BLUETOOTH_MEMO).unwrap();
    b.write("linux.bluetooth_autostart", &off).unwrap();
    assert_eq!(sim.text(BLUETOOTH_MEMO).unwrap(), memo);
    b.write(
        "linux.bluetooth_autostart",
        &json!({"items": {"auto_enable": 1}}),
    )
    .unwrap();
    assert_eq!(sim.text(BLUETOOTH).unwrap(), original);
}

#[test]
fn bluetooth_files_with_their_own_style_come_back_byte_for_byte() {
    let sim = recorded("mint-22.3");
    let original = "[General]\r\nName = Desk\r\n\r\n[Policy]\r\nReconnectAttempts = 3\r\nAutoEnable = true\r\nResumeDelay=2";
    sim.file(BLUETOOTH, original);
    let (before, fixed) = cycle(&sim, "linux.bluetooth_autostart");
    assert_eq!(before, json!({"items": {"auto_enable": 1}}));
    assert_eq!(fixed, json!({"items": {"auto_enable": 0}}));
    assert_eq!(sim.text(BLUETOOTH).unwrap(), original);

    sim.file(BLUETOOTH, "[General]\nName=Desk");
    let mut b = backend(&sim);
    b.write(
        "linux.bluetooth_autostart",
        &json!({"items": {"auto_enable": 0}}),
    )
    .unwrap();
    assert_eq!(
        sim.text(BLUETOOTH).unwrap(),
        "[General]\nName=Desk\n\n[Policy]\nAutoEnable=false\n"
    );
    b.write(
        "linux.bluetooth_autostart",
        &json!({"items": {"auto_enable": 1}}),
    )
    .unwrap();
    assert_eq!(sim.text(BLUETOOTH).unwrap(), "[General]\nName=Desk");
}

#[test]
fn a_bluetooth_setting_that_is_already_off_is_not_a_problem() {
    let sim = recorded("ubuntu-26.04");
    sim.file(BLUETOOTH, "[Policy]\nAutoEnable=false\n");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.bluetooth_autostart"),
        json!({"items": {"auto_enable": 0}})
    );
    assert_eq!(
        status(&mut b, "linux.bluetooth_autostart"),
        CheckStatus::Compliant
    );
    b.write(
        "linux.bluetooth_autostart",
        &json!({"items": {"auto_enable": 0}}),
    )
    .unwrap();
    assert!(!sim.has(BLUETOOTH_MEMO));
}

#[test]
fn bluetooth_is_left_alone_when_it_is_missing_or_says_something_unknown() {
    let gone = Sim::fixture("ubuntu-26.04");
    let original = gone.text(BLUETOOTH).unwrap();
    let mut b = backend(&gone);
    assert!(!ids(&b).contains(&"linux.bluetooth_autostart".to_string()));
    let o = b.observe("linux.bluetooth_autostart").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, dev::NO_BLUETOOTH);
    assert!(b
        .write(
            "linux.bluetooth_autostart",
            &json!({"items": {"auto_enable": 0}})
        )
        .is_err());
    assert_eq!(gone.text(BLUETOOTH).unwrap(), original);

    let nofile = recorded("ubuntu-26.04");
    nofile
        .files
        .borrow_mut()
        .remove(std::path::Path::new(BLUETOOTH));
    let o = backend(&nofile)
        .observe("linux.bluetooth_autostart")
        .unwrap();
    assert_eq!(o.reason, dev::NO_BLUETOOTH);

    let odd = recorded("ubuntu-26.04");
    odd.file(BLUETOOTH, "[Policy]\nAutoEnable=maybe\n");
    let mut b = backend(&odd);
    assert!(!ids(&b).contains(&"linux.bluetooth_autostart".to_string()));
    let o = b.observe("linux.bluetooth_autostart").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, UNRECOGNISED);
    assert!(b
        .write(
            "linux.bluetooth_autostart",
            &json!({"items": {"auto_enable": 0}})
        )
        .is_err());
    assert_eq!(odd.text(BLUETOOTH).unwrap(), "[Policy]\nAutoEnable=maybe\n");
}

#[test]
fn turning_bluetooth_back_on_without_a_record_changes_nothing() {
    let sim = recorded("fedora-44");
    sim.file(BLUETOOTH, "[Policy]\nAutoEnable=false\n");
    let mut b = backend(&sim);
    let err = b
        .write(
            "linux.bluetooth_autostart",
            &json!({"items": {"auto_enable": 1}}),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), NO_RECORD);
    assert_eq!(sim.text(BLUETOOTH).unwrap(), "[Policy]\nAutoEnable=false\n");
}

#[test]
fn a_bad_bluetooth_value_is_refused() {
    let sim = recorded("ubuntu-26.04");
    let mut b = backend(&sim);
    for bad in [
        json!({"items": {"auto_enable": 2}}),
        json!({"items": {"auto_enable": "no"}}),
        json!({"items": {"auto_enable": 0, "extra": 1}}),
        json!({"items": {}}),
    ] {
        assert!(b.write("linux.bluetooth_autostart", &bad).is_err(), "{bad}");
    }
    assert!(!sim.has(BLUETOOTH_MEMO));
}

fn with_survey(name: &str, answer: &str) -> Sim {
    let sim = recorded(name);
    sim.file(SURVEY_TOOL, "#!/usr/bin/perl\n");
    sim.file(SURVEY, &survey_text(answer));
    sim
}

#[test]
fn the_installed_programs_report_is_not_offered_where_it_is_not_installed() {
    for name in DISTROS {
        let sim = recorded(name);
        let mut b = backend(&sim);
        assert!(
            !ids(&b).contains(&"linux.usage_survey".to_string()),
            "{name}"
        );
        let o = b.observe("linux.usage_survey").unwrap();
        assert!(!o.eligible, "{name}");
        assert_eq!(o.reason, dev::NO_USAGE_SURVEY, "{name}");
        assert!(b
            .write("linux.usage_survey", &json!({"items": {"participate": 0}}))
            .is_err());
    }
    let removed = recorded("ubuntu-26.04");
    removed.file(SURVEY, &survey_text("yes"));
    let mut b = backend(&removed);
    assert!(!ids(&b).contains(&"linux.usage_survey".to_string()));
    assert_eq!(
        b.observe("linux.usage_survey").unwrap().reason,
        dev::NO_USAGE_SURVEY
    );
}

#[test]
fn the_installed_programs_report_is_switched_off_and_the_file_comes_back_byte_for_byte() {
    for name in ["ubuntu-26.04", "mint-22.3"] {
        let sim = with_survey(name, "yes");
        let original = sim.text(SURVEY).unwrap();
        let mut b = backend(&sim);
        assert!(
            ids(&b).contains(&"linux.usage_survey".to_string()),
            "{name}"
        );
        assert_eq!(status(&mut b, "linux.usage_survey"), CheckStatus::Attention);
        let (before, fixed) = cycle(&sim, "linux.usage_survey");
        assert_eq!(before, json!({"items": {"participate": 1}}), "{name}");
        assert_eq!(fixed, json!({"items": {"participate": 0}}), "{name}");
        assert_eq!(sim.text(SURVEY).unwrap(), original, "{name}");
        assert!(!sim.has(SURVEY_MEMO), "{name}");

        let mut b = backend(&sim);
        b.write("linux.usage_survey", &json!({"items": {"participate": 0}}))
            .unwrap();
        assert_eq!(
            sim.text(SURVEY).unwrap(),
            original.replace("PARTICIPATE=\"yes\"", "PARTICIPATE=\"no\""),
            "{name}"
        );
    }
}

#[test]
fn an_answer_of_no_is_already_protected_and_the_family_without_the_program_never_sees_it() {
    let sim = with_survey("ubuntu-26.04", "no");
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.usage_survey"),
        json!({"items": {"participate": 0}})
    );
    assert_eq!(status(&mut b, "linux.usage_survey"), CheckStatus::Compliant);
    b.write("linux.usage_survey", &json!({"items": {"participate": 0}}))
        .unwrap();
    assert!(!sim.has(SURVEY_MEMO));

    let fedora = with_survey("fedora-44", "yes");
    assert!(!ids(&backend(&fedora)).contains(&"linux.usage_survey".to_string()));
}

#[test]
fn an_installed_programs_report_file_nobody_can_read_is_left_alone() {
    for text in [
        "MY_HOSTID=\"abc\"\n",
        "PARTICIPATE=\"Yes\"\n",
        "PARTICIPATE=\"maybe\"\n",
        "# PARTICIPATE=\"yes\"\n",
    ] {
        let sim = with_survey("ubuntu-26.04", "yes");
        sim.file(SURVEY, text);
        let mut b = backend(&sim);
        let o = b.observe("linux.usage_survey").unwrap();
        assert!(!o.eligible, "{text}");
        assert_eq!(o.reason, UNRECOGNISED, "{text}");
        assert!(b
            .write("linux.usage_survey", &json!({"items": {"participate": 0}}))
            .is_err());
        assert_eq!(sim.text(SURVEY).unwrap(), text);
        assert!(!sim.has(SURVEY_MEMO));
    }
    let sim = with_survey("ubuntu-26.04", "yes");
    sim.files.borrow_mut().remove(std::path::Path::new(SURVEY));
    assert_eq!(
        backend(&sim).observe("linux.usage_survey").unwrap().reason,
        dev::NO_USAGE_SURVEY
    );
}

#[test]
fn turning_the_installed_programs_report_back_on_without_a_record_changes_nothing() {
    let sim = with_survey("ubuntu-26.04", "no");
    let mut b = backend(&sim);
    let err = b
        .write("linux.usage_survey", &json!({"items": {"participate": 1}}))
        .unwrap_err();
    assert_eq!(err.to_string(), NO_RECORD);
    assert_eq!(sim.text(SURVEY).unwrap(), survey_text("no"));
}

fn finding_of(sim: &Sim, title: &str) -> Option<crate::model::Finding> {
    finding(sim, title)
}

#[test]
fn one_account_that_can_make_changes_is_fine_on_every_recorded_install() {
    for name in DISTROS {
        let sim = recorded(name);
        let found = finding_of(&sim, ADMIN_ACCOUNTS).unwrap();
        assert_eq!(found.status, CheckStatus::Ok, "{name}");
        assert_eq!(
            found.detail,
            format!("1 {} {TESTER}", f::ADMIN_ONE),
            "{name}"
        );
    }
}

#[test]
fn more_than_one_account_that_can_make_changes_is_for_your_information_and_nothing_else_is_listed()
{
    let sim = recorded("ubuntu-26.04");
    sim.file(
        "/etc/group",
        "root:x:0:\nadm:x:4:syslog,tester\nsudo:x:27:tester,alex\nwheel:x:10:alex,sam\nadmin:x:116:\ndocker:x:999:tester,bob\n",
    );
    let found = finding_of(&sim, ADMIN_ACCOUNTS).unwrap();
    assert_eq!(found.status, CheckStatus::Info);
    assert_eq!(
        found.detail,
        format!("3 {} tester, alex, sam", f::ADMIN_MANY)
    );
    for other in ["bob", "syslog", "docker", "adm"] {
        assert!(!found.detail.contains(other), "{other}");
    }
    sim.file("/etc/group", "sudo:x:27:tester,not a name,\n");
    let found = finding_of(&sim, ADMIN_ACCOUNTS).unwrap();
    assert_eq!(found.status, CheckStatus::Ok);
    assert_eq!(found.detail, format!("1 {} tester", f::ADMIN_ONE));
}

#[test]
fn nothing_is_said_about_who_can_make_changes_when_it_cannot_be_told() {
    let sim = recorded("fedora-44");
    sim.file("/etc/group", "wheel:x:10:\nroot:x:0:\n");
    assert!(finding_of(&sim, ADMIN_ACCOUNTS).is_none());
    drop_file(&sim, "/etc/group");
    assert!(finding_of(&sim, ADMIN_ACCOUNTS).is_none());
}

fn listening(sim: &Sim) -> Sim {
    sim.tool("/usr/bin/ss");
    sim.clone()
}

#[test]
fn a_fresh_install_has_no_program_open_to_the_network_beyond_the_usual_ones() {
    for name in DISTROS {
        let sim = listening(&recorded(name));
        assert!(sim.get("rec.ss").contains("avahi-daemon"), "{name}");
        let found = finding_of(&sim, OPEN_PROGRAMS).unwrap();
        assert_eq!(found.status, CheckStatus::Ok, "{name}: {}", found.detail);
        assert_eq!(found.detail, f::OPEN_NONE, "{name}");
        assert!(sim.ran("/usr/bin/ss -Hltnup"), "{name}");
    }
}

fn add_listener(sim: &Sim, line: &str) {
    sim.set("rec.ss", &format!("{}{line}\n", sim.get("rec.ss")));
}

#[test]
fn a_program_that_listens_on_every_address_is_named() {
    let sim = listening(&recorded("ubuntu-26.04"));
    add_listener(
        &sim,
        "tcp   LISTEN 0      5            0.0.0.0:8000       0.0.0.0:*    users:((\"python3\",pid=4242,fd=3))",
    );
    let found = finding_of(&sim, OPEN_PROGRAMS).unwrap();
    assert_eq!(found.status, CheckStatus::Attention);
    assert_eq!(found.detail, format!("1 {} python3", f::OPEN_ONE));

    add_listener(
        &sim,
        "tcp   LISTEN 0      128             [::]:22          [::]:*    users:((\"sshd\",pid=900,fd=4))",
    );
    add_listener(
        &sim,
        "udp   UNCONN 0      0       192.168.1.7:9999       0.0.0.0:*    users:((\"python3\",pid=4243,fd=5))",
    );
    add_listener(
        &sim,
        "tcp   LISTEN 0      5        0.0.0.0:9000       0.0.0.0:*",
    );
    let found = finding_of(&sim, OPEN_PROGRAMS).unwrap();
    assert_eq!(found.status, CheckStatus::Attention);
    assert_eq!(
        found.detail,
        format!("3 {} python3, sshd, {}", f::OPEN_MANY, f::OPEN_UNNAMED)
    );
}

#[test]
fn the_usual_desktop_listeners_and_loopback_ones_are_not_worth_a_warning() {
    let sim = listening(&recorded("ubuntu-26.04"));
    for line in [
        "udp   UNCONN 0      0           0.0.0.0:68         0.0.0.0:*    users:((\"NetworkManager\",pid=700,fd=22))",
        "udp   UNCONN 0      0  [fe80::1%enp1s0]:546           [::]:*    users:((\"NetworkManager\",pid=700,fd=23))",
        "udp   UNCONN 0      0           0.0.0.0:40001      0.0.0.0:*    users:((\"avahi-daemon\",pid=842,fd=14))",
        "tcp   LISTEN 0      4096        0.0.0.0:5355       0.0.0.0:*    users:((\"systemd-resolve\",pid=655,fd=14))",
        "tcp   LISTEN 0      5         127.0.0.1:8000       0.0.0.0:*    users:((\"python3\",pid=1,fd=3))",
        "tcp   LISTEN 0      5             [::1]:8001          [::]:*    users:((\"python3\",pid=1,fd=4))",
        "tcp   LISTEN 0      5   [::ffff:127.0.0.1]:8002       [::]:*    users:((\"python3\",pid=1,fd=5))",
    ] {
        add_listener(&sim, line);
    }
    let found = finding_of(&sim, OPEN_PROGRAMS).unwrap();
    assert_eq!(found.status, CheckStatus::Ok, "{}", found.detail);

    add_listener(
        &sim,
        "udp   UNCONN 0      0           0.0.0.0:54321      0.0.0.0:*    users:((\"firefox\",pid=3000,fd=60))",
    );
    assert_eq!(
        finding_of(&sim, OPEN_PROGRAMS).unwrap().status,
        CheckStatus::Ok
    );
    add_listener(
        &sim,
        "udp   UNCONN 0      0           0.0.0.0:1900       0.0.0.0:*    users:((\"firefox\",pid=3000,fd=61))",
    );
    let found = finding_of(&sim, OPEN_PROGRAMS).unwrap();
    assert_eq!(found.detail, format!("1 {} firefox", f::OPEN_ONE));
    sim.set(
        "rec.ss",
        &sim.get("rec.ss").replace("0.0.0.0:1900 ", "127.0.0.1:1900"),
    );

    add_listener(
        &sim,
        "tcp   LISTEN 0      128         0.0.0.0:40001      0.0.0.0:*    users:((\"avahi-daemon\",pid=842,fd=14))",
    );
    let found = finding_of(&sim, OPEN_PROGRAMS).unwrap();
    assert_eq!(found.status, CheckStatus::Attention);
}

#[test]
fn nothing_is_said_about_programs_open_to_the_network_when_the_tool_cannot_answer() {
    let sim = recorded("ubuntu-26.04");
    assert!(finding_of(&sim, OPEN_PROGRAMS).is_none());
    sim.tool("/usr/bin/ss").fail("/usr/bin/ss");
    assert!(finding_of(&sim, OPEN_PROGRAMS).is_none());
    let sim = listening(&recorded("ubuntu-26.04"));
    sim.set("rec.ss", "garbage\n");
    assert!(finding_of(&sim, OPEN_PROGRAMS).is_none());
}

fn with_drive_tools(sim: &Sim) -> &Sim {
    sim.tool("/usr/bin/findmnt").tool("/usr/bin/lsblk")
}

#[test]
fn memory_saved_to_a_plain_file_is_not_protected_on_ubuntu_and_mint() {
    for (name, swap) in [("ubuntu-26.04", "/swap.img"), ("mint-22.3", "/swapfile")] {
        let sim = recorded(name);
        with_drive_tools(&sim).set("root.source", "/dev/vda2");
        assert!(sim.text("/proc/swaps").unwrap().contains(swap), "{name}");
        let found = finding_of(&sim, SWAP_PROTECTION).unwrap();
        assert_eq!(found.status, CheckStatus::Attention, "{name}");
        assert_eq!(found.detail, f::SWAP_OPEN, "{name}");
        assert!(
            sim.ran(&format!("/usr/bin/findmnt -n -o SOURCE --target {swap}")),
            "{name}"
        );
    }
}

#[test]
fn memory_kept_in_memory_only_is_protected_on_fedora_without_asking_the_drive() {
    let sim = recorded("fedora-44");
    let found = finding_of(&sim, SWAP_PROTECTION).unwrap();
    assert_eq!(found.status, CheckStatus::Ok);
    assert_eq!(found.detail, f::SWAP_SAFE);
    assert!(!sim.ran("/usr/bin/lsblk"));
}

#[test]
fn memory_saved_to_an_encrypted_drive_is_protected() {
    let sim = recorded("ubuntu-26.04");
    with_drive_tools(&sim).set("root.source", "/dev/mapper/vda2_crypt");
    sim.set("crypt:/dev/mapper/vda2_crypt", "1");
    assert_eq!(
        finding_of(&sim, SWAP_PROTECTION).unwrap().status,
        CheckStatus::Ok
    );

    let partition = recorded("ubuntu-26.04");
    with_drive_tools(&partition).set("root.source", "/dev/vda2");
    partition.file(
        "/proc/swaps",
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/mapper/cryptswap          partition\t4194300\t\t0\t\t-2\n",
    );
    assert_eq!(
        finding_of(&partition, SWAP_PROTECTION).unwrap().status,
        CheckStatus::Attention
    );
    partition.set("crypt:/dev/mapper/cryptswap", "1");
    assert_eq!(
        finding_of(&partition, SWAP_PROTECTION).unwrap().status,
        CheckStatus::Ok
    );

    let apart = recorded("ubuntu-26.04");
    with_drive_tools(&apart).set("root.source", "/dev/vda2");
    apart.set("mount:/swap.img", "/dev/mapper/swapvol");
    apart.set("crypt:/dev/mapper/swapvol", "1");
    assert_eq!(
        finding_of(&apart, SWAP_PROTECTION).unwrap().status,
        CheckStatus::Ok
    );
}

#[test]
fn one_unprotected_area_is_enough_and_no_swap_at_all_is_fine() {
    let mixed = recorded("fedora-44");
    with_drive_tools(&mixed).set("root.source", "/dev/vda3");
    mixed.file(
        "/proc/swaps",
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/zram0                              partition\t3989500\t\t0\t\t100\n/swapfile                               file\t\t1048572\t\t0\t\t-2\n",
    );
    assert_eq!(
        finding_of(&mixed, SWAP_PROTECTION).unwrap().status,
        CheckStatus::Attention
    );

    let none = recorded("ubuntu-26.04");
    none.file(
        "/proc/swaps",
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n",
    );
    let found = finding_of(&none, SWAP_PROTECTION).unwrap();
    assert_eq!(found.status, CheckStatus::Ok);
    assert_eq!(found.detail, f::SWAP_SAFE);
}

#[test]
fn nothing_is_said_about_memory_saved_to_the_drive_when_it_cannot_be_traced() {
    let sim = recorded("ubuntu-26.04");
    assert!(
        finding_of(&sim, SWAP_PROTECTION).is_none(),
        "no drive tools installed"
    );
    with_drive_tools(&sim).set("root.source", "/dev/vda2");
    sim.fail("/usr/bin/lsblk");
    assert!(finding_of(&sim, SWAP_PROTECTION).is_none());

    let odd = recorded("ubuntu-26.04");
    with_drive_tools(&odd).set("root.source", "/dev/vda2");
    odd.file(
        "/proc/swaps",
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/odd\\040name                            file\t\t100\t\t0\t\t-2\n",
    );
    assert!(finding_of(&odd, SWAP_PROTECTION).is_none());

    let overlay = recorded("ubuntu-26.04");
    with_drive_tools(&overlay).set("root.source", "overlay");
    assert!(finding_of(&overlay, SWAP_PROTECTION).is_none());
    drop_file(&overlay, "/proc/swaps");
    assert!(finding_of(&overlay, SWAP_PROTECTION).is_none());
}
