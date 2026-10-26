//! The Linux controls against computers that look like real installs: every fix is followed by a check and an undo, and
//! the undo must leave the computer reading exactly as it did before.

use super::sim::Sim;
use super::*;
use crate::engine::{assessment, Engine};
use crate::linux::backend::LinuxBackend;
use crate::linux::catalog::{spec, specs, Scope};
use crate::model::{Backend, CheckStatus, Control};
use crate::os::Os;
use serde_json::json;

const MEMO: &str = "/var/lib/secblitz/Linux";

fn backend(sim: &Sim) -> LinuxBackend<Sim> {
    LinuxBackend::new(sim.clone(), MEMO.into())
}

fn ubuntu() -> Sim {
    let sim = Sim::fixture("ubuntu-26.04");
    for tool in [
        "/usr/sbin/ufw",
        "/usr/bin/dpkg-query",
        "/usr/bin/apt-config",
        "/usr/sbin/sysctl",
    ] {
        sim.tool(tool);
    }
    sim.unit("ufw.service", "enabled", true)
        .unit("unattended-upgrades.service", "enabled", true)
        .unit("apport.service", "enabled", true)
        .unit("NetworkManager.service", "enabled", true)
        .set("dpkg.unattended", "1")
        .set("ufw.active", "0")
        .file("/etc/machine-id", "0123456789abcdef\n");
    sim
}

fn debian() -> Sim {
    let sim = Sim::fixture("debian-13");
    for tool in [
        "/usr/sbin/ufw",
        "/usr/bin/dpkg-query",
        "/usr/bin/apt-config",
        "/usr/sbin/sysctl",
        "/usr/sbin/sshd",
    ] {
        sim.tool(tool);
    }
    sim.unit("ufw.service", "enabled", true)
        .unit("ssh.service", "enabled", true)
        .unit("sshd.service", "alias", true)
        .unit("NetworkManager.service", "enabled", true)
        .set("dpkg.unattended", "1")
        .set("ufw.active", "0")
        .file("/etc/machine-id", "0123456789abcdef\n");
    sim
}

fn fedora() -> Sim {
    let sim = Sim::fixture("fedora-44");
    for tool in [
        "/usr/bin/firewall-cmd",
        "/usr/bin/firewall-offline-cmd",
        "/usr/sbin/sysctl",
        "/usr/sbin/sshd",
    ] {
        sim.tool(tool);
    }
    sim.unit("firewalld.service", "enabled", true)
        .unit("sshd.service", "disabled", false)
        .unit("NetworkManager.service", "enabled", true)
        .file("/usr/bin/gnome-software", "")
        .set("fw.zone", "FedoraWorkstation")
        .set("fw.target.FedoraWorkstation", "default")
        .set(
            "fw.ports.FedoraWorkstation",
            "1025-65535/tcp 1025-65535/udp",
        )
        .file("/etc/machine-id", "0123456789abcdef\n");
    sim
}

/// Fedora with the automatic updater added, which a stock Workstation does not have.
fn fedora_automatic() -> Sim {
    let sim = fedora();
    sim.unit("dnf5-automatic.timer", "disabled", false).file(
        "/usr/share/dnf5/dnf5-plugins/automatic.conf",
        "[commands]\napply_updates = no\n",
    );
    sim
}

fn linuxmint() -> Sim {
    let sim = Sim::fixture("mint-22.3");
    for tool in [
        "/usr/sbin/ufw",
        "/usr/bin/dpkg-query",
        "/usr/bin/apt-config",
        "/usr/sbin/sysctl",
        "/usr/bin/mintupdate-automation",
    ] {
        sim.tool(tool);
    }
    sim.unit("ufw.service", "enabled", true)
        .unit("mintupdate-automation-upgrade.timer", "disabled", false)
        .unit("apt-daily-upgrade.timer", "enabled", true)
        .unit("NetworkManager.service", "enabled", true)
        .file("/usr/bin/mintupdate-automation", "")
        .file("/etc/X11/default-display-manager", "/usr/sbin/lightdm\n")
        .set("dpkg.unattended", "0")
        .set("ufw.active", "0")
        .file("/etc/machine-id", "0123456789abcdef\n");
    sim
}

fn value(b: &mut LinuxBackend<Sim>, id: &str) -> Value {
    b.observe(id).unwrap().value
}

fn status(b: &mut LinuxBackend<Sim>, id: &str) -> CheckStatus {
    assessment(id, &b.observe(id).unwrap()).unwrap()
}

/// A check the engine would report as skipped: something looks unprotected, but it may not be touched.
fn skipped(b: &mut LinuxBackend<Sim>, id: &str) -> bool {
    let o = b.observe(id).unwrap();
    !o.eligible && spec(id).unwrap().any_unsafe(&o.value)
}

/// What the engine does: read, derive the fixed value, write it, read it back, then write the original back.
fn cycle(sim: &Sim, id: &str) -> (Value, Value) {
    let mut b = backend(sim);
    let before = value(&mut b, id);
    let s = spec(id).unwrap();
    assert!(s.any_unsafe(&before), "{id} should need a fix: {before}");
    let fixed = s.derive_target(&before).unwrap();
    b.write(id, &fixed).unwrap();
    let after = value(&mut b, id);
    assert_eq!(after, fixed, "{id} did not read back as fixed");
    assert!(!s.any_unsafe(&after), "{id} is still unsafe: {after}");
    b.write(id, &before).unwrap();
    assert_eq!(value(&mut b, id), before, "{id} did not undo exactly");
    (before, fixed)
}

fn set_file(sim: &Sim, path: &str, f: impl FnOnce(&str) -> String) {
    let old = sim.text(path).unwrap();
    sim.file(path, &f(&old));
}

#[test]
fn a_stock_ubuntu_install_reads_as_it_really_is() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    assert_eq!(b.machine_id().unwrap(), "0123456789abcdef");
    assert_eq!(
        value(&mut b, "linux.firewall"),
        json!({"items": {"enabled": "no", "incoming": "deny"}})
    );
    assert_eq!(status(&mut b, "linux.firewall"), CheckStatus::Attention);
    assert_eq!(
        value(&mut b, "linux.auto_updates"),
        json!({"items": {"unattended": 1}})
    );
    assert_eq!(status(&mut b, "linux.auto_updates"), CheckStatus::Compliant);
    assert_eq!(
        value(&mut b, "linux.kernel_protections"),
        json!({"items": {"kptr_restrict": 1, "dmesg_restrict": 1, "protected_hardlinks": 1,
            "protected_symlinks": 1, "protected_fifos": 1, "protected_regular": 2}})
    );
    assert_eq!(
        status(&mut b, "linux.kernel_protections"),
        CheckStatus::Compliant
    );
    for id in [
        "linux.ssh_server",
        "linux.file_sharing",
        "linux.autologin",
        "linux.guest",
    ] {
        assert_eq!(status(&mut b, id), CheckStatus::Compliant, "{id}");
    }
    assert_eq!(
        value(&mut b, "linux.autologin"),
        json!({"items": {"gdm_automatic": null, "lightdm_user": null}})
    );
    assert_eq!(
        value(&mut b, "linux.crash_reports"),
        json!({"items": {"apport": 1}})
    );
    assert_eq!(
        status(&mut b, "linux.crash_reports"),
        CheckStatus::Attention
    );
    assert_eq!(
        value(&mut b, "linux.connectivity_check"),
        json!({"items": {"enabled": 1}})
    );
    assert_eq!(
        value(&mut b, "linux.wifi_mac"),
        json!({"items": {"cloned_mac": "preserve"}})
    );
}

#[test]
fn ubuntu_firewall_is_turned_on_and_off_again_exactly() {
    let sim = ubuntu();
    let (before, fixed) = cycle(&sim, "linux.firewall");
    assert_eq!(
        before,
        json!({"items": {"enabled": "no", "incoming": "deny"}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"enabled": "yes", "incoming": "deny"}})
    );
    assert_eq!(
        sim.text("/etc/ufw/ufw.conf")
            .unwrap()
            .matches("ENABLED=no")
            .count(),
        1
    );
    assert!(!sim.ran("/usr/sbin/ufw default deny incoming"));
}

#[test]
fn a_firewall_that_lets_everything_in_is_set_to_deny_and_back() {
    let sim = ubuntu();
    sim.set("ufw.active", "1");
    set_file(&sim, "/etc/ufw/ufw.conf", |t| {
        t.replace("ENABLED=no", "ENABLED=yes")
    });
    set_file(&sim, "/etc/default/ufw", |t| {
        t.replace(
            "DEFAULT_INPUT_POLICY=\"DROP\"",
            "DEFAULT_INPUT_POLICY=\"ACCEPT\"",
        )
    });
    let (before, fixed) = cycle(&sim, "linux.firewall");
    assert_eq!(
        before,
        json!({"items": {"enabled": "yes", "incoming": "allow"}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"enabled": "yes", "incoming": "deny"}})
    );
    assert!(sim.ran("/usr/sbin/ufw default deny incoming"));
    assert!(sim.ran("/usr/sbin/ufw default allow incoming"));
}

#[test]
fn a_computer_with_no_firewall_program_is_skipped_with_a_plain_reason() {
    let sim = ubuntu();
    sim.tools.borrow_mut().remove("/usr/sbin/ufw");
    sim.units.borrow_mut().remove("ufw.service");
    let mut b = backend(&sim);
    let o = b.observe("linux.firewall").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, NO_FIREWALL);
    assert!(skipped(&mut b, "linux.firewall"));
}

#[test]
fn unattended_upgrades_is_switched_on_with_its_own_file_and_undone_by_removing_it() {
    let sim = ubuntu();
    set_file(&sim, "/etc/apt/apt.conf.d/20auto-upgrades", |t| {
        t.replace("Unattended-Upgrade \"1\"", "Unattended-Upgrade \"0\"")
    });
    let original = sim.text("/etc/apt/apt.conf.d/20auto-upgrades").unwrap();
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.auto_updates");
    assert_eq!(before, json!({"items": {"unattended": 0}}));
    let fixed = spec("linux.auto_updates")
        .unwrap()
        .derive_target(&before)
        .unwrap();
    b.write("linux.auto_updates", &fixed).unwrap();
    assert!(sim.has("/etc/apt/apt.conf.d/52secblitz-auto-upgrades"));
    assert_eq!(value(&mut b, "linux.auto_updates"), fixed);
    b.write("linux.auto_updates", &before).unwrap();
    assert!(!sim.has("/etc/apt/apt.conf.d/52secblitz-auto-upgrades"));
    assert_eq!(value(&mut b, "linux.auto_updates"), before);
    assert_eq!(
        sim.text("/etc/apt/apt.conf.d/20auto-upgrades").unwrap(),
        original
    );
}

#[test]
fn the_updater_is_not_installed_so_the_check_is_skipped() {
    let sim = ubuntu();
    sim.set("dpkg.unattended", "0");
    let mut b = backend(&sim);
    let o = b.observe("linux.auto_updates").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, NO_AUTO_UPDATES);
    assert!(skipped(&mut b, "linux.auto_updates"));
}

#[test]
fn kernel_settings_are_fixed_kept_and_put_back() {
    let sim = ubuntu();
    sim.file("/proc/sys/kernel/kptr_restrict", "0\n");
    sim.file("/proc/sys/fs/protected_fifos", "0\n");
    let (before, fixed) = cycle(&sim, "linux.kernel_protections");
    assert_eq!(before["items"]["kptr_restrict"], 0);
    assert_eq!(fixed["items"]["kptr_restrict"], 1);
    assert_eq!(fixed["items"]["protected_regular"], 2);
    assert!(!sim.has("/etc/sysctl.d/90-secblitz.conf"));
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.kptr_restrict=1"));
    assert!(sim.ran("/usr/sbin/sysctl -w kernel.kptr_restrict=0"));
}

#[test]
fn the_kernel_file_holds_only_what_secblitz_set() {
    let sim = ubuntu();
    sim.file("/proc/sys/kernel/kptr_restrict", "0\n");
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.kernel_protections");
    let fixed = spec("linux.kernel_protections")
        .unwrap()
        .derive_target(&before)
        .unwrap();
    b.write("linux.kernel_protections", &fixed).unwrap();
    let file = sim.text("/etc/sysctl.d/90-secblitz.conf").unwrap();
    assert!(file.contains("kernel.kptr_restrict = 1\n"));
    assert!(!file.contains("dmesg"));
    assert!(!file.contains("protected"));
}

#[test]
fn crash_reports_are_switched_off_in_place_and_back() {
    let sim = ubuntu();
    let original = sim.text("/etc/default/apport").unwrap();
    let (_, fixed) = cycle(&sim, "linux.crash_reports");
    assert_eq!(fixed, json!({"items": {"apport": 0}}));
    assert_eq!(sim.text("/etc/default/apport").unwrap(), original);
}

#[test]
fn the_internet_check_gets_its_own_file_which_an_undo_removes() {
    let sim = ubuntu();
    let (_, fixed) = cycle(&sim, "linux.connectivity_check");
    assert_eq!(fixed, json!({"items": {"enabled": 0}}));
    assert!(!sim.has("/etc/NetworkManager/conf.d/90-secblitz-connectivity.conf"));
    assert!(sim.ran("/usr/bin/systemctl reload NetworkManager.service"));
}

#[test]
fn the_wifi_address_policy_is_set_to_stable_and_back() {
    let sim = ubuntu();
    let (before, fixed) = cycle(&sim, "linux.wifi_mac");
    assert_eq!(before, json!({"items": {"cloned_mac": "preserve"}}));
    assert_eq!(fixed, json!({"items": {"cloned_mac": "stable"}}));
}

#[test]
fn a_hardware_address_from_the_administrator_comes_back_after_an_undo() {
    let sim = ubuntu();
    sim.file(
        "/etc/NetworkManager/conf.d/10-mine.conf",
        "[connection]\nwifi.cloned-mac-address=00:11:22:33:44:55\n",
    );
    let (before, _) = cycle(&sim, "linux.wifi_mac");
    assert_eq!(
        before,
        json!({"items": {"cloned_mac": "00:11:22:33:44:55"}})
    );
    assert!(sim.has("/etc/NetworkManager/conf.d/10-mine.conf"));
}

#[test]
fn network_manager_missing_is_skipped_not_an_error() {
    let sim = ubuntu();
    sim.files.borrow_mut().remove(std::path::Path::new(
        "/etc/NetworkManager/NetworkManager.conf",
    ));
    let mut b = backend(&sim);
    let o = b.observe("linux.wifi_mac").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, NO_NETWORK_MANAGER);
    assert_eq!(
        value(&mut b, "linux.connectivity_check"),
        json!({"items": {"enabled": null}})
    );
}

#[test]
fn a_wifi_policy_of_the_wrong_kind_is_never_written() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    for bad in [
        "stable\nfoo=bar",
        "stable-ssid;rm",
        "00:11:22:33:44",
        "caf\u{e9}",
    ] {
        let v = json!({"items": {"cloned_mac": bad}});
        assert!(b.write("linux.wifi_mac", &v).is_err(), "{bad:?}");
    }
    assert!(!sim.has("/etc/NetworkManager/conf.d/90-secblitz-wifi-mac.conf"));
}

#[test]
fn ssh_server_is_stopped_and_restored_exactly_as_it_was() {
    let sim = debian();
    sim.unit("ssh.socket", "enabled", true);
    let (before, _) = cycle(&sim, "linux.ssh_server");
    assert_eq!(before, json!({"items": {"enabled": 1}}));
    assert_eq!(sim.state("ssh.service"), ("enabled".into(), true));
    assert_eq!(sim.state("ssh.socket"), ("enabled".into(), true));
    assert_eq!(sim.state("sshd.service"), ("alias".into(), true));
    assert!(sim.ran("/usr/bin/systemctl disable --now ssh.socket"));
    assert!(!sim.has("/var/lib/secblitz/Linux/ssh-units.txt"));
}

#[test]
fn a_service_that_was_only_running_is_only_stopped_and_started_again() {
    let sim = debian();
    sim.unit("ssh.service", "disabled", true);
    let mut b = backend(&sim);
    let fixed = json!({"items": {"enabled": 0}});
    b.write("linux.ssh_server", &fixed).unwrap();
    assert_eq!(sim.state("ssh.service"), ("disabled".into(), false));
    b.write("linux.ssh_server", &json!({"items": {"enabled": 1}}))
        .unwrap();
    assert_eq!(sim.state("ssh.service"), ("disabled".into(), true));
}

#[test]
fn a_second_fix_does_not_lose_the_record_of_the_first() {
    let sim = debian();
    let mut b = backend(&sim);
    let off = json!({"items": {"enabled": 0}});
    b.write("linux.ssh_server", &off).unwrap();
    b.write("linux.ssh_server", &off).unwrap();
    b.write("linux.ssh_server", &json!({"items": {"enabled": 1}}))
        .unwrap();
    assert_eq!(sim.state("ssh.service"), ("enabled".into(), true));
}

#[test]
fn without_a_record_the_server_comes_back_as_the_service_only() {
    let sim = debian();
    sim.unit("ssh.service", "disabled", false);
    let mut b = backend(&sim);
    b.write("linux.ssh_server", &json!({"items": {"enabled": 1}}))
        .unwrap();
    assert_eq!(sim.state("ssh.service"), ("enabled".into(), true));
}

#[test]
fn ssh_passwords_are_switched_off_with_a_file_that_comes_first() {
    let sim = debian();
    sim.file(
        "/etc/ssh/sshd_config.d/50-cloud-init.conf",
        "PasswordAuthentication yes\n",
    );
    sim.file(
        "/home/sam/.ssh/authorized_keys",
        "# mine\nssh-ed25519 AAAA sam\n",
    );
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.ssh_password");
    assert_eq!(
        before,
        json!({"items": {"password": 1, "root_login": "prohibit-password"}})
    );
    assert_eq!(status(&mut b, "linux.ssh_password"), CheckStatus::Attention);
    let (_, fixed) = cycle(&sim, "linux.ssh_password");
    assert_eq!(
        fixed,
        json!({"items": {"password": 0, "root_login": "prohibit-password"}})
    );
    assert!(!sim.has("/etc/ssh/sshd_config.d/00-secblitz.conf"));
    assert!(sim.ran("/usr/bin/systemctl reload ssh.service"));
}

#[test]
fn passwords_are_not_switched_off_while_nobody_has_a_key() {
    let sim = debian();
    sim.file("/home/sam/.ssh/authorized_keys", "# nothing yet\n\n");
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.ssh_password");
    assert_eq!(before["items"]["password"], 1);
    let fixed = json!({"items": {"password": 0, "root_login": "prohibit-password"}});
    let e = b.write("linux.ssh_password", &fixed).unwrap_err();
    assert_eq!(e.to_string(), NO_SIGN_IN_KEY);
    assert!(!sim.has("/etc/ssh/sshd_config.d/00-secblitz.conf"));
    assert_eq!(value(&mut b, "linux.ssh_password"), before);
    sim.file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA admin\n");
    b.write("linux.ssh_password", &fixed).unwrap();
    assert_eq!(value(&mut b, "linux.ssh_password")["items"]["password"], 0);
    sim.files
        .borrow_mut()
        .remove(std::path::Path::new("/root/.ssh/authorized_keys"));
    b.write("linux.ssh_password", &before).unwrap();
    assert_eq!(value(&mut b, "linux.ssh_password"), before);
}

#[test]
fn a_root_login_that_is_allowed_is_closed_and_a_bad_file_is_taken_away_again() {
    let sim = debian();
    sim.file("/home/sam/.ssh/authorized_keys", "ssh-ed25519 AAAA sam\n");
    set_file(&sim, "/etc/ssh/sshd_config", |t| {
        t.replace("#PermitRootLogin prohibit-password", "PermitRootLogin yes")
    });
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.ssh_password")["items"]["root_login"],
        "yes"
    );
    cycle(&sim, "linux.ssh_password");
    sim.fail("/usr/sbin/sshd -t");
    let fixed = json!({"items": {"password": 0, "root_login": "no"}});
    assert!(b.write("linux.ssh_password", &fixed).is_err());
    assert!(!sim.has("/etc/ssh/sshd_config.d/00-secblitz.conf"));
}

#[test]
fn ssh_settings_are_left_alone_when_the_server_is_off_or_missing() {
    let sim = debian();
    sim.unit("ssh.service", "disabled", false);
    let mut b = backend(&sim);
    let o = b.observe("linux.ssh_password").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, REMOTE_SIGN_IN_OFF);
    assert!(skipped(&mut b, "linux.ssh_password"));
    sim.units.borrow_mut().clear();
    let o = b.observe("linux.ssh_password").unwrap();
    assert_eq!(o.reason, NO_REMOTE_SIGN_IN);
    sim.unit("ssh.service", "enabled", true)
        .fail("/usr/sbin/sshd -T");
    let o = b.observe("linux.ssh_password").unwrap();
    assert_eq!(o.reason, REMOTE_SIGN_IN_UNREADABLE);
}

#[test]
fn file_sharing_is_stopped_and_started_again() {
    let sim = debian();
    sim.unit("smbd.service", "enabled", true)
        .unit("nmbd.service", "enabled", true);
    let (before, _) = cycle(&sim, "linux.file_sharing");
    assert_eq!(before, json!({"items": {"samba": 1}}));
    assert_eq!(sim.state("smbd.service"), ("enabled".into(), true));
    assert_eq!(sim.state("nmbd.service"), ("enabled".into(), true));
}

#[test]
fn gdm_automatic_sign_in_is_turned_off_in_its_line_and_back() {
    let sim = ubuntu();
    set_file(&sim, "/etc/gdm3/custom.conf", |t| {
        t.replace("# Enabling automatic login\n#  AutomaticLoginEnable = true\n#  AutomaticLogin = user1\n", "# Enabling automatic login\nAutomaticLoginEnable = True\nAutomaticLogin = sam\n")
    });
    let original = sim.text("/etc/gdm3/custom.conf").unwrap();
    let (before, fixed) = cycle(&sim, "linux.autologin");
    assert_eq!(
        before,
        json!({"items": {"gdm_automatic": "true", "lightdm_user": null}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"gdm_automatic": "false", "lightdm_user": null}})
    );
    let after = sim.text("/etc/gdm3/custom.conf").unwrap();
    assert_eq!(after, original.replace("= True", "= true"));
}

fn mint() -> Sim {
    let sim = debian();
    sim.file("/etc/X11/default-display-manager", "/usr/sbin/lightdm\n");
    sim
}

#[test]
fn lightdm_automatic_sign_in_and_guests_are_changed_in_the_administrators_file() {
    let sim = mint();
    sim.file(
        "/etc/lightdm/lightdm.conf.d/70-linuxmint.conf",
        "[Seat:*]\nautologin-user=sam\nallow-guest=true\n",
    );
    let original = sim
        .text("/etc/lightdm/lightdm.conf.d/70-linuxmint.conf")
        .unwrap();
    let (before, _) = cycle(&sim, "linux.autologin");
    assert_eq!(
        before,
        json!({"items": {"gdm_automatic": null, "lightdm_user": "sam"}})
    );
    let (before, fixed) = cycle(&sim, "linux.guest");
    assert_eq!(before, json!({"items": {"allow_guest": "true"}}));
    assert_eq!(fixed, json!({"items": {"allow_guest": "false"}}));
    assert_eq!(
        sim.text("/etc/lightdm/lightdm.conf.d/70-linuxmint.conf")
            .unwrap(),
        original
    );
    assert!(!sim.has("/etc/lightdm/lightdm.conf.d/99-secblitz.conf"));
}

#[test]
fn lightdm_allows_guests_unless_told_otherwise_and_a_vendor_file_is_never_edited() {
    let sim = mint();
    sim.file(
        "/usr/share/lightdm/lightdm.conf.d/50-vendor.conf",
        "[Seat:*]\nallow-guest=true\n",
    );
    let (before, _) = cycle(&sim, "linux.guest");
    assert_eq!(before, json!({"items": {"allow_guest": "true"}}));
    assert_eq!(
        sim.text("/usr/share/lightdm/lightdm.conf.d/50-vendor.conf")
            .unwrap(),
        "[Seat:*]\nallow-guest=true\n"
    );
    assert!(!sim.has("/etc/lightdm/lightdm.conf.d/99-secblitz.conf"));
    let plain = mint();
    let (before, _) = cycle(&plain, "linux.guest");
    assert_eq!(before, json!({"items": {"allow_guest": "true"}}));
}

#[test]
fn a_user_name_with_odd_characters_is_never_written_or_trusted() {
    let sim = mint();
    sim.file(
        "/etc/lightdm/lightdm.conf",
        "[Seat:*]\nautologin-user=sam\n",
    );
    let mut b = backend(&sim);
    for bad in ["sam;x", "-sam", "sam kim", "", "a".repeat(33).as_str()] {
        let v = json!({"items": {"gdm_automatic": null, "lightdm_user": bad}});
        assert!(b.write("linux.autologin", &v).is_err(), "{bad:?}");
    }
    sim.file(
        "/etc/lightdm/lightdm.conf",
        "[Seat:*]\nautologin-user=sam$(x)\n",
    );
    assert!(b.observe("linux.autologin").is_err());
}

#[test]
fn fedora_stock_install_reads_as_it_really_is() {
    let sim = fedora();
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.firewall"),
        json!({"items": {"enabled": "yes", "incoming": "reject"}})
    );
    assert_eq!(status(&mut b, "linux.firewall"), CheckStatus::Compliant);
    assert_eq!(
        value(&mut b, "linux.fedora_open_ports"),
        json!({"items": {"open_ranges": "1025-65535/tcp 1025-65535/udp"}})
    );
    assert_eq!(
        value(&mut b, "linux.wifi_mac"),
        json!({"items": {"cloned_mac": "stable"}})
    );
    assert_eq!(status(&mut b, "linux.wifi_mac"), CheckStatus::Compliant);
    assert_eq!(
        value(&mut b, "linux.countme"),
        json!({"items": {"countme": 1}})
    );
    let o = b.observe("linux.auto_updates").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, SOFTWARE_APP_UPDATES);
    assert!(skipped(&mut b, "linux.auto_updates"));
    assert_eq!(
        value(&mut b, "linux.kernel_protections"),
        json!({"items": {"kptr_restrict": 0, "dmesg_restrict": 1, "protected_hardlinks": 1,
            "protected_symlinks": 1, "protected_fifos": 1, "protected_regular": 1}})
    );
    assert_eq!(
        value(&mut b, "linux.autologin"),
        json!({"items": {"gdm_automatic": null, "lightdm_user": null}})
    );
}

#[test]
fn fedora_without_the_software_app_says_updates_are_not_set_up() {
    let sim = fedora();
    sim.files
        .borrow_mut()
        .remove(std::path::Path::new("/usr/bin/gnome-software"));
    let o = backend(&sim).observe("linux.auto_updates").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, NO_AUTO_UPDATES);
    let e = backend(&sim)
        .write("linux.auto_updates", &json!({"items": {"unattended": 1}}))
        .unwrap_err();
    assert_eq!(e.to_string(), NO_AUTO_UPDATES);
}

#[test]
fn a_stock_linux_mint_install_reads_as_it_really_is() {
    let sim = linuxmint();
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.firewall"),
        json!({"items": {"enabled": "no", "incoming": "deny"}})
    );
    assert_eq!(status(&mut b, "linux.firewall"), CheckStatus::Attention);
    assert_eq!(
        value(&mut b, "linux.auto_updates"),
        json!({"items": {"unattended": 0}})
    );
    assert_eq!(status(&mut b, "linux.auto_updates"), CheckStatus::Attention);
    assert!(b.observe("linux.auto_updates").unwrap().eligible);
    assert_eq!(
        value(&mut b, "linux.kernel_protections"),
        json!({"items": {"kptr_restrict": 1, "dmesg_restrict": 0, "protected_hardlinks": 1,
            "protected_symlinks": 1, "protected_fifos": 1, "protected_regular": 2}})
    );
    assert_eq!(
        status(&mut b, "linux.kernel_protections"),
        CheckStatus::Attention
    );
    for id in [
        "linux.ssh_server",
        "linux.file_sharing",
        "linux.autologin",
        "linux.guest",
    ] {
        assert_eq!(status(&mut b, id), CheckStatus::Compliant, "{id}");
    }
    let ids: Vec<String> = b.controls().into_iter().map(|c| c.id).collect();
    assert!(ids.contains(&"linux.crash_reports".to_string()));
    assert!(!ids.contains(&"linux.countme".to_string()));
    assert_eq!(
        value(&mut b, "linux.crash_reports"),
        json!({"items": {"apport": null}})
    );
    assert_ne!(
        status(&mut b, "linux.crash_reports"),
        CheckStatus::Attention
    );
}

#[test]
fn linux_mint_updates_are_switched_on_with_its_own_tool_and_undone_exactly() {
    let sim = linuxmint();
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.auto_updates");
    let fixed = spec("linux.auto_updates")
        .unwrap()
        .derive_target(&before)
        .unwrap();
    b.write("linux.auto_updates", &fixed).unwrap();
    assert!(sim.ran("/usr/bin/mintupdate-automation upgrade enable"));
    assert!(sim.has("/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled"));
    assert_eq!(
        sim.state("mintupdate-automation-upgrade.timer"),
        ("enabled".into(), true)
    );
    assert_eq!(
        value(&mut b, "linux.auto_updates"),
        json!({"items": {"unattended": 1}})
    );
    assert_eq!(status(&mut b, "linux.auto_updates"), CheckStatus::Compliant);
    b.write("linux.auto_updates", &before).unwrap();
    assert!(sim.ran("/usr/bin/mintupdate-automation upgrade disable"));
    assert!(!sim.has("/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled"));
    assert_eq!(
        sim.state("mintupdate-automation-upgrade.timer"),
        ("disabled".into(), false)
    );
    assert_eq!(value(&mut b, "linux.auto_updates"), before);
}

#[test]
fn linux_mint_updates_that_were_already_on_are_never_turned_off() {
    let sim = linuxmint();
    sim.file(
        "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled",
        "",
    )
    .unit("mintupdate-automation-upgrade.timer", "enabled", true);
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.auto_updates"),
        json!({"items": {"unattended": 1}})
    );
    assert_eq!(status(&mut b, "linux.auto_updates"), CheckStatus::Compliant);
    let e = b
        .write("linux.auto_updates", &json!({"items": {"unattended": 0}}))
        .unwrap_err();
    assert_eq!(e.to_string(), NO_RECORD);
    assert!(!sim.ran("/usr/bin/mintupdate-automation upgrade disable"));
}

#[test]
fn linux_mint_half_set_up_updates_return_to_the_same_half() {
    let sim = linuxmint();
    sim.file(
        "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled",
        "",
    );
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.auto_updates");
    assert_eq!(before, json!({"items": {"unattended": 0}}));
    b.write("linux.auto_updates", &json!({"items": {"unattended": 1}}))
        .unwrap();
    assert_eq!(
        value(&mut b, "linux.auto_updates"),
        json!({"items": {"unattended": 1}})
    );
    b.write("linux.auto_updates", &before).unwrap();
    assert!(sim.has("/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled"));
    assert_eq!(
        sim.state("mintupdate-automation-upgrade.timer"),
        ("disabled".into(), false)
    );
}

#[test]
fn linux_mint_without_its_tool_falls_back_to_unattended_upgrades_being_absent() {
    let sim = linuxmint();
    sim.files
        .borrow_mut()
        .remove(std::path::Path::new("/usr/bin/mintupdate-automation"));
    let o = backend(&sim).observe("linux.auto_updates").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, NO_AUTO_UPDATES);
}

#[test]
fn the_wide_fedora_port_ranges_are_closed_and_opened_again_in_the_same_form() {
    let sim = fedora();
    let (before, fixed) = cycle(&sim, "linux.fedora_open_ports");
    assert_eq!(
        before,
        json!({"items": {"open_ranges": "1025-65535/tcp 1025-65535/udp"}})
    );
    assert_eq!(fixed, json!({"items": {"open_ranges": null}}));
    assert_eq!(sim.get("fw.ports.FedoraWorkstation").split(' ').count(), 2);
}

#[test]
fn only_wide_ranges_can_be_opened_and_only_a_few_at_once() {
    let sim = fedora();
    let mut b = backend(&sim);
    for bad in [
        "22-22/tcp",
        "1025-65535/sctp",
        "0-65535/tcp",
        "1025-70000/udp",
        "1025-65535/tcp;reboot",
        "1025-65535/tcp  1025-65535/udp",
        "9000-1000/tcp",
    ] {
        let v = json!({"items": {"open_ranges": bad}});
        assert!(b.write("linux.fedora_open_ports", &v).is_err(), "{bad:?}");
    }
    let many = (0..9)
        .map(|n| format!("{}-{}/tcp", 2000 + n * 2000, 3999 + n * 2000))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(b
        .write(
            "linux.fedora_open_ports",
            &json!({"items": {"open_ranges": many}})
        )
        .is_err());
    assert_eq!(
        sim.get("fw.ports.FedoraWorkstation"),
        "1025-65535/tcp 1025-65535/udp"
    );
}

#[test]
fn firewalld_that_is_stopped_is_started_and_stopped_again_as_it_was() {
    let sim = fedora();
    sim.unit("firewalld.service", "disabled", false);
    let (before, fixed) = cycle(&sim, "linux.firewall");
    assert_eq!(
        before,
        json!({"items": {"enabled": "no", "incoming": "reject"}})
    );
    assert_eq!(
        fixed,
        json!({"items": {"enabled": "yes", "incoming": "reject"}})
    );
    assert_eq!(sim.state("firewalld.service"), ("disabled".into(), false));
    let sim = fedora();
    sim.unit("firewalld.service", "enabled", false);
    cycle(&sim, "linux.firewall");
    assert_eq!(sim.state("firewalld.service"), ("enabled".into(), false));
}

#[test]
fn a_zone_that_accepts_everything_is_dropped_and_put_back() {
    let sim = fedora();
    sim.set("fw.target.FedoraWorkstation", "ACCEPT");
    let (before, fixed) = cycle(&sim, "linux.firewall");
    assert_eq!(before["items"]["incoming"], "allow");
    assert_eq!(fixed["items"]["incoming"], "deny");
    assert_eq!(sim.get("fw.target.FedoraWorkstation"), "ACCEPT");
}

#[test]
fn a_firewall_that_was_switched_off_for_good_or_cannot_be_read_is_left_alone() {
    let sim = fedora();
    sim.unit("firewalld.service", "masked", false);
    let mut b = backend(&sim);
    let o = b.observe("linux.firewall").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, FIREWALL_MASKED);
    assert!(b
        .write(
            "linux.firewall",
            &json!({"items": {"enabled": "yes", "incoming": "deny"}})
        )
        .is_err());
    let sim = fedora();
    sim.fail("/usr/bin/firewall-cmd");
    let mut b = backend(&sim);
    let o = b.observe("linux.firewall").unwrap();
    assert!(!o.eligible);
    assert_eq!(o.reason, FIREWALL_UNREADABLE);
    assert!(skipped(&mut b, "linux.firewall"));
}

#[test]
fn fedora_counting_is_switched_off_in_the_files_that_had_it_and_only_those() {
    let sim = fedora();
    let files = [
        "/etc/yum.repos.d/fedora.repo",
        "/etc/yum.repos.d/fedora-updates.repo",
        "/etc/yum.repos.d/fedora-updates-testing.repo",
        "/etc/yum.repos.d/fedora-cisco-openh264.repo",
    ];
    let originals: Vec<String> = files.iter().map(|f| sim.text(f).unwrap()).collect();
    let (_, fixed) = cycle(&sim, "linux.countme");
    assert_eq!(fixed, json!({"items": {"countme": 0}}));
    for (f, o) in files.iter().zip(&originals) {
        assert_eq!(&sim.text(f).unwrap(), o, "{f}");
    }
    let mut b = backend(&sim);
    let fixed = json!({"items": {"countme": 0}});
    b.write("linux.countme", &fixed).unwrap();
    assert_eq!(value(&mut b, "linux.countme"), fixed);
    assert!(!sim.text(files[0]).unwrap().contains("countme=1"));
}

#[test]
fn counting_cannot_be_restored_without_its_record_and_says_so() {
    let sim = fedora();
    let mut b = backend(&sim);
    let e = b
        .write("linux.countme", &json!({"items": {"countme": 1}}))
        .unwrap_err();
    assert_eq!(e.to_string(), NO_RECORD);
}

#[test]
fn counting_is_not_asked_about_where_there_are_no_software_sources() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    assert_eq!(
        value(&mut b, "linux.countme"),
        json!({"items": {"countme": null}})
    );
}

#[test]
fn dnf_automatic_is_switched_on_with_the_timer_and_restored() {
    let sim = fedora_automatic();
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.auto_updates");
    assert_eq!(before, json!({"items": {"unattended": 0}}));
    let fixed = json!({"items": {"unattended": 1}});
    b.write("linux.auto_updates", &fixed).unwrap();
    assert_eq!(value(&mut b, "linux.auto_updates"), fixed);
    assert_eq!(sim.state("dnf5-automatic.timer"), ("enabled".into(), true));
    assert!(sim
        .text("/etc/dnf/automatic.conf")
        .unwrap()
        .contains("apply_updates=yes"));
    b.write("linux.auto_updates", &before).unwrap();
    assert_eq!(value(&mut b, "linux.auto_updates"), before);
    assert_eq!(
        sim.state("dnf5-automatic.timer"),
        ("disabled".into(), false)
    );
    assert!(!sim.has("/etc/dnf/automatic.conf"));
}

#[test]
fn dnf_automatic_keeps_what_the_administrator_had_in_its_file() {
    let sim = fedora_automatic();
    sim.file(
        "/etc/dnf/automatic.conf",
        "[commands]\napply_updates = no\nrandom_sleep = 5\n",
    );
    sim.unit("dnf5-automatic.timer", "enabled", true);
    let mut b = backend(&sim);
    let before = value(&mut b, "linux.auto_updates");
    let fixed = json!({"items": {"unattended": 1}});
    b.write("linux.auto_updates", &fixed).unwrap();
    assert_eq!(
        sim.text("/etc/dnf/automatic.conf").unwrap(),
        "[commands]\napply_updates = yes\nrandom_sleep = 5\n"
    );
    b.write("linux.auto_updates", &before).unwrap();
    assert_eq!(
        sim.text("/etc/dnf/automatic.conf").unwrap(),
        "[commands]\napply_updates = no\nrandom_sleep = 5\n"
    );
    assert_eq!(sim.state("dnf5-automatic.timer"), ("enabled".into(), true));
}

#[test]
fn gdm_on_fedora_is_found_in_its_own_folder() {
    let sim = fedora();
    set_file(&sim, "/etc/gdm/custom.conf", |t| {
        t.replace("[daemon]", "[daemon]\nAutomaticLoginEnable=True")
    });
    let (before, _) = cycle(&sim, "linux.autologin");
    assert_eq!(before["items"]["gdm_automatic"], "true");
}

#[test]
fn a_third_value_since_the_fix_stops_the_engine_from_undoing_it() {
    let sim = ubuntu();
    sim.file("/proc/sys/kernel/kptr_restrict", "0\n");
    let dir = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_for(Os::Linux, dir.path().to_path_buf(), Box::new(backend(&sim))).unwrap();
    let applied = engine
        .apply_selected(&["linux.kernel_protections".to_string()], |_| {})
        .unwrap();
    let r = applied
        .results
        .iter()
        .find(|r| r.id == "linux.kernel_protections")
        .unwrap();
    assert_eq!(r.status, CheckStatus::Applied, "{}", r.detail);
    sim.file("/proc/sys/kernel/kptr_restrict", "2\n");
    let undone = engine.revert(|_| {}).unwrap();
    let r = undone
        .results
        .iter()
        .find(|r| r.id == "linux.kernel_protections")
        .unwrap();
    assert_eq!(r.status, CheckStatus::Conflict, "{}", r.detail);
    assert_eq!(sim.text("/proc/sys/kernel/kptr_restrict").unwrap(), "2\n");
}

#[test]
fn the_engine_checks_fixes_and_undoes_a_whole_ubuntu_install() {
    let sim = ubuntu();
    let dir = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open_for(Os::Linux, dir.path().to_path_buf(), Box::new(backend(&sim))).unwrap();
    let first = engine.audit().unwrap();
    let state = |r: &crate::engine::Report, id: &str| {
        r.results
            .iter()
            .find(|x| x.id == id)
            .unwrap()
            .status
            .clone()
    };
    assert_eq!(state(&first, "linux.firewall"), CheckStatus::Attention);
    assert_eq!(state(&first, "linux.crash_reports"), CheckStatus::Attention);
    assert_eq!(
        state(&first, "linux.kernel_protections"),
        CheckStatus::Compliant
    );
    assert!(first.results.iter().all(|r| r.id != "linux.countme"));
    assert!(!first.findings.is_empty());

    let picked = [
        "linux.firewall".to_string(),
        "linux.crash_reports".to_string(),
    ];
    let applied = engine.apply_selected(&picked, |_| {}).unwrap();
    for id in ["linux.firewall", "linux.crash_reports"] {
        assert_eq!(state(&applied, id), CheckStatus::Applied, "{id}");
    }
    assert!(sim
        .text("/etc/default/apport")
        .unwrap()
        .contains("enabled=0"));
    assert_eq!(sim.get("ufw.active"), "1");
    // The two optional checks are never part of "fix everything".
    assert_eq!(
        value(&mut backend(&sim), "linux.wifi_mac"),
        json!({"items": {"cloned_mac": "preserve"}})
    );

    let second = engine.audit().unwrap();
    assert_eq!(state(&second, "linux.firewall"), CheckStatus::Compliant);

    let undone = engine.revert(|_| {}).unwrap();
    for id in ["linux.firewall", "linux.crash_reports"] {
        assert_eq!(state(&undone, id), CheckStatus::Restored, "{id}");
    }
    let third = engine.audit().unwrap();
    for r in &first.results {
        assert_eq!(state(&third, &r.id), r.status, "{}", r.id);
    }
    assert_eq!(sim.get("ufw.active"), "0");
}

#[test]
fn the_controls_listed_follow_the_distribution() {
    let ubuntu = backend(&ubuntu()).controls();
    let fedora = backend(&fedora()).controls();
    let ids = |c: &[Control]| c.iter().map(|c| c.id.clone()).collect::<Vec<_>>();
    assert_eq!(ubuntu.len(), 11);
    assert_eq!(fedora.len(), 12);
    assert!(ids(&ubuntu).contains(&"linux.crash_reports".to_string()));
    assert!(!ids(&ubuntu).contains(&"linux.countme".to_string()));
    assert!(ids(&fedora).contains(&"linux.fedora_open_ports".to_string()));
    assert!(!ids(&fedora).contains(&"linux.crash_reports".to_string()));
    for c in ubuntu.iter().chain(&fedora) {
        let s = spec(&c.id).unwrap();
        assert_eq!(s.scope, Scope::System);
        assert_eq!(c.target, s.catalog_target());
    }
    let all: Vec<&str> = specs()
        .iter()
        .filter(|s| s.scope == Scope::System)
        .map(|s| s.id)
        .collect();
    for id in all {
        assert!(
            ubuntu.iter().chain(&fedora).any(|c| c.id == id),
            "{id} is not offered on any distribution"
        );
    }
}

#[test]
fn person_controls_and_unknown_ids_are_refused() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    assert!(b.observe("linux.screen_lock").is_err());
    assert!(b.observe("defender.realtime").is_err());
    assert!(b
        .write(
            "linux.screen_lock",
            &json!({"items": {"lock_enabled": 1, "idle_never": 0}})
        )
        .is_err());
}

#[test]
fn a_value_that_is_not_a_legal_setting_is_refused_before_anything_runs() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    for v in [
        json!({"items": {"enabled": "maybe", "incoming": "deny"}}),
        json!({"items": {"enabled": "yes"}}),
        json!({"enabled": "yes", "incoming": "deny"}),
    ] {
        assert!(b.write("linux.firewall", &v).is_err(), "{v}");
    }
    assert!(sim.calls.borrow().is_empty());
}

#[test]
fn the_machine_identity_is_required() {
    let sim = ubuntu();
    sim.files
        .borrow_mut()
        .remove(std::path::Path::new("/etc/machine-id"));
    let e = backend(&sim).machine_id().unwrap_err();
    assert_eq!(e.to_string(), MACHINE_ID_MISSING);
}

#[test]
fn findings_report_what_cannot_be_fixed() {
    let sim = ubuntu();
    sim.tool("/usr/bin/findmnt")
        .tool("/usr/bin/lsblk")
        .tool("/usr/lib/update-notifier/apt-check")
        .set("root.source", "/dev/mapper/ubuntu--vg-root")
        .set("apt.waiting", "3");
    sim.file("/sys/module/apparmor/parameters/enabled", "Y\n");
    sim.files.borrow_mut().insert(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c".into(),
        vec![6, 0, 0, 0, 1],
    );
    let mut b = backend(&sim);
    let found = b.findings().unwrap();
    let get = |title: &str| found.iter().find(|f| f.title == title).unwrap();
    assert_eq!(
        get(crate::advice::DISK_ENCRYPTION).status,
        CheckStatus::Attention
    );
    assert_eq!(
        get(crate::advice::LINUX_SECURE_BOOT).status,
        CheckStatus::Ok
    );
    assert_eq!(
        get(crate::advice::UPDATES_WAITING).status,
        CheckStatus::Attention
    );
    assert_eq!(get(crate::advice::RESTART_NEEDED).status, CheckStatus::Ok);
    assert_eq!(get(crate::advice::PROGRAM_LIMITS).status, CheckStatus::Ok);
    assert!(found
        .iter()
        .all(|f| f.detail != crate::linux::controls::findings::SELINUX_ON));

    sim.set("root.crypt", "1").set("apt.waiting", "0");
    sim.file("/run/reboot-required", "*** System restart required ***\n");
    sim.files.borrow_mut().insert(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c".into(),
        vec![6, 0, 0, 0, 0],
    );
    sim.file("/sys/module/apparmor/parameters/enabled", "N\n");
    let found = b.findings().unwrap();
    let get = |title: &str| found.iter().find(|f| f.title == title).unwrap();
    assert_eq!(get(crate::advice::DISK_ENCRYPTION).status, CheckStatus::Ok);
    assert_eq!(
        get(crate::advice::LINUX_SECURE_BOOT).status,
        CheckStatus::Attention
    );
    assert_eq!(get(crate::advice::UPDATES_WAITING).status, CheckStatus::Ok);
    assert_eq!(
        get(crate::advice::RESTART_NEEDED).status,
        CheckStatus::Attention
    );
    assert_eq!(
        get(crate::advice::PROGRAM_LIMITS).status,
        CheckStatus::Attention
    );
}

#[test]
fn findings_that_cannot_be_told_are_unknown_not_a_problem() {
    let sim = ubuntu();
    let mut b = backend(&sim);
    let found = b.findings().unwrap();
    for title in [
        crate::advice::DISK_ENCRYPTION,
        crate::advice::LINUX_SECURE_BOOT,
        crate::advice::UPDATES_WAITING,
    ] {
        let f = found.iter().find(|f| f.title == title).unwrap();
        assert_eq!(f.status, CheckStatus::Unknown, "{title}");
    }
}

#[test]
fn fedora_findings_use_its_own_tools() {
    let sim = fedora();
    sim.tool("/usr/bin/dnf5");
    sim.file("/sys/fs/selinux/enforce", "1");
    let mut b = backend(&sim);
    let found = b.findings().unwrap();
    assert!(found
        .iter()
        .any(|f| f.title == crate::advice::PROGRAM_LIMITS && f.status == CheckStatus::Ok));
    assert!(found
        .iter()
        .all(|f| f.detail != crate::linux::controls::findings::APPARMOR_ON));
}

#[test]
fn fedora_never_downloads_package_lists_and_an_empty_cache_is_not_a_restart() {
    let sim = fedora();
    sim.tool("/usr/bin/dnf5");
    let mut b = backend(&sim);
    let status = |b: &mut LinuxBackend<Sim>, title: &str| {
        let found = b.findings().unwrap();
        found
            .iter()
            .find(|f| f.title == title)
            .map(|f| f.status.clone())
    };
    assert_eq!(status(&mut b, crate::advice::RESTART_NEEDED), None);
    assert_eq!(
        status(&mut b, crate::advice::UPDATES_WAITING),
        Some(CheckStatus::Unknown)
    );
    sim.set("dnf.cache", "1");
    assert_eq!(
        status(&mut b, crate::advice::RESTART_NEEDED),
        Some(CheckStatus::Ok)
    );
    assert_eq!(
        status(&mut b, crate::advice::UPDATES_WAITING),
        Some(CheckStatus::Ok)
    );
    sim.set("dnf.restart", "1").set("dnf.waiting", "1");
    assert_eq!(
        status(&mut b, crate::advice::RESTART_NEEDED),
        Some(CheckStatus::Attention)
    );
    assert_eq!(
        status(&mut b, crate::advice::UPDATES_WAITING),
        Some(CheckStatus::Attention)
    );
    assert!(sim
        .calls
        .borrow()
        .iter()
        .filter(|c| c.starts_with("/usr/bin/dnf5"))
        .all(|c| c.starts_with("/usr/bin/dnf5 -C ")));
}

#[test]
fn the_notes_folder_is_not_mistaken_for_a_journal() {
    let sim = ubuntu();
    let dir = tempfile::tempdir().unwrap();
    let notes = dir.path().join(crate::platform::LINUX_NOTES);
    std::fs::create_dir(&notes).unwrap();
    std::fs::write(notes.join("ssh-units.txt"), b"ssh.service 1 1\n").unwrap();
    let mut engine =
        Engine::open_for(Os::Linux, dir.path().to_path_buf(), Box::new(backend(&sim))).unwrap();
    engine.audit().unwrap();
    assert!(engine.history().unwrap().is_empty());
    assert_eq!(
        std::fs::read(notes.join("ssh-units.txt")).unwrap(),
        b"ssh.service 1 1\n"
    );
}

#[test]
fn every_finding_title_the_linux_backend_can_emit_has_linux_advice_and_no_windows_words() {
    use crate::advice::{finding_impact, for_finding, is_linux_finding, NextStep};
    for title in findings::TITLES {
        assert!(is_linux_finding(title), "{title} has no Linux advice");
        let a = for_finding(title, &CheckStatus::Attention, "");
        assert_ne!(a.label, "Protection check", "{title}");
        assert_ne!(a.step, NextStep::Repair, "{title}");
        let x = crate::explain::for_check(title)
            .unwrap_or_else(|| panic!("no explanation for {title}"));
        for line in [
            a.label,
            a.next,
            a.impact,
            finding_impact(title),
            x.what,
            x.risk,
            x.change,
        ] {
            assert!(!line.is_empty(), "{title}");
            for word in ["Windows", "Microsoft", "BitLocker", "BIOS"] {
                assert!(!line.contains(word), "{title}: {line}");
            }
        }
    }
}
