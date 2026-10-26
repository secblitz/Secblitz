use super::*;
use crate::linux::cmd::fake::FakeSys;
use std::path::Path;

const UBUNTU: &[u8] = b"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n";
const FEDORA: &[u8] = b"ID=fedora\nVERSION_ID=44\n";

/// Ubuntu's /etc/os-release is a link, which is never read, so only the copy in /usr/lib is there.
fn ubuntu() -> FakeSys {
    let sys = FakeSys::default();
    sys.file("/usr/lib/os-release", UBUNTU);
    sys
}

fn fedora() -> FakeSys {
    let sys = FakeSys::default();
    sys.file("/etc/os-release", FEDORA);
    sys
}

const DPKG: [&str; 2] = ["-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"];

fn called(sys: &FakeSys, key: &str) -> bool {
    sys.calls.borrow().iter().any(|c| c == key)
}

#[test]
fn linux_apps_come_after_the_windows_apps_and_never_match_a_windows_package() {
    let all = super::super::catalog();
    let windows = super::super::catalog::CATALOG.len();
    assert_eq!(all.len(), windows + CATALOG.len());
    assert_eq!(all[windows].name, "TeamViewer");
    assert_eq!(super::super::catalog::owner("teamviewer"), None);
    assert_eq!(super::super::catalog::owner("anydesk"), None);
    assert_eq!(owner("teamviewer"), Some(windows as u16));
    assert_eq!(owner("teamviewer-host"), Some(windows as u16));
    assert_eq!(owner("anydesk"), Some(windows as u16 + 1));
    assert_eq!(owner("rustdesk"), Some(windows as u16 + 2));
    assert_eq!(owner("Microsoft.BingWeather"), None);
}

#[test]
fn only_remote_control_apps_are_in_the_catalog_and_none_is_a_system_package() {
    for name in [
        "ubuntu-desktop",
        "snapd",
        "gnome-shell",
        "firefox",
        "gnome-software",
        "firmware-updater",
        "gdm3",
        "openssh-server",
        "samba",
        "systemd",
    ] {
        assert_eq!(owner(name), None, "{name}");
    }
    assert!(CATALOG.iter().all(|a| a.group == Group::RemoteAccess));
}

#[test]
fn package_names_are_checked_before_any_program_sees_them() {
    for ok in ["teamviewer", "libfoo++", "a.b_c-d", "7zip"] {
        assert!(is_valid_package(ok), "{ok}");
    }
    for bad in [
        "",
        "-s",
        "Team",
        "a b",
        "a;b",
        "a/b",
        "../x",
        "é",
        &"a".repeat(101),
    ] {
        assert!(!is_valid_package(bad), "{bad}");
        assert_eq!(owner(bad), None);
    }
}

#[test]
fn installed_apps_are_found_by_package_name_on_a_debian_system() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/dpkg-query",
        &DPKG,
        0,
        "bash\t5.3-2\tii \nteamviewer\t15.5.1\tii \nteamviewer-host\t15.5.1\tii \nanydesk\t7.0\trc \nrustdesk\t1.3\tii \n",
    );
    let found = inventory(&sys).unwrap();
    let names: Vec<_> = found.iter().map(|i| i.package.as_str()).collect();
    assert_eq!(names, ["teamviewer", "teamviewer-host", "rustdesk"]);
    assert_eq!(found[0].index, found[1].index);
    assert_eq!(found[0].version, "15.5.1");
}

#[test]
fn installed_apps_are_found_by_package_name_on_a_fedora_system() {
    let sys = fedora();
    sys.reply(
        "/usr/bin/rpm",
        &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        0,
        "bash\t5.3-1.fc44\nanydesk\t7.0.0-1\n",
    );
    let found = inventory(&sys).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].package, "anydesk");
    assert_eq!(found[0].version, "7.0.0-1");
}

#[test]
fn a_failed_listing_and_an_unknown_system_are_plain_errors() {
    let sys = ubuntu();
    sys.reply("/usr/bin/dpkg-query", &DPKG, 2, "");
    assert_eq!(inventory(&sys).unwrap_err().to_string(), LIST_FAILED);
    let other = FakeSys::default();
    other.file("/etc/os-release", b"ID=arch\n");
    assert!(inventory(&other).is_err());
}

const APT_PLAN: &str = "NOTE: This is only a simulation!\nReading package lists...\nThe following packages will be REMOVED:\n  teamviewer\nRemv teamviewer [15.5.1]\nRemv teamviewer-host:amd64 [15.5.1]\n";

const DNF_PLAN: &str = "Package          Arch   Version         Repository   Size\nRemoving:\n anydesk x86_64 0:7.0.0-1 @System 9.1 MiB\nRemoving dependent packages:\n anydesk-extras x86_64 0:7.0.0-1 @System 1.0 MiB\n\nTransaction Summary:\n Removing:           2 packages\n\nAfter this operation, 10 MiB will be freed (install 0 B, remove 10 MiB).\nOperation aborted by the user.\n";

#[test]
fn a_simulated_removal_lists_every_package_it_would_take() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "teamviewer"],
        0,
        APT_PLAN,
    );
    assert_eq!(
        simulate(&sys, Manager::Apt, "teamviewer").unwrap(),
        ["teamviewer", "teamviewer-host"]
    );
    let sys = fedora();
    sys.reply(
        "/usr/bin/dnf",
        &["remove", "--assumeno", "--no-autoremove", "anydesk"],
        1,
        DNF_PLAN,
    );
    assert_eq!(
        simulate(&sys, Manager::Dnf, "anydesk").unwrap(),
        ["anydesk", "anydesk-extras"]
    );
    sys.reply(
        "/usr/bin/dnf",
        &["remove", "--assumeno", "--no-autoremove", "rustdesk"],
        1,
        "No packages to remove for argument: rustdesk\n\nNothing to do.\n",
    );
    assert!(simulate(&sys, Manager::Dnf, "rustdesk").unwrap().is_empty());
    sys.reply(
        "/usr/bin/dnf",
        &["remove", "--assumeno", "--no-autoremove", "anydesk"],
        1,
        "something unexpected\n",
    );
    assert_eq!(
        simulate(&sys, Manager::Dnf, "anydesk")
            .unwrap_err()
            .to_string(),
        FAILED
    );
    assert_eq!(
        simulate(&sys, Manager::Dnf, "-y").unwrap_err().to_string(),
        REFUSED
    );
}

#[test]
fn the_gate_lets_through_only_the_apps_own_packages() {
    let plan = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
    assert!(gate("teamviewer", &plan(&["teamviewer", "teamviewer-host"])).is_ok());
    assert!(gate("teamviewer", &plan(&[])).is_ok());
    for bad in [
        plan(&["teamviewer", "ubuntu-desktop"]),
        plan(&["teamviewer", "snapd"]),
        plan(&["gdm3"]),
        plan(&["firefox", "teamviewer"]),
        plan(&["gnome-software"]),
        plan(&["anydesk"]),
    ] {
        assert_eq!(
            gate("teamviewer", &bad).unwrap_err().to_string(),
            REFUSED,
            "{bad:?}"
        );
    }
    assert!(gate("ubuntu-desktop", &plan(&["ubuntu-desktop"])).is_err());
}

#[test]
fn an_app_is_removed_after_a_clean_simulation_and_read_back() {
    // The package manager lists the app before the removal and no longer afterwards.
    let after = ubuntu();
    after.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "anydesk"],
        0,
        "Remv anydesk [7.0]\n",
    );
    after.reply("/usr/bin/apt-get", &["remove", "-y", "anydesk"], 0, "");
    struct Flip<'a>(&'a FakeSys, std::cell::Cell<u32>);
    impl Sys for Flip<'_> {
        fn run(&self, program: &'static str, args: &[&str]) -> Result<crate::linux::cmd::Output> {
            if program == "/usr/bin/dpkg-query" {
                let n = self.1.get();
                self.1.set(n + 1);
                return Ok(crate::linux::cmd::Output {
                    status: if n == 0 { 0 } else { 1 },
                    stdout: if n == 0 { "ii ".into() } else { String::new() },
                    stderr: String::new(),
                });
            }
            self.0.run(program, args)
        }
        fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
            self.0.read(path)
        }
        fn write_atomic(&self, p: &Path, b: &[u8], m: u32) -> Result<()> {
            self.0.write_atomic(p, b, m)
        }
        fn remove(&self, p: &Path) -> Result<()> {
            self.0.remove(p)
        }
    }
    let flip = Flip(&after, std::cell::Cell::new(0));
    assert_eq!(remove_package(&flip, "anydesk"), PackageOutcome::Removed);
    assert!(called(&after, "/usr/bin/apt-get remove -y anydesk"));
}

#[test]
fn a_plan_that_takes_other_programs_runs_nothing() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "teamviewer"],
        0,
        "Remv teamviewer [15]\nRemv ubuntu-desktop [1]\n",
    );
    assert_eq!(
        remove_package(&sys, "teamviewer"),
        PackageOutcome::Failed(REFUSED.into())
    );
    assert!(!called(&sys, "/usr/bin/apt-get remove -y teamviewer"));
}

#[test]
fn a_package_that_is_already_gone_is_not_removed_again() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "rustdesk"],
        0,
        "Package 'rustdesk' is not installed, so not removed\n",
    );
    sys.reply(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${db:Status-Abbrev}", "rustdesk"],
        1,
        "",
    );
    assert_eq!(remove_package(&sys, "rustdesk"), PackageOutcome::Removed);
    assert!(!called(&sys, "/usr/bin/apt-get remove -y rustdesk"));
}

#[test]
fn a_removal_that_fails_or_leaves_the_app_behind_is_a_plain_failure() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "rustdesk"],
        0,
        "Remv rustdesk [1]\n",
    );
    sys.reply(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${db:Status-Abbrev}", "rustdesk"],
        0,
        "ii ",
    );
    sys.reply("/usr/bin/apt-get", &["remove", "-y", "rustdesk"], 100, "");
    assert_eq!(
        remove_package(&sys, "rustdesk"),
        PackageOutcome::Failed(FAILED.into())
    );
    sys.reply("/usr/bin/apt-get", &["remove", "-y", "rustdesk"], 0, "");
    assert_eq!(
        remove_package(&sys, "rustdesk"),
        PackageOutcome::Failed(FAILED.into())
    );
}

#[test]
fn fedora_removal_never_pulls_in_dependencies_the_person_did_not_choose() {
    let sys = fedora();
    sys.reply(
        "/usr/bin/dnf",
        &["remove", "--assumeno", "--no-autoremove", "anydesk"],
        1,
        "Removing:\n anydesk x86_64 0:7-1 @System 1 MiB\n\nTransaction Summary:\n",
    );
    sys.reply("/usr/bin/rpm", &["-q", "anydesk"], 0, "anydesk-7-1\n");
    sys.reply(
        "/usr/bin/dnf",
        &["remove", "-y", "--no-autoremove", "anydesk"],
        0,
        "",
    );
    // The package manager still lists it: the removal is not believed.
    assert_eq!(
        remove_package(&sys, "anydesk"),
        PackageOutcome::Failed(FAILED.into())
    );
    assert!(called(
        &sys,
        "/usr/bin/dnf remove -y --no-autoremove anydesk"
    ));
}

#[test]
fn every_removal_sentence_is_plain() {
    for sentence in SENTENCES {
        assert!(sentence.ends_with('.'));
        assert!(!sentence.contains('\u{2014}'));
        assert_eq!(plain(sentence), Some(sentence));
    }
    assert_eq!(plain("anything else"), None);
}
