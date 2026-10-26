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
    assert_eq!(owner("xrdp"), Some(windows as u16 + 3));
    assert_eq!(owner("x11vnc"), Some(windows as u16 + 4));
    assert_eq!(owner("vino"), Some(windows as u16 + 5));
    assert_eq!(owner("transmission-gtk"), Some(windows as u16 + 6));
    assert_eq!(owner("transmission-common"), Some(windows as u16 + 6));
    assert_eq!(owner("warpinator"), Some(windows as u16 + 7));
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
    assert!(CATALOG
        .iter()
        .all(|a| matches!(a.group, Group::RemoteAccess | Group::Sharing)));
}

#[test]
fn remote_control_servers_and_sharing_apps_have_their_own_groups() {
    let group = |name: &str| CATALOG.iter().find(|a| a.name == name).unwrap().group;
    for name in [
        "TeamViewer",
        "AnyDesk",
        "RustDesk",
        "xrdp",
        "x11vnc",
        "Vino",
    ] {
        assert_eq!(group(name), Group::RemoteAccess, "{name}");
    }
    for name in ["Transmission", "Warpinator"] {
        assert_eq!(group(name), Group::Sharing, "{name}");
    }
    for name in [
        "xrdp-sesman",
        "vino-extras",
        "x11vnc-data",
        "warpinator-nemo",
        "transmissionbt",
    ] {
        assert_eq!(
            owner(name).is_some(),
            name.starts_with("transmission-"),
            "{name}"
        );
    }
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

const MINT_DPKG: &str = "bash\t5.3-2\tii \ntransmission-common\t4.0.5-1build5mint2+mint22\tii \ntransmission-gtk\t4.0.5-1build5mint2+mint22\tii \nwarpinator\t1.8.9\tii \nvino\t3.22.0-8\trc \n";

#[test]
fn transmission_is_listed_when_its_removal_takes_only_transmission_packages() {
    let sys = ubuntu();
    sys.reply("/usr/bin/dpkg-query", &DPKG, 0, MINT_DPKG);
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "transmission-gtk"],
        0,
        "Reading package lists...\nThe following packages will be REMOVED:\n  transmission-common transmission-gtk\nRemv transmission-gtk [4.0.5-1build5mint2+mint22]\nRemv transmission-common [4.0.5-1build5mint2+mint22]\n",
    );
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "transmission-common"],
        0,
        "Remv transmission-gtk [4.0.5-1build5mint2+mint22]\nRemv transmission-common [4.0.5-1build5mint2+mint22]\n",
    );
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "warpinator"],
        0,
        "Remv mint-meta-cinnamon [1.0]\nRemv warpinator [1.8.9]\n",
    );
    let names: Vec<_> = listable(&sys)
        .unwrap()
        .into_iter()
        .map(|i| i.package)
        .collect();
    assert_eq!(names, ["transmission-common", "transmission-gtk"]);
    assert_eq!(
        gate(
            "warpinator",
            &["mint-meta-cinnamon".to_owned(), "warpinator".to_owned()]
        )
        .unwrap_err()
        .to_string(),
        REFUSED
    );
}

#[test]
fn removing_transmission_takes_its_shared_files_and_nothing_else() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "transmission-gtk"],
        0,
        "Remv transmission-gtk [4.0.5-1build5mint2+mint22]\nRemv transmission-common [4.0.5-1build5mint2+mint22]\n",
    );
    sys.reply(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${db:Status-Abbrev}", "transmission-gtk"],
        1,
        "",
    );
    assert_eq!(
        remove_package(&sys, "transmission-gtk"),
        PackageOutcome::Removed
    );
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "transmission-gtk"],
        0,
        "Remv transmission-gtk [4]\nRemv mint-meta-cinnamon [1]\n",
    );
    sys.reply(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${db:Status-Abbrev}", "transmission-gtk"],
        0,
        "ii ",
    );
    assert_eq!(
        remove_package(&sys, "transmission-gtk"),
        PackageOutcome::Failed(REFUSED.into())
    );
    assert!(!called(&sys, "/usr/bin/apt-get remove -y transmission-gtk"));
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
    sys.reply(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${db:Status-Abbrev}", "teamviewer"],
        0,
        "ii ",
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

const RECORD_PATH: &str = "/var/lib/secblitz/Linux/removed-apps.txt";

fn record_of(sys: &FakeSys) -> String {
    sys.files
        .borrow()
        .get(Path::new(RECORD_PATH))
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

fn status(sys: &FakeSys, package: &str, installed: bool) {
    sys.reply(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${db:Status-Abbrev}", package],
        i32::from(!installed),
        if installed { "ii " } else { "" },
    );
}

/// Answers each look at the package database from a fixed list of "installed" answers, then repeats the last.
struct Seen<'a>(&'a FakeSys, std::cell::Cell<usize>, &'static [bool]);

impl Sys for Seen<'_> {
    fn run(&self, program: &'static str, args: &[&str]) -> Result<crate::linux::cmd::Output> {
        if program == "/usr/bin/dpkg-query" {
            let n = self.1.get();
            self.1.set(n + 1);
            let installed = self.2[n.min(self.2.len() - 1)];
            return Ok(crate::linux::cmd::Output {
                status: i32::from(!installed),
                stdout: if installed {
                    "ii ".into()
                } else {
                    String::new()
                },
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

#[test]
fn a_removal_is_written_down_once_per_app() {
    let sys = ubuntu();
    record_removal(&sys, "anydesk", &[], 100).unwrap();
    record_removal(&sys, "xrdp", &[], 200).unwrap();
    record_removal(&sys, "anydesk", &[], 300).unwrap();
    assert_eq!(record_of(&sys), "xrdp\t200\nanydesk\t300\n");
    assert!(record_removal(&sys, "bash", &[], 1).is_err());
}

#[test]
fn the_record_keeps_only_the_newest_lines_and_skips_bad_ones() {
    let sys = ubuntu();
    let mut text = String::from("../evil\t5\nbash\t5\nanydesk\tsoon\nanydesk\n");
    for n in 0..70 {
        text.push_str(&format!("transmission-{n}\t{n}\n"));
    }
    sys.file(RECORD_PATH, text.as_bytes());
    record_removal(&sys, "xrdp", &[], 999).unwrap();
    let written = record_of(&sys);
    assert_eq!(written.lines().count(), 64);
    assert!(written.ends_with("xrdp\t999\n"));
    assert!(!written.contains("evil") && !written.contains("bash"));
    assert!(!written.contains("transmission-0\t"));
}

#[test]
fn a_successful_removal_is_recorded() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "xrdp"],
        0,
        "Remv xrdp [1]\n",
    );
    sys.reply("/usr/bin/apt-get", &["remove", "-y", "xrdp"], 0, "");
    let seen = Seen(&sys, std::cell::Cell::new(0), &[true, true, false]);
    assert_eq!(remove_recorded(&seen, "xrdp", 50), PackageOutcome::Removed);
    assert_eq!(record_of(&sys), "xrdp\t50\n");
}

#[test]
fn a_refused_removal_is_not_recorded() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "xrdp"],
        0,
        "Remv xrdp [1]\nRemv ubuntu-desktop [1]\n",
    );
    status(&sys, "xrdp", true);
    assert_eq!(
        remove_recorded(&sys, "xrdp", 50),
        PackageOutcome::Failed(REFUSED.into())
    );
    assert_eq!(record_of(&sys), "");
}

#[test]
fn an_app_that_was_never_installed_is_not_recorded() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "rustdesk"],
        0,
        "Package 'rustdesk' is not installed, so not removed\n",
    );
    status(&sys, "rustdesk", false);
    assert_eq!(
        remove_recorded(&sys, "rustdesk", 50),
        PackageOutcome::Removed
    );
    assert_eq!(record_of(&sys), "");
}

#[test]
fn the_removed_list_holds_only_apps_that_are_gone_now() {
    let sys = ubuntu();
    sys.file(RECORD_PATH, b"anydesk\t10\nxrdp\t20\n");
    status(&sys, "anydesk", true);
    status(&sys, "xrdp", false);
    let gone = removed(&sys).unwrap();
    assert_eq!(gone.len(), 1);
    assert_eq!(gone[0].package, "xrdp");
    assert_eq!(gone[0].t, 20);
}

#[test]
fn reinstalling_installs_the_app_and_clears_its_line() {
    let sys = ubuntu();
    sys.file(RECORD_PATH, b"xrdp\t20\nanydesk\t10\n");
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "install", "xrdp"],
        0,
        "Inst xrdp (1 Ubuntu)\n",
    );
    sys.reply("/usr/bin/apt-get", &["install", "-y", "xrdp"], 0, "");
    let seen = Seen(&sys, std::cell::Cell::new(0), &[false, true]);
    reinstall_package(&seen, "xrdp").unwrap();
    assert!(called(&sys, "/usr/bin/apt-get install -y xrdp"));
    assert_eq!(record_of(&sys), "anydesk\t10\n");
}

#[test]
fn a_package_that_went_with_an_earlier_one_counts_as_removed_on_fedora() {
    let sys = fedora();
    sys.reply("/usr/bin/rpm", &["-q", "transmission-gtk"], 1, "");
    // dnf says "No packages to remove" on its error output and fails, which must not read as a failed removal.
    sys.reply(
        "/usr/bin/dnf",
        &[
            "remove",
            "--assumeno",
            "--no-autoremove",
            "transmission-gtk",
        ],
        1,
        "",
    );
    assert_eq!(
        remove_package(&sys, "transmission-gtk"),
        PackageOutcome::Removed
    );
    assert!(!called(
        &sys,
        "/usr/bin/dnf remove -y --no-autoremove transmission-gtk"
    ));
}

#[test]
fn fedora_reinstalls_with_dnf_and_reads_it_back() {
    let sys = fedora();
    sys.file(RECORD_PATH, b"xrdp\t20\n");
    sys.reply("/usr/bin/rpm", &["-q", "xrdp"], 1, "");
    sys.reply(
        "/usr/bin/dnf",
        &["install", "--assumeno", "xrdp"],
        1,
        "Installing:\n xrdp x86_64 1-1 fedora 1 MiB\n\nTransaction Summary:\n",
    );
    sys.reply("/usr/bin/dnf", &["install", "-y", "xrdp"], 0, "");
    // The package manager still does not list it afterwards: the install is not believed.
    let error = reinstall_package(&sys, "xrdp").unwrap_err();
    assert_eq!(error.to_string(), INSTALL_FAILED);
    assert!(called(&sys, "/usr/bin/dnf install -y xrdp"));
    assert_eq!(record_of(&sys), "xrdp\t20\n");
}

#[test]
fn an_app_that_was_not_recorded_is_left_alone() {
    let sys = ubuntu();
    sys.file(RECORD_PATH, b"xrdp\t20\n");
    for package in ["anydesk", "bash", "../xrdp"] {
        let error = reinstall_package(&sys, package).unwrap_err();
        assert_eq!(error.to_string(), NOT_RECORDED, "{package}");
    }
    assert!(!called(&sys, "/usr/bin/apt-get install -y anydesk"));
}

#[test]
fn a_plan_that_would_remove_something_is_refused() {
    let sys = ubuntu();
    sys.file(RECORD_PATH, b"xrdp\t20\n");
    status(&sys, "xrdp", false);
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "install", "xrdp"],
        0,
        "Inst xrdp (1)\nRemv vino [3]\n",
    );
    let error = reinstall_package(&sys, "xrdp").unwrap_err();
    assert_eq!(error.to_string(), INSTALL_REFUSED);
    assert!(!called(&sys, "/usr/bin/apt-get install -y xrdp"));
    assert_eq!(record_of(&sys), "xrdp\t20\n");

    let sys = fedora();
    sys.file(RECORD_PATH, b"xrdp\t20\n");
    sys.reply("/usr/bin/rpm", &["-q", "xrdp"], 1, "");
    sys.reply(
        "/usr/bin/dnf",
        &["install", "--assumeno", "xrdp"],
        1,
        "Installing:\n xrdp x86_64 1-1 f 1 MiB\nRemoving:\n vino x86_64 3-1 @System 1 MiB\n\nTransaction Summary:\n",
    );
    let error = reinstall_package(&sys, "xrdp").unwrap_err();
    assert_eq!(error.to_string(), INSTALL_REFUSED);
    assert!(!called(&sys, "/usr/bin/dnf install -y xrdp"));
}

#[test]
fn an_app_that_is_already_back_only_clears_its_line() {
    let sys = ubuntu();
    sys.file(RECORD_PATH, b"xrdp\t20\n");
    status(&sys, "xrdp", true);
    reinstall_package(&sys, "xrdp").unwrap();
    assert_eq!(record_of(&sys), "");
    assert!(!called(&sys, "/usr/bin/apt-get install -y xrdp"));
}

#[test]
fn a_failed_install_keeps_the_line_and_says_so_plainly() {
    let sys = ubuntu();
    sys.file(RECORD_PATH, b"xrdp\t20\n");
    status(&sys, "xrdp", false);
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "install", "xrdp"],
        0,
        "Inst xrdp (1)\n",
    );
    sys.reply("/usr/bin/apt-get", &["install", "-y", "xrdp"], 100, "");
    let error = reinstall_package(&sys, "xrdp").unwrap_err();
    assert_eq!(plain(&error.to_string()), Some(INSTALL_FAILED));
    assert!(INSTALL_FAILED.contains("online"));
    assert_eq!(record_of(&sys), "xrdp\t20\n");
}

#[test]
fn an_app_removed_with_its_other_packages_comes_back_whole() {
    let sys = ubuntu();
    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "remove", "transmission-common"],
        0,
        "Remv transmission-gtk [4]\nRemv transmission-common [4]\n",
    );
    sys.reply(
        "/usr/bin/apt-get",
        &["remove", "-y", "transmission-common"],
        0,
        "",
    );
    let seen = Seen(&sys, std::cell::Cell::new(0), &[true, true, false]);
    assert_eq!(
        remove_recorded(&seen, "transmission-common", 70),
        PackageOutcome::Removed
    );
    assert_eq!(
        record_of(&sys),
        "transmission-common\t70\ttransmission-gtk\n"
    );

    sys.reply(
        "/usr/bin/apt-get",
        &["-s", "install", "transmission-common", "transmission-gtk"],
        0,
        "Inst transmission-common (4)\nInst transmission-gtk (4)\n",
    );
    sys.reply(
        "/usr/bin/apt-get",
        &["install", "-y", "transmission-common", "transmission-gtk"],
        0,
        "",
    );
    let seen = Seen(&sys, std::cell::Cell::new(0), &[false, false, true]);
    reinstall_package(&seen, "transmission-common").unwrap();
    assert!(called(
        &sys,
        "/usr/bin/apt-get install -y transmission-common transmission-gtk"
    ));
    assert_eq!(record_of(&sys), "");
}

#[test]
fn a_recorded_package_of_another_app_is_never_installed_with_it() {
    let sys = ubuntu();
    sys.file(
        RECORD_PATH,
        b"transmission-common\t5\ttransmission-gtk xrdp bash ../x\n",
    );
    let found = read_record(&sys).unwrap();
    assert_eq!(found[0].also, vec!["transmission-gtk".to_owned()]);
}
