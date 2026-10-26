use super::*;
use crate::linux::cmd::fake::FakeSys;
use crate::linux::cmd::Output;
use crate::space::Entry;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

const SNAP_LIST: &str =
    include_str!("../../../../tests/fixtures/linux/ubuntu-26.04/space/snap-list-all.txt");
const DPKG: &str =
    include_str!("../../../../tests/fixtures/linux/ubuntu-26.04/space/dpkg-linux.txt");
const NOTHING_UNNEEDED: &str =
    include_str!("../../../../tests/fixtures/linux/ubuntu-26.04/space/apt-autoremove.txt");
const OLD_KERNELS_UNNEEDED: &str = include_str!(
    "../../../../tests/fixtures/linux/ubuntu-26.04/space/apt-autoremove-old-kernels.txt"
);
const REMOVE_34: &str =
    include_str!("../../../../tests/fixtures/linux/ubuntu-26.04/space/apt-remove-34.txt");

const UBUNTU: &[u8] = b"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n";
const DPKG_FORMAT: &str = "-f=${Package}\t${Installed-Size}\t${db:Status-Abbrev}\n";

const KIB_34: u64 = 92_489 + 31_712 + 16_920 + 2_390 + 163_400 + 25_266 + 4_447 + 237;

/// The version 34 packages in the order the listing prints them, which is the order they are checked and removed in.
fn packages_34() -> Vec<&'static str> {
    DPKG.lines()
        .filter_map(|line| line.split('\t').next())
        .filter(|name| name.contains("7.0.0-34"))
        .collect()
}

/// Programs answer from a queue per command line; the last answer repeats. Every call is recorded.
struct Script {
    base: FakeSys,
    queued: RefCell<HashMap<String, VecDeque<Output>>>,
    calls: RefCell<Vec<String>>,
}

fn key(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

impl Script {
    fn ubuntu() -> Self {
        let base = FakeSys::default();
        base.file("/usr/lib/os-release", UBUNTU);
        Self {
            base,
            queued: RefCell::default(),
            calls: RefCell::default(),
        }
    }

    fn say(&self, program: &str, args: &[&str], status: i32, stdout: &str) {
        self.queued
            .borrow_mut()
            .entry(key(program, args))
            .or_default()
            .push_back(Output {
                status,
                stdout: stdout.into(),
                stderr: String::new(),
            });
    }

    fn ran(&self, command: &str) -> bool {
        self.calls.borrow().iter().any(|c| c == command)
    }

    fn ran_anything_with(&self, text: &str) -> bool {
        self.calls.borrow().iter().any(|c| c.contains(text))
    }
}

impl Sys for Script {
    fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
        let key = key(program, args);
        self.calls.borrow_mut().push(key.clone());
        let mut queued = self.queued.borrow_mut();
        match queued.get_mut(&key) {
            Some(answers) if answers.len() > 1 => Ok(answers.pop_front().unwrap()),
            Some(answers) => Ok(answers[0].clone()),
            None => bail!("Unexpected program: {key}"),
        }
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        self.base.read(path)
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        self.base.write_atomic(path, bytes, mode)
    }

    fn remove(&self, path: &Path) -> Result<()> {
        self.base.remove(path)
    }
}

struct Folder(Vec<Entry>);

impl Fs for Folder {
    fn list(&self, dir: &Path, _max: usize) -> std::io::Result<Vec<Entry>> {
        if dir == Path::new(SNAP_FILES) {
            Ok(self.0.clone())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    fn delete_checked(
        &self,
        _path: &Path,
        _shared: bool,
        _check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        panic!("snaps are removed by snap, never by deleting files");
    }

    fn remove_empty_dir(
        &self,
        _path: &Path,
        _shared: bool,
        _check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        panic!("no folder is removed");
    }
}

fn snap_file(name: &str, size: u64) -> Entry {
    Entry {
        path: PathBuf::from(SNAP_FILES).join(name),
        is_dir: false,
        reparse: false,
        size,
        created: 0,
        written: 0,
    }
}

fn snap_folder() -> Folder {
    Folder(vec![
        snap_file("gnome-46-2404_168.snap", 645_148_672),
        snap_file("gnome-46-2404_177.snap", 645_951_488),
        snap_file("core24_2124.snap", 70_033_408),
    ])
}

fn list_without_old_copy() -> String {
    SNAP_LIST
        .lines()
        .filter(|l| !l.contains("disabled"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn only_disabled_copies_of_an_app_that_has_a_current_copy_are_old() {
    assert_eq!(
        parse_disabled(SNAP_LIST),
        [("gnome-46-2404".to_owned(), "168".to_owned())]
    );
    let text = "\
Name   Version  Rev  Tracking       Publisher  Notes
alone  1        4    latest/stable  me         disabled
both   1        5    latest/stable  me         base,disabled
both   2        6    latest/stable  me         base
odd    1        x7   latest/stable  me         disabled
odd    2        8    latest/stable  me         -
Bad_Name 1      9    latest/stable  me         disabled
Bad_Name 2      10   latest/stable  me         -
short  1        3
";
    assert_eq!(parse_disabled(text), [("both".to_owned(), "5".to_owned())]);
    assert!(parse_disabled("").is_empty());
}

#[test]
fn old_app_copies_are_measured_from_their_files_without_removing_anything() {
    let sys = Script::ubuntu();
    sys.say(SNAP, &["list", "--all"], 0, SNAP_LIST);
    let found = snaps(&sys, &snap_folder()).unwrap();
    assert_eq!(
        found,
        [OldSnap {
            name: "gnome-46-2404".into(),
            revision: "168".into(),
            bytes: 645_148_672
        }]
    );
    let t = tally(&found);
    assert_eq!((t.bytes, t.files, t.left_alone), (645_148_672, 1, 0));
    assert_eq!(sys.calls.borrow().as_slice(), ["/usr/bin/snap list --all"]);
}

#[test]
fn a_missing_file_still_counts_the_copy_with_no_size() {
    let sys = Script::ubuntu();
    sys.say(SNAP, &["list", "--all"], 0, SNAP_LIST);
    let t = tally(&snaps(&sys, &Folder(vec![])).unwrap());
    assert_eq!((t.bytes, t.files), (0, 1));
}

#[test]
fn nothing_old_means_nothing_is_removed() {
    let sys = Script::ubuntu();
    sys.say(SNAP, &["list", "--all"], 0, &list_without_old_copy());
    let t = tally(&snaps(&sys, &Folder(vec![])).unwrap());
    assert_eq!((t.bytes, t.files), (0, 0));
    assert_eq!(
        clean_snaps(&sys, &Folder(vec![])).unwrap(),
        Tally::default()
    );
    assert!(!sys.ran_anything_with("remove"));
}

#[test]
fn removing_old_app_copies_removes_exactly_those_revisions_and_reports_what_went() {
    let sys = Script::ubuntu();
    sys.say(SNAP, &["list", "--all"], 0, SNAP_LIST);
    sys.say(SNAP, &["list", "--all"], 0, &list_without_old_copy());
    sys.say(SNAP, &["remove", "gnome-46-2404", "--revision=168"], 0, "");
    let t = clean_snaps(&sys, &snap_folder()).unwrap();
    assert_eq!((t.bytes, t.files, t.left_alone), (645_148_672, 1, 0));
    assert!(sys.ran("/usr/bin/snap remove gnome-46-2404 --revision=168"));
    let removals = sys
        .calls
        .borrow()
        .iter()
        .filter(|c| c.contains(" remove "))
        .count();
    assert_eq!(removals, 1);
}

#[test]
fn a_removal_that_changes_nothing_is_a_plain_failure() {
    let sys = Script::ubuntu();
    sys.say(SNAP, &["list", "--all"], 0, SNAP_LIST);
    sys.say(SNAP, &["remove", "gnome-46-2404", "--revision=168"], 1, "");
    let e = clean_snaps(&sys, &snap_folder()).unwrap_err();
    assert_eq!(e.to_string(), CANNOT_CLEAN);
}

#[test]
fn a_list_that_cannot_be_read_is_a_plain_failure() {
    let sys = Script::ubuntu();
    sys.say(SNAP, &["list", "--all"], 1, "");
    assert_eq!(
        snaps(&sys, &snap_folder()).unwrap_err().to_string(),
        CANNOT_CLEAN
    );
}

struct NoSnap;

impl Sys for NoSnap {
    fn run(&self, program: &'static str, _args: &[&str]) -> Result<Output> {
        bail!("Could not start {program}")
    }
    fn read(&self, _path: &Path) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn write_atomic(&self, _path: &Path, _bytes: &[u8], _mode: u32) -> Result<()> {
        Ok(())
    }
    fn remove(&self, _path: &Path) -> Result<()> {
        Ok(())
    }
}

#[test]
fn a_computer_without_snap_has_no_old_app_copies() {
    assert!(snaps(&NoSnap, &Folder(vec![])).unwrap().is_empty());
    assert_eq!(
        clean_snaps(&NoSnap, &Folder(vec![])).unwrap(),
        Tally::default()
    );
}

#[test]
fn kernel_versions_are_read_from_package_and_release_names() {
    assert_eq!(version_of("7.0.0-38-generic"), Some((7, 0, 0, 38)));
    assert_eq!(
        version_of("linux-image-7.0.0-34-generic"),
        Some((7, 0, 0, 34))
    );
    assert_eq!(version_of("linux-headers-7.0.0-34"), Some((7, 0, 0, 34)));
    assert_eq!(
        version_of("linux-modules-nvidia-595-open-7.0.0-34-generic"),
        Some((7, 0, 0, 34))
    );
    assert_eq!(
        version_of("linux-image-unsigned-6.8.0-1015-aws"),
        Some((6, 8, 0, 1015))
    );
    assert!(version_of("7.0.0-38-generic") > version_of("7.0.0-9-generic"));
    for meta in [
        "linux-image-generic-hwe-26.04",
        "linux-headers-generic-hwe-26.04",
        "linux-modules-nvidia-595-open-generic-hwe-26.04",
        "linux-tools-common",
        "linux-image-generic",
        "",
    ] {
        assert_eq!(version_of(meta), None, "{meta}");
    }
}

#[test]
fn simulated_removals_are_read_without_architecture_suffixes() {
    assert_eq!(
        planned_removals("Remv a:amd64 [1]\nRemv b [2] [c:amd64 ]\nInst d [3]\nnot Remv e\n"),
        ["a", "b"]
    );
    let names = planned_removals(OLD_KERNELS_UNNEEDED);
    assert_eq!(names.len(), 7);
    assert!(names.contains(&"linux-image-unsigned-7.0.0-30-generic".to_owned()));
    assert!(names.contains(&"linux-main-modules-zfs-7.0.0-30-generic".to_owned()));
}

fn kernel_machine(running: &str, unneeded: &str) -> Script {
    let sys = Script::ubuntu();
    sys.say(UNAME, &["-r"], 0, running);
    sys.say(DPKG_QUERY, &["-W", DPKG_FORMAT], 0, DPKG);
    sys.say(APT_GET, &["-s", "autoremove"], 0, unneeded);
    sys
}

fn simulate_34(sys: &Script, output: &str) {
    let packages = packages_34();
    let mut args = vec!["-s", "remove"];
    args.extend(&packages);
    sys.say(APT_GET, &args, 0, output);
}

fn remove_34() -> Vec<&'static str> {
    let mut args = vec!["remove", "-y"];
    args.extend(packages_34());
    args
}

#[test]
fn the_recorded_listing_has_eight_version_34_packages() {
    assert_eq!(packages_34().len(), 8);
    assert_eq!(planned_removals(REMOVE_34).len(), 8);
}

#[test]
fn nothing_is_offered_while_the_system_does_not_call_older_versions_unneeded() {
    let sys = kernel_machine("7.0.0-38-generic\n", NOTHING_UNNEEDED);
    assert!(kernels(&sys).unwrap().is_empty());
    assert!(!sys.ran_anything_with("-s remove"));
    assert_eq!(clean_kernels(&sys).unwrap(), Tally::default());
    assert!(!sys.ran_anything_with(" remove -y"));
}

#[test]
fn older_versions_the_system_no_longer_needs_are_measured_from_their_installed_size() {
    let sys = kernel_machine("7.0.0-38-generic\n", REMOVE_34);
    simulate_34(&sys, REMOVE_34);
    let found = kernels(&sys).unwrap();
    let names: Vec<&str> = found.iter().map(|k| k.package.as_str()).collect();
    assert_eq!(names, packages_34());
    let t = kernel_tally(&found);
    assert_eq!((t.bytes, t.files), (KIB_34 * 1024, 8));
    assert!(!sys.ran_anything_with(" remove -y"));
}

#[test]
fn the_running_and_newest_versions_leftover_settings_and_meta_packages_are_never_candidates() {
    let everything = format!("{REMOVE_34}{OLD_KERNELS_UNNEEDED}Remv linux-image-7.0.0-38-generic [1]\nRemv linux-image-7.0.0-31-generic [1]\nRemv linux-image-generic-hwe-26.04 [1]\n");
    let sys = kernel_machine("7.0.0-38-generic\n", &everything);
    simulate_34(&sys, REMOVE_34);
    let found = kernels(&sys).unwrap();
    assert_eq!(found.len(), 8);
    for package in found {
        assert!(package.package.contains("7.0.0-34"), "{}", package.package);
    }
}

#[test]
fn a_computer_started_on_an_older_version_keeps_that_one_and_the_newest() {
    let sys = kernel_machine("7.0.0-34-generic\n", REMOVE_34);
    assert!(kernels(&sys).unwrap().is_empty());
    assert!(!sys.ran_anything_with("-s remove"));
}

#[test]
fn only_old_versions_that_the_system_lists_as_unneeded_are_candidates() {
    let sys = kernel_machine(
        "7.0.0-38-generic\n",
        "Remv linux-image-7.0.0-34-generic [7.0.0-34.34]\nRemv libfoo [1]\n",
    );
    sys.say(
        APT_GET,
        &["-s", "remove", "linux-image-7.0.0-34-generic"],
        0,
        "Remv linux-image-7.0.0-34-generic [7.0.0-34.34]\n",
    );
    let found = kernels(&sys).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].package, "linux-image-7.0.0-34-generic");
}

#[test]
fn a_simulation_that_takes_anything_else_refuses_and_removes_nothing() {
    let sys = kernel_machine("7.0.0-38-generic\n", REMOVE_34);
    let extra = format!("{REMOVE_34}Remv linux-generic-hwe-26.04 [7.0.0-38.38]\n");
    simulate_34(&sys, &extra);
    assert_eq!(kernels(&sys).unwrap_err().to_string(), KERNELS_KEPT);
    assert_eq!(clean_kernels(&sys).unwrap_err().to_string(), KERNELS_KEPT);
    assert!(!sys.ran_anything_with(" remove -y"));
}

#[test]
fn removing_old_versions_removes_exactly_the_checked_list_and_checks_again() {
    let sys = kernel_machine("7.0.0-38-generic\n", REMOVE_34);
    sys.say(APT_GET, &["-s", "autoremove"], 0, NOTHING_UNNEEDED);
    simulate_34(&sys, REMOVE_34);
    sys.say(APT_GET, &remove_34(), 0, "");
    let t = clean_kernels(&sys).unwrap();
    assert_eq!((t.bytes, t.files, t.left_alone), (KIB_34 * 1024, 8, 0));
    let removal = format!("/usr/bin/apt-get {}", remove_34().join(" "));
    assert!(sys.ran(&removal), "{:?}", sys.calls.borrow());
    assert!(!removal.contains("7.0.0-38"));
    let autoremoves = sys
        .calls
        .borrow()
        .iter()
        .filter(|c| c.ends_with("-s autoremove"))
        .count();
    assert_eq!(autoremoves, 2);
}

#[test]
fn a_failed_removal_is_a_plain_failure() {
    let sys = kernel_machine("7.0.0-38-generic\n", REMOVE_34);
    simulate_34(&sys, REMOVE_34);
    sys.say(APT_GET, &remove_34(), 100, "");
    assert_eq!(clean_kernels(&sys).unwrap_err().to_string(), CANNOT_CLEAN);
}

#[test]
fn the_recorded_seven_unneeded_packages_of_a_fresh_install_are_all_offered() {
    let sys = Script::ubuntu();
    sys.say(UNAME, &["-r"], 0, "7.0.0-38-generic\n");
    let names = planned_removals(OLD_KERNELS_UNNEEDED);
    let mut rows = String::new();
    for name in &names {
        rows.push_str(&format!("{name}\t1000\tii \n"));
    }
    for name in [
        "linux-image-7.0.0-38-generic",
        "linux-image-generic-hwe-26.04",
        "linux-modules-7.0.0-38-generic",
        "linux-headers-7.0.0-38",
        "linux-tools-common",
    ] {
        rows.push_str(&format!("{name}\t2000\tii \n"));
    }
    rows.push_str("linux-image-unsigned-7.0.0-38-generic\t0\tun \n");
    sys.say(DPKG_QUERY, &["-W", DPKG_FORMAT], 0, &rows);
    sys.say(APT_GET, &["-s", "autoremove"], 0, OLD_KERNELS_UNNEEDED);
    let mut args = vec!["-s", "remove"];
    args.extend(names.iter().map(String::as_str));
    sys.say(APT_GET, &args, 0, OLD_KERNELS_UNNEEDED);
    let found = kernels(&sys).unwrap();
    assert_eq!(found.len(), 7);
    assert_eq!(kernel_tally(&found).bytes, 7 * 1000 * 1024);
}

#[test]
fn kernels_are_left_alone_on_systems_that_are_not_debian_based() {
    let fedora = Script::ubuntu();
    fedora
        .base
        .file("/usr/lib/os-release", b"ID=fedora\nVERSION_ID=44\n");
    assert!(kernels(&fedora).unwrap().is_empty());
    assert!(fedora.calls.borrow().is_empty());
    assert_eq!(clean_kernels(&fedora).unwrap(), Tally::default());
}

#[test]
fn an_unreadable_running_version_or_listing_stops_before_anything_is_chosen() {
    let sys = kernel_machine("custom\n", REMOVE_34);
    assert_eq!(kernels(&sys).unwrap_err().to_string(), CANNOT_CLEAN);
    let sys = Script::ubuntu();
    sys.say(UNAME, &["-r"], 0, "7.0.0-38-generic\n");
    sys.say(DPKG_QUERY, &["-W", DPKG_FORMAT], 1, "");
    assert_eq!(kernels(&sys).unwrap_err().to_string(), CANNOT_CLEAN);
    assert!(!sys.ran_anything_with("apt-get"));
}
