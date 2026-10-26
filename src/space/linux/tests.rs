use super::*;
use crate::linux::cmd::fake::FakeSys;
use crate::linux::cmd::Output;
use crate::space::Entry;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

const DAY: u64 = 86_400;
const NOW: u64 = 100 * DAY;

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn file(path: &str, size: u64, age_days: u64) -> Entry {
    Entry {
        path: PathBuf::from(path),
        is_dir: false,
        reparse: false,
        size,
        created: NOW - age_days * DAY,
        written: NOW - age_days * DAY,
    }
}

/// Each folder answers its listings in turn; the last one repeats. Deleting records the path and says yes.
#[derive(Default)]
struct Mem {
    listings: RefCell<HashMap<PathBuf, Vec<Vec<Entry>>>>,
    deleted: RefCell<Vec<PathBuf>>,
}

impl Mem {
    fn with(dir: &str, turns: Vec<Vec<Entry>>) -> Self {
        let mem = Mem::default();
        mem.listings.borrow_mut().insert(PathBuf::from(dir), turns);
        mem
    }
}

impl Fs for Mem {
    fn list(&self, dir: &Path, _max: usize) -> std::io::Result<Vec<Entry>> {
        let mut all = self.listings.borrow_mut();
        let Some(turns) = all.get_mut(dir) else {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        };
        Ok(if turns.len() > 1 {
            turns.remove(0)
        } else {
            turns[0].clone()
        })
    }

    fn delete_checked(
        &self,
        path: &Path,
        _shared: bool,
        check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        let fresh = self
            .listings
            .borrow()
            .values()
            .flatten()
            .flatten()
            .find(|e| e.path == path)
            .cloned();
        match fresh {
            Some(e) if check(&e) => {
                self.deleted.borrow_mut().push(path.to_path_buf());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn remove_empty_dir(
        &self,
        _path: &Path,
        _shared: bool,
        _check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        Ok(false)
    }
}

const UBUNTU: &str = "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n";
const FEDORA: &str = "ID=fedora\nVERSION_ID=44\n";

fn sys_with(os_release: &str) -> FakeSys {
    let sys = FakeSys::default();
    sys.file("/etc/os-release", os_release.as_bytes());
    sys
}

#[test]
fn crash_reports_older_than_a_week_are_measured_and_removed_but_nothing_else() {
    let dir = "/var/crash";
    let mem = Mem::with(
        dir,
        vec![vec![
            file("/var/crash/old.crash", 400, 9),
            file("/var/crash/new.crash", 100, 1),
            file("/var/crash/old.upload", 50, 30),
            Entry {
                reparse: true,
                ..file("/var/crash/link.crash", 5, 30)
            },
            Entry {
                is_dir: true,
                ..file("/var/crash/sub", 0, 30)
            },
            file("/var/crash/sub/inner.crash", 700, 30),
        ]],
    );
    let measured = flat(&mem, Path::new(dir), &CRASH_RULE, NOW, false);
    assert_eq!((measured.bytes, measured.files), (400, 1));
    assert!(mem.deleted.borrow().is_empty());
    let cleaned = flat(&mem, Path::new(dir), &CRASH_RULE, NOW, true);
    assert_eq!((cleaned.bytes, cleaned.files), (400, 1));
    assert_eq!(
        mem.deleted.borrow().as_slice(),
        [PathBuf::from("/var/crash/old.crash")]
    );
}

#[test]
fn a_missing_crash_folder_is_nothing_to_remove() {
    let mem = Mem::default();
    let t = flat(&mem, Path::new("/var/crash"), &CRASH_RULE, NOW, false);
    assert_eq!((t.bytes, t.files), (0, 0));
}

#[test]
fn debian_package_caches_count_only_the_downloaded_packages() {
    let mem = Mem::with(
        APT_ARCHIVES,
        vec![vec![
            file("/var/cache/apt/archives/a_1_amd64.deb", 1000, 0),
            file("/var/cache/apt/archives/b_2_amd64.deb", 2000, 0),
            file("/var/cache/apt/archives/lock", 0, 0),
        ]],
    );
    let t = measure_machine(&sys_with(UBUNTU), &mem, Item::PackageCaches, NOW, far()).unwrap();
    assert_eq!((t.bytes, t.files), (3000, 2));
}

#[test]
fn cleaning_the_debian_cache_runs_apt_get_clean_and_reports_what_went() {
    let dir = APT_ARCHIVES;
    let mem = Mem::with(
        dir,
        vec![
            vec![file("/var/cache/apt/archives/a_1_amd64.deb", 5000, 0)],
            vec![],
        ],
    );
    let sys = sys_with(UBUNTU);
    sys.reply("/usr/bin/apt-get", &["clean"], 0, "");
    let t = clean_machine(&sys, &mem, Item::PackageCaches, NOW, far()).unwrap();
    assert_eq!((t.bytes, t.files, t.left_alone), (5000, 1, 0));
    assert!(sys
        .calls
        .borrow()
        .contains(&"/usr/bin/apt-get clean".to_owned()));
}

#[test]
fn fedora_package_caches_are_the_downloaded_rpm_files_in_both_cache_folders() {
    let mem = Mem::with(
        "/var/cache/libdnf5",
        vec![vec![file("/var/cache/libdnf5/p/x.rpm", 700, 0)]],
    );
    mem.listings.borrow_mut().insert(
        PathBuf::from("/var/cache/dnf"),
        vec![vec![file("/var/cache/dnf/y.rpm", 300, 0)]],
    );
    let t = measure_machine(&sys_with(FEDORA), &mem, Item::PackageCaches, NOW, far()).unwrap();
    assert_eq!((t.bytes, t.files), (1000, 2));
    let sys = sys_with(FEDORA);
    sys.reply("/usr/bin/dnf", &["clean", "packages"], 0, "");
    let t = clean_machine(&sys, &mem, Item::PackageCaches, NOW, far()).unwrap();
    assert_eq!(t.left_alone, 2);
    assert!(sys
        .calls
        .borrow()
        .contains(&"/usr/bin/dnf clean packages".to_owned()));
}

#[test]
fn a_failed_cache_clean_is_a_plain_error_and_a_system_we_do_not_know_is_refused() {
    let mem = Mem::with(APT_ARCHIVES, vec![vec![]]);
    let sys = sys_with(UBUNTU);
    sys.reply("/usr/bin/apt-get", &["clean"], 100, "");
    let e = clean_machine(&sys, &mem, Item::PackageCaches, NOW, far()).unwrap_err();
    assert_eq!(e.to_string(), CANNOT_CLEAN);
    let other = sys_with("ID=arch\n");
    let e = measure_machine(&other, &mem, Item::PackageCaches, NOW, far()).unwrap_err();
    assert_eq!(e.to_string(), NOT_ON_THIS_SYSTEM);
}

#[test]
fn only_the_items_a_part_belongs_to_can_be_asked_for() {
    let mem = Mem::default();
    let sys = sys_with(UBUNTU);
    for item in [Item::Temp, Item::Trash, Item::ThumbnailCache] {
        assert!(measure_machine(&sys, &mem, item, NOW, far()).is_err());
        assert!(clean_machine(&sys, &mem, item, NOW, far()).is_err());
    }
}

const UNUSED_LIST: &str = "\
        ID                                    Branch   Op
 1.     org.freedesktop.Platform.GL.default   23.08    r
 2. [-] org.gnome.Platform.Locale             46       r

Proceed with these changes to the system installation? [Y/n]: n
";

const RUNTIMES: &str = "\
org.freedesktop.Platform\t25.08\t670.7 MB
org.freedesktop.Platform.GL.default\t23.08\t462.3 MB
org.gnome.Platform.Locale\t46\t163.8 kB
org.gnome.Platform\t46\t1.2 GB
";

fn flatpak_sys(scope: &str, unused: &str, status: i32) -> FakeSys {
    let sys = FakeSys::default();
    sys.reply(
        "/usr/bin/flatpak",
        &["uninstall", scope, "--unused"],
        status,
        unused,
    );
    sys.reply(
        "/usr/bin/flatpak",
        &[
            "list",
            scope,
            "--runtime",
            "--columns=application,branch,size",
        ],
        0,
        RUNTIMES,
    );
    sys
}

#[test]
fn flatpak_lists_are_read_and_sizes_use_decimal_units() {
    let rows = parse_unused(UNUSED_LIST).unwrap();
    assert_eq!(
        rows,
        [
            (
                "org.freedesktop.Platform.GL.default".to_owned(),
                "23.08".to_owned()
            ),
            ("org.gnome.Platform.Locale".to_owned(), "46".to_owned()),
        ]
    );
    assert_eq!(parse_unused("Nothing unused to uninstall\n"), Some(vec![]));
    assert_eq!(parse_unused("Something else entirely\n"), None);
    assert_eq!(parse_size("670.7 MB"), Some(670_700_000));
    assert_eq!(parse_size("163.8 kB"), Some(163_800));
    assert_eq!(parse_size("1.2 GB"), Some(1_200_000_000));
    assert_eq!(parse_size("512 bytes"), Some(512));
    assert_eq!(parse_size("many"), None);
}

#[test]
fn unused_runtimes_are_measured_without_removing_anything() {
    let sys = flatpak_sys("--system", UNUSED_LIST, 1);
    let t = measure_machine(&sys, &Mem::default(), Item::FlatpakRuntimes, NOW, far()).unwrap();
    assert_eq!((t.bytes, t.files), (462_300_000 + 163_800, 2));
    assert_eq!(sys.answers.borrow().as_slice(), ["n\n"]);
    assert!(sys.calls.borrow().iter().all(|c| !c.contains(" -y")));
}

#[test]
fn nothing_unused_means_nothing_to_remove_and_no_second_program_runs() {
    let sys = FakeSys::default();
    sys.reply(
        "/usr/bin/flatpak",
        &["uninstall", "--user", "--unused"],
        0,
        "Nothing unused to uninstall\n",
    );
    let dirs = PersonDirs::new(Path::new("/home/a"), None, None).unwrap();
    let t = measure_person(&sys, &Mem::default(), &dirs, UserArea::FlatpakUser, NOW).unwrap();
    assert_eq!((t.bytes, t.files), (0, 0));
    assert_eq!(sys.calls.borrow().len(), 1);
}

#[test]
fn an_answer_that_is_not_a_list_is_not_taken_for_nothing_to_remove() {
    let sys = flatpak_sys("--system", "error: something odd\n", 1);
    assert!(measure_machine(&sys, &Mem::default(), Item::FlatpakRuntimes, NOW, far()).is_err());
}

#[test]
fn removing_unused_runtimes_asks_for_exactly_those_and_says_what_it_freed() {
    let sys = flatpak_sys("--user", UNUSED_LIST, 1);
    sys.reply(
        "/usr/bin/flatpak",
        &["uninstall", "--user", "--unused", "-y", "--noninteractive"],
        0,
        "",
    );
    let dirs = PersonDirs::new(Path::new("/home/a"), None, None).unwrap();
    let t = clean_person(&sys, &Mem::default(), &dirs, UserArea::FlatpakUser, NOW).unwrap();
    assert_eq!(t.bytes, 462_300_000 + 163_800);
    let failing = flatpak_sys("--user", UNUSED_LIST, 1);
    failing.reply(
        "/usr/bin/flatpak",
        &["uninstall", "--user", "--unused", "-y", "--noninteractive"],
        1,
        "",
    );
    assert!(clean_person(&failing, &Mem::default(), &dirs, UserArea::FlatpakUser, NOW).is_err());
}

struct NoFlatpak;

impl Sys for NoFlatpak {
    fn run(&self, program: &'static str, _args: &[&str]) -> Result<Output> {
        bail!("Could not start {program}")
    }
    fn run_answering(&self, program: &'static str, _args: &[&str], _a: &str) -> Result<Output> {
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
fn a_computer_without_flatpak_has_nothing_to_remove() {
    let t = measure_machine(
        &NoFlatpak,
        &Mem::default(),
        Item::FlatpakRuntimes,
        NOW,
        far(),
    )
    .unwrap();
    assert_eq!((t.bytes, t.files), (0, 0));
    let t = clean_machine(
        &NoFlatpak,
        &Mem::default(),
        Item::FlatpakRuntimes,
        NOW,
        far(),
    )
    .unwrap();
    assert_eq!(t.bytes, 0);
}

#[test]
fn the_persons_folders_come_from_their_home_and_ignore_relative_settings() {
    let d = PersonDirs::new(Path::new("/home/a"), Some(Path::new("rel")), None).unwrap();
    assert_eq!(d.previews()[0], Path::new("/home/a/.cache/thumbnails"));
    assert_eq!(d.previews()[1], Path::new("/home/a/.thumbnails"));
    assert_eq!(d.trash()[0], Path::new("/home/a/.local/share/Trash/files"));
    assert_eq!(d.trash()[1], Path::new("/home/a/.local/share/Trash/info"));
    let d = PersonDirs::new(
        Path::new("/home/a"),
        Some(Path::new("/c")),
        Some(Path::new("/d")),
    )
    .unwrap();
    assert_eq!(d.previews()[0], Path::new("/c/thumbnails"));
    assert_eq!(d.trash()[0], Path::new("/d/Trash/files"));
    assert!(PersonDirs::new(Path::new("home"), None, None).is_none());
}

#[test]
fn emptying_the_trash_uses_the_desktops_tool_and_reports_the_difference() {
    let dirs = PersonDirs::new(Path::new("/home/a"), None, None).unwrap();
    let files = "/home/a/.local/share/Trash/files";
    let mem = Mem::with(
        files,
        vec![
            vec![file("/home/a/.local/share/Trash/files/x", 9000, 40)],
            vec![file("/home/a/.local/share/Trash/files/x", 9000, 40)],
            vec![],
        ],
    );
    mem.listings.borrow_mut().insert(
        PathBuf::from("/home/a/.local/share/Trash/info"),
        vec![
            vec![file("/home/a/.local/share/Trash/info/x.trashinfo", 100, 40)],
            vec![file("/home/a/.local/share/Trash/info/x.trashinfo", 100, 40)],
            vec![],
        ],
    );
    let sys = FakeSys::default();
    sys.reply("/usr/bin/gio", &["trash", "--empty"], 0, "");
    let before = measure_person(&sys, &mem, &dirs, UserArea::Trash, NOW).unwrap();
    assert_eq!(before.bytes, 9100);
    let t = clean_person(&sys, &mem, &dirs, UserArea::Trash, NOW).unwrap();
    assert_eq!(t.bytes, 9100);
    sys.reply("/usr/bin/gio", &["trash", "--empty"], 1, "");
    let e = clean_person(&sys, &mem, &dirs, UserArea::Trash, NOW).unwrap_err();
    assert_eq!(e.to_string(), TRASH_NOT_EMPTIED);
}

#[test]
fn only_the_preview_pictures_in_the_cache_are_removed() {
    let dirs = PersonDirs::new(Path::new("/home/a"), None, None).unwrap();
    let mem = Mem::with(
        "/home/a/.cache/thumbnails",
        vec![vec![
            file("/home/a/.cache/thumbnails/abc.png", 4000, 0),
            file("/home/a/.cache/thumbnails/notes.txt", 10, 0),
        ]],
    );
    mem.listings.borrow_mut().insert(
        PathBuf::from("/home/a/.thumbnails"),
        vec![vec![file("/home/a/.thumbnails/old.png", 1000, 0)]],
    );
    let sys = FakeSys::default();
    let measured = measure_person(&sys, &mem, &dirs, UserArea::ThumbnailCache, NOW).unwrap();
    assert_eq!((measured.bytes, measured.files), (5000, 2));
    let cleaned = clean_person(&sys, &mem, &dirs, UserArea::ThumbnailCache, NOW).unwrap();
    assert_eq!(cleaned.files, 2);
    let gone = mem.deleted.borrow();
    assert!(gone
        .iter()
        .all(|p| p.extension().is_some_and(|e| e == "png")));
}

#[test]
fn windows_areas_are_not_cleaned_here() {
    let dirs = PersonDirs::new(Path::new("/home/a"), None, None).unwrap();
    let sys = FakeSys::default();
    assert!(measure_person(&sys, &Mem::default(), &dirs, UserArea::Temp, NOW).is_err());
    assert!(clean_person(&sys, &Mem::default(), &dirs, UserArea::Thumbnails, NOW).is_err());
}

#[cfg(unix)]
mod on_disk {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn real_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn a_real_crash_folder_loses_only_old_flat_crash_files_and_links_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("old.crash"), vec![1u8; 300]).unwrap();
        fs::write(root.join("keep.txt"), b"x").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("deep.crash"), b"x").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.crash"), b"s").unwrap();
        symlink(outside.path().join("secret.crash"), root.join("link.crash")).unwrap();
        let later = real_now() + 30 * DAY;
        let m = flat(&RealFs, root, &CRASH_RULE, later, false);
        assert_eq!((m.bytes, m.files), (300, 1));
        let c = flat(&RealFs, root, &CRASH_RULE, later, true);
        assert_eq!(c.files, 1);
        assert!(!root.join("old.crash").exists());
        assert!(root.join("keep.txt").exists());
        assert!(root.join("sub").join("deep.crash").exists());
        assert!(outside.path().join("secret.crash").exists());
        assert!(fs::symlink_metadata(root.join("link.crash")).is_ok());
    }

    #[test]
    fn a_file_is_removed_only_if_it_still_passes_when_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.crash");
        fs::write(&path, b"x").unwrap();
        assert!(!RealFs.delete_checked(&path, false, &|_| false).unwrap());
        assert!(path.exists());
        assert!(RealFs.delete_checked(&path, false, &|_| true).unwrap());
        assert!(!path.exists());
        let target = dir.path().join("target");
        fs::write(&target, b"x").unwrap();
        let link = dir.path().join("l.crash");
        symlink(&target, &link).unwrap();
        assert!(RealFs.delete_checked(&link, false, &|_| true).is_err());
        assert!(target.exists());
    }

    #[test]
    fn previews_are_walked_through_their_size_folders() {
        let home = tempfile::tempdir().unwrap();
        let dirs = PersonDirs::new(home.path(), None, None).unwrap();
        let normal = home.path().join(".cache").join("thumbnails").join("normal");
        fs::create_dir_all(&normal).unwrap();
        fs::write(normal.join("a.png"), vec![0u8; 2000]).unwrap();
        fs::write(normal.join("b.png"), vec![0u8; 500]).unwrap();
        let sys = FakeSys::default();
        let now = real_now() + DAY;
        let m = measure_person(&sys, &RealFs, &dirs, UserArea::ThumbnailCache, now).unwrap();
        assert_eq!((m.bytes, m.files), (2500, 2));
        let c = clean_person(&sys, &RealFs, &dirs, UserArea::ThumbnailCache, now).unwrap();
        assert_eq!(c.files, 2);
        assert!(!normal.join("a.png").exists());
        assert!(normal.exists());
    }
}
