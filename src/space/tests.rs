use super::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Error;

const DAY: u64 = 86_400;
const NOW: u64 = 100 * DAY;

struct Fake {
    entries: RefCell<BTreeMap<PathBuf, Entry>>,
    in_use: HashSet<PathBuf>,
    fresher: HashMap<PathBuf, Entry>,
    listing: HashMap<PathBuf, Vec<Entry>>,
    listed: RefCell<Vec<PathBuf>>,
    deleted: RefCell<Vec<PathBuf>>,
    removed_dirs: RefCell<Vec<PathBuf>>,
}

impl Fake {
    fn new() -> Self {
        Fake {
            entries: RefCell::default(),
            in_use: HashSet::new(),
            fresher: HashMap::new(),
            listing: HashMap::new(),
            listed: RefCell::default(),
            deleted: RefCell::default(),
            removed_dirs: RefCell::default(),
        }
    }

    fn put(&self, path: &str, is_dir: bool, reparse: bool, size: u64, created: u64, written: u64) {
        let path = PathBuf::from(path);
        self.entries.borrow_mut().insert(
            path.clone(),
            Entry {
                path,
                is_dir,
                reparse,
                size,
                created,
                written,
            },
        );
    }

    fn file(&self, path: &str, size: u64, age_days: u64) {
        let t = NOW - age_days * DAY;
        self.put(path, false, false, size, t, t);
    }

    fn dir(&self, path: &str, age_days: u64) {
        let t = NOW - age_days * DAY;
        self.put(path, true, false, 0, t, t);
    }

    fn deleted(&self) -> Vec<String> {
        self.deleted
            .borrow()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
}

impl Fs for Fake {
    fn list(&self, dir: &Path) -> std::io::Result<Vec<Entry>> {
        self.listed.borrow_mut().push(dir.to_path_buf());
        if let Some(fixed) = self.listing.get(dir) {
            return Ok(fixed.clone());
        }
        Ok(self
            .entries
            .borrow()
            .values()
            .filter(|e| e.path.parent() == Some(dir))
            .cloned()
            .collect())
    }

    fn delete_checked(&self, path: &Path, check: &dyn Fn(&Entry) -> bool) -> std::io::Result<bool> {
        if self.in_use.contains(path) {
            return Err(Error::from_raw_os_error(32));
        }
        let Some(real) = self.entries.borrow().get(path).cloned() else {
            return Ok(false);
        };
        let seen = self.fresher.get(path).cloned().unwrap_or(real);
        if !check(&seen) {
            return Ok(false);
        }
        self.entries.borrow_mut().remove(path);
        self.deleted.borrow_mut().push(path.to_path_buf());
        Ok(true)
    }

    fn remove_empty_dir(
        &self,
        path: &Path,
        check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        let Some(real) = self.entries.borrow().get(path).cloned() else {
            return Ok(false);
        };
        if !check(&real) {
            return Ok(false);
        }
        if self
            .entries
            .borrow()
            .values()
            .any(|e| e.path.parent() == Some(path))
        {
            return Err(Error::other("not empty"));
        }
        self.entries.borrow_mut().remove(path);
        self.removed_dirs.borrow_mut().push(path.to_path_buf());
        Ok(true)
    }
}

fn root() -> PathBuf {
    PathBuf::from("/Windows/Temp")
}

fn plain(path: &str, age_days: u64) -> Entry {
    let t = NOW - age_days * DAY;
    Entry {
        path: PathBuf::from(path),
        is_dir: false,
        reparse: false,
        size: 1,
        created: t,
        written: t,
    }
}

#[test]
fn old_temp_files_are_counted_and_removed() {
    let fs = Fake::new();
    fs.file("/Windows/Temp/a.tmp", 100, 8);
    fs.file("/Windows/Temp/b.tmp", 50, 30);
    fs.put(
        "/Windows/Temp/touched.tmp",
        false,
        false,
        999,
        NOW - 8 * DAY,
        NOW - DAY,
    );
    let measured = measure(&fs, &root(), &TEMP_RULE, NOW);
    assert_eq!((measured.bytes, measured.files), (150, 2));
    assert!(fs.deleted().is_empty());
    let cleaned = clean(&fs, &root(), &TEMP_RULE, NOW);
    assert_eq!(
        (cleaned.bytes, cleaned.files, cleaned.left_alone),
        (150, 2, 0)
    );
    assert_eq!(fs.deleted().len(), 2);
    assert!(fs
        .entries
        .borrow()
        .contains_key(Path::new("/Windows/Temp/touched.tmp")));
}

#[test]
fn new_files_are_kept() {
    let fs = Fake::new();
    fs.file("/Windows/Temp/new.tmp", 100, 6);
    assert_eq!(measure(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert_eq!(clean(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert!(fs.deleted().is_empty());
}

#[test]
fn in_use_files_are_left_alone() {
    let mut fs = Fake::new();
    fs.file("/Windows/Temp/busy.tmp", 500, 10);
    fs.file("/Windows/Temp/free.tmp", 70, 10);
    fs.in_use.insert(PathBuf::from("/Windows/Temp/busy.tmp"));
    let t = clean(&fs, &root(), &TEMP_RULE, NOW);
    assert_eq!((t.bytes, t.files, t.left_alone), (70, 1, 1));
    assert_eq!(fs.deleted(), vec!["/Windows/Temp/free.tmp"]);
}

#[test]
fn reparse_points_are_never_entered_or_deleted() {
    let mut fs = Fake::new();
    let t = NOW - 30 * DAY;
    fs.put("/Windows/Temp/junction", true, true, 0, t, t);
    fs.put("/Windows/Temp/link.tmp", false, true, 10, t, t);
    fs.file("/Windows/Temp/junction/inside.tmp", 100, 30);
    fs.listing.insert(
        PathBuf::from("/Windows/Temp/junction"),
        vec![plain("/Windows/Temp/junction/inside.tmp", 30)],
    );
    assert_eq!(measure(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert_eq!(clean(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert!(fs.deleted().is_empty());
    assert!(fs.removed_dirs.borrow().is_empty());
    assert!(!fs.listed.borrow().iter().any(|d| d.ends_with("junction")));
}

#[test]
fn a_path_outside_the_root_is_refused() {
    let mut fs = Fake::new();
    fs.put(
        "/Windows/System32/x.dll",
        false,
        false,
        1,
        NOW - 30 * DAY,
        NOW - 30 * DAY,
    );
    fs.listing
        .insert(root(), vec![plain("/Windows/System32/x.dll", 30)]);
    assert_eq!(clean(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert!(fs.deleted().is_empty());

    assert!(within(&root(), Path::new("/Windows/Temp/a/b")));
    assert!(within(&root(), Path::new("/windows/TEMP/A.tmp")));
    assert!(!within(&root(), Path::new("/Windows/Temp")));
    assert!(!within(
        &root(),
        Path::new("/Windows/Temp/../System32/x.dll")
    ));
    assert!(!within(&root(), Path::new("/Windows/TempX/a.tmp")));
    assert!(!within(&root(), Path::new("/Windows/Tem")));
}

#[test]
fn dump_rule_matches_only_dump_files() {
    let fs = Fake::new();
    let r = PathBuf::from("/Windows/Minidump");
    fs.file("/Windows/Minidump/a.dmp", 10, 15);
    fs.file("/Windows/Minidump/b.MDMP", 10, 15);
    fs.file("/Windows/Minidump/c.hdmp", 10, 15);
    fs.file("/Windows/Minidump/d.txt", 10, 15);
    fs.file("/Windows/Minidump/e.dmp", 10, 13);
    let t = clean(&fs, &r, &DUMP_RULE, NOW);
    assert_eq!(t.files, 3);
    assert_eq!(fs.deleted().len(), 3);
}

#[test]
fn thumbnail_rule_matches_only_thumbcache_files() {
    let fs = Fake::new();
    let r = PathBuf::from("/Explorer");
    fs.file("/Explorer/thumbcache_256.db", 10, 0);
    fs.file("/Explorer/iconcache_32.db", 10, 0);
    let t = clean(&fs, &r, &THUMB_RULE, NOW);
    assert_eq!(t.files, 1);
    assert_eq!(fs.deleted(), vec!["/Explorer/thumbcache_256.db"]);
}

#[test]
fn old_empty_folders_are_removed_but_the_root_never() {
    let fs = Fake::new();
    fs.dir("/Windows/Temp/old", 9);
    fs.dir("/Windows/Temp/old/deeper", 9);
    fs.dir("/Windows/Temp/young", 1);
    fs.dir("/Windows/Temp/full", 9);
    fs.file("/Windows/Temp/full/keep.tmp", 5, 1);
    fs.file("/Windows/Temp/old/deeper/x.tmp", 5, 9);
    clean(&fs, &root(), &TEMP_RULE, NOW);
    let removed: Vec<_> = fs.removed_dirs.borrow().clone();
    assert_eq!(
        removed,
        vec![
            PathBuf::from("/Windows/Temp/old/deeper"),
            PathBuf::from("/Windows/Temp/old")
        ]
    );
    assert!(!removed.contains(&root()));
}

#[test]
fn deep_trees_stop_at_the_depth_cap() {
    let fs = Fake::new();
    let mut path = String::from("/Windows/Temp");
    for i in 0..200 {
        path.push_str(&format!("/d{i}"));
        fs.dir(&path, 30);
        fs.file(&format!("{path}/f.tmp"), 1, 30);
    }
    let t = clean(&fs, &root(), &TEMP_RULE, NOW);
    assert!(fs.listed.borrow().len() <= MAX_DEPTH);
    assert!(t.files as usize <= MAX_DEPTH);
}

#[test]
fn entry_cap_stops_the_walk() {
    let mut fs = Fake::new();
    let many: Vec<Entry> = (0..MAX_ENTRIES + 10)
        .map(|i| plain(&format!("/Windows/Temp/f{i}.tmp"), 30))
        .collect();
    fs.listing.insert(root(), many);
    let t = measure(&fs, &root(), &TEMP_RULE, NOW);
    assert_eq!(t.files as usize, MAX_ENTRIES);
}

#[test]
fn the_check_runs_again_at_delete_time() {
    let mut fs = Fake::new();
    fs.file("/Windows/Temp/swapped.tmp", 10, 30);
    let p = PathBuf::from("/Windows/Temp/swapped.tmp");
    let mut touched = fs.entries.borrow()[&p].clone();
    touched.written = NOW - DAY;
    fs.fresher.insert(p.clone(), touched);
    assert_eq!(clean(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert!(fs.deleted().is_empty());

    let mut moved = fs.entries.borrow()[&p].clone();
    moved.path = PathBuf::from("/Windows/System32/swapped.tmp");
    fs.fresher.insert(p, moved);
    assert_eq!(clean(&fs, &root(), &TEMP_RULE, NOW), Tally::default());
    assert!(fs.deleted().is_empty());
}

#[test]
fn a_single_known_file_is_found_without_walking_below() {
    let fs = Fake::new();
    fs.file("/Windows/MEMORY.DMP", 900, 20);
    fs.file("/Windows/Temp/old.dmp", 5, 20);
    let win = PathBuf::from("/Windows");
    let m = single_file(&fs, &win, "memory.dmp", &DUMP_RULE, NOW, false);
    assert_eq!((m.bytes, m.files), (900, 1));
    let c = single_file(&fs, &win, "MEMORY.DMP", &DUMP_RULE, NOW, true);
    assert_eq!(c.files, 1);
    assert_eq!(fs.listed.borrow().as_slice(), [win.clone(), win]);
}

#[test]
fn size_phrase_reads_plainly() {
    assert_eq!(size_phrase(0), "");
    assert_eq!(size_phrase(1), "1 MB");
    assert_eq!(size_phrase(300 * 1024 * 1024), "300 MB");
    assert_eq!(size_phrase(3 * 1024 * 1024 * 1024), "3.0 GB");
}

#[test]
fn user_area_bytes_round_trip() {
    for a in [UserArea::Temp, UserArea::CrashDumps, UserArea::Thumbnails] {
        assert_eq!(UserArea::from_byte(a.to_byte()), Some(a));
    }
    assert_eq!(UserArea::from_byte(3), None);
}

#[test]
fn item_ids_are_fixed() {
    let ids: Vec<_> = Item::ALL.iter().map(|i| i.id()).collect();
    assert_eq!(
        ids,
        [
            "space.temp",
            "space.update_leftovers",
            "space.crash_dumps",
            "space.thumbnails"
        ]
    );
}
