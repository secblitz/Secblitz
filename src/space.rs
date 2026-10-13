//! Finding and removing leftover files that Windows and apps leave behind.
//!
//! One engine walks every folder. It never follows a reparse point, deletes only files that
//! still pass the filters when they are opened for deletion, and stays inside the folder it was
//! given. The file system sits behind [`Fs`] so the rules are tested without Windows.
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    clean_machine, clean_user, machine_roots, measure_machine, measure_user, user_roots,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Item {
    Temp,
    UpdateLeftovers,
    CrashDumps,
    Thumbnails,
}

impl Item {
    pub const ALL: [Item; 4] = [
        Item::Temp,
        Item::UpdateLeftovers,
        Item::CrashDumps,
        Item::Thumbnails,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Item::Temp => "space.temp",
            Item::UpdateLeftovers => "space.update_leftovers",
            Item::CrashDumps => "space.crash_dumps",
            Item::Thumbnails => "space.thumbnails",
        }
    }
}

/// The signed-in person's own folders, handled by the helper that runs as that person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserArea {
    Temp,
    CrashDumps,
    Thumbnails,
}

impl UserArea {
    pub fn to_byte(self) -> u8 {
        match self {
            UserArea::Temp => 0,
            UserArea::CrashDumps => 1,
            UserArea::Thumbnails => 2,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(UserArea::Temp),
            1 => Some(UserArea::CrashDumps),
            2 => Some(UserArea::Thumbnails),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tally {
    pub bytes: u64,
    pub files: u64,
    pub left_alone: u64,
}

impl Tally {
    pub fn add(&mut self, other: Tally) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.files = self.files.saturating_add(other.files);
        self.left_alone = self.left_alone.saturating_add(other.left_alone);
    }
}

pub const TEMP_DAYS: u64 = 7;
pub const DUMP_DAYS: u64 = 14;
pub const MAX_DEPTH: usize = 32;
pub const MAX_ENTRIES: usize = 200_000;
/// How long cleaning may run before it stops and reports what it has done so far.
pub const CLEAN_BUDGET: Duration = Duration::from_secs(8 * 60);
pub const MEASURE_BUDGET: Duration = Duration::from_secs(90);

/// One directory entry. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    pub is_dir: bool,
    pub reparse: bool,
    pub size: u64,
    pub created: u64,
    pub written: u64,
}

/// What the engine needs from a file system.
pub trait Fs {
    /// At most `max` entries of `dir`, so a folder with millions of files is never read whole.
    fn list(&self, dir: &Path, max: usize) -> std::io::Result<Vec<Entry>>;
    /// Opens `path` for deletion without following reparse points, reads its facts again from
    /// the handle and deletes it only if `check` still passes. Ok(false) means it was skipped.
    /// Unless `shared`, a file that another program has open for writing or deleting fails to
    /// open.
    fn delete_checked(
        &self,
        path: &Path,
        shared: bool,
        check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool>;
    /// The same for a folder, which only goes away when it is empty.
    fn remove_empty_dir(
        &self,
        path: &Path,
        shared: bool,
        check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool>;
}

pub struct Rule {
    pub min_age_days: u64,
    pub extensions: &'static [&'static str],
    pub name_prefix: Option<&'static str>,
    pub remove_old_dirs: bool,
    /// Whether another program may hold the file open with delete sharing and still have it
    /// removed. Explorer does this with the picture previews on purpose.
    pub allow_shared: bool,
}

pub const TEMP_RULE: Rule = Rule {
    min_age_days: TEMP_DAYS,
    extensions: &[],
    name_prefix: None,
    remove_old_dirs: true,
    allow_shared: false,
};
pub const DUMP_RULE: Rule = Rule {
    min_age_days: DUMP_DAYS,
    extensions: &["dmp", "mdmp", "hdmp"],
    name_prefix: None,
    remove_old_dirs: false,
    allow_shared: false,
};
pub const THUMB_RULE: Rule = Rule {
    min_age_days: 0,
    extensions: &["db"],
    name_prefix: Some("thumbcache_"),
    remove_old_dirs: false,
    allow_shared: true,
};

fn is_old(rule: &Rule, e: &Entry, now: u64) -> bool {
    let age = rule.min_age_days * 86_400;
    now.saturating_sub(e.created) >= age && now.saturating_sub(e.written) >= age
}

fn passes(rule: &Rule, e: &Entry, now: u64) -> bool {
    if e.is_dir || e.reparse {
        return false;
    }
    let name = e
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext_ok = rule.extensions.is_empty()
        || e.path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| rule.extensions.iter().any(|r| x.eq_ignore_ascii_case(r)));
    let prefix_ok = rule.name_prefix.is_none_or(|p| name.starts_with(p));
    is_old(rule, e, now) && ext_ok && prefix_ok
}

/// A folder's age comes from when it was made. Its own write time changes when the clean
/// empties it, so it says nothing about how long the folder has been there.
fn dir_is_old(rule: &Rule, e: &Entry, now: u64) -> bool {
    e.is_dir && !e.reparse && now.saturating_sub(e.created) >= rule.min_age_days * 86_400
}

/// True when `path` is strictly inside `root`, comparing names without regard to ASCII case.
/// A `..` in either path is refused.
pub fn within(root: &Path, path: &Path) -> bool {
    let key = |c: Component<'_>| match c {
        Component::ParentDir => None,
        other => Some(other.as_os_str().to_string_lossy().to_ascii_lowercase()),
    };
    let root: Option<Vec<String>> = root.components().map(key).collect();
    let path: Option<Vec<String>> = path.components().map(key).collect();
    match (root, path) {
        (Some(root), Some(path)) => path.len() > root.len() && path[..root.len()] == root[..],
        _ => false,
    }
}

fn file_pass(
    fs: &dyn Fs,
    root: &Path,
    rule: &Rule,
    now: u64,
    delete: bool,
    e: &Entry,
    tally: &mut Tally,
) {
    if !passes(rule, e, now) {
        return;
    }
    if !delete {
        tally.bytes += e.size;
        tally.files += 1;
        return;
    }
    match fs.delete_checked(&e.path, rule.allow_shared, &|fresh| {
        passes(rule, fresh, now) && within(root, &fresh.path)
    }) {
        Ok(true) => {
            tally.bytes += e.size;
            tally.files += 1;
        }
        Ok(false) => {}
        Err(_) => tally.left_alone += 1,
    }
}

fn walk(fs: &dyn Fs, root: &Path, rule: &Rule, now: u64, delete: bool, deadline: Instant) -> Tally {
    let mut tally = Tally::default();
    let mut seen = 0usize;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut dirs = Vec::new();
    'walk: while let Some((dir, depth)) = stack.pop() {
        if seen >= MAX_ENTRIES || Instant::now() >= deadline {
            break;
        }
        let Ok(entries) = fs.list(&dir, MAX_ENTRIES - seen) else {
            continue;
        };
        for e in entries {
            seen += 1;
            if seen > MAX_ENTRIES || Instant::now() >= deadline {
                break 'walk;
            }
            if e.reparse || !within(root, &e.path) {
                continue;
            }
            if e.is_dir {
                if depth + 1 < MAX_DEPTH {
                    stack.push((e.path.clone(), depth + 1));
                    dirs.push(e);
                }
                continue;
            }
            file_pass(fs, root, rule, now, delete, &e, &mut tally);
        }
    }
    if delete && rule.remove_old_dirs {
        dirs.sort_by_key(|d| std::cmp::Reverse(d.path.components().count()));
        for d in dirs {
            if Instant::now() >= deadline {
                break;
            }
            if dir_is_old(rule, &d, now) {
                let _ = fs.remove_empty_dir(&d.path, rule.allow_shared, &|fresh| {
                    fresh.is_dir && !fresh.reparse && within(root, &fresh.path)
                });
            }
        }
    }
    tally
}

pub fn measure(fs: &dyn Fs, root: &Path, rule: &Rule, now: u64, deadline: Instant) -> Tally {
    walk(fs, root, rule, now, false, deadline)
}

pub fn clean(fs: &dyn Fs, root: &Path, rule: &Rule, now: u64, deadline: Instant) -> Tally {
    walk(fs, root, rule, now, true, deadline)
}

/// One known file inside `root`, such as `MEMORY.DMP` in the Windows folder. Only that
/// folder's own listing is read; nothing beneath it is walked.
pub fn single_file(
    fs: &dyn Fs,
    root: &Path,
    name: &str,
    rule: &Rule,
    now: u64,
    delete: bool,
) -> Tally {
    let mut tally = Tally::default();
    let Ok(entries) = fs.list(root, MAX_ENTRIES) else {
        return tally;
    };
    let found = entries.into_iter().find(|e| {
        !e.reparse
            && within(root, &e.path)
            && e.path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
    });
    if let Some(e) = found {
        file_pass(fs, root, rule, now, delete, &e, &mut tally);
    }
    tally
}

/// The error text when Windows must restart to finish an update before it can tidy.
pub const NEEDS_RESTART: &str = "needs restart";

/// Reads the result of the component cleanup: 0, or the error code Windows gave. 3010 means a
/// restart would finish the job, which Secblitz leaves to the person.
#[cfg_attr(not(windows), allow(dead_code))]
fn component_cleanup_outcome(reply: &serde_json::Value) -> anyhow::Result<()> {
    const CBS_E_PENDING: u32 = 0x800F_0806;
    match reply.get("code").and_then(|v| v.as_i64()) {
        Some(0 | 3010) => Ok(()),
        Some(code) if code as u32 == CBS_E_PENDING => anyhow::bail!(NEEDS_RESTART),
        code => {
            anyhow::bail!("Windows did not finish tidying the leftovers from updates ({code:?})")
        }
    }
}

pub fn size_phrase(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    if bytes == 0 {
        String::new()
    } else if bytes < 1024 * MB {
        format!("{} MB", bytes.div_ceil(MB).max(1))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * MB as f64))
    }
}

#[cfg(not(windows))]
pub fn user_roots(_area: UserArea) -> Vec<PathBuf> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn machine_roots(_item: Item) -> Vec<(PathBuf, &'static Rule)> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn measure_user(_area: UserArea) -> Tally {
    Tally::default()
}
#[cfg(not(windows))]
pub fn clean_user(_area: UserArea) -> Tally {
    Tally::default()
}
#[cfg(not(windows))]
pub fn measure_machine(_item: Item) -> Tally {
    Tally::default()
}
#[cfg(not(windows))]
pub fn clean_machine(_item: Item) -> anyhow::Result<Tally> {
    Ok(Tally::default())
}
