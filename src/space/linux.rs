//! Free up space on Linux: install files the package manager keeps, old crash reports, the picture
//! preview cache, runtimes no Flatpak app needs, and the Trash.
//!
//! The parts that need rights (package caches, crash reports, system runtimes) run in the root
//! helper; the person's own folders run in the window as that person. Programs go through [`Sys`]
//! and files through [`Fs`], so everything here is tested without touching the computer.
use super::{
    clean, file_pass, measure, Fs, Item, Rule, Tally, UserArea, CLEAN_BUDGET, MAX_ENTRIES,
    MEASURE_BUDGET,
};
use crate::linux::cmd::Sys;
use crate::linux::distro::{distro, Family};
use anyhow::{bail, ensure, Result};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const CRASH_DIR: &str = "/var/crash";
pub const CRASH_DAYS: u64 = 7;
pub const APT_ARCHIVES: &str = "/var/cache/apt/archives";
pub const DNF_CACHES: [&str; 2] = ["/var/cache/libdnf5", "/var/cache/dnf"];

const FLATPAK: &str = "/usr/bin/flatpak";
const GIO: &str = "/usr/bin/gio";
const APT_GET: &str = "/usr/bin/apt-get";
const DNF: &str = "/usr/bin/dnf";

pub const NOT_ON_THIS_SYSTEM: &str = "This clean up is not available on your system yet.";
pub const CANNOT_CLEAN: &str = "Secblitz could not finish this clean up. Nothing else was changed. Close any program that is installing software, then try again.";
pub const TRASH_NOT_EMPTIED: &str =
    "Secblitz could not empty the Trash. Nothing else was changed. Try emptying it from your files app.";

const fn rule(min_age_days: u64, extension: &'static [&'static str]) -> Rule {
    Rule {
        min_age_days,
        extensions: extension,
        name_prefix: None,
        remove_old_dirs: false,
        allow_shared: false,
    }
}

const CRASH_RULE: Rule = rule(CRASH_DAYS, &["crash"]);
const DEB_RULE: Rule = rule(0, &["deb"]);
const RPM_RULE: Rule = rule(0, &["rpm"]);
const PREVIEW_RULE: Rule = rule(0, &["png"]);
const TRASH_RULE: Rule = rule(0, &[]);

/// The folders of the signed-in person that cleaning may touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonDirs {
    home: PathBuf,
    cache: PathBuf,
    data: PathBuf,
}

impl PersonDirs {
    /// `cache` and `data` are the person's `XDG_CACHE_HOME` and `XDG_DATA_HOME`; a value that is not an absolute path is ignored.
    pub fn new(home: &Path, cache: Option<&Path>, data: Option<&Path>) -> Option<Self> {
        let absolute = |p: Option<&Path>| p.filter(|p| p.is_absolute()).map(Path::to_path_buf);
        home.is_absolute().then(|| Self {
            home: home.to_path_buf(),
            cache: absolute(cache).unwrap_or_else(|| home.join(".cache")),
            data: absolute(data).unwrap_or_else(|| home.join(".local").join("share")),
        })
    }

    pub fn from_env() -> Option<Self> {
        let var = |name| std::env::var_os(name).map(PathBuf::from);
        Self::new(
            &var("HOME")?,
            var("XDG_CACHE_HOME").as_deref(),
            var("XDG_DATA_HOME").as_deref(),
        )
    }

    fn previews(&self) -> [PathBuf; 2] {
        [self.cache.join("thumbnails"), self.home.join(".thumbnails")]
    }

    fn trash(&self) -> [PathBuf; 2] {
        let trash = self.data.join("Trash");
        [trash.join("files"), trash.join("info")]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Manager {
    Apt,
    Dnf,
}

fn manager(sys: &dyn Sys) -> Result<Manager> {
    let text = sys
        .read(Path::new("/etc/os-release"))?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    match distro(&text, None).family {
        Family::Debian => Ok(Manager::Apt),
        Family::Fedora => Ok(Manager::Dnf),
        Family::Other => bail!(NOT_ON_THIS_SYSTEM),
    }
}

/// Files directly inside `dir` that pass `rule`. Nothing below it is read, so a folder anyone can write to cannot lead the walk somewhere else.
fn flat(fs: &dyn Fs, dir: &Path, rule: &Rule, now: u64, delete: bool) -> Tally {
    let mut tally = Tally::default();
    let Ok(entries) = fs.list(dir, MAX_ENTRIES) else {
        return tally;
    };
    for entry in entries {
        if entry.path.parent() == Some(dir) {
            file_pass(fs, dir, rule, now, delete, &entry, &mut tally);
        }
    }
    tally
}

fn cache_tally(
    sys: &dyn Sys,
    fs: &dyn Fs,
    now: u64,
    deadline: Instant,
    delete: bool,
) -> Result<Tally> {
    Ok(match manager(sys)? {
        Manager::Apt => flat(fs, Path::new(APT_ARCHIVES), &DEB_RULE, now, delete),
        Manager::Dnf => {
            let mut total = Tally::default();
            for dir in DNF_CACHES {
                total.add(measure(fs, Path::new(dir), &RPM_RULE, now, deadline));
            }
            total
        }
    })
}

fn gone(before: Tally, after: Tally) -> Tally {
    Tally {
        bytes: before.bytes.saturating_sub(after.bytes),
        files: before.files.saturating_sub(after.files),
        left_alone: after.files,
    }
}

/// The size of what `item` would remove on this computer. Runs as root.
pub fn measure_machine(
    sys: &dyn Sys,
    fs: &dyn Fs,
    item: Item,
    now: u64,
    deadline: Instant,
) -> Result<Tally> {
    match item {
        Item::PackageCaches => cache_tally(sys, fs, now, deadline, false),
        Item::CrashReports => Ok(flat(fs, Path::new(CRASH_DIR), &CRASH_RULE, now, false)),
        Item::FlatpakRuntimes => unused_runtimes(sys, Scope::System).map(|u| u.tally()),
        _ => bail!(NOT_ON_THIS_SYSTEM),
    }
}

/// Removes what `item` measured. Runs as root. The answer says how much was freed.
pub fn clean_machine(
    sys: &dyn Sys,
    fs: &dyn Fs,
    item: Item,
    now: u64,
    deadline: Instant,
) -> Result<Tally> {
    match item {
        Item::PackageCaches => {
            let before = cache_tally(sys, fs, now, deadline, false)?;
            let out = match manager(sys)? {
                Manager::Apt => sys.run(APT_GET, &["clean"])?,
                Manager::Dnf => sys.run(DNF, &["clean", "packages"])?,
            };
            ensure!(out.success(), CANNOT_CLEAN);
            let after = cache_tally(sys, fs, now, deadline, false)?;
            Ok(gone(before, after))
        }
        Item::CrashReports => Ok(flat(fs, Path::new(CRASH_DIR), &CRASH_RULE, now, true)),
        Item::FlatpakRuntimes => remove_unused_runtimes(sys, Scope::System),
        _ => bail!(NOT_ON_THIS_SYSTEM),
    }
}

fn tree(
    fs: &dyn Fs,
    roots: &[PathBuf],
    rule: &Rule,
    now: u64,
    deadline: Instant,
    delete: bool,
) -> Tally {
    let mut total = Tally::default();
    for root in roots {
        total.add(if delete {
            clean(fs, root, rule, now, deadline)
        } else {
            measure(fs, root, rule, now, deadline)
        });
    }
    total
}

/// The size of one of the person's own areas.
pub fn measure_person(
    sys: &dyn Sys,
    fs: &dyn Fs,
    dirs: &PersonDirs,
    area: UserArea,
    now: u64,
) -> Result<Tally> {
    let deadline = Instant::now() + MEASURE_BUDGET;
    match area {
        UserArea::ThumbnailCache => Ok(tree(
            fs,
            &dirs.previews(),
            &PREVIEW_RULE,
            now,
            deadline,
            false,
        )),
        UserArea::Trash => Ok(tree(fs, &dirs.trash(), &TRASH_RULE, now, deadline, false)),
        UserArea::FlatpakUser => unused_runtimes(sys, Scope::User).map(|u| u.tally()),
        _ => bail!(NOT_ON_THIS_SYSTEM),
    }
}

/// Cleans one of the person's own areas. The Trash is emptied by the desktop's own tool, so every trash can on the computer is emptied together.
pub fn clean_person(
    sys: &dyn Sys,
    fs: &dyn Fs,
    dirs: &PersonDirs,
    area: UserArea,
    now: u64,
) -> Result<Tally> {
    let deadline = Instant::now() + CLEAN_BUDGET;
    match area {
        UserArea::ThumbnailCache => Ok(tree(
            fs,
            &dirs.previews(),
            &PREVIEW_RULE,
            now,
            deadline,
            true,
        )),
        UserArea::Trash => {
            let before = tree(fs, &dirs.trash(), &TRASH_RULE, now, deadline, false);
            let out = sys.run_long(GIO, &["trash", "--empty"])?;
            ensure!(out.success(), TRASH_NOT_EMPTIED);
            let after = tree(fs, &dirs.trash(), &TRASH_RULE, now, deadline, false);
            Ok(gone(before, after))
        }
        UserArea::FlatpakUser => remove_unused_runtimes(sys, Scope::User),
        _ => bail!(NOT_ON_THIS_SYSTEM),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    System,
    User,
}

impl Scope {
    fn flag(self) -> &'static str {
        match self {
            Scope::System => "--system",
            Scope::User => "--user",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Unused {
    /// Runtime, branch and its installed size in bytes.
    items: Vec<(String, String, u64)>,
}

impl Unused {
    fn tally(&self) -> Tally {
        Tally {
            bytes: self.items.iter().map(|i| i.2).sum(),
            files: self.items.len() as u64,
            left_alone: 0,
        }
    }
}

fn not_installed(error: &anyhow::Error) -> bool {
    error.to_string().starts_with("Could not start")
}

/// What Flatpak lists under "Uninstall unused", when asked and then told no.
/// `None` means the answer was neither a list nor "nothing".
fn parse_unused(text: &str) -> Option<Vec<(String, String)>> {
    if text.contains("Nothing unused to uninstall") {
        return Some(Vec::new());
    }
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else { continue };
        let numbered = first
            .strip_suffix('.')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !numbered {
            continue;
        }
        let rest: Vec<&str> = words.filter(|w| !w.starts_with('[')).collect();
        if let [id, branch, .., "r"] = rest.as_slice() {
            if id.contains('.') {
                rows.push(((*id).to_owned(), (*branch).to_owned()));
            }
        }
    }
    (!rows.is_empty()).then_some(rows)
}

/// "670.7 MB" as Flatpak prints sizes: decimal units.
fn parse_size(text: &str) -> Option<u64> {
    let (number, unit) = text.trim().split_once(' ')?;
    let value: f64 = number.parse().ok()?;
    let scale = match unit.trim().to_ascii_lowercase().as_str() {
        "byte" | "bytes" | "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => return None,
    };
    (value >= 0.0).then(|| (value * scale).round() as u64)
}

fn runtime_sizes(sys: &dyn Sys, scope: Scope) -> Result<Vec<(String, String, u64)>> {
    let out = sys.run(
        FLATPAK,
        &[
            "list",
            scope.flag(),
            "--runtime",
            "--columns=application,branch,size",
        ],
    )?;
    ensure!(out.success(), CANNOT_CLEAN);
    Ok(out
        .stdout
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (id, branch) = (words.next()?, words.next()?);
            let size = parse_size(&words.collect::<Vec<_>>().join(" "))?;
            Some((id.to_owned(), branch.to_owned(), size))
        })
        .collect())
}

fn unused_runtimes(sys: &dyn Sys, scope: Scope) -> Result<Unused> {
    let asked = match sys.run_answering(FLATPAK, &["uninstall", scope.flag(), "--unused"], "n\n") {
        Ok(out) => out,
        Err(e) if not_installed(&e) => return Ok(Unused { items: Vec::new() }),
        Err(e) => return Err(e),
    };
    let Some(unused) = parse_unused(&asked.stdout) else {
        bail!(CANNOT_CLEAN);
    };
    if unused.is_empty() {
        return Ok(Unused { items: Vec::new() });
    }
    let sizes = runtime_sizes(sys, scope)?;
    let items = unused
        .into_iter()
        .map(|(id, branch)| {
            let size = sizes
                .iter()
                .find(|s| s.0 == id && s.1 == branch)
                .map_or(0, |s| s.2);
            (id, branch, size)
        })
        .collect();
    Ok(Unused { items })
}

fn remove_unused_runtimes(sys: &dyn Sys, scope: Scope) -> Result<Tally> {
    let unused = unused_runtimes(sys, scope)?;
    if unused.items.is_empty() {
        return Ok(Tally::default());
    }
    let out = sys.run_long(
        FLATPAK,
        &[
            "uninstall",
            scope.flag(),
            "--unused",
            "-y",
            "--noninteractive",
        ],
    )?;
    ensure!(out.success(), CANNOT_CLEAN);
    Ok(unused.tally())
}

#[cfg(unix)]
pub use real::RealFs;

#[cfg(unix)]
mod real {
    use super::*;
    use crate::space::Entry;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::UNIX_EPOCH;

    /// The real file system. A link is never followed, and a file is removed only if it is still the one that was checked.
    pub struct RealFs;

    fn secs(time: io::Result<std::time::SystemTime>) -> Option<u64> {
        time.ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    }

    fn entry_of(path: &Path, meta: &fs::Metadata) -> Entry {
        let written = secs(meta.modified()).unwrap_or(0);
        Entry {
            path: path.to_path_buf(),
            is_dir: meta.is_dir(),
            reparse: meta.file_type().is_symlink(),
            size: meta.len(),
            created: secs(meta.created()).unwrap_or(written),
            written,
        }
    }

    impl Fs for RealFs {
        fn list(&self, dir: &Path, max: usize) -> io::Result<Vec<Entry>> {
            let mut out = Vec::new();
            for item in fs::read_dir(dir)?.take(max) {
                let path = item?.path();
                if let Ok(meta) = fs::symlink_metadata(&path) {
                    out.push(entry_of(&path, &meta));
                }
            }
            Ok(out)
        }

        fn delete_checked(
            &self,
            path: &Path,
            _shared: bool,
            check: &dyn Fn(&Entry) -> bool,
        ) -> io::Result<bool> {
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let meta = file.metadata()?;
            if !meta.is_file() || !check(&entry_of(path, &meta)) {
                return Ok(false);
            }
            let now = fs::symlink_metadata(path)?;
            if (now.dev(), now.ino()) != (meta.dev(), meta.ino()) {
                return Ok(false);
            }
            fs::remove_file(path)?;
            Ok(true)
        }

        fn remove_empty_dir(
            &self,
            path: &Path,
            _shared: bool,
            check: &dyn Fn(&Entry) -> bool,
        ) -> io::Result<bool> {
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_dir() || !check(&entry_of(path, &meta)) {
                return Ok(false);
            }
            fs::remove_dir(path)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests;
