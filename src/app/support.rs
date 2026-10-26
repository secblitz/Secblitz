//! The support file: a small zip the person can attach to a problem report. Nothing is sent
//! anywhere. It holds counts and settings, never files, names or the sites someone visited.
use crate::app::history::{self, Entry, Kind as HistoryKind};
use redact::Redactor;
use secblitz::debloat::Batch;
use secblitz::engine::ChangeSummary;
use secblitz::filter::config::{BlockHistory, Config, Status};
use secblitz::filter::matcher::Kind as SiteKind;
use secblitz::updater::UpdateStatus;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

mod redact;
mod zip;

pub use redact::hide_sites;

const MAX_FILE: usize = 120_000;
const NEWEST_ENTRIES: usize = 30;
const BLOCK_DAYS: usize = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum Changes {
    Unreadable,
    Damaged,
    Read(ChangeSummary),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum AppState {
    Removed { copy_kept: bool },
    BroughtBack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFact {
    pub family: String,
    pub state: AppState,
}

#[derive(Debug, Clone)]
pub struct WebFacts {
    pub config: Config,
    pub status: Option<Status>,
    pub lists: Vec<(String, Option<u64>)>,
    pub stats: Option<BlockHistory>,
}

/// Everything a support file is made from. Built by `collect`, turned into files by `files`.
#[derive(Debug, Clone)]
pub struct Facts {
    pub at: u64,
    pub version: String,
    pub windows: String,
    pub language: String,
    pub theme: String,
    pub installed: bool,
    pub background: Option<bool>,
    pub tray: bool,
    pub checked_at: Option<u64>,
    pub checks: Vec<(String, String)>,
    pub history: Vec<Entry>,
    pub changes: Changes,
    pub apps: Option<Vec<AppFact>>,
    pub web: Option<WebFacts>,
    pub update: Option<UpdateStatus>,
    pub services: Vec<(String, String)>,
    pub problems: Vec<String>,
}

fn stamp(t: u64) -> String {
    let local = secblitz::clock::local_seconds(t);
    let (y, m, d) = history::civil(local / 86_400);
    let rest = local % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn day(days: u64) -> String {
    let (y, m, d) = history::civil(days);
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn file_name(at: u64) -> String {
    let local = secblitz::clock::local_seconds(at);
    let (y, m, d) = history::civil(local / 86_400);
    let rest = local % 86_400;
    format!(
        "Secblitz-support-{y:04}-{m:02}-{d:02}-{:02}{:02}.zip",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn zip_time(at: u64) -> zip::DosTime {
    let local = secblitz::clock::local_seconds(at);
    let (y, m, d) = history::civil(local / 86_400);
    let rest = local % 86_400;
    zip::DosTime::new(
        y,
        m,
        d,
        (rest / 3600) as u32,
        (rest % 3600 / 60) as u32,
        (rest % 60) as u32,
    )
}

fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

fn about(f: &Facts) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "Secblitz support file");
    let _ = writeln!(s, "Made: {} (local time)", stamp(f.at));
    let _ = writeln!(
        s,
        "Secblitz: {} ({})",
        f.version,
        if f.installed { "installed" } else { "portable" }
    );
    let _ = writeln!(s, "Windows: {}", f.windows);
    let _ = writeln!(s, "Language: {}", f.language);
    let _ = writeln!(s, "Theme: {}", f.theme);
    let _ = writeln!(
        s,
        "Background checks: {}",
        f.background.map_or("unknown", on_off)
    );
    let _ = writeln!(s, "System tray icon: {}", on_off(f.tray));
    s
}

fn last_check(f: &Facts) -> String {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for (_, status) in &f.checks {
        *counts.entry(status).or_default() += 1;
    }
    let checks: Vec<_> = f
        .checks
        .iter()
        .map(|(id, status)| serde_json::json!({ "id": id, "status": status }))
        .collect();
    let value = serde_json::json!({
        "checked_at": f.checked_at.map(stamp),
        "counts": counts,
        "checks": checks,
    });
    serde_json::to_string_pretty(&value).unwrap_or_default() + "\n"
}

fn kind_name(kind: HistoryKind) -> &'static str {
    match kind {
        HistoryKind::Check => "check",
        HistoryKind::Fix => "fix",
        HistoryKind::Undo => "undo",
        HistoryKind::UndoSome => "undo some",
        HistoryKind::Debloat => "app removal",
        HistoryKind::Restore => "app restore",
        HistoryKind::Recovery => "recovery",
        HistoryKind::SecureBootRenewal => "secure boot renewal",
        HistoryKind::FreedSpace => "freed space",
    }
}

fn history_text(f: &Facts) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "Recorded entries: {}", f.history.len());
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &f.history {
        *kinds.entry(kind_name(e.kind)).or_default() += 1;
    }
    for (kind, n) in kinds {
        let _ = writeln!(s, "  {kind}: {n}");
    }
    if let (Some(first), Some(last)) = (f.history.first(), f.history.last()) {
        let _ = writeln!(s, "First: {}", stamp(first.t));
        let _ = writeln!(s, "Last: {}", stamp(last.t));
    }
    let _ = writeln!(s, "Newest entries:");
    for e in f.history.iter().rev().take(NEWEST_ENTRIES) {
        let _ = writeln!(
            s,
            "  {}  {}  {} of {} protected  ({})",
            stamp(e.t),
            kind_name(e.kind),
            e.protected,
            e.total,
            e.n
        );
    }
    s
}

fn changes_text(f: &Facts) -> String {
    let mut s = String::new();
    match &f.changes {
        Changes::Unreadable => {
            let _ = writeln!(s, "The record of changes could not be read.");
        }
        Changes::Damaged => {
            let _ = writeln!(s, "History damaged: yes");
        }
        Changes::Read(c) => {
            let _ = writeln!(s, "History damaged: no");
            let _ = writeln!(s, "Recorded sets of changes: {}", c.sets);
            let _ = writeln!(s, "  Applied: {}", c.applied);
            let _ = writeln!(s, "  Unfinished or being put back: {}", c.pending);
            let _ = writeln!(s, "  Put back: {}", c.reverted);
            let _ = writeln!(s, "Checks with a fix in place:");
            for id in &c.checks {
                let _ = writeln!(s, "  {id}");
            }
        }
    }
    s
}

fn apps_text(f: &Facts) -> String {
    let mut s = String::new();
    let Some(apps) = &f.apps else {
        let _ = writeln!(s, "The list of removed apps could not be read.");
        return s;
    };
    let _ = writeln!(s, "Apps Secblitz has removed: {}", apps.len());
    for app in apps {
        let state = match app.state {
            AppState::Removed { copy_kept: true } => "removed, copy kept",
            AppState::Removed { copy_kept: false } => "removed, no copy kept",
            AppState::BroughtBack => "brought back",
        };
        let _ = writeln!(s, "  {}: {state}", app.family);
    }
    s
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn apps_from(
    batches: &[Batch],
    family: impl Fn(u16) -> Option<String>,
    has_copy: impl Fn(u16) -> bool,
) -> Vec<AppFact> {
    let mut latest: BTreeMap<u16, bool> = BTreeMap::new();
    for batch in batches {
        for r in &batch.removed {
            latest.insert(r.index, r.restored);
        }
    }
    latest
        .into_iter()
        .filter_map(|(index, restored)| {
            Some(AppFact {
                family: family(index)?,
                state: if restored {
                    AppState::BroughtBack
                } else {
                    AppState::Removed {
                        copy_kept: has_copy(index),
                    }
                },
            })
        })
        .collect()
}

fn web_text(f: &Facts) -> String {
    let mut s = String::new();
    let Some(web) = &f.web else {
        let _ = writeln!(s, "Web protection settings could not be read.");
        return s;
    };
    let c = &web.config;
    let _ = writeln!(s, "Switches:");
    for (name, on) in [
        ("ads", c.ads),
        ("tracking", c.tracking),
        ("dangerous sites", c.dangerous),
        ("adult sites", c.adult),
        ("gambling", c.gambling),
        ("scams", c.scam),
        ("pop-ups", c.popups),
        ("safe search", c.safe_search),
        ("private lookups", c.private_lookups),
    ] {
        let _ = writeln!(s, "  {name}: {}", on_off(on));
    }
    let _ = writeln!(s, "Paused: {}", if c.paused(f.at) { "yes" } else { "no" });
    let _ = writeln!(s, "Sites always allowed: {}", c.allow.len());
    let _ = writeln!(s, "Sites allowed for a few minutes: {}", c.allow_once.len());
    match &web.status {
        Some(st) => {
            let _ = writeln!(
                s,
                "Service listening: {}",
                if st.listening { "yes" } else { "no" }
            );
            let _ = writeln!(s, "Service state: {:?}", st.state);
            let _ = writeln!(s, "Lookups: {:?}", st.lookups);
            let _ = writeln!(
                s,
                "Lists updated: {}",
                st.lists_updated.map_or("never".into(), stamp)
            );
            let _ = writeln!(s, "Ways around Web protection found:");
            match &st.gaps {
                Some(gaps) if gaps.is_empty() => {
                    let _ = writeln!(s, "  none");
                }
                Some(gaps) => {
                    for gap in gaps {
                        let _ = writeln!(s, "  {gap:?}");
                    }
                }
                None => {
                    let _ = writeln!(s, "  could not be checked");
                }
            }
            let _ = writeln!(
                s,
                "Last error: {}",
                st.last_error
                    .map_or("none".into(), |e| hide_sites(&format!("{e:?}")))
            );
        }
        None => {
            let _ = writeln!(s, "No status from the Web protection service.");
        }
    }
    let _ = writeln!(s, "Block lists:");
    for (id, updated) in &web.lists {
        let _ = writeln!(
            s,
            "  {id}: {}",
            updated.map_or("not downloaded".into(), stamp)
        );
    }
    if let Some(stats) = &web.stats {
        let _ = writeln!(s, "Blocks per day:");
        let skip = stats.days.len().saturating_sub(BLOCK_DAYS);
        for d in &stats.days[skip..] {
            let parts: Vec<String> = SiteKind::ALL
                .iter()
                .map(|k| format!("{k:?} {}", d.blocked[k.index()]))
                .collect();
            let _ = writeln!(s, "  {}: {}", day(d.day), parts.join(", "));
        }
    }
    s
}

fn updates_text(f: &Facts) -> String {
    let mut s = String::new();
    match &f.update {
        None => {
            let _ = writeln!(s, "The update status could not be read.");
        }
        Some(u) => {
            let _ = writeln!(
                s,
                "Last checked: {}",
                if u.checked_at == 0 {
                    "never".into()
                } else {
                    stamp(u.checked_at)
                }
            );
            let _ = writeln!(s, "Result: {}", hide_sites(&format!("{:?}", u.result)));
        }
    }
    s
}

fn services_text(f: &Facts) -> String {
    let mut s = String::new();
    if f.services.is_empty() {
        let _ = writeln!(s, "Services could not be read.");
    }
    for (name, state) in &f.services {
        let _ = writeln!(s, "{name}: {state}");
    }
    s
}

fn problem_text(f: &Facts) -> String {
    if f.problems.is_empty() {
        return "No problem is recorded.\n".into();
    }
    f.problems.iter().map(|p| format!("{p}\n")).collect()
}

fn capped(mut text: String) -> Vec<u8> {
    if text.len() > MAX_FILE {
        let mut end = MAX_FILE;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n(cut: too long)\n");
    }
    text.into_bytes()
}

/// The files that go into the zip, every one cleaned of personal parts.
pub fn files(f: &Facts, redactor: &Redactor) -> Vec<(String, Vec<u8>)> {
    [
        ("about.txt", about(f)),
        ("last-check.json", last_check(f)),
        ("history.txt", history_text(f)),
        ("changes.txt", changes_text(f)),
        ("apps.txt", apps_text(f)),
        ("web-protection.txt", web_text(f)),
        ("updates.txt", updates_text(f)),
        ("services.txt", services_text(f)),
        ("last-problem.txt", problem_text(f)),
    ]
    .into_iter()
    .map(|(name, text)| (name.to_owned(), capped(redactor.clean(&text))))
    .collect()
}

pub fn archive(f: &Facts, redactor: &Redactor) -> Result<Vec<u8>, String> {
    zip::write(&files(f, redactor), zip_time(f.at)).map_err(|e| e.to_string())
}

/// `name` with the number `save_new` adds when the name is taken; 1 leaves it as it is.
pub fn numbered(name: &str, n: u8) -> String {
    let (stem, ext) = name.rsplit_once('.').unwrap_or((name, "zip"));
    if n <= 1 {
        name.to_owned()
    } else {
        format!("{stem}-{n}.{ext}")
    }
}

/// Creates a new file in `dir`, adding a number when the name is taken. An existing file or
/// link is never opened or replaced. Returns the path and the number used.
pub fn save_new(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<(PathBuf, u8)> {
    use std::io::Write;
    for n in 1..100 {
        let path = dir.join(numbered(name, n));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
                return Ok((path, n));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "too many support files",
    ))
}

/// The newest support file in `dir`. Links and anything not named like a support file are skipped.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn newest_file(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("Secblitz-support-") && n.ends_with(".zip"))
        })
        .filter_map(|e| {
            let meta = std::fs::symlink_metadata(e.path()).ok()?;
            meta.is_file()
                .then_some(())
                .and(meta.modified().ok())
                .map(|at| (at, e.path()))
        })
        .max()
        .map(|(_, path)| path)
}

#[cfg(windows)]
pub use system::downloads;

/// Opens Downloads in Explorer with the newest support file selected.
#[cfg(windows)]
pub fn show_in_folder() -> bool {
    use std::os::windows::process::CommandExt;
    let Some(dir) = downloads() else {
        return false;
    };
    let Some(root) = std::env::var_os("SystemRoot").filter(|r| !r.is_empty()) else {
        return false;
    };
    let mut explorer = std::process::Command::new(Path::new(&root).join("explorer.exe"));
    match newest_file(&dir) {
        Some(file) => explorer.raw_arg(format!("/select,\"{}\"", file.display())),
        None => explorer.arg(&dir),
    };
    explorer.creation_flags(0x08000000).spawn().is_ok()
}

#[cfg(not(windows))]
pub fn show_in_folder() -> bool {
    false
}

/// Explorer folder windows, so the one that opens for the support file can be
/// brought to the front by the window that asked for it.
pub mod folder {
    /// Visible Explorer folder windows, front first.
    #[cfg(windows)]
    pub fn windows() -> Vec<isize> {
        use windows_sys::core::BOOL;
        use windows_sys::Win32::Foundation::HWND;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetClassNameW, IsWindowVisible,
        };
        unsafe extern "system" fn visit(hwnd: HWND, param: isize) -> BOOL {
            // SAFETY: `param` is the Vec passed below, alive for the whole enumeration.
            let found = unsafe { &mut *(param as *mut Vec<isize>) };
            let mut class = [0u16; 32];
            // SAFETY: the buffer and its length describe `class`.
            let n = unsafe { GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32) };
            // SAFETY: plain query of a window handle Windows just gave us.
            let visible = unsafe { IsWindowVisible(hwnd) } != 0;
            if n > 0 && visible && String::from_utf16_lossy(&class[..n as usize]) == "CabinetWClass"
            {
                found.push(hwnd as isize);
            }
            1
        }
        let mut found = Vec::new();
        // SAFETY: the callback only uses `found` through the pointer given here.
        unsafe { EnumWindows(Some(visit), &mut found as *mut Vec<isize> as isize) };
        found
    }

    #[cfg(not(windows))]
    pub fn windows() -> Vec<isize> {
        Vec::new()
    }

    /// Waits a moment for the folder window and brings it to the front. The
    /// desktop's Explorer opens it, and Windows would keep it behind Secblitz.
    #[cfg(windows)]
    pub fn bring_forward(before: &[isize]) {
        use windows_sys::Win32::Foundation::HWND;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE,
        };
        for tries in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let now = windows();
            let new = now.iter().find(|h| !before.contains(h));
            // An already open Downloads window is reused instead of a new one.
            let Some(&hwnd) = new.or(now.first().filter(|_| tries >= 15)) else {
                continue;
            };
            let hwnd = hwnd as HWND;
            // SAFETY: plain window calls on a handle from the enumeration above.
            unsafe {
                if IsIconic(hwnd) != 0 {
                    ShowWindow(hwnd, SW_RESTORE);
                }
                SetForegroundWindow(hwnd);
            }
            return;
        }
    }

    #[cfg(not(windows))]
    pub fn bring_forward(_: &[isize]) {}
}

pub fn redactor() -> Redactor {
    let redactor = Redactor::new(
        &std::env::var("USERNAME").unwrap_or_default(),
        &std::env::var("COMPUTERNAME").unwrap_or_default(),
    )
    .and_user(&system::session_user().unwrap_or_default());
    system::profile_folders()
        .iter()
        .fold(redactor, |r, folder| r.and_profile(folder))
}

/// What the person's own settings and the last check say, gathered on the window's thread.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub language: String,
    pub theme: String,
    pub installed: bool,
    pub background: Option<bool>,
    pub tray: bool,
    pub checked_at: Option<u64>,
    pub checks: Vec<(String, String)>,
    pub problems: Vec<String>,
}

/// Who saves the file in the person's Downloads.
pub enum Saver {
    /// The launcher, which runs as the person even when this window runs as another account.
    Launcher(std::sync::Arc<crate::broker::Client>),
    /// This window, which runs as the person.
    Here,
}

/// Collects, builds and saves the file in Downloads. Returns the saved file's name.
pub fn create(inputs: Inputs, saver: Saver) -> Result<String, String> {
    let at = history::now();
    let facts = system::collect(inputs, at);
    let bytes = archive(&facts, &redactor())?;
    let name = file_name(at);
    let n = match saver {
        Saver::Launcher(client) => match client.save_file(at, &bytes) {
            Ok(Ok(n)) => n,
            Ok(Err(reply)) => return Err(format!("The launcher answered {reply:?}")),
            Err(e) => return Err(format!("{e:#}")),
        },
        Saver::Here => {
            let dir = system::downloads().ok_or_else(|| "Downloads folder not found".to_owned())?;
            save_new(&dir, &name, &bytes).map_err(|e| e.to_string())?.1
        }
    };
    Ok(numbered(&name, n))
}

mod system {
    use super::*;

    #[cfg(windows)]
    pub fn downloads() -> Option<PathBuf> {
        known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Downloads)
    }

    /// Every account's profile folder name. A folder keeps its old name when an account is
    /// renamed, and under an administrator's password this window's own profile is not the person's.
    #[cfg(windows)]
    pub fn profile_folders() -> Vec<String> {
        known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_UserProfiles)
            .and_then(|dir| std::fs::read_dir(dir).ok())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }

    #[cfg(windows)]
    fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use std::ptr::null_mut;
        use windows_sys::Win32::System::Com::CoTaskMemFree;
        use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
        let mut raw = null_mut();
        // SAFETY: valid GUID and output pointer; the allocation is freed below even on failure.
        let hr = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut raw) };
        let path = if hr >= 0 && !raw.is_null() {
            // SAFETY: success returns a NUL-terminated UTF-16 string, freed only below.
            let slice = unsafe { secblitz::platform::security::wide_str(raw) };
            slice.map(|s| PathBuf::from(std::ffi::OsString::from_wide(s)))
        } else {
            None
        };
        // SAFETY: null or the allocation returned above.
        unsafe { CoTaskMemFree(raw.cast()) };
        path.filter(|p| p.is_absolute() && p.is_dir())
    }

    /// The person signed in to this session. After an administrator's password was typed in,
    /// this window runs as that administrator, but the person is still this one.
    #[cfg(windows)]
    pub fn session_user() -> Option<String> {
        use windows_sys::Win32::System::RemoteDesktop::{
            WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SESSION,
        };
        let (mut raw, mut bytes) = (std::ptr::null_mut(), 0u32);
        // SAFETY: the out-pointers are valid; the returned buffer is freed below.
        let ok = unsafe {
            WTSQuerySessionInformationW(
                std::ptr::null_mut(),
                WTS_CURRENT_SESSION,
                WTSUserName,
                &mut raw,
                &mut bytes,
            )
        };
        if ok == 0 || raw.is_null() {
            return None;
        }
        // SAFETY: success returns a NUL-terminated UTF-16 string, freed only below.
        let name =
            unsafe { secblitz::platform::security::wide_str(raw) }.map(String::from_utf16_lossy);
        // SAFETY: `raw` came from WTSQuerySessionInformationW and is freed once.
        unsafe { WTSFreeMemory(raw.cast()) };
        name
    }

    #[cfg(not(windows))]
    pub fn session_user() -> Option<String> {
        None
    }

    #[cfg(not(windows))]
    pub fn profile_folders() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(windows))]
    pub fn downloads() -> Option<PathBuf> {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
        Some(PathBuf::from(home).join("Downloads")).filter(|p| p.is_dir())
    }

    pub fn collect(inputs: Inputs, at: u64) -> Facts {
        let Inputs {
            language,
            theme,
            installed,
            background,
            tray,
            checked_at,
            checks,
            problems,
        } = inputs;
        let (changes, apps, web, services) = sources();
        Facts {
            at,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            windows: windows_text(),
            language,
            theme,
            installed,
            background,
            tray,
            checked_at,
            checks,
            history: secblitz::platform::app_dir()
                .map(|d| history::load(&d))
                .unwrap_or_default(),
            changes,
            apps,
            web,
            update: crate::app::settings::update_status().ok(),
            services,
            problems,
        }
    }

    type Sources = (
        Changes,
        Option<Vec<AppFact>>,
        Option<WebFacts>,
        Vec<(String, String)>,
    );

    #[cfg(windows)]
    fn sources() -> Sources {
        use secblitz::debloat::{self, journal, offline};
        use secblitz::filter::{self, config, scm};
        let changes = match secblitz::platform::state_dir().and_then(|dir| {
            secblitz::engine::Engine::open(
                dir,
                secblitz::permissions::with_permissions(secblitz::platform::backend()?),
            )
        }) {
            Ok(mut engine) => engine
                .change_summary()
                .map_or(Changes::Unreadable, Changes::Read),
            Err(e)
                if e.downcast_ref::<secblitz::engine::recover::JournalDamaged>()
                    .is_some() =>
            {
                Changes::Damaged
            }
            Err(_) => Changes::Unreadable,
        };
        let apps = Some(apps_from(
            &journal::load(),
            |i| {
                debloat::catalog()
                    .get(usize::from(i))
                    .map(|a| a.family.to_owned())
            },
            offline::has_copy,
        ));
        let web = config::config_path().ok().map(|path| WebFacts {
            config: config::load_config(&path),
            status: config::status_path()
                .ok()
                .and_then(|p| config::load_status(&p)),
            lists: config::lists_dir()
                .map(|dir| {
                    filter::lists::SOURCES
                        .iter()
                        .map(|s| (s.id.to_owned(), filter::fetch::stored_at(&dir, s.id)))
                        .collect()
                })
                .unwrap_or_default(),
            stats: config::stats_path()
                .ok()
                .and_then(|p| config::load_stats(&p)),
        });
        let monitor = secblitz::service::query_status()
            .map(|s| format!("{:?}", s.state))
            .unwrap_or_else(|_| "unknown".into());
        let filter_state = scm::state()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|_| "unknown".into());
        let services = vec![
            ("SecblitzMonitor".to_owned(), monitor),
            (filter::SERVICE_NAME.to_owned(), filter_state),
        ];
        (changes, apps, web, services)
    }

    #[cfg(not(windows))]
    fn sources() -> Sources {
        (Changes::Unreadable, None, None, Vec::new())
    }

    #[cfg(windows)]
    fn windows_text() -> String {
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
        };
        fn value(name: &str) -> Option<String> {
            let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
            let mut buf = [0u16; 128];
            let mut size = (buf.len() * 2) as u32;
            // SAFETY: both names are NUL-terminated; `buf` and `size` describe one writable buffer.
            let status = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").as_ptr(),
                    wide(name).as_ptr(),
                    RRF_RT_REG_SZ,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if status != 0 {
                return None;
            }
            let len = (size as usize / 2).saturating_sub(1);
            Some(String::from_utf16_lossy(&buf[..len]).trim().to_owned())
        }
        let build = value("CurrentBuildNumber").and_then(|b| b.parse::<u32>().ok());
        let version = value("DisplayVersion").or_else(|| value("ReleaseId"));
        let processor = std::env::var("PROCESSOR_ARCHITEW6432")
            .or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE"))
            .ok();
        windows_line(
            value("ProductName").as_deref(),
            version.as_deref(),
            build,
            processor.as_deref(),
            secblitz::platform::x64_on_arm(),
        )
    }

    #[cfg(not(windows))]
    fn windows_text() -> String {
        windows_line(None, None, None, Some(std::env::consts::ARCH), false)
    }
}

/// Windows 11 still reports itself as "Windows 10" in its product name, so the build number decides.
fn windows_line(
    edition: Option<&str>,
    version: Option<&str>,
    build: Option<u32>,
    processor: Option<&str>,
    x64_on_arm: bool,
) -> String {
    let mut edition = edition.unwrap_or("Windows (unknown edition)").to_owned();
    if build.is_some_and(|b| b >= 22_000) {
        edition = edition.replacen("Windows 10", "Windows 11", 1);
    }
    let mut parts = vec![edition];
    if let Some(v) = version {
        parts.push(format!("version {v}"));
    }
    if let Some(b) = build {
        parts.push(format!("build {b}"));
    }
    parts.push(match (processor, x64_on_arm) {
        (_, true) => "ARM processor, running the x64 build".to_owned(),
        (Some(p), false) => format!("processor {p}"),
        (None, false) => "processor unknown".to_owned(),
    });
    parts.join(", ")
}

#[cfg(test)]
mod tests;
