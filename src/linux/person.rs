//! The settings that belong to the signed-in person: desktop settings read and changed with `gsettings`, and the Ubuntu
//! Insights consent files. They run in the app's own process, as the person, and are recorded in a journal in the
//! person's own state folder.
//!
//! A desktop setting that is unsafe by default (recent files, notification text on the lock screen) is stored as 2 when
//! nothing was ever set and as 1 when the person set it, so undo can reset the key instead of writing a value.

use super::catalog::{self, Scope};
use super::cmd::Sys;
use super::distro::{Desktop, Distro};
use crate::model::{Backend, Control, Finding, Observation};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::path::PathBuf;

const GSETTINGS: &str = "/usr/bin/gsettings";
const DCONF: &str = "/usr/bin/dconf";
const GETENT: &str = "/usr/bin/getent";
const STAT: &str = "/usr/bin/stat";
const CHMOD: &str = "/usr/bin/chmod";
const NO_IDENTITY: &str =
    "Secblitz could not identify this computer, so it will not change anything.";
pub const UNAVAILABLE: &str = "This setting is not available on your desktop yet.";
const NOT_CONFIRMED: &str = "Secblitz could not confirm that the setting changed.";
const RECENT_AGE_KEY: &str = "recent-files-max-age";
const RECENT_REMEMBER_KEY: &str = "remember-recent-files";
const HOME_CONTROL: &str = "linux.home_private";
const INSIGHTS_SOURCES: [&str; 3] = ["linux", "desktop_provision", "release_upgrader"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A switch where on is safe: 0 off, 1 on because the person set it, 2 on by default.
    Lock,
    /// A switch where on is unsafe and is the default: 0 off, 1 on because the person set it, 2 on by default.
    OnByDefault,
    /// A switch with no default that matters: 0 off, 1 on.
    Plain,
    /// The idle delay: 1 when it is 0 (never), otherwise 0.
    Idle,
    /// A switch where on is safe and off is the default: 0 off because the person set it, 1 on, 2 off by default.
    OffByDefault,
    /// Recent files kept with no age limit: 0 not forever, 1 forever because the person set it, 2 forever by default.
    Age,
}

struct Gs {
    name: &'static str,
    schema: &'static str,
    key: &'static str,
    shape: Shape,
}

const fn gs(name: &'static str, schema: &'static str, key: &'static str, shape: Shape) -> Gs {
    Gs {
        name,
        schema,
        key,
        shape,
    }
}

const GNOME_LOCK: &[Gs] = &[
    gs(
        "lock_enabled",
        "org.gnome.desktop.screensaver",
        "lock-enabled",
        Shape::Lock,
    ),
    gs(
        "idle_never",
        "org.gnome.desktop.session",
        "idle-delay",
        Shape::Idle,
    ),
];
const CINNAMON_LOCK: &[Gs] = &[
    gs(
        "lock_enabled",
        "org.cinnamon.desktop.screensaver",
        "lock-enabled",
        Shape::Lock,
    ),
    gs(
        "idle_never",
        "org.cinnamon.desktop.session",
        "idle-delay",
        Shape::Idle,
    ),
];
const GNOME_REMOTE: &[Gs] = &[
    gs(
        "rdp",
        "org.gnome.desktop.remote-desktop.rdp",
        "enable",
        Shape::Plain,
    ),
    gs(
        "vnc",
        "org.gnome.desktop.remote-desktop.vnc",
        "enable",
        Shape::Plain,
    ),
];
const GNOME_RECENT: &[Gs] = &[gs(
    "keep_forever",
    "org.gnome.desktop.privacy",
    RECENT_AGE_KEY,
    Shape::Age,
)];
const CINNAMON_RECENT: &[Gs] = &[gs(
    "keep_forever",
    "org.cinnamon.desktop.privacy",
    RECENT_AGE_KEY,
    Shape::Age,
)];
const GNOME_PREVIEWS: &[Gs] = &[gs(
    "show_on_lock",
    "org.gnome.desktop.notifications",
    "show-in-lock-screen",
    Shape::OnByDefault,
)];

const GNOME_AUTORUN: &[Gs] = &[gs(
    "never",
    "org.gnome.desktop.media-handling",
    "autorun-never",
    Shape::OffByDefault,
)];
const CINNAMON_AUTORUN: &[Gs] = &[gs(
    "never",
    "org.cinnamon.desktop.media-handling",
    "autorun-never",
    Shape::OffByDefault,
)];
const GNOME_LOCATION: &[Gs] = &[gs(
    "enabled",
    "org.gnome.system.location",
    "enabled",
    Shape::Plain,
)];
const GNOME_PROBLEMS: &[Gs] = &[
    gs(
        "report_problems",
        "org.gnome.desktop.privacy",
        "report-technical-problems",
        Shape::Plain,
    ),
    gs(
        "send_usage_stats",
        "org.gnome.desktop.privacy",
        "send-software-usage-stats",
        Shape::Plain,
    ),
];
const GNOME_APP_USAGE: &[Gs] = &[gs(
    "remember_usage",
    "org.gnome.desktop.privacy",
    "remember-app-usage",
    Shape::OnByDefault,
)];
const GNOME_OLD_FILES: &[Gs] = &[
    gs(
        "trash",
        "org.gnome.desktop.privacy",
        "remove-old-trash-files",
        Shape::OffByDefault,
    ),
    gs(
        "temp",
        "org.gnome.desktop.privacy",
        "remove-old-temp-files",
        Shape::OffByDefault,
    ),
];
const CINNAMON_OLD_FILES: &[Gs] = &[
    gs(
        "trash",
        "org.cinnamon.desktop.privacy",
        "remove-old-trash-files",
        Shape::OffByDefault,
    ),
    gs(
        "temp",
        "org.cinnamon.desktop.privacy",
        "remove-old-temp-files",
        Shape::OffByDefault,
    ),
];
const CINNAMON_PREVIEWS: &[Gs] = &[gs(
    "show_on_lock",
    "org.cinnamon.desktop.screensaver",
    "show-notifications",
    Shape::OnByDefault,
)];

const MINT_UPDATES: &[Gs] = &[
    gs(
        "flatpaks",
        "com.linuxmint.updates",
        "auto-update-flatpaks",
        Shape::OffByDefault,
    ),
    gs(
        "spices",
        "com.linuxmint.updates",
        "auto-update-cinnamon-spices",
        Shape::OffByDefault,
    ),
];
const GNOME_SOFTWARE: &[Gs] = &[gs(
    "download",
    "org.gnome.software",
    "download-updates",
    Shape::Lock,
)];
/// Controls whose settings belong to an app that may not be installed: they are offered only where its schema exists.
const APP_CONTROLS: [&str; 2] = ["linux.mint_app_updates", "linux.app_store_updates"];

/// The desktop settings behind a control on this desktop; empty when the control has none here.
fn desktop_keys(id: &str, desktop: Desktop) -> &'static [Gs] {
    match (id, desktop) {
        ("linux.mint_app_updates", _) => MINT_UPDATES,
        ("linux.app_store_updates", _) => GNOME_SOFTWARE,
        ("linux.screen_lock", Desktop::Gnome) => GNOME_LOCK,
        ("linux.screen_lock", Desktop::Cinnamon) => CINNAMON_LOCK,
        ("linux.remote_desktop", Desktop::Gnome) => GNOME_REMOTE,
        ("linux.recent_files", Desktop::Gnome) => GNOME_RECENT,
        ("linux.recent_files", Desktop::Cinnamon) => CINNAMON_RECENT,
        ("linux.lock_previews", Desktop::Gnome) => GNOME_PREVIEWS,
        ("linux.lock_previews", Desktop::Cinnamon) => CINNAMON_PREVIEWS,
        ("linux.media_autorun", Desktop::Gnome) => GNOME_AUTORUN,
        ("linux.media_autorun", Desktop::Cinnamon) => CINNAMON_AUTORUN,
        ("linux.location", Desktop::Gnome) => GNOME_LOCATION,
        ("linux.problem_reports", Desktop::Gnome) => GNOME_PROBLEMS,
        ("linux.app_usage", Desktop::Gnome) => GNOME_APP_USAGE,
        ("linux.old_files", Desktop::Gnome) => GNOME_OLD_FILES,
        ("linux.old_files", Desktop::Cinnamon) => CINNAMON_OLD_FILES,
        _ => &[],
    }
}

fn consent_path(config: &std::path::Path, source: &str) -> PathBuf {
    config
        .join("ubuntu-insights")
        .join(format!("{source}-consent.toml"))
}

/// Where a `consent_state = ...` line sits in a consent file and what it says.
fn consent_line(text: &str) -> Option<(usize, std::ops::Range<usize>, bool)> {
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        if let Some((left, right)) = body.split_once('=') {
            if left.trim() == "consent_state" {
                let word = right.trim();
                let on = match word {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                };
                let at = start + left.len() + 1 + right.find(word)?;
                return Some((start, at..at + word.len(), on));
            }
        }
        start += line.len();
    }
    None
}

struct Reading {
    value: Option<u32>,
    /// False when the setting could not be read, or could not be told apart from its default.
    sure: bool,
}

impl Reading {
    fn of(value: u32) -> Self {
        Self {
            value: Some(value),
            sure: true,
        }
    }

    fn missing() -> Self {
        Self {
            value: None,
            sure: false,
        }
    }
}

pub struct PersonBackend<S: Sys> {
    sys: S,
    config_dir: PathBuf,
    desktop: Desktop,
    uid: u32,
    controls: Vec<Control>,
}

impl<S: Sys> PersonBackend<S> {
    /// `config_dir` is the person's configuration folder (`~/.config`). With `session_bus` false, no desktop setting is
    /// offered: `gsettings` without the person's bus would change a throwaway copy instead of their settings. `uid` is
    /// the person's own account number, which names their home folder.
    pub fn new(sys: S, distro: &Distro, config_dir: PathBuf, session_bus: bool, uid: u32) -> Self {
        let controls = catalog::specs()
            .iter()
            .filter(|s| s.scope == Scope::Person)
            .filter(|s| {
                if s.id == "linux.ubuntu_insights" {
                    distro.id == "ubuntu"
                } else if s.id == HOME_CONTROL {
                    true
                } else {
                    let keys = desktop_keys(s.id, distro.desktop);
                    session_bus
                        && !keys.is_empty()
                        && (!APP_CONTROLS.contains(&s.id)
                            || keys.iter().all(|g| {
                                sys.run(GSETTINGS, &["get", g.schema, g.key])
                                    .is_ok_and(|out| out.success())
                            }))
                }
            })
            .map(|s| Control {
                id: s.id.into(),
                title: s.id.into(),
                description: "Changed in the signed-in person's own session.".into(),
                target: s.catalog_target(),
                reboot: s.reboot,
            })
            .collect();
        Self {
            sys,
            config_dir,
            desktop: distro.desktop,
            uid,
            controls,
        }
    }

    fn get(&self, schema: &str, key: &str) -> Option<String> {
        let out = self.sys.run(GSETTINGS, &["get", schema, key]).ok()?;
        out.success().then(|| out.stdout.trim().to_owned())
    }

    /// Whether the person's own settings hold a value for the key. `None` when `dconf` is not installed.
    fn user_set(&self, schema: &str, key: &str) -> Option<bool> {
        let path = format!("/{}/{key}", schema.replace('.', "/"));
        let out = self.sys.run(DCONF, &["read", &path]).ok()?;
        out.success().then(|| !out.stdout.trim().is_empty())
    }

    fn flag(&self, schema: &str, key: &str) -> Option<bool> {
        match self.get(schema, key)?.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }

    fn read_desktop(&self, g: &Gs) -> Reading {
        let on = |set: Option<bool>, default_unsafe: bool| match (set, default_unsafe) {
            (Some(true), _) => Reading::of(1),
            (Some(false), _) => Reading::of(2),
            (None, false) => Reading::of(1),
            (None, true) => Reading {
                value: Some(1),
                sure: false,
            },
        };
        match g.shape {
            Shape::OffByDefault => match self.flag(g.schema, g.key) {
                Some(true) => Reading::of(1),
                Some(false) => match self.user_set(g.schema, g.key) {
                    Some(true) => Reading::of(0),
                    Some(false) => Reading::of(2),
                    None => Reading {
                        value: Some(0),
                        sure: false,
                    },
                },
                None => Reading::missing(),
            },
            Shape::Plain => self
                .flag(g.schema, g.key)
                .map_or_else(Reading::missing, |b| Reading::of(u32::from(b))),
            Shape::Idle => match self.get(g.schema, g.key) {
                Some(text) => {
                    let number = text.trim_start_matches("uint32").trim().parse::<u32>();
                    number.map_or_else(|_| Reading::missing(), |n| Reading::of(u32::from(n == 0)))
                }
                None => Reading::missing(),
            },
            Shape::Lock | Shape::OnByDefault => match self.flag(g.schema, g.key) {
                Some(false) => Reading::of(0),
                Some(true) => on(
                    self.user_set(g.schema, g.key),
                    g.shape == Shape::OnByDefault,
                ),
                None => Reading::missing(),
            },
            Shape::Age => {
                let (Some(remember), Some(age)) = (
                    self.flag(g.schema, RECENT_REMEMBER_KEY),
                    self.get(g.schema, g.key),
                ) else {
                    return Reading::missing();
                };
                match age.parse::<i64>() {
                    Ok(-1) if remember => on(self.user_set(g.schema, g.key), true),
                    Ok(_) => Reading::of(0),
                    Err(_) => Reading::missing(),
                }
            }
        }
    }

    fn read_consent(&self, source: &str) -> Reading {
        match self.sys.read(&consent_path(&self.config_dir, source)) {
            Ok(None) => Reading {
                value: None,
                sure: true,
            },
            Ok(Some(bytes)) => {
                let text = String::from_utf8_lossy(&bytes);
                consent_line(&text).map_or_else(
                    || Reading {
                        value: None,
                        sure: true,
                    },
                    |(_, _, on)| Reading::of(u32::from(on)),
                )
            }
            Err(_) => Reading::missing(),
        }
    }

    /// The person's home folder and which of its "everyone else" permission bits are set. `None` unless the account
    /// database names an absolute path that is a real folder owned by this person.
    fn read_home(&self) -> Option<(String, u32)> {
        let uid = self.uid.to_string();
        let out = self.sys.run(GETENT, &["passwd", &uid]).ok()?;
        if !out.success() {
            return None;
        }
        let line = out.stdout.lines().next()?;
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 || fields[2] != uid {
            return None;
        }
        let home = fields[5];
        if !home.starts_with('/') || home == "/" || home.chars().any(char::is_control) {
            return None;
        }
        let out = self.sys.run(STAT, &["-c", "%a %u %F", "--", home]).ok()?;
        if !out.success() {
            return None;
        }
        let mut parts = out.stdout.trim().splitn(3, ' ');
        let mode = u32::from_str_radix(parts.next()?, 8).ok()?;
        let owner = parts.next()?;
        let kind = parts.next()?;
        (owner == uid && kind == "directory").then(|| (home.to_owned(), mode & 0o7))
    }

    fn write_home(&self, others: u32) -> Result<()> {
        ensure!(others <= 7, "{NOT_CONFIRMED}");
        let (home, _) = self.read_home().context(UNAVAILABLE)?;
        let mut mode = String::from("o=");
        for (bit, letter) in [(4, 'r'), (2, 'w'), (1, 'x')] {
            if others & bit != 0 {
                mode.push(letter);
            }
        }
        let out = self.sys.run(CHMOD, &["--", &mode, &home])?;
        ensure!(out.success(), "{NOT_CONFIRMED}");
        Ok(())
    }

    fn read_all(&self, id: &str) -> Vec<(&'static str, Reading)> {
        if id == HOME_CONTROL {
            return vec![(
                "others",
                self.read_home()
                    .map_or_else(Reading::missing, |(_, others)| Reading::of(others)),
            )];
        }
        if id == "linux.ubuntu_insights" {
            return INSIGHTS_SOURCES
                .iter()
                .map(|s| (*s, self.read_consent(s)))
                .collect();
        }
        desktop_keys(id, self.desktop)
            .iter()
            .map(|g| (g.name, self.read_desktop(g)))
            .collect()
    }

    fn set(&self, schema: &str, key: &str, value: &str) -> Result<()> {
        let out = self.sys.run(GSETTINGS, &["set", schema, key, value])?;
        ensure!(out.success(), "{NOT_CONFIRMED}");
        Ok(())
    }

    fn reset(&self, schema: &str, key: &str) -> Result<()> {
        let out = self.sys.run(GSETTINGS, &["reset", schema, key])?;
        ensure!(out.success(), "{NOT_CONFIRMED}");
        Ok(())
    }

    fn write_desktop(&self, g: &Gs, want: u32) -> Result<()> {
        let word = |on: bool| if on { "true" } else { "false" };
        match (g.shape, want) {
            (Shape::Plain, 0 | 1) => self.set(g.schema, g.key, word(want == 1)),
            (Shape::Lock | Shape::OnByDefault | Shape::OffByDefault, 0 | 1) => {
                self.set(g.schema, g.key, word(want == 1))
            }
            (Shape::Lock | Shape::OnByDefault | Shape::OffByDefault | Shape::Age, 2) => {
                self.reset(g.schema, g.key)
            }
            (Shape::Idle, 0) => self.set(g.schema, g.key, "300"),
            (Shape::Idle, 1) => self.set(g.schema, g.key, "0"),
            (Shape::Age, 0) => self.set(g.schema, g.key, "30"),
            (Shape::Age, 1) => self.set(g.schema, g.key, "-1"),
            _ => bail!("{NOT_CONFIRMED}"),
        }
    }

    fn write_consent(&self, source: &str, on: bool) -> Result<()> {
        let path = consent_path(&self.config_dir, source);
        let bytes = self.sys.read(&path)?.context(NOT_CONFIRMED)?;
        let text = String::from_utf8(bytes).context(NOT_CONFIRMED)?;
        let (_, word, _) = consent_line(&text).context(NOT_CONFIRMED)?;
        let mut edited = text.clone();
        edited.replace_range(word, if on { "true" } else { "false" });
        self.sys.write_atomic(&path, edited.as_bytes(), 0o600)
    }
}

fn items_of(value: &Value) -> Result<&Map<String, Value>> {
    value
        .get("items")
        .and_then(Value::as_object)
        .context("The setting has no items")
}

impl<S: Sys> Backend for PersonBackend<S> {
    fn machine_id(&mut self) -> Result<String> {
        let bytes = self
            .sys
            .read(std::path::Path::new("/etc/machine-id"))?
            .context(NO_IDENTITY)?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
    }

    fn controls(&self) -> Vec<Control> {
        self.controls.clone()
    }

    fn observe(&mut self, id: &str) -> Result<Observation> {
        ensure!(
            self.controls.iter().any(|c| c.id == id),
            "Unknown control id: {id}"
        );
        let mut items = Map::new();
        let mut sure = true;
        for (name, reading) in self.read_all(id) {
            sure &= reading.sure;
            items.insert(name.into(), reading.value.map_or(Value::Null, Value::from));
        }
        if !sure {
            eprintln!("A desktop setting for {id} could not be read exactly.");
        }
        Ok(Observation {
            value: json!({ "items": items }),
            eligible: sure,
            reason: if sure {
                String::new()
            } else {
                UNAVAILABLE.into()
            },
            ..Observation::default()
        })
    }

    fn write(&mut self, id: &str, value: &Value) -> Result<()> {
        ensure!(
            self.controls.iter().any(|c| c.id == id),
            "Unknown control id: {id}"
        );
        catalog::spec(id)
            .context("Unknown control id")?
            .validate(value)?;
        let wanted = items_of(value)?;
        let current = self.read_all(id);
        for (name, reading) in &current {
            let want = wanted
                .get(*name)
                .context("The setting is missing an item")?;
            if want.as_u64().map(|n| n as u32) == reading.value {
                continue;
            }
            ensure!(reading.sure, "{UNAVAILABLE}");
            let want = want.as_u64().context(NOT_CONFIRMED)? as u32;
            if id == HOME_CONTROL {
                self.write_home(want)?;
            } else if id == "linux.ubuntu_insights" {
                self.write_consent(name, want == 1)?;
            } else {
                let g = desktop_keys(id, self.desktop)
                    .iter()
                    .find(|g| g.name == *name)
                    .context(NOT_CONFIRMED)?;
                self.write_desktop(g, want)?;
            }
        }
        for (name, reading) in self.read_all(id) {
            let want = wanted.get(name).and_then(Value::as_u64).map(|n| n as u32);
            ensure!(want == reading.value && reading.sure, "{NOT_CONFIRMED}");
        }
        Ok(())
    }

    fn findings(&mut self) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }
}

/// The journal folder for one person: `$XDG_STATE_HOME/secblitz`, else `~/.local/state/secblitz`. A relative
/// setting is not trusted.
pub fn state_dir_in(home: &std::path::Path, xdg_state_home: Option<&std::path::Path>) -> PathBuf {
    match xdg_state_home.filter(|p| p.is_absolute()) {
        Some(base) => base.join("secblitz"),
        None => home.join(".local/state/secblitz"),
    }
}

/// The configuration folder: `$XDG_CONFIG_HOME`, else `~/.config`.
pub fn config_dir_in(home: &std::path::Path, xdg_config_home: Option<&std::path::Path>) -> PathBuf {
    match xdg_config_home.filter(|p| p.is_absolute()) {
        Some(base) => base.to_owned(),
        None => home.join(".config"),
    }
}

/// The bus address to give `gsettings`: the person's own socket, found from their environment only when it is exactly
/// the usual one or when that socket exists.
pub fn session_bus(
    uid: u32,
    environment: Option<&str>,
    socket_exists: impl Fn(&std::path::Path) -> bool,
) -> Option<String> {
    let usual = super::cmd::session_bus_address(uid);
    let socket = PathBuf::from(format!("/run/user/{uid}/bus"));
    (environment == Some(usual.as_str()) || socket_exists(&socket)).then_some(usual)
}

#[cfg(target_os = "linux")]
mod session {
    use super::*;
    use crate::engine::Engine;
    use crate::linux::cmd::SessionSys;
    use crate::linux::distro;
    use crate::platform::unix::check_private_dir;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::Path;

    const SESSION_UNUSUAL: &str = "Secblitz cannot start because this sign-in session is not set up the usual way. Sign out, sign back in, then open Secblitz again.";
    const FOLDER_UNTRUSTED: &str =
        "Secblitz cannot trust its folder in your home, so it will not change your settings.";

    fn uid() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    fn env_path(name: &str) -> Option<PathBuf> {
        std::env::var_os(name).map(PathBuf::from)
    }

    fn state_dir(home: &Path) -> Result<PathBuf> {
        let dir = state_dir_in(home, env_path("XDG_STATE_HOME").as_deref());
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .context(FOLDER_UNTRUSTED)?;
        check_private_dir(&dir, uid()).context(FOLDER_UNTRUSTED)?;
        Ok(dir)
    }

    fn parts() -> Result<(PathBuf, Box<dyn Backend>)> {
        let home = env_path("HOME").filter(|h| h.is_absolute());
        let home = home.context(SESSION_UNUSUAL)?;
        let uid = uid();
        let bus_env = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        let bus = session_bus(uid, bus_env.as_deref(), |p| p.exists());
        if bus.is_none() {
            eprintln!("No desktop session bus was found, so no desktop settings are offered.");
        }
        let sys = SessionSys::new(
            &bus.clone()
                .unwrap_or_else(|| crate::linux::cmd::session_bus_address(uid)),
            uid,
        )?;
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").ok();
        let distro = distro::detect(&sys, desktop.as_deref());
        let config = config_dir_in(&home, env_path("XDG_CONFIG_HOME").as_deref());
        let backend = PersonBackend::new(sys, &distro, config, bus.is_some(), uid);
        Ok((state_dir(&home)?, Box::new(backend)))
    }

    /// The engine for this person's settings, on their own journal.
    /// The person's private Secblitz folder, created and checked like the one their undo history uses.
    pub fn own_state_dir() -> Result<PathBuf> {
        let home = env_path("HOME").filter(|h| h.is_absolute());
        state_dir(&home.context(SESSION_UNUSUAL)?)
    }

    pub fn open_engine() -> Result<Engine> {
        let (dir, backend) = parts()?;
        Engine::open(dir, backend)
    }

    /// Moves a damaged personal history aside. Fails with `NotDamaged` when there is nothing to move.
    pub fn start_fresh() -> Result<()> {
        let (dir, backend) = parts()?;
        crate::engine::recover::start_fresh(&dir, backend).map(drop)
    }
}

#[cfg(target_os = "linux")]
pub use session::{open_engine, own_state_dir, start_fresh};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::linux::cmd::Output;
    use crate::linux::distro::Family;
    use crate::os::Os;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::rc::Rc;

    /// A desktop that keeps its settings the way dconf does: a default for every key and the values the person set.
    struct Desk {
        defaults: BTreeMap<(String, String), String>,
        set: RefCell<BTreeMap<(String, String), String>>,
        files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        dconf: bool,
        calls: RefCell<Vec<String>>,
        home: RefCell<String>,
        home_mode: Cell<u32>,
        home_owner: Cell<u32>,
        home_kind: RefCell<&'static str>,
    }

    const UBUNTU_PERSON: &str =
        include_str!("../../tests/fixtures/linux/ubuntu-26.04/gsettings-person.txt");
    const FEDORA_PERSON: &str =
        include_str!("../../tests/fixtures/linux/fedora-44/gsettings-person.txt");
    const MINT_PERSON: &str =
        include_str!("../../tests/fixtures/linux/mint-22.3/gsettings-person.txt");
    const UBUNTU_HOME: &str = include_str!("../../tests/fixtures/linux/ubuntu-26.04/home-mode.txt");
    const FEDORA_HOME: &str = include_str!("../../tests/fixtures/linux/fedora-44/home-mode.txt");
    const MINT_HOME: &str = include_str!("../../tests/fixtures/linux/mint-22.3/home-mode.txt");
    const UID: u32 = 1000;

    fn key(schema: &str, key: &str) -> (String, String) {
        (schema.into(), key.into())
    }

    impl Desk {
        /// The real GNOME defaults on Ubuntu 26.04.
        fn stock() -> Self {
            let defaults = [
                ("org.gnome.desktop.screensaver", "lock-enabled", "true"),
                ("org.gnome.desktop.session", "idle-delay", "uint32 300"),
                ("org.gnome.desktop.remote-desktop.rdp", "enable", "false"),
                ("org.gnome.desktop.remote-desktop.vnc", "enable", "false"),
                ("org.gnome.desktop.privacy", RECENT_REMEMBER_KEY, "true"),
                ("org.gnome.desktop.privacy", RECENT_AGE_KEY, "-1"),
                (
                    "org.gnome.desktop.notifications",
                    "show-in-lock-screen",
                    "true",
                ),
            ]
            .into_iter()
            .map(|(s, k, v)| (key(s, k), v.to_owned()))
            .collect();
            let mut desk = Self {
                defaults,
                set: RefCell::default(),
                files: RefCell::default(),
                dconf: true,
                calls: RefCell::default(),
                home: RefCell::new("/home/tester".into()),
                home_mode: Cell::new(0o750),
                home_owner: Cell::new(UID),
                home_kind: RefCell::new("directory"),
            };
            desk.record(UBUNTU_PERSON);
            desk.set_home(UBUNTU_HOME);
            desk.files
                .borrow_mut()
                .insert("/etc/machine-id".into(), b"0123456789abcdef\n".to_vec());
            for source in INSIGHTS_SOURCES {
                desk.files.borrow_mut().insert(
                    consent_path(Path::new("/home/p/.config"), source),
                    b"consent_state = false\n".to_vec(),
                );
            }
            desk
        }

        /// Adds the defaults of a recorded `gsettings list-recursively` listing.
        fn record(&mut self, listing: &str) {
            for line in listing.lines() {
                let mut parts = line.splitn(3, ' ');
                let (schema, k, v) = (
                    parts.next().unwrap(),
                    parts.next().unwrap(),
                    parts.next().unwrap(),
                );
                self.defaults.insert(key(schema, k), v.to_owned());
            }
        }

        fn fedora() -> Self {
            let mut desk = Self::stock();
            desk.record(FEDORA_PERSON);
            desk.set_home(FEDORA_HOME);
            desk
        }

        fn mint() -> Self {
            let mut desk = Self::stock();
            desk.record(MINT_PERSON);
            desk.set_home(MINT_HOME);
            desk
        }

        fn set_home(&self, recorded: &str) {
            let mut fields = recorded.split_whitespace();
            self.home_mode
                .set(u32::from_str_radix(fields.next().unwrap(), 8).unwrap());
            *self.home.borrow_mut() = fields.nth(1).unwrap().to_owned();
        }

        fn current(&self, schema: &str, k: &str) -> Option<String> {
            let id = key(schema, k);
            self.set
                .borrow()
                .get(&id)
                .or_else(|| self.defaults.get(&id))
                .cloned()
        }

        fn put(&self, schema: &str, k: &str, v: &str) {
            self.set.borrow_mut().insert(key(schema, k), v.into());
        }

        fn file(&self, source: &str) -> String {
            let path = consent_path(Path::new("/home/p/.config"), source);
            String::from_utf8(self.files.borrow()[&path].clone()).unwrap()
        }
    }

    fn out(status: i32, stdout: &str) -> Result<Output> {
        Ok(Output {
            status,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    impl Sys for Rc<Desk> {
        fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
            self.calls
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            match (program, args) {
                (GSETTINGS, ["get", s, k]) => match self.current(s, k) {
                    Some(v) => out(0, &format!("{v}\n")),
                    None => out(1, ""),
                },
                (GSETTINGS, ["set", s, k, v]) => {
                    if !self.defaults.contains_key(&key(s, k)) {
                        return out(1, "");
                    }
                    let stored = if self.defaults[&key(s, k)].starts_with("uint32") {
                        format!("uint32 {v}")
                    } else {
                        (*v).to_owned()
                    };
                    self.put(s, k, &stored);
                    out(0, "")
                }
                (GSETTINGS, ["reset", s, k]) => {
                    self.set.borrow_mut().remove(&key(s, k));
                    out(0, "")
                }
                (GETENT, ["passwd", uid]) if *uid == UID.to_string() => out(
                    0,
                    &format!(
                        "tester:x:{UID}:{UID}:Tester,,,:{}:/bin/bash\n",
                        self.home.borrow()
                    ),
                ),
                (STAT, ["-c", "%a %u %F", "--", path]) if *path == self.home.borrow().as_str() => {
                    out(
                        0,
                        &format!(
                            "{:o} {} {}\n",
                            self.home_mode.get(),
                            self.home_owner.get(),
                            self.home_kind.borrow()
                        ),
                    )
                }
                (CHMOD, ["--", mode, path]) if *path == self.home.borrow().as_str() => {
                    let bits = mode
                        .strip_prefix("o=")
                        .expect("only the others bits change");
                    let others = bits.chars().fold(0, |n, c| {
                        n | match c {
                            'r' => 4,
                            'w' => 2,
                            'x' => 1,
                            _ => panic!("bad mode {mode}"),
                        }
                    });
                    self.home_mode.set(self.home_mode.get() & !0o7 | others);
                    out(0, "")
                }
                (DCONF, ["read", path]) if self.dconf => {
                    let (schema, k) = path.rsplit_once('/').unwrap();
                    let schema = schema.trim_start_matches('/').replace('/', ".");
                    let shown = self.set.borrow().get(&key(&schema, k)).cloned();
                    out(0, &shown.map(|v| format!("{v}\n")).unwrap_or_default())
                }
                _ => anyhow::bail!("Unexpected program: {program} {args:?}"),
            }
        }

        fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
            Ok(self.files.borrow().get(path).cloned())
        }

        fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
            assert_eq!(mode, 0o600);
            self.files.borrow_mut().insert(path.into(), bytes.to_vec());
            Ok(())
        }

        fn remove(&self, path: &Path) -> Result<()> {
            self.files.borrow_mut().remove(path);
            Ok(())
        }
    }

    fn distro(id: &str, desktop: Desktop) -> Distro {
        Distro {
            family: Family::Debian,
            id: id.into(),
            version: "26.04".into(),
            desktop,
        }
    }

    fn backend(desk: &Rc<Desk>, id: &str, desktop: Desktop, bus: bool) -> PersonBackend<Rc<Desk>> {
        PersonBackend::new(
            Rc::clone(desk),
            &distro(id, desktop),
            "/home/p/.config".into(),
            bus,
            UID,
        )
    }

    fn engine(desk: &Rc<Desk>, dir: &Path) -> Engine {
        let b = backend(desk, "ubuntu", Desktop::Gnome, true);
        Engine::open_for(Os::Linux, dir.to_owned(), Box::new(b)).unwrap()
    }

    fn ids(b: &PersonBackend<Rc<Desk>>) -> Vec<String> {
        b.controls().into_iter().map(|c| c.id).collect()
    }

    fn items(b: &mut PersonBackend<Rc<Desk>>, id: &str) -> Value {
        let o = b.observe(id).unwrap();
        assert!(o.eligible, "{id}: {}", o.reason);
        o.value["items"].clone()
    }

    #[test]
    fn a_stock_gnome_desktop_reads_as_the_defaults() {
        let desk = Rc::new(Desk::stock());
        let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
        assert_eq!(
            ids(&b),
            [
                "linux.screen_lock",
                "linux.remote_desktop",
                "linux.recent_files",
                "linux.lock_previews",
                "linux.ubuntu_insights",
                "linux.media_autorun",
                "linux.location",
                "linux.problem_reports",
                "linux.app_usage",
                "linux.old_files",
                "linux.home_private"
            ]
        );
        assert_eq!(
            items(&mut b, "linux.screen_lock"),
            json!({"lock_enabled": 2, "idle_never": 0})
        );
        assert_eq!(
            items(&mut b, "linux.remote_desktop"),
            json!({"rdp": 0, "vnc": 0})
        );
        assert_eq!(
            items(&mut b, "linux.recent_files"),
            json!({"keep_forever": 2})
        );
        assert_eq!(
            items(&mut b, "linux.lock_previews"),
            json!({"show_on_lock": 2})
        );
        assert_eq!(
            items(&mut b, "linux.ubuntu_insights"),
            json!({"linux": 0, "desktop_provision": 0, "release_upgrader": 0})
        );
        assert_eq!(items(&mut b, "linux.media_autorun"), json!({"never": 1}));
        assert_eq!(items(&mut b, "linux.location"), json!({"enabled": 0}));
        assert_eq!(
            items(&mut b, "linux.problem_reports"),
            json!({"report_problems": 0, "send_usage_stats": 0})
        );
        assert_eq!(
            items(&mut b, "linux.app_usage"),
            json!({"remember_usage": 2})
        );
        assert_eq!(
            items(&mut b, "linux.old_files"),
            json!({"trash": 2, "temp": 2})
        );
        assert_eq!(items(&mut b, "linux.home_private"), json!({"others": 0}));
        assert_eq!(b.machine_id().unwrap(), "0123456789abcdef");
    }

    #[test]
    fn controls_follow_the_desktop_the_distribution_and_the_session_bus() {
        let desk = Rc::new(Desk::stock());
        assert_eq!(
            ids(&backend(&desk, "linuxmint", Desktop::Cinnamon, true)),
            [
                "linux.screen_lock",
                "linux.recent_files",
                "linux.lock_previews",
                "linux.media_autorun",
                "linux.old_files",
                "linux.home_private"
            ]
        );
        assert_eq!(
            ids(&backend(&desk, "fedora", Desktop::Gnome, true)),
            [
                "linux.screen_lock",
                "linux.remote_desktop",
                "linux.recent_files",
                "linux.lock_previews",
                "linux.media_autorun",
                "linux.location",
                "linux.problem_reports",
                "linux.app_usage",
                "linux.old_files",
                "linux.home_private"
            ]
        );
        assert_eq!(
            ids(&backend(&desk, "debian", Desktop::Other, true)),
            ["linux.home_private"]
        );
        assert_eq!(
            ids(&backend(&desk, "ubuntu", Desktop::Gnome, false)),
            ["linux.ubuntu_insights", "linux.home_private"]
        );
        for b in [
            backend(&desk, "ubuntu", Desktop::Gnome, true),
            backend(&desk, "linuxmint", Desktop::Cinnamon, true),
        ] {
            for c in b.controls() {
                assert_eq!(c.target, catalog::spec(&c.id).unwrap().catalog_target());
            }
        }
    }

    #[test]
    fn every_unsafe_setting_is_fixed_and_undone_exactly() {
        let desk = Rc::new(Desk::stock());
        desk.put("org.gnome.desktop.screensaver", "lock-enabled", "false");
        desk.put("org.gnome.desktop.session", "idle-delay", "uint32 0");
        desk.put("org.gnome.desktop.remote-desktop.rdp", "enable", "true");
        desk.put(
            "org.gnome.desktop.notifications",
            "show-in-lock-screen",
            "true",
        );
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        let before_set = desk.set.borrow().clone();
        let before_files = desk.files.borrow().clone();

        let report = e.audit_with_progress(|_| {}).unwrap();
        let flagged: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.status.as_str() == "attention")
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            flagged,
            [
                "linux.screen_lock",
                "linux.remote_desktop",
                "linux.recent_files",
                "linux.lock_previews",
                "linux.app_usage",
                "linux.old_files"
            ]
        );
        assert_eq!(
            desk.set.borrow().clone(),
            before_set,
            "checking changed something"
        );

        let all: Vec<String> = flagged.iter().map(|s| s.to_string()).collect();
        let applied = e.apply_selected(&all, |_| {}).unwrap();
        assert!(applied
            .results
            .iter()
            .all(|r| r.status.as_str() == "applied"));
        let now = |s: &str, k: &str| desk.current(s, k).unwrap();
        assert_eq!(now("org.gnome.desktop.screensaver", "lock-enabled"), "true");
        assert_eq!(now("org.gnome.desktop.session", "idle-delay"), "uint32 300");
        assert_eq!(
            now("org.gnome.desktop.remote-desktop.rdp", "enable"),
            "false"
        );
        assert_eq!(now("org.gnome.desktop.privacy", RECENT_AGE_KEY), "30");
        assert_eq!(
            now("org.gnome.desktop.notifications", "show-in-lock-screen"),
            "false"
        );

        e.revert(|_| {}).unwrap();
        assert_eq!(desk.set.borrow().clone(), before_set, "undo left a trace");
        assert_eq!(desk.files.borrow().clone(), before_files);
        let again = e.audit_with_progress(|_| {}).unwrap();
        assert_eq!(
            again
                .results
                .iter()
                .filter(|r| r.status.as_str() == "attention")
                .count(),
            6
        );
    }

    #[test]
    fn a_setting_that_was_at_its_default_is_reset_not_written_back() {
        let desk = Rc::new(Desk::stock());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        e.apply_selected(
            &[
                "linux.recent_files".into(),
                "linux.lock_previews".into(),
                "linux.app_usage".into(),
                "linux.old_files".into(),
            ],
            |_| {},
        )
        .unwrap();
        desk.calls.borrow_mut().clear();
        e.revert(|_| {}).unwrap();
        assert!(desk.set.borrow().is_empty(), "{:?}", desk.set.borrow());
        let calls = desk.calls.borrow().join("\n");
        assert!(calls.contains("reset org.gnome.desktop.privacy remember-app-usage"));
        assert!(calls.contains("reset org.gnome.desktop.privacy remove-old-trash-files"));
        assert!(calls.contains("reset org.gnome.desktop.privacy remove-old-temp-files"));
        assert!(calls.contains("reset org.gnome.desktop.privacy recent-files-max-age"));
        assert!(calls.contains("reset org.gnome.desktop.notifications show-in-lock-screen"));
        assert!(!calls.contains(" set "), "{calls}");
    }

    #[test]
    fn a_value_the_person_set_is_written_back_as_that_value() {
        let desk = Rc::new(Desk::stock());
        desk.put("org.gnome.desktop.privacy", RECENT_AGE_KEY, "-1");
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        e.apply_selected(&["linux.recent_files".into()], |_| {})
            .unwrap();
        e.revert(|_| {}).unwrap();
        assert_eq!(
            desk.set
                .borrow()
                .get(&key("org.gnome.desktop.privacy", RECENT_AGE_KEY)),
            Some(&"-1".to_owned())
        );
    }

    #[test]
    fn insights_consent_is_restored_per_source_and_only_that_line_changes() {
        let desk = Rc::new(Desk::stock());
        let config = Path::new("/home/p/.config");
        let original = "# set by the installer\r\nconsent_state = true\r\nother = 1\r\n";
        desk.files
            .borrow_mut()
            .insert(consent_path(config, "linux"), original.as_bytes().to_vec());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        e.apply_selected(&["linux.ubuntu_insights".into()], |_| {})
            .unwrap();
        assert_eq!(
            desk.file("linux"),
            "# set by the installer\r\nconsent_state = false\r\nother = 1\r\n"
        );
        assert_eq!(desk.file("desktop_provision"), "consent_state = false\n");
        e.revert(|_| {}).unwrap();
        assert_eq!(desk.file("linux"), original);
        assert_eq!(desk.file("release_upgrader"), "consent_state = false\n");
    }

    #[test]
    fn a_stock_ubuntu_install_has_nothing_to_fix_for_insights() {
        let desk = Rc::new(Desk::stock());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        let report = e.audit_with_progress(|_| {}).unwrap();
        let r = report
            .results
            .iter()
            .find(|r| r.id == "linux.ubuntu_insights")
            .unwrap();
        assert_eq!(r.status.as_str(), "compliant");
    }

    #[test]
    fn a_missing_consent_file_is_not_a_problem_and_not_created() {
        let desk = Rc::new(Desk::stock());
        desk.files
            .borrow_mut()
            .retain(|p, _| !p.ends_with("linux-consent.toml"));
        let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
        assert_eq!(
            items(&mut b, "linux.ubuntu_insights"),
            json!({"linux": null, "desktop_provision": 0, "release_upgrader": 0})
        );
    }

    #[test]
    fn without_dconf_an_unsafe_default_cannot_be_told_from_a_choice_so_nothing_is_changed() {
        let mut stock = Desk::stock();
        stock.dconf = false;
        let desk = Rc::new(stock);
        let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
        let o = b.observe("linux.recent_files").unwrap();
        assert!(!o.eligible);
        assert_eq!(o.reason, UNAVAILABLE);
        let value = catalog::spec("linux.recent_files")
            .unwrap()
            .catalog_target();
        assert!(b.write("linux.recent_files", &value).is_err());
        assert!(desk.set.borrow().is_empty());
        let lock = b.observe("linux.screen_lock").unwrap();
        assert!(lock.eligible);
    }

    #[test]
    fn a_missing_schema_makes_the_setting_unavailable() {
        let mut stock = Desk::stock();
        stock
            .defaults
            .retain(|(schema, _), _| schema != "org.gnome.desktop.screensaver");
        let desk = Rc::new(stock);
        let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
        let o = b.observe("linux.screen_lock").unwrap();
        assert!(!o.eligible);
        assert_eq!(o.value["items"]["lock_enabled"], Value::Null);
    }

    #[test]
    fn an_unknown_control_or_a_bad_value_is_refused() {
        let desk = Rc::new(Desk::stock());
        let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
        assert!(b.observe("linux.firewall").is_err());
        assert!(b.observe("uac.enabled").is_err());
        assert!(b.write("linux.firewall", &json!({"items": {}})).is_err());
        assert!(b
            .write(
                "linux.screen_lock",
                &json!({"items": {"lock_enabled": 7, "idle_never": 0}})
            )
            .is_err());
        assert!(desk.set.borrow().is_empty());
    }

    #[test]
    fn consent_lines_are_found_only_when_they_say_true_or_false() {
        let (start, range, on) = consent_line("a = 1\nconsent_state=true\n").unwrap();
        assert_eq!((start, on), (6, true));
        assert_eq!(&"a = 1\nconsent_state=true\n"[range], "true");
        assert!(consent_line("consent_state = maybe\n").is_none());
        assert!(consent_line("other = true\n").is_none());
        assert!(consent_line("").is_none());
    }

    #[test]
    fn the_journal_and_configuration_folders_follow_the_standard_variables() {
        let home = Path::new("/home/p");
        assert_eq!(
            state_dir_in(home, None),
            PathBuf::from("/home/p/.local/state/secblitz")
        );
        assert_eq!(
            state_dir_in(home, Some(Path::new("/data/state"))),
            PathBuf::from("/data/state/secblitz")
        );
        assert_eq!(
            state_dir_in(home, Some(Path::new("relative"))),
            PathBuf::from("/home/p/.local/state/secblitz")
        );
        assert_eq!(config_dir_in(home, None), PathBuf::from("/home/p/.config"));
        assert_eq!(
            config_dir_in(home, Some(Path::new("/x"))),
            PathBuf::from("/x")
        );
    }

    #[test]
    fn the_session_bus_is_only_ever_the_persons_own_socket() {
        let usual = "unix:path=/run/user/1000/bus";
        assert_eq!(
            session_bus(1000, Some(usual), |_| false).as_deref(),
            Some(usual)
        );
        assert_eq!(session_bus(1000, None, |_| true).as_deref(), Some(usual));
        assert_eq!(
            session_bus(1000, Some("unix:path=/tmp/evil"), |_| true).as_deref(),
            Some(usual)
        );
        assert_eq!(
            session_bus(1000, Some("unix:path=/tmp/evil"), |_| false),
            None
        );
        assert_eq!(session_bus(1000, None, |_| false), None);
    }

    fn engine_on(desk: &Rc<Desk>, id: &str, desktop: Desktop, dir: &Path) -> Engine {
        let b = backend(desk, id, desktop, true);
        Engine::open_for(Os::Linux, dir.to_owned(), Box::new(b)).unwrap()
    }

    fn status(e: &mut Engine, id: &str) -> String {
        let report = e.audit_with_progress(|_| {}).unwrap();
        report
            .results
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} was not checked"))
            .status
            .as_str()
            .to_owned()
    }

    fn calls(desk: &Rc<Desk>) -> String {
        desk.calls.borrow().join("\n")
    }

    #[test]
    fn plugged_in_drives_are_fixed_on_mint_by_setting_the_key_and_undone_by_resetting_it() {
        let desk = Rc::new(Desk::mint());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine_on(&desk, "linuxmint", Desktop::Cinnamon, state.path());
        assert_eq!(status(&mut e, "linux.media_autorun"), "attention");
        assert!(desk.set.borrow().is_empty());
        e.apply_selected(&["linux.media_autorun".into()], |_| {})
            .unwrap();
        assert_eq!(
            desk.current("org.cinnamon.desktop.media-handling", "autorun-never")
                .unwrap(),
            "true"
        );
        assert_eq!(status(&mut e, "linux.media_autorun"), "compliant");
        desk.calls.borrow_mut().clear();
        e.revert(|_| {}).unwrap();
        assert!(desk.set.borrow().is_empty(), "{:?}", desk.set.borrow());
        assert!(calls(&desk).contains("reset org.cinnamon.desktop.media-handling autorun-never"));
        assert!(!calls(&desk).contains(" set "), "{}", calls(&desk));
    }

    #[test]
    fn a_choice_to_allow_plugged_in_drives_to_start_is_written_back_as_that_choice() {
        let desk = Rc::new(Desk::mint());
        desk.put(
            "org.cinnamon.desktop.media-handling",
            "autorun-never",
            "false",
        );
        let state = tempfile::tempdir().unwrap();
        let mut e = engine_on(&desk, "linuxmint", Desktop::Cinnamon, state.path());
        let mut b = backend(&desk, "linuxmint", Desktop::Cinnamon, true);
        assert_eq!(items(&mut b, "linux.media_autorun"), json!({"never": 0}));
        e.apply_selected(&["linux.media_autorun".into()], |_| {})
            .unwrap();
        e.revert(|_| {}).unwrap();
        assert_eq!(
            desk.set
                .borrow()
                .get(&key("org.cinnamon.desktop.media-handling", "autorun-never")),
            Some(&"false".to_owned())
        );
    }

    #[test]
    fn plugged_in_drives_are_already_safe_on_gnome_and_the_missing_key_is_not_offered() {
        for desk in [Desk::stock(), Desk::fedora()] {
            let desk = Rc::new(desk);
            let state = tempfile::tempdir().unwrap();
            let mut e = engine(&desk, state.path());
            assert_eq!(status(&mut e, "linux.media_autorun"), "compliant");
        }
        let mut stock = Desk::mint();
        stock
            .defaults
            .retain(|(schema, _), _| schema != "org.cinnamon.desktop.media-handling");
        let desk = Rc::new(stock);
        let mut b = backend(&desk, "linuxmint", Desktop::Cinnamon, true);
        let o = b.observe("linux.media_autorun").unwrap();
        assert!(!o.eligible);
        assert_eq!(o.reason, UNAVAILABLE);
    }

    #[test]
    fn location_sharing_that_was_turned_on_is_switched_off_and_put_back_by_undo() {
        for desk in [Desk::stock(), Desk::fedora()] {
            let desk = Rc::new(desk);
            let state = tempfile::tempdir().unwrap();
            let mut e = engine(&desk, state.path());
            assert_eq!(status(&mut e, "linux.location"), "compliant");
            desk.put("org.gnome.system.location", "enabled", "true");
            let before = desk.set.borrow().clone();
            assert_eq!(status(&mut e, "linux.location"), "attention");
            e.apply_selected(&["linux.location".into()], |_| {})
                .unwrap();
            assert_eq!(
                desk.current("org.gnome.system.location", "enabled")
                    .unwrap(),
                "false"
            );
            assert_eq!(status(&mut e, "linux.location"), "compliant");
            e.revert(|_| {}).unwrap();
            assert_eq!(desk.set.borrow().clone(), before);
        }
    }

    #[test]
    fn problem_and_usage_reports_are_switched_off_one_by_one_and_undone_exactly() {
        let desk = Rc::new(Desk::stock());
        desk.put(
            "org.gnome.desktop.privacy",
            "send-software-usage-stats",
            "true",
        );
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        let before = desk.set.borrow().clone();
        assert_eq!(status(&mut e, "linux.problem_reports"), "attention");
        desk.calls.borrow_mut().clear();
        e.apply_selected(&["linux.problem_reports".into()], |_| {})
            .unwrap();
        assert!(
            !calls(&desk).contains("report-technical-problems false"),
            "a key that was already off is left alone"
        );
        assert_eq!(
            desk.current("org.gnome.desktop.privacy", "send-software-usage-stats")
                .unwrap(),
            "false"
        );
        assert_eq!(status(&mut e, "linux.problem_reports"), "compliant");
        e.revert(|_| {}).unwrap();
        assert_eq!(desk.set.borrow().clone(), before);
        desk.put(
            "org.gnome.desktop.privacy",
            "report-technical-problems",
            "true",
        );
        let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
        assert_eq!(
            items(&mut b, "linux.problem_reports"),
            json!({"report_problems": 1, "send_usage_stats": 1})
        );
    }

    #[test]
    fn app_history_is_reset_when_it_was_the_default_and_written_back_when_the_person_set_it() {
        let desk = Rc::new(Desk::stock());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        assert_eq!(status(&mut e, "linux.app_usage"), "attention");
        e.apply_selected(&["linux.app_usage".into()], |_| {})
            .unwrap();
        assert_eq!(
            desk.current("org.gnome.desktop.privacy", "remember-app-usage")
                .unwrap(),
            "false"
        );
        assert_eq!(status(&mut e, "linux.app_usage"), "compliant");
        e.revert(|_| {}).unwrap();
        assert!(desk.set.borrow().is_empty());

        desk.put("org.gnome.desktop.privacy", "remember-app-usage", "true");
        e.apply_selected(&["linux.app_usage".into()], |_| {})
            .unwrap();
        e.revert(|_| {}).unwrap();
        assert_eq!(
            desk.set
                .borrow()
                .get(&key("org.gnome.desktop.privacy", "remember-app-usage")),
            Some(&"true".to_owned())
        );
    }

    #[test]
    fn old_files_are_cleaned_by_themselves_only_after_a_choice_and_undo_leaves_no_trace() {
        for (desk, id, desktop, schema) in [
            (
                Desk::stock(),
                "ubuntu",
                Desktop::Gnome,
                "org.gnome.desktop.privacy",
            ),
            (
                Desk::fedora(),
                "fedora",
                Desktop::Gnome,
                "org.gnome.desktop.privacy",
            ),
            (
                Desk::mint(),
                "linuxmint",
                Desktop::Cinnamon,
                "org.cinnamon.desktop.privacy",
            ),
        ] {
            let desk = Rc::new(desk);
            let state = tempfile::tempdir().unwrap();
            let mut e = engine_on(&desk, id, desktop, state.path());
            assert_eq!(status(&mut e, "linux.old_files"), "attention");
            assert!(desk.set.borrow().is_empty());
            e.apply_selected(&["linux.old_files".into()], |_| {})
                .unwrap();
            for k in ["remove-old-trash-files", "remove-old-temp-files"] {
                assert_eq!(desk.current(schema, k).unwrap(), "true", "{id} {k}");
            }
            assert_eq!(
                desk.current(schema, "old-files-age").unwrap(),
                "uint32 30",
                "the age limit is not touched"
            );
            assert_eq!(status(&mut e, "linux.old_files"), "compliant");
            e.revert(|_| {}).unwrap();
            assert!(
                desk.set.borrow().is_empty(),
                "{id}: {:?}",
                desk.set.borrow()
            );
        }
    }

    #[test]
    fn only_the_old_files_setting_that_is_off_is_changed_and_a_choice_to_keep_files_is_kept() {
        let desk = Rc::new(Desk::stock());
        desk.put(
            "org.gnome.desktop.privacy",
            "remove-old-trash-files",
            "true",
        );
        desk.put(
            "org.gnome.desktop.privacy",
            "remove-old-temp-files",
            "false",
        );
        let state = tempfile::tempdir().unwrap();
        let mut e = engine(&desk, state.path());
        let before = desk.set.borrow().clone();
        desk.calls.borrow_mut().clear();
        e.apply_selected(&["linux.old_files".into()], |_| {})
            .unwrap();
        assert!(!calls(&desk).contains("remove-old-trash-files true"));
        assert_eq!(
            desk.current("org.gnome.desktop.privacy", "remove-old-temp-files")
                .unwrap(),
            "true"
        );
        e.revert(|_| {}).unwrap();
        assert_eq!(desk.set.borrow().clone(), before);
    }

    #[test]
    fn lock_screen_messages_follow_the_mint_desktop_key() {
        let desk = Rc::new(Desk::mint());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine_on(&desk, "linuxmint", Desktop::Cinnamon, state.path());
        assert_eq!(status(&mut e, "linux.lock_previews"), "compliant");
        desk.put(
            "org.cinnamon.desktop.screensaver",
            "show-notifications",
            "true",
        );
        let before = desk.set.borrow().clone();
        assert_eq!(status(&mut e, "linux.lock_previews"), "attention");
        e.apply_selected(&["linux.lock_previews".into()], |_| {})
            .unwrap();
        assert_eq!(
            desk.current("org.cinnamon.desktop.screensaver", "show-notifications")
                .unwrap(),
            "false"
        );
        e.revert(|_| {}).unwrap();
        assert_eq!(desk.set.borrow().clone(), before);
    }

    const UPDATES: &str = "com.linuxmint.updates";
    const FLATPAKS: &str = "auto-update-flatpaks";
    const SPICES: &str = "auto-update-cinnamon-spices";

    #[test]
    fn mint_app_updates_are_turned_on_and_undo_resets_what_was_never_set() {
        let desk = Rc::new(Desk::mint());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine_on(&desk, "linuxmint", Desktop::Cinnamon, state.path());
        let mut b = backend(&desk, "linuxmint", Desktop::Cinnamon, true);
        assert_eq!(
            items(&mut b, "linux.mint_app_updates"),
            json!({"flatpaks": 2, "spices": 2})
        );
        assert_eq!(status(&mut e, "linux.mint_app_updates"), "attention");
        assert!(desk.set.borrow().is_empty());
        e.apply_selected(&["linux.mint_app_updates".into()], |_| {})
            .unwrap();
        for k in [FLATPAKS, SPICES] {
            assert_eq!(desk.current(UPDATES, k).unwrap(), "true");
        }
        assert_eq!(status(&mut e, "linux.mint_app_updates"), "compliant");
        desk.calls.borrow_mut().clear();
        e.revert(|_| {}).unwrap();
        assert!(desk.set.borrow().is_empty(), "{:?}", desk.set.borrow());
        assert!(calls(&desk).contains("reset com.linuxmint.updates auto-update-flatpaks"));
        assert!(calls(&desk).contains("reset com.linuxmint.updates auto-update-cinnamon-spices"));
        assert!(!calls(&desk).contains(" set "), "{}", calls(&desk));
    }

    #[test]
    fn only_the_mint_update_switch_that_is_off_is_changed_and_a_choice_comes_back_as_that_choice() {
        let desk = Rc::new(Desk::mint());
        desk.put(UPDATES, FLATPAKS, "true");
        desk.put(UPDATES, SPICES, "false");
        let state = tempfile::tempdir().unwrap();
        let mut e = engine_on(&desk, "linuxmint", Desktop::Cinnamon, state.path());
        let mut b = backend(&desk, "linuxmint", Desktop::Cinnamon, true);
        assert_eq!(
            items(&mut b, "linux.mint_app_updates"),
            json!({"flatpaks": 1, "spices": 0})
        );
        desk.calls.borrow_mut().clear();
        e.apply_selected(&["linux.mint_app_updates".into()], |_| {})
            .unwrap();
        assert!(!calls(&desk).contains("set com.linuxmint.updates auto-update-flatpaks"));
        assert_eq!(desk.current(UPDATES, SPICES).unwrap(), "true");
        e.revert(|_| {}).unwrap();
        assert_eq!(desk.current(UPDATES, FLATPAKS).unwrap(), "true");
        assert_eq!(desk.current(UPDATES, SPICES).unwrap(), "false");
        assert_eq!(desk.set.borrow().len(), 2);
    }

    #[test]
    fn mint_app_updates_are_not_offered_where_the_update_manager_is_missing() {
        for (desk, id, desktop) in [
            (Desk::stock(), "ubuntu", Desktop::Gnome),
            (Desk::fedora(), "fedora", Desktop::Gnome),
        ] {
            let desk = Rc::new(desk);
            let listed = ids(&backend(&desk, id, desktop, true));
            assert!(
                !listed.contains(&"linux.mint_app_updates".to_string()),
                "{id}"
            );
        }
        let desk = Rc::new(Desk::mint());
        assert!(!ids(&backend(&desk, "linuxmint", Desktop::Cinnamon, false))
            .contains(&"linux.mint_app_updates".to_string()));
        let mut half = Desk::mint();
        half.defaults.remove(&key(UPDATES, SPICES));
        let desk = Rc::new(half);
        assert!(!ids(&backend(&desk, "linuxmint", Desktop::Cinnamon, true))
            .contains(&"linux.mint_app_updates".to_string()));
    }

    #[test]
    fn the_software_app_downloads_updates_by_default_and_a_turned_off_switch_is_fixed_and_put_back()
    {
        const SCHEMA: &str = "org.gnome.software";
        const KEY: &str = "download-updates";
        let desk = Rc::new(Desk::fedora());
        let state = tempfile::tempdir().unwrap();
        let mut e = engine_on(&desk, "fedora", Desktop::Gnome, state.path());
        let mut b = backend(&desk, "fedora", Desktop::Gnome, true);
        assert_eq!(
            items(&mut b, "linux.app_store_updates"),
            json!({"download": 2})
        );
        assert_eq!(status(&mut e, "linux.app_store_updates"), "compliant");

        desk.put(SCHEMA, KEY, "false");
        assert_eq!(
            items(&mut b, "linux.app_store_updates"),
            json!({"download": 0})
        );
        assert_eq!(status(&mut e, "linux.app_store_updates"), "attention");
        e.apply_selected(&["linux.app_store_updates".into()], |_| {})
            .unwrap();
        assert_eq!(desk.current(SCHEMA, KEY).unwrap(), "true");
        assert_eq!(status(&mut e, "linux.app_store_updates"), "compliant");
        e.revert(|_| {}).unwrap();
        assert_eq!(desk.current(SCHEMA, KEY).unwrap(), "false");
        assert_eq!(desk.set.borrow().len(), 1);
    }

    #[test]
    fn the_software_app_check_is_not_offered_where_the_app_is_missing() {
        for (desk, id, desktop) in [
            (Desk::stock(), "ubuntu", Desktop::Gnome),
            (Desk::mint(), "linuxmint", Desktop::Cinnamon),
        ] {
            let desk = Rc::new(desk);
            let listed = ids(&backend(&desk, id, desktop, true));
            assert!(
                !listed.contains(&"linux.app_store_updates".to_string()),
                "{id}"
            );
        }
        let desk = Rc::new(Desk::fedora());
        let listed = ids(&backend(&desk, "fedora", Desktop::Gnome, true));
        assert!(listed.contains(&"linux.app_store_updates".to_string()));
        assert!(!ids(&backend(&desk, "fedora", Desktop::Gnome, false))
            .contains(&"linux.app_store_updates".to_string()));
    }

    #[test]
    fn a_home_folder_other_people_can_enter_is_closed_and_the_exact_mode_comes_back() {
        for (mode, closed) in [
            (0o755, 0o750),
            (0o751, 0o750),
            (0o705, 0o700),
            (0o2755, 0o2750),
            (0o777, 0o770),
        ] {
            let desk = Rc::new(Desk::stock());
            desk.home_mode.set(mode);
            let state = tempfile::tempdir().unwrap();
            let mut e = engine(&desk, state.path());
            assert_eq!(
                status(&mut e, "linux.home_private"),
                "attention",
                "{mode:o}"
            );
            assert_eq!(desk.home_mode.get(), mode, "checking changed the folder");
            e.apply_selected(&["linux.home_private".into()], |_| {})
                .unwrap();
            assert_eq!(desk.home_mode.get(), closed, "{mode:o}");
            assert!(calls(&desk).contains("/usr/bin/chmod -- o= /home/tester"));
            assert_eq!(status(&mut e, "linux.home_private"), "compliant");
            e.revert(|_| {}).unwrap();
            assert_eq!(
                desk.home_mode.get(),
                mode,
                "undo left {:o}",
                desk.home_mode.get()
            );
        }
    }

    #[test]
    fn the_recorded_home_folders_are_private_already() {
        for desk in [Desk::stock(), Desk::fedora(), Desk::mint()] {
            let desk = Rc::new(desk);
            let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
            assert_eq!(items(&mut b, "linux.home_private"), json!({"others": 0}));
        }
        assert_eq!(Desk::fedora().home_mode.get(), 0o700);
    }

    #[test]
    fn a_home_folder_that_is_not_the_persons_own_real_folder_is_never_changed() {
        type Spoil = fn(&Desk);
        let cases: [Spoil; 4] = [
            |d| d.home_owner.set(0),
            |d| *d.home_kind.borrow_mut() = "symbolic link",
            |d| *d.home.borrow_mut() = "home/tester".into(),
            |d| *d.home.borrow_mut() = "/".into(),
        ];
        for spoil in cases {
            let desk = Rc::new(Desk::stock());
            desk.home_mode.set(0o755);
            spoil(&desk);
            let mut b = backend(&desk, "ubuntu", Desktop::Gnome, true);
            let o = b.observe("linux.home_private").unwrap();
            assert!(!o.eligible);
            assert_eq!(o.reason, UNAVAILABLE);
            let target = catalog::spec("linux.home_private")
                .unwrap()
                .catalog_target();
            assert!(b.write("linux.home_private", &target).is_err());
            assert_eq!(desk.home_mode.get(), 0o755);
            assert!(!calls(&desk).contains("chmod"), "{}", calls(&desk));
        }
    }

    #[test]
    fn a_missing_account_entry_makes_the_home_folder_check_unavailable() {
        let desk = Rc::new(Desk::stock());
        let b = PersonBackend::new(
            Rc::clone(&desk),
            &distro("ubuntu", Desktop::Gnome),
            "/home/p/.config".into(),
            true,
            4242,
        );
        assert!(b.read_home().is_none());
    }
}
