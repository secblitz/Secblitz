//! How each system-wide Linux check reads its setting and how a fix or an undo changes it. Every module here owns a few
//! controls from `linux::catalog` and works through [`Cx`], so tests can stand in for the computer.

pub mod accounts;
pub mod browsers;
pub mod findings;
pub mod firewall;
pub mod ini;
pub mod kernel;
pub mod network;
pub mod privacy;
pub mod remote;
pub mod services;
pub mod units;
pub mod updates;

#[cfg(test)]
mod browser_tests;
#[cfg(test)]
pub(crate) mod sim;
#[cfg(test)]
mod tests;

use super::cmd::{Output, Sys};
use super::distro::Distro;
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const ELIGIBLE: &str = "Eligible unmanaged local preference";
pub const READ_FAILED: &str = "Secblitz could not read this setting. Try again in a moment.";
pub const CHANGE_FAILED: &str =
    "Secblitz could not change this setting. Try again, and if it keeps failing, leave it as it is.";
pub const NO_RECORD: &str =
    "Secblitz no longer has a record of what it changed here, so it left this setting as it is.";
pub const UNRECOGNISED: &str =
    "This setting holds something Secblitz does not recognise, so it leaves it alone.";
pub const NO_FIREWALL: &str =
    "No firewall program was found on this computer, so Secblitz leaves this alone.";
pub const FIREWALL_MASKED: &str =
    "The firewall was switched off for good on this computer, so Secblitz leaves it alone.";
pub const FIREWALL_UNREADABLE: &str =
    "Secblitz could not read the firewall settings, so it leaves them alone.";
pub const NO_AUTO_UPDATES: &str =
    "Automatic updates are not set up on this computer, so Secblitz leaves this alone.";
pub const SOFTWARE_APP_UPDATES: &str =
    "The Software app downloads updates for you on this computer, so Secblitz leaves this alone.";
pub const NO_REMOTE_SIGN_IN: &str = "Remote sign-in is not installed on this computer.";
pub const REMOTE_SIGN_IN_OFF: &str =
    "Remote sign-in is switched off, so these settings do not matter right now.";
pub const REMOTE_SIGN_IN_UNREADABLE: &str =
    "Secblitz could not read the remote sign-in settings, so it leaves them alone.";
pub const NO_SIGN_IN_KEY: &str = "Secblitz did not turn off password sign-in, because no sign-in key is set up on this computer and you could be locked out. Set up a key first.";
pub const NO_NETWORK_MANAGER: &str =
    "The network settings program is not installed on this computer, so Secblitz leaves this alone.";
pub const MACHINE_ID_MISSING: &str =
    "Secblitz is not fully installed. Reinstall it from the software app.";

/// Every sentence a person can be shown by this folder's controls, for the translation tests.
pub const SENTENCES: [&str; 16] = [
    READ_FAILED,
    CHANGE_FAILED,
    NO_RECORD,
    UNRECOGNISED,
    NO_FIREWALL,
    FIREWALL_MASKED,
    FIREWALL_UNREADABLE,
    NO_AUTO_UPDATES,
    SOFTWARE_APP_UPDATES,
    NO_REMOTE_SIGN_IN,
    REMOTE_SIGN_IN_OFF,
    REMOTE_SIGN_IN_UNREADABLE,
    NO_SIGN_IN_KEY,
    NO_NETWORK_MANAGER,
    MACHINE_ID_MISSING,
    ELIGIBLE,
];

/// An error that is already a plain sentence for the person.
#[derive(Debug)]
pub struct Plain(pub &'static str);

impl std::fmt::Display for Plain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Plain {}

pub fn plain(sentence: &'static str) -> anyhow::Error {
    anyhow::Error::new(Plain(sentence))
}

/// Keeps the detail for the log and gives the person the sentence.
pub fn detail(what: &str, e: &anyhow::Error, sentence: &'static str) -> anyhow::Error {
    if let Some(Plain(sentence)) = e.downcast_ref::<Plain>() {
        return plain(sentence);
    }
    eprintln!("secblitz: {what}: {e:#}");
    plain(sentence)
}

pub struct Cx<'a> {
    pub sys: &'a dyn Sys,
    pub distro: &'a Distro,
    /// Where a fix keeps what it needs to undo itself exactly, inside the protected state folder.
    pub memo: &'a Path,
}

pub type Items = BTreeMap<String, Item>;

pub fn items_of(value: &Value) -> Result<Items> {
    let items = value
        .get("items")
        .and_then(Value::as_object)
        .ok_or_else(|| plain(UNRECOGNISED))?;
    items
        .iter()
        .map(|(k, v)| {
            let item = match v {
                Value::Null => Item::Absent,
                Value::Number(n) => Item::Num(
                    n.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| plain(UNRECOGNISED))?,
                ),
                Value::String(s) => Item::Text(s.clone()),
                _ => return Err(plain(UNRECOGNISED)),
            };
            Ok((k.clone(), item))
        })
        .collect()
}

pub fn observation(pairs: Vec<(&str, Item)>, eligible: bool, reason: &str) -> Observation {
    let mut items = Map::new();
    for (key, item) in pairs {
        items.insert(
            key.to_string(),
            match item {
                Item::Absent => Value::Null,
                Item::Num(n) => json!(n),
                Item::Text(t) => json!(t),
            },
        );
    }
    Observation {
        value: json!({ "items": items }),
        eligible,
        reason: if reason.is_empty() { ELIGIBLE } else { reason }.to_string(),
        ..Observation::default()
    }
}

/// Every key unread, so nothing counts as protected, and the reason a person is told.
pub fn unavailable(id: &str, reason: &str) -> Observation {
    let keys = super::catalog::spec(id).map_or(&[][..], |s| s.keys);
    observation(
        keys.iter().map(|k| (k.name, Item::Absent)).collect(),
        false,
        reason,
    )
}

pub fn text_of<'w>(want: &'w Items, key: &str) -> Result<Option<&'w str>> {
    match want.get(key) {
        None | Some(Item::Absent) => Ok(None),
        Some(Item::Text(t)) => Ok(Some(t)),
        Some(Item::Num(_)) => Err(plain(UNRECOGNISED)),
    }
}

pub fn num_of(want: &Items, key: &str) -> Result<Option<u32>> {
    match want.get(key) {
        None | Some(Item::Absent) => Ok(None),
        Some(Item::Num(n)) => Ok(Some(*n)),
        Some(Item::Text(_)) => Err(plain(UNRECOGNISED)),
    }
}

pub fn flag(on: bool) -> Item {
    Item::Num(u32::from(on))
}

pub fn text_item(t: impl Into<String>) -> Item {
    Item::Text(t.into())
}

impl<'a> Cx<'a> {
    pub fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
        self.sys.run(program, args)
    }

    /// Like [`Cx::run`], but a program that fails is an error.
    pub fn run_ok(&self, program: &'static str, args: &[&str]) -> Result<Output> {
        let out = self.sys.run(program, args)?;
        if !out.success() {
            bail!(
                "{program} {} failed with {}: {}",
                args.join(" "),
                out.status,
                out.stderr.trim()
            );
        }
        Ok(out)
    }

    pub fn text(&self, path: &str) -> Result<Option<String>> {
        match self.sys.read(Path::new(path))? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| anyhow!("{path} is not text")),
        }
    }

    pub fn write_text(&self, path: &str, text: &str, mode: u32) -> Result<()> {
        self.sys
            .write_atomic(Path::new(path), text.as_bytes(), mode)
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        self.sys.remove(Path::new(path))
    }

    /// The plain file names in a folder, sorted; a missing folder has none.
    pub fn list(&self, dir: &str) -> Vec<String> {
        let Ok(out) = self.sys.run("/usr/bin/ls", &["-1", dir]) else {
            return Vec::new();
        };
        if !out.success() {
            return Vec::new();
        }
        let mut names: Vec<String> = out
            .stdout
            .lines()
            .filter(|n| !n.is_empty() && !n.contains('/'))
            .map(str::to_string)
            .collect();
        names.sort();
        names
    }

    fn memo_file(&self, name: &str) -> PathBuf {
        self.memo.join(format!("{name}.txt"))
    }

    pub fn memo_read(&self, name: &str) -> Result<Option<Vec<String>>> {
        Ok(self.sys.read(&self.memo_file(name))?.map(|b| {
            String::from_utf8_lossy(&b)
                .lines()
                .map(str::to_string)
                .collect()
        }))
    }

    pub fn memo_write(&self, name: &str, lines: &[String]) -> Result<()> {
        let mut text = lines.join("\n");
        text.push('\n');
        self.sys
            .write_atomic(&self.memo_file(name), text.as_bytes(), 0o600)
    }

    pub fn memo_clear(&self, name: &str) -> Result<()> {
        self.sys.remove(&self.memo_file(name))
    }
}
