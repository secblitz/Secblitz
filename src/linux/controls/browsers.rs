//! Browser privacy settings, set as policy files that the browsers read at start: Firefox from
//! `/etc/firefox/policies/policies.json`, Chrome, Chromium and Brave from a managed policy folder each.
//!
//! Firefox reads one policy file, so Secblitz adds its keys to the file that is there and keeps the original bytes to put
//! back. The Chromium family reads every file in the folder, so Secblitz owns one file, `secblitz.json`, in each.

use super::{flag, num_of, observation, plain, unavailable, Cx, Items, NO_RECORD, UNRECOGNISED};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::path::Path;

pub const NO_BROWSER: &str =
    "No supported web browser was found on this computer, so Secblitz leaves this alone.";
pub const NO_FIREFOX: &str =
    "Firefox is not installed on this computer, so Secblitz leaves this alone.";

pub const SENTENCES: [&str; 2] = [NO_BROWSER, NO_FIREFOX];

const TEST: &str = "/usr/bin/test";
const MKDIR: &str = "/usr/bin/mkdir";
const RMDIR: &str = "/usr/bin/rmdir";
const POLICIES: &str = "/etc/firefox/policies/policies.json";
const FIREFOX_DIRS: [&str; 2] = ["/etc/firefox", "/etc/firefox/policies"];
const FIREFOX_PRESENT: [&str; 7] = [
    "/usr/bin/firefox",
    "/usr/bin/firefox-esr",
    "/snap/bin/firefox",
    "/usr/lib/firefox",
    "/usr/lib64/firefox",
    "/usr/lib/firefox-esr",
    "/opt/firefox",
];
const ORIGIN_MEMO: &str = "browser_firefox_origin.bin";
const FIREFOX_DIRS_MEMO: &str = "browser_firefox_dirs";
const CHROMIUM_DIRS_MEMO: &str = "browser_chromium_dirs";
const CHROMIUM_FILE: &str = "secblitz.json";

struct Chromium {
    folders: [&'static str; 3],
    programs: &'static [&'static str],
}

const CHROMIUM: [Chromium; 4] = [
    Chromium {
        folders: [
            "/etc/opt/chrome",
            "/etc/opt/chrome/policies",
            "/etc/opt/chrome/policies/managed",
        ],
        programs: &["/opt/google/chrome/chrome", "/usr/bin/google-chrome-stable"],
    },
    Chromium {
        folders: [
            "/etc/chromium",
            "/etc/chromium/policies",
            "/etc/chromium/policies/managed",
        ],
        programs: &[
            "/usr/bin/chromium",
            "/usr/lib64/chromium-browser/chromium-browser",
        ],
    },
    Chromium {
        folders: [
            "/etc/chromium-browser",
            "/etc/chromium-browser/policies",
            "/etc/chromium-browser/policies/managed",
        ],
        programs: &["/usr/bin/chromium-browser", "/snap/bin/chromium"],
    },
    Chromium {
        folders: [
            "/etc/brave",
            "/etc/brave/policies",
            "/etc/brave/policies/managed",
        ],
        programs: &["/usr/bin/brave-browser", "/opt/brave.com/brave/brave"],
    },
];

const CHROMIUM_DATA: [(&str, bool); 2] = [
    ("MetricsReportingEnabled", false),
    ("UrlKeyedAnonymizedDataCollectionEnabled", false),
];

#[derive(Clone, Copy, PartialEq)]
enum Ctl {
    Data,
    Https,
}

impl Ctl {
    fn id(self) -> &'static str {
        match self {
            Ctl::Data => "linux.browser_data_collection",
            Ctl::Https => "linux.browser_https_only",
        }
    }

    fn memo(self) -> &'static str {
        match self {
            Ctl::Data => "browser_firefox_data",
            Ctl::Https => "browser_firefox_https",
        }
    }

    fn other(self) -> Ctl {
        match self {
            Ctl::Data => Ctl::Https,
            Ctl::Https => Ctl::Data,
        }
    }

    fn firefox_policies(self) -> Vec<(&'static str, Value)> {
        match self {
            Ctl::Data => vec![
                ("DisableTelemetry", json!(true)),
                ("DisableFirefoxStudies", json!(true)),
            ],
            Ctl::Https => vec![("HttpsOnlyMode", json!("enabled"))],
        }
    }

    fn firefox_safe(self, policies: &Map<String, Value>) -> bool {
        match self {
            Ctl::Data => ["DisableTelemetry", "DisableFirefoxStudies"]
                .iter()
                .all(|k| policies.get(*k) == Some(&json!(true))),
            Ctl::Https => matches!(
                policies.get("HttpsOnlyMode").and_then(Value::as_str),
                Some("enabled" | "force_enabled")
            ),
        }
    }
}

fn exists(cx: &Cx, flag: &str, path: &str) -> bool {
    cx.run(TEST, &[flag, path]).is_ok_and(|o| o.success())
}

fn firefox_installed(cx: &Cx) -> bool {
    FIREFOX_PRESENT.iter().any(|p| exists(cx, "-e", p)) || exists(cx, "-d", FIREFOX_DIRS[0])
}

/// The `policies` folder, not the folder above it, says a browser is here: other packages put their own files in
/// `/etc/chromium` and `/etc/opt/chrome` (Fedora's GNOME browser connector does) without any browser installed.
fn chromium_installed(cx: &Cx, browser: &Chromium) -> bool {
    exists(cx, "-d", browser.folders[1]) || browser.programs.iter().any(|p| exists(cx, "-e", p))
}

fn parse_policies(bytes: &[u8]) -> Result<Value> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|_| plain(UNRECOGNISED))?;
    match doc.get("policies") {
        None => {}
        Some(Value::Object(_)) => {}
        Some(_) => return Err(plain(UNRECOGNISED)),
    }
    if doc.is_object() {
        Ok(doc)
    } else {
        Err(plain(UNRECOGNISED))
    }
}

fn read_policies(cx: &Cx) -> Result<Option<(Vec<u8>, Value)>> {
    match cx.sys.read(Path::new(POLICIES))? {
        Some(bytes) => {
            let doc = parse_policies(&bytes)?;
            Ok(Some((bytes, doc)))
        }
        None => Ok(None),
    }
}

fn policies_of(doc: &Value) -> Map<String, Value> {
    doc.get("policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn pretty(doc: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(doc)? + "\n")
}

fn firefox_item(cx: &Cx, ctl: Ctl) -> Result<Item> {
    if !firefox_installed(cx) {
        return Ok(Item::Absent);
    }
    let safe = match read_policies(cx)? {
        Some((_, doc)) => ctl.firefox_safe(&policies_of(&doc)),
        None => false,
    };
    Ok(flag(!safe))
}

fn json_files(cx: &Cx, folder: &str) -> Vec<String> {
    cx.list(folder)
        .into_iter()
        .filter(|n| {
            n.ends_with(".json")
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        })
        .collect()
}

/// The value each setting ends up with, the way the browser reads the folder: files by name, the last one wins.
fn chromium_safe(cx: &Cx, browser: &Chromium) -> Result<bool> {
    let folder = browser.folders[2];
    let mut seen: Map<String, Value> = Map::new();
    for name in json_files(cx, folder) {
        let Some(text) = cx.text(&format!("{folder}/{name}"))? else {
            continue;
        };
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&text) {
            seen.extend(map);
        }
    }
    Ok(CHROMIUM_DATA
        .iter()
        .all(|(k, v)| seen.get(*k) == Some(&json!(*v))))
}

fn chromium_item(cx: &Cx) -> Result<Item> {
    let mut any = false;
    let mut unsafe_ = false;
    for browser in &CHROMIUM {
        if chromium_installed(cx, browser) {
            any = true;
            unsafe_ |= !chromium_safe(cx, browser)?;
        }
    }
    Ok(if any { flag(unsafe_) } else { Item::Absent })
}

fn unreadable_policy(id: &str, e: anyhow::Error) -> Result<Observation> {
    if e.downcast_ref::<super::Plain>().is_some() {
        return Ok(unavailable(id, UNRECOGNISED));
    }
    Err(e)
}

pub fn observe_data_collection(cx: &Cx) -> Result<Observation> {
    data_collection(cx).or_else(|e| unreadable_policy(Ctl::Data.id(), e))
}

pub fn observe_https_only(cx: &Cx) -> Result<Observation> {
    https_only(cx).or_else(|e| unreadable_policy(Ctl::Https.id(), e))
}

fn data_collection(cx: &Cx) -> Result<Observation> {
    let (firefox, chromium) = (firefox_item(cx, Ctl::Data)?, chromium_item(cx)?);
    if firefox == Item::Absent && chromium == Item::Absent {
        return Ok(unavailable(Ctl::Data.id(), NO_BROWSER));
    }
    Ok(observation(
        vec![("firefox", firefox), ("chromium", chromium)],
        true,
        "",
    ))
}

fn https_only(cx: &Cx) -> Result<Observation> {
    match firefox_item(cx, Ctl::Https)? {
        Item::Absent => Ok(unavailable(Ctl::Https.id(), NO_FIREFOX)),
        item => Ok(observation(vec![("firefox", item)], true, "")),
    }
}

/// Only folders Secblitz could have made may be taken away again.
fn ours(folder: &str) -> bool {
    FIREFOX_DIRS.contains(&folder) || CHROMIUM.iter().any(|b| b.folders.contains(&folder))
}

/// Makes each missing folder on the way down and returns the ones it made.
fn make_folders(cx: &Cx, folders: &[&str], made: &mut Vec<String>) -> Result<()> {
    for folder in folders {
        if !exists(cx, "-d", folder) {
            cx.run_ok(MKDIR, &["-m", "0755", folder])?;
            made.push((*folder).to_string());
        }
    }
    Ok(())
}

fn remove_made(cx: &Cx, name: &str) -> Result<()> {
    if let Some(made) = cx.memo_read(name)? {
        for folder in made.iter().rev().filter(|f| ours(f)) {
            let _ = cx.run(RMDIR, &[folder]);
        }
        cx.memo_clear(name)?;
    }
    Ok(())
}

fn keep_made(cx: &Cx, name: &str, made: Vec<String>) -> Result<()> {
    if made.is_empty() {
        return Ok(());
    }
    let mut all = cx.memo_read(name)?.unwrap_or_default();
    all.extend(made);
    cx.memo_write(name, &all)
}

fn firefox_apply(cx: &Cx, ctl: Ctl) -> Result<()> {
    let current = read_policies(cx)?;
    let mut doc = match &current {
        Some((_, doc)) => doc.clone(),
        None => json!({}),
    };
    if current
        .as_ref()
        .is_some_and(|(_, doc)| ctl.firefox_safe(&policies_of(doc)))
    {
        return Ok(());
    }
    let active = cx.memo_read(ctl.memo())?.is_some() || cx.memo_read(ctl.other().memo())?.is_some();
    if !active {
        let mut origin = Vec::new();
        match &current {
            Some((bytes, _)) => {
                origin.push(b'E');
                origin.extend_from_slice(bytes);
            }
            None => origin.push(b'N'),
        }
        cx.sys
            .write_atomic(&cx.memo.join(ORIGIN_MEMO), &origin, 0o600)?;
    }
    let mut made = Vec::new();
    make_folders(cx, &FIREFOX_DIRS, &mut made)?;
    keep_made(cx, FIREFOX_DIRS_MEMO, made)?;

    let root = doc.as_object_mut().ok_or_else(|| plain(UNRECOGNISED))?;
    let policies = root
        .entry("policies")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| plain(UNRECOGNISED))?;
    if cx.memo_read(ctl.memo())?.is_none() {
        let mut set = Map::new();
        let mut unset = Vec::new();
        for (key, _) in ctl.firefox_policies() {
            match policies.get(key) {
                Some(old) => {
                    set.insert(key.to_string(), old.clone());
                }
                None => unset.push(json!(key)),
            }
        }
        let prior = json!({"set": set, "unset": unset});
        cx.memo_write(ctl.memo(), &[prior.to_string()])?;
    }
    for (key, value) in ctl.firefox_policies() {
        policies.insert(key.to_string(), value);
    }
    cx.write_text(POLICIES, &pretty(&doc)?, 0o644)
}

fn firefox_revert(cx: &Cx, ctl: Ctl) -> Result<()> {
    let prior: Value = cx
        .memo_read(ctl.memo())?
        .and_then(|lines| lines.first().and_then(|l| serde_json::from_str(l).ok()))
        .ok_or_else(|| plain(NO_RECORD))?;
    let others = cx.memo_read(ctl.other().memo())?.is_some();
    let finish = |cx: &Cx| -> Result<()> {
        cx.memo_clear(ctl.memo())?;
        if !others {
            cx.sys.remove(&cx.memo.join(ORIGIN_MEMO))?;
            remove_made(cx, FIREFOX_DIRS_MEMO)?;
        }
        Ok(())
    };
    let Some((_, mut doc)) = read_policies(cx)? else {
        return finish(cx);
    };
    let root = doc.as_object_mut().ok_or_else(|| plain(UNRECOGNISED))?;
    if let Some(Value::Object(policies)) = root.get_mut("policies") {
        if let Some(Value::Object(set)) = prior.get("set") {
            for (key, old) in set {
                policies.insert(key.clone(), old.clone());
            }
        }
        if let Some(Value::Array(unset)) = prior.get("unset") {
            for key in unset.iter().filter_map(Value::as_str) {
                policies.remove(key);
            }
        }
    }
    if others {
        cx.write_text(POLICIES, &pretty(&doc)?, 0o644)?;
        return finish(cx);
    }
    let mut trimmed = doc.clone();
    if trimmed
        .get("policies")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        if let Some(root) = trimmed.as_object_mut() {
            root.remove("policies");
        }
    }
    match cx.sys.read(&cx.memo.join(ORIGIN_MEMO))?.as_deref() {
        Some([b'E', original @ ..]) => {
            let same = parse_policies(original)
                .map(|o| o == doc || o == trimmed)
                .unwrap_or(false);
            if same {
                cx.sys.write_atomic(Path::new(POLICIES), original, 0o644)?;
            } else {
                cx.write_text(POLICIES, &pretty(&doc)?, 0o644)?;
            }
        }
        Some([b'N']) if trimmed == json!({}) => cx.remove(POLICIES)?,
        _ => cx.write_text(POLICIES, &pretty(&doc)?, 0o644)?,
    }
    finish(cx)
}

fn chromium_text() -> String {
    let mut map = Map::new();
    for (key, value) in CHROMIUM_DATA {
        map.insert(key.to_string(), json!(value));
    }
    serde_json::to_string_pretty(&Value::Object(map)).unwrap_or_default() + "\n"
}

fn chromium_apply(cx: &Cx) -> Result<()> {
    let mut made = Vec::new();
    for browser in &CHROMIUM {
        if !chromium_installed(cx, browser) {
            continue;
        }
        let path = format!("{}/{CHROMIUM_FILE}", browser.folders[2]);
        if chromium_safe(cx, browser)? && cx.text(&path)?.is_none() {
            continue;
        }
        make_folders(cx, &browser.folders, &mut made)?;
        cx.write_text(&path, &chromium_text(), 0o644)?;
    }
    keep_made(cx, CHROMIUM_DIRS_MEMO, made)
}

fn chromium_revert(cx: &Cx) -> Result<()> {
    for browser in &CHROMIUM {
        cx.remove(&format!("{}/{CHROMIUM_FILE}", browser.folders[2]))?;
    }
    remove_made(cx, CHROMIUM_DIRS_MEMO)
}

fn write(cx: &Cx, ctl: Ctl, want: &Items) -> Result<()> {
    match num_of(want, "firefox")? {
        Some(0) => firefox_apply(cx, ctl)?,
        Some(1) => firefox_revert(cx, ctl)?,
        Some(_) => return Err(plain(UNRECOGNISED)),
        None => {}
    }
    if ctl == Ctl::Data {
        match num_of(want, "chromium")? {
            Some(0) => chromium_apply(cx)?,
            Some(1) => chromium_revert(cx)?,
            Some(_) => return Err(plain(UNRECOGNISED)),
            None => {}
        }
    }
    Ok(())
}

pub fn write_data_collection(cx: &Cx, want: &Items) -> Result<()> {
    write(cx, Ctl::Data, want)
}

pub fn write_https_only(cx: &Cx, want: &Items) -> Result<()> {
    write(cx, Ctl::Https, want)
}
