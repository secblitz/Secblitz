//! Signing in without a password: automatic sign-in and the guest account, in GDM and LightDM.
//!
//! `gdm_automatic` is GDM's `AutomaticLoginEnable` as "true" or "false"; `lightdm_user` is the name LightDM signs in by
//! itself, absent when it does not; `allow_guest` is LightDM's `allow-guest`, absent when LightDM is not the sign-in
//! screen. A setting is changed in the line where it already is, and an undo puts that line back.

use super::{ini, observation, plain, text_item, text_of, Cx, Items, UNRECOGNISED};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::Result;
use std::collections::BTreeMap;

const GDM_FILES: [&str; 2] = ["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"];
const DISPLAY_MANAGER: &str = "/etc/X11/default-display-manager";
const LIGHTDM_DIRS: [&str; 3] = [
    "/usr/share/lightdm/lightdm.conf.d",
    "/etc/xdg/lightdm/lightdm.conf.d",
    "/etc/lightdm/lightdm.conf.d",
];
const LIGHTDM_MAIN: &str = "/etc/lightdm/lightdm.conf";
const LIGHTDM_DROPIN: &str = "/etc/lightdm/lightdm.conf.d/99-secblitz.conf";
const LIGHTDM_SECTIONS: [&str; 2] = ["Seat:*", "SeatDefaults"];

fn gdm_file(cx: &Cx) -> Result<Option<(&'static str, String)>> {
    for path in GDM_FILES {
        if let Some(text) = cx.text(path)? {
            return Ok(Some((path, text)));
        }
    }
    Ok(None)
}

fn gdm_value(text: &str) -> Option<&'static str> {
    let v = ini::get(text, &["daemon"], "AutomaticLoginEnable")?;
    Some(match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => "true",
        _ => "false",
    })
}

fn lightdm_in_use(cx: &Cx) -> Result<bool> {
    Ok(cx
        .text(DISPLAY_MANAGER)?
        .is_some_and(|t| t.trim().ends_with("lightdm")))
}

/// A sign-in name: letters, digits, dots, dashes and underscores, not starting with a dash.
fn user_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// LightDM's files from the lowest to the highest priority: a file in a later folder replaces one of the same name in an
/// earlier folder, the files of a folder are read by name, and the main file is read last.
fn lightdm_files(cx: &Cx) -> Result<Vec<(String, String)>> {
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for dir in LIGHTDM_DIRS {
        for name in cx.list(dir) {
            if name.ends_with(".conf") {
                by_name.insert(name.clone(), format!("{dir}/{name}"));
            }
        }
    }
    let mut files = Vec::new();
    for path in by_name.into_values().chain([LIGHTDM_MAIN.to_string()]) {
        if let Some(text) = cx.text(&path)? {
            files.push((path, text));
        }
    }
    Ok(files)
}

/// The value that counts for `key`, with the file that sets it. LightDM allows guests unless told otherwise.
fn lightdm_effective(
    files: &[(String, String)],
    key: &str,
    skip: Option<&str>,
) -> (Option<String>, Option<String>) {
    let found = files
        .iter()
        .filter(|(p, _)| Some(p.as_str()) != skip)
        .rev()
        .find_map(|(p, t)| ini::get(t, &LIGHTDM_SECTIONS, key).map(|v| (p.clone(), v)));
    let (path, value) = match found {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
    };
    let value = value.filter(|v| !v.is_empty());
    let value = match (key, value) {
        ("allow-guest", None) => Some("true".to_string()),
        ("allow-guest", Some(v)) => Some(v.to_ascii_lowercase()),
        (_, v) => v,
    };
    (path, value)
}

pub fn observe_autologin(cx: &Cx) -> Result<Observation> {
    let gdm = match gdm_file(cx)? {
        Some((_, text)) => gdm_value(&text).map_or(Item::Absent, text_item),
        None => Item::Absent,
    };
    let lightdm = if lightdm_in_use(cx)? {
        match lightdm_effective(&lightdm_files(cx)?, "autologin-user", None).1 {
            Some(name) if user_ok(&name) => text_item(name),
            Some(_) => return Err(plain(UNRECOGNISED)),
            None => Item::Absent,
        }
    } else {
        Item::Absent
    };
    Ok(observation(
        vec![("gdm_automatic", gdm), ("lightdm_user", lightdm)],
        true,
        "",
    ))
}

pub fn write_autologin(cx: &Cx, want: &Items) -> Result<()> {
    let gdm = text_of(want, "gdm_automatic")?;
    let user = text_of(want, "lightdm_user")?;
    if gdm.is_some_and(|v| !matches!(v, "true" | "false")) || user.is_some_and(|u| !user_ok(u)) {
        return Err(plain(UNRECOGNISED));
    }
    if let Some((path, text)) = gdm_file(cx)? {
        let now = gdm_value(&text);
        let new = match (gdm, now) {
            (Some(v), now) if now != Some(v) => {
                Some(ini::set(&text, "daemon", "AutomaticLoginEnable", v))
            }
            (None, Some(_)) => Some(ini::unset(&text, &["daemon"], "AutomaticLoginEnable")),
            _ => None,
        };
        if let Some(new) = new {
            cx.write_text(path, &new, 0o644)?;
        }
    }
    if lightdm_in_use(cx)? {
        lightdm_set(cx, "autologin-user", user)?;
    }
    Ok(())
}

pub fn observe_guest(cx: &Cx) -> Result<Observation> {
    let item = if lightdm_in_use(cx)? {
        match lightdm_effective(&lightdm_files(cx)?, "allow-guest", None)
            .1
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            Some("true" | "1" | "yes") => text_item("true"),
            Some("false" | "0" | "no") => text_item("false"),
            _ => return Err(plain(UNRECOGNISED)),
        }
    } else {
        Item::Absent
    };
    Ok(observation(vec![("allow_guest", item)], true, ""))
}

pub fn write_guest(cx: &Cx, want: &Items) -> Result<()> {
    let Some(value) = text_of(want, "allow_guest")? else {
        return Ok(());
    };
    if !matches!(value, "true" | "false") || !lightdm_in_use(cx)? {
        return Err(plain(UNRECOGNISED));
    }
    lightdm_set(cx, "allow-guest", Some(value))
}

/// Sets a LightDM key to `desired` (`None` leaves it empty). An existing line in the administrator's files is changed
/// in place; otherwise Secblitz's own file carries the setting, and goes away when the others already give the value.
fn lightdm_set(cx: &Cx, key: &str, desired: Option<&str>) -> Result<()> {
    let files = lightdm_files(cx)?;
    let want = desired.map(str::to_string);
    let ours = files.iter().find(|(p, _)| p == LIGHTDM_DROPIN);
    if let Some((_, text)) = ours {
        let without = lightdm_effective(&files, key, Some(LIGHTDM_DROPIN)).1;
        if without == want {
            let rest = ini::unset(text, &LIGHTDM_SECTIONS, key);
            if ini::has_assignments(&rest) {
                return cx.write_text(LIGHTDM_DROPIN, &rest, 0o644);
            }
            return cx.remove(LIGHTDM_DROPIN);
        }
    }
    let (path, now) = lightdm_effective(&files, key, None);
    if now == want {
        return Ok(());
    }
    let value = desired.unwrap_or("");
    let editable = path
        .as_deref()
        .filter(|p| p.starts_with("/etc/lightdm/"))
        .and_then(|p| files.iter().find(|(f, _)| f == p));
    match editable {
        Some((path, text)) => {
            let section = LIGHTDM_SECTIONS
                .iter()
                .find(|s| ini::get(text, &[**s], key).is_some())
                .copied()
                .unwrap_or("Seat:*");
            cx.write_text(path, &ini::set(text, section, key, value), 0o644)
        }
        None => {
            let current = ours.map(|(_, t)| t.as_str()).unwrap_or("");
            cx.write_text(
                LIGHTDM_DROPIN,
                &ini::set(current, "Seat:*", key, value),
                0o644,
            )
        }
    }
}
