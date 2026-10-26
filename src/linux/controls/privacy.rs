//! Privacy settings: Ubuntu's crash reports, Fedora's computer counting, the network program's internet check and the
//! address a new Wi-Fi connection shows to the network.
//!
//! `apport` is 1 when crash reports are on; `countme` is 1 when a Fedora software source counts this computer; `enabled`
//! is 1 when the network program checks the internet with an outside address; `cloned_mac` is the Wi-Fi address policy.

use super::units;
use super::{
    flag, ini, num_of, observation, plain, text_item, text_of, unavailable, Cx, Items,
    CHANGE_FAILED, NO_NETWORK_MANAGER, NO_RECORD, UNRECOGNISED,
};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::Result;
use std::collections::BTreeMap;

const APPORT: &str = "/etc/default/apport";
const REPOS: &str = "/etc/yum.repos.d";
const COUNTME_MEMO: &str = "countme";
const NM_MAIN: &str = "/etc/NetworkManager/NetworkManager.conf";
const NM_DIRS: [&str; 3] = [
    "/usr/lib/NetworkManager/conf.d",
    "/run/NetworkManager/conf.d",
    "/etc/NetworkManager/conf.d",
];
const NM_UNIT: &str = "NetworkManager.service";
const CONNECTIVITY_DROPIN: &str = "/etc/NetworkManager/conf.d/90-secblitz-connectivity.conf";
const WIFI_MAC_DROPIN: &str = "/etc/NetworkManager/conf.d/90-secblitz-wifi-mac.conf";
const NOTE: &str = "# Written by Secblitz. Delete this file to go back to how it was.\n";

pub fn observe_crash_reports(cx: &Cx) -> Result<Observation> {
    let item = match cx.text(APPORT)? {
        Some(text) => flag(ini::get(&text, &[""], "enabled").as_deref() != Some("0")),
        None => Item::Absent,
    };
    Ok(observation(vec![("apport", item)], true, ""))
}

pub fn write_crash_reports(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = num_of(want, "apport")? else {
        return Ok(());
    };
    if on > 1 {
        return Err(plain(UNRECOGNISED));
    }
    let text = cx.text(APPORT)?.ok_or_else(|| plain(CHANGE_FAILED))?;
    cx.write_text(
        APPORT,
        &ini::set(&text, "", "enabled", &on.to_string()),
        0o644,
    )
}

fn name_ok(name: &str, extra: &[char]) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

fn repo_files(cx: &Cx) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    for name in cx.list(REPOS) {
        if name.ends_with(".repo") && name_ok(&name, &['_', '.', '-', '+']) {
            let path = format!("{REPOS}/{name}");
            if let Some(text) = cx.text(&path)? {
                files.push((path, text));
            }
        }
    }
    Ok(files)
}

/// The software sources in a file that are on and count this computer.
fn counting(text: &str) -> Vec<String> {
    ini::sections(text)
        .into_iter()
        .filter(|s| !s.is_empty())
        .filter(|s| {
            ini::get(text, &[s], "countme").as_deref() == Some("1")
                && ini::get(text, &[s], "enabled").as_deref() != Some("0")
        })
        .collect()
}

pub fn observe_countme(cx: &Cx) -> Result<Observation> {
    let files = repo_files(cx)?;
    let item = if files.is_empty() {
        Item::Absent
    } else {
        flag(files.iter().any(|(_, t)| !counting(t).is_empty()))
    };
    Ok(observation(vec![("countme", item)], true, ""))
}

pub fn write_countme(cx: &Cx, want: &Items) -> Result<()> {
    match num_of(want, "countme")? {
        Some(0) => {
            let mut changes = Vec::new();
            for (path, text) in repo_files(cx)? {
                let sections = counting(&text);
                if sections
                    .iter()
                    .any(|s| !name_ok(s, &['_', '.', '-', '+', ':', '@']))
                {
                    return Err(plain(UNRECOGNISED));
                }
                if !sections.is_empty() {
                    changes.push((path, text, sections));
                }
            }
            if changes.is_empty() {
                return Ok(());
            }
            let record: Vec<String> = changes
                .iter()
                .flat_map(|(p, _, secs)| secs.iter().map(move |s| format!("{p} {s}")))
                .collect();
            cx.memo_write(COUNTME_MEMO, &record)?;
            for (path, text, sections) in changes {
                let mut text = text;
                for section in sections {
                    text = ini::set(&text, &section, "countme", "0");
                }
                cx.write_text(&path, &text, 0o644)?;
            }
            Ok(())
        }
        Some(1) => {
            let record = cx
                .memo_read(COUNTME_MEMO)?
                .ok_or_else(|| plain(NO_RECORD))?;
            let mut edits: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for line in &record {
                let (path, section) = line.split_once(' ').ok_or_else(|| plain(NO_RECORD))?;
                let file = path.strip_prefix(&format!("{REPOS}/")).unwrap_or("");
                if !file.ends_with(".repo")
                    || !name_ok(file, &['_', '.', '-', '+'])
                    || !name_ok(section, &['_', '.', '-', '+', ':', '@'])
                {
                    return Err(plain(NO_RECORD));
                }
                edits
                    .entry(path.to_string())
                    .or_default()
                    .push(section.to_string());
            }
            for (path, sections) in edits {
                let Some(mut text) = cx.text(&path)? else {
                    continue;
                };
                for section in sections {
                    if ini::get(&text, &[&section], "countme").as_deref() == Some("0") {
                        text = ini::set(&text, &section, "countme", "1");
                    }
                }
                cx.write_text(&path, &text, 0o644)?;
            }
            cx.memo_clear(COUNTME_MEMO)
        }
        _ => Ok(()),
    }
}

/// The network program's files from the lowest to the highest priority, or `None` when it is not installed: the main
/// file, then the files of the three folders by name, where a file in a later folder replaces one of the same name.
pub(super) fn nm_files(cx: &Cx) -> Result<Option<Vec<String>>> {
    let Some(main) = cx.text(NM_MAIN)? else {
        return Ok(None);
    };
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for dir in NM_DIRS {
        for name in cx.list(dir) {
            if name.ends_with(".conf") {
                by_name.insert(name.clone(), format!("{dir}/{name}"));
            }
        }
    }
    let mut texts = vec![main];
    for path in by_name.into_values() {
        if let Some(text) = cx.text(&path)? {
            texts.push(text);
        }
    }
    Ok(Some(texts))
}

pub(super) fn nm_get(texts: &[String], section: &str, key: &str) -> Option<String> {
    texts
        .iter()
        .rev()
        .find_map(|t| ini::get(t, &[section], key))
}

fn connectivity_on(texts: &[String]) -> bool {
    let uri = nm_get(texts, "connectivity", "uri").unwrap_or_default();
    let enabled = nm_get(texts, "connectivity", "enabled").unwrap_or_default();
    let interval = nm_get(texts, "connectivity", "interval").unwrap_or_default();
    !uri.is_empty()
        && !matches!(
            enabled.to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        )
        && interval.trim() != "0"
}

pub(super) fn reload_network_manager(cx: &Cx) -> Result<()> {
    match units::probe(cx, NM_UNIT) {
        Some(unit) if unit.active => units::reload(cx, NM_UNIT),
        _ => Ok(()),
    }
}

pub fn observe_connectivity(cx: &Cx) -> Result<Observation> {
    let item = match nm_files(cx)? {
        Some(texts) => flag(connectivity_on(&texts)),
        None => Item::Absent,
    };
    Ok(observation(vec![("enabled", item)], true, ""))
}

/// Our drop-in is taken away first, so an undo returns to what the other files say.
pub fn write_connectivity(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = num_of(want, "enabled")? else {
        return Ok(());
    };
    if on > 1 {
        return Err(plain(UNRECOGNISED));
    }
    cx.remove(CONNECTIVITY_DROPIN)?;
    let texts = nm_files(cx)?.ok_or_else(|| plain(NO_NETWORK_MANAGER))?;
    if connectivity_on(&texts) != (on == 1) {
        if on == 1 {
            return Err(plain(CHANGE_FAILED));
        }
        cx.write_text(
            CONNECTIVITY_DROPIN,
            &format!("{NOTE}[connectivity]\nenabled=false\n"),
            0o644,
        )?;
    }
    reload_network_manager(cx)
}

fn mac_ok(value: &str) -> bool {
    matches!(value, "preserve" | "permanent" | "random" | "stable")
        || (value.len() == 17
            && value.split(':').count() == 6
            && value
                .split(':')
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// The address policy a new Wi-Fi connection gets. A rule that names its own devices counts only when it names Wi-Fi.
/// "stable-ssid" keeps one address per network, which is as safe as "stable".
fn wifi_mac(texts: &[String]) -> Result<String> {
    let mut value = None;
    for text in texts {
        for section in ini::sections(text) {
            if !section.starts_with("connection") {
                continue;
            }
            let devices = ini::get(text, &[&section], "match-device");
            if devices.is_some_and(|d| !d.contains("type:wifi")) {
                continue;
            }
            if let Some(v) = ini::get(text, &[&section], "wifi.cloned-mac-address") {
                value = Some(v);
            }
        }
    }
    let value = value
        .unwrap_or_else(|| "preserve".into())
        .to_ascii_lowercase();
    let value = if value == "stable-ssid" {
        "stable".into()
    } else {
        value
    };
    if mac_ok(&value) {
        Ok(value)
    } else {
        Err(plain(UNRECOGNISED))
    }
}

pub fn observe_wifi_mac(cx: &Cx) -> Result<Observation> {
    let Some(texts) = nm_files(cx)? else {
        return Ok(unavailable("linux.wifi_mac", NO_NETWORK_MANAGER));
    };
    match wifi_mac(&texts) {
        Ok(v) => Ok(observation(vec![("cloned_mac", text_item(v))], true, "")),
        Err(_) => Ok(unavailable("linux.wifi_mac", UNRECOGNISED)),
    }
}

pub fn write_wifi_mac(cx: &Cx, want: &Items) -> Result<()> {
    let Some(value) = text_of(want, "cloned_mac")? else {
        return Ok(());
    };
    let value = value.to_ascii_lowercase();
    if !mac_ok(&value) {
        return Err(plain(UNRECOGNISED));
    }
    cx.remove(WIFI_MAC_DROPIN)?;
    let texts = nm_files(cx)?.ok_or_else(|| plain(NO_NETWORK_MANAGER))?;
    if wifi_mac(&texts)? != value {
        if !matches!(value.as_str(), "stable" | "random") {
            return Err(plain(CHANGE_FAILED));
        }
        cx.write_text(
            WIFI_MAC_DROPIN,
            &format!("{NOTE}[connection.90-secblitz-wifi-mac]\nwifi.cloned-mac-address={value}\n"),
            0o644,
        )?;
    }
    reload_network_manager(cx)
}
