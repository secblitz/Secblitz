//! Network protections: whether this computer accepts or sends route changes ("redirects") and whether it answers name
//! lookups from other computers on the local network.
//!
//! A kernel network setting is kept per network connection, and a connection follows a redirect when either the shared
//! `all` value or its own value is on. So every connection is read, and a fix turns every one of them off. An undo puts
//! each recorded value back and takes the settings out of Secblitz's own file.

use super::kernel::{NOTE, SYSCTL};
use super::{
    ini, num_of, observation, plain, text_item, text_of, unavailable, units, Cx, Items,
    CHANGE_FAILED, NO_RECORD, UNRECOGNISED,
};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::Result;
use std::collections::BTreeSet;

const REDIRECTS_DROPIN: &str = "/etc/sysctl.d/90-secblitz-network-redirects.conf";
const REDIRECTS_MEMO: &str = "network_redirects";
const CONF_DIRS: [(&str, &str); 2] = [
    ("net.ipv4", "/proc/sys/net/ipv4/conf"),
    ("net.ipv6", "/proc/sys/net/ipv6/conf"),
];
/// Each key and whether the second (IPv6) family has it too.
const REDIRECT_KEYS: [(&str, bool); 2] = [("accept_redirects", true), ("send_redirects", false)];

fn families(both: bool) -> &'static [(&'static str, &'static str)] {
    if both {
        &CONF_DIRS
    } else {
        &CONF_DIRS[..1]
    }
}

fn interface_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name.chars().all(|c| c.is_ascii_graphic())
}

/// Every connection folder of the setting that exists now, `lo` left out, as `/proc/sys/...` file paths.
fn redirect_paths(cx: &Cx, key: &str, both: bool) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for (_, dir) in families(both) {
        let mut names = vec!["all".to_string(), "default".to_string()];
        names.extend(
            cx.list(dir)
                .into_iter()
                .filter(|n| n != "lo" && n != "all" && n != "default" && interface_ok(n)),
        );
        for name in names {
            let path = format!("{dir}/{name}/{key}");
            if cx.text(&path)?.is_some() {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

fn path_value(cx: &Cx, path: &str) -> Result<u32> {
    Ok(cx
        .text(path)?
        .and_then(|t| t.trim().parse::<u32>().ok())
        .unwrap_or(0))
}

pub fn observe_redirects(cx: &Cx) -> Result<Observation> {
    let mut pairs = Vec::new();
    for (key, both) in REDIRECT_KEYS {
        let paths = redirect_paths(cx, key, both)?;
        let item = if paths.is_empty() {
            Item::Absent
        } else {
            let mut on = false;
            for path in &paths {
                on |= path_value(cx, path)? != 0;
            }
            super::flag(on)
        };
        pairs.push((key, item));
    }
    Ok(observation(pairs, true, ""))
}

/// The keys Secblitz's own file sets now.
fn persisted(cx: &Cx) -> Result<BTreeSet<&'static str>> {
    let mut kept = BTreeSet::new();
    if let Some(text) = cx.text(REDIRECTS_DROPIN)? {
        for (key, _) in REDIRECT_KEYS {
            if text
                .lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains(&format!(".{key} ")))
            {
                kept.insert(key);
            }
        }
    }
    Ok(kept)
}

fn write_redirects_file(cx: &Cx, keys: &BTreeSet<&'static str>) -> Result<()> {
    if keys.is_empty() {
        return cx.remove(REDIRECTS_DROPIN);
    }
    let mut text = String::from(NOTE);
    for (key, both) in REDIRECT_KEYS {
        if !keys.contains(key) {
            continue;
        }
        for (family, _) in families(both) {
            for name in ["all", "default", "*"] {
                text.push_str(&format!("{family}.conf.{name}.{key} = 0\n"));
            }
        }
    }
    cx.write_text(REDIRECTS_DROPIN, &text, 0o644)
}

fn set_path(cx: &Cx, path: &str, value: u32) -> Result<()> {
    let name = path.strip_prefix("/proc/sys/").unwrap_or(path);
    cx.run_ok(SYSCTL, &["-w", &format!("{name}={value}")])?;
    Ok(())
}

/// A recorded line is `<path> <value>` for a path this control could have listed itself.
fn parse_record(line: &str, key: &str) -> Result<Option<(String, u32)>> {
    let (path, value) = line.split_once(' ').ok_or_else(|| plain(NO_RECORD))?;
    let value: u32 = value.parse().map_err(|_| plain(NO_RECORD))?;
    let Some(rest) = CONF_DIRS
        .iter()
        .find_map(|(_, dir)| path.strip_prefix(&format!("{dir}/")))
    else {
        return Err(plain(NO_RECORD));
    };
    let (name, file) = rest.split_once('/').ok_or_else(|| plain(NO_RECORD))?;
    if !interface_ok(name) || file.contains('/') || !REDIRECT_KEYS.iter().any(|(k, _)| *k == file) {
        return Err(plain(NO_RECORD));
    }
    Ok((file == key).then(|| (path.to_string(), value)))
}

pub fn write_redirects(cx: &Cx, want: &Items) -> Result<()> {
    let mut keep = persisted(cx)?;
    let memo = cx.memo_read(REDIRECTS_MEMO)?;
    let mut record = memo.clone().unwrap_or_default();
    let mut changes: Vec<(String, u32)> = Vec::new();
    let mut touched = false;
    for (key, both) in REDIRECT_KEYS {
        match num_of(want, key)? {
            Some(0) => {
                let mut fresh = Vec::new();
                let mut on = false;
                for path in redirect_paths(cx, key, both)? {
                    let value = path_value(cx, &path)?;
                    if value != 0 {
                        on = true;
                        if !record.iter().any(|l| l.starts_with(&format!("{path} "))) {
                            fresh.push(format!("{path} {value}"));
                        }
                        changes.push((path, 0));
                    }
                }
                if on {
                    record.extend(fresh);
                    keep.insert(key);
                    touched = true;
                }
            }
            Some(1) => {
                if memo.is_none() {
                    return Err(plain(NO_RECORD));
                }
                let mut left = Vec::new();
                for line in &record {
                    match parse_record(line, key)? {
                        Some((path, value)) => {
                            if cx.text(&path)?.is_some() {
                                changes.push((path, value));
                            }
                        }
                        None => left.push(line.clone()),
                    }
                }
                record = left;
                keep.remove(key);
                touched = true;
            }
            Some(_) => return Err(plain(UNRECOGNISED)),
            None => {}
        }
    }
    if !touched {
        return Ok(());
    }
    if record.is_empty() {
        cx.memo_clear(REDIRECTS_MEMO)?;
    } else {
        cx.memo_write(REDIRECTS_MEMO, &record)?;
    }
    write_redirects_file(cx, &keep)?;
    for (path, value) in changes {
        set_path(cx, &path, value)?;
    }
    Ok(())
}

const RESOLVED_CONF: &str = "/etc/systemd/resolved.conf";
const RESOLVED_DIRS: [&str; 3] = [
    "/usr/lib/systemd/resolved.conf.d",
    "/run/systemd/resolved.conf.d",
    "/etc/systemd/resolved.conf.d",
];
const LLMNR_DROPIN: &str = "/etc/systemd/resolved.conf.d/90-secblitz.conf";
const RESOLVED_UNIT: &str = "systemd-resolved.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// The word systemd uses for the setting; `None` when the text is not one it knows.
fn llmnr_word(value: &str) -> Option<&'static str> {
    Some(match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" | "on" => "yes",
        "no" | "false" | "0" | "off" => "no",
        "resolve" => "resolve",
        _ => return None,
    })
}

/// What systemd-resolved is told to do: the main file, then the files of the three folders by name, where a file in a
/// later folder replaces one of the same name and a later name wins. With nothing said, it answers.
fn effective_llmnr(cx: &Cx) -> Result<Option<&'static str>> {
    let mut by_name = std::collections::BTreeMap::new();
    for dir in RESOLVED_DIRS {
        for name in cx.list(dir) {
            if name.ends_with(".conf") {
                by_name.insert(name.clone(), format!("{dir}/{name}"));
            }
        }
    }
    let mut texts = Vec::new();
    if let Some(main) = cx.text(RESOLVED_CONF)? {
        texts.push(main);
    }
    for path in by_name.into_values() {
        if let Some(text) = cx.text(&path)? {
            texts.push(text);
        }
    }
    let mut word = Some("yes");
    for text in &texts {
        if let Some(value) = ini::get(text, &["Resolve"], "LLMNR") {
            word = llmnr_word(&value);
        }
    }
    Ok(word)
}

fn resolver_active(cx: &Cx) -> bool {
    units::probe(cx, RESOLVED_UNIT).is_some_and(|u| u.active)
}

pub fn observe_llmnr(cx: &Cx) -> Result<Observation> {
    if !resolver_active(cx) {
        return Ok(observation(vec![("llmnr", Item::Absent)], true, ""));
    }
    match effective_llmnr(cx)? {
        Some(word) => Ok(observation(vec![("llmnr", text_item(word))], true, "")),
        None => Ok(unavailable("linux.llmnr", UNRECOGNISED)),
    }
}

pub fn write_llmnr(cx: &Cx, want: &Items) -> Result<()> {
    let Some(word) = text_of(want, "llmnr")? else {
        return Ok(());
    };
    cx.remove(LLMNR_DROPIN)?;
    if effective_llmnr(cx)? != Some(llmnr_word(word).ok_or_else(|| plain(UNRECOGNISED))?) {
        if word != "no" {
            return Err(plain(CHANGE_FAILED));
        }
        cx.write_text(LLMNR_DROPIN, &format!("{NOTE}[Resolve]\nLLMNR=no\n"), 0o644)?;
        if effective_llmnr(cx)? != Some("no") {
            cx.remove(LLMNR_DROPIN)?;
            return Err(plain(CHANGE_FAILED));
        }
    }
    cx.run_ok(SYSTEMCTL, &["try-restart", RESOLVED_UNIT])?;
    Ok(())
}
