//! Kernel settings that keep one program from reading another's secrets: hidden kernel addresses, a private kernel log,
//! protection of shared folders and the rule for looking inside other running programs. The running value is read from
//! `/proc/sys`; a fix sets it and keeps it after a restart in the control's own file, an undo puts the recorded value
//! back and takes the key out of that file.

use super::{observation, plain, Cx, Items, UNRECOGNISED};
use crate::hardening::{item_is_safe, Item};
use crate::linux::catalog::spec;
use crate::model::Observation;
use anyhow::Result;
use std::collections::BTreeMap;

pub const NOTE: &str = "# Written by Secblitz. Delete this file to go back to how it was.\n";
pub const SYSCTL: &str = "/usr/sbin/sysctl";

/// A control made of running kernel settings, each kept after a restart in the control's own file.
pub(super) struct Def {
    pub(super) id: &'static str,
    pub(super) dropin: &'static str,
    pub(super) keys: &'static [(&'static str, &'static str)],
}

const PROTECTIONS: Def = Def {
    id: "linux.kernel_protections",
    dropin: "/etc/sysctl.d/90-secblitz.conf",
    keys: &[
        ("kptr_restrict", "kernel.kptr_restrict"),
        ("dmesg_restrict", "kernel.dmesg_restrict"),
        ("protected_hardlinks", "fs.protected_hardlinks"),
        ("protected_symlinks", "fs.protected_symlinks"),
        ("protected_fifos", "fs.protected_fifos"),
        ("protected_regular", "fs.protected_regular"),
    ],
};

const PTRACE: Def = Def {
    id: "linux.ptrace",
    dropin: "/etc/sysctl.d/90-secblitz-ptrace.conf",
    keys: &[("ptrace_scope", "kernel.yama.ptrace_scope")],
};

fn proc_path(sysctl: &str) -> String {
    format!("/proc/sys/{}", sysctl.replace('.', "/"))
}

pub(super) fn running(cx: &Cx, sysctl: &str) -> Result<Item> {
    Ok(match cx.text(&proc_path(sysctl))? {
        Some(text) => text.trim().parse::<u32>().map_or(Item::Absent, Item::Num),
        None => Item::Absent,
    })
}

pub fn observe(cx: &Cx) -> Result<Observation> {
    observe_def(cx, &PROTECTIONS)
}

/// A computer without the Yama module has no such file, so nothing is offered there.
pub fn observe_ptrace(cx: &Cx) -> Result<Observation> {
    observe_def(cx, &PTRACE)
}

pub(super) fn observe_def(cx: &Cx, def: &Def) -> Result<Observation> {
    let mut pairs = Vec::new();
    for (key, sysctl) in def.keys {
        pairs.push((*key, running(cx, sysctl)?));
    }
    Ok(observation(pairs, true, ""))
}

/// The keys the control's own file sets now.
fn kept(cx: &Cx, def: &Def) -> Result<BTreeMap<&'static str, u32>> {
    let mut kept = BTreeMap::new();
    if let Some(text) = cx.text(def.dropin)? {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            if let (Some((key, _)), Ok(v)) = (
                def.keys.iter().find(|(_, s)| *s == name.trim()),
                value.trim().parse::<u32>(),
            ) {
                kept.insert(*key, v);
            }
        }
    }
    Ok(kept)
}

pub fn write(cx: &Cx, want: &Items) -> Result<()> {
    write_def(cx, want, &PROTECTIONS)
}

pub fn write_ptrace(cx: &Cx, want: &Items) -> Result<()> {
    write_def(cx, want, &PTRACE)
}

pub(super) fn write_def(cx: &Cx, want: &Items, def: &Def) -> Result<()> {
    let catalog = spec(def.id).ok_or_else(|| plain(UNRECOGNISED))?;
    let mut persist = kept(cx, def)?;
    let mut apply: Vec<(&'static str, u32)> = Vec::new();
    for (key, sysctl) in def.keys {
        let (key, sysctl) = (*key, *sysctl);
        let Some(Item::Num(value)) = want.get(key) else {
            continue;
        };
        if running(cx, sysctl)? == Item::Num(*value) && !persist.contains_key(key) {
            continue;
        }
        let rule = catalog
            .keys
            .iter()
            .find(|k| k.name == key)
            .map(|k| k.rule)
            .ok_or_else(|| plain(UNRECOGNISED))?;
        if item_is_safe(rule, &Item::Num(*value)) {
            persist.insert(key, *value);
        } else {
            persist.remove(key);
        }
        apply.push((sysctl, *value));
    }
    if apply.is_empty() {
        return Ok(());
    }
    if persist.is_empty() {
        cx.remove(def.dropin)?;
    } else {
        let mut text = String::from(NOTE);
        for (key, sysctl) in def.keys {
            if let Some(v) = persist.get(key) {
                text.push_str(&format!("{sysctl} = {v}\n"));
            }
        }
        cx.write_text(def.dropin, &text, 0o644)?;
    }
    for (sysctl, value) in apply {
        cx.run_ok(SYSCTL, &["-w", &format!("{sysctl}={value}")])?;
    }
    Ok(())
}
