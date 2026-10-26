//! Services and sockets of the system manager: reading whether they are on, switching them off and putting them back
//! as they were. What was on is written down first, so an undo returns exactly the units that were switched off.

use super::{plain, Cx, NO_RECORD};
use anyhow::Result;

const SYSTEMCTL: &str = "/usr/bin/systemctl";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub name: &'static str,
    pub state: String,
    pub active: bool,
}

impl Unit {
    pub fn enabled(&self) -> bool {
        matches!(self.state.as_str(), "enabled" | "enabled-runtime")
    }

    /// Another name for a unit that is listed on its own.
    pub fn alias(&self) -> bool {
        self.state == "alias"
    }

    pub fn masked(&self) -> bool {
        self.state.starts_with("masked")
    }

    pub fn on(&self) -> bool {
        !self.alias() && (self.enabled() || self.active)
    }
}

/// The unit as the system manager knows it, or `None` when there is no such unit or no system manager.
pub fn probe(cx: &Cx, name: &'static str) -> Option<Unit> {
    let out = cx.run(SYSTEMCTL, &["is-enabled", name]).ok()?;
    let state = out.stdout.lines().next().unwrap_or("").trim().to_string();
    if state.is_empty() || state == "not-found" {
        return None;
    }
    let active = cx
        .run(SYSTEMCTL, &["is-active", name])
        .is_ok_and(|o| o.stdout.trim() == "active");
    Some(Unit {
        name,
        state,
        active,
    })
}

pub fn probe_all(cx: &Cx, names: &[&'static str]) -> Vec<Unit> {
    names.iter().filter_map(|n| probe(cx, n)).collect()
}

fn known(names: &[&'static str], name: &str) -> Option<&'static str> {
    names.iter().copied().find(|n| *n == name)
}

/// Writes down which of the units are on, then switches those off. Nothing is written when none are on, so a second
/// fix cannot overwrite the record of the first.
pub fn switch_off(cx: &Cx, memo: &str, units: &[Unit]) -> Result<()> {
    let on: Vec<&Unit> = units.iter().filter(|u| u.on()).collect();
    if on.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = on
        .iter()
        .map(|u| {
            format!(
                "{} {} {}",
                u.name,
                u8::from(u.enabled()),
                u8::from(u.active)
            )
        })
        .collect();
    cx.memo_write(memo, &lines)?;
    for unit in on {
        if unit.enabled() {
            cx.run_ok(SYSTEMCTL, &["disable", "--now", unit.name])?;
        } else {
            cx.run_ok(SYSTEMCTL, &["stop", unit.name])?;
        }
    }
    Ok(())
}

/// Puts back exactly the units the record names. Without a record the first listed unit that exists is switched on.
pub fn switch_on(
    cx: &Cx,
    memo: &str,
    names: &[&'static str],
    fallback: &[&'static str],
) -> Result<()> {
    let Some(lines) = cx.memo_read(memo)? else {
        let unit = probe_all(cx, fallback)
            .into_iter()
            .find(|u| !u.alias() && !u.masked())
            .ok_or_else(|| plain(NO_RECORD))?;
        cx.run_ok(SYSTEMCTL, &["enable", "--now", unit.name])?;
        return Ok(());
    };
    let mut wanted = Vec::new();
    for line in &lines {
        let mut parts = line.split(' ');
        let (Some(name), Some(enabled), Some(active), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(plain(NO_RECORD));
        };
        let name = known(names, name).ok_or_else(|| plain(NO_RECORD))?;
        wanted.push((name, enabled == "1", active == "1"));
    }
    for (name, enabled, active) in wanted {
        if enabled {
            cx.run_ok(SYSTEMCTL, &["enable", name])?;
        }
        if active {
            cx.run_ok(SYSTEMCTL, &["start", name])?;
        }
    }
    cx.memo_clear(memo)?;
    Ok(())
}

/// Leaves the unit enabled and running only as far as it was before: it is never switched on by this.
pub fn settle(cx: &Cx, unit: &Unit, was_enabled: bool, was_active: bool) -> Result<()> {
    let off_enabled = unit.enabled() && !was_enabled;
    let off_active = unit.active && !was_active;
    if off_enabled && off_active {
        disable_now(cx, unit.name)
    } else if off_enabled {
        disable(cx, unit.name)
    } else if off_active {
        stop(cx, unit.name)
    } else {
        Ok(())
    }
}

/// Returns a unit to the enabled and running state it had before.
pub fn put_back(cx: &Cx, name: &'static str, enabled: bool, active: bool) -> Result<()> {
    cx.run_ok(
        SYSTEMCTL,
        &[if enabled { "enable" } else { "disable" }, name],
    )?;
    if active {
        start(cx, name)
    } else {
        stop(cx, name)
    }
}

pub fn reload(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["reload", name]).map(drop)
}

pub fn enable_now(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["enable", "--now", name]).map(drop)
}

pub fn disable_now(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["disable", "--now", name]).map(drop)
}

pub fn start(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["start", name]).map(drop)
}

pub fn stop(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["stop", name]).map(drop)
}

pub fn enable(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["enable", name]).map(drop)
}

pub fn disable(cx: &Cx, name: &'static str) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["disable", name]).map(drop)
}
