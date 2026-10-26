//! The firewall (ufw on the Debian family, firewalld on Fedora) and the wide port ranges of Fedora Workstation.
//!
//! `enabled` is "yes" when the firewall is running; `incoming` is what happens to connections from other computers
//! that nothing allowed: "deny" drops them silently, "reject" answers that they are refused, "allow" lets them in.

use super::units::{self, Unit};
use super::{
    ini, observation, plain, text_item, text_of, unavailable, Cx, Items, FIREWALL_MASKED,
    FIREWALL_UNREADABLE, NO_FIREWALL, UNRECOGNISED,
};
use crate::hardening::Item;
use crate::linux::distro::Family;
use crate::model::Observation;
use anyhow::{bail, Result};

const UFW: &str = "/usr/sbin/ufw";
const FIREWALL_CMD: &str = "/usr/bin/firewall-cmd";
const FIREWALL_OFFLINE_CMD: &str = "/usr/bin/firewall-offline-cmd";
const FIREWALLD: &str = "firewalld.service";
const MEMO: &str = "firewalld";
/// A range of at least this many ports counts as wide.
const WIDE: u32 = 1000;
const MAX_RANGES: usize = 8;

enum Tool {
    Ufw,
    Firewalld(Unit),
}

fn choose(cx: &Cx) -> Option<Tool> {
    let ufw = || {
        cx.run(UFW, &["version"])
            .is_ok_and(|o| o.success())
            .then_some(Tool::Ufw)
    };
    let firewalld = || units::probe(cx, FIREWALLD).map(Tool::Firewalld);
    match cx.distro.family {
        Family::Fedora => firewalld().or_else(ufw),
        _ => ufw().or_else(firewalld),
    }
}

fn yes_no(on: bool) -> Item {
    text_item(if on { "yes" } else { "no" })
}

pub fn observe_firewall(cx: &Cx) -> Result<Observation> {
    match choose(cx) {
        None => Ok(unavailable("linux.firewall", NO_FIREWALL)),
        Some(Tool::Ufw) => Ok(observe_ufw(cx)),
        Some(Tool::Firewalld(unit)) => Ok(observe_firewalld(cx, &unit)),
    }
}

pub fn write_firewall(cx: &Cx, want: &Items) -> Result<()> {
    match choose(cx) {
        None => Err(plain(NO_FIREWALL)),
        Some(Tool::Ufw) => write_ufw(cx, want),
        Some(Tool::Firewalld(unit)) => write_firewalld(cx, &unit, want),
    }
}

fn ufw_enabled(cx: &Cx) -> Option<bool> {
    if let Ok(out) = cx.run(UFW, &["status"]) {
        if out.success() {
            match out.stdout.lines().next().map(str::trim) {
                Some("Status: active") => return Some(true),
                Some("Status: inactive") => return Some(false),
                _ => {}
            }
        }
    }
    let conf = cx.text("/etc/ufw/ufw.conf").ok()??;
    match ini::get(&conf, &[""], "ENABLED")?
        .to_ascii_lowercase()
        .as_str()
    {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

fn ufw_incoming(cx: &Cx) -> Option<&'static str> {
    let text = cx.text("/etc/default/ufw").ok()??;
    match ini::get(&text, &[""], "DEFAULT_INPUT_POLICY")?.as_str() {
        "DROP" => Some("deny"),
        "REJECT" => Some("reject"),
        "ACCEPT" => Some("allow"),
        _ => None,
    }
}

fn observe_ufw(cx: &Cx) -> Observation {
    let enabled = ufw_enabled(cx).map_or(Item::Absent, yes_no);
    let incoming = ufw_incoming(cx).map_or(Item::Absent, text_item);
    observation(vec![("enabled", enabled), ("incoming", incoming)], true, "")
}

fn write_ufw(cx: &Cx, want: &Items) -> Result<()> {
    let enabled = text_of(want, "enabled")?;
    let incoming = text_of(want, "incoming")?;
    let now_on = ufw_enabled(cx) == Some(true);
    if enabled == Some("no") && now_on {
        cx.run_ok(UFW, &["disable"])?;
    }
    if let Some(policy) = incoming {
        if !matches!(policy, "deny" | "reject" | "allow") {
            return Err(plain(UNRECOGNISED));
        }
        if ufw_incoming(cx) != Some(policy) {
            cx.run_ok(UFW, &["default", policy, "incoming"])?;
        }
    }
    if enabled == Some("yes") && !now_on {
        cx.run_ok(UFW, &["--force", "enable"])?;
    }
    Ok(())
}

/// firewalld's own commands, for the running service or, when it is stopped, for its files.
struct Fw<'a, 'b> {
    cx: &'b Cx<'a>,
    running: bool,
}

impl Fw<'_, '_> {
    fn query(&self, args: &[&str], permanent: bool) -> Result<String> {
        let out = if self.running {
            let mut all = Vec::new();
            if permanent {
                all.push("--permanent");
            }
            all.extend_from_slice(args);
            self.cx.run_ok(FIREWALL_CMD, &all)?
        } else {
            self.cx.run_ok(FIREWALL_OFFLINE_CMD, args)?
        };
        Ok(out.stdout.trim().to_string())
    }

    fn change(&self, args: &[&str]) -> Result<()> {
        self.query(args, true).map(drop)
    }

    fn reload(&self) -> Result<()> {
        if self.running {
            self.cx.run_ok(FIREWALL_CMD, &["--reload"])?;
        }
        Ok(())
    }

    fn default_zone(&self) -> Result<String> {
        let zone = self.query(&["--get-default-zone"], false)?;
        if zone.is_empty()
            || zone.len() > 64
            || !zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            bail!("unusual default zone {zone:?}");
        }
        Ok(zone)
    }

    fn incoming(&self, zone: &str) -> Result<&'static str> {
        let flag = format!("--zone={zone}");
        Ok(match self.query(&[&flag, "--get-target"], true)?.as_str() {
            "DROP" => "deny",
            "REJECT" | "%%REJECT%%" | "default" => "reject",
            "ACCEPT" => "allow",
            other => bail!("unusual zone target {other:?}"),
        })
    }

    fn ports(&self, zone: &str) -> Result<String> {
        let flag = format!("--zone={zone}");
        self.query(&[&flag, "--list-ports"], true)
    }
}

fn observe_firewalld(cx: &Cx, unit: &Unit) -> Observation {
    if unit.masked() {
        return unavailable("linux.firewall", FIREWALL_MASKED);
    }
    let enabled = yes_no(unit.enabled() && unit.active);
    let fw = Fw {
        cx,
        running: unit.active,
    };
    let incoming = fw.default_zone().and_then(|zone| fw.incoming(&zone));
    match incoming {
        Ok(incoming) => observation(
            vec![("enabled", enabled), ("incoming", text_item(incoming))],
            true,
            "",
        ),
        Err(e) => {
            eprintln!("secblitz: firewalld: {e:#}");
            observation(
                vec![("enabled", enabled), ("incoming", Item::Absent)],
                false,
                FIREWALL_UNREADABLE,
            )
        }
    }
}

fn write_firewalld(cx: &Cx, unit: &Unit, want: &Items) -> Result<()> {
    if unit.masked() {
        return Err(plain(FIREWALL_MASKED));
    }
    let enabled = text_of(want, "enabled")?;
    let incoming = text_of(want, "incoming")?;
    let on = unit.enabled() && unit.active;
    let fw = Fw {
        cx,
        running: unit.active,
    };
    if enabled == Some("yes") && !on {
        cx.memo_write(
            MEMO,
            &[format!(
                "{FIREWALLD} {} {}",
                u8::from(unit.enabled()),
                u8::from(unit.active)
            )],
        )?;
    }
    if let Some(policy) = incoming {
        let target = match policy {
            "deny" => "DROP",
            "reject" => "default",
            "allow" => "ACCEPT",
            _ => return Err(plain(UNRECOGNISED)),
        };
        let zone = fw.default_zone()?;
        if fw.incoming(&zone)? != policy {
            fw.change(&[&format!("--zone={zone}"), &format!("--set-target={target}")])?;
            fw.reload()?;
        }
    }
    match enabled {
        Some("yes") if !on => units::enable_now(cx, FIREWALLD)?,
        Some("no") if on => restore_firewalld(cx, unit)?,
        _ => {}
    }
    Ok(())
}

fn restore_firewalld(cx: &Cx, unit: &Unit) -> Result<()> {
    let before = match cx.memo_read(MEMO)? {
        None => None,
        Some(lines) => match lines.first().map(String::as_str) {
            Some("firewalld.service 0 0") => Some((false, false)),
            Some("firewalld.service 0 1") => Some((false, true)),
            Some("firewalld.service 1 0") => Some((true, false)),
            Some("firewalld.service 1 1") => Some((true, true)),
            _ => return Err(plain(super::NO_RECORD)),
        },
    };
    let (was_enabled, was_active) = before.unwrap_or((false, false));
    units::settle(cx, unit, was_enabled, was_active)?;
    cx.memo_clear(MEMO)
}

/// A range such as `1025-65535/tcp`, as numbers and the protocol.
fn range(token: &str) -> Option<(u32, u32, &str)> {
    let (ports, proto) = token.split_once('/')?;
    let (from, to) = ports.split_once('-')?;
    let digits = |s: &str| s.len() <= 5 && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(from) || !digits(to) || !matches!(proto, "tcp" | "udp") {
        return None;
    }
    let (from, to): (u32, u32) = (from.parse().ok()?, to.parse().ok()?);
    ((1..=65535).contains(&from) && (1..=65535).contains(&to) && from <= to)
        .then_some((from, to, proto))
}

fn wide_ranges(ports: &str) -> Vec<String> {
    let mut wide: Vec<String> = ports
        .split_whitespace()
        .filter(|t| range(t).is_some_and(|(a, b, _)| b - a + 1 >= WIDE))
        .map(str::to_string)
        .collect();
    wide.sort();
    wide.dedup();
    wide
}

pub fn observe_open_ports(cx: &Cx) -> Result<Observation> {
    let Some(unit) = units::probe(cx, FIREWALLD).filter(|u| !u.masked()) else {
        return Ok(observation(vec![("open_ranges", Item::Absent)], true, ""));
    };
    let fw = Fw {
        cx,
        running: unit.active,
    };
    match fw.default_zone().and_then(|zone| fw.ports(&zone)) {
        Ok(ports) => {
            let wide = wide_ranges(&ports);
            let item = if wide.is_empty() {
                Item::Absent
            } else {
                text_item(wide.join(" "))
            };
            Ok(observation(vec![("open_ranges", item)], true, ""))
        }
        Err(e) => {
            eprintln!("secblitz: firewalld ports: {e:#}");
            Ok(unavailable("linux.fedora_open_ports", FIREWALL_UNREADABLE))
        }
    }
}

pub fn write_open_ports(cx: &Cx, want: &Items) -> Result<()> {
    let wanted: Vec<String> = match text_of(want, "open_ranges")? {
        None => Vec::new(),
        Some(text) => {
            let tokens: Vec<&str> = text.split(' ').collect();
            let legal = tokens.len() <= MAX_RANGES
                && tokens
                    .iter()
                    .all(|t| range(t).is_some_and(|(a, b, _)| b - a + 1 >= WIDE));
            if !legal {
                return Err(plain(UNRECOGNISED));
            }
            tokens.into_iter().map(str::to_string).collect()
        }
    };
    let unit = units::probe(cx, FIREWALLD)
        .filter(|u| !u.masked())
        .ok_or_else(|| plain(NO_FIREWALL))?;
    let fw = Fw {
        cx,
        running: unit.active,
    };
    let zone = fw.default_zone()?;
    let zone_flag = format!("--zone={zone}");
    let current = wide_ranges(&fw.ports(&zone)?);
    for port in current.iter().filter(|p| !wanted.contains(p)) {
        fw.change(&[&zone_flag, &format!("--remove-port={port}")])?;
    }
    for port in wanted.iter().filter(|p| !current.contains(p)) {
        fw.change(&[&zone_flag, &format!("--add-port={port}")])?;
    }
    fw.reload()
}
