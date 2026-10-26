//! Automatic security updates: `unattended-upgrades` on the Debian family, `dnf5 automatic` on Fedora.
//!
//! `unattended` is the number of days between automatic updates, 0 when they are off. Secblitz never installs the
//! updater; it only switches on one that is already there.

use super::units::{self, Unit};
use super::{ini, num_of, observation, plain, unavailable, Cx, Items, NO_AUTO_UPDATES, NO_RECORD};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::Result;

const APT_DROPIN: &str = "/etc/apt/apt.conf.d/52secblitz-auto-upgrades";
const APT_NOTE: &str = "// Written by Secblitz. Delete this file to go back to how it was.\n";
const DNF_CONF: &str = "/etc/dnf/automatic.conf";
const DNF_FILES: [&str; 3] = [
    "/usr/share/dnf5/dnf5-plugins/automatic.conf",
    "/etc/dnf/dnf5-plugins/automatic.conf",
    DNF_CONF,
];
const TIMER: &str = "dnf5-automatic.timer";
const MEMO: &str = "dnf-automatic";
const MAX_DAYS: u32 = 365;

enum Updater {
    Apt,
    Dnf(Option<Unit>),
}

fn choose(cx: &Cx) -> Updater {
    // dpkg-query exists only where packages are .deb files.
    if cx.run("/usr/bin/dpkg-query", &["--version"]).is_ok() {
        Updater::Apt
    } else {
        Updater::Dnf(units::probe(cx, TIMER))
    }
}

pub fn observe(cx: &Cx) -> Result<Observation> {
    match choose(cx) {
        Updater::Apt => observe_apt(cx),
        Updater::Dnf(timer) => observe_dnf(cx, timer),
    }
}

pub fn write(cx: &Cx, want: &Items) -> Result<()> {
    let Some(days) = num_of(want, "unattended")? else {
        return Ok(());
    };
    if days > MAX_DAYS {
        return Err(plain(super::UNRECOGNISED));
    }
    match choose(cx) {
        Updater::Apt => write_apt(cx, days),
        Updater::Dnf(timer) => write_dnf(cx, timer, days),
    }
}

fn apt_installed(cx: &Cx) -> Result<bool> {
    let out = cx.run(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${Status}", "unattended-upgrades"],
    )?;
    Ok(out.success() && out.stdout.trim() == "install ok installed")
}

/// The days between automatic updates and whether the package lists are refreshed, as apt reads its settings now.
fn periodic(cx: &Cx) -> Result<(u32, u32)> {
    let out = cx.run_ok("/usr/bin/apt-config", &["dump"])?;
    let number = |key: &str| {
        out.stdout
            .lines()
            .filter_map(|l| l.strip_prefix(key))
            .filter_map(|rest| {
                rest.trim()
                    .trim_end_matches(';')
                    .trim()
                    .trim_matches('"')
                    .parse::<u32>()
                    .ok()
            })
            .next_back()
            .unwrap_or(0)
            .min(MAX_DAYS)
    };
    Ok((
        number("APT::Periodic::Unattended-Upgrade "),
        number("APT::Periodic::Update-Package-Lists "),
    ))
}

fn observe_apt(cx: &Cx) -> Result<Observation> {
    if !apt_installed(cx).unwrap_or(false) {
        return Ok(unavailable("linux.auto_updates", NO_AUTO_UPDATES));
    }
    let (days, _) = periodic(cx)?;
    Ok(observation(vec![("unattended", Item::Num(days))], true, ""))
}

/// Our own drop-in is removed first, so an undo returns to what the other files say; it is written again only when
/// they do not already give the wanted value.
fn write_apt(cx: &Cx, days: u32) -> Result<()> {
    cx.remove(APT_DROPIN)?;
    let (now, lists) = periodic(cx)?;
    if now == days {
        return Ok(());
    }
    let mut text = String::from(APT_NOTE);
    if days > 0 && lists == 0 {
        text.push_str("APT::Periodic::Update-Package-Lists \"1\";\n");
    }
    text.push_str(&format!("APT::Periodic::Unattended-Upgrade \"{days}\";\n"));
    cx.write_text(APT_DROPIN, &text, 0o644)
}

fn dnf_applies(cx: &Cx) -> Result<bool> {
    let mut apply = None;
    for path in DNF_FILES {
        if let Some(text) = cx.text(path)? {
            if let Some(v) = ini::get(&text, &["commands"], "apply_updates") {
                apply = Some(v);
            }
        }
    }
    Ok(apply
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")))
}

fn observe_dnf(cx: &Cx, timer: Option<Unit>) -> Result<Observation> {
    let Some(timer) = timer.filter(|t| !t.masked()) else {
        return Ok(unavailable("linux.auto_updates", NO_AUTO_UPDATES));
    };
    let on = timer.enabled() && dnf_applies(cx)?;
    Ok(observation(
        vec![("unattended", Item::Num(u32::from(on)))],
        true,
        "",
    ))
}

fn write_dnf(cx: &Cx, timer: Option<Unit>, days: u32) -> Result<()> {
    let timer = timer
        .filter(|t| !t.masked())
        .ok_or_else(|| plain(NO_AUTO_UPDATES))?;
    let own = cx.text(DNF_CONF)?;
    let key = |text: &Option<String>| {
        text.as_deref()
            .and_then(|t| ini::get(t, &["commands"], "apply_updates"))
    };
    if days > 0 {
        let already = timer.enabled() && dnf_applies(cx)?;
        if !already {
            let before = key(&own).unwrap_or_else(|| "absent".into());
            if before.is_empty() || before.contains(char::is_whitespace) {
                return Err(plain(super::UNRECOGNISED));
            }
            cx.memo_write(
                MEMO,
                &[
                    format!(
                        "timer {} {}",
                        u8::from(timer.enabled()),
                        u8::from(timer.active)
                    ),
                    format!("apply {before}"),
                ],
            )?;
        }
        let text = ini::set(
            own.as_deref().unwrap_or(""),
            "commands",
            "apply_updates",
            "yes",
        );
        cx.write_text(DNF_CONF, &text, 0o644)?;
        if !timer.enabled() {
            units::enable_now(cx, TIMER)?;
        }
        return Ok(());
    }
    let lines = cx.memo_read(MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
    let (Some(timer_line), Some(apply_line)) = (lines.first(), lines.get(1)) else {
        return Err(plain(NO_RECORD));
    };
    let flags: Vec<&str> = timer_line.split(' ').collect();
    let (was_enabled, was_active) = match flags.as_slice() {
        ["timer", e, a] => (*e == "1", *a == "1"),
        _ => return Err(plain(NO_RECORD)),
    };
    let previous = apply_line
        .strip_prefix("apply ")
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_graphic()))
        .ok_or_else(|| plain(NO_RECORD))?;
    let current = own.unwrap_or_default();
    if previous == "absent" {
        let text = ini::unset(&current, &["commands"], "apply_updates");
        if ini::has_assignments(&text) {
            cx.write_text(DNF_CONF, &text, 0o644)?;
        } else {
            cx.remove(DNF_CONF)?;
        }
    } else {
        cx.write_text(
            DNF_CONF,
            &ini::set(&current, "commands", "apply_updates", previous),
            0o644,
        )?;
    }
    units::settle(cx, &timer, was_enabled, was_active)?;
    cx.memo_clear(MEMO)
}
