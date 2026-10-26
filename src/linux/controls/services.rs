//! Services the computer runs for itself: the clock, printer sharing, the finder of network printers, Ubuntu's news
//! downloads and the hold on snap app updates.
//!
//! `ntp` is 1 when the clock sets itself from the internet. `share_printers`, `remote_admin` and `remote_any` are 1 when
//! the printing service shares printers, lets other computers manage it, or accepts connections from any address.
//! `cups_protocol` is 1 when the printer finder is on and accepts announcements over the old printing protocol. `apt_news`
//! and `motd_news` are 1 when Ubuntu downloads news for update messages and for the sign-in text. `held` is 1 when snap
//! app updates are held back for good or for more than a week.

use super::units;
use super::{
    flag, ini, num_of, observation, plain, unavailable, Cx, Items, CHANGE_FAILED, NO_RECORD,
    UNRECOGNISED,
};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::{anyhow, Result};
use std::path::Path;

const TIMEDATECTL: &str = "/usr/bin/timedatectl";
const CUPSCTL: &str = "/usr/sbin/cupsctl";
const PRO: &str = "/usr/bin/pro";
const SNAP: &str = "/usr/bin/snap";
const DATE: &str = "/usr/bin/date";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const BROWSED_CONF: &str = "/etc/cups/cups-browsed.conf";
const BROWSED_UNIT: &str = "cups-browsed.service";
const MOTD_NEWS: &str = "/etc/default/motd-news";
const BROWSED_MEMO: &str = "printer-finder-file";
const MOTD_MEMO: &str = "ubuntu-news-file";
const SNAP_MEMO: &str = "snap-hold";
const WEEK: i64 = 7 * 24 * 3600;

pub const NO_TIME_SYNC: &str =
    "This computer cannot set its own clock from the internet, so Secblitz leaves this alone.";
pub const NO_PRINTING: &str =
    "Printing is not set up on this computer, so Secblitz leaves this alone.";
pub const NO_PRINTER_FINDER: &str =
    "The finder of network printers is not set up on this computer, so Secblitz leaves this alone.";
pub const NO_SNAP_STORE: &str =
    "Ubuntu's app store is not running on this computer, so Secblitz leaves this alone.";

/// Every sentence a person can be shown by these controls, for the translation tests.
pub const SENTENCES: [&str; 4] = [NO_TIME_SYNC, NO_PRINTING, NO_PRINTER_FINDER, NO_SNAP_STORE];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Keeps a file's exact bytes so an undo can write them back.
fn remember_file(cx: &Cx, memo: &str, bytes: &[u8]) -> Result<()> {
    cx.memo_write(memo, &[hex(bytes)])
}

fn remembered_file(cx: &Cx, memo: &str) -> Result<Option<Vec<u8>>> {
    let Some(lines) = cx.memo_read(memo)? else {
        return Ok(None);
    };
    match lines.as_slice() {
        [line] => unhex(line).map(Some).ok_or_else(|| plain(NO_RECORD)),
        _ => Err(plain(NO_RECORD)),
    }
}

fn put_back_file(cx: &Cx, path: &str, bytes: &[u8]) -> Result<()> {
    cx.sys.write_atomic(Path::new(path), bytes, 0o644)
}

fn two_state(want: &Items, key: &str) -> Result<Option<u32>> {
    match num_of(want, key)? {
        Some(n) if n > 1 => Err(plain(UNRECOGNISED)),
        other => Ok(other),
    }
}

/// `CanNTP` and `NTP` as the clock service reports them, or `None` when it cannot be asked.
fn clock(cx: &Cx) -> Option<(bool, bool)> {
    let out = cx.run(TIMEDATECTL, &["show"]).ok()?;
    if !out.success() {
        return None;
    }
    let value = |key: &str| {
        out.stdout
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim() == "yes")
    };
    Some((value("CanNTP")?, value("NTP")?))
}

pub fn observe_time_sync(cx: &Cx) -> Result<Observation> {
    match clock(cx) {
        Some((true, ntp)) => Ok(observation(vec![("ntp", flag(ntp))], true, "")),
        _ => Ok(unavailable("linux.time_sync", NO_TIME_SYNC)),
    }
}

pub fn write_time_sync(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = two_state(want, "ntp")? else {
        return Ok(());
    };
    match clock(cx) {
        Some((true, now)) if now != (on == 1) => cx
            .run_ok(
                TIMEDATECTL,
                &["set-ntp", if on == 1 { "true" } else { "false" }],
            )
            .map(drop),
        Some((true, _)) => Ok(()),
        _ => Err(plain(NO_TIME_SYNC)),
    }
}

const CUPS_KEYS: [(&str, &str, &str); 3] = [
    ("share_printers", "_share_printers", "share-printers"),
    ("remote_admin", "_remote_admin", "remote-admin"),
    ("remote_any", "_remote_any", "remote-any"),
];

/// The three printing service switches in the order of `CUPS_KEYS`, or `None` when they cannot be read.
fn cups_switches(cx: &Cx) -> Option<[bool; 3]> {
    let out = cx.run(CUPSCTL, &[]).ok()?;
    if !out.success() {
        return None;
    }
    let mut on = [false; 3];
    for (slot, (_, setting, _)) in on.iter_mut().zip(CUPS_KEYS) {
        let value = out
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix(setting)?.strip_prefix('='))?;
        *slot = match value.trim() {
            "1" => true,
            "0" => false,
            _ => return None,
        };
    }
    Some(on)
}

pub fn observe_printer_sharing(cx: &Cx) -> Result<Observation> {
    let Some(on) = cups_switches(cx) else {
        return Ok(unavailable("linux.printer_sharing", NO_PRINTING));
    };
    let pairs = CUPS_KEYS
        .iter()
        .zip(on)
        .map(|((key, _, _), on)| (*key, flag(on)))
        .collect();
    Ok(observation(pairs, true, ""))
}

pub fn write_printer_sharing(cx: &Cx, want: &Items) -> Result<()> {
    let now = cups_switches(cx).ok_or_else(|| plain(NO_PRINTING))?;
    let mut flags = Vec::new();
    for ((key, _, name), now) in CUPS_KEYS.iter().zip(now) {
        match two_state(want, key)? {
            Some(0) if now => flags.push(format!("--no-{name}")),
            Some(1) if !now => flags.push(format!("--{name}")),
            _ => {}
        }
    }
    if flags.is_empty() {
        return Ok(());
    }
    let args: Vec<&str> = flags.iter().map(String::as_str).collect();
    cx.run_ok(CUPSCTL, &args).map(drop)
}

/// The words of the last uncommented `BrowseRemoteProtocols` line, or `None` when there is none.
fn browse_protocols(text: &str) -> Option<Vec<String>> {
    text.lines().rev().find_map(|line| {
        let mut words = line.split_whitespace();
        if !words.next()?.eq_ignore_ascii_case("BrowseRemoteProtocols") {
            return None;
        }
        Some(
            words
                .flat_map(|w| w.split(','))
                .filter(|w| !w.is_empty())
                .map(str::to_ascii_lowercase)
                .collect(),
        )
    })
}

fn uses_old_protocol(words: &[String]) -> bool {
    words.iter().any(|w| w == "cups" || w == "all")
}

/// The file with every `BrowseRemoteProtocols` line rewritten without the old protocol and nothing else touched.
fn without_old_protocol(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for raw in text.split_inclusive('\n') {
        let mut words = raw.split_whitespace();
        if !words
            .next()
            .is_some_and(|w| w.eq_ignore_ascii_case("BrowseRemoteProtocols"))
        {
            out.push_str(raw);
            continue;
        }
        let mut kept: Vec<String> = Vec::new();
        for word in words.flat_map(|w| w.split(',')).filter(|w| !w.is_empty()) {
            let word = word.to_ascii_lowercase();
            let word = if word == "all" { "dnssd".into() } else { word };
            if word != "cups" && !kept.contains(&word) {
                kept.push(word);
            }
        }
        if kept.is_empty() {
            kept.push("none".into());
        }
        let indent = &raw[..raw.len() - raw.trim_start().len()];
        let ending = &raw[raw.trim_end_matches(['\r', '\n']).len()..];
        out.push_str(&format!(
            "{indent}BrowseRemoteProtocols {}{ending}",
            kept.join(" ")
        ));
    }
    out
}

/// The printer finder's file and whether it is on, or `None` when it is not installed or has no such line.
fn printer_finder(cx: &Cx) -> Result<Option<(String, bool)>> {
    let Some(unit) = units::probe(cx, BROWSED_UNIT) else {
        return Ok(None);
    };
    let Some(text) = cx.text(BROWSED_CONF)? else {
        return Ok(None);
    };
    let Some(words) = browse_protocols(&text) else {
        return Ok(None);
    };
    Ok(Some((text, unit.on() && uses_old_protocol(&words))))
}

pub fn observe_printer_discovery(cx: &Cx) -> Result<Observation> {
    match printer_finder(cx)? {
        Some((_, unsafe_now)) => Ok(observation(
            vec![("cups_protocol", flag(unsafe_now))],
            true,
            "",
        )),
        None => Ok(unavailable("linux.printer_discovery", NO_PRINTER_FINDER)),
    }
}

pub fn write_printer_discovery(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = two_state(want, "cups_protocol")? else {
        return Ok(());
    };
    let (text, now) = printer_finder(cx)?.ok_or_else(|| plain(NO_PRINTER_FINDER))?;
    if now == (on == 1) {
        return Ok(());
    }
    if on == 0 {
        remember_file(cx, BROWSED_MEMO, text.as_bytes())?;
        cx.write_text(BROWSED_CONF, &without_old_protocol(&text), 0o644)?;
    } else {
        let bytes = remembered_file(cx, BROWSED_MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
        put_back_file(cx, BROWSED_CONF, &bytes)?;
    }
    cx.run_ok(SYSTEMCTL, &["try-restart", BROWSED_UNIT])?;
    if on == 1 {
        cx.memo_clear(BROWSED_MEMO)?;
    }
    Ok(())
}

/// `apt_news` from the Ubuntu Pro tool: `None` when the tool is missing or says something unexpected.
fn apt_news(cx: &Cx) -> Option<bool> {
    let out = cx.run(PRO, &["config", "show"]).ok()?;
    if !out.success() {
        return None;
    }
    out.stdout.lines().find_map(|l| {
        let mut words = l.split_whitespace();
        if words.next()? != "apt_news" {
            return None;
        }
        match (words.next()?, words.next()) {
            ("True", None) => Some(true),
            ("False", None) => Some(false),
            _ => None,
        }
    })
}

fn motd_news(text: &str) -> bool {
    ini::get(text, &[""], "ENABLED").as_deref() == Some("1")
}

pub fn observe_ubuntu_news(cx: &Cx) -> Result<Observation> {
    let apt = apt_news(cx).map_or(Item::Absent, flag);
    let motd = cx
        .text(MOTD_NEWS)?
        .map_or(Item::Absent, |t| flag(motd_news(&t)));
    Ok(observation(
        vec![("apt_news", apt), ("motd_news", motd)],
        true,
        "",
    ))
}

pub fn write_ubuntu_news(cx: &Cx, want: &Items) -> Result<()> {
    if let Some(on) = two_state(want, "apt_news")? {
        if apt_news(cx).is_some_and(|now| now != (on == 1)) {
            let setting = if on == 1 {
                "apt_news=true"
            } else {
                "apt_news=false"
            };
            cx.run_ok(PRO, &["config", "set", setting])?;
        }
    }
    let Some(on) = two_state(want, "motd_news")? else {
        return Ok(());
    };
    let Some(text) = cx.text(MOTD_NEWS)? else {
        return Ok(());
    };
    if motd_news(&text) == (on == 1) {
        return Ok(());
    }
    if on == 0 {
        remember_file(cx, MOTD_MEMO, text.as_bytes())?;
        cx.write_text(MOTD_NEWS, &ini::set(&text, "", "ENABLED", "0"), 0o644)
    } else {
        let bytes = remembered_file(cx, MOTD_MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
        put_back_file(cx, MOTD_NEWS, &bytes)?;
        cx.memo_clear(MOTD_MEMO)
    }
}

/// Seconds since 1970 for a time such as `2026-10-26T05:44:41.238528701Z`, as the snap tool prints it.
fn rfc3339_seconds(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once('T')?;
    let mut d = date.split('-');
    let (year, month, day) = (
        d.next()?.parse::<i64>().ok()?,
        d.next()?.parse::<i64>().ok()?,
        d.next()?.parse::<i64>().ok()?,
    );
    if d.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let split = rest.find(['Z', '+', '-'])?;
    let (clock, zone) = rest.split_at(split);
    let mut c = clock.split(':');
    let (hour, minute) = (
        c.next()?.parse::<i64>().ok()?,
        c.next()?.parse::<i64>().ok()?,
    );
    let second = c.next()?.split('.').next()?.parse::<i64>().ok()?;
    if c.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let offset = match zone {
        "Z" => 0,
        _ => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let (h, m) = zone[1..].split_once(':')?;
            sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60)
        }
    };
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

struct SnapDown;

/// What `refresh.hold` says, or `None` when no hold is set.
fn snap_hold(cx: &Cx) -> Result<Option<String>, SnapDown> {
    let out = cx
        .run(SNAP, &["get", "system", "refresh.hold"])
        .map_err(|_| SnapDown)?;
    if out.success() {
        let value = out.stdout.trim();
        return Ok((!value.is_empty()).then(|| value.to_string()));
    }
    if out.stderr.contains("has no") && out.stderr.contains("refresh.hold") {
        return Ok(None);
    }
    Err(SnapDown)
}

fn now_seconds(cx: &Cx) -> Result<i64> {
    let out = cx.run_ok(DATE, &["-u", "+%s"])?;
    out.stdout
        .trim()
        .parse()
        .map_err(|_| anyhow!("the clock gave {:?}", out.stdout))
}

fn hold_is_long(cx: &Cx, value: &str) -> Result<bool> {
    if value == "forever" {
        return Ok(true);
    }
    let until = rfc3339_seconds(value).ok_or_else(|| plain(UNRECOGNISED))?;
    Ok(until > now_seconds(cx)? + WEEK)
}

fn hold_text_ok(value: &str) -> bool {
    value == "forever"
        || (value.len() <= 40
            && value
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'T' | 'Z' | ':' | '.' | '+' | '-'))
            && rfc3339_seconds(value).is_some())
}

pub fn observe_snap_updates(cx: &Cx) -> Result<Observation> {
    let held = match snap_hold(cx) {
        Err(_) => return Ok(unavailable("linux.snap_updates", NO_SNAP_STORE)),
        Ok(None) => false,
        Ok(Some(value)) => match hold_is_long(cx, &value) {
            Ok(held) => held,
            Err(_) => return Ok(unavailable("linux.snap_updates", UNRECOGNISED)),
        },
    };
    Ok(observation(vec![("held", flag(held))], true, ""))
}

pub fn write_snap_updates(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = two_state(want, "held")? else {
        return Ok(());
    };
    let now = snap_hold(cx).map_err(|_| plain(NO_SNAP_STORE))?;
    let long = match &now {
        Some(value) => hold_is_long(cx, value)?,
        None => false,
    };
    if long == (on == 1) {
        return Ok(());
    }
    if on == 0 {
        let value = now.ok_or_else(|| plain(CHANGE_FAILED))?;
        cx.memo_write(SNAP_MEMO, &[value])?;
        cx.run_ok(SNAP, &["unset", "system", "refresh.hold"])?;
    } else {
        let lines = cx.memo_read(SNAP_MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
        let [value] = lines.as_slice() else {
            return Err(plain(NO_RECORD));
        };
        if !hold_text_ok(value) {
            return Err(plain(NO_RECORD));
        }
        cx.run_ok(SNAP, &["set", "system", &format!("refresh.hold={value}")])?;
        cx.memo_clear(SNAP_MEMO)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_read_as_the_snap_tool_prints_them() {
        assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_seconds("2026-10-26T05:44:41.238528701Z"),
            Some(1_792_993_481)
        );
        assert_eq!(
            rfc3339_seconds("2026-10-26T07:44:41+02:00"),
            Some(1_792_993_481)
        );
        assert_eq!(
            rfc3339_seconds("2026-10-26T00:44:41-05:00"),
            Some(1_792_993_481)
        );
        for bad in ["", "forever", "2026-13-01T00:00:00Z", "2026-10-26", "x"] {
            assert_eq!(rfc3339_seconds(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_saved_file_comes_back_byte_for_byte() {
        let bytes = b"a\r\nb\n\xff\x00 c";
        assert_eq!(unhex(&hex(bytes)).unwrap(), bytes);
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn only_the_old_protocol_leaves_the_printer_finder_line() {
        let text = "# BrowseRemoteProtocols cups\n  BrowseRemoteProtocols dnssd,CUPS  \r\nOther 1";
        assert_eq!(
            without_old_protocol(text),
            "# BrowseRemoteProtocols cups\n  BrowseRemoteProtocols dnssd\r\nOther 1"
        );
        assert_eq!(
            without_old_protocol("BrowseRemoteProtocols cups"),
            "BrowseRemoteProtocols none"
        );
        assert_eq!(
            without_old_protocol("BrowseRemoteProtocols all\n"),
            "BrowseRemoteProtocols dnssd\n"
        );
        assert_eq!(browse_protocols("# BrowseRemoteProtocols cups\n"), None);
    }
}
