//! Network guards: fake sender addresses, connection floods, messages that choose their own route, calls to the whole
//! network, temporary addresses, the computer name that networks are told, private website lookups, the computer's own
//! announcements on the local network and old remote services.
//!
//! A kernel network setting is kept per network connection and the kernel combines the shared `all` value with each
//! connection's own value in its own way, so the value that counts is worked out for every connection the way the kernel
//! does it. A fix changes only what is needed, keeps it after a restart in the control's own file and writes down every
//! value it replaced; an undo puts each one back and takes the file away.

use super::kernel::{observe_def, write_def, Def, NOTE, SYSCTL};
use super::network::{
    filed_setting, interface_ok, make_resolved_folder, remove_resolved_folder, resolver_active,
    running_setting, RESOLVED_UNIT, SYSTEMCTL,
};
use super::privacy::{nm_files, nm_get, reload_network_manager};
use super::services::{put_back_file, remember_file, remembered_file};
use super::{
    flag, ini, num_of, observation, plain, text_item, text_of, unavailable, units, Cx, Items,
    CHANGE_FAILED, NO_NETWORK_MANAGER, NO_RECORD, UNRECOGNISED,
};
use crate::hardening::{item_is_safe, Item};
use crate::linux::catalog::spec;
use crate::model::Observation;
use anyhow::Result;

type Family = (&'static str, &'static str);

const V4: Family = ("net.ipv4", "/proc/sys/net/ipv4/conf");
const V6: Family = ("net.ipv6", "/proc/sys/net/ipv6/conf");

/// How the kernel turns the shared `all` value and a connection's own value into the one that counts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Combine {
    /// The higher of the two.
    Higher,
    /// On only when both are on.
    Both,
    /// Only the connection's own value; the shared one is not looked at.
    Own,
}

struct Group {
    id: &'static str,
    item: &'static str,
    key: &'static str,
    memo: &'static str,
    dropin: &'static str,
    families: &'static [Family],
    combine: Combine,
    fixed: i64,
}

const FAKE_SOURCES: Group = Group {
    id: "linux.fake_sources",
    item: "rp_filter",
    key: "rp_filter",
    memo: "fake_sources",
    dropin: "/etc/sysctl.d/90-secblitz-fake-sources.conf",
    families: &[V4],
    combine: Combine::Higher,
    fixed: 2,
};

const SOURCE_ROUTING: Group = Group {
    id: "linux.source_routing",
    item: "accept_source_route",
    key: "accept_source_route",
    memo: "source_routing",
    dropin: "/etc/sysctl.d/90-secblitz-source-routing.conf",
    families: &[V4, V6],
    combine: Combine::Both,
    fixed: 0,
};

const IPV6_PRIVACY: Group = Group {
    id: "linux.ipv6_privacy",
    item: "use_tempaddr",
    key: "use_tempaddr",
    memo: "ipv6_privacy",
    dropin: "/etc/sysctl.d/90-secblitz-ipv6-privacy.conf",
    families: &[V6],
    combine: Combine::Own,
    fixed: 2,
};

const FLOOD: Def = Def {
    id: "linux.flood_protection",
    dropin: "/etc/sysctl.d/90-secblitz-flood-protection.conf",
    keys: &[("syncookies", "net.ipv4.tcp_syncookies")],
};

const BROADCAST: Def = Def {
    id: "linux.broadcast_pings",
    dropin: "/etc/sysctl.d/90-secblitz-broadcast-pings.conf",
    keys: &[("ignore_broadcasts", "net.ipv4.icmp_echo_ignore_broadcasts")],
};

/// One connection's own value, read from `/proc/sys`; `None` when there is no such file or it holds no number.
fn number(cx: &Cx, path: &str) -> Result<Option<i64>> {
    Ok(cx.text(path)?.and_then(|t| t.trim().parse::<i64>().ok()))
}

/// What one family's connection folders hold for a setting.
struct Readings {
    v6: bool,
    dir: &'static str,
    all: Option<i64>,
    /// `default` first, then every real connection, each as (name, own value).
    named: Vec<(String, i64)>,
}

impl Readings {
    fn path(&self, name: &str, key: &str) -> String {
        format!("{}/{name}/{key}", self.dir)
    }

    fn effective(&self, combine: Combine, own: i64) -> i64 {
        let all = self.all.unwrap_or(0);
        match combine {
            Combine::Higher => all.max(own),
            Combine::Both => {
                let allowed = if self.v6 {
                    all.min(own) > 0
                } else {
                    all != 0 && own != 0
                };
                i64::from(allowed)
            }
            Combine::Own => own,
        }
    }
}

fn read_family(cx: &Cx, family: Family, key: &str) -> Result<Readings> {
    let (head, dir) = family;
    let mut readings = Readings {
        v6: head == V6.0,
        dir,
        all: number(cx, &format!("{dir}/all/{key}"))?,
        named: Vec::new(),
    };
    let mut names = vec!["default".to_string()];
    names.extend(
        cx.list(dir)
            .into_iter()
            .filter(|n| n != "lo" && n != "all" && n != "default" && interface_ok(n)),
    );
    for name in names {
        if let Some(value) = number(cx, &format!("{dir}/{name}/{key}"))? {
            readings.named.push((name, value));
        }
    }
    Ok(readings)
}

fn read_group(cx: &Cx, g: &Group) -> Result<Vec<Readings>> {
    g.families
        .iter()
        .map(|family| read_family(cx, *family, g.key))
        .collect()
}

fn effective_values(g: &Group, readings: &[Readings]) -> Vec<i64> {
    readings
        .iter()
        .flat_map(|r| r.named.iter().map(|(_, own)| r.effective(g.combine, *own)))
        .collect()
}

pub fn observe_fake_sources(cx: &Cx) -> Result<Observation> {
    observe_group(cx, &FAKE_SOURCES)
}

pub fn observe_source_routing(cx: &Cx) -> Result<Observation> {
    observe_group(cx, &SOURCE_ROUTING)
}

pub fn observe_ipv6_privacy(cx: &Cx) -> Result<Observation> {
    observe_group(cx, &IPV6_PRIVACY)
}

/// The value that counts across every connection: the weakest one, or for a setting that is only on or off, whether any
/// connection is on.
fn observe_group(cx: &Cx, g: &Group) -> Result<Observation> {
    let values = effective_values(g, &read_group(cx, g)?);
    let item = if values.is_empty() {
        Item::Absent
    } else if g.combine == Combine::Both {
        flag(values.contains(&1))
    } else {
        let weakest = values.into_iter().min().unwrap_or(0);
        Item::Num(u32::try_from(weakest.clamp(0, 2)).unwrap_or(0))
    };
    Ok(observation(vec![(g.item, item)], true, ""))
}

/// What a fix changes: every path with the value it holds now, and the lines of the control's file.
struct Plan {
    changes: Vec<(String, i64)>,
    lines: Vec<String>,
}

fn plan(cx: &Cx, g: &Group) -> Result<Option<Plan>> {
    let readings = read_group(cx, g)?;
    let mut bad: Vec<(usize, String)> = Vec::new();
    for (i, r) in readings.iter().enumerate() {
        for (name, own) in &r.named {
            let value = r.effective(g.combine, *own);
            let unsafe_now = match g.combine {
                Combine::Higher => value < 1,
                Combine::Both => value == 1,
                Combine::Own => value < g.fixed,
            };
            if unsafe_now {
                bad.push((i, name.clone()));
            }
        }
    }
    if bad.is_empty() {
        return Ok(None);
    }
    let mut changes: Vec<(String, i64)> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    // A connection someone set to strict would be loosened by the shared value, so then only the connections that are
    // unprotected are written by name.
    let strict_somewhere = g.combine == Combine::Higher
        && readings
            .iter()
            .any(|r| r.all == Some(1) || r.named.iter().any(|(_, own)| *own == 1));
    for (i, r) in readings.iter().enumerate() {
        let (head, _) = g.families[i];
        let mut targets: Vec<(&str, i64)> = Vec::new();
        match g.combine {
            Combine::Higher if strict_somewhere => {
                for (name, own) in &r.named {
                    if bad.iter().any(|(j, n)| *j == i && n == name) {
                        targets.push((name, *own));
                    }
                }
            }
            Combine::Higher => {
                if r.all == Some(0) {
                    targets.push(("all", 0));
                }
                for (name, own) in &r.named {
                    if *own == 0 {
                        targets.push((name, 0));
                    }
                }
            }
            Combine::Both => {
                if let Some(all) = r.all.filter(|v| *v > 0) {
                    targets.push(("all", all));
                }
                for (name, own) in &r.named {
                    if *own > 0 {
                        targets.push((name, *own));
                    }
                }
            }
            Combine::Own => {
                for (name, own) in &r.named {
                    if *own < g.fixed {
                        targets.push((name, *own));
                    }
                }
            }
        }
        for (name, old) in targets {
            changes.push((r.path(name, g.key), old));
        }
        if strict_somewhere {
            for (j, name) in &bad {
                if *j == i {
                    lines.push(line_for(head, name, g.key, g.fixed));
                }
            }
        } else {
            for name in ["all", "default", "*"] {
                lines.push(line_for(head, name, g.key, g.fixed));
            }
        }
    }
    Ok(Some(Plan { changes, lines }))
}

/// A connection name with a dot or another odd character cannot be told apart from the dotted setting name, so such a
/// name is written in the slash form the file reader accepts.
fn line_for(head: &str, name: &str, key: &str, value: i64) -> String {
    let plain = name == "*"
        || name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if plain {
        format!("{head}.conf.{name}.{key} = {value}")
    } else {
        format!("{}/conf/{name}/{key} = {value}", head.replace('.', "/"))
    }
}

fn set_value(cx: &Cx, path: &str, value: i64) -> Result<()> {
    let name = path.strip_prefix("/proc/sys/").unwrap_or(path);
    cx.run_ok(SYSCTL, &["-w", &format!("{name}={value}")])?;
    Ok(())
}

/// A recorded line is `<path> <value>` for a path this control could have listed itself.
fn parse_record(g: &Group, line: &str) -> Result<(String, i64)> {
    let (path, value) = line.split_once(' ').ok_or_else(|| plain(NO_RECORD))?;
    let value: i64 = value.parse().map_err(|_| plain(NO_RECORD))?;
    let rest = g
        .families
        .iter()
        .find_map(|(_, dir)| path.strip_prefix(&format!("{dir}/")))
        .ok_or_else(|| plain(NO_RECORD))?;
    let (name, file) = rest.split_once('/').ok_or_else(|| plain(NO_RECORD))?;
    if !interface_ok(name) || file != g.key {
        return Err(plain(NO_RECORD));
    }
    Ok((path.to_string(), value))
}

fn apply_group(cx: &Cx, g: &Group) -> Result<()> {
    let Some(plan) = plan(cx, g)? else {
        return Ok(());
    };
    let mut record = cx.memo_read(g.memo)?.unwrap_or_default();
    for (path, old) in &plan.changes {
        if !record.iter().any(|l| l.starts_with(&format!("{path} "))) {
            record.push(format!("{path} {old}"));
        }
    }
    cx.memo_write(g.memo, &record)?;
    let mut lines: Vec<String> = cx
        .text(g.dropin)?
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    for line in plan.lines {
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    let mut text = String::from(NOTE);
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    cx.write_text(g.dropin, &text, 0o644)?;
    for (path, _) in &plan.changes {
        set_value(cx, path, g.fixed)?;
    }
    Ok(())
}

fn undo_group(cx: &Cx, g: &Group) -> Result<()> {
    let record = cx.memo_read(g.memo)?.ok_or_else(|| plain(NO_RECORD))?;
    let mut put_back = Vec::new();
    for line in &record {
        put_back.push(parse_record(g, line)?);
    }
    cx.remove(g.dropin)?;
    for (path, value) in put_back {
        if cx.text(&path)?.is_some() {
            set_value(cx, &path, value)?;
        }
    }
    cx.memo_clear(g.memo)
}

enum Way {
    Fix,
    Undo,
}

/// A value the catalog calls safe is the fix; one it calls unsafe is an undo; anything else is not ours to write.
fn way(id: &str, item: &str, fixed: i64, want: &Items) -> Result<Option<Way>> {
    let Some(value) = num_of(want, item)? else {
        return Ok(None);
    };
    if i64::from(value) == fixed {
        return Ok(Some(Way::Fix));
    }
    let rule = spec(id)
        .and_then(|s| s.keys.iter().find(|k| k.name == item))
        .map(|k| k.rule)
        .ok_or_else(|| plain(UNRECOGNISED))?;
    if item_is_safe(rule, &Item::Num(value)) {
        return Err(plain(UNRECOGNISED));
    }
    Ok(Some(Way::Undo))
}

fn write_group(cx: &Cx, want: &Items, g: &Group) -> Result<()> {
    match way(g.id, g.item, g.fixed, want)? {
        Some(Way::Fix) => apply_group(cx, g),
        Some(Way::Undo) => undo_group(cx, g),
        None => Ok(()),
    }
}

pub fn write_fake_sources(cx: &Cx, want: &Items) -> Result<()> {
    write_group(cx, want, &FAKE_SOURCES)
}

pub fn write_source_routing(cx: &Cx, want: &Items) -> Result<()> {
    write_group(cx, want, &SOURCE_ROUTING)
}

const NM_PRIVACY_DROPIN: &str = "/etc/NetworkManager/conf.d/90-secblitz-ipv6-privacy.conf";

/// The sysctl file and running values are changed first; the network program only learns the same wish for connections
/// that follow its own default. It is told to reread its files, which leaves every connection up, so new addresses
/// arrive the next time a connection is made.
pub fn write_ipv6_privacy(cx: &Cx, want: &Items) -> Result<()> {
    match way(IPV6_PRIVACY.id, IPV6_PRIVACY.item, IPV6_PRIVACY.fixed, want)? {
        Some(Way::Fix) => {
            apply_group(cx, &IPV6_PRIVACY)?;
            if nm_files(cx)?.is_some() {
                cx.write_text(
                    NM_PRIVACY_DROPIN,
                    &format!("{NOTE}[connection]\nipv6.ip6-privacy=2\n"),
                    0o644,
                )?;
                reload_network_manager(cx)?;
            }
            Ok(())
        }
        Some(Way::Undo) => {
            undo_group(cx, &IPV6_PRIVACY)?;
            if cx.text(NM_PRIVACY_DROPIN)?.is_some() {
                cx.remove(NM_PRIVACY_DROPIN)?;
                reload_network_manager(cx)?;
            }
            Ok(())
        }
        None => Ok(()),
    }
}

pub fn observe_flood_protection(cx: &Cx) -> Result<Observation> {
    observe_def(cx, &FLOOD)
}

pub fn write_flood_protection(cx: &Cx, want: &Items) -> Result<()> {
    write_def(cx, want, &FLOOD)
}

pub fn observe_broadcast_pings(cx: &Cx) -> Result<Observation> {
    observe_def(cx, &BROADCAST)
}

pub fn write_broadcast_pings(cx: &Cx, want: &Items) -> Result<()> {
    write_def(cx, want, &BROADCAST)
}

const HOSTNAME_DROPIN: &str = "/etc/NetworkManager/conf.d/90-secblitz-computer-name.conf";
/// Newer versions of the network program read the first key of each pair and older ones the second, so both are written.
const HOSTNAME_KEYS: [[&str; 2]; 2] = [
    ["ipv4.dhcp-send-hostname-v2", "ipv4.dhcp-send-hostname"],
    ["ipv6.dhcp-send-hostname-v2", "ipv6.dhcp-send-hostname"],
];

fn hostname_file() -> String {
    let mut text = format!("{NOTE}[connection]\n");
    for key in HOSTNAME_KEYS.iter().flatten() {
        text.push_str(&format!("{key}=false\n"));
    }
    text
}

/// Whether the network program's files let it send the computer name, `None` when a file holds a word it does not know.
/// For each address family the name is sent unless every key that is set says no, because which of the two keys counts
/// depends on the version of the network program.
fn sends_name(texts: &[String]) -> Option<bool> {
    let mut sends = false;
    for keys in HOSTNAME_KEYS {
        let mut family = false;
        let mut any = false;
        for key in keys {
            let Some(word) = nm_get(texts, "connection", key) else {
                continue;
            };
            any = true;
            family |= match word.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                _ => return None,
            };
        }
        sends |= family || !any;
    }
    Some(sends)
}

pub fn observe_computer_name(cx: &Cx) -> Result<Observation> {
    let Some(texts) = nm_files(cx)? else {
        return Ok(unavailable("linux.computer_name_sent", NO_NETWORK_MANAGER));
    };
    match sends_name(&texts) {
        Some(sends) => Ok(observation(vec![("sends", flag(sends))], true, "")),
        None => Ok(unavailable("linux.computer_name_sent", UNRECOGNISED)),
    }
}

/// Our file is taken away first, so an undo returns to what the other files say.
pub fn write_computer_name(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = num_of(want, "sends")? else {
        return Ok(());
    };
    if on > 1 {
        return Err(plain(UNRECOGNISED));
    }
    cx.remove(HOSTNAME_DROPIN)?;
    let texts = nm_files(cx)?.ok_or_else(|| plain(NO_NETWORK_MANAGER))?;
    if sends_name(&texts).ok_or_else(|| plain(UNRECOGNISED))? != (on == 1) {
        if on == 1 {
            return Err(plain(CHANGE_FAILED));
        }
        cx.write_text(HOSTNAME_DROPIN, &hostname_file(), 0o644)?;
        let now = nm_files(cx)?.and_then(|texts| sends_name(&texts));
        if now != Some(false) {
            cx.remove(HOSTNAME_DROPIN)?;
            return Err(plain(CHANGE_FAILED));
        }
    }
    reload_network_manager(cx)
}

const DOT_DROPIN: &str = "/etc/systemd/resolved.conf.d/90-secblitz-dns.conf";

fn dot_word(value: &str) -> Option<&'static str> {
    Some(match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" | "on" => "yes",
        "no" | "false" | "0" | "off" => "no",
        "opportunistic" => "opportunistic",
        _ => return None,
    })
}

fn running_dot(cx: &Cx) -> Result<Option<&'static str>> {
    Ok(running_setting(cx, "dnsovertls")?.and_then(|w| dot_word(&w)))
}

/// What the resolver is told to do: the files say, and with nothing said it does what it was built to.
fn effective_dot(cx: &Cx) -> Result<Option<&'static str>> {
    match filed_setting(cx, "DNSOverTLS")? {
        Some(value) => Ok(dot_word(&value)),
        None => running_dot(cx),
    }
}

pub fn observe_encrypted_dns(cx: &Cx) -> Result<Observation> {
    if !resolver_active(cx) {
        return Ok(observation(vec![("dns_over_tls", Item::Absent)], true, ""));
    }
    match effective_dot(cx)? {
        Some(word) => Ok(observation(
            vec![("dns_over_tls", text_item(word))],
            true,
            "",
        )),
        None => Ok(unavailable("linux.encrypted_dns", UNRECOGNISED)),
    }
}

fn undo_dot_file(cx: &Cx) -> Result<()> {
    cx.remove(DOT_DROPIN)?;
    remove_resolved_folder(cx)
}

/// The resolver keeps its running value until it restarts, so it is restarted after every change and the running value is
/// read back before the change is trusted.
pub fn write_encrypted_dns(cx: &Cx, want: &Items) -> Result<()> {
    let Some(word) = text_of(want, "dns_over_tls")? else {
        return Ok(());
    };
    let wanted = dot_word(word).ok_or_else(|| plain(UNRECOGNISED))?;
    if !matches!(wanted, "opportunistic" | "no") {
        return Err(plain(UNRECOGNISED));
    }
    undo_dot_file(cx)?;
    let restart = |cx: &Cx| cx.run_ok(SYSTEMCTL, &["try-restart", RESOLVED_UNIT]);
    if wanted == "no"
        && filed_setting(cx, "DNSOverTLS")?.is_none()
        && running_dot(cx)? != Some(wanted)
    {
        restart(cx)?;
    }
    if effective_dot(cx)? != Some(wanted) {
        if wanted == "no" {
            return Err(plain(CHANGE_FAILED));
        }
        let made = make_resolved_folder(cx).and_then(|()| {
            cx.write_text(
                DOT_DROPIN,
                &format!("{NOTE}[Resolve]\nDNSOverTLS={wanted}\n"),
                0o644,
            )
        });
        if let Err(e) = made {
            undo_dot_file(cx)?;
            return Err(e);
        }
        if let Err(e) = restart(cx) {
            undo_dot_file(cx)?;
            let _ = restart(cx);
            return Err(e);
        }
        if running_dot(cx)? != Some(wanted) {
            undo_dot_file(cx)?;
            let _ = restart(cx);
            return Err(plain(CHANGE_FAILED));
        }
    }
    Ok(())
}

const AVAHI_CONF: &str = "/etc/avahi/avahi-daemon.conf";
const AVAHI_UNIT: &str = "avahi-daemon.service";
const AVAHI_MEMO: &str = "announce_name_file";

fn publishing_off(text: &str) -> bool {
    matches!(
        ini::get(text, &["publish"], "disable-publishing")
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("yes" | "true" | "1")
    )
}

/// The announcer's file when it is running or starts by itself, `None` when there is nothing to change.
fn announcer(cx: &Cx) -> Result<Option<String>> {
    match units::probe(cx, AVAHI_UNIT) {
        Some(unit) if unit.on() => cx.text(AVAHI_CONF),
        _ => Ok(None),
    }
}

pub fn observe_announce_name(cx: &Cx) -> Result<Observation> {
    let item = match announcer(cx)? {
        Some(text) => flag(!publishing_off(&text)),
        None => Item::Absent,
    };
    Ok(observation(vec![("announcing", item)], true, ""))
}

fn restart_announcer(cx: &Cx) -> Result<()> {
    cx.run_ok(SYSTEMCTL, &["try-restart", AVAHI_UNIT]).map(drop)
}

pub fn write_announce_name(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = num_of(want, "announcing")? else {
        return Ok(());
    };
    match on {
        0 => {
            let text = announcer(cx)?.ok_or_else(|| plain(CHANGE_FAILED))?;
            if publishing_off(&text) {
                return Ok(());
            }
            remember_file(cx, AVAHI_MEMO, text.as_bytes())?;
            cx.write_text(
                AVAHI_CONF,
                &ini::set(&text, "publish", "disable-publishing", "yes"),
                0o644,
            )?;
            if let Err(e) = restart_announcer(cx) {
                put_back_file(cx, AVAHI_CONF, text.as_bytes())?;
                cx.memo_clear(AVAHI_MEMO)?;
                let _ = restart_announcer(cx);
                return Err(e);
            }
            Ok(())
        }
        1 => {
            let bytes = remembered_file(cx, AVAHI_MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
            let now = cx.text(AVAHI_CONF)?.ok_or_else(|| plain(NO_RECORD))?;
            let written = ini::set(
                &String::from_utf8_lossy(&bytes),
                "publish",
                "disable-publishing",
                "yes",
            );
            if now != written && now.as_bytes() != bytes.as_slice() {
                return Err(plain(UNRECOGNISED));
            }
            put_back_file(cx, AVAHI_CONF, &bytes)?;
            restart_announcer(cx)?;
            cx.memo_clear(AVAHI_MEMO)
        }
        _ => Err(plain(UNRECOGNISED)),
    }
}

/// Old remote services that send everything unprotected, sockets before the services they start, so nothing starts the
/// service again. Folder sharing is left out: people set it up on purpose, and another check covers it.
pub(super) const OLD_SERVICES: [&str; 11] = [
    "telnet.socket",
    "rsh.socket",
    "rlogin.socket",
    "tftp.socket",
    "tftpd-hpa.service",
    "vsftpd.service",
    "proftpd.service",
    "xinetd.service",
    "inetd.service",
    "snmpd.service",
    "rexec.socket",
];

const OLD_SERVICES_MEMO: &str = "old_network_services";

pub fn observe_old_services(cx: &Cx) -> Result<Observation> {
    let on = units::probe_all(cx, &OLD_SERVICES).iter().any(|u| u.on());
    Ok(observation(vec![("enabled", flag(on))], true, ""))
}

pub fn write_old_services(cx: &Cx, want: &Items) -> Result<()> {
    match num_of(want, "enabled")? {
        Some(0) => units::switch_off(cx, OLD_SERVICES_MEMO, &units::probe_all(cx, &OLD_SERVICES)),
        Some(1) => units::switch_on(cx, OLD_SERVICES_MEMO, &OLD_SERVICES, &[]),
        None => Ok(()),
        Some(_) => Err(plain(UNRECOGNISED)),
    }
}
