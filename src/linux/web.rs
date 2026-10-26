//! Web protection on Linux. The filter itself is the portable one in `filter`; this is how it is started, how lookups are
//! sent to it and taken back, and what the window may read and ask for.
//!
//! Lookups are sent to the filter by one runtime setting for systemd-resolved, which exists only while the filter is
//! really answering. A stopped or crashed filter never leaves the computer without working lookups.

use super::cmd::Sys;
use super::controls::plain;
use crate::filter::adapters::{split_search_list, usable_servers, usable_suffixes};
use crate::filter::config::{
    self, fresh, normalized_site, BlockHistory, Config, RecentItem, RecentList, Status,
    ALLOWED_TOO_LONG, MAX_ALLOWED, MAX_ALLOWED_ONCE, MAX_RECENT, MAX_STATS, MAX_STATUS,
};
use crate::filter::control::{
    self, allowed_config, allowed_once_config, disallowed_config, paused_config,
    paused_until_restart_config, resumed_config, Desired, ServiceState, ALLOWED_FULL, NOT_A_SITE,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

/// The filter's own folder. The root helper writes `config.json` here; the filter writes `Data`.
pub const DIR: &str = "/var/lib/secblitz-filter";
pub const UNIT: &str = "secblitz-filter.service";
/// The only address the filter listens on. systemd-resolved keeps 127.0.0.53 and 127.0.0.54 for itself.
pub const LISTEN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 153);
pub const DROPIN_DIR: &str = "/run/systemd/resolved.conf.d";
/// Sorts after the file the private lookups check writes (`90-secblitz-dns.conf`), so its switch wins over that one.
pub const DROPIN: &str = "/run/systemd/resolved.conf.d/95-secblitz-web-protection.conf";
const RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";
const ETC_RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLVED_UNIT: &str = "systemd-resolved.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const RESOLVECTL: &str = "/usr/bin/resolvectl";
const READLINK: &str = "/usr/bin/readlink";
const MKDIR: &str = "/usr/bin/mkdir";
const TEST: &str = "/usr/bin/test";
const MAX_RESOLV: usize = 64 * 1024;
/// Where `/etc/resolv.conf` may lead for the lookup service to be the one answering this computer's programs.
const RESOLVED_STUBS: [&str; 4] = [
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/usr/lib/systemd/resolv.conf",
    "/lib/systemd/resolv.conf",
];
const START_LIMIT: Duration = Duration::from_secs(10);

pub const NOT_AVAILABLE: &str = "Web protection is not available on this computer, because it does not use the usual way of looking up websites. Nothing was changed.";
pub const COULD_NOT_START: &str =
    "Web protection could not start. Try again in a moment, and if it keeps failing, leave it off.";
pub const COULD_NOT_SAVE: &str = "Secblitz could not save the web protection settings. Turn web protection on first, then try again.";
pub const ENCRYPTED_DNS_LEFT_TO_WEB: &str = "Web protection looks up websites for this computer, and its private lookups option sends them encrypted, so Secblitz leaves this alone.";

/// Every sentence this feature shows that is not already translated elsewhere, for the translation tests.
pub const SENTENCES: [&str; 8] = [
    NOT_AVAILABLE,
    COULD_NOT_START,
    COULD_NOT_SAVE,
    ENCRYPTED_DNS_LEFT_TO_WEB,
    NOT_A_SITE,
    ALLOWED_FULL,
    ALLOWED_TOO_LONG,
    super::controls::CHANGE_FAILED,
];

fn path(name: &str) -> PathBuf {
    PathBuf::from(DIR).join(name)
}

fn data(name: &str) -> PathBuf {
    PathBuf::from(DIR).join("Data").join(name)
}

pub fn config_path() -> PathBuf {
    path("config.json")
}

/// What the lookup service is told while web protection answers. Switching its encrypted lookups off is needed because
/// the filter speaks plain lookups on this computer; the filter itself sends them encrypted when private lookups is on.
pub fn dropin_text() -> String {
    format!(
        "# Written by Secblitz while web protection is on. It is taken away whenever web protection stops.\n\
         [Resolve]\n\
         DNS=\n\
         DNS={LISTEN}\n\
         Domains=~.\n\
         DNSOverTLS=no\n"
    )
}

/// The network's own lookup servers and search names, from the file the lookup service keeps for programs that read it
/// directly. Our own address and every other loopback address are left out.
pub fn parse_resolv_conf(text: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut servers = Vec::new();
    let mut suffixes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => {
                if let Some(ip) = words.next().and_then(|w| w.parse::<IpAddr>().ok()) {
                    servers.push(ip);
                }
            }
            Some("search" | "domain") => suffixes = words.map(str::to_owned).collect(),
            _ => {}
        }
    }
    (usable_servers(servers), usable_suffixes(suffixes))
}

fn read_resolv() -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(RESOLV_CONF).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_RESOLV as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_RESOLV)
        .then(|| String::from_utf8(bytes).ok())
        .flatten()
}

pub fn upstream_servers() -> Vec<IpAddr> {
    read_resolv().map_or_else(Vec::new, |t| parse_resolv_conf(&t).0)
}

pub fn dns_suffixes() -> Vec<String> {
    read_resolv().map_or_else(Vec::new, |t| {
        let (_, suffixes) = parse_resolv_conf(&t);
        usable_suffixes(suffixes.iter().flat_map(|s| split_search_list(s)))
    })
}

/// Whether the lookup service is what answers this computer's programs: it runs, `resolvectl` is there and
/// `/etc/resolv.conf` leads to it. Anything else and sending lookups to the filter would change nothing.
pub fn resolver_in_use(sys: &dyn Sys) -> bool {
    let running = sys
        .run(SYSTEMCTL, &["is-active", RESOLVED_UNIT])
        .is_ok_and(|o| o.stdout.trim() == "active");
    let tool = sys
        .run(TEST, &["-x", RESOLVECTL])
        .is_ok_and(|o| o.success());
    running && tool && etc_resolv_conf_uses_resolved(sys)
}

fn etc_resolv_conf_uses_resolved(sys: &dyn Sys) -> bool {
    let target = sys
        .run(READLINK, &["-f", ETC_RESOLV_CONF])
        .ok()
        .filter(|o| o.success())
        .map(|o| o.stdout.trim().to_owned());
    if target
        .as_deref()
        .is_some_and(|t| RESOLVED_STUBS.contains(&t))
    {
        return true;
    }
    sys.read(std::path::Path::new(ETC_RESOLV_CONF))
        .ok()
        .flatten()
        .is_some_and(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["nameserver", "127.0.0.53"])
        })
}

pub fn parse_service_state(text: &str) -> ServiceState {
    let value = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(str::trim)
    };
    if value("LoadState=") == Some("not-found") {
        return ServiceState::NotInstalled;
    }
    match value("ActiveState=") {
        Some("active") => ServiceState::Running,
        Some("inactive" | "failed") => ServiceState::Stopped,
        _ => ServiceState::Other,
    }
}

pub fn service_state(sys: &dyn Sys) -> ServiceState {
    sys.run(
        SYSTEMCTL,
        &["show", "--property=LoadState,ActiveState", UNIT],
    )
    .map_or(ServiceState::Other, |o| parse_service_state(&o.stdout))
}

/// Everything the window shows about web protection.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WebState {
    /// The lookup service is what answers this computer, so web protection can work here.
    pub available: bool,
    pub config: Config,
    pub status: Option<Status>,
    pub service: ServiceState,
    /// Lookups are being sent to the filter right now.
    pub routed: bool,
    pub now: u64,
    /// Blocks from the last fifteen minutes, newest first.
    pub recent: Vec<RecentItem>,
    pub stats: Option<BlockHistory>,
}

fn read_json<T: serde::de::DeserializeOwned>(
    sys: &dyn Sys,
    file: &std::path::Path,
    cap: u64,
) -> Option<T> {
    let bytes = sys.read(file).ok().flatten()?;
    if bytes.len() as u64 > cap {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn load_config(sys: &dyn Sys) -> Config {
    read_json::<Config>(sys, &config_path(), config::MAX_CONFIG)
        .map(Config::sanitized)
        .unwrap_or_default()
}

fn load_status(sys: &dyn Sys) -> Option<Status> {
    read_json(sys, &data("status.json"), MAX_STATUS)
}

fn routed(sys: &dyn Sys) -> bool {
    sys.read(std::path::Path::new(DROPIN))
        .ok()
        .flatten()
        .is_some()
}

pub fn state(sys: &dyn Sys, now: u64) -> WebState {
    let recent = read_json::<RecentList>(sys, &data("recent.json"), MAX_RECENT)
        .map(|r| r.within_window(now).items)
        .unwrap_or_default();
    WebState {
        available: resolver_in_use(sys),
        config: load_config(sys),
        status: load_status(sys),
        service: service_state(sys),
        routed: routed(sys),
        now,
        recent,
        stats: read_json(sys, &data("stats.json"), MAX_STATS),
    }
}

/// Whether web protection is set up to answer, for the checks that must not fight it.
pub fn config_needs_service(text: &str) -> bool {
    serde_json::from_str::<Config>(text)
        .map(Config::sanitized)
        .is_ok_and(|c| c.needs_service())
}

#[cfg(test)]
fn pause(_: Duration) {}

#[cfg(not(test))]
fn pause(length: Duration) {
    std::thread::sleep(length);
}

/// The lookup service reads its settings again once now and then, and programs keep answers for a while, so a change
/// shows once both have caught up.
fn settle(sys: &dyn Sys) {
    pause(crate::filter::service::CONFIG_EVERY + Duration::from_secs(1));
    let _ = sys.run(RESOLVECTL, &["flush-caches"]);
}

fn restart_resolver(sys: &dyn Sys) -> Result<()> {
    let out = sys.run(SYSTEMCTL, &["try-restart", RESOLVED_UNIT])?;
    anyhow::ensure!(
        out.success(),
        "systemctl try-restart {RESOLVED_UNIT} failed: {}",
        out.stderr.trim()
    );
    let _ = sys.run(RESOLVECTL, &["flush-caches"]);
    Ok(())
}

fn system_stopping(sys: &dyn Sys) -> bool {
    sys.run(SYSTEMCTL, &["is-system-running"])
        .is_ok_and(|o| o.stdout.trim() == "stopping")
}

/// Takes the setting away and has the lookup service forget it. Lookups go back to the network's own servers.
pub fn remove_rule(sys: &dyn Sys) -> Result<()> {
    let was_there = routed(sys);
    sys.remove(std::path::Path::new(DROPIN))?;
    if was_there && !system_stopping(sys) {
        restart_resolver(sys)?;
    }
    Ok(())
}

fn add_rule_file(sys: &dyn Sys) -> Result<()> {
    if !resolver_in_use(sys) {
        return Err(plain(NOT_AVAILABLE));
    }
    let made = sys.run(MKDIR, &["-p", DROPIN_DIR])?;
    anyhow::ensure!(made.success(), "Could not make {DROPIN_DIR}");
    sys.write_atomic(
        std::path::Path::new(DROPIN),
        dropin_text().as_bytes(),
        0o644,
    )?;
    if let Err(error) = restart_resolver(sys) {
        let _ = sys.remove(std::path::Path::new(DROPIN));
        let _ = restart_resolver(sys);
        return Err(error);
    }
    Ok(())
}

/// What `reconcile` finds to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Nothing,
    Add,
    Remove,
}

/// The setting exists only while a switch or private lookups is on and the filter is running, fresh and listening. A
/// pause keeps it: the filter then forwards everything.
pub fn next_step(
    config: &Config,
    service: ServiceState,
    status: Option<&Status>,
    current: Option<&str>,
    now: u64,
) -> Step {
    let want = matches!(
        control::desired(config, service, status, &[], now),
        Desired::Rule(_)
    );
    match (want, current) {
        (true, Some(text)) if text == dropin_text() => Step::Nothing,
        (true, _) => Step::Add,
        (false, Some(_)) => Step::Remove,
        (false, None) => Step::Nothing,
    }
}

/// Brings the lookup setting in line with what is true now.
pub fn reconcile(sys: &dyn Sys, service: ServiceState, now: u64) -> Result<()> {
    let current = sys
        .read(std::path::Path::new(DROPIN))
        .ok()
        .flatten()
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    let status = load_status(sys);
    match next_step(
        &load_config(sys),
        service,
        status.as_ref(),
        current.as_deref(),
        now,
    ) {
        Step::Nothing => Ok(()),
        Step::Add => add_rule_file(sys),
        Step::Remove => remove_rule(sys),
    }
}

/// The unit's own step after it reports that it is answering. It may not be called "running" yet by the system
/// manager, so the state is given.
pub fn add_rule_when_ready(sys: &dyn Sys, now: u64) -> Result<()> {
    reconcile(sys, ServiceState::Running, now)
}

fn wait_until_listening(sys: &dyn Sys, now: impl Fn() -> u64) -> bool {
    let mut waited = Duration::ZERO;
    loop {
        if load_status(sys).is_some_and(|s| s.listening && fresh(&s, now())) {
            return true;
        }
        if waited >= START_LIMIT {
            return false;
        }
        pause(Duration::from_millis(250));
        waited += Duration::from_millis(250);
    }
}

fn start_service(sys: &dyn Sys) -> Result<()> {
    match sys.run(SYSTEMCTL, &["enable", "--now", UNIT]) {
        Ok(out) if out.success() => Ok(()),
        Ok(out) => {
            eprintln!("Could not start {UNIT}: {}", out.stderr.trim());
            Err(plain(COULD_NOT_START))
        }
        Err(error) => {
            eprintln!("Could not start {UNIT}: {error:#}");
            Err(plain(COULD_NOT_START))
        }
    }
}

fn stop_service(sys: &dyn Sys) -> Result<()> {
    if service_state(sys) == ServiceState::NotInstalled {
        return Ok(());
    }
    let out = sys.run(SYSTEMCTL, &["disable", "--now", UNIT])?;
    anyhow::ensure!(
        out.success(),
        "Could not stop {UNIT}: {}",
        out.stderr.trim()
    );
    Ok(())
}

fn save_config(sys: &dyn Sys, new: &Config) -> Result<()> {
    let bytes = config::config_bytes(new)?;
    sys.write_atomic(&config_path(), &bytes, 0o644)
        .map_err(|error| {
            eprintln!("Could not save the web protection settings: {error:#}");
            plain(COULD_NOT_SAVE)
        })
}

/// Saves the switches and starts or stops the filter to match. Turning off takes the lookup setting away first, so
/// lookups never point at a stopped filter.
pub fn apply(sys: &dyn Sys, new: Config, now: impl Fn() -> u64) -> Result<()> {
    let new = new.sanitized();
    if new.needs_service() {
        if !resolver_in_use(sys) {
            return Err(plain(NOT_AVAILABLE));
        }
        if let Err(error) = start_service(sys) {
            let _ = stop_service(sys);
            return Err(error);
        }
        save_config(sys, &new)?;
        wait_until_listening(sys, &now);
        reconcile(sys, service_state(sys), now())?;
        settle(sys);
        Ok(())
    } else {
        remove_rule(sys)?;
        if sys.read(&config_path()).ok().flatten().is_some() {
            save_config(sys, &new)?;
        }
        stop_service(sys)
    }
}

fn rewrite(sys: &dyn Sys, edit: impl FnOnce(Config) -> Result<Config>, now: u64) -> Result<()> {
    let edited = edit(load_config(sys))?;
    let edited = edited.without_expired(now).unwrap_or(edited);
    save_config(sys, &edited)?;
    settle(sys);
    Ok(())
}

/// How long a pause lasts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseFor {
    Quarter,
    Hour,
    UntilRestart,
}

pub fn pause_web(sys: &dyn Sys, length: PauseFor, now: u64) -> Result<()> {
    rewrite(
        sys,
        |c| {
            Ok(match length {
                PauseFor::Quarter => paused_config(c, now, Duration::from_secs(15 * 60)),
                PauseFor::Hour => paused_config(c, now, Duration::from_secs(3600)),
                PauseFor::UntilRestart => paused_until_restart_config(c, config::boot_time(now)),
            })
        },
        now,
    )
}

pub fn resume(sys: &dyn Sys, now: u64) -> Result<()> {
    rewrite(sys, |c| Ok(resumed_config(c)), now)
}

pub fn allow_site(sys: &dyn Sys, site: &str, now: u64) -> Result<()> {
    rewrite(sys, |c| allowed_config(c, site), now)
}

pub fn allow_site_once(sys: &dyn Sys, site: &str, now: u64) -> Result<()> {
    rewrite(sys, |c| allowed_once_config(c, site, now), now)
}

pub fn remove_allowed(sys: &dyn Sys, site: &str, now: u64) -> Result<()> {
    rewrite(sys, |c| Ok(disallowed_config(c, site)), now)
}

/// The lookup setting first, then the filter. Every step runs even when an earlier one failed, and the first error is
/// returned, so removing Secblitz never stops halfway.
pub fn remove_everything(sys: &dyn Sys) -> Result<()> {
    control::run_all(vec![
        Box::new(|| remove_rule(sys).context("Remove the web protection setting")),
        Box::new(|| stop_service(sys).context("Stop web protection")),
    ])
}

/// Whether a request's settings are small and clean enough to save. The helper refuses anything else.
pub fn check_config(config: &Config) -> Result<()> {
    anyhow::ensure!(
        config.allow.len() <= MAX_ALLOWED && config.allow_once.len() <= MAX_ALLOWED_ONCE,
        ALLOWED_FULL
    );
    anyhow::ensure!(
        config
            .allow
            .iter()
            .map(String::as_str)
            .chain(config.allow_once.iter().map(|a| a.site.as_str()))
            .all(|site| normalized_site(site).as_deref() == Some(site)),
        NOT_A_SITE
    );
    Ok(())
}

/// A site name exactly as web protection writes it.
pub fn check_site(site: &str) -> Result<()> {
    anyhow::ensure!(
        site.len() <= 253 && normalized_site(site).as_deref() == Some(site),
        NOT_A_SITE
    );
    Ok(())
}

#[cfg(test)]
mod tests;
