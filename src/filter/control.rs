//! Who answers for web protection: portable decisions plus the Windows glue that applies them.
//! The routing rule only exists while the filter is really answering, so a stopped
//! or crashed filter never leaves the PC without working lookups.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::config::{
    fresh, normalized_site, AllowOnce, Config, Status, ALLOW_ONCE_SECONDS, MAX_ALLOWED,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    Running,
    Other,
}

pub const NOT_A_SITE: &str = "That is not a website name. Type it the way it appears in the address bar, for example example.com.";
pub const ALLOWED_FULL: &str =
    "The list of allowed sites is full. Remove a site you no longer need and try again.";

const FALLBACK: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
];
const MAX_NETWORK_SERVERS: usize = 4;

/// Servers for the rule, in order: the filter, the network's own servers (some
/// networks only answer through their own, and sign-in pages need them), then
/// Quad9.
pub fn rule_servers(network: &[IpAddr]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let mut taken = 0;
    for ip in network {
        if taken == MAX_NETWORK_SERVERS {
            break;
        }
        if ip.is_loopback() || out.contains(ip) {
            continue;
        }
        out.push(*ip);
        taken += 1;
    }
    for ip in FALLBACK {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Desired {
    Rule(Vec<IpAddr>),
    NoRule,
}

/// The rule exists only while a switch or private lookups are on and the service is running, fresh and listening. A pause keeps it.
/// status is fresh and says it is listening. A pause keeps the rule: the
/// service then forwards everything.
pub fn desired(
    config: &Config,
    service: ServiceState,
    status: Option<&Status>,
    network: &[IpAddr],
    now: u64,
) -> Desired {
    let answering =
        service == ServiceState::Running && status.is_some_and(|s| s.listening && fresh(s, now));
    if config.needs_service() && answering {
        Desired::Rule(rule_servers(network))
    } else {
        Desired::NoRule
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Change {
    Nothing,
    Set(Vec<IpAddr>),
    Remove,
}

/// Compares what should be there with what is, so Windows is only touched
/// (and its lookup cache only flushed) when something differs.
pub fn change(desired: &Desired, current: Option<&[IpAddr]>) -> Change {
    match (desired, current) {
        (Desired::NoRule, None) => Change::Nothing,
        (Desired::NoRule, Some(_)) => Change::Remove,
        (Desired::Rule(want), Some(have)) if want.as_slice() == have => Change::Nothing,
        (Desired::Rule(want), _) => Change::Set(want.clone()),
    }
}

pub fn servers_value(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

/// Reads a stored server list. Anything that is not a plain list of
/// addresses reads as an empty list, which never equals what we want, so the
/// next change rewrites the rule cleanly.
pub fn parse_servers_value(value: &str) -> Vec<IpAddr> {
    let parsed: Option<Vec<IpAddr>> = value
        .split([';', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().ok())
        .collect();
    parsed.unwrap_or_default()
}

pub fn paused_config(mut config: Config, now: u64, duration: Duration) -> Config {
    config.paused_until = Some(now.saturating_add(duration.as_secs()));
    config.paused_boot = None;
    config
}

pub fn paused_until_restart_config(mut config: Config, boot: u64) -> Config {
    config.paused_until = None;
    config.paused_boot = Some(boot);
    config
}

pub fn resumed_config(mut config: Config) -> Config {
    config.paused_until = None;
    config.paused_boot = None;
    config
}

pub fn allowed_config(mut config: Config, site: &str) -> anyhow::Result<Config> {
    let Some(name) = normalized_site(site) else {
        anyhow::bail!(NOT_A_SITE);
    };
    if config.allow.contains(&name) {
        return Ok(config);
    }
    anyhow::ensure!(config.allow.len() < MAX_ALLOWED, ALLOWED_FULL);
    config.allow.push(name);
    Ok(config)
}

/// Lets a site through for ten minutes. Running out of room drops the entry that would end first.
pub fn allowed_once_config(mut config: Config, site: &str, now: u64) -> anyhow::Result<Config> {
    let Some(name) = normalized_site(site) else {
        anyhow::bail!(NOT_A_SITE);
    };
    config
        .allow_once
        .retain(|a| a.until > now && a.site != name);
    config.allow_once.push(AllowOnce {
        site: name,
        until: now.saturating_add(ALLOW_ONCE_SECONDS),
    });
    Ok(config.sanitized())
}

pub fn disallowed_config(mut config: Config, site: &str) -> Config {
    let name = normalized_site(site).unwrap_or_else(|| site.trim().to_ascii_lowercase());
    config.allow.retain(|a| *a != name);
    config
}

/// Runs every step even when an earlier one failed, and returns the first
/// error. Uninstall must never stop halfway.
pub fn run_all(steps: Vec<Box<dyn FnOnce() -> anyhow::Result<()> + '_>>) -> anyhow::Result<()> {
    let mut first = Ok(());
    for step in steps {
        let result = step();
        if first.is_ok() {
            first = result;
        }
    }
    first
}

#[cfg(windows)]
mod glue {
    use super::*;
    use crate::filter::{adapters, config, routing, scm, service};
    use anyhow::{Context, Result};
    use std::time::Instant;

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    const NEEDS_ADMIN: &str = "Changing web protection needs administrator rights";

    pub fn reconcile() -> Result<()> {
        crate::platform::require_admin(NEEDS_ADMIN)?;
        let config = config::load_config(&config::config_path()?);
        let service = scm::state()?;
        let status = config::load_status(&config::status_path()?);
        let network = adapters::upstream_servers();
        let want = desired(&config, service, status.as_ref(), &network, unix_now());
        let current = routing::current_rule()?;
        match change(&want, current.as_deref()) {
            Change::Nothing => Ok(()),
            Change::Set(servers) => routing::set_rule(&servers),
            Change::Remove => routing::remove_rule(),
        }
    }

    fn wait_until_listening(limit: Duration) -> bool {
        let Ok(path) = config::status_path() else {
            return false;
        };
        let start = Instant::now();
        loop {
            let ok =
                config::load_status(&path).is_some_and(|s| s.listening && fresh(&s, unix_now()));
            if ok {
                return true;
            }
            if start.elapsed() >= limit {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Saves the switches and starts or stops the filter to match. Turning
    /// off removes the rule first, so lookups never point at a stopped filter.
    pub fn apply_switches(new: Config) -> Result<()> {
        crate::platform::require_admin(NEEDS_ADMIN)?;
        scm::ensure_dirs()?;
        if new.needs_service() && scm::state()? == ServiceState::NotInstalled {
            scm::install()?;
        }
        config::save_config(&config::config_path()?, &new)?;
        if new.needs_service() {
            scm::set_enabled(true)?;
            // If it never starts listening (port taken), reconcile leaves
            // the rule out and the page explains it from the status file.
            wait_until_listening(Duration::from_secs(10));
            reconcile()?;
            settle();
            Ok(())
        } else {
            routing::remove_rule()?;
            scm::set_enabled(false)
        }
    }

    /// The service reads the config every couple of seconds and Windows caches answers, so a change shows once both catch up.
    fn settle() {
        std::thread::sleep(service::CONFIG_EVERY + Duration::from_secs(1));
        routing::flush_cache();
    }

    fn rewrite(edit: impl FnOnce(Config) -> Result<Config>) -> Result<()> {
        crate::platform::require_admin(NEEDS_ADMIN)?;
        let path = config::config_path()?;
        let edited = edit(config::load_config(&path))?;
        let edited = edited.without_expired(unix_now()).unwrap_or(edited);
        config::save_config(&path, &edited)?;
        settle();
        Ok(())
    }

    pub fn pause_for(duration: Duration) -> Result<()> {
        rewrite(|c| Ok(paused_config(c, unix_now(), duration)))
    }

    pub fn pause_until_restart() -> Result<()> {
        rewrite(|c| {
            Ok(paused_until_restart_config(
                c,
                config::boot_time(unix_now()),
            ))
        })
    }

    pub fn resume() -> Result<()> {
        rewrite(|c| Ok(resumed_config(c)))
    }

    pub fn allow_site(name: &str) -> Result<()> {
        rewrite(|c| allowed_config(c, name))
    }

    pub fn allow_site_once(name: &str) -> Result<()> {
        rewrite(|c| allowed_once_config(c, name, unix_now()))
    }

    pub fn remove_allowed(name: &str) -> Result<()> {
        rewrite(|c| Ok(disallowed_config(c, name)))
    }

    /// Rule first, then the service, then the files. The reconcile task
    /// belongs to `maintenance.ps1` (installer), which deletes it after this.
    pub fn remove_everything() -> Result<()> {
        crate::platform::require_admin(NEEDS_ADMIN)?;
        // A failed rule removal still deletes the service and folder; the
        // rule's Quad9 fallback servers keep lookups working.
        super::run_all(vec![
            Box::new(|| routing::remove_rule().context("Remove the web protection rule")),
            Box::new(|| scm::delete().context("Remove the web protection service")),
            Box::new(scm::remove_dir),
        ])
    }

    pub fn install_all() -> Result<()> {
        crate::platform::require_admin(NEEDS_ADMIN)?;
        scm::ensure_dirs()?;
        scm::install()
    }
}

#[cfg(windows)]
pub use glue::{
    allow_site, allow_site_once, apply_switches, install_all, pause_for, pause_until_restart,
    reconcile, remove_allowed, remove_everything, resume,
};

#[cfg(test)]
mod tests {
    #[test]
    fn run_all_runs_every_step_and_keeps_first_error() {
        use std::cell::Cell;
        let ran = Cell::new(0);
        let r = super::run_all(vec![
            Box::new(|| {
                ran.set(ran.get() + 1);
                Err(anyhow::anyhow!("first"))
            }),
            Box::new(|| {
                ran.set(ran.get() + 1);
                Err(anyhow::anyhow!("second"))
            }),
            Box::new(|| {
                ran.set(ran.get() + 1);
                Ok(())
            }),
        ]);
        assert_eq!(ran.get(), 3);
        assert_eq!(r.unwrap_err().to_string(), "first");
    }

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn status(listening: bool, written_at: u64) -> Status {
        Status {
            listening,
            written_at,
            ..Status::default()
        }
    }

    fn on() -> Config {
        Config {
            ads: true,
            ..Config::default()
        }
    }

    #[test]
    fn rule_servers_order_and_dedupe() {
        let got = rule_servers(&[
            ip("192.168.1.1"),
            ip("127.0.0.1"),
            ip("::1"),
            ip("192.168.1.1"),
            ip("fe80::1"),
        ]);
        let want: Vec<IpAddr> = [
            "127.0.0.1",
            "::1",
            "192.168.1.1",
            "fe80::1",
            "9.9.9.9",
            "149.112.112.112",
        ]
        .map(ip)
        .to_vec();
        assert_eq!(got, want);
        // The network already hands out Quad9: it is not listed twice.
        let got = rule_servers(&[ip("9.9.9.9")]);
        assert_eq!(got.iter().filter(|i| **i == ip("9.9.9.9")).count(), 1);
        assert_eq!(got.last(), Some(&ip("149.112.112.112")));
    }

    #[test]
    fn rule_servers_caps_network_at_four() {
        let network: Vec<IpAddr> = (1..=7).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        let got = rule_servers(&network);
        assert_eq!(got.len(), 2 + 4 + 2);
        assert_eq!(&got[2..6], &network[..4]);
        assert_eq!(rule_servers(&[]).len(), 4);
    }

    #[test]
    fn desired_rule_requires_fresh_listening_status() {
        let now = 10_000;
        let net = [ip("192.168.1.1")];
        let rule = Desired::Rule(rule_servers(&net));
        let run = ServiceState::Running;
        assert_eq!(
            desired(&on(), run, Some(&status(true, now - 5)), &net, now),
            rule
        );
        for s in [
            Some(status(true, now - 500)),
            Some(status(false, now - 5)),
            None,
        ] {
            assert_eq!(desired(&on(), run, s.as_ref(), &net, now), Desired::NoRule);
        }
    }

    #[test]
    fn private_lookups_alone_keep_the_rule() {
        let s = status(true, 100);
        let only_private = Config {
            private_lookups: true,
            ..Config::default()
        };
        assert!(matches!(
            desired(&only_private, ServiceState::Running, Some(&s), &[], 100),
            Desired::Rule(_)
        ));
    }

    #[test]
    fn desired_no_rule_when_all_off() {
        let s = status(true, 100);
        assert_eq!(
            desired(
                &Config::default(),
                ServiceState::Running,
                Some(&s),
                &[],
                100
            ),
            Desired::NoRule
        );
    }

    #[test]
    fn desired_keeps_rule_while_paused() {
        let s = status(true, 100);
        let paused = Config {
            paused_until: Some(500),
            ..on()
        };
        assert!(paused.paused(100));
        assert!(matches!(
            desired(&paused, ServiceState::Running, Some(&s), &[], 100),
            Desired::Rule(_)
        ));
    }

    #[test]
    fn desired_no_rule_when_service_stopped() {
        let s = status(true, 100);
        for state in [
            ServiceState::Stopped,
            ServiceState::NotInstalled,
            ServiceState::Other,
        ] {
            assert_eq!(desired(&on(), state, Some(&s), &[], 100), Desired::NoRule);
        }
    }

    #[test]
    fn change_touches_windows_only_when_different() {
        let a = vec![ip("127.0.0.1"), ip("9.9.9.9")];
        let b = vec![ip("9.9.9.9"), ip("127.0.0.1")];
        let want = Desired::Rule(a.clone());
        assert_eq!(change(&want, Some(&a)), Change::Nothing);
        assert_eq!(change(&want, Some(&b)), Change::Set(a.clone()));
        assert_eq!(change(&want, None), Change::Set(a.clone()));
        assert_eq!(change(&Desired::NoRule, None), Change::Nothing);
        assert_eq!(change(&Desired::NoRule, Some(&a)), Change::Remove);
    }

    #[test]
    fn server_list_round_trips_as_windows_stores_it() {
        let servers = rule_servers(&[ip("10.0.2.3")]);
        let value = servers_value(&servers);
        assert_eq!(value, "127.0.0.1;::1;10.0.2.3;9.9.9.9;149.112.112.112");
        assert_eq!(parse_servers_value(&value), servers);
        assert_eq!(
            parse_servers_value("127.0.0.1, ::1"),
            vec![ip("127.0.0.1"), ip("::1")]
        );
        assert!(parse_servers_value("127.0.0.1;nope").is_empty());
        assert!(parse_servers_value("").is_empty());
    }

    #[test]
    fn pausing_for_a_while_replaces_pausing_until_restart() {
        let until_restart = paused_until_restart_config(on(), 5_000);
        assert_eq!(until_restart.paused_boot, Some(5_000));
        assert_eq!(until_restart.paused_until, None);
        let timed = paused_config(until_restart.clone(), 100, Duration::from_secs(900));
        assert_eq!(timed.paused_until, Some(1000));
        assert_eq!(timed.paused_boot, None);
        let again = paused_until_restart_config(timed, 5_000);
        assert_eq!(again, until_restart);
        assert_eq!(resumed_config(until_restart), on());
    }

    #[test]
    fn allowing_a_site_stores_the_plain_name_once() {
        let c = allowed_config(on(), "  Example.COM. ").unwrap();
        assert_eq!(c.allow, ["example.com"]);
        let c = allowed_config(c, "example.com").unwrap();
        assert_eq!(c.allow, ["example.com"]);
        let c = allowed_config(c, "shop.example.org").unwrap();
        assert_eq!(c.allow, ["example.com", "shop.example.org"]);
        assert!(c.ads);
    }

    #[test]
    fn allowing_refuses_what_is_not_a_site_name() {
        for bad in [
            "",
            "com",
            "a b.com",
            "http://example.com",
            "ex*.com",
            "a..com",
        ] {
            let e = allowed_config(on(), bad).unwrap_err().to_string();
            assert!(e.contains("not a website name"), "{bad}");
        }
    }

    #[test]
    fn the_allowed_list_has_a_limit() {
        let mut c = on();
        for i in 0..MAX_ALLOWED {
            c = allowed_config(c, &format!("site{i}.example")).unwrap();
        }
        let e = allowed_config(c.clone(), "one-more.example").unwrap_err();
        assert!(e.to_string().contains("full"));
        assert!(allowed_config(c, "site7.example").is_ok());
    }

    #[test]
    fn removing_an_allowed_site() {
        let c = allowed_config(on(), "a.example").unwrap();
        let c = allowed_config(c, "b.example").unwrap();
        let c = disallowed_config(c, " A.example ");
        assert_eq!(c.allow, ["b.example"]);
        assert_eq!(disallowed_config(c.clone(), "nothing.example"), c);
    }

    #[test]
    fn letting_a_site_through_once_lasts_ten_minutes_and_leaves_the_rest() {
        let base = Config {
            allow: vec!["keep.example".into()],
            ..on()
        };
        let c = allowed_once_config(base.clone(), " Shop.Example. ", 1000).unwrap();
        assert_eq!(c.allow_once.len(), 1);
        assert_eq!(c.allow_once[0].site, "shop.example");
        assert_eq!(c.allow_once[0].until, 1000 + ALLOW_ONCE_SECONDS);
        assert_eq!(c.allow, base.allow);
        assert!(c.ads);
        assert!(c.allowed_once("www.shop.example", 1001));
        let again = allowed_once_config(c, "shop.example", 1300).unwrap();
        assert_eq!(again.allow_once.len(), 1);
        assert_eq!(again.allow_once[0].until, 1300 + ALLOW_ONCE_SECONDS);
        let e = allowed_once_config(on(), "not a site", 1000).unwrap_err();
        assert!(e.to_string().contains("not a website name"));
    }

    #[test]
    fn letting_sites_through_drops_the_expired_and_keeps_twenty_at_most() {
        let mut c = on();
        for i in 0..25u64 {
            c = allowed_once_config(c, &format!("site{i}.example"), 1000 + i).unwrap();
        }
        assert_eq!(c.allow_once.len(), crate::filter::config::MAX_ALLOWED_ONCE);
        assert!(c.allowed_once("site24.example", 1100));
        assert!(!c.allowed_once("site0.example", 1100));
        let later = allowed_once_config(c, "late.example", 5000).unwrap();
        assert_eq!(later.allow_once.len(), 1);
        assert_eq!(later.allow_once[0].site, "late.example");
    }

    #[test]
    fn pause_and_resume_change_only_the_pause() {
        let base = Config {
            ads: true,
            dangerous: true,
            ..Config::default()
        };
        let paused = paused_config(base.clone(), 1000, Duration::from_secs(3600));
        assert_eq!(paused.paused_until, Some(4600));
        assert!(paused.ads && paused.dangerous && !paused.tracking);
        assert_eq!(resumed_config(paused), base);
    }
}
