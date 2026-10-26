//! The two small files shared by the app and the filter service: the switches
//! the app writes (`config.json`) and the status the service writes.

use anyhow::{ensure, Context, Result};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::gaps::Gap;
use super::lists::valid_hostname;
use super::matcher::{Kind, Switches, KINDS};

pub const MAX_CONFIG: u64 = 16 * 1024;
pub const MAX_STATUS: u64 = 16 * 1024;
pub const MAX_RECENT: u64 = 64 * 1024;
pub const MAX_STATS: u64 = 64 * 1024;
const FRESH_SECONDS: u64 = 120;
/// Boot time comes from uptime, which drifts when the clock is corrected. The service ends the pause at start, which
/// holds with Fast Startup, which keeps the uptime counting across a shutdown.
const BOOT_SLACK: u64 = 30;
pub const MAX_ALLOWED: usize = 200;
pub const MAX_ALLOWED_ONCE: usize = 20;
pub const ALLOW_ONCE_SECONDS: u64 = 10 * 60;

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct Config {
    pub ads: bool,
    pub tracking: bool,
    pub dangerous: bool,
    #[serde(default)]
    pub adult: bool,
    #[serde(default)]
    pub gambling: bool,
    #[serde(default)]
    pub scam: bool,
    #[serde(default)]
    pub popups: bool,
    #[serde(default)]
    pub safe_search: bool,
    #[serde(default)]
    pub private_lookups: bool,
    /// Unix seconds; everything is off until then.
    #[serde(default)]
    pub paused_until: Option<u64>,
    /// Boot time (unix seconds) of the start "until restart" was chosen in.
    #[serde(default)]
    pub paused_boot: Option<u64>,
    #[serde(default)]
    pub allow: Vec<String>,
    /// Sites let through for a few minutes. The service drops the ones that ran out.
    #[serde(default)]
    pub allow_once: Vec<AllowOnce>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AllowOnce {
    pub site: String,
    /// Unix seconds.
    pub until: u64,
}

impl Config {
    pub fn any_on(&self) -> bool {
        self.ads
            || self.tracking
            || self.dangerous
            || self.adult
            || self.gambling
            || self.scam
            || self.popups
            || self.safe_search
    }

    pub fn needs_service(&self) -> bool {
        self.any_on() || self.private_lookups
    }

    pub fn private_active(&self, now: u64) -> bool {
        self.private_lookups && !self.paused(now)
    }

    /// Ends an "until restart" pause, since the service only starts again with the PC.
    pub fn after_service_start(&self) -> Option<Config> {
        self.paused_boot.is_some().then(|| Config {
            paused_boot: None,
            ..self.clone()
        })
    }

    pub fn paused(&self, now: u64) -> bool {
        self.paused_until.is_some_and(|t| t > now)
            || self
                .paused_boot
                .is_some_and(|b| b.abs_diff(boot_time(now)) <= BOOT_SLACK)
    }

    pub fn active(&self, now: u64) -> Switches {
        if self.paused(now) {
            return Switches::default();
        }
        Switches {
            ads: self.ads,
            tracking: self.tracking,
            dangerous: self.dangerous,
            adult: self.adult,
            gambling: self.gambling,
            scam: self.scam,
            popups: self.popups,
            safe_search: self.safe_search,
        }
    }

    /// An entry counts only while it has time left and no more than the longest
    /// allowed stretch, so a changed file cannot let a site through for good.
    pub fn allowed_once(&self, name: &str, now: u64) -> bool {
        self.allow_once.iter().any(|a| {
            a.until > now
                && a.until - now <= ALLOW_ONCE_SECONDS
                && (name == a.site
                    || name
                        .strip_suffix(a.site.as_str())
                        .is_some_and(|p| p.ends_with('.')))
        })
    }

    /// The config without the let-throughs that ran out, or `None` when none did.
    pub fn without_expired(&self, now: u64) -> Option<Config> {
        let live: Vec<AllowOnce> = self
            .allow_once
            .iter()
            .filter(|a| a.until > now)
            .cloned()
            .collect();
        (live.len() != self.allow_once.len()).then(|| Config {
            allow_once: live,
            ..self.clone()
        })
    }

    pub fn sanitized(mut self) -> Config {
        let mut clean: Vec<String> = Vec::new();
        for name in &self.allow {
            let name = normalized_site(name);
            if let Some(name) = name {
                if !clean.contains(&name) && clean.len() < MAX_ALLOWED {
                    clean.push(name);
                }
            }
        }
        self.allow = clean;
        let mut once: Vec<AllowOnce> = Vec::new();
        for entry in &self.allow_once {
            let Some(site) = normalized_site(&entry.site) else {
                continue;
            };
            match once.iter_mut().find(|o| o.site == site) {
                Some(seen) => seen.until = seen.until.max(entry.until),
                None => once.push(AllowOnce {
                    site,
                    until: entry.until,
                }),
            }
        }
        once.sort_by(|a, b| b.until.cmp(&a.until));
        once.truncate(MAX_ALLOWED_ONCE);
        self.allow_once = once;
        self
    }
}

pub fn normalized_site(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    valid_hostname(&name).then_some(name)
}

/// Boot time in unix seconds.
pub fn boot_time(now: u64) -> u64 {
    now.saturating_sub(uptime_seconds())
}

#[cfg(windows)]
fn uptime_seconds() -> u64 {
    // SAFETY: takes no arguments and only reads the tick counter.
    unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() / 1000 }
}

#[cfg(not(windows))]
fn uptime_seconds() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split('.').next()?.trim().parse().ok())
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    #[default]
    Starting,
    Ready,
    NoLists,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    PortInUse,
    DownloadFailed,
    ListInvalid,
    NoUpstream,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Lookups {
    #[default]
    Plain,
    Private,
    PrivateFallback,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
pub struct Status {
    pub listening: bool,
    pub state: State,
    pub lists_updated: Option<u64>,
    pub day: u64,
    #[serde(deserialize_with = "counters")]
    pub blocked: [u64; KINDS],
    #[serde(deserialize_with = "counters")]
    pub domains: [u64; KINDS],
    pub last_error: Option<ErrorCode>,
    pub written_at: u64,
    #[serde(default)]
    pub lookups: Lookups,
    /// Unix seconds of the last dangerous block. Never a name.
    #[serde(default)]
    pub dangerous_at: Option<u64>,
    /// Ways around Web protection found on this PC, or `None` when the check could not run.
    #[serde(default)]
    pub gaps: Option<Vec<Gap>>,
    /// The last scam or dangerous block, with its name, for the tray notice. Other kinds never leave the service.
    #[serde(default)]
    pub notice: Option<Notice>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Notice {
    pub kind: Kind,
    pub site: String,
    /// Unix seconds.
    pub at: u64,
}

/// Older files have three to five counters; the missing ones are zero.
pub fn counters<'de, D: Deserializer<'de>>(d: D) -> Result<[u64; KINDS], D::Error> {
    let values = Vec::<u64>::deserialize(d)?;
    if !(3..=KINDS).contains(&values.len()) {
        return Err(D::Error::custom("unexpected number of counters"));
    }
    let mut out = [0; KINDS];
    out[..values.len()].copy_from_slice(&values);
    Ok(out)
}

pub const RECENT_SECONDS: u64 = 15 * 60;
pub const MAX_RECENT_ITEMS: usize = 50;
pub const STATS_DAYS: u64 = 30;
pub const TOP_SITES: usize = 10;

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
pub struct RecentList {
    #[serde(default)]
    pub items: Vec<RecentItem>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RecentItem {
    pub name: String,
    pub kind: Kind,
    /// Unix seconds.
    pub at: u64,
}

impl RecentList {
    pub fn within_window(mut self, now: u64) -> RecentList {
        self.items
            .retain(|i| i.at <= now && now - i.at <= RECENT_SECONDS);
        self.items.sort_by(|a, b| b.at.cmp(&a.at));
        self
    }
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
pub struct BlockHistory {
    #[serde(default)]
    pub days: Vec<DayCount>,
    #[serde(default)]
    pub top: Vec<TopSite>,
    #[serde(default)]
    pub top_companies: Vec<TopSite>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DayCount {
    /// Days since 1970-01-01.
    pub day: u64,
    #[serde(deserialize_with = "counters")]
    pub blocked: [u64; KINDS],
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopSite {
    pub site: String,
    pub count: u64,
}

pub(super) fn read_capped(path: &Path, max: u64) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(max + 1).read_to_end(&mut buf).ok()?;
    (buf.len() as u64 <= max).then_some(buf)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("File has no folder")?;
    let name = path.file_name().context("File has no name")?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    fs::write(&tmp, bytes).with_context(|| format!("Cannot write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("Cannot replace {}", path.display()))?;
    Ok(())
}

/// Missing, oversize or unreadable files mean everything off.
pub fn load_config(path: &Path) -> Config {
    read_capped(path, MAX_CONFIG)
        .and_then(|b| serde_json::from_slice::<Config>(&b).ok())
        .map(Config::sanitized)
        .unwrap_or_default()
}

pub const ALLOWED_TOO_LONG: &str =
    "The list of allowed sites is too long. Remove a site you no longer need and try again.";

/// The file's bytes, or why it cannot be written. Never too big: the service would refuse it and switch everything off.
pub fn config_bytes(c: &Config) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(&c.clone().sanitized())?;
    ensure!(bytes.len() as u64 <= MAX_CONFIG, ALLOWED_TOO_LONG);
    Ok(bytes)
}

pub fn save_config(path: &Path, c: &Config) -> Result<()> {
    write_atomic(path, &config_bytes(c)?)
}

pub fn load_status(path: &Path) -> Option<Status> {
    serde_json::from_slice(&read_capped(path, MAX_STATUS)?).ok()
}

pub fn save_status(path: &Path, s: &Status) -> Result<()> {
    write_atomic(path, &serde_json::to_vec(s)?)
}

pub fn load_recent(path: &Path) -> Option<RecentList> {
    serde_json::from_slice(&read_capped(path, MAX_RECENT)?).ok()
}

pub fn load_stats(path: &Path) -> Option<BlockHistory> {
    serde_json::from_slice(&read_capped(path, MAX_STATS)?).ok()
}

/// A status written in the last two minutes: the service is alive.
pub fn fresh(status: &Status, now: u64) -> bool {
    status.written_at <= now && now - status.written_at <= FRESH_SECONDS
}

/// `<ProgramData>\Secblitz\Filter`. On Windows the folder comes from the
/// known-folder API, never from the inherited environment; the `ProgramData`
/// variable is only the fallback for the portable (test) build.
pub fn dir() -> Result<PathBuf> {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        Ok(PathBuf::from(crate::linux::web::DIR))
    }
    #[cfg(not(all(target_os = "linux", not(test))))]
    {
        Ok(program_data()?
            .join("Secblitz")
            .join(crate::platform::WEB_PROTECTION))
    }
}

#[cfg(windows)]
fn program_data() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    let mut value = null_mut();
    // SAFETY: valid GUID and output pointer; the allocation is freed below
    // even when the call fails.
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut value) };
    let path = if hr >= 0 && !value.is_null() {
        // SAFETY: a successful call returns a NUL-terminated UTF-16 string, freed only below.
        let slice = unsafe { crate::platform::security::wide_str(value) };
        slice.map(|s| PathBuf::from(std::ffi::OsString::from_wide(s)))
    } else {
        None
    };
    // SAFETY: null or the allocation returned by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(value.cast()) };
    path.filter(|p| p.is_absolute())
        .context("ProgramData is not available")
}

#[cfg(all(not(windows), any(test, not(target_os = "linux"))))]
fn program_data() -> Result<PathBuf> {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .context("ProgramData is not available")
}

pub fn config_path() -> Result<PathBuf> {
    Ok(dir()?.join("config.json"))
}

pub fn data_dir() -> Result<PathBuf> {
    Ok(dir()?.join("Data"))
}

pub fn status_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("status.json"))
}

pub fn recent_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("recent.json"))
}

pub fn stats_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("stats.json"))
}

pub fn stats_detail_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("stats-detail.json"))
}

pub fn lists_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("lists"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_turns_everything_off_until_time() {
        let c = Config {
            ads: true,
            tracking: true,
            paused_until: Some(1000),
            ..Config::default()
        };
        assert!(c.any_on());
        assert!(c.paused(999));
        assert_eq!(c.active(999), Switches::default());
        assert!(!c.paused(1000));
        assert_eq!(
            c.active(1000),
            Switches {
                ads: true,
                tracking: true,
                ..Switches::default()
            }
        );
        assert!(!Config::default().any_on());
    }

    #[test]
    fn scam_and_popup_switches_count_as_on() {
        for c in [
            Config {
                scam: true,
                ..Config::default()
            },
            Config {
                popups: true,
                ..Config::default()
            },
        ] {
            assert!(c.any_on());
            assert!(c.needs_service());
        }
        let c = Config {
            scam: true,
            popups: true,
            ..Config::default()
        };
        let on = c.active(0);
        assert!(on.scam && on.popups && !on.ads && !on.dangerous);
        assert!(!c.active(0).adult);
        let paused = Config {
            paused_until: Some(100),
            ..c
        };
        assert_eq!(paused.active(50), Switches::default());
    }

    #[test]
    fn a_config_from_before_scam_blocking_still_loads_with_them_off() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        fs::write(
            &p,
            r#"{"ads":true,"tracking":true,"dangerous":true,"adult":true,"allow":["ok.example"]}"#,
        )
        .unwrap();
        let c = load_config(&p);
        assert!(c.ads && c.adult && !c.scam && !c.popups);
        assert!(c.allow_once.is_empty());
        assert_eq!(c.allow, ["ok.example"]);
    }

    fn once(site: &str, until: u64) -> AllowOnce {
        AllowOnce {
            site: site.into(),
            until,
        }
    }

    #[test]
    fn a_let_through_covers_the_site_and_its_subdomains_until_it_runs_out() {
        let c = Config {
            allow_once: vec![once("shop.example", 1000 + 60)],
            ..Config::default()
        };
        assert!(c.allowed_once("shop.example", 1000));
        assert!(c.allowed_once("www.shop.example", 1000));
        assert!(!c.allowed_once("notshop.example", 1000));
        assert!(!c.allowed_once("example", 1000));
        assert!(c.allowed_once("shop.example", 1059));
        assert!(!c.allowed_once("shop.example", 1060));
        assert!(!c.allowed_once("shop.example", 5000));
    }

    #[test]
    fn a_let_through_longer_than_ten_minutes_is_ignored() {
        let c = Config {
            allow_once: vec![
                once("fine.example", 1000 + ALLOW_ONCE_SECONDS),
                once("forged.example", 1000 + ALLOW_ONCE_SECONDS + 1),
                once("far.example", u64::MAX),
            ],
            ..Config::default()
        };
        assert!(c.allowed_once("fine.example", 1000));
        assert!(!c.allowed_once("forged.example", 1000));
        assert!(!c.allowed_once("far.example", 1000));
    }

    #[test]
    fn expired_let_throughs_are_dropped_and_the_rest_kept() {
        let c = Config {
            ads: true,
            allow: vec!["keep.example".into()],
            allow_once: vec![once("old.example", 900), once("live.example", 1100)],
            ..Config::default()
        };
        let pruned = c.without_expired(1000).unwrap();
        assert_eq!(pruned.allow_once, [once("live.example", 1100)]);
        assert!(pruned.ads);
        assert_eq!(pruned.allow, c.allow);
        assert_eq!(pruned.without_expired(1000), None);
        assert_eq!(Config::default().without_expired(1000), None);
        let gone = c.without_expired(1100).unwrap();
        assert!(gone.allow_once.is_empty());
    }

    #[test]
    fn let_throughs_are_cleaned_and_limited_when_saved() {
        let mut entries: Vec<AllowOnce> = (0..30)
            .map(|i| once(&format!("site{i}.example"), 1000 + i))
            .collect();
        entries.push(once("not a name", 5000));
        entries.push(once("SITE3.example.", 4000));
        let c = Config {
            allow_once: entries,
            ..Config::default()
        }
        .sanitized();
        assert_eq!(c.allow_once.len(), MAX_ALLOWED_ONCE);
        assert!(c.allow_once.iter().all(|a| a.site != "not a name"));
        let site3: Vec<_> = c
            .allow_once
            .iter()
            .filter(|a| a.site == "site3.example")
            .collect();
        assert_eq!(site3.len(), 1);
        assert_eq!(site3[0].until, 4000);
    }

    #[test]
    fn family_switches_count_as_on() {
        for c in [
            Config {
                adult: true,
                ..Config::default()
            },
            Config {
                gambling: true,
                ..Config::default()
            },
            Config {
                safe_search: true,
                ..Config::default()
            },
        ] {
            assert!(c.any_on());
        }
        let c = Config {
            adult: true,
            gambling: true,
            safe_search: true,
            ..Config::default()
        };
        let on = c.active(0);
        assert!(on.adult && on.gambling && on.safe_search && !on.ads);
        let private = Config {
            private_lookups: true,
            ..Config::default()
        };
        assert!(!private.any_on());
        assert!(private.needs_service());
        assert!(!Config::default().needs_service());
    }

    #[test]
    fn a_service_start_ends_the_pause_until_restart() {
        let now = 1_000_000;
        let c = Config {
            ads: true,
            paused_boot: Some(boot_time(now)),
            ..Config::default()
        };
        assert!(c.paused(now));
        let started = c.after_service_start().unwrap();
        assert_eq!(started.paused_boot, None);
        assert!(!started.paused(now));
        assert!(started.active(now).ads);
        assert_eq!(started.ads, c.ads);
        assert_eq!(Config::default().after_service_start(), None);
        let timed = Config {
            paused_until: Some(now + 600),
            ..Config::default()
        };
        assert_eq!(timed.after_service_start(), None);
    }

    #[test]
    fn paused_until_restart_holds_for_this_start_only() {
        let now = 1_000_000;
        let boot = boot_time(now);
        let c = Config {
            ads: true,
            paused_boot: Some(boot),
            ..Config::default()
        };
        assert!(c.paused(now));
        assert_eq!(c.active(now), Switches::default());
        let same = Config {
            paused_boot: Some(boot + BOOT_SLACK),
            ..c.clone()
        };
        assert!(same.paused(now));
        let earlier_start = Config {
            paused_boot: Some(boot.saturating_sub(BOOT_SLACK + 1)),
            ..c.clone()
        };
        assert!(!earlier_start.paused(now));
        assert!(earlier_start.active(now).ads);
        let both = Config {
            paused_until: Some(now + 5),
            ..earlier_start
        };
        assert!(both.paused(now) && !both.paused(now + 5));
    }

    #[test]
    fn the_boot_time_does_not_move_while_the_pc_runs() {
        let a = boot_time(1_000_000);
        let b = boot_time(1_000_090);
        assert!(a.abs_diff(b) <= 90 + 1);
    }

    #[test]
    fn config_round_trips_and_old_files_load() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        let c = Config {
            ads: true,
            paused_until: Some(5),
            ..Config::default()
        };
        save_config(&p, &c).unwrap();
        assert_eq!(load_config(&p), c);
        fs::write(&p, r#"{"ads":true,"tracking":false,"dangerous":true}"#).unwrap();
        let old = load_config(&p);
        assert!(old.ads && old.dangerous && old.paused_until.is_none());
        assert!(!old.adult && !old.gambling && !old.safe_search && !old.private_lookups);
        assert!(old.paused_boot.is_none() && old.allow.is_empty());
    }

    #[test]
    fn new_fields_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        let c = Config {
            ads: true,
            adult: true,
            gambling: true,
            safe_search: true,
            private_lookups: true,
            paused_boot: Some(1234),
            allow: vec!["example.com".into(), "shop.example.org".into()],
            ..Config::default()
        };
        save_config(&p, &c).unwrap();
        assert_eq!(load_config(&p), c);
    }

    #[test]
    fn allowed_sites_are_cleaned_when_read_and_written() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        fs::write(
            &p,
            r#"{"ads":true,"tracking":false,"dangerous":false,
                "allow":["Example.COM","example.com","bad name.com","com","a.b.example.org.","-x.com"]}"#,
        )
        .unwrap();
        assert_eq!(load_config(&p).allow, ["example.com", "a.b.example.org"]);
        let c = Config {
            allow: vec!["A.example".into(), "a.example".into(), "no".into()],
            ..Config::default()
        };
        save_config(&p, &c).unwrap();
        assert_eq!(load_config(&p).allow, ["a.example"]);
    }

    #[test]
    fn allowed_sites_stop_at_two_hundred() {
        let many: Vec<String> = (0..300).map(|i| format!("site{i}.example")).collect();
        let c = Config {
            allow: many,
            ..Config::default()
        }
        .sanitized();
        assert_eq!(c.allow.len(), MAX_ALLOWED);
        assert_eq!(c.allow[199], "site199.example");
    }

    #[test]
    fn a_full_list_of_ordinary_names_fits_in_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        let allow: Vec<String> = (0..MAX_ALLOWED)
            .map(|i| format!("a-reasonably-long-site-name-{i:03}.example-company.co.uk"))
            .collect();
        let c = Config {
            ads: true,
            allow,
            ..Config::default()
        };
        save_config(&p, &c).unwrap();
        assert_eq!(load_config(&p), c);
        assert!(fs::metadata(&p).unwrap().len() <= MAX_CONFIG);
    }

    #[test]
    fn a_config_too_big_to_read_back_is_never_written() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        let long = format!("{0}.{0}.{0}.com", "a".repeat(60));
        let allow: Vec<String> = (0..MAX_ALLOWED).map(|i| format!("{i}{long}")).collect();
        let c = Config {
            ads: true,
            allow,
            ..Config::default()
        };
        let e = save_config(&p, &c).unwrap_err().to_string();
        assert!(e.contains("too long"));
        assert!(!p.exists());
    }

    #[test]
    fn oversize_config_is_default() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        let pad = " ".repeat(17_000);
        fs::write(
            &p,
            format!(r#"{{"ads":true,"tracking":true,"dangerous":true}}{pad}"#),
        )
        .unwrap();
        assert_eq!(load_config(&p), Config::default());
        fs::write(&p, "not json").unwrap();
        assert_eq!(load_config(&p), Config::default());
        assert_eq!(
            load_config(&d.path().join("missing.json")),
            Config::default()
        );
    }

    #[test]
    fn status_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("status.json");
        let s = Status {
            listening: true,
            state: State::NoLists,
            lists_updated: Some(7),
            day: 20000,
            blocked: [1, 2, 3, 4, 5, 6, 7],
            domains: [10, 20, 30, 40, 50, 60, 70],
            last_error: Some(ErrorCode::PortInUse),
            written_at: 99,
            lookups: Lookups::PrivateFallback,
            dangerous_at: Some(88),
            gaps: Some(vec![Gap::Vpn, Gap::BrowserSecureDns]),
            notice: Some(Notice {
                kind: Kind::Scam,
                site: "shop.example".into(),
                at: 88,
            }),
        };
        save_status(&p, &s).unwrap();
        assert_eq!(load_status(&p), Some(s));
        let text = fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"no-lists\"") && text.contains("\"port-in-use\""));
        assert!(text.contains("\"private-fallback\""));
        assert!(text.contains("\"Vpn\""));
        assert_eq!(load_status(&d.path().join("missing.json")), None);
        fs::write(&p, vec![b' '; 20_000]).unwrap();
        assert_eq!(load_status(&p), None);
    }

    #[test]
    fn status_from_before_the_family_lists_still_reads() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("status.json");
        fs::write(
            &p,
            r#"{"listening":true,"state":"ready","lists_updated":5,"day":20000,
                "blocked":[1,2,3],"domains":[10,20,30],"last_error":null,"written_at":99}"#,
        )
        .unwrap();
        let s = load_status(&p).unwrap();
        assert_eq!(s.blocked, [1, 2, 3, 0, 0, 0, 0]);
        assert_eq!(s.domains, [10, 20, 30, 0, 0, 0, 0]);
        assert_eq!(s.lookups, Lookups::Plain);
        assert_eq!(s.dangerous_at, None);
        assert_eq!(s.notice, None);
        assert!(s.listening && s.state == State::Ready);
        fs::write(
            &p,
            r#"{"listening":true,"state":"ready","lists_updated":null,"day":1,
                "blocked":[1,2,3,4,5,6,7,8],"domains":[0,0,0],"last_error":null,"written_at":99}"#,
        )
        .unwrap();
        assert_eq!(load_status(&p), None);
    }

    #[test]
    fn status_files_without_gaps_still_load_and_claim_nothing() {
        let old = r#"{"listening":true,"state":"ready","lists_updated":1,"day":2,
            "blocked":[1,2,3,4,5],"domains":[1,2,3,4,5],"last_error":null,"written_at":3}"#;
        let s: Status = serde_json::from_str(old).unwrap();
        assert_eq!(s.gaps, None);
    }

    #[test]
    fn status_with_five_counters_from_0_10_still_reads() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("status.json");
        fs::write(
            &p,
            r#"{"listening":true,"state":"ready","lists_updated":5,"day":20000,
                "blocked":[1,2,3,4,5],"domains":[10,20,30,40,50],"last_error":null,
                "written_at":99,"lookups":"private","dangerous_at":7}"#,
        )
        .unwrap();
        let s = load_status(&p).unwrap();
        assert_eq!(s.blocked, [1, 2, 3, 4, 5, 0, 0]);
        assert_eq!(s.domains, [10, 20, 30, 40, 50, 0, 0]);
        assert_eq!(s.dangerous_at, Some(7));
    }

    #[test]
    fn new_status_has_seven_counters_and_names_no_site_by_default() {
        let s = Status {
            blocked: [1, 2, 3, 4, 5, 6, 7],
            dangerous_at: Some(7),
            ..Status::default()
        };
        let text = serde_json::to_string(&s).unwrap();
        assert!(text.contains("\"blocked\":[1,2,3,4,5,6,7]"));
        assert!(text.contains("\"dangerous_at\":7"));
        assert!(text.contains("\"lookups\":\"plain\""));
        assert!(text.contains("\"notice\":null"));
    }

    #[test]
    fn recent_and_stats_files_read_back_and_tolerate_trouble() {
        let d = tempfile::tempdir().unwrap();
        let recent = d.path().join("recent.json");
        fs::write(
            &recent,
            r#"{"items":[{"name":"ads.example.com","kind":"ads","at":1791334020},
                          {"name":"x.example","kind":"gambling","at":1791334000}]}"#,
        )
        .unwrap();
        let list = load_recent(&recent).unwrap();
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].kind, Kind::Ads);
        assert_eq!(list.items[1].kind, Kind::Gambling);
        assert_eq!(load_recent(&d.path().join("missing.json")), None);
        fs::write(&recent, "{{").unwrap();
        assert_eq!(load_recent(&recent), None);
        fs::write(&recent, vec![b' '; 70_000]).unwrap();
        assert_eq!(load_recent(&recent), None);
        fs::write(
            &recent,
            r#"{"items":[{"name":"a.b","kind":"banana","at":1}]}"#,
        )
        .unwrap();
        assert_eq!(load_recent(&recent), None);

        let stats = d.path().join("stats.json");
        fs::write(
            &stats,
            r#"{"days":[{"day":20368,"blocked":[1,2,3,4,5]},{"day":20369,"blocked":[1,2,3]}],
                "top":[{"site":"doubleclick.net","count":120}]}"#,
        )
        .unwrap();
        let h = load_stats(&stats).unwrap();
        assert_eq!(h.days[0].blocked, [1, 2, 3, 4, 5, 0, 0]);
        assert_eq!(h.days[1].blocked, [1, 2, 3, 0, 0, 0, 0]);
        assert_eq!(h.top[0].site, "doubleclick.net");
        assert_eq!(load_stats(&d.path().join("missing.json")), None);
        fs::write(&stats, "{}").unwrap();
        assert_eq!(load_stats(&stats), Some(BlockHistory::default()));
    }

    #[test]
    fn recent_window_drops_old_and_orders_newest_first() {
        let item = |name: &str, at| RecentItem {
            name: name.into(),
            kind: Kind::Ads,
            at,
        };
        let list = RecentList {
            items: vec![
                item("old", 1000),
                item("newer", 1800),
                item("edge", 1000 + RECENT_SECONDS),
                item("future", 5000),
            ],
        }
        .within_window(1000 + RECENT_SECONDS);
        let names: Vec<_> = list.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["edge", "newer", "old"]);
        let later = RecentList {
            items: list.items.clone(),
        }
        .within_window(1000 + RECENT_SECONDS + 1);
        assert_eq!(later.items.len(), 2);
    }

    #[test]
    fn freshness_window() {
        let s = Status {
            written_at: 1000,
            ..Status::default()
        };
        assert!(fresh(&s, 1000));
        assert!(fresh(&s, 1120));
        assert!(!fresh(&s, 1121));
        // A timestamp from the future is not fresh.
        assert!(!fresh(&s, 999));
    }
}
