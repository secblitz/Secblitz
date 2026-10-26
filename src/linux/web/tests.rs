use super::*;
use crate::filter::config::{AllowOnce, ErrorCode, State};
use crate::linux::cmd::fake::FakeSys;

const NOW: u64 = 1_800_000_000;
const CONFIG: &str = "/var/lib/secblitz-filter/config.json";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn on() -> Config {
    Config {
        ads: true,
        ..Config::default()
    }
}

fn listening(at: u64) -> Status {
    Status {
        listening: true,
        state: State::Ready,
        written_at: at,
        ..Status::default()
    }
}

fn put<T: Serialize>(sys: &FakeSys, file: PathBuf, value: &T) {
    sys.file(file.to_str().unwrap(), &serde_json::to_vec(value).unwrap());
}

/// A computer where the lookup service answers, with everything the commands may run.
fn computer() -> FakeSys {
    let sys = FakeSys::default();
    sys.reply(SYSTEMCTL, &["is-active", RESOLVED_UNIT], 0, "active\n");
    sys.reply(TEST, &["-x", RESOLVECTL], 0, "");
    sys.reply(
        READLINK,
        &["-f", ETC_RESOLV_CONF],
        0,
        "/run/systemd/resolve/stub-resolv.conf\n",
    );
    sys.reply(MKDIR, &["-p", DROPIN_DIR], 0, "");
    sys.reply(SYSTEMCTL, &["try-restart", RESOLVED_UNIT], 0, "");
    sys.reply(
        SYSTEMCTL,
        &["--no-block", "try-restart", RESOLVED_UNIT],
        0,
        "",
    );
    sys.reply(RESOLVECTL, &["flush-caches"], 0, "");
    sys.reply(SYSTEMCTL, &["is-system-running"], 1, "running\n");
    sys.reply(
        SYSTEMCTL,
        &["show", "--property=LoadState,ActiveState", UNIT],
        0,
        "LoadState=loaded\nActiveState=active\n",
    );
    sys.reply(SYSTEMCTL, &["enable", "--now", UNIT], 0, "");
    sys.reply(SYSTEMCTL, &["disable", "--now", UNIT], 0, "");
    sys
}

fn ran(sys: &FakeSys) -> Vec<String> {
    sys.calls.borrow().clone()
}

fn position(calls: &[String], what: &str) -> usize {
    calls
        .iter()
        .position(|c| c.contains(what))
        .unwrap_or_else(|| panic!("{what} did not run: {calls:?}"))
}

fn file(sys: &FakeSys, path: &str) -> Option<String> {
    sys.files
        .borrow()
        .get(std::path::Path::new(path))
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

fn saved(sys: &FakeSys) -> Config {
    serde_json::from_str(&file(sys, CONFIG).unwrap()).unwrap()
}

#[test]
fn the_lookup_setting_has_the_exact_text() {
    assert_eq!(
        dropin_text(),
        "# Written by Secblitz while web protection is on. It is taken away whenever web protection stops.\n\
         [Resolve]\nDNS=\nDNS=127.0.0.153\nDomains=~.\nDNSOverTLS=no\n"
    );
}

#[test]
fn the_setting_sorts_after_the_private_lookups_file_and_lives_in_the_volatile_folder() {
    assert!(DROPIN.starts_with("/run/"));
    let ours = DROPIN.rsplit('/').next().unwrap();
    assert!(ours > "90-secblitz-dns.conf");
    assert!(ours > "90-secblitz.conf");
    assert_eq!(ours, crate::linux::web_gaps::OUR_DROPIN_NAME);
}

#[test]
fn the_filter_never_listens_where_the_lookup_service_does() {
    assert!(LISTEN.is_loopback());
    assert_ne!(LISTEN, Ipv4Addr::new(127, 0, 0, 53));
    assert_ne!(LISTEN, Ipv4Addr::new(127, 0, 0, 54));
    assert_ne!(LISTEN, Ipv4Addr::LOCALHOST);
}

const UBUNTU_RESOLV: &str = "\
# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.

nameserver 127.0.0.153
nameserver 192.168.1.1
nameserver fe80::1%2
nameserver 2001:4860:4860::8888
nameserver 192.168.1.1
search lan.example corp.example
";

#[test]
fn the_networks_servers_are_read_and_ours_and_loopback_are_left_out() {
    let (servers, suffixes) = parse_resolv_conf(UBUNTU_RESOLV);
    assert_eq!(servers, [ip("192.168.1.1"), ip("2001:4860:4860::8888")]);
    assert_eq!(suffixes, ["lan.example", "corp.example"]);
}

#[test]
fn only_four_servers_are_kept_and_comments_and_odd_lines_are_ignored() {
    let text = "; comment\n# comment\noptions edns0\nnameserver 10.0.0.1\nnameserver 10.0.0.2\n\
                nameserver 10.0.0.3\nnameserver 10.0.0.4\nnameserver 10.0.0.5\nnameserver nonsense\n\
                nameserver\nnameserver 127.0.0.53\nnameserver ::1\n";
    let (servers, suffixes) = parse_resolv_conf(text);
    assert_eq!(servers.len(), 4);
    assert_eq!(servers[0], ip("10.0.0.1"));
    assert!(suffixes.is_empty());
    assert_eq!(parse_resolv_conf(""), (Vec::new(), Vec::new()));
}

#[test]
fn the_last_search_line_wins_and_public_endings_are_dropped() {
    let (_, suffixes) = parse_resolv_conf("search old.example\nsearch com home.example\n");
    assert_eq!(suffixes, ["home.example"]);
    let (_, suffixes) = parse_resolv_conf("domain fritz.box\n");
    assert_eq!(suffixes, ["fritz.box"]);
}

#[test]
fn the_service_state_comes_from_the_system_managers_words() {
    let state =
        |l: &str, a: &str| parse_service_state(&format!("LoadState={l}\nActiveState={a}\n"));
    assert_eq!(state("loaded", "active"), ServiceState::Running);
    assert_eq!(state("loaded", "inactive"), ServiceState::Stopped);
    assert_eq!(state("loaded", "failed"), ServiceState::Stopped);
    assert_eq!(state("loaded", "activating"), ServiceState::Other);
    assert_eq!(state("loaded", "deactivating"), ServiceState::Other);
    assert_eq!(state("not-found", "inactive"), ServiceState::NotInstalled);
    assert_eq!(parse_service_state(""), ServiceState::Other);
}

#[test]
fn web_protection_is_offered_only_where_the_lookup_service_answers_programs() {
    assert!(resolver_in_use(&computer()));
    for target in [
        "/run/systemd/resolve/resolv.conf",
        "/usr/lib/systemd/resolv.conf",
    ] {
        let sys = computer();
        sys.reply(
            READLINK,
            &["-f", ETC_RESOLV_CONF],
            0,
            &format!("{target}\n"),
        );
        assert!(resolver_in_use(&sys), "{target}");
    }
    let direct = computer();
    direct.reply(
        READLINK,
        &["-f", ETC_RESOLV_CONF],
        0,
        "/run/NetworkManager/no-stub-resolv.conf\n",
    );
    assert!(!resolver_in_use(&direct));
    let plain_file = computer();
    plain_file.reply(READLINK, &["-f", ETC_RESOLV_CONF], 0, "/etc/resolv.conf\n");
    plain_file.file(ETC_RESOLV_CONF, b"nameserver 127.0.0.53\noptions edns0\n");
    assert!(resolver_in_use(&plain_file));
    plain_file.file(ETC_RESOLV_CONF, b"nameserver 192.168.1.1\n");
    assert!(!resolver_in_use(&plain_file));
    let stopped = computer();
    stopped.reply(SYSTEMCTL, &["is-active", RESOLVED_UNIT], 3, "inactive\n");
    assert!(!resolver_in_use(&stopped));
    let no_tool = computer();
    no_tool.reply(TEST, &["-x", RESOLVECTL], 1, "");
    assert!(!resolver_in_use(&no_tool));
}

#[test]
fn lookups_are_sent_to_the_filter_only_while_it_is_really_answering() {
    let running = ServiceState::Running;
    let status = listening(NOW - 5);
    let ours = dropin_text();
    let next = |config: &Config, service, status: Option<&Status>, current: Option<&str>| {
        next_step(config, service, status, current, NOW)
    };
    assert_eq!(next(&on(), running, Some(&status), None), Step::Add);
    assert_eq!(
        next(&on(), running, Some(&status), Some(&ours)),
        Step::Nothing
    );
    assert_eq!(
        next(&on(), running, Some(&status), Some("old text")),
        Step::Add
    );
    let private = Config {
        private_lookups: true,
        ..Config::default()
    };
    assert_eq!(next(&private, running, Some(&status), None), Step::Add);
    let paused = Config {
        paused_until: Some(NOW + 600),
        ..on()
    };
    assert_eq!(
        next(&paused, running, Some(&status), Some(&ours)),
        Step::Nothing,
        "a pause keeps the setting; the filter then forwards everything"
    );
    let not_listening = Status {
        listening: false,
        ..status.clone()
    };
    let stale = listening(NOW - 500);
    for (service, status) in [
        (ServiceState::Stopped, Some(&status)),
        (ServiceState::NotInstalled, Some(&status)),
        (ServiceState::Other, Some(&status)),
        (running, Some(&not_listening)),
        (running, Some(&stale)),
        (running, None),
    ] {
        assert_eq!(next(&on(), service, status, Some(&ours)), Step::Remove);
        assert_eq!(next(&on(), service, status, None), Step::Nothing);
    }
    let off = Config::default();
    assert_eq!(
        next(&off, running, Some(&status), Some(&ours)),
        Step::Remove
    );
    assert_eq!(next(&off, running, Some(&status), None), Step::Nothing);
}

#[test]
fn the_setting_is_written_and_the_lookup_service_restarted_and_its_answers_forgotten() {
    let sys = computer();
    put(&sys, config_path(), &on());
    put(&sys, data("status.json"), &listening(NOW - 1));
    reconcile(&sys, ServiceState::Running, NOW).unwrap();
    assert_eq!(file(&sys, DROPIN).unwrap(), dropin_text());
    let calls = ran(&sys);
    assert!(position(&calls, "mkdir -p") < position(&calls, "try-restart"));
    assert!(position(&calls, "try-restart") < position(&calls, "flush-caches"));
    reconcile(&sys, ServiceState::Running, NOW).unwrap();
    assert_eq!(
        ran(&sys)
            .iter()
            .filter(|c| c.contains("try-restart"))
            .count(),
        1,
        "nothing is restarted when the setting is already right"
    );
}

#[test]
fn the_unit_adds_the_setting_after_it_reports_ready_even_before_it_counts_as_running() {
    let sys = computer();
    put(&sys, config_path(), &on());
    put(&sys, data("status.json"), &listening(NOW));
    add_rule_when_ready(&sys, NOW).unwrap();
    assert!(file(&sys, DROPIN).is_some());
    let idle = computer();
    put(&idle, data("status.json"), &listening(NOW));
    add_rule_when_ready(&idle, NOW).unwrap();
    assert!(
        file(&idle, DROPIN).is_none(),
        "nothing is on, so nothing is added"
    );
}

#[test]
fn the_units_own_steps_never_wait_for_the_lookup_service_to_restart() {
    let sys = computer();
    put(&sys, config_path(), &on());
    put(&sys, data("status.json"), &listening(NOW));
    add_rule_when_ready(&sys, NOW).unwrap();
    assert!(file(&sys, DROPIN).is_some());
    remove_rule_from_unit(&sys).unwrap();
    assert!(file(&sys, DROPIN).is_none());
    let restarts: Vec<String> = ran(&sys)
        .into_iter()
        .filter(|c| c.contains("try-restart"))
        .collect();
    assert_eq!(restarts.len(), 2, "{restarts:?}");
    assert!(
        restarts.iter().all(|c| c.contains("--no-block")),
        "a restart that waits would hold up the filter's own start or stop: {restarts:?}"
    );
}

#[test]
fn a_filter_that_is_not_answering_gets_no_setting() {
    let sys = computer();
    put(&sys, config_path(), &on());
    put(
        &sys,
        data("status.json"),
        &Status {
            listening: false,
            last_error: Some(ErrorCode::PortInUse),
            written_at: NOW,
            ..Status::default()
        },
    );
    add_rule_when_ready(&sys, NOW).unwrap();
    assert!(file(&sys, DROPIN).is_none());
    assert!(ran(&sys).iter().all(|c| !c.contains("try-restart")));
}

#[test]
fn a_restart_that_fails_leaves_no_setting_behind() {
    let sys = computer();
    put(&sys, config_path(), &on());
    put(&sys, data("status.json"), &listening(NOW));
    sys.reply(SYSTEMCTL, &["try-restart", RESOLVED_UNIT], 1, "");
    assert!(reconcile(&sys, ServiceState::Running, NOW).is_err());
    assert!(file(&sys, DROPIN).is_none());
}

#[test]
fn nothing_is_added_where_the_lookup_service_is_not_in_use() {
    let sys = computer();
    sys.reply(SYSTEMCTL, &["is-active", RESOLVED_UNIT], 3, "inactive\n");
    put(&sys, config_path(), &on());
    put(&sys, data("status.json"), &listening(NOW));
    let error = reconcile(&sys, ServiceState::Running, NOW).unwrap_err();
    assert_eq!(error.to_string(), NOT_AVAILABLE);
    assert!(file(&sys, DROPIN).is_none());
}

#[test]
fn taking_the_setting_away_restarts_the_lookup_service_unless_the_system_is_going_down() {
    let sys = computer();
    sys.file(DROPIN, dropin_text().as_bytes());
    remove_rule(&sys).unwrap();
    assert!(file(&sys, DROPIN).is_none());
    assert!(ran(&sys).iter().any(|c| c.contains("try-restart")));
    assert!(ran(&sys).iter().any(|c| c.contains("flush-caches")));

    let again = computer();
    remove_rule(&again).unwrap();
    assert!(ran(&again).is_empty(), "no setting, nothing to undo");

    let shutdown = computer();
    shutdown.reply(SYSTEMCTL, &["is-system-running"], 1, "stopping\n");
    shutdown.file(DROPIN, dropin_text().as_bytes());
    remove_rule(&shutdown).unwrap();
    assert!(file(&shutdown, DROPIN).is_none());
    assert!(ran(&shutdown).iter().all(|c| !c.contains("try-restart")));
}

#[test]
fn turning_web_protection_on_starts_the_filter_saves_the_switches_and_sends_lookups_to_it() {
    let sys = computer();
    put(&sys, data("status.json"), &listening(NOW));
    apply(&sys, on(), || NOW).unwrap();
    assert!(saved(&sys).ads);
    assert_eq!(file(&sys, DROPIN).unwrap(), dropin_text());
    let calls = ran(&sys);
    assert!(position(&calls, "enable --now") < position(&calls, "mkdir -p"));
}

#[test]
fn the_config_file_sits_in_the_filters_own_folder() {
    assert_eq!(config_path(), PathBuf::from(CONFIG));
    assert_eq!(
        data("status.json"),
        PathBuf::from("/var/lib/secblitz-filter/Data/status.json")
    );
}

#[test]
fn turning_web_protection_on_where_it_cannot_work_says_so_and_changes_nothing() {
    let sys = computer();
    sys.reply(SYSTEMCTL, &["is-active", RESOLVED_UNIT], 3, "inactive\n");
    let error = apply(&sys, on(), || NOW).unwrap_err();
    assert_eq!(error.to_string(), NOT_AVAILABLE);
    assert!(sys.files.borrow().is_empty());
    assert!(ran(&sys).iter().all(|c| !c.contains("enable")));
}

#[test]
fn a_filter_that_cannot_start_is_stopped_again_and_nothing_is_saved() {
    let sys = computer();
    sys.reply(SYSTEMCTL, &["enable", "--now", UNIT], 1, "");
    let error = apply(&sys, on(), || NOW).unwrap_err();
    assert_eq!(error.to_string(), COULD_NOT_START);
    assert!(sys.files.borrow().is_empty());
    assert!(ran(&sys).iter().any(|c| c.contains("disable --now")));
}

#[test]
fn turning_everything_off_takes_the_setting_away_before_the_filter_stops() {
    let sys = computer();
    sys.file(DROPIN, dropin_text().as_bytes());
    put(&sys, config_path(), &on());
    apply(&sys, Config::default(), || NOW).unwrap();
    assert!(file(&sys, DROPIN).is_none());
    assert!(!saved(&sys).needs_service());
    let calls = ran(&sys);
    assert!(position(&calls, "try-restart") < position(&calls, "disable --now"));
}

#[test]
fn turning_off_what_was_never_on_needs_no_filter() {
    let sys = computer();
    sys.reply(
        SYSTEMCTL,
        &["show", "--property=LoadState,ActiveState", UNIT],
        0,
        "LoadState=not-found\nActiveState=inactive\n",
    );
    apply(&sys, Config::default(), || NOW).unwrap();
    assert!(sys.files.borrow().is_empty());
    assert!(ran(&sys).iter().all(|c| !c.contains("disable")));
}

#[test]
fn removing_everything_runs_every_step_even_when_one_fails() {
    let sys = computer();
    sys.file(DROPIN, dropin_text().as_bytes());
    sys.reply(SYSTEMCTL, &["try-restart", RESOLVED_UNIT], 1, "");
    assert!(remove_everything(&sys).is_err());
    assert!(file(&sys, DROPIN).is_none());
    assert!(ran(&sys).iter().any(|c| c.contains("disable --now")));
}

#[test]
fn a_site_is_allowed_and_let_through_once_and_taken_back_in_the_saved_settings() {
    let sys = computer();
    put(&sys, config_path(), &on());
    allow_site(&sys, "Example.COM.", NOW).unwrap();
    allow_site_once(&sys, "shop.example", NOW).unwrap();
    let now_saved = saved(&sys);
    assert!(now_saved.ads);
    assert_eq!(now_saved.allow, ["example.com"]);
    assert_eq!(
        now_saved.allow_once,
        [AllowOnce {
            site: "shop.example".into(),
            until: NOW + config::ALLOW_ONCE_SECONDS
        }]
    );
    remove_allowed(&sys, "example.com", NOW).unwrap();
    assert!(saved(&sys).allow.is_empty());
}

#[test]
fn a_name_that_is_not_a_website_is_refused_before_anything_is_saved() {
    let sys = computer();
    put(&sys, config_path(), &on());
    let before = file(&sys, CONFIG);
    for bad in ["", "not a name", "a/b", "../x", "x;y"] {
        assert_eq!(
            allow_site(&sys, bad, NOW).unwrap_err().to_string(),
            NOT_A_SITE,
            "{bad}"
        );
        assert_eq!(
            allow_site_once(&sys, bad, NOW).unwrap_err().to_string(),
            NOT_A_SITE
        );
        assert!(check_site(bad).is_err(), "{bad}");
    }
    assert_eq!(file(&sys, CONFIG), before);
}

#[test]
fn pausing_stores_the_end_of_the_pause_and_resuming_clears_it() {
    let sys = computer();
    put(&sys, config_path(), &on());
    pause_web(&sys, PauseFor::Quarter, NOW).unwrap();
    assert_eq!(saved(&sys).paused_until, Some(NOW + 900));
    pause_web(&sys, PauseFor::Hour, NOW).unwrap();
    assert_eq!(saved(&sys).paused_until, Some(NOW + 3600));
    pause_web(&sys, PauseFor::UntilRestart, NOW).unwrap();
    let c = saved(&sys);
    assert_eq!(c.paused_until, None);
    assert!(c.paused_boot.is_some());
    resume(&sys, NOW).unwrap();
    let c = saved(&sys);
    assert_eq!((c.paused_until, c.paused_boot), (None, None));
    assert!(c.ads);
}

#[test]
fn saving_without_the_filters_folder_gives_a_plain_sentence() {
    struct NoFolder(FakeSys);
    impl Sys for NoFolder {
        fn run(&self, p: &'static str, a: &[&str]) -> Result<crate::linux::cmd::Output> {
            self.0.run(p, a)
        }
        fn read(&self, p: &std::path::Path) -> Result<Option<Vec<u8>>> {
            self.0.read(p)
        }
        fn write_atomic(&self, _: &std::path::Path, _: &[u8], _: u32) -> Result<()> {
            anyhow::bail!("No such folder")
        }
        fn remove(&self, p: &std::path::Path) -> Result<()> {
            self.0.remove(p)
        }
    }
    let sys = NoFolder(computer());
    assert_eq!(
        allow_site(&sys, "example.com", NOW)
            .unwrap_err()
            .to_string(),
        COULD_NOT_SAVE
    );
}

#[test]
fn a_request_with_too_many_or_odd_names_is_refused() {
    check_config(&Config::default()).unwrap();
    check_config(&Config {
        allow: vec!["example.com".into()],
        allow_once: vec![AllowOnce {
            site: "shop.example".into(),
            until: NOW,
        }],
        ..on()
    })
    .unwrap();
    let many = Config {
        allow: (0..=MAX_ALLOWED)
            .map(|i| format!("site{i}.example"))
            .collect(),
        ..on()
    };
    assert_eq!(check_config(&many).unwrap_err().to_string(), ALLOWED_FULL);
    let many_once = Config {
        allow_once: (0..=MAX_ALLOWED_ONCE)
            .map(|i| AllowOnce {
                site: format!("site{i}.example"),
                until: NOW,
            })
            .collect(),
        ..on()
    };
    assert!(check_config(&many_once).is_err());
    for bad in ["Example.com", "example.com.", "a b", "", "x/y"] {
        let c = Config {
            allow: vec![bad.into()],
            ..on()
        };
        assert_eq!(
            check_config(&c).unwrap_err().to_string(),
            NOT_A_SITE,
            "{bad}"
        );
        let c = Config {
            allow_once: vec![AllowOnce {
                site: bad.into(),
                until: NOW,
            }],
            ..on()
        };
        assert!(check_config(&c).is_err(), "{bad}");
    }
    assert!(check_site("example.com").is_ok());
    assert!(check_site(&format!("{}.example", "a".repeat(300))).is_err());
}

#[test]
fn the_state_the_window_reads_gathers_the_files_the_filter_wrote() {
    let sys = computer();
    put(&sys, config_path(), &on());
    put(&sys, data("status.json"), &listening(NOW - 3));
    put(
        &sys,
        data("recent.json"),
        &RecentList {
            items: vec![
                RecentItem {
                    name: "old.example".into(),
                    kind: crate::filter::matcher::Kind::Scam,
                    at: NOW - 4000,
                },
                RecentItem {
                    name: "new.example".into(),
                    kind: crate::filter::matcher::Kind::Scam,
                    at: NOW - 10,
                },
            ],
        },
    );
    sys.file(DROPIN, dropin_text().as_bytes());
    let got = state(&sys, NOW);
    assert!(got.available && got.routed);
    assert!(got.config.ads);
    assert_eq!(got.service, ServiceState::Running);
    assert_eq!(got.status.as_ref().unwrap().written_at, NOW - 3);
    assert_eq!(got.recent.len(), 1);
    assert_eq!(got.recent[0].name, "new.example");
    assert!(got.stats.is_none());
    let json = serde_json::to_string(&got).unwrap();
    assert_eq!(serde_json::from_str::<WebState>(&json).unwrap(), got);
}

#[test]
fn a_computer_that_never_had_web_protection_reads_as_everything_off() {
    let got = state(&computer(), NOW);
    assert_eq!(got.config, Config::default());
    assert!(got.status.is_none() && got.recent.is_empty() && !got.routed);
}

#[test]
fn files_that_are_too_big_or_broken_read_as_nothing() {
    let sys = computer();
    sys.file(CONFIG, b"{\"ads\":true");
    sys.file(
        data("status.json").to_str().unwrap(),
        &vec![b' '; MAX_STATUS as usize + 1],
    );
    let got = state(&sys, NOW);
    assert_eq!(got.config, Config::default());
    assert!(got.status.is_none());
}

#[test]
fn other_checks_can_tell_from_the_text_whether_web_protection_is_set_up() {
    assert!(config_needs_service(
        r#"{"ads":true,"tracking":false,"dangerous":false}"#
    ));
    assert!(config_needs_service(
        r#"{"ads":false,"tracking":false,"dangerous":false,"private_lookups":true}"#
    ));
    assert!(!config_needs_service(
        r#"{"ads":false,"tracking":false,"dangerous":false}"#
    ));
    assert!(!config_needs_service("not json"));
    assert!(!config_needs_service(""));
}

#[test]
fn every_sentence_web_protection_shows_is_plain_and_has_no_em_dash() {
    for sentence in SENTENCES {
        assert!(!sentence.contains('\u{2014}'), "{sentence}");
        for jargon in ["DNS", "resolver", "systemd", "daemon", "port"] {
            assert!(!sentence.contains(jargon), "{sentence} mentions {jargon}");
        }
    }
}
