//! The topics the Protection page groups its settings under.
use super::flow;
use secblitz::engine::Report;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topic {
    Threats,
    SignIn,
    Network,
    Windows,
    Browsers,
    Privacy,
    Ai,
    Clutter,
}

impl Topic {
    pub const ALL: [Topic; 8] = [
        Topic::Threats,
        Topic::SignIn,
        Topic::Network,
        Topic::Windows,
        Topic::Browsers,
        Topic::Privacy,
        Topic::Ai,
        Topic::Clutter,
    ];

    /// The topics that hold at least one check on `os`, in display order. Windows shows all of them.
    pub fn shown_on(os: secblitz::os::Os) -> Vec<Topic> {
        if os == secblitz::os::Os::Windows {
            return Topic::ALL.to_vec();
        }
        let ids = secblitz::engine::catalog::ids(os);
        Topic::ALL
            .into_iter()
            .filter(|t| ids.iter().any(|id| Topic::of(id) == *t))
            .collect()
    }

    /// The topic a setting belongs to. The first rule that fits wins; unknown settings are Windows settings.
    pub fn of(id: &str) -> Topic {
        let head = id.split_once('.').map_or(id, |(head, _)| head);
        match (head, id) {
            (_, "smartscreen.apps" | "net.hosts_file") | ("defender" | "clickfix", _) => {
                Topic::Threats
            }
            ("uac" | "accounts" | "lsa" | "wdigest" | "ntlm" | "session", _) => Topic::SignIn,
            (
                "firewall" | "net" | "tls" | "smb" | "smb1" | "remote_desktop"
                | "remote_assistance" | "wifi",
                _,
            )
            | (_, "printer.spooler_remote" | "services.legacy_remote") => Topic::Network,
            ("browser", _) | (_, "smartscreen.browser_policy") => Topic::Browsers,
            (_, "privacy.recall") | ("ai", _) => Topic::Ai,
            ("privacy", _) => Topic::Privacy,
            ("debloat", _) => Topic::Clutter,
            (
                "linux",
                "linux.firewall"
                | "linux.fedora_open_ports"
                | "linux.ssh_server"
                | "linux.ssh_password"
                | "linux.file_sharing"
                | "linux.remote_desktop"
                | "linux.network_redirects"
                | "linux.llmnr"
                | "linux.rare_protocols"
                | "linux.fake_sources"
                | "linux.flood_protection"
                | "linux.source_routing"
                | "linux.broadcast_pings"
                | "linux.announce_name"
                | "linux.old_network_services"
                | "linux.bluetooth_autostart",
            ) => Topic::Network,
            (
                "linux",
                "linux.autologin"
                | "linux.guest"
                | "linux.screen_lock"
                | "linux.media_autorun"
                | "linux.home_private"
                | "linux.root_account"
                | "linux.screen_off_delay"
                | "linux.lock_delay"
                | "linux.lock_on_suspend",
            ) => Topic::SignIn,
            (
                "linux",
                "linux.browser_data_collection"
                | "linux.browser_https_only"
                | "linux.browser_tracking"
                | "linux.browser_ad_topics"
                | "linux.browser_sponsored"
                | "linux.browser_pocket"
                | "linux.browser_safe_browsing"
                | "linux.browser_password_leaks"
                | "linux.browser_background"
                | "linux.browser_search_suggestions"
                | "linux.browser_encrypted_dns",
            ) => Topic::Browsers,
            (
                "linux",
                "linux.crash_reports"
                | "linux.countme"
                | "linux.connectivity_check"
                | "linux.wifi_mac"
                | "linux.ipv6_privacy"
                | "linux.computer_name_sent"
                | "linux.encrypted_dns"
                | "linux.recent_files"
                | "linux.lock_previews"
                | "linux.ubuntu_insights"
                | "linux.location"
                | "linux.problem_reports"
                | "linux.app_usage"
                | "linux.old_files"
                | "linux.crash_files"
                | "linux.usage_stats",
            ) => Topic::Privacy,
            ("linux", "linux.printer_sharing" | "linux.printer_discovery") => Topic::Network,
            ("linux", "linux.ubuntu_news" | "linux.usage_survey") => Topic::Privacy,
            (
                "linux",
                "linux.memory_shuffle"
                | "linux.bpf_hardening"
                | "linux.terminal_drivers"
                | "linux.crash_memory"
                | "linux.app_sandbox_limits"
                | "linux.processor_updates",
            ) => Topic::Windows,
            _ => Topic::Windows,
        }
    }

    pub fn of_finding(title: &str) -> Topic {
        if let Some(id) = secblitz::advice::control_for_finding(title) {
            return Topic::of(id);
        }
        match title {
            "Security providers" | "Defender" | "SmartScreen" => Topic::Threats,
            "Windows Firewall" => Topic::Network,
            secblitz::advice::ACCOUNTS_WITHOUT_PASSWORD
            | secblitz::advice::ADMIN_WITHOUT_PASSWORD
            | secblitz::advice::EXTRA_ADMIN_ACCOUNTS
            | secblitz::advice::ADMIN_ACCOUNTS => Topic::SignIn,
            secblitz::advice::OPEN_PROGRAMS => Topic::Network,
            _ if title.starts_with("asr.") || title.starts_with("cfa.") => Topic::Threats,
            _ if title.starts_with("dns.") => Topic::Network,
            _ => Topic::of(title),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Topic::Threats => "Viruses and threats",
            Topic::SignIn => "Sign-in",
            Topic::Network => "Network",
            Topic::Windows => "Windows",
            Topic::Browsers => "Browsers",
            Topic::Privacy => "Privacy",
            Topic::Ai => "AI features",
            Topic::Clutter => "Less clutter",
        }
    }

    /// The name shown to the person. The topic saved as `windows` is "System" on the other systems.
    pub fn display_label(self, os: secblitz::os::Os) -> &'static str {
        match (self, os) {
            (Topic::Windows, secblitz::os::Os::Linux | secblitz::os::Os::Macos) => "System",
            _ => self.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub to_fix: usize,
    pub to_look: usize,
    pub switched_back: usize,
    pub options: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    ToFix(usize),
    SwitchedBack(usize),
    ToLookAt(usize),
    Options(usize),
    AllSet,
    Checking,
}

impl Line {
    pub fn of(counts: Option<Counts>) -> Line {
        match counts {
            None => Line::Checking,
            Some(c) if c.to_fix > 0 => Line::ToFix(c.to_fix),
            Some(c) if c.switched_back > 0 => Line::SwitchedBack(c.switched_back),
            Some(c) if c.to_look > 0 => Line::ToLookAt(c.to_look),
            Some(c) if c.options > 0 => Line::Options(c.options),
            Some(_) => Line::AllSet,
        }
    }

    pub fn needs_action(self) -> bool {
        matches!(self, Line::ToFix(_) | Line::SwitchedBack(_))
    }
}

/// Optional settings that were switched back are tagged but left for the person to tick.
pub fn default_selection(report: &Report, available: &[String]) -> Vec<String> {
    flow::recommended(report, available)
}

pub fn first_needing_action(lines: impl Fn(Topic) -> Line) -> Option<Topic> {
    Topic::ALL.into_iter().find(|t| lines(*t).needs_action())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secblitz::engine::Outcome;
    use secblitz::model::CheckStatus;
    use Topic::*;

    #[test]
    fn windows_shows_every_topic() {
        assert_eq!(
            Topic::shown_on(secblitz::os::Os::Windows),
            Topic::ALL.to_vec()
        );
    }

    #[test]
    fn linux_shows_only_topics_with_linux_checks() {
        let shown = Topic::shown_on(secblitz::os::Os::Linux);
        assert_eq!(shown, vec![SignIn, Network, Windows, Browsers, Privacy]);
        for gone in [Threats, Ai, Clutter] {
            assert!(!shown.contains(&gone));
        }
    }

    #[test]
    fn a_system_without_checks_shows_no_topics() {
        assert!(Topic::shown_on(secblitz::os::Os::Macos).is_empty());
    }

    #[test]
    fn every_hardening_setting_goes_where_the_design_says() {
        let expected: &[(&str, Topic)] = &[
            ("defender.cloud_protection", Threats),
            ("defender.pua", Threats),
            ("defender.script_nis", Threats),
            ("defender.asr.standard", Threats),
            ("defender.asr.web_script_email", Threats),
            ("defender.asr.office", Threats),
            ("defender.asr.ransomware_usb", Threats),
            ("defender.network_protection", Threats),
            ("defender.cfa_watch", Threats),
            ("defender.cfa_block", Threats),
            ("defender.cfa_allowed_apps", Threats),
            ("defender.cloud_block_level", Threats),
            ("defender.exclusions_risky", Threats),
            ("smartscreen.apps", Threats),
            ("net.hosts_file", Threats),
            ("lsa.run_as_ppl", SignIn),
            ("lsa.restrict_anonymous", SignIn),
            ("accounts.lockout_policy", SignIn),
            ("accounts.builtin_administrator", SignIn),
            ("accounts.autologon", SignIn),
            ("accounts.stale_enabled", SignIn),
            ("ntlm.lm_compat_level", SignIn),
            ("ntlm.extras", SignIn),
            ("session.lock_on_wake", SignIn),
            ("net.public_sharing_exposure", Network),
            ("net.llmnr", Network),
            ("net.stack_hardening", Network),
            ("net.netbios", Network),
            ("net.mdns", Network),
            ("net.wpad", Network),
            ("wifi.risky_profiles", Network),
            ("remote_assistance.disabled", Network),
            ("remote_desktop.disabled", Network),
            ("firewall.outbound_smb_internet", Network),
            ("firewall.user_dir_inbound_allow", Network),
            ("tls.legacy_protocols", Network),
            ("printer.spooler_remote", Network),
            ("services.legacy_remote", Network),
            ("smb1.disabled", Network),
            ("smb.shares_exposed", Network),
            ("printer.point_and_print", Windows),
            ("autorun.disabled", Windows),
            ("clickfix.run_box", Threats),
            ("wsh.disabled", Windows),
            ("update.auto_policy_disabled", Windows),
            ("update.store_autoupdate_policy", Windows),
            ("update.paused", Windows),
            ("driver.vulnerable_blocklist", Windows),
            ("system.exploit_mitigations", Windows),
            ("ps.v2_engine", Windows),
            ("vbs.memory_integrity", Windows),
            ("vbs.kernel_stack_protection", Windows),
            ("services.unquoted_paths", Windows),
            ("persistence.run_and_tasks", Windows),
            ("recovery.winre_enabled", Windows),
            ("smartscreen.browser_policy", Browsers),
            ("privacy.activity_history", Privacy),
            ("privacy.advertising_id", Privacy),
            ("privacy.diagnostic_data_level", Privacy),
            ("privacy.delivery_optimization", Privacy),
            ("privacy.clipboard_sync", Privacy),
            ("privacy.online_speech", Privacy),
            ("privacy.typing_inking", Privacy),
            ("privacy.lock_screen_notifications", Privacy),
            ("privacy.signin_email", Privacy),
            ("privacy.wifi_random_address", Privacy),
            ("browser.shopping_ai", Browsers),
            ("browser.data_collection", Browsers),
            ("browser.safety_mode", Browsers),
            ("browser.dns_bypass", Browsers),
            ("browser.extensions_off", Browsers),
            ("privacy.recall", Ai),
            ("ai.click_to_do", Ai),
            ("ai.paint", Ai),
            ("ai.notepad", Ai),
            ("debloat.widgets_policy", Clutter),
            ("debloat.device_companion_apps", Clutter),
        ];
        for (id, topic) in expected {
            assert_eq!(Topic::of(id), *topic, "{id}");
        }
        for spec in secblitz::hardening::all() {
            assert!(
                expected.iter().any(|(id, _)| *id == spec.id),
                "{} is missing from the expected list",
                spec.id
            );
        }
        for (id, _) in expected {
            assert!(
                secblitz::hardening::spec(id).is_some(),
                "{id} is not a setting"
            );
        }
    }

    #[test]
    fn every_linux_setting_goes_where_the_design_says() {
        let expected: &[(&str, Topic)] = &[
            ("linux.firewall", Network),
            ("linux.fedora_open_ports", Network),
            ("linux.ssh_server", Network),
            ("linux.ssh_password", Network),
            ("linux.file_sharing", Network),
            ("linux.remote_desktop", Network),
            ("linux.autologin", SignIn),
            ("linux.guest", SignIn),
            ("linux.screen_lock", SignIn),
            ("linux.auto_updates", Windows),
            ("linux.kernel_protections", Windows),
            ("linux.ptrace", Windows),
            ("linux.network_redirects", Network),
            ("linux.llmnr", Network),
            ("linux.fake_sources", Network),
            ("linux.flood_protection", Network),
            ("linux.source_routing", Network),
            ("linux.broadcast_pings", Network),
            ("linux.announce_name", Network),
            ("linux.old_network_services", Network),
            ("linux.ipv6_privacy", Privacy),
            ("linux.computer_name_sent", Privacy),
            ("linux.encrypted_dns", Privacy),
            ("linux.crash_reports", Privacy),
            ("linux.countme", Privacy),
            ("linux.connectivity_check", Privacy),
            ("linux.wifi_mac", Privacy),
            ("linux.recent_files", Privacy),
            ("linux.lock_previews", Privacy),
            ("linux.ubuntu_insights", Privacy),
            ("linux.time_sync", Windows),
            ("linux.printer_sharing", Network),
            ("linux.printer_discovery", Network),
            ("linux.ubuntu_news", Privacy),
            ("linux.snap_updates", Windows),
            ("linux.media_autorun", SignIn),
            ("linux.location", Privacy),
            ("linux.problem_reports", Privacy),
            ("linux.app_usage", Privacy),
            ("linux.old_files", Privacy),
            ("linux.home_private", SignIn),
            ("linux.screen_off_delay", SignIn),
            ("linux.lock_delay", SignIn),
            ("linux.lock_on_suspend", SignIn),
            ("linux.usage_stats", Privacy),
            ("linux.browser_data_collection", Browsers),
            ("linux.browser_https_only", Browsers),
            ("linux.memory_shuffle", Windows),
            ("linux.bpf_hardening", Windows),
            ("linux.terminal_drivers", Windows),
            ("linux.crash_memory", Windows),
            ("linux.crash_files", Privacy),
            ("linux.rare_protocols", Network),
            ("linux.app_sandbox_limits", Windows),
            ("linux.processor_updates", Windows),
            ("linux.root_account", SignIn),
            ("linux.bluetooth_autostart", Network),
            ("linux.usage_survey", Privacy),
            ("linux.mint_app_updates", Windows),
            ("linux.app_store_updates", Windows),
            ("linux.browser_tracking", Browsers),
            ("linux.browser_ad_topics", Browsers),
            ("linux.browser_sponsored", Browsers),
            ("linux.browser_pocket", Browsers),
            ("linux.browser_safe_browsing", Browsers),
            ("linux.browser_password_leaks", Browsers),
            ("linux.browser_background", Browsers),
            ("linux.browser_search_suggestions", Browsers),
            ("linux.browser_encrypted_dns", Browsers),
        ];
        for (id, topic) in expected {
            assert_eq!(Topic::of(id), *topic, "{id}");
        }
        for spec in secblitz::linux::catalog::specs() {
            assert!(
                expected.iter().any(|(id, _)| *id == spec.id),
                "{} is missing from the expected list",
                spec.id
            );
        }
        assert_eq!(expected.len(), secblitz::linux::catalog::specs().len());
        for title in [
            secblitz::advice::DISK_ENCRYPTION,
            secblitz::advice::LINUX_SECURE_BOOT,
            secblitz::advice::UPDATES_WAITING,
            secblitz::advice::RESTART_NEEDED,
            secblitz::advice::PROGRAM_LIMITS,
            secblitz::advice::UNCHECKED_SOURCES,
            secblitz::advice::SECURITY_SUPPORT,
            secblitz::advice::HARDWARE_UPDATES,
            secblitz::advice::SWAP_PROTECTION,
        ] {
            assert_eq!(Topic::of_finding(title), Windows, "{title}");
        }
        for title in [
            secblitz::advice::ACCOUNTS_WITHOUT_PASSWORD,
            secblitz::advice::ADMIN_WITHOUT_PASSWORD,
            secblitz::advice::EXTRA_ADMIN_ACCOUNTS,
            secblitz::advice::ADMIN_ACCOUNTS,
        ] {
            assert_eq!(Topic::of_finding(title), SignIn, "{title}");
        }
        assert_eq!(Topic::of_finding(secblitz::advice::OPEN_PROGRAMS), Network);
    }

    #[test]
    fn the_older_settings_of_the_catalog_go_where_the_design_says() {
        let by_family = |family: &str| -> Option<Topic> {
            Some(match family {
                "defender" => Threats,
                "uac" | "lsa" | "wdigest" | "accounts" | "ntlm" | "session" => SignIn,
                "firewall" | "net" | "tls" | "smb" | "smb1" | "wifi" => Network,
                "installer" | "permissions" | "update" | "recovery" => Windows,
                _ => return None,
            })
        };
        let mut ids = secblitz::platform::control_ids();
        ids.extend(secblitz::permissions::controls().into_iter().map(|c| c.id));
        assert!(ids.len() > 60);
        let mut seen = 0;
        for id in ids
            .iter()
            .filter(|id| secblitz::hardening::spec(id).is_none())
        {
            let family = id.split('.').next().unwrap();
            let topic = by_family(family).unwrap_or_else(|| panic!("no expectation for {id}"));
            assert_eq!(Topic::of(id), topic, "{id}");
            seen += 1;
        }
        assert!(seen > 10, "{seen}");
        for (id, topic) in [
            ("defender.realtime", Threats),
            ("firewall.public.enabled", Network),
            ("uac.consent", SignIn),
            ("wdigest.use_logon_credential", SignIn),
            ("lsa.limit_blank_password_use", SignIn),
            ("installer.always_install_elevated", Windows),
            ("permissions.service.bits", Windows),
        ] {
            assert!(ids.iter().any(|i| i == id), "{id}");
            assert_eq!(Topic::of(id), topic, "{id}");
        }
    }

    #[test]
    fn settings_other_work_adds_later_land_in_their_topics() {
        for (id, topic) in [
            ("browser.dns_bypass", Browsers),
            ("browser.copilot_sidebar", Browsers),
            ("privacy.online_speech", Privacy),
            ("privacy.recall", Ai),
            ("debloat.widgets_policy", Clutter),
            ("wifi.random_address", Network),
            ("smartscreen.something_new", Windows),
            ("never.heard.of.it", Windows),
            ("", Windows),
        ] {
            assert_eq!(Topic::of(id), topic, "{id:?}");
        }
    }

    #[test]
    fn the_first_rule_that_fits_wins() {
        assert_eq!(Topic::of("net.hosts_file"), Threats);
        assert_eq!(Topic::of("net.llmnr"), Network);
        assert_eq!(Topic::of("printer.spooler_remote"), Network);
        assert_eq!(Topic::of("printer.point_and_print"), Windows);
        assert_eq!(Topic::of("services.legacy_remote"), Network);
        assert_eq!(Topic::of("services.unquoted_paths"), Windows);
        assert_eq!(Topic::of("smartscreen.apps"), Threats);
        assert_eq!(Topic::of("smartscreen.browser_policy"), Browsers);
    }

    #[test]
    fn rows_named_by_a_title_find_a_topic_too() {
        for (title, topic) in [
            ("Remote Desktop", Network),
            ("SMB1", Network),
            ("Automatic logon", SignIn),
            ("Memory integrity", Windows),
            ("Security providers", Threats),
            ("Defender", Threats),
            ("SmartScreen", Threats),
            ("Windows Firewall", Network),
            ("Windows updates", Windows),
            ("Device encryption", Windows),
            ("Service permissions: BITS", Windows),
            ("Journal recovery", Windows),
            ("defender.mode", Threats),
            ("asr.configured", Threats),
            ("dns.configuration", Network),
            ("browser.inventory", Browsers),
            ("backup.coverage", Windows),
        ] {
            assert_eq!(Topic::of_finding(title), topic, "{title}");
        }
    }

    #[test]
    fn every_topic_has_a_name_and_a_place_in_the_list() {
        let mut names = std::collections::HashSet::new();
        for t in Topic::ALL {
            assert!(names.insert(t.label()), "{t:?}");
        }
        assert_eq!(names.len(), 8);
        assert_eq!(
            serde_json::to_string(&Topic::SignIn).unwrap(),
            "\"sign_in\""
        );
        assert_eq!(serde_json::from_str::<Topic>("\"ai\"").unwrap(), Topic::Ai);
        assert!(serde_json::from_str::<Topic>("\"nope\"").is_err());
    }

    #[test]
    fn the_windows_topic_is_called_system_on_the_other_systems() {
        use secblitz::os::Os;
        assert_eq!(Topic::Windows.display_label(Os::Windows), "Windows");
        assert_eq!(Topic::Windows.display_label(Os::Linux), "System");
        assert_eq!(Topic::Windows.display_label(Os::Macos), "System");
        for t in Topic::ALL.into_iter().filter(|t| *t != Topic::Windows) {
            for os in [Os::Windows, Os::Linux, Os::Macos] {
                assert_eq!(t.display_label(os), t.label());
            }
        }
        assert_eq!(
            serde_json::to_string(&Topic::Windows).unwrap(),
            "\"windows\""
        );
    }

    #[test]
    fn a_tile_says_the_most_pressing_thing_first() {
        let c = |to_fix, switched_back, options| {
            Some(Counts {
                to_fix,
                switched_back,
                options,
                ..Counts::default()
            })
        };
        assert_eq!(Line::of(None), Line::Checking);
        assert_eq!(Line::of(c(2, 1, 3)), Line::ToFix(2));
        assert_eq!(Line::of(c(0, 1, 3)), Line::SwitchedBack(1));
        assert_eq!(Line::of(c(0, 0, 3)), Line::Options(3));
        let look = Some(Counts {
            to_look: 2,
            options: 3,
            ..Counts::default()
        });
        assert_eq!(Line::of(look), Line::ToLookAt(2));
        assert!(!Line::ToLookAt(2).needs_action());
        assert_eq!(Line::of(c(0, 0, 0)), Line::AllSet);
        assert!(Line::ToFix(1).needs_action() && Line::SwitchedBack(1).needs_action());
        assert!(!Line::Options(1).needs_action());
        assert!(!Line::AllSet.needs_action() && !Line::Checking.needs_action());
    }

    #[test]
    fn the_first_topic_with_something_to_fix_is_found_in_tile_order() {
        let lines = |t: Topic| match t {
            Browsers => Line::ToFix(1),
            Clutter => Line::SwitchedBack(2),
            Privacy => Line::Options(4),
            _ => Line::AllSet,
        };
        assert_eq!(first_needing_action(lines), Some(Browsers));
        assert_eq!(first_needing_action(|_| Line::AllSet), None);
        assert_eq!(first_needing_action(|_| Line::Options(2)), None);
    }

    fn outcome(id: &str, status: CheckStatus, undoable: bool) -> Outcome {
        Outcome {
            id: id.into(),
            title: id.into(),
            status,
            undoable,
            ..Outcome::default()
        }
    }

    fn report(rows: &[(&str, CheckStatus, bool)]) -> (Report, Vec<String>) {
        let report = Report {
            results: rows
                .iter()
                .map(|(id, status, undoable)| outcome(id, status.clone(), *undoable))
                .collect(),
            ..Report::default()
        };
        let available = rows.iter().map(|(id, ..)| (*id).to_owned()).collect();
        (report, available)
    }

    #[test]
    fn only_recommended_settings_start_ticked_even_when_switched_back() {
        let (r, available) = report(&[
            ("defender.pua", CheckStatus::Attention, true),
            ("defender.script_nis", CheckStatus::Attention, false),
            ("privacy.advertising_id", CheckStatus::Attention, true),
            ("privacy.clipboard_sync", CheckStatus::Attention, false),
        ]);
        let ticked = default_selection(&r, &available);
        assert!(ticked.contains(&"defender.pua".to_owned()));
        assert!(ticked.contains(&"defender.script_nis".to_owned()));
        assert!(
            !ticked.contains(&"privacy.advertising_id".to_owned()),
            "a switched back optional setting is not ticked for the person"
        );
        assert!(
            !ticked.contains(&"privacy.clipboard_sync".to_owned()),
            "an optional setting is never ticked for the person"
        );
        let mut unique = ticked.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ticked.len());
    }
}
