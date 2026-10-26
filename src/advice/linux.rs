//! Plain names, effects and next steps for the Linux checks and findings.
use super::NextStep;

/// Titles of the read-only Linux findings, for the backend to report.
pub const DISK_ENCRYPTION: &str = "Linux disk encryption";
pub const SECURE_BOOT: &str = "Linux Secure Boot";
pub const UPDATES_WAITING: &str = "Linux updates waiting";
pub const RESTART_NEEDED: &str = "Linux restart needed";
pub const PROGRAM_LIMITS: &str = "Linux program limits";
pub const ACCOUNTS_WITHOUT_PASSWORD: &str = "Linux accounts without a password";
pub const ADMIN_WITHOUT_PASSWORD: &str = "Linux admin rights without a password";
pub const UNCHECKED_SOURCES: &str = "Linux software sources without checks";
pub const SECURITY_SUPPORT: &str = "Linux security support";
pub const HARDWARE_UPDATES: &str = "Linux hardware updates";

pub(super) fn label(id: &str) -> Option<&'static str> {
    Some(match id {
        "linux.firewall" => "Firewall",
        "linux.fedora_open_ports" => "Open network doors",
        "linux.auto_updates" => "Automatic security updates",
        "linux.ssh_server" => "Remote sign-in service",
        "linux.ssh_password" => "Remote sign-in passwords",
        "linux.file_sharing" => "Windows-style file sharing",
        "linux.autologin" => "Automatic sign-in",
        "linux.guest" => "Guest sign-in",
        "linux.kernel_protections" => "Built-in system protections",
        "linux.crash_reports" => "Crash reports",
        "linux.countme" => "Fedora usage counting",
        "linux.connectivity_check" => "Internet connection check",
        "linux.wifi_mac" => "Wi-Fi address privacy",
        "linux.ptrace" => "Looking inside other programs",
        "linux.network_redirects" => "Network route changes",
        "linux.llmnr" => "Name lookups on the network",
        "linux.screen_lock" => "Screen lock",
        "linux.remote_desktop" => "Screen sharing",
        "linux.recent_files" => "Recent files list",
        "linux.lock_previews" => "Messages on the lock screen",
        "linux.ubuntu_insights" => "Ubuntu usage reports",
        "linux.time_sync" => "Automatic clock",
        "linux.printer_sharing" => "Printer sharing",
        "linux.printer_discovery" => "Network printer finder",
        "linux.ubuntu_news" => "Ubuntu news downloads",
        "linux.snap_updates" => "App store updates",
        "linux.media_autorun" => "Auto-start of plugged-in drives",
        "linux.location" => "Location sharing",
        "linux.problem_reports" => "Problem and usage reports",
        "linux.app_usage" => "Most-used apps list",
        "linux.old_files" => "Automatic Trash cleanup",
        "linux.home_private" => "Privacy of your home folder",
        "linux.browser_data_collection" => "Browser usage data",
        "linux.browser_https_only" => "Secure connections only",
        "linux.browser_tracking" => "Tracker blocking",
        "linux.browser_ad_topics" => "Interest-based ads",
        "linux.browser_sponsored" => "Sponsored shortcuts",
        "linux.browser_pocket" => "Pocket suggestions",
        "linux.browser_safe_browsing" => "Warnings about dangerous sites",
        "linux.browser_password_leaks" => "Leaked password warnings",
        "linux.browser_background" => "Browser running after you close it",
        "linux.browser_search_suggestions" => "Search suggestions while typing",
        "linux.browser_encrypted_dns" => "Private website lookups",
        _ => return None,
    })
}

pub(super) fn impact(id: &str) -> Option<&'static str> {
    Some(match id {
        "linux.firewall" => "Other computers on a network reaching programs on your computer",
        "linux.fedora_open_ports" => {
            "A program you start becoming reachable from other computers without you knowing"
        }
        "linux.auto_updates" => "Known security holes staying open on your computer",
        "linux.ssh_server" => {
            "Strangers on the internet or your network trying to sign in to your computer"
        }
        "linux.ssh_password" => "Someone guessing a password to sign in to your computer from afar",
        "linux.file_sharing" => {
            "Other computers on the network seeing or opening your shared files"
        }
        "linux.autologin" => "Anyone who turns on your computer getting straight into your account",
        "linux.guest" => "A stranger using your computer and your internet without an account",
        "linux.kernel_protections" => {
            "Harmful programs learning system details that help them take over your computer"
        }
        "linux.crash_reports" => "Pieces of your documents ending up in crash reports",
        "linux.countme" => {
            "Fedora's servers learning that your computer exists and which version it runs"
        }
        "linux.connectivity_check" => {
            "An outside company learning when and where your computer connects"
        }
        "linux.wifi_mac" => {
            "Wi-Fi networks recognizing your computer and following it from place to place"
        }
        "linux.ptrace" => {
            "A harmful program reading passwords and secrets from the other programs you run"
        }
        "linux.network_redirects" => {
            "Someone on the same network quietly sending your traffic through their computer"
        }
        "linux.llmnr" => {
            "Someone on the same network tricking your computer into handing over a sign-in password"
        }
        "linux.screen_lock" => "Anyone walking up to your computer while you are away",
        "linux.remote_desktop" => {
            "Someone watching or controlling your screen from another computer"
        }
        "linux.recent_files" => "Other people seeing which files you opened lately",
        "linux.lock_previews" => "Visitors reading your private messages on a locked screen",
        "linux.ubuntu_insights" => {
            "Details about your computer and software being sent to Ubuntu's makers"
        }
        "linux.time_sync" => "Secure connections failing because your computer has the wrong time",
        "linux.printer_sharing" => {
            "Other computers on the network using your printers or changing how printing works"
        }
        "linux.printer_discovery" => {
            "A stranger on the network adding a fake printer that attacks your computer"
        }
        "linux.ubuntu_news" => {
            "Ubuntu's makers learning that your computer is online while they show you news"
        }
        "linux.snap_updates" => {
            "Apps from Ubuntu's app store staying out of date with known security holes"
        }
        "linux.media_autorun" => "A plugged-in drive or disc starting programs without you asking",
        "linux.location" => "Apps and websites finding out where you are",
        "linux.problem_reports" => {
            "Details about problems and how you use your software being sent to its makers"
        }
        "linux.app_usage" => "Other people seeing which apps you use the most",
        "linux.old_files" => {
            "Deleted files and leftovers staying on your computer for anyone to find"
        }
        "linux.home_private" => "Other people with an account on this computer reading your files",
        "linux.browser_data_collection" => {
            "Details about the sites you visit and how you browse being sent to the companies behind your browsers"
        }
        "linux.browser_https_only" => {
            "Someone on the same network reading or changing a page that is not protected"
        }
        "linux.browser_tracking" => {
            "Websites and advertisers following you from page to page to learn what you like"
        }
        "linux.browser_ad_topics" => {
            "Your browser keeping a list of your interests that sites use to pick ads for you"
        }
        "linux.browser_sponsored" => {
            "Paid shortcuts and stories being placed where you look first in Firefox"
        }
        "linux.browser_pocket" => {
            "Firefox suggesting stories from a third party and sending it details about what you read"
        }
        "linux.browser_safe_browsing" => {
            "Opening a fake or harmful site with no warning"
        }
        "linux.browser_password_leaks" => {
            "Using a password that criminals already have without being told"
        }
        "linux.browser_background" => {
            "A browser staying active and online after you thought you had closed it"
        }
        "linux.browser_search_suggestions" => {
            "Everything you type in the address bar being sent to a search company before you press Enter"
        }
        "linux.browser_encrypted_dns" => {
            "Anyone on your network seeing which websites you look up"
        }
        _ => return None,
    })
}

pub(super) fn repair(id: &str) -> Option<&'static str> {
    Some(match id {
        "linux.firewall" => {
            "It blocks connections that other computers start without being invited."
        }
        "linux.auto_updates" => "Security updates will install by themselves in the background.",
        "linux.ssh_password" => {
            "Remote sign-in will stop accepting passwords, including for the main administrator account."
        }
        "linux.file_sharing" => "File sharing with Windows computers will be switched off.",
        "linux.autologin" => "Your computer will ask for your password when it starts.",
        "linux.guest" => "The guest option will be removed from the sign-in screen.",
        "linux.kernel_protections" => {
            "Extra built-in protections will be switched on. No restart is needed."
        }
        "linux.ptrace" => {
            "Programs will only be able to look inside programs they started themselves. No restart is needed."
        }
        "linux.network_redirects" => {
            "This computer will ignore route changes sent by other computers and stop sending its own."
        }
        "linux.llmnr" => {
            "This computer will stop answering name lookups from other computers on the network."
        }
        "linux.crash_reports" => "Ubuntu will stop collecting crash reports.",
        "linux.countme" => "Fedora will stop counting this computer.",
        "linux.screen_lock" => "The screen will lock after a few minutes without use.",
        "linux.remote_desktop" => "Screen sharing from other computers will be switched off.",
        "linux.lock_previews" => "The text of messages will be hidden while the screen is locked.",
        "linux.ubuntu_insights" => "Sending usage reports to Ubuntu will be switched off.",
        "linux.time_sync" => "The clock will set itself from the internet.",
        "linux.printer_sharing" => "Sharing printers with other computers will be switched off.",
        "linux.printer_discovery" => {
            "Printers announced by other computers the old way will be ignored."
        }
        "linux.ubuntu_news" => "Ubuntu will stop downloading news and advertising.",
        "linux.snap_updates" => "The hold on app store updates will end.",
        "linux.media_autorun" => {
            "Drives and discs you plug in will no longer start anything by themselves."
        }
        "linux.location" => "Location sharing will be switched off. Apps will not be told where you are.",
        "linux.problem_reports" => "Problem reports and usage statistics will stop being sent.",
        "linux.home_private" => {
            "Other accounts on this computer will no longer be able to open your home folder."
        }
        "linux.browser_data_collection" => {
            "Your browsers will stop sending usage data to the companies that make them."
        }
        "linux.browser_tracking" => "Your browsers will block the trackers that follow you from site to site.",
        "linux.browser_ad_topics" => "Your browser will stop building a list of your interests for ads.",
        "linux.browser_sponsored" => "Firefox will stop showing paid shortcuts, stories and suggestions.",
        "linux.browser_pocket" => "Pocket will be switched off in Firefox.",
        "linux.browser_safe_browsing" => "Your browsers will warn you again before opening dangerous sites.",
        "linux.browser_password_leaks" => "Your browser will warn you when a saved password has been leaked.",
        "linux.browser_background" => "Your browser will stop running after you close its windows.",
        _ => return None,
    })
}

pub(super) fn consequence(id: &str) -> Option<&'static str> {
    Some(match id {
        "linux.ssh_server" => "Nobody can sign in to this computer from another one. Do not choose this if you manage it from afar. You can undo this.",
        "linux.fedora_open_ports" => "A tool that must be reached from other computers may stop working until you allow it. You can undo this.",
        "linux.connectivity_check" => "Your computer stops contacting an outside address. Wi-Fi sign-in pages may no longer pop up by themselves.",
        "linux.wifi_mac" => "Each Wi-Fi network sees a made-up address. A network that knew your old one may ask you to sign in again.",
        "linux.recent_files" => "The list of recent files is forgotten after 30 days. Your files stay where they are. You can undo this.",
        "linux.app_usage" => "Your computer stops keeping track of which apps you use most. Search may list apps in a different order. You can undo this.",
        "linux.old_files" => "Files in the Trash for over 30 days, and old temporary files, are deleted for good. Undo cannot bring them back.",
        "linux.browser_https_only" => "Firefox warns you before opening a page that is not protected. You can still open it. You can undo this.",
        "linux.browser_search_suggestions" => "Suggestions while you type in the address bar will stop. You can still search as before. You can undo this.",
        "linux.browser_encrypted_dns" => "Your browsers look up websites through a private service. Some work or school networks may not load. You can undo this.",
        _ => return None,
    })
}

pub(super) fn finding(title: &str) -> Option<(&'static str, &'static str, NextStep)> {
    Some(match title {
        "Linux disk encryption" => (
            "Protection if your computer is lost",
            "The disk can only be encrypted when Linux is installed. Back up your files first, because reinstalling erases the disk.",
            NextStep::ReviewWithAdministrator,
        ),
        "Linux Secure Boot" => (
            "Startup protection",
            "This is a setting in your computer's startup menu. Turning it on can stop some drivers, such as for graphics cards, from loading.",
            NextStep::ReviewFirmware,
        ),
        "Linux updates waiting" => (
            "Updates waiting",
            "Open Software Updater, Update Manager or Software, whichever your computer has, and install what is waiting.",
            NextStep::None,
        ),
        "Linux restart needed" => (
            "Restart needed",
            "Updates are installed but need a restart to work. Save your work and restart when it suits you. We never restart for you.",
            NextStep::None,
        ),
        "Linux program limits" => (
            "Limits on programs",
            "The built-in guard that keeps programs inside their limits is not fully on. We cannot change this one safely for you.",
            NextStep::ReviewWithAdministrator,
        ),
        ACCOUNTS_WITHOUT_PASSWORD => (
            "Accounts without a password",
            "Give each account a password in your system settings, or ask whoever set up this computer to do it.",
            NextStep::ReviewWithAdministrator,
        ),
        ADMIN_WITHOUT_PASSWORD => (
            "Admin rights without a password",
            "Ask whoever set up this computer if the rule that skips the password is needed. If not, it should be removed.",
            NextStep::ReviewWithAdministrator,
        ),
        UNCHECKED_SOURCES => (
            "Software sources without checks",
            "Remove that source in your software settings, or ask whoever added it. We cannot tell if it is safe to remove.",
            NextStep::ReviewWithAdministrator,
        ),
        SECURITY_SUPPORT => (
            "Security updates for your Linux",
            "Move to a newer version of Linux, and back up your files first.",
            NextStep::ReviewWithAdministrator,
        ),
        HARDWARE_UPDATES => (
            "Updates for your computer's parts",
            "Open your software app and install the updates for your computer's parts.",
            NextStep::None,
        ),
        _ => return None,
    })
}

pub(super) fn finding_impact(title: &str) -> Option<&'static str> {
    Some(match title {
        "Linux disk encryption" => {
            "Someone who finds your computer reading your files if it is lost or stolen"
        }
        "Linux Secure Boot" => "Hidden malware starting before your system does",
        "Linux updates waiting" => "Missing security fixes on your computer",
        "Linux restart needed" => "Security fixes that are installed but not working yet",
        "Linux program limits" => {
            "A harmful program reaching files and settings it should not touch"
        }
        ACCOUNTS_WITHOUT_PASSWORD => "Anyone using your computer getting into an account freely",
        ADMIN_WITHOUT_PASSWORD => {
            "A harmful program taking over your computer without being asked for a password"
        }
        UNCHECKED_SOURCES => "Tampered software being installed on your computer",
        SECURITY_SUPPORT => "New security holes never being fixed on your computer",
        HARDWARE_UPDATES => "Known weak spots staying open in your computer's parts",
        _ => return None,
    })
}

/// The sentences the checks give when a setting cannot be offered. They are already plain, so the person reads them as they are.
pub(super) fn not_offered(reason: &str) -> Option<&'static str> {
    use crate::linux::controls as c;
    [
        c::NO_FIREWALL,
        c::FIREWALL_MASKED,
        c::FIREWALL_UNREADABLE,
        c::NO_AUTO_UPDATES,
        c::SOFTWARE_APP_UPDATES,
        c::NO_REMOTE_SIGN_IN,
        c::REMOTE_SIGN_IN_OFF,
        c::REMOTE_SIGN_IN_UNREADABLE,
        c::NO_NETWORK_MANAGER,
        c::services::NO_TIME_SYNC,
        c::services::NO_PRINTING,
        c::services::NO_PRINTER_FINDER,
        c::services::NO_SNAP_STORE,
        c::UNRECOGNISED,
        c::browsers::NO_BROWSER,
        c::browsers::NO_FIREFOX,
        c::browsers::NO_CHROMIUM,
        crate::linux::person::UNAVAILABLE,
    ]
    .into_iter()
    .find(|sentence| *sentence == reason)
}

/// Words that mean nothing to someone who has just left Windows.
#[cfg(test)]
pub(crate) fn assert_plain_words(text: &str) {
    const JARGON: [&str; 22] = [
        "ssh",
        "sshd",
        "sysctl",
        "daemon",
        "port",
        "ports",
        "kernel",
        "polkit",
        "gsettings",
        "apparmor",
        "selinux",
        "systemd",
        "root",
        "sudo",
        "ufw",
        "firewalld",
        "dbus",
        "gdm",
        "lightdm",
        "samba",
        "dpkg",
        "apt",
    ];
    for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        let lower = word.to_ascii_lowercase();
        assert!(!JARGON.contains(&lower.as_str()), "jargon {word}: {text}");
    }
    assert!(!text.contains('\u{2014}'), "em dash: {text}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advice::{
        choice_consequence, control_impact, control_label, finding_impact, for_control,
        for_finding, is_choice_check_id, Group,
    };
    use crate::model::CheckStatus;

    #[test]
    fn every_linux_control_has_plain_text_and_the_right_kind_of_offer() {
        for spec in crate::linux::catalog::specs() {
            let id = spec.id;
            assert_ne!(control_label(id), "Protection check", "{id}");
            assert!(!control_impact(id).is_empty(), "{id}");
            assert_eq!(is_choice_check_id(id), spec.ask, "{id}");
            let a = for_control(id, &CheckStatus::Attention, "Eligible");
            assert_eq!(a.step, NextStep::Repair, "{id}");
            assert_eq!(a.ask, spec.ask, "{id}");
            if spec.ask {
                assert_eq!(a.next, choice_consequence(id), "{id}");
                assert!(a.next.len() < 130, "{id}: consequence is too long");
                assert!(consequence(id).is_some() && repair(id).is_none(), "{id}");
            } else {
                assert_eq!(a.group, Group::Recommended, "{id}");
                assert!(repair(id).is_some() && consequence(id).is_none(), "{id}");
            }
            for line in [a.label, a.next, a.impact] {
                assert!(!line.is_empty(), "{id}");
                assert_plain_words(line);
            }
        }
    }

    #[test]
    fn the_optional_privacy_choices_are_extras_that_never_count_against_the_score() {
        for id in [
            "linux.connectivity_check",
            "linux.wifi_mac",
            "linux.recent_files",
            "linux.app_usage",
            "linux.old_files",
            "linux.browser_https_only",
            "linux.browser_search_suggestions",
            "linux.browser_encrypted_dns",
        ] {
            assert_eq!(crate::advice::extra_section(id), Some("Privacy extras"));
            let a = for_control(id, &CheckStatus::Attention, "Eligible");
            assert_eq!(a.group, Group::Information, "{id}");
        }
        assert_eq!(crate::advice::extra_section("linux.firewall"), None);
        assert_eq!(
            for_control("linux.fedora_open_ports", &CheckStatus::Attention, "").group,
            Group::Choice
        );
    }

    #[test]
    fn every_linux_finding_says_what_to_do_in_plain_words() {
        for title in [
            DISK_ENCRYPTION,
            SECURE_BOOT,
            UPDATES_WAITING,
            RESTART_NEEDED,
            PROGRAM_LIMITS,
            ACCOUNTS_WITHOUT_PASSWORD,
            ADMIN_WITHOUT_PASSWORD,
            UNCHECKED_SOURCES,
            SECURITY_SUPPORT,
            HARDWARE_UPDATES,
        ] {
            let a = for_finding(title, &CheckStatus::Attention, "");
            assert_ne!(a.label, "Protection check", "{title}");
            assert!(!finding_impact(title).is_empty(), "{title}");
            assert_ne!(a.step, NextStep::Repair, "{title}");
            for line in [a.label, a.next, a.impact] {
                assert_plain_words(line);
            }
        }
        assert!(finding("Windows Firewall").is_none());
    }

    #[test]
    fn the_sentence_a_check_gives_for_a_setting_it_cannot_offer_is_what_the_person_reads() {
        use crate::linux::controls as c;
        for reason in [
            c::NO_FIREWALL,
            c::FIREWALL_MASKED,
            c::FIREWALL_UNREADABLE,
            c::NO_AUTO_UPDATES,
            c::SOFTWARE_APP_UPDATES,
            c::NO_REMOTE_SIGN_IN,
            c::REMOTE_SIGN_IN_OFF,
            c::REMOTE_SIGN_IN_UNREADABLE,
            c::NO_NETWORK_MANAGER,
            c::UNRECOGNISED,
            c::browsers::NO_BROWSER,
            c::browsers::NO_FIREFOX,
            c::browsers::NO_CHROMIUM,
            crate::linux::person::UNAVAILABLE,
        ] {
            let a = for_control("linux.firewall", &CheckStatus::Skipped, reason);
            assert_eq!(a.status, "Not offered", "{reason}");
            assert_eq!(a.next, reason);
            assert_eq!(a.group, Group::Information);
            assert_ne!(a.step, NextStep::Repair);
            assert_plain_words(a.next);
        }
        let other = for_control(
            "linux.firewall",
            &CheckStatus::Skipped,
            "Not offered: another program manages the firewall",
        );
        assert_ne!(other.status, "Not offered");
    }
}
