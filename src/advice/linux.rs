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
pub const EXTRA_ADMIN_ACCOUNTS: &str = "Linux extra all-powerful accounts";
pub const ADMIN_ACCOUNTS: &str = "Linux admin accounts";
pub const OPEN_PROGRAMS: &str = "Linux programs open to the network";
pub const SWAP_PROTECTION: &str = "Linux memory saved to the drive";

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
        "linux.fake_sources" => "Faked sender addresses",
        "linux.flood_protection" => "Protection from connection floods",
        "linux.source_routing" => "Messages that choose their own route",
        "linux.broadcast_pings" => "Calls to the whole network",
        "linux.ipv6_privacy" => "Private network address",
        "linux.computer_name_sent" => "Computer name shared with networks",
        "linux.encrypted_dns" => "Private website lookups",
        "linux.announce_name" => "Announcing this computer",
        "linux.old_network_services" => "Old network services",
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
        "linux.screen_off_delay" => "Time before the screen goes dark",
        "linux.lock_delay" => "Wait before the screen locks",
        "linux.lock_on_suspend" => "Lock when the computer sleeps",
        "linux.usage_stats" => "Software usage statistics",
        "linux.browser_data_collection" => "Browser usage data",
        "linux.browser_https_only" => "Secure connections only",
        "linux.memory_shuffle" => "Memory layout",
        "linux.bpf_hardening" => "Small programs inside the system",
        "linux.terminal_drivers" => "Old terminal drivers",
        "linux.crash_memory" => "Memory of crashed programs",
        "linux.crash_files" => "Saved crash files",
        "linux.rare_protocols" => "Rarely used network protocols",
        "linux.app_sandbox_limits" => "Private boxes for apps",
        "linux.processor_updates" => "Processor updates",
        "linux.root_account" => "Main administrator account",
        "linux.bluetooth_autostart" => "Bluetooth at start",
        "linux.usage_survey" => "Installed programs report",
        "linux.mint_app_updates" => "Automatic app updates",
        "linux.app_store_updates" => "Automatic app downloads",
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
        "linux.fake_sources" => {
            "Someone sending harmful messages that pretend to come from a computer you trust"
        }
        "linux.flood_protection" => {
            "Someone knocking your computer offline by flooding it with fake connection requests"
        }
        "linux.source_routing" => {
            "Someone steering network messages around the protections of your network"
        }
        "linux.broadcast_pings" => {
            "Your computer being used to flood someone else with replies"
        }
        "linux.ipv6_privacy" => {
            "Websites and networks recognising your computer by its address from day to day"
        }
        "linux.computer_name_sent" => {
            "Every network you join learning the name of your computer, which often holds your own name"
        }
        "linux.encrypted_dns" => {
            "Anyone on the network seeing every website you look up"
        }
        "linux.announce_name" => {
            "Strangers on the same network seeing the name of your computer and what it offers"
        }
        "linux.old_network_services" => {
            "Anyone on the network reading or taking over what these old services handle"
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
        "linux.screen_off_delay" => "Your screen staying readable for a long time after you walk away",
        "linux.lock_delay" => "Anyone using your computer in the moments after the screen goes dark",
        "linux.lock_on_suspend" => "Anyone who wakes your computer finding it already unlocked",
        "linux.usage_stats" => "Details about how you use your software being sent to its makers",
        "linux.browser_data_collection" => {
            "Details about the sites you visit and how you browse being sent to the companies behind your browsers"
        }
        "linux.browser_https_only" => {
            "Someone on the same network reading or changing a page that is not protected"
        }
        "linux.memory_shuffle" => {
            "A harmful program finding what it wants to attack in memory far more easily"
        }
        "linux.bpf_hardening" => {
            "A harmful program using the system's inner workings to gain more control than it should have"
        }
        "linux.terminal_drivers" => {
            "A harmful program loading an old, flawed driver to take over your computer"
        }
        "linux.crash_memory" => "Secrets from a crashed program being left in a file on your disk",
        "linux.crash_files" => "Passwords and private text from a crashed program staying on your disk",
        "linux.rare_protocols" => {
            "A flaw in a network feature you never use being used to attack your computer"
        }
        "linux.app_sandbox_limits" => {
            "A harmful app using a private box to get around the limits placed on it"
        }
        "linux.processor_updates" => "Known flaws in your processor staying open",
        "linux.root_account" => {
            "Someone guessing the password of the account that can change everything"
        }
        "linux.bluetooth_autostart" => {
            "Someone nearby trying to connect to your computer while Bluetooth is on without you knowing"
        }
        "linux.usage_survey" => {
            "A list of every program on your computer being sent out each week"
        }
        "linux.mint_app_updates" => "Apps and add-ons staying out of date with known security holes",
        "linux.app_store_updates" => "Apps staying out of date with known security holes",
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
        "linux.fake_sources" => {
            "This computer will throw away network messages that claim to come from a place they could not have come from."
        }
        "linux.flood_protection" => {
            "This computer will keep answering real visitors when it is flooded with fake requests to connect."
        }
        "linux.source_routing" => {
            "This computer will ignore network messages that try to choose their own route."
        }
        "linux.broadcast_pings" => {
            "This computer will stop answering calls that are sent to every computer on the network at once."
        }
        "linux.ipv6_privacy" => {
            "This computer will use temporary addresses that change from time to time, starting with your next connection to a network."
        }
        "linux.old_network_services" => {
            "Old network services that send data without protection will be stopped and switched off."
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
        "linux.screen_off_delay" => "The screen will go dark after five minutes without use.",
        "linux.lock_delay" => "The screen will lock the moment it goes dark.",
        "linux.lock_on_suspend" => "The screen will lock whenever the computer goes to sleep.",
        "linux.usage_stats" => "Sending software usage statistics will be switched off.",
        "linux.browser_data_collection" => {
            "Your browsers will stop sending usage data to the companies that make them."
        }
        "linux.memory_shuffle" => {
            "The system will place each program's memory in a different spot every time. No restart is needed."
        }
        "linux.bpf_hardening" => {
            "Small programs inside the system will be guarded better, and ordinary users stay unable to add their own. No restart is needed."
        }
        "linux.terminal_drivers" => {
            "Old terminal drivers will only load when an administrator asks. No restart is needed."
        }
        "linux.crash_memory" => {
            "Programs that run with extra rights will no longer leave a copy of their memory when they crash. No restart is needed."
        }
        "linux.crash_files" => {
            "The memory of a crashed program will no longer be saved on your disk. Files saved earlier stay where they are."
        }
        "linux.rare_protocols" => {
            "Rarely used network protocols will no longer load by themselves. Nothing that is running is stopped."
        }
        "linux.app_sandbox_limits" => {
            "Apps will need permission to make a private box for themselves. No restart is needed."
        }
        "linux.processor_updates" => {
            "The processor update will be installed from your software sources. It starts working the next time your computer starts, and we never restart it for you. Other software is not changed."
        }
        "linux.usage_survey" => "Your computer will stop sending the list of installed programs.",
        "linux.mint_app_updates" => {
            "Apps and add-ons will update by themselves. Updates for Linux itself stay as they are."
        }
        "linux.app_store_updates" => "The Software app will download updates by itself.",
        _ => return None,
    })
}

pub(super) fn consequence(id: &str) -> Option<&'static str> {
    Some(match id {
        "linux.ssh_server" => "Nobody can sign in to this computer from another one. Do not choose this if you manage it from afar. You can undo this.",
        "linux.fedora_open_ports" => "A tool that must be reached from other computers may stop working until you allow it. You can undo this.",
        "linux.computer_name_sent" => "Networks stop seeing your computer's name from your next connection. Some routers then show it as unknown. You can undo this.",
        "linux.encrypted_dns" => "Website lookups are scrambled when your network allows it. Some networks may answer more slowly. You can undo this.",
        "linux.announce_name" => "Printers and speakers may no longer see what this computer shares. This computer still finds them. You can undo this.",
        "linux.connectivity_check" => "Your computer stops contacting an outside address. Wi-Fi sign-in pages may no longer pop up by themselves.",
        "linux.wifi_mac" => "Each Wi-Fi network sees a made-up address. A network that knew your old one may ask you to sign in again.",
        "linux.recent_files" => "The list of recent files is forgotten after 30 days. Your files stay where they are. You can undo this.",
        "linux.app_usage" => "Your computer stops keeping track of which apps you use most. Search may list apps in a different order. You can undo this.",
        "linux.old_files" => "Files in the Trash for over 30 days, and old temporary files, are deleted for good. Undo cannot bring them back.",
        "linux.browser_https_only" => "Firefox warns you before opening a page that is not protected. You can still open it. You can undo this.",
        "linux.root_account" => "The main administrator account can no longer sign in with a password. Other administrators still can. You can undo this.",
        "linux.bluetooth_autostart" => "Bluetooth stays off after each start until you turn it on. Skip this if you use a Bluetooth keyboard or mouse. You can undo this.",
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
        EXTRA_ADMIN_ACCOUNTS => (
            "Extra accounts with full control",
            "Ask whoever set up this computer why the extra account is there. If it is not needed, it should be removed.",
            NextStep::ReviewWithAdministrator,
        ),
        ADMIN_ACCOUNTS => (
            "Who can make changes to this computer",
            "Look at the accounts listed. If someone there should not change this computer, take that right from them in your system settings.",
            NextStep::None,
        ),
        OPEN_PROGRAMS => (
            "Programs open to the network",
            "Look at the programs listed. If you do not use one of them, close it, or ask whoever set up this computer.",
            NextStep::ReviewWithAdministrator,
        ),
        SWAP_PROTECTION => (
            "Memory saved to the drive",
            "Encrypting the drive when you install Linux also protects this. We cannot change it safely for you.",
            NextStep::ReviewWithAdministrator,
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
        EXTRA_ADMIN_ACCOUNTS => {
            "A hidden account changing anything on your computer without limits"
        }
        ADMIN_ACCOUNTS => {
            "Someone changing or removing anything on your computer without you knowing"
        }
        OPEN_PROGRAMS => {
            "Other computers on the network reaching programs you did not mean to share"
        }
        SWAP_PROTECTION => {
            "Someone who finds your computer reading passwords and open documents from the drive"
        }
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
        c::devices::NO_BLUETOOTH,
        c::devices::NO_USAGE_SURVEY,
        c::UNRECOGNISED,
        c::browsers::NO_BROWSER,
        c::browsers::NO_FIREFOX,
        c::hardening::CRASH_REPORTS_NEED_IT,
        c::hardening::NO_OTHER_ADMIN,
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
            "linux.computer_name_sent",
            "linux.encrypted_dns",
            "linux.announce_name",
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
            EXTRA_ADMIN_ACCOUNTS,
            ADMIN_ACCOUNTS,
            OPEN_PROGRAMS,
            SWAP_PROTECTION,
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
            c::devices::NO_BLUETOOTH,
            c::devices::NO_USAGE_SURVEY,
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
