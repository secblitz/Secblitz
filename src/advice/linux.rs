//! Plain names, effects and next steps for the Linux checks and findings.
use super::NextStep;

/// Titles of the read-only Linux findings, for the backend to report.
pub const DISK_ENCRYPTION: &str = "Linux disk encryption";
pub const SECURE_BOOT: &str = "Linux Secure Boot";
pub const UPDATES_WAITING: &str = "Linux updates waiting";
pub const RESTART_NEEDED: &str = "Linux restart needed";
pub const PROGRAM_LIMITS: &str = "Linux program limits";

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
        "linux.screen_lock" => "Screen lock",
        "linux.remote_desktop" => "Screen sharing",
        "linux.recent_files" => "Recent files list",
        "linux.lock_previews" => "Messages on the lock screen",
        "linux.ubuntu_insights" => "Ubuntu usage reports",
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
        "linux.screen_lock" => "Anyone walking up to your computer while you are away",
        "linux.remote_desktop" => {
            "Someone watching or controlling your screen from another computer"
        }
        "linux.recent_files" => "Other people seeing which files you opened lately",
        "linux.lock_previews" => "Visitors reading your private messages on a locked screen",
        "linux.ubuntu_insights" => {
            "Details about your computer and software being sent to Ubuntu's makers"
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
        "linux.crash_reports" => "Ubuntu will stop collecting crash reports.",
        "linux.countme" => "Fedora will stop counting this computer.",
        "linux.screen_lock" => "The screen will lock after a few minutes without use.",
        "linux.remote_desktop" => "Screen sharing from other computers will be switched off.",
        "linux.lock_previews" => "The text of messages will be hidden while the screen is locked.",
        "linux.ubuntu_insights" => "Sending usage reports to Ubuntu will be switched off.",
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
        c::UNRECOGNISED,
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
