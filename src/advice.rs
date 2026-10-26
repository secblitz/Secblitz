//! Presentation-only advice. These are translation source keys, never commands
//! or mutation authority. Only a control outcome of `attention` offers a fix.
mod choice;
mod impact;
mod labels;
mod linux;
mod reasons;

use crate::model::CheckStatus;
pub use choice::{choice_consequence, is_choice_check_id};
pub use impact::{control_impact, finding_impact};
use labels::control_help;
pub use labels::control_label;
#[cfg(test)]
pub(crate) use linux::assert_plain_words as assert_plain_linux_words;
pub use linux::{
    DISK_ENCRYPTION, PROGRAM_LIMITS, RESTART_NEEDED, SECURE_BOOT as LINUX_SECURE_BOOT,
    UPDATES_WAITING,
};
use reasons::{managed, not_offered, repair_help};

/// The optional group a choice belongs to. These never count against the score.
pub fn extra_section(id: &str) -> Option<&'static str> {
    if matches!(
        id,
        "linux.connectivity_check"
            | "linux.wifi_mac"
            | "linux.recent_files"
            | "linux.app_usage"
            | "linux.old_files"
    ) {
        return Some("Privacy extras");
    }
    Some(match id.split_once('.')?.0 {
        "privacy" | "browser" => "Privacy extras",
        "ai" => "AI features",
        "debloat" => "Less clutter",
        _ => return None,
    })
}

pub fn control_for_finding(title: &str) -> Option<&'static str> {
    Some(match title {
        "Memory integrity" => "vbs.memory_integrity",
        "Automatic logon" => "accounts.autologon",
        "Remote Desktop" => "remote_desktop.disabled",
        "SMB1" => "smb1.disabled",
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextStep {
    None,
    Repair,
    OpenWindowsSecurity,
    OpenWindowsUpdate,
    OpenEncryption,
    OpenAccounts,
    OpenRemoteDesktop,
    ReviewFirmware,
    ReviewWindowsFeatures,
    ReviewWithAdministrator,
    ReviewUndo,
    OpenHistory,
    Restart,
    CheckAgain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Recommended,
    Protected,
    Choice,
    Information,
}

pub struct Advice {
    pub label: &'static str,
    pub status: &'static str,
    pub next: &'static str,
    pub step: NextStep,
    pub group: Group,
    pub impact: &'static str,
    pub ask: bool,
}

impl Advice {
    pub fn impact_prefix(&self) -> &'static str {
        if self.impact.is_empty() {
            return "";
        }
        match self.group {
            Group::Recommended => "Turning it on protects you from:",
            Group::Protected => "Protects you from:",
            _ => "Why it matters:",
        }
    }
}

fn base(label: &'static str, status: &CheckStatus, help: (&'static str, NextStep)) -> Advice {
    let mut a = Advice {
        label,
        status: "Needs your choice",
        next: help.0,
        step: help.1,
        group: Group::Choice,
        impact: "",
        ask: false,
    };
    match status {
        CheckStatus::Compliant | CheckStatus::Ok => {
            a.status = "Good to go";
            a.next = "Nothing to do here.";
            a.step = NextStep::None;
            a.group = Group::Protected;
        }
        CheckStatus::Unknown | CheckStatus::Error => {
            a.status = "Couldn't check";
        }
        _ => {}
    }
    a
}

pub fn for_control(id: &str, status: &CheckStatus, detail: &str) -> Advice {
    let mut a = base(control_label(id), status, control_help(id));
    match status {
        CheckStatus::Attention if a.label != "Protection check" && id != "findings" => {
            a.status = "Can fix";
            a.next = repair_help(id);
            a.step = NextStep::Repair;
            a.group = Group::Recommended;
            if is_choice_check_id(id) {
                a.status = "Your choice";
                a.next = choice_consequence(id);
                a.ask = true;
                a.group = if extra_section(id).is_some() {
                    Group::Information
                } else {
                    Group::Choice
                };
            }
        }
        CheckStatus::Applied => {
            a.status = "Fixed";
            a.next = "This setting was updated and checked.";
            a.step = NextStep::None;
            a.group = Group::Protected;
        }
        CheckStatus::Unchanged
            if matches!(
                detail,
                "Target preference already present"
                    | "Target preference already present; original before image retained"
            ) =>
        {
            a.status = "Good to go";
            a.next = "Nothing to do here.";
            a.step = NextStep::None;
            a.group = Group::Protected;
        }
        CheckStatus::Restored => {
            a.next = "Your earlier setting was restored.";
            a.step = NextStep::CheckAgain;
        }
        &CheckStatus::Pending => {
            a.next = "Undo your last fixes before making new ones.";
            a.step = NextStep::ReviewUndo;
        }
        &CheckStatus::Conflict => {
            a.next = "This setting changed again after our fix, so we left it alone.";
            a.step = NextStep::ReviewUndo;
        }
        CheckStatus::Skipped if managed(detail) => {
            a.status = "Managed elsewhere";
            a.next = "This computer's owner controls this setting, so we leave it as it is.";
            a.step = NextStep::ReviewWithAdministrator;
        }
        CheckStatus::Skipped if detail == crate::vbs::ALREADY_ON => {
            a.status = "Good to go";
            a.next = "This protection is already running on this computer. Nothing to change.";
            a.step = NextStep::None;
            a.group = Group::Protected;
        }
        CheckStatus::Skipped if not_offered(detail).is_some() => {
            a.status = "Not offered";
            a.next = not_offered(detail).unwrap_or_default();
            a.step = NextStep::None;
            a.group = Group::Information;
        }
        CheckStatus::Skipped
            if matches!(
                detail,
                "Preserving absent or nonzero UAC preference"
                    | "Preserving absent or already-safe machine preference"
            ) =>
        {
            // The engine refuses to write an absent (or already-safe) value: that
            // is Windows' own safe default, so it counts as protected.
            a.status = "Protected by Windows";
            a.next = "Windows' safe default is in place.";
            a.step = NextStep::None;
            a.group = Group::Protected;
        }
        CheckStatus::Skipped
            if matches!(
                detail,
                "Revert the active transaction before starting another apply"
                    | "Revert the active transaction before applying again"
            ) =>
        {
            a.next = "Undo your last fixes before making new ones.";
            a.step = NextStep::ReviewUndo;
        }
        CheckStatus::Skipped if id.starts_with("permissions.service.") && !detail.is_empty() => {
            // The permission list could not be proven safe to edit (unusual
            // layout, owner or device rules). We never claim it is protected.
            a.status = "Left as it is";
            a.next = "Nothing was changed. If you're not sure, leave it as it is.";
        }
        _ => {}
    }
    if (*status == CheckStatus::Applied && detail == "Preference applied; restart required")
        || (*status == CheckStatus::Restored
            && detail == "Original preference restored; restart required")
    {
        a.status = "Restart needed";
        a.group = Group::Choice;
        a.next = "Save your work and restart your computer to finish this change.";
        a.step = NextStep::Restart;
    }
    a.impact = control_impact(id);
    a
}

/// Typed firewall evidence refines presentation only. Status and the engine's
/// live eligibility checks remain mutation authority; prose is not evidence.
pub fn for_outcome(outcome: &crate::engine::Outcome) -> Advice {
    use crate::model::{Authority, EffectiveFirewall, InboundAction};
    let mut a = for_control(&outcome.id, &outcome.status, &outcome.detail);
    let enabled = matches!(
        outcome.id.as_str(),
        "firewall.domain.enabled" | "firewall.private.enabled" | "firewall.public.enabled"
    );
    let inbound = matches!(
        outcome.id.as_str(),
        "firewall.domain.inbound" | "firewall.private.inbound" | "firewall.public.inbound"
    );
    if !enabled && !inbound {
        return a;
    }
    if outcome.authority == Some(Authority::Managed) {
        a.status = "Managed elsewhere";
        a.next = "This computer's owner controls this setting, so we leave it as it is.";
        a.step = NextStep::ReviewWithAdministrator;
        a.group = Group::Choice;
        return a;
    }
    let verified = matches!(outcome.effective, Some(EffectiveFirewall::Enabled(_))) && enabled
        || matches!(outcome.effective, Some(EffectiveFirewall::Inbound(_))) && inbound;
    if outcome.authority != Some(Authority::Local) || !verified {
        if matches!(
            outcome.status,
            CheckStatus::Attention
                | CheckStatus::Compliant
                | CheckStatus::Ok
                | CheckStatus::Unchanged
                | CheckStatus::Applied
        ) {
            a.status = "Couldn't check";
            a.next =
                "We couldn't confirm your firewall setting. Check again before making changes.";
            a.step = NextStep::CheckAgain;
            a.group = Group::Choice;
        }
        return a;
    }
    if matches!(
        outcome.status,
        CheckStatus::Compliant | CheckStatus::Ok | CheckStatus::Unchanged | CheckStatus::Applied
    ) {
        let protected = matches!(
            outcome.effective,
            Some(
                EffectiveFirewall::Enabled(true) | EffectiveFirewall::Inbound(InboundAction::Block)
            )
        );
        if protected && outcome.status != CheckStatus::Applied {
            a.status = "Protected by Windows";
            a.next = "Windows is already blocking these connections. Nothing to do.";
            a.step = NextStep::None;
            a.group = Group::Protected;
        } else if !protected {
            a.status = "Needs your choice";
            a.next =
                "We couldn't confirm your firewall setting. Check again before making changes.";
            a.step = NextStep::CheckAgain;
            a.group = Group::Choice;
        }
    }
    a
}

fn undo_ready(detail: &str) -> bool {
    detail.starts_with(crate::vbs::UNDO_READY)
}

/// Whether a finding comes from a Linux check, so the window never points it at a Windows settings page.
pub fn is_linux_finding(title: &str) -> bool {
    linux::finding(title).is_some()
}

pub fn for_finding(title: &str, status: &CheckStatus, detail: &str) -> Advice {
    use NextStep::*;
    let (label, next, step) = match title {
        "Security providers" => ("Your security apps", "Open Windows Security to make sure your antivirus is on and working.", OpenWindowsSecurity),
        "Windows Firewall" => ("Network protection", "Open Windows Security and make sure the firewall is on.", OpenWindowsSecurity),
        "Defender" => ("Virus protection", "Open Windows Security to make sure virus protection is on and up to date.", OpenWindowsSecurity),
        "Windows lifecycle" => ("Windows support", "Open Windows Update to check your version of Windows still gets security updates.", OpenWindowsUpdate),
        "Device encryption" => ("Protection if your computer is lost", "Open encryption settings. Save your recovery key somewhere safe before you change anything.", OpenEncryption),
        "Secure Boot" => ("Startup protection", "This is set when your computer starts up. Follow your computer maker's guide before changing it.", ReviewFirmware),
        "Windows updates" => ("Windows updates", "Open Windows Update and install anything that is waiting.", OpenWindowsUpdate),
        "Remote Desktop" => ("Remote access", "Remote access lets someone sign in to this computer from elsewhere. Turn it off in Settings if you don't use it.", OpenRemoteDesktop),
        "SMB1" => ("Older file sharing", "An old way of sharing files is still on. Turn it off in Windows Features unless an old device needs it.", ReviewWindowsFeatures),
        "SmartScreen" => ("Unsafe app and website warnings", "Open Windows Security and make sure warnings about risky apps and websites are on.", OpenWindowsSecurity),
        "Memory integrity" => ("Core system protection", "Open Windows Security and look at the extra protection for the core of Windows. Some older devices don't work with it.", OpenWindowsSecurity),
        "Memory integrity not running" if undo_ready(detail) => ("Core system protection", "Core system protection is on but is not running. Restart your computer (choose Restart, not Shut down). If it still isn't running, undo it.", ReviewUndo),
        "Memory integrity not running" => ("Core system protection", "Core system protection is on but is not running. Restart your computer (choose Restart, not Shut down). If it still isn't running, open History and undo your fixes, newest first.", OpenHistory),
        "Kernel stack protection not running" if undo_ready(detail) => ("Extra core protection", "Extra core protection is on but is not running. Restart your computer (choose Restart, not Shut down). If it still isn't running, undo it.", ReviewUndo),
        "Kernel stack protection not running" => ("Extra core protection", "Extra core protection is on but is not running. Restart your computer (choose Restart, not Shut down). If it still isn't running, open History and undo your fixes, newest first.", OpenHistory),
        "A device may not be working" if undo_ready(detail) => ("Core system protection", "Windows is blocking a driver, so a device may not work. If a device stopped working, undo this fix.", ReviewUndo),
        "A device may not be working" => ("Core system protection", "Windows is blocking a driver, so a device may not work. If a device stopped working, open History and undo your fixes, newest first.", OpenHistory),
        "Management and mutation eligibility" => ("Who manages this computer", "If you're not sure who manages this computer, look at work or school accounts in Settings.", ReviewWithAdministrator),
        "Automatic logon" => ("Automatic sign-in", "Your computer signs in by itself. Turn that off if other people can get to it.", OpenAccounts),
        "Service permissions: BITS" => ("Update download permissions", "We leave this one alone. If a fix is available, it appears under Needs your attention.", ReviewWithAdministrator),
        "Service permissions: wuauserv" => ("Windows Update permissions", "We leave this one alone. If a fix is available, it appears under Needs your attention.", ReviewWithAdministrator),
        "Service permissions: WinDefend" => ("Antivirus service permissions", "We leave this one alone. If a fix is available, it appears under Needs your attention.", ReviewWithAdministrator),
        "Service permissions: Schedule" => ("Scheduled task service permissions", "We leave this one alone. If a fix is available, it appears under Needs your attention.", ReviewWithAdministrator),
        "Service permissions: SecblitzMonitor" => ("Protection monitor permissions", "We leave this one alone. If a fix is available, it appears under Needs your attention.", ReviewWithAdministrator),
        "Journal recovery" => ("Saved changes", "Undo your last fixes before making new ones.", ReviewUndo),
        "Assessment unavailable" | "Windows service settings" => ("Additional protection checks", "Check again in a moment. Nothing has been changed.", CheckAgain),
        _ => linux::finding(title).unwrap_or((
            "Protection check",
            "Check again in a moment. Nothing has been changed.",
            CheckAgain,
        )),
    };
    let mut a = base(label, status, (next, step));
    if *status == CheckStatus::Info {
        a.group = Group::Information;
        a.status = "For your information";
    }
    a.impact = finding_impact(title);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_recognized_control_and_finding_has_non_empty_impact() {
        for id in [
            "defender.realtime",
            "defender.behavior",
            "defender.ioav",
            "defender.archive",
            "firewall.domain.enabled",
            "firewall.private.enabled",
            "firewall.public.enabled",
            "firewall.domain.inbound",
            "firewall.private.inbound",
            "firewall.public.inbound",
            "uac.enabled",
            "uac.consent",
            "installer.always_install_elevated",
            "lsa.restrict_anonymous_sam",
            "lsa.limit_blank_password_use",
            "wdigest.use_logon_credential",
            "permissions.service.bits",
            "permissions.service.wuauserv",
        ] {
            let a = for_control(id, &CheckStatus::Attention, "");
            assert!(!a.impact.is_empty(), "missing impact for control: {id}");
            let a_ok = for_control(id, &CheckStatus::Compliant, "");
            assert!(
                !a_ok.impact.is_empty(),
                "missing impact for compliant control: {id}"
            );
        }
        assert!(for_control("unknown.id", &CheckStatus::Attention, "")
            .impact
            .is_empty());
        assert!(for_control("findings", &CheckStatus::Attention, "")
            .impact
            .is_empty());

        for title in [
            "Windows lifecycle",
            "Device encryption",
            "Secure Boot",
            "Windows updates",
            "Remote Desktop",
            "SMB1",
            "SmartScreen",
            "Memory integrity",
            "Automatic logon",
        ] {
            let a = for_finding(title, &CheckStatus::Attention, "");
            assert!(!a.impact.is_empty(), "missing impact for finding: {title}");
        }
        for title in [
            "Security providers",
            "Windows Firewall",
            "Defender",
            "Journal recovery",
            "Assessment unavailable",
        ] {
            assert!(
                for_finding(title, &CheckStatus::Attention, "")
                    .impact
                    .is_empty(),
                "unexpected impact for finding: {title}"
            );
        }
    }

    #[test]
    fn every_extended_control_has_plain_label_impact_help_and_the_right_kind_of_offer() {
        for spec in crate::hardening::all() {
            let id = spec.id;
            assert_ne!(control_label(id), "Protection check", "{id}");
            assert!(!control_impact(id).is_empty(), "{id}");
            assert_eq!(is_choice_check_id(id), spec.ask, "{id}");
            let ok = for_control(id, &CheckStatus::Compliant, "");
            assert_eq!(ok.group, Group::Protected, "{id}");
            assert!(!ok.ask);
            let a = for_control(id, &CheckStatus::Attention, "Eligible");
            assert_eq!(a.step, NextStep::Repair, "{id}");
            assert_eq!(a.ask, spec.ask, "{id}");
            if spec.ask {
                assert_eq!(a.status, "Your choice");
                assert_eq!(a.next, choice_consequence(id));
                assert!(a.next.ends_with('.') && !a.next.contains('\n'));
                assert!(
                    a.next.len() < 130,
                    "{id}: consequence must stay one short line"
                );
                assert_eq!(
                    a.group,
                    if extra_section(id).is_some() {
                        Group::Information
                    } else {
                        Group::Choice
                    }
                );
            } else {
                assert_eq!(a.status, "Can fix");
                assert_eq!(a.group, Group::Recommended);
                assert!(choice_consequence(id).is_empty());
            }
            let managed = for_control(
                id,
                &CheckStatus::Skipped,
                "Applied computer Group Policy: assessment only",
            );
            assert_eq!(managed.status, "Managed elsewhere", "{id}");
            assert_ne!(managed.step, NextStep::Repair);
            let applied = for_control(
                id,
                &CheckStatus::Applied,
                "Preference applied; restart required",
            );
            assert_eq!(applied.status, "Restart needed", "{id}");
        }
        assert!(!is_choice_check_id("uac.enabled") && !is_choice_check_id("unknown.id"));
    }

    #[test]
    fn not_offered_reasons_are_calm_facts_that_never_count_against_the_score() {
        for reason in [
            "Not offered: Secure Boot is off",
            "Not offered: Smart App Control is on",
            "Not offered: some sign-in add-ons would stop working",
            "Not offered: sign-in add-ons from other companies are installed",
            "Not offered: no other administrator account is enabled",
            "Not offered: no other administrator account could be confirmed",
            "Not offered: Defender real-time protection is off",
            "Not offered: Defender cloud protection is off",
            "Not offered: Web protection is off",
            "Not offered: this computer uses Configuration Manager",
            "Not offered: Microsoft Office was not found",
            "Not offered: this edition of Windows does not include it",
            "Not offered: Defender behavior monitoring is off",
            "Not offered: the old file-sharing version could not be checked",
            "Not offered: the old file-sharing version (SMB1) is still on",
            "Not offered: a shared folder or drive may rely on the old name service",
            "Not offered: a browser rule already turns off every add-on",
            "Not offered: the browser add-on rules on this computer could not be read",
            "Not offered: Recall is not available on this computer",
            "Not offered: Paint was not found on this computer",
            "Not offered: Notepad was not found on this computer",
            "Not offered: this version of Windows does not have it",
            "Not offered: this setting is not available on Windows Home",
            "Not offered: Windows keeps this setting for you to change yourself",
            "Not offered: a printer on this computer is shared with other computers",
            "Not offered: printing is busy right now",
            "Not offered: your account has no password",
            "Not offered: you are connected to this computer from another device right now",
            "Not offered: something is using the old file sharing right now",
            "Not offered: Windows Home cannot accept Remote Desktop connections",
            "Not offered: this computer is set up as a kiosk",
            "Not offered: Secblitz cannot tell who is signed in",
            "Not offered: you are signed in with the built-in Administrator account",
            "Not offered: a locked sign-in would stay locked until an administrator unlocks it",
            crate::vbs::NOT_SUPPORTED,
            crate::vbs::LOCKED,
            crate::vbs::DRIVER,
            "Not offered: a driver on this computer may not work with it: old.sys, older.sys",
            crate::vbs::DRIVERS_UNREADABLE,
            crate::vbs::NEEDS_MEMORY_INTEGRITY,
            crate::vbs::NEEDS_RESTART,
            crate::vbs::NO_SHADOW_STACKS,
            crate::vbs::UNREADABLE,
            crate::vbs::SET_BY_HAND,
            crate::vbs::OLD_WINDOWS,
            "Not offered: the hosts file could not be found",
            "Not offered: the hosts file is too large to change safely",
            "Not offered: the hosts file uses a format we cannot keep exactly",
            "Not offered: too many items to switch off safely at once",
            "Not offered: a shared folder would be left with no one who can open it",
            "Not offered: a shared folder would be left that only administrators can open",
            "Not offered: a shared folder has permissions that could not be put back exactly",
            "Not offered: the recovery tools are missing from this computer",
            "Not offered: this computer has no Wi-Fi adapter",
            "Not offered: the Wi-Fi settings of this computer could not be read",
        ] {
            let a = for_control("lsa.run_as_ppl", &CheckStatus::Skipped, reason);
            assert_eq!(a.status, "Not offered", "{reason}");
            assert_eq!(a.group, Group::Information);
            assert_ne!(a.step, NextStep::Repair);
        }
        assert_ne!(
            for_control(
                "lsa.run_as_ppl",
                &CheckStatus::Skipped,
                "Not offered: anything"
            )
            .status,
            "Not offered"
        );
    }

    #[test]
    fn optional_switches_sit_in_their_own_groups_and_never_count_against_the_score() {
        for (id, section) in [
            ("privacy.recall", "Privacy extras"),
            ("privacy.online_speech", "Privacy extras"),
            ("privacy.typing_inking", "Privacy extras"),
            ("privacy.lock_screen_notifications", "Privacy extras"),
            ("privacy.signin_email", "Privacy extras"),
            ("privacy.wifi_random_address", "Privacy extras"),
            ("ai.click_to_do", "AI features"),
            ("ai.paint", "AI features"),
            ("ai.notepad", "AI features"),
            ("debloat.widgets_policy", "Less clutter"),
            ("debloat.device_companion_apps", "Less clutter"),
            ("browser.shopping_ai", "Privacy extras"),
            ("browser.data_collection", "Privacy extras"),
            ("browser.safety_mode", "Privacy extras"),
            ("browser.dns_bypass", "Privacy extras"),
        ] {
            assert_eq!(extra_section(id), Some(section), "{id}");
            let a = for_control(id, &CheckStatus::Attention, "Eligible");
            assert_eq!(
                (a.status, a.group, a.ask),
                ("Your choice", Group::Information, true),
                "{id}"
            );
            assert!(a.impact_prefix().starts_with("Why it matters"), "{id}");
        }
        assert_eq!(extra_section("uac.enabled"), None);
        assert_eq!(extra_section("findings"), None);
    }

    #[test]
    fn findings_with_an_automatic_fix_point_at_their_control() {
        for (title, id) in [
            ("Automatic logon", "accounts.autologon"),
            ("Remote Desktop", "remote_desktop.disabled"),
            ("SMB1", "smb1.disabled"),
        ] {
            assert_eq!(control_for_finding(title), Some(id));
            assert!(crate::hardening::is_hardening_check_id(id));
            assert_eq!(
                for_finding(title, &CheckStatus::Attention, "").label,
                control_label(id)
            );
            assert_eq!(
                for_finding(title, &CheckStatus::Attention, "").impact,
                control_impact(id)
            );
        }
        assert_eq!(control_for_finding("Secure Boot"), None);
        assert!(choice_consequence("accounts.autologon").contains("password or PIN"));
        assert!(choice_consequence("smb1.disabled").contains("restart"));
    }

    #[test]
    fn core_protection_rows_read_well_when_offered_blocked_or_waiting_for_a_restart() {
        for id in ["vbs.memory_integrity", "vbs.kernel_stack_protection"] {
            let a = for_control(id, &CheckStatus::Attention, "Eligible");
            assert_eq!(
                (a.status, a.step, a.ask),
                ("Your choice", NextStep::Repair, true)
            );
            assert!(
                a.next.contains("restart") && a.next.contains("undo"),
                "{id}"
            );
            let applied = for_control(
                id,
                &CheckStatus::Applied,
                "Preference applied; restart required",
            );
            assert_eq!(applied.status, "Restart needed");
            assert_eq!(applied.step, NextStep::Restart);
            for reason in [
                crate::vbs::NOT_SUPPORTED,
                crate::vbs::LOCKED,
                "Not offered: a driver on this computer may not work with it: a.sys",
                crate::vbs::NEEDS_MEMORY_INTEGRITY,
                crate::vbs::NO_SHADOW_STACKS,
                crate::vbs::SET_BY_HAND,
                crate::vbs::OLD_WINDOWS,
            ] {
                let n = for_control(id, &CheckStatus::Skipped, reason);
                assert_eq!(n.status, "Not offered", "{reason}");
                assert_eq!(n.group, Group::Information);
                assert_eq!(n.step, NextStep::None);
                assert!(n.next.ends_with('.') && n.next.len() < 170, "{reason}");
                assert!(!n.next.contains("Memory integrity"), "{reason}");
            }
            let on = for_control(id, &CheckStatus::Skipped, crate::vbs::ALREADY_ON);
            assert_eq!((on.status, on.group), ("Good to go", Group::Protected));
            let m = for_control(
                id,
                &CheckStatus::Skipped,
                "Relevant policy is configured: assessment only",
            );
            assert_eq!(m.status, "Managed elsewhere");
        }
        let driver = for_control(
            "vbs.memory_integrity",
            &CheckStatus::Skipped,
            "Not offered: a driver on this computer may not work with it: a.sys",
        );
        assert!(driver
            .next
            .contains("Device security, then Core isolation details"));
        assert!(!driver.next.contains("a.sys"));
    }

    #[test]
    fn a_core_protection_that_is_on_but_not_running_offers_a_restart_then_undo() {
        let ready = format!("{}. boot: 1.", crate::vbs::UNDO_READY);
        for title in [
            "Memory integrity not running",
            "Kernel stack protection not running",
            "A device may not be working",
        ] {
            let a = for_finding(title, &CheckStatus::Attention, &ready);
            assert_eq!(a.step, NextStep::ReviewUndo, "{title}");
            assert_eq!(a.group, Group::Choice);
            assert!(a.next.contains("undo"), "{title}");
            assert!(!a.impact.is_empty(), "{title}");
            assert!(a.next.len() < 170);
            let h = for_finding(title, &CheckStatus::Attention, "boot: 1.");
            assert_eq!(h.step, NextStep::OpenHistory, "{title}");
            assert!(h.next.contains("History") && h.next.len() < 190, "{title}");
        }
        assert_eq!(
            control_for_finding("Memory integrity"),
            Some("vbs.memory_integrity")
        );
        assert_eq!(control_for_finding("Memory integrity not running"), None);
        assert_eq!(
            control_for_finding("Kernel stack protection not running"),
            None
        );
        assert_eq!(control_for_finding("A device may not be working"), None);
        assert_eq!(control_for_finding("Secure Boot"), None);
    }

    #[test]
    fn every_reason_the_handled_item_scripts_give_has_a_calm_plain_sentence() {
        let script = include_str!("platform/hardening.handled.ps1");
        let mut found = 0;
        for piece in script.split('\'') {
            if piece.starts_with("Not offered: ") {
                found += 1;
                let line = not_offered(piece).unwrap_or_else(|| panic!("no sentence for {piece}"));
                assert!(line.ends_with('.') && line.len() < 100, "{piece}");
            }
        }
        assert!(found >= 4, "{found}");
    }

    #[test]
    fn recovery_tools_row_is_a_normal_fix_with_a_plain_reason_when_not_offered() {
        let id = "recovery.winre_enabled";
        let a = for_control(id, &CheckStatus::Attention, "Eligible");
        assert_eq!(
            (a.status, a.step, a.ask, a.group),
            ("Can fix", NextStep::Repair, false, Group::Recommended)
        );
        assert!(
            a.next.contains("recovery tools") && a.next.len() < 130,
            "{}",
            a.next
        );
        assert_eq!(a.impact_prefix(), "Turning it on protects you from:");
        assert!(!a.impact.is_empty() && !a.impact.ends_with('.'));
        let ok = for_control(id, &CheckStatus::Compliant, "");
        assert_eq!((ok.status, ok.group), ("Good to go", Group::Protected));
        let script = include_str!("platform/hardening.ps1");
        let start = script.find("'recovery.winre_enabled' {").unwrap();
        let body = &script[start..start + script[start..].find("\n        }\n").unwrap()];
        let reasons: Vec<&str> = body
            .split('\'')
            .filter(|p| p.starts_with("Not offered: "))
            .collect();
        assert!(!reasons.is_empty());
        for reason in reasons {
            let a = for_control(id, &CheckStatus::Skipped, reason);
            assert_eq!(
                (a.status, a.group),
                ("Not offered", Group::Information),
                "{reason}"
            );
            assert_ne!(a.step, NextStep::Repair);
            assert!(
                a.next.ends_with('.') && !a.next.contains('\u{2014}'),
                "{reason}"
            );
        }
        let managed = for_control(
            id,
            &CheckStatus::Skipped,
            "Domain-managed machine: assessment only",
        );
        assert_eq!(managed.status, "Managed elsewhere");
        assert_eq!(
            for_control(id, &CheckStatus::Conflict, "").step,
            NextStep::ReviewUndo
        );
    }

    #[test]
    fn handled_item_controls_are_choices_with_a_plain_consequence() {
        for id in [
            "services.unquoted_paths",
            "firewall.user_dir_inbound_allow",
            "net.hosts_file",
            "persistence.run_and_tasks",
            "browser.extensions_off",
        ] {
            assert!(is_choice_check_id(id), "{id}");
            let a = for_control(id, &CheckStatus::Attention, "Eligible");
            assert_eq!(
                (a.status, a.step, a.ask),
                ("Your choice", NextStep::Repair, true)
            );
            assert!(!a.impact.is_empty() && a.next == choice_consequence(id));
            let managed = for_control(
                id,
                &CheckStatus::Skipped,
                "Domain-managed machine: assessment only",
            );
            assert_eq!(managed.status, "Managed elsewhere", "{id}");
            assert_eq!(
                for_control(id, &CheckStatus::Conflict, "").step,
                NextStep::ReviewUndo
            );
        }
    }

    #[test]
    fn impact_prefix_follows_group_and_is_empty_when_impact_is_empty() {
        let a = for_control("uac.enabled", &CheckStatus::Compliant, "");
        assert_eq!(a.group, Group::Protected);
        assert_eq!(a.impact_prefix(), "Protects you from:");

        let a = for_control("uac.enabled", &CheckStatus::Attention, "");
        assert_eq!(a.group, Group::Recommended);
        assert_eq!(a.impact_prefix(), "Turning it on protects you from:");

        let a = for_control("uac.enabled", &CheckStatus::Unknown, "");
        assert_eq!(a.group, Group::Choice);
        assert_eq!(a.impact_prefix(), "Why it matters:");

        let a = for_control(
            "uac.enabled",
            &CheckStatus::Applied,
            "Preference applied; restart required",
        );
        assert_eq!(a.group, Group::Choice);
        assert_eq!(a.impact_prefix(), "Why it matters:");

        let a = for_control("unknown.id", &CheckStatus::Compliant, "");
        assert!(a.impact.is_empty());
        assert_eq!(a.impact_prefix(), "");
    }

    #[test]
    fn applied_firewall_with_contradictory_evidence_is_not_protected() {
        use crate::{
            engine::Outcome,
            model::{Authority, EffectiveFirewall, InboundAction},
        };
        for (id, effective) in [
            ("firewall.public.enabled", EffectiveFirewall::Enabled(false)),
            (
                "firewall.private.inbound",
                EffectiveFirewall::Inbound(InboundAction::Allow),
            ),
        ] {
            let outcome = Outcome {
                id: id.into(),
                status: CheckStatus::Applied,
                effective: Some(effective),
                authority: Some(Authority::Local),
                ..Default::default()
            };
            let advice = for_outcome(&outcome);
            assert_eq!(advice.group, Group::Choice);
            assert_eq!(advice.step, NextStep::CheckAgain);
            assert_ne!(advice.status, "Fixed");
        }
        assert_eq!(
            for_control(
                "uac.enabled",
                &CheckStatus::Skipped,
                "Relevant policy is configured: assessment only"
            )
            .status,
            "Managed elsewhere"
        );
    }

    #[test]
    fn firewall_protection_uses_typed_evidence_never_reason_text() {
        use crate::{
            engine::Outcome,
            model::{Authority, EffectiveFirewall, InboundAction},
        };
        let mut outcome = Outcome {
            id: "firewall.public.inbound".into(),
            status: CheckStatus::Compliant,
            detail: "untrusted prose saying defaults are safe".into(),
            effective: Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            authority: Some(Authority::Local),
            ..Default::default()
        };
        assert_eq!(for_outcome(&outcome).status, "Protected by Windows");
        assert_eq!(for_outcome(&outcome).step, NextStep::None);
        outcome.authority = Some(Authority::Managed);
        assert_eq!(for_outcome(&outcome).status, "Managed elsewhere");
        assert_eq!(for_outcome(&outcome).group, Group::Choice);
        for authority in [None, Some(Authority::Unknown)] {
            outcome.authority = authority;
            assert_ne!(for_outcome(&outcome).group, Group::Protected);
        }
        outcome.authority = Some(Authority::Local);
        for evidence in [
            None,
            Some(EffectiveFirewall::Enabled(true)),
            Some(EffectiveFirewall::Inbound(InboundAction::Allow)),
        ] {
            outcome.effective = evidence;
            assert_ne!(for_outcome(&outcome).group, Group::Protected);
        }
        outcome.status = CheckStatus::Attention;
        assert_eq!(for_outcome(&outcome).step, NextStep::Repair);
        outcome.status = CheckStatus::Skipped;
        assert_ne!(for_outcome(&outcome).step, NextStep::Repair);
    }

    #[test]
    fn informational_findings_do_not_count_as_problems_or_protection() {
        for title in ["Windows updates", "Journal recovery"] {
            assert_eq!(
                for_finding(title, &CheckStatus::Info, "").group,
                Group::Information
            );
            assert_eq!(
                for_finding(title, &CheckStatus::Pending, "").group,
                Group::Choice
            );
        }
    }

    #[test]
    fn findings_never_offer_repairs_or_infer_health_from_info() {
        for title in [
            "Windows Firewall",
            "Defender",
            "Service permissions: BITS",
            "Windows updates",
        ] {
            for status in [
                CheckStatus::Attention,
                CheckStatus::Review,
                CheckStatus::Info,
                CheckStatus::Unknown,
            ] {
                let a = for_finding(title, &status, "Everything is fine; eligible");
                assert_ne!(a.step, NextStep::Repair);
                assert_ne!(a.group, Group::Protected);
                assert!(!a.next.contains("Secblitz can fix"));
            }
        }
    }

    #[test]
    fn skips_restores_and_restart_do_not_claim_protection() {
        let a = for_control(
            "uac.enabled",
            &CheckStatus::Skipped,
            "Preserving absent or nonzero UAC preference",
        );
        assert_eq!(a.status, "Protected by Windows");
        assert_eq!(a.group, Group::Protected);
        assert_eq!(a.next, "Windows' safe default is in place.");
        for id in [
            "installer.always_install_elevated",
            "wdigest.use_logon_credential",
            "lsa.restrict_anonymous_sam",
            "lsa.limit_blank_password_use",
            "uac.consent",
        ] {
            let a = for_control(
                id,
                &CheckStatus::Skipped,
                "Preserving absent or already-safe machine preference",
            );
            assert_eq!(a.group, Group::Protected, "{id}");
            assert_eq!(a.step, NextStep::None, "{id}");
        }
        let p = for_control(
            "permissions.service.bits",
            &CheckStatus::Skipped,
            "Service permissions preserved: Complex ACL requires manual review",
        );
        assert_eq!(p.group, Group::Choice);
        assert_eq!(p.status, "Left as it is");
        assert_eq!(
            for_control(
                "uac.enabled",
                &CheckStatus::Skipped,
                "Domain-managed machine: assessment only"
            )
            .status,
            "Managed elsewhere"
        );
        assert_eq!(
            for_control(
                "uac.enabled",
                &CheckStatus::Skipped,
                "Group Policy authority is unknown: assessment only"
            )
            .status,
            "Needs your choice"
        );
        for (status, detail) in [
            (CheckStatus::Restored, "Original preference restored"),
            (
                CheckStatus::Unchanged,
                "Original preference already present",
            ),
            (CheckStatus::Skipped, "new reason"),
        ] {
            assert_eq!(
                for_control("uac.enabled", &status, detail).group,
                Group::Choice
            );
        }
        assert_eq!(
            for_control(
                "wdigest.use_logon_credential",
                &CheckStatus::Applied,
                "Preference applied; restart required"
            )
            .status,
            "Restart needed"
        );
        assert_eq!(
            for_control("unknown.control", &CheckStatus::Attention, "eligible").step,
            NextStep::CheckAgain
        );
        assert_eq!(
            for_control("firewall.public.enabled", &CheckStatus::Attention, "").step,
            NextStep::Repair
        );
    }
}
