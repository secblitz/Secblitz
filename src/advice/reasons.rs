//! Why a check is not offered, how to repair it, and who manages it.
/// Calm facts, not faults: they never lower the score.
pub(super) fn not_offered(reason: &str) -> Option<&'static str> {
    use crate::vbs as v;
    // The driver reason also names the drivers after a colon; the names are
    // shown in "More details", never matched here.
    if v::is_driver_reason(reason) {
        return Some(
            "A driver on this computer may not work with it, so we leave this alone. To look yourself, open Windows Security, then Device security, then Core isolation details.",
        );
    }
    Some(match reason {
        r if r == v::NOT_SUPPORTED => {
            "This computer doesn't support it, or virtualization is off in its start-up settings, so we leave this alone."
        }
        r if r == v::LOCKED => {
            "It is locked in your computer's start-up settings, so we leave this alone."
        }
        r if r == v::DRIVERS_UNREADABLE => "We couldn't check your drivers, so we leave this alone.",
        r if r == v::NEEDS_MEMORY_INTEGRITY => {
            "Turn on Core system protection first, then check again."
        }
        r if r == v::NEEDS_RESTART => {
            "Restart your computer to finish turning on Core system protection, then check again."
        }
        r if r == v::SET_BY_HAND => {
            "Virtualization security was set up by hand on this computer, so we leave it alone."
        }
        r if r == v::OLD_WINDOWS => {
            "This version of Windows doesn't have it, so there is nothing to turn on."
        }
        r if r == v::NO_SHADOW_STACKS => {
            "This computer's processor doesn't support it, so there is nothing to turn on."
        }
        r if r == v::UNREADABLE => "We couldn't check this computer's support for it, so we leave it alone.",
        "Not offered: Secure Boot is off" => {
            "This protection needs Secure Boot, which is off on this computer. We leave it alone."
        }
        "Not offered: Smart App Control is on" => {
            "Smart App Control already guards this part of Windows, so we leave it alone."
        }
        "Not offered: some sign-in add-ons would stop working" => {
            "Some sign-in add-ons would stop working, so we leave this alone."
        }
        "Not offered: sign-in add-ons from other companies are installed" => {
            "Sign-in add-ons from other companies are installed, so we leave this alone."
        }
        "Not offered: no other administrator account is enabled"
        | "Not offered: no other administrator account could be confirmed" => {
            "This may be the only administrator account, so we keep it switched on."
        }
        "Not offered: Defender real-time protection is off" => {
            "Turn on live virus protection first, then check again."
        }
        "Not offered: Web protection is off" => {
            "Turn on Web protection first, then check again."
        }
        r if r == crate::engine::cfa::NOT_WATCHED => {
            "Turn on the folder watch first, then come back after a week."
        }
        r if r == crate::engine::cfa::STILL_WATCHING => {
            "Windows is still watching your files. Full protection is offered after a week of watching."
        }
        r if r == crate::engine::cfa::COVERED => {
            "Putting full protection back turns this on too."
        }
        "Not offered: folder protection is off" => "Turn on the folder watch first, then check again.",
        "Not offered: Defender cloud protection is off" => {
            "Turn on cloud threat lookups first, then check again."
        }
        "Not offered: this computer uses Configuration Manager" => {
            "Your organization's tools manage this, so we leave it alone."
        }
        "Not offered: Microsoft Office was not found" => {
            "Microsoft Office isn't installed here, so there is nothing to protect."
        }
        "Not offered: this edition of Windows does not include it" => {
            "This version of Windows doesn't include this protection."
        }
        "Not offered: Windows Home cannot accept Remote Desktop connections" => {
            "Windows Home can't accept Remote Desktop connections, so there is nothing to turn off."
        }
        "Not offered: this computer is set up as a kiosk" => {
            "This computer is set up as a kiosk that signs in by itself, so we leave this alone."
        }
        "Not offered: Defender behavior monitoring is off" => {
            "Turn on suspicious app detection first, then check again."
        }
        "Not offered: the old file-sharing version could not be checked" => {
            "We couldn't check something this depends on, so we leave it alone."
        }
        "Not offered: the old file-sharing version (SMB1) is still on" => {
            "Old file sharing is still on here, so we leave this alone."
        }
        "Not offered: a shared folder or drive may rely on the old name service" => {
            "A shared folder or drive here may need this, so we leave it alone."
        }
        "Not offered: Recall is not available on this computer" => {
            "Recall is not on this computer, so there is nothing to change."
        }
        "Not offered: Paint was not found on this computer" => {
            "Paint isn't installed here, so there is nothing to turn off."
        }
        "Not offered: Notepad was not found on this computer" => {
            "The Notepad app isn't installed here, so there is nothing to turn off."
        }
        "Not offered: this version of Windows does not have it" => {
            "This version of Windows doesn't have it, so there is nothing to turn off."
        }
        "Not offered: Windows keeps this setting for you to change yourself" => {
            "Windows only lets you hide Widgets yourself. It takes one switch in Settings."
        }
        "Not offered: this setting is not available on Windows Home" => {
            "Windows Home does not support this setting, so we leave it alone."
        }
        "Not offered: a printer on this computer is shared with other computers" => {
            "A printer on this computer is shared with others, so we leave this alone."
        }
        "Not offered: printing is busy right now" => {
            "Something is waiting to print, so we leave this for now. Try again when printing is finished."
        }
        "Not offered: you are connected to this computer from another device right now" => {
            "You are connected from another device, so we leave this alone. Turning it off would cut you off."
        }
        "Not offered: something is using the old file sharing right now" => {
            "Something is using the old file sharing right now, so we leave this alone."
        }
        "Not offered: your account has no password" => {
            "Give your account a password first, then check again."
        }
        "Not offered: you are signed in with the built-in Administrator account" => {
            "You are signed in with this account, so we keep it switched on. To hide it, make your own administrator account, sign in with that, then check again."
        }
        "Not offered: Secblitz cannot tell who is signed in" => {
            "We could not tell which account is signed in, so we leave this alone."
        }
        "Not offered: a locked sign-in would stay locked until an administrator unlocks it" => {
            "A locked account here would stay locked until an administrator unlocks it, so we leave this alone."
        }
        "Not offered: the hosts file could not be found" => {
            "The hosts file is missing, so there is nothing for us to change."
        }
        "Not offered: the hosts file is too large to change safely" => {
            "The hosts file is too big to change safely, so we leave it alone."
        }
        "Not offered: the hosts file uses a format we cannot keep exactly" => {
            "The hosts file is saved in a format we can't keep exactly, so we leave it alone."
        }
        "Not offered: too many items to switch off safely at once" => {
            "There are too many to switch off safely at once, so we leave this alone."
        }
        "Not offered: a shared folder would be left with no one who can open it" => {
            "A shared folder would be left that nobody can open, so we leave this alone."
        }
        "Not offered: a shared folder would be left that only administrators can open" => {
            "A shared folder would be left that only administrators can open, so we leave this alone."
        }
        "Not offered: a shared folder has permissions that could not be put back exactly" => {
            "A shared folder has permissions we could not put back exactly, so we leave this alone."
        }
        "Not offered: the recovery tools are missing from this computer" => {
            "The files the recovery tools need are missing from this computer, so we leave this alone."
        }
        "Not offered: this computer has no Wi-Fi adapter" => {
            "This computer has no Wi-Fi adapter, so there is nothing to change."
        }
        "Not offered: the Wi-Fi settings of this computer could not be read" => {
            "We couldn't read this computer's Wi-Fi settings, so we leave them alone."
        }
        "Not offered: a browser rule already turns off every add-on" => {
            "A rule on this computer already turns off browser add-ons, so we leave it alone."
        }
        "Not offered: the browser add-on rules on this computer could not be read" => {
            "We couldn't read this computer's browser add-on rules, so we leave them alone."
        }
        _ => return super::linux::not_offered(reason),
    })
}

pub(super) fn repair_help(id: &str) -> &'static str {
    match id {
        "firewall.domain.enabled"
        | "firewall.private.enabled"
        | "firewall.public.enabled"
        | "firewall.domain.inbound"
        | "firewall.private.inbound"
        | "firewall.public.inbound" => {
            "It stops uninvited connections to your computer."
        }
        "permissions.service.bits" | "permissions.service.wuauserv" => {
            "It keeps Windows updates safe from unwanted changes."
        }
        "wdigest.use_logon_credential" => {
            "Your password will no longer be kept where other programs can read it."
        }
        "uac.enabled" => "Windows will ask before big changes are made.",
        "uac.consent" => "Windows will ask for approval before big changes.",
        "installer.always_install_elevated" => {
            "App installers will no longer get full control of your computer."
        }
        "lsa.restrict_anonymous_sam" => {
            "Other devices on the network will no longer see your account names."
        }
        "lsa.limit_blank_password_use" => {
            "Accounts without a password can no longer be used over the network."
        }
        "defender.pua" => "Junk apps bundled with downloads will be blocked.",
        "defender.script_nis" => "It turns scanning for harmful scripts back on.",
        "defender.asr.standard" => {
            "It stops harmful programs from reading your sign-in details."
        }
        "net.public_sharing_exposure" => {
            "Your shared files and printers stay hidden on public Wi-Fi."
        }
        "printer.point_and_print" => {
            "Printer drivers will only be installed with your permission."
        }
        "net.llmnr" => "Wrong name-lookup answers will be ignored.",
        "accounts.lockout_policy" => {
            "Too many wrong passwords will lock sign-in for a few minutes."
        }
        "system.exploit_mitigations" => {
            "It switches Windows' built-in memory protections back on."
        }
        "recovery.winre_enabled" => {
            "It turns the recovery tools back on, so Windows can repair itself if it stops starting."
        }
        _ => super::linux::repair(id).unwrap_or("It turns this protection on."),
    }
}

pub(super) fn managed(reason: &str) -> bool {
    // Exact backend reason keys only; an unknown authority is not management.
    let reason = reason
        .strip_prefix("Service permissions preserved: ")
        .unwrap_or(reason);
    matches!(
        reason,
        "Domain-managed machine: assessment only"
            | "Device is registered with MDM: assessment only"
            | "Applied computer Group Policy: assessment only"
            | "Relevant resultant Group Policy: assessment only"
            | "Firewall profile has resultant Group Policy: assessment only"
            | "Configured management/security policy: assessment only"
            | "Relevant policy is configured: assessment only"
            | "Other machine Installer policy is configured: assessment only"
            | "Applied computer policy settings: service permissions are assessment only"
    )
}
