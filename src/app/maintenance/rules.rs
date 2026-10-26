//! What Secblitz offers for each individual check rule: advice, the page to open and the follow-up actions.
pub fn rule_advice(rule_id: &str) -> Option<&'static str> {
    Some(match rule_id {
        "os.feature_release_support" => "Your version of Windows is running out of safety updates. Install the newest version in Windows Update.",
        "boot.secure_boot_certs" => "Your computer's startup security needs a renewal. Install all Windows updates, then check your computer maker's website.",
        "defender.tamper_protection" => "Turn on Tamper Protection so malware can't switch off your virus protection.",
        "defender.threats" => "Windows found something harmful. Secblitz can remove it, and Windows Security usually keeps a copy you can restore.",
        "defender.exclusions_risky" => "Your virus protection skips some risky places. Look at the list in Windows Security.",
        "defender.scan_age" => "Your computer hasn't been scanned for a while. Run a quick scan in Windows Security.",
        "smartscreen.apps" => "Turn on warnings for unknown downloads in Windows Security.",
        "smartscreen.browser_policy" => "A setting has switched off your browser's warnings about dangerous sites. Ask whoever set up this computer.",
        "update.paused" => "Updates are paused. Resume them in Windows Update.",
        "update.reboot_overdue" => "Restart your computer to finish installing updates. Save your work first.",
        "ps.v2_engine" => "A very old Windows tool is still installed. Remove it in Windows Features.",
        "net.hosts_file" => "A hidden file is sending trusted websites somewhere else. Ask someone you trust to check it.",
        "persistence.wmi_subscriptions" => "Something is set to run quietly in the background. Ask someone you trust to look at it.",
        "services.unquoted_paths" => "A background program has a risky setup. Run a virus scan from this page, then ask someone you trust to look at it.",
        "remote.rdp" => "Remote access lets someone sign in to this computer from elsewhere. Turn it off in Settings if you don't use it.",
        "smb.v1" => "An old way of sharing files is still on. Turn it off in Windows Features unless an old device needs it.",
        "accounts.stale_enabled" => "Some old accounts are still switched on. Remove the ones nobody uses.",
        "smb.shares_exposed" => "Some folders are shared with everyone on your network. Stop sharing what you don't need.",
        "firewall.user_dir_inbound_allow" => "Apps in your Downloads or Desktop folders are allowed through the firewall. Remove ones you don't know.",
        "accounts.daily_admin" => "You use an administrator account every day. Make a normal account for daily use.",
        "accounts.hello_configured" => "No PIN or Windows Hello is set up. Add one in Sign-in options.",
        "accounts.find_my_device" => "Find my device is off. Turn it on in Settings so you can find a lost laptop.",
        "vbs.memory_integrity" => "Core system protection (Memory integrity) is off. Protection shows whether this computer can turn it on safely.",
        "vbs.kernel_stack_protection" => "An extra shield for the core of Windows is off. Protection shows whether this computer can turn it on safely.",
        "net.dns_encryption" => "Your internet lookups aren't private. Turn on encrypted lookups in your network settings.",
        "net.wifi_security" => "Your Wi-Fi has weak or no protection. Switch to the newest security option on your router.",
        "persistence.run_and_tasks" => "Open Task Manager, Startup apps, and switch off ones you don't know.",
        "clickfix.run_history" => "Something typed into the Run box looks like a fake check page trick. Run a full virus scan and change your passwords from another device.",
        "browser.permissions" => "Some browser add-ons can read every site you visit. Remove the ones you don't use in your browser's menu.",
        "winre.enabled" => "Recovery tools are off. They help if Windows stops starting. Ask someone you trust to turn them back on.",
        _ => return None,
    })
}

/// What the startup security tip says while the renewal is offered, started or held back.
pub fn rule_renewal_advice(renewal: secblitz::diagnostics::Renewal) -> Option<&'static str> {
    use secblitz::diagnostics::{Blocker, Renewal};
    Some(match renewal {
        Renewal::Offer { .. } => "Your computer's startup security certificates need renewing. Secblitz can start this for you.",
        Renewal::Started => "Renewal started. It finishes after you restart your computer. You can keep working.",
        Renewal::Blocked(Blocker::MakerUpdate) => "Your computer maker needs to update your computer first. Check their website for a firmware update.",
        Renewal::Blocked(Blocker::TaskOff) => "Windows can't renew your startup security because its update job is switched off. Install all Windows updates, then check again.",
        Renewal::Blocked(Blocker::OtherSystem) => "Your computer also starts another system, such as Linux. Renewing could stop it from starting, so Secblitz leaves this to you. Check that system's website first.",
        Renewal::Blocked(Blocker::NotChecked) | Renewal::NotApplicable | Renewal::Done | Renewal::VirtualPc | Renewal::Unknown => return None,
    })
}

pub fn rule_open(rule_id: &str) -> Option<secblitz::actions::Action> {
    use secblitz::actions::Action;
    if let Some(g) = crate::guide::guide(rule_id) {
        return Some(g.page.action());
    }
    match rule_id {
        "os.feature_release_support" | "boot.secure_boot_certs" | "update.paused" => {
            Some(Action::OpenWindowsUpdate)
        }
        "defender.tamper_protection" => Some(Action::OpenTamperProtection),
        "defender.threats" | "defender.scan_age" => Some(Action::OpenProtectionHistory),
        "defender.exclusions_risky" => Some(Action::OpenWindowsSecurity),
        id if id.starts_with("smartscreen.") => Some(Action::OpenAppBrowserControl),
        "ps.v2_engine" => Some(Action::OpenOptionalFeatures),
        "accounts.stale_enabled" => Some(Action::OpenAccounts),
        "accounts.hello_configured" => Some(Action::OpenSignInSettings),
        "firewall.user_dir_inbound_allow" => Some(Action::OpenFirewall),
        _ => None,
    }
}

pub fn rule_fix(rule_id: &str) -> Option<&'static str> {
    let id = match rule_id {
        "remote.rdp" => "remote_desktop.disabled",
        "smb.v1" => "smb1.disabled",
        "winre.enabled" => "recovery.winre_enabled",
        "browser.permissions" => "browser.extensions_off",
        other => other,
    };
    secblitz::hardening::spec(id).map(|spec| spec.id)
}

pub fn rule_fix_advice(rule_id: &str) -> &'static str {
    match rule_id {
        "remote.rdp" => "Remote access is on. If you don't use it, Secblitz can turn it off for you.",
        "smb.v1" => "An old way of sharing files is still on. Secblitz can turn it off for you, unless an old device needs it.",
        "services.unquoted_paths" => "A background program has a risky setup. We can fix this for you.",
        "firewall.user_dir_inbound_allow" => "Apps in your Downloads or Desktop folders are allowed through the firewall. We can fix this for you.",
        "net.hosts_file" => "A hidden file is sending trusted websites somewhere else. We can fix this for you.",
        "persistence.run_and_tasks" => "A risky program starts by itself with Windows. We can switch it off for you.",
        "accounts.stale_enabled" => "Some old accounts are still switched on. Secblitz can switch them off, and you can undo it.",
        "smb.shares_exposed" => "Some folders are shared with everyone on your network. Secblitz can limit them, and you can undo it.",
        "smartscreen.browser_policy" => "A setting has switched off your browser's warnings about dangerous sites. Secblitz can remove it, and you can undo it.",
        "winre.enabled" => "Recovery tools are off. Secblitz can turn them back on for you, and you can undo it.",
        "browser.permissions" => "Some browser add-ons can read every site you visit. Secblitz can turn off the ones you pick, and you can undo it.",
        _ => "Secblitz can fix this for you, and you can undo it. Look it over first.",
    }
}

pub fn rule_restart(rule_id: &str) -> bool {
    rule_id == "update.reboot_overdue"
}

pub fn rule_scan(rule_id: &str) -> bool {
    matches!(rule_id, "defender.scan_age" | "clickfix.run_history")
}

pub fn rule_remove_threats(rule_id: &str) -> bool {
    rule_id == "defender.threats"
}

/// The plain sentence for a renewal that was refused or has just started.
pub fn renewal_result_text(outcome: secblitz::actions::RenewalOutcome) -> &'static str {
    use secblitz::actions::{RenewalOutcome, RenewalRefusal};
    match outcome {
        RenewalOutcome::Started { confirmed: true } => "Renewal started. It finishes after you restart your computer. You can keep working.",
        RenewalOutcome::Started { confirmed: false } => "Windows has been asked to start the renewal. It finishes after you restart your computer. You can keep working.",
        RenewalOutcome::Refused(RenewalRefusal::AlreadyStarted) => "The renewal has already started. It finishes after you restart your computer.",
        RenewalOutcome::Refused(RenewalRefusal::AlreadyUpdated) => "Your startup security is already up to date.",
        RenewalOutcome::Refused(RenewalRefusal::MakerBlocked) => "Your computer maker needs to update your computer first. Check their website for a firmware update.",
        RenewalOutcome::Refused(RenewalRefusal::OtherSystem) => "Your computer also starts another system, so Secblitz didn't change anything. Check that system's website first.",
        RenewalOutcome::Refused(RenewalRefusal::VirtualMachine) => "This is a virtual computer, so Secblitz didn't change anything.",
        RenewalOutcome::Refused(RenewalRefusal::TaskMissing | RenewalRefusal::TaskDisabled) => "Windows can't renew your startup security because its update job is switched off. Install all Windows updates, then try again.",
        RenewalOutcome::Refused(_) => "We couldn't start the renewal, and nothing was changed. Install all Windows updates, then try again.",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatsResult {
    Nothing,
    Removed,
    Partly,
    Stuck,
}

pub fn threats_result(r: &secblitz::actions::ThreatRemoval) -> ThreatsResult {
    match (r.found, r.removed, r.left) {
        (0, _, 0) => ThreatsResult::Nothing,
        (_, removed, 0) if removed > 0 => ThreatsResult::Removed,
        (_, removed, _) if removed > 0 => ThreatsResult::Partly,
        _ => ThreatsResult::Stuck,
    }
}
