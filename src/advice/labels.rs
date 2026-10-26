//! Plain names and next steps for each check.
use super::NextStep;

pub fn control_label(id: &str) -> &'static str {
    match id {
        "readiness" => "Device check",
        "defender.realtime" => "Live virus protection",
        "defender.behavior" => "Suspicious app detection",
        "defender.ioav" => "Downloaded file checks",
        "defender.archive" => "Compressed file checks",
        "firewall.domain.enabled" => "Work network firewall",
        "firewall.private.enabled" => "Home network firewall",
        "firewall.public.enabled" => "Public network firewall",
        "firewall.domain.inbound" => "Work network incoming connections",
        "firewall.private.inbound" => "Home network incoming connections",
        "firewall.public.inbound" => "Public network incoming connections",
        "uac.enabled" => "Permission prompts",
        "uac.consent" => "Administrator approval",
        "installer.always_install_elevated" => "App installation permissions",
        "lsa.restrict_anonymous_sam" => "Account name privacy",
        "lsa.limit_blank_password_use" => "Remote sign-in safeguards",
        "wdigest.use_logon_credential" => "Sign-in secret protection",
        "permissions.service.bits" => "Update download protection",
        "permissions.service.wuauserv" => "Windows Update protection",
        "defender.cloud_protection" => "Cloud threat lookups",
        "defender.pua" => "Junk app blocking",
        "defender.script_nis" => "Script and network traffic checks",
        "defender.asr.standard" => "Defender app and script protections",
        "defender.asr.web_script_email" => "Risky script and attachment warnings",
        "lsa.run_as_ppl" => "Sign-in process shield",
        "net.public_sharing_exposure" => "Hide your computer on public Wi-Fi",
        "printer.point_and_print" => "Printer driver safety",
        "net.llmnr" => "Name-lookup reply blocking",
        "accounts.lockout_policy" => "Lock after wrong passwords",
        "autorun.disabled" => "USB stick auto-start",
        "clickfix.run_box" => "Run box",
        "wifi.risky_profiles" => "Wi-Fi networks that join by themselves",
        "lsa.restrict_anonymous" => "Account and folder list privacy",
        "remote_assistance.disabled" => "Remote Assistance invitations",
        "wsh.disabled" => "Old script files",
        "update.auto_policy_disabled" => "Automatic updates switched off",
        "ntlm.lm_compat_level" => "Old sign-in methods",
        "accounts.builtin_administrator" => "Built-in Administrator account",
        "privacy.activity_history" => "Activity history",
        "privacy.advertising_id" => "Ad tracking ID",
        "defender.asr.office" => "Protections for Office files",
        "defender.asr.ransomware_usb" => "Ransomware and USB shields",
        "defender.network_protection" => "Harmful website blocking",
        "defender.cfa_watch" => "Watch for apps changing your files",
        "defender.cfa_block" => "Protect your files from ransomware",
        "defender.cfa_allowed_apps" => "Apps allowed to change your files",
        "defender.cloud_block_level" => "Stricter cloud blocking",
        "net.stack_hardening" => "Network traffic hardening",
        "net.netbios" => "Old name service (NetBIOS)",
        "net.mdns" => "Local name lookups (mDNS)",
        "net.wpad" => "Automatic proxy search",
        "firewall.outbound_smb_internet" => "File sharing to the internet",
        "tls.legacy_protocols" => "Old secure-connection versions",
        "ntlm.extras" => "Stricter old sign-in settings",
        "driver.vulnerable_blocklist" => "Unsafe driver blocking",
        "system.exploit_mitigations" => "Built-in memory protections",
        "ps.v2_engine" => "Old scripting tool",
        "printer.spooler_remote" => "Print sharing on this computer",
        "services.legacy_remote" => "Old remote tools that start by themselves",
        "session.lock_on_wake" => "Password after sleep",
        "update.store_autoupdate_policy" => "Store app updates",
        "update.paused" => "Paused Windows updates",
        "smartscreen.apps" => "Unknown download warnings",
        "privacy.recall" => "Recall screenshots",
        "privacy.diagnostic_data_level" => "Diagnostic data",
        "privacy.delivery_optimization" => "Update sharing",
        "privacy.clipboard_sync" => "Clipboard sync",
        "privacy.online_speech" => "Online speech recognition",
        "privacy.typing_inking" => "Sending typing and handwriting",
        "privacy.lock_screen_notifications" => "Messages on the lock screen",
        "privacy.signin_email" => "Email address on the sign-in screen",
        "privacy.wifi_random_address" => "Random Wi-Fi address",
        "ai.click_to_do" => "Click to Do",
        "ai.paint" => "AI tools in Paint",
        "ai.notepad" => "AI tools in Notepad",
        "debloat.widgets_policy" => "Widgets button and news board",
        "debloat.device_companion_apps" => "Extra apps for new devices",
        "defender.exclusions_risky" => "Antivirus skip list",
        "accounts.autologon" => "Automatic sign-in",
        "remote_desktop.disabled" => "Remote access",
        "smb1.disabled" => "Older file sharing",
        "vbs.memory_integrity" => "Core system protection",
        "vbs.kernel_stack_protection" => "Extra core protection",
        "services.unquoted_paths" => "Risky background program setup",
        "firewall.user_dir_inbound_allow" => "Firewall allowances for downloads",
        "net.hosts_file" => "Redirected trusted websites",
        "persistence.run_and_tasks" => "Risky start-up programs",
        "accounts.stale_enabled" => "Old accounts still switched on",
        "smb.shares_exposed" => "Who can open your shared folders",
        "smartscreen.browser_policy" => "Browser warnings about dangerous sites",
        "recovery.winre_enabled" => "Windows recovery tools",
        "browser.shopping_ai" => "Shopping and AI sidebars in your browsers",
        "browser.data_collection" => "Usage data your browsers send",
        "browser.safety_mode" => "Stronger protection in your browsers",
        "browser.dns_bypass" => "Browsers use Web protection",
        "browser.extensions_off" => "Turn off a browser add-on",
        "findings" => "Additional protection checks",
        _ => super::linux::label(id).unwrap_or("Protection check"),
    }
}

pub(super) fn control_help(id: &str) -> (&'static str, NextStep) {
    use NextStep::*;
    match id {
        "defender.realtime" | "defender.behavior" | "defender.ioav" | "defender.archive" => (
            "Open Windows Security and make sure virus protection is on.",
            OpenWindowsSecurity,
        ),
        "firewall.domain.enabled"
        | "firewall.private.enabled"
        | "firewall.public.enabled"
        | "firewall.domain.inbound"
        | "firewall.private.inbound"
        | "firewall.public.inbound" => (
            "Open Windows Security and make sure the firewall is on.",
            OpenWindowsSecurity,
        ),
        "uac.enabled" | "uac.consent" => (
            "We can't change this one safely for you. If you're not sure, leave it as it is.",
            ReviewWithAdministrator,
        ),
        "installer.always_install_elevated" => (
            "We can't change this one safely for you. If you're not sure, leave it as it is.",
            ReviewWithAdministrator,
        ),
        "lsa.restrict_anonymous_sam" => (
            "We can't change this one safely for you. If you're not sure, leave it as it is.",
            ReviewWithAdministrator,
        ),
        "lsa.limit_blank_password_use" => (
            "Make sure every account on this computer has a password.",
            OpenAccounts,
        ),
        "wdigest.use_logon_credential" => (
            "We can't change this one safely for you. If you're not sure, leave it as it is.",
            ReviewWithAdministrator,
        ),
        "permissions.service.bits" | "permissions.service.wuauserv" => (
            "We can't change this one safely for you. If you're not sure, leave it as it is.",
            ReviewWithAdministrator,
        ),
        "defender.cloud_protection" | "defender.pua" | "defender.script_nis" => (
            "Open Windows Security and make sure virus protection is fully turned on.",
            OpenWindowsSecurity,
        ),
        "accounts.builtin_administrator" => (
            "Check who can sign in to this computer and switch off accounts nobody uses.",
            OpenAccounts,
        ),
        "update.auto_policy_disabled" => (
            "Open Windows Update and make sure updates are allowed to install.",
            OpenWindowsUpdate,
        ),
        "update.paused" => ("Open Windows Update and resume updates.", OpenWindowsUpdate),
        "smartscreen.apps" | "defender.exclusions_risky" => (
            "Open Windows Security and check the app and file protection settings.",
            OpenWindowsSecurity,
        ),
        "vbs.memory_integrity" | "vbs.kernel_stack_protection" => (
            "Open Windows Security and look at the extra protection for the core of Windows. Some older devices don't work with it.",
            OpenWindowsSecurity,
        ),
        "ps.v2_engine" => (
            "Open Windows Features and untick the old scripting tool.",
            ReviewWindowsFeatures,
        ),
        "session.lock_on_wake" => (
            "Open sign-in settings and choose to ask for your password after sleep.",
            OpenAccounts,
        ),
        "defender.asr.standard"
        | "defender.asr.web_script_email"
        | "lsa.run_as_ppl"
        | "net.public_sharing_exposure"
        | "printer.point_and_print"
        | "net.llmnr"
        | "accounts.lockout_policy"
        | "autorun.disabled"
        | "clickfix.run_box"
        | "wifi.risky_profiles"
        | "lsa.restrict_anonymous"
        | "remote_assistance.disabled"
        | "wsh.disabled"
        | "ntlm.lm_compat_level"
        | "privacy.activity_history"
        | "privacy.advertising_id"
        | "defender.asr.office"
        | "defender.asr.ransomware_usb"
        | "defender.network_protection"
        | "defender.cloud_block_level"
        | "defender.cfa_watch"
        | "defender.cfa_block"
        | "defender.cfa_allowed_apps"
        | "net.stack_hardening"
        | "net.netbios"
        | "net.mdns"
        | "net.wpad"
        | "firewall.outbound_smb_internet"
        | "tls.legacy_protocols"
        | "ntlm.extras"
        | "driver.vulnerable_blocklist"
        | "system.exploit_mitigations"
        | "printer.spooler_remote"
        | "services.legacy_remote"
        | "update.store_autoupdate_policy"
        | "accounts.autologon"
        | "remote_desktop.disabled"
        | "smb1.disabled"
        | "privacy.recall"
        | "privacy.diagnostic_data_level"
        | "privacy.delivery_optimization"
        | "privacy.clipboard_sync"
        | "privacy.online_speech"
        | "privacy.typing_inking"
        | "privacy.lock_screen_notifications"
        | "privacy.signin_email"
        | "privacy.wifi_random_address"
        | "ai.click_to_do"
        | "ai.paint"
        | "ai.notepad"
        | "debloat.widgets_policy"
        | "debloat.device_companion_apps"
        | "services.unquoted_paths"
        | "firewall.user_dir_inbound_allow"
        | "net.hosts_file"
        | "persistence.run_and_tasks"
        | "accounts.stale_enabled"
        | "smb.shares_exposed"
        | "smartscreen.browser_policy"
        | "browser.shopping_ai"
        | "browser.data_collection"
        | "browser.safety_mode"
        | "browser.dns_bypass"
        | "browser.extensions_off"
        | "recovery.winre_enabled" => (
            "We can't change this one safely for you. If you're not sure, leave it as it is.",
            ReviewWithAdministrator,
        ),
        _ => (
            "Check again in a moment. Nothing has been changed.",
            CheckAgain,
        ),
    }
}
