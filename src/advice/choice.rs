//! Checks that ask first, and what choosing them changes.
pub fn is_choice_check_id(id: &str) -> bool {
    crate::hardening::is_ask_check_id(id) || crate::linux::catalog::spec(id).is_some_and(|s| s.ask)
}

pub fn choice_consequence(id: &str) -> &'static str {
    match id {
        "defender.cloud_protection" => {
            "Windows Defender will send details about suspicious files to Microsoft to catch new threats faster."
        }
        "defender.asr.web_script_email" => {
            "Windows will ask before running scripts or email attachments that look risky, and you can allow them."
        }
        "lsa.run_as_ppl" => {
            "Sign-in add-ons from other companies may stop working. Needs a restart."
        }
        "autorun.disabled" => {
            "Plugging in a USB stick or disc will no longer pop up a menu. Open it from File Explorer instead. Needs a restart."
        }
        "clickfix.run_box" => {
            "Win+R and Run in the Start menu stop working for everyone on this computer."
        }
        "wifi.risky_profiles" => {
            "Saved risky Wi-Fi networks stop joining by themselves. You can still connect by hand."
        }
        "lsa.restrict_anonymous" => {
            "Very old devices may stop showing your shared folders. Needs a restart."
        }
        "remote_assistance.disabled" => {
            "Nobody can invite a helper to control this computer this way. Quick Assist still works."
        }
        "wsh.disabled" => "Old .vbs and .js script files will stop running when you open them.",
        "update.auto_policy_disabled" => {
            "Windows will go back to installing security updates by itself."
        }
        "ntlm.lm_compat_level" => {
            "Very old network drives or scanners may stop signing in. Needs a restart."
        }
        "accounts.builtin_administrator" => {
            "Switches off the built-in Administrator account. Your own account keeps working."
        }
        "privacy.activity_history" => "Windows stops keeping a list of what you did on this computer.",
        "privacy.advertising_id" => "Apps will show less relevant ads. Nothing else changes.",
        "defender.asr.office" => {
            "Office files that try to start other programs are blocked. Macro-heavy files may stop working."
        }
        "defender.asr.ransomware_usb" => {
            "Windows asks before unknown programs or USB apps run, and you can allow them."
        }
        "defender.network_protection" => {
            "Programs are blocked from known harmful sites. Some VPNs or games may be blocked by mistake."
        }
        "defender.cloud_block_level" => {
            "Windows is stricter with unknown files and may pause a download for up to 20 seconds."
        }
        "defender.cfa_watch" => {
            "Windows quietly notes which apps change your files. Nothing is blocked, and you can undo this."
        }
        "defender.cfa_block" => {
            "Apps Windows doesn't trust can no longer change your files. One you use may need allowing. You can undo this."
        }
        "defender.cfa_allowed_apps" => {
            "These apps will be allowed to change your files in protected folders. Undo takes them off the list."
        }
        "net.stack_hardening" => "Nothing you will notice day to day. Needs a restart.",
        "net.netbios" => "Very old network devices may stop being found by name.",
        "net.mdns" => {
            "Casting, AirPrint and some smart-home devices may stop showing up. Needs a restart."
        }
        "net.wpad" => {
            "Networks that set up their proxy automatically may stop working. Needs a restart."
        }
        "firewall.outbound_smb_internet" => {
            "Cloud file shares reached over the internet may stop connecting. Home sharing still works."
        }
        "tls.legacy_protocols" => {
            "Very old apps or devices may fail to connect securely. Needs a restart."
        }
        "ntlm.extras" => "Very old network drives or scanners may stop connecting. Needs a restart.",
        "driver.vulnerable_blocklist" => {
            "A very old hardware tool may stop working if its driver is on the list. Needs a restart."
        }
        "ps.v2_engine" => {
            "Very old scripts that need the old version stop working. Removing it can take a minute."
        }
        "printer.spooler_remote" => {
            "Other computers can no longer print through this computer. Printing restarts for a moment."
        }
        "services.legacy_remote" => {
            "Remote tools that use these services stop working until you turn them back on."
        }
        "session.lock_on_wake" => "You will type your password each time the computer wakes from sleep.",
        "update.store_autoupdate_policy" => "Store apps will go back to updating by themselves.",
        "update.paused" => "Windows will start downloading updates again and may ask you to restart.",
        "smartscreen.apps" => {
            "Windows will warn you before you run unknown programs. You can still choose to run them."
        }
        "privacy.recall" => "Windows stops saving screen pictures and deletes the ones it kept.",
        "privacy.diagnostic_data_level" => {
            "Windows sends only the basic diagnostic data it needs. Nothing stops working."
        }
        "privacy.delivery_optimization" => {
            "Updates still come from Microsoft. This computer just stops sharing them with others."
        }
        "privacy.online_speech" => {
            "Voice typing and dictation stop working. Nothing else changes."
        }
        "privacy.typing_inking" => {
            "Windows stops sending what you type and write. Suggestions may improve more slowly."
        }
        "privacy.lock_screen_notifications" => {
            "Messages no longer show on the lock screen. You still see them after you sign in."
        }
        "privacy.wifi_random_address" => {
            "Wi-Fi networks stop recognising this computer. One for known devices only may ask you to approve it again."
        }
        "privacy.signin_email" => {
            "The sign-in screen no longer shows your email address."
        }
        "privacy.clipboard_sync" => {
            "What you copy stays on this computer and no longer appears on your other devices."
        }
        "ai.click_to_do" => "Click to Do stops offering actions on what is on your screen.",
        "ai.paint" => "Paint's AI drawing tools turn off. Normal drawing works as before.",
        "ai.notepad" => "Notepad's AI writing tools turn off. Normal typing and saving work as before.",
        "debloat.widgets_policy" => "The Widgets button and news board go away for everyone on this computer.",
        "debloat.device_companion_apps" => {
            "Device pictures and details stop downloading. Your devices still work as before."
        }
        "defender.exclusions_risky" => {
            "Skipped places are scanned again, so some games or work tools may scan slower."
        }
        "accounts.autologon" => {
            "Your computer will ask for your password or PIN at startup. Make sure you know it."
        }
        "remote_desktop.disabled" => {
            "Other devices can no longer connect to this computer with Remote Desktop. You can turn it back on."
        }
        "smb1.disabled" => {
            "Very old network drives or printers that only use the old sharing may stop working. Needs a restart."
        }
        "vbs.memory_integrity" => {
            "Some very old devices may stop working. Needs a restart. You can undo this in History."
        }
        "vbs.kernel_stack_protection" => {
            "Some older drivers may not load. Needs a restart. You can undo this in History."
        }
        "services.unquoted_paths" => {
            "Only the way the program's location is written changes. The program keeps running as before."
        }
        "firewall.user_dir_inbound_allow" => {
            "Programs in your Downloads or Desktop folders lose their firewall allowance and may ask again."
        }
        "net.hosts_file" => {
            "Redirected websites go to their real address again. Your other entries stay as they are."
        }
        "persistence.run_and_tasks" => {
            "Risky programs stop starting with Windows. Nothing is deleted, and you can undo this."
        }
        "accounts.stale_enabled" => {
            "Old accounts are switched off, not deleted. Undo switches them back on."
        }
        "smb.shares_exposed" => {
            "Only the people listed on these folders can open them from other devices. Others may lose access."
        }
        "smartscreen.browser_policy" => {
            "Edge and Chrome will warn you about dangerous websites again."
        }
        "browser.shopping_ai" => {
            "Shopping and AI panels go away. Browsers will say they are managed by your organization, which only means a setting was made."
        }
        "browser.data_collection" => {
            "Browsers stop sending usage data. They will say they are managed by your organization, which only means a setting was made."
        }
        "browser.safety_mode" => {
            "Stronger protection turns on. Browsers will say they are managed by your organization, which only means a setting was made."
        }
        "browser.extensions_off" => {
            "Picked add-ons turn off for all users. Browsers say they are managed by your organization, which only means a setting was made."
        }
        "browser.dns_bypass" => {
            "Keep Web protection on. Browsers will say they are managed by your organization, which only means a setting was made."
        }
        _ => super::linux::consequence(id).unwrap_or(""),
    }
}
