//! What each check or finding protects you from.
pub fn control_impact(id: &str) -> &'static str {
    match id {
        "readiness" => "A full drive stopping fixes and updates from completing",
        "defender.realtime" => "Malware running as soon as it lands on your computer",
        "defender.behavior" => "Apps that behave like malware even when not yet known",
        "defender.ioav" => "Harmful files downloaded from the web or email attachments",
        "defender.archive" => "Malware hidden inside zip and other compressed files",
        "firewall.domain.enabled" => "Other devices on your work network reaching your computer",
        "firewall.private.enabled" => "Other devices on your home network reaching your computer",
        "firewall.public.enabled" => {
            "Other devices at public places like cafes or airports reaching your computer"
        }
        "firewall.domain.inbound" => "Uninvited incoming connections on your work network",
        "firewall.private.inbound" => "Uninvited incoming connections on your home network",
        "firewall.public.inbound" => {
            "Uninvited incoming connections on public networks like cafes or airports"
        }
        "uac.enabled" => "Apps silently making system-wide changes without asking you",
        "uac.consent" => "Apps making big changes without asking for approval",
        "installer.always_install_elevated" => {
            "Any app installer quietly getting full control of your computer"
        }
        "lsa.restrict_anonymous_sam" => "Other devices on the network seeing your account names",
        "lsa.limit_blank_password_use" => {
            "Someone signing in over the network to an account with no password"
        }
        "wdigest.use_logon_credential" => "Harmful programs reading your Windows password",
        "permissions.service.bits" | "permissions.service.wuauserv" => {
            "Altered Windows updates reaching your computer"
        }
        "defender.cloud_protection" => "New threats that only cloud checks can spot",
        "defender.pua" => "Junk and adware bundled with free downloads",
        "defender.script_nis" => {
            "Harmful scripts and harmful network traffic reaching your computer"
        }
        "defender.asr.standard" => {
            "Harmful programs reading your sign-in details or hiding inside Windows"
        }
        "defender.asr.web_script_email" => {
            "Harmful scripts and email attachments starting programs"
        }
        "lsa.run_as_ppl" => "Harmful programs reading your sign-in details",
        "net.public_sharing_exposure" => "Other devices on public Wi-Fi seeing your shared files",
        "printer.point_and_print" => {
            "Harmful printer drivers getting full control of your computer"
        }
        "net.llmnr" => "Someone on your network answering name lookups with wrong replies",
        "accounts.lockout_policy" => "Someone trying one password after another on your computer",
        "autorun.disabled" => "Harmful programs starting from a USB stick or disc",
        "clickfix.run_box" => "A fake web page tricking you into running a harmful command",
        "wifi.risky_profiles" => "Unknown Wi-Fi hotspots connecting your computer without asking",
        "lsa.restrict_anonymous" => {
            "Other devices on the network seeing your accounts and shared folders"
        }
        "remote_assistance.disabled" => {
            "Someone controlling your computer through a help invitation"
        }
        "wsh.disabled" => "Harmful script files starting with a double-click",
        "update.auto_policy_disabled" => "Security fixes never being installed",
        "ntlm.lm_compat_level" => "Old, weak sign-in methods used on your network",
        "accounts.builtin_administrator" => "An unused account with full power staying switched on",
        "privacy.activity_history" => {
            "A record of what you did on this computer being kept and shared"
        }
        "privacy.advertising_id" => "Apps tracking you across other apps for ads",
        "defender.asr.office" => "Harmful Office files starting programs",
        "defender.asr.ransomware_usb" => {
            "Ransomware or a harmful USB stick locking or copying your files"
        }
        "defender.network_protection" => {
            "Programs connecting to known harmful websites and servers"
        }
        "defender.cfa_watch" => "Not knowing which apps change your personal files",
        "defender.cfa_block" => "Ransomware locking your photos and documents",
        "defender.cfa_allowed_apps" => "A trusted app being stopped from saving your work",
        "defender.cloud_block_level" => {
            "Brand-new harmful files slipping through before anyone has judged them"
        }
        "net.stack_hardening" => "Someone on your network redirecting your computer's traffic",
        "net.netbios" => "Someone on your network learning your computer's name and misleading it",
        "net.mdns" => "Devices on your network answering name lookups with wrong replies",
        "net.wpad" => "Someone on your network pointing your computer at an unwanted proxy",
        "firewall.outbound_smb_internet" => {
            "Your computer sending sign-in details to a file server on the internet"
        }
        "tls.legacy_protocols" => "Old, breakable secure connections being forced on your computer",
        "ntlm.extras" => "Weak stored copies of your password being misused",
        "driver.vulnerable_blocklist" => "A flawed driver being used to switch off your security",
        "system.exploit_mitigations" => "A program bug causing serious trouble on your computer",
        "ps.v2_engine" => "Harmful scripts running through an old version of a Windows tool",
        "printer.spooler_remote" => {
            "Other computers on your network sending requests to your printing service"
        }
        "services.legacy_remote" => {
            "Someone reaching your computer through forgotten remote-access tools"
        }
        "session.lock_on_wake" => "Anyone nearby opening your computer while you are away",
        "update.store_autoupdate_policy" => {
            "Store apps staying out of date and open to known flaws"
        }
        "update.paused" => "Security fixes waiting while your computer stays without them",
        "smartscreen.apps" => {
            "Unrecognized installers and harmful downloads starting with one click"
        }
        "privacy.recall" => {
            "Pictures of your screen, passwords included, being kept on this computer"
        }
        "privacy.diagnostic_data_level" => {
            "More details about how you use your computer leaving it than needed"
        }
        "privacy.delivery_optimization" => {
            "Your computer sending files to unknown computers over your connection"
        }
        "privacy.clipboard_sync" => "What you copy showing up on your other devices",
        "privacy.online_speech" => "Your voice being sent to an online service",
        "privacy.typing_inking" => "Samples of what you type and write being sent to Microsoft",
        "privacy.lock_screen_notifications" => {
            "Anyone nearby reading your messages on the lock screen"
        }
        "privacy.wifi_random_address" => {
            "Public Wi-Fi networks recognising your computer from one visit to the next"
        }
        "privacy.signin_email" => "Your email address showing on the sign-in screen",
        "ai.click_to_do" => "Windows offering to pass what is on your screen to AI tools",
        "ai.paint" => "Your drawings being sent to online AI tools",
        "ai.notepad" => "What you type in Notepad being sent to online AI tools",
        "debloat.widgets_policy" => {
            "News, ads and stories you did not ask for popping up on your computer"
        }
        "debloat.device_companion_apps" => {
            "Extra apps being suggested when you plug in a new device"
        }
        "defender.exclusions_risky" => "Malware hiding in places your antivirus skips",
        "accounts.autologon" => {
            "Anyone who turns on your computer getting straight into your account"
        }
        "remote_desktop.disabled" => "Someone signing in to your computer from another place",
        "smb1.disabled" => "Old file-sharing flaws that let malware spread between computers",
        "vbs.memory_integrity" => "Harmful drivers getting into the core of Windows",
        "vbs.kernel_stack_protection" => {
            "A driver bug causing serious trouble in the core of Windows"
        }
        "services.unquoted_paths" => "Windows starting the wrong program with full power",
        "firewall.user_dir_inbound_allow" => {
            "A harmful download letting others connect straight to your computer"
        }
        "net.hosts_file" => "Trusted websites quietly sending you to different ones",
        "persistence.run_and_tasks" => {
            "A harmful program starting again every time you turn on your computer"
        }
        "accounts.stale_enabled" => "Forgotten accounts staying switched on",
        "smb.shares_exposed" => {
            "Other people on your network opening or changing your shared files"
        }
        "smartscreen.browser_policy" => "Scam and virus websites opening with no warning",
        "browser.shopping_ai" => {
            "Shopping and AI tools in your browsers seeing the pages you visit"
        }
        "browser.data_collection" => {
            "Your browsers reporting how you use them and what you look at"
        }
        "browser.safety_mode" => "Harmful sites and trackers getting more room in your browsers",
        "browser.extensions_off" => "A harmful add-on watching everything you do on every website",
        "browser.dns_bypass" => {
            "Ads, trackers and dangerous sites slipping past Web protection in your browsers"
        }
        "recovery.winre_enabled" => {
            "Being stuck without a way to repair Windows if it stops starting"
        }
        _ => "",
    }
}

pub fn finding_impact(title: &str) -> &'static str {
    match title {
        "Windows lifecycle" => "Running Windows that no longer gets security fixes",
        "Device encryption" => {
            "Someone who finds your computer reading your files if it is lost or stolen"
        }
        "Secure Boot" => "Hidden malware starting before Windows does",
        "Windows updates" => "Missing security fixes on your computer",
        "Remote Desktop" => "Someone signing in to your computer from another place",
        "SMB1" => "Old file-sharing flaws that let malware spread between computers",
        "SmartScreen" => "Scam websites and unrecognized apps you open by mistake",
        "Memory integrity" | "Memory integrity not running" | "A device may not be working" => {
            "Harmful drivers getting into the core of Windows"
        }
        "Kernel stack protection not running" => {
            "A driver bug causing serious trouble in the core of Windows"
        }
        "Automatic logon" => "Anyone who turns on your computer getting straight into your account",
        _ => "",
    }
}
