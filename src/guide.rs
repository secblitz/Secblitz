//! Plain step-by-step help for what only the person can do in Windows itself. Pure data: pages open only through `Page::request`; all text is translation source keys.
use crate::broker::Request;
use secblitz::actions::Action;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    CoreIsolation,
    Firewall,
    DeviceSecurity,
    WindowsSecurity,
    VirusSettings,
    ProtectionHistory,
    ProtectionHistoryList,
    AppBrowser,
    Encryption,
    BitLocker,
    FindMyDevice,
    SignIn,
    OtherUsers,
    WorkAccounts,
    Recovery,
    RemoteDesktop,
    WindowsUpdate,
    OptionalFeatures,
    Wifi,
    Network,
    Backup,
    Storage,
    InstalledApps,
    Taskbar,
    PrivacySettings,
}

impl Page {
    pub const ALL: [Page; 25] = [
        Page::CoreIsolation,
        Page::Firewall,
        Page::DeviceSecurity,
        Page::WindowsSecurity,
        Page::VirusSettings,
        Page::ProtectionHistory,
        Page::ProtectionHistoryList,
        Page::AppBrowser,
        Page::Encryption,
        Page::BitLocker,
        Page::FindMyDevice,
        Page::SignIn,
        Page::OtherUsers,
        Page::WorkAccounts,
        Page::Recovery,
        Page::RemoteDesktop,
        Page::WindowsUpdate,
        Page::OptionalFeatures,
        Page::Wifi,
        Page::Network,
        Page::Backup,
        Page::Storage,
        Page::InstalledApps,
        Page::Taskbar,
        Page::PrivacySettings,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Page::CoreIsolation => "Core isolation",
            Page::Firewall => "Firewall and network protection",
            Page::DeviceSecurity => "Device security",
            Page::WindowsSecurity => "Windows Security",
            Page::VirusSettings => "Virus and threat protection settings",
            Page::ProtectionHistory => "Virus and threat protection",
            Page::ProtectionHistoryList => "Protection history",
            Page::AppBrowser => "App and browser control",
            Page::Encryption => "Device encryption",
            Page::BitLocker => "BitLocker",
            Page::FindMyDevice => "Find my device",
            Page::SignIn => "Sign-in options",
            Page::OtherUsers => "Other users",
            Page::WorkAccounts => "Access work or school",
            Page::Recovery => "Recovery",
            Page::RemoteDesktop => "Remote Desktop",
            Page::WindowsUpdate => "Windows Update",
            Page::OptionalFeatures => "Optional features",
            Page::Wifi => "Wi-Fi settings",
            Page::Network => "Network and internet",
            Page::Backup => "Windows Backup",
            Page::Storage => "Storage",
            Page::InstalledApps => "Installed apps",
            Page::Taskbar => "Taskbar settings",
            Page::PrivacySettings => "Privacy settings",
        }
    }

    pub fn button(self) -> &'static str {
        match self {
            Page::CoreIsolation => "Open Core isolation",
            Page::Firewall => "Open Firewall protection",
            Page::DeviceSecurity => "Open Device security",
            Page::WindowsSecurity => "Open Windows Security",
            Page::VirusSettings => "Open virus protection settings",
            Page::ProtectionHistory => "Open virus protection",
            Page::ProtectionHistoryList => "Open Protection history",
            Page::AppBrowser => "Open App and browser control",
            Page::Encryption => "Open Device encryption",
            Page::BitLocker => "Open BitLocker",
            Page::FindMyDevice => "Open Find my device",
            Page::SignIn => "Open Sign-in options",
            Page::OtherUsers => "Open Other users",
            Page::WorkAccounts => "Open Access work or school",
            Page::Recovery => "Open Recovery",
            Page::RemoteDesktop => "Open Remote Desktop",
            Page::WindowsUpdate => "Open Windows Update",
            Page::OptionalFeatures => "Open Optional features",
            Page::Wifi => "Open Wi-Fi settings",
            Page::Network => "Open Network and internet",
            Page::Backup => "Open Windows Backup",
            Page::Storage => "Open Storage",
            Page::InstalledApps => "Open Installed apps",
            Page::Taskbar => "Open Taskbar settings",
            Page::PrivacySettings => "Open Privacy settings",
        }
    }

    pub fn action(self) -> Action {
        match self {
            Page::CoreIsolation => Action::OpenCoreIsolation,
            Page::Firewall => Action::OpenFirewall,
            Page::DeviceSecurity => Action::OpenDeviceSecurity,
            Page::WindowsSecurity => Action::OpenWindowsSecurity,
            Page::VirusSettings => Action::OpenTamperProtection,
            Page::ProtectionHistory => Action::OpenProtectionHistory,
            Page::ProtectionHistoryList => Action::OpenProtectionHistoryList,
            Page::AppBrowser => Action::OpenAppBrowserControl,
            Page::Encryption => Action::OpenEncryptionSettings,
            Page::BitLocker => Action::OpenBitLocker,
            Page::FindMyDevice => Action::OpenFindMyDevice,
            Page::SignIn => Action::OpenSignInSettings,
            Page::OtherUsers => Action::OpenAccounts,
            Page::WorkAccounts => Action::OpenWorkAccounts,
            Page::Recovery => Action::OpenRecovery,
            Page::RemoteDesktop => Action::OpenRemoteDesktop,
            Page::WindowsUpdate => Action::OpenWindowsUpdate,
            Page::OptionalFeatures => Action::OpenOptionalFeatures,
            Page::Wifi => Action::OpenWifi,
            Page::Network => Action::OpenNetwork,
            Page::Backup => Action::OpenBackup,
            Page::Storage => Action::OpenStorage,
            Page::InstalledApps => Action::OpenInstalledApps,
            Page::Taskbar => Action::OpenTaskbar,
            Page::PrivacySettings => Action::OpenDesktopPrivacy,
        }
    }

    pub fn request(self) -> Request {
        match self {
            Page::CoreIsolation => Request::OpenCoreIsolation,
            Page::Firewall => Request::OpenFirewall,
            Page::DeviceSecurity => Request::OpenDeviceSecurity,
            Page::WindowsSecurity => Request::OpenWindowsSecurity,
            Page::VirusSettings => Request::OpenTamperProtection,
            Page::ProtectionHistory => Request::OpenProtectionHistory,
            Page::ProtectionHistoryList => Request::OpenProtectionHistoryList,
            Page::AppBrowser => Request::OpenAppBrowserControl,
            Page::Encryption => Request::OpenEncryption,
            Page::BitLocker => Request::OpenBitLocker,
            Page::FindMyDevice => Request::OpenFindMyDevice,
            Page::SignIn => Request::OpenSignIn,
            Page::OtherUsers => Request::OpenAccounts,
            Page::WorkAccounts => Request::OpenWorkAccounts,
            Page::Recovery => Request::OpenRecovery,
            Page::RemoteDesktop => Request::OpenRemoteDesktop,
            Page::WindowsUpdate => Request::OpenWindowsUpdate,
            Page::OptionalFeatures => Request::OpenOptionalFeatures,
            Page::Wifi => Request::OpenWifi,
            Page::Network => Request::OpenNetwork,
            Page::Backup => Request::OpenBackup,
            Page::Storage => Request::OpenStorage,
            Page::InstalledApps => Request::OpenInstalledApps,
            Page::Taskbar => Request::OpenTaskbar,
            Page::PrivacySettings => Request::OpenDesktopPrivacy,
        }
    }

    #[cfg(test)]
    pub fn from_request(request: Request) -> Option<Page> {
        Page::ALL.into_iter().find(|p| p.request() == request)
    }

    pub fn from_action(action: Action) -> Option<Page> {
        Page::ALL.into_iter().find(|p| p.action() == action)
    }

    pub fn for_finding(title: &str) -> Option<Page> {
        Some(match title {
            "Windows Firewall" => Page::Firewall,
            "SmartScreen" => Page::AppBrowser,
            "Management and mutation eligibility" => Page::WorkAccounts,
            _ => return None,
        })
    }

    pub fn for_step(step: secblitz::advice::NextStep) -> Option<Page> {
        use secblitz::advice::NextStep as S;
        Some(match step {
            S::OpenWindowsSecurity => Page::WindowsSecurity,
            S::OpenWindowsUpdate => Page::WindowsUpdate,
            S::OpenEncryption => Page::Encryption,
            S::OpenAccounts => Page::SignIn,
            S::OpenRemoteDesktop => Page::RemoteDesktop,
            S::ReviewWindowsFeatures => Page::OptionalFeatures,
            S::ReviewFirmware => Page::Recovery,
            _ => return None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Guide {
    pub page: Page,
    pub alt: Option<Page>,
    pub steps: &'static [&'static str],
}

const fn g(page: Page, steps: &'static [&'static str]) -> Guide {
    Guide {
        page,
        alt: None,
        steps,
    }
}

static MEMORY_INTEGRITY: Guide = g(
    Page::CoreIsolation,
    &[
        "Find Memory integrity under Core isolation and turn it on.",
        "If Windows names a driver that blocks it, update that driver or its app, then try again.",
        "Restart your computer when Windows asks.",
    ],
);
static KERNEL_STACK: Guide = g(
    Page::CoreIsolation,
    &[
        "Turn on Memory integrity first. The next option appears below it.",
        "Turn on Kernel-mode Hardware-enforced Stack Protection.",
        "If you don't see it, your computer doesn't support it and nothing is wrong.",
        "Restart your computer when Windows asks.",
    ],
);
static ENCRYPTION: Guide = Guide {
    page: Page::Encryption,
    alt: Some(Page::BitLocker),
    steps: &[
        "Save your recovery key somewhere safe first. Microsoft accounts keep it at account.microsoft.com/devices/recoverykey.",
        "Turn on Device encryption.",
        "No Device encryption page? Use Open BitLocker instead, and choose Turn on BitLocker.",
    ],
};
/// Windows Home has no BitLocker settings, so a PC without Device encryption has no other way.
static ENCRYPTION_HOME: Guide = g(
    Page::Encryption,
    &[
        "Save your recovery key somewhere safe first. Microsoft accounts keep it at account.microsoft.com/devices/recoverykey.",
        "Turn on Device encryption.",
        "No Device encryption page? Then this computer can't encrypt its drive with Windows Home.",
    ],
);
static SECURE_BOOT: Guide = g(
    Page::Recovery,
    &[
        "Encrypted computer? Find your recovery key first at aka.ms/myrecoverykey, as Windows may ask for it after this.",
        "Save your work, then select Restart now next to Advanced startup.",
        "Choose Troubleshoot, Advanced options, UEFI Firmware Settings, then Restart. No such option? Stop here.",
        "Turn on Secure Boot, often under Boot or Security. Menus differ by computer maker. Save and exit.",
    ],
);
static AUTOLOGON: Guide = g(
    Page::SignIn,
    &[
        "Press the Windows key and R together, type netplwiz and press Enter.",
        "Tick Users must enter a user name and password to use this computer, then select OK.",
        "No such box? Open Sign-in options, turn off the option that only allows Windows Hello sign-in, then try again.",
    ],
);
static REMOTE_DESKTOP: Guide = g(
    Page::RemoteDesktop,
    &[
        "Using this computer from another device right now? Stop here. Turning this off ends that connection.",
        "Turn off Remote Desktop.",
        "Select Confirm if Windows asks.",
    ],
);
static SMB1: Guide = g(
    Page::OptionalFeatures,
    &[
        "If an old printer or shared drive needs it, leave it on.",
        "Scroll down and select More Windows features.",
        "Untick SMB 1.0/CIFS File Sharing Support, then select OK.",
        "Restart your computer when Windows asks.",
    ],
);
static LIFECYCLE: Guide = g(
    Page::WindowsUpdate,
    &[
        "Select Check for updates.",
        "If a newer version of Windows is offered, choose Download and install.",
        "If none is offered, look on this page for Extended Security Updates (Enroll now), or plan for a computer that runs Windows 11.",
    ],
);
static SECURE_BOOT_CERTS: Guide = g(
    Page::WindowsUpdate,
    &[
        "Select Check for updates and install everything offered.",
        "Restart when Windows asks. You may need to do this more than once.",
        "Then look for a startup (BIOS) update on your computer maker's website.",
        "Your computer maker may need to release one before the renewal can finish.",
    ],
);
static RUN_HISTORY: Guide = g(
    Page::WindowsSecurity,
    &[
        "Run a full scan first. Choose Scan options, then Full scan, then Scan now.",
        "Then use another phone or computer to change your passwords. Start with your email, then your bank.",
        "Turn on two-step sign-in wherever it is offered.",
        "Watch your bank and card statements for anything you don't know.",
    ],
);
static UPDATES: Guide = g(
    Page::WindowsUpdate,
    &[
        "Select Check for updates.",
        "Choose Download and install for anything offered.",
        "Restart when Windows asks.",
    ],
);
static REBOOT: Guide = g(
    Page::WindowsUpdate,
    &[
        "Save your work.",
        "Select Restart now when Windows shows that a restart is needed.",
    ],
);
static WORK: Guide = g(
    Page::WorkAccounts,
    &[
        "Look at the accounts listed. A work or school account means someone else may manage this computer.",
        "If you don't recognise one, ask the person or company named there. Don't disconnect an account you use to sign in to Windows.",
    ],
);
static HELLO: Guide = g(
    Page::SignIn,
    &[
        "Select PIN (Windows Hello).",
        "Choose Set up and follow the steps.",
        "Face or fingerprint appear here too if your computer has the hardware.",
    ],
);
static FIND_MY_DEVICE: Guide = g(
    Page::FindMyDevice,
    &[
        "Turn on Find my device.",
        "It needs a Microsoft account. If the switch is greyed out, sign in with one first.",
    ],
);
static DAILY_ADMIN: Guide = Guide {
    page: Page::OtherUsers,
    alt: None,
    steps: &[
        "Choose Add account, then I don't have this person's sign-in information, then Add a user without a Microsoft account.",
        "Give it a strong password. Select it, choose Change account type, then Administrator.",
        "Sign in to it and set your everyday account to Standard user the same way.",
        "Use your everyday account from now on. Windows asks for the admin password when needed.",
    ],
};
static TAMPER: Guide = g(
    Page::VirusSettings,
    &[
        "Scroll to Tamper Protection and turn it on.",
        "Select Yes if Windows asks. Windows only lets a person turn this on.",
    ],
);
static WIFI: Guide = g(
    Page::Wifi,
    &[
        "Not your own network, such as a café? Don't change anything. Avoid private sign-ins on it.",
        "Select your network, then its properties, to see its security type.",
        "Open your router's settings page. The address and password are often on a sticker on the router.",
        "Set the Wi-Fi security to WPA3, or WPA2 if WPA3 isn't listed, and save.",
    ],
);
static DNS: Guide = g(
    Page::Network,
    &[
        "If Secblitz Web protection is on, skip this. It already manages your lookups.",
        "Choose Wi-Fi or Ethernet, open your connection's properties, then select Edit next to DNS server assignment.",
        "Keep the addresses shown, set DNS over HTTPS to On (automatic template), then select Save.",
        "Windows 10 has no such setting, so leave it as it is.",
    ],
);
static THREATS: Guide = g(
    Page::ProtectionHistoryList,
    &[
        "Open each item Windows found and choose Actions.",
        "Choose Remove or Quarantine, then run a quick scan.",
    ],
);
static WIDGETS: Guide = g(
    Page::Taskbar,
    &[
        "Turn off Widgets under Taskbar items.",
        "This hides Widgets for your account. Anyone else who uses this computer can do the same.",
    ],
);
/// Hidden background tasks (WMI): nothing is removed by hand, since some work
/// and hardware tools use them. A deep scan cleans what is really harmful.
static HIDDEN_TASKS: Guide = g(
    Page::ProtectionHistory,
    &[
        "Don't remove anything yourself. Some work or hardware tools set these up on purpose.",
        "Save your work. Choose Scan options, then Microsoft Defender Offline scan, then Scan now.",
        "Your computer restarts and scans for about 15 minutes. Windows removes what it finds.",
        "Still listed after that? Ask someone you trust who knows computers to look at it with you.",
    ],
);

static RECENT_FILES: Guide = g(
    Page::PrivacySettings,
    &[
        "Find the switch for remembering recent files, or file history.",
        "Turn it off, or choose how long files are remembered.",
    ],
);
static LOCK_PREVIEWS: Guide = g(
    Page::PrivacySettings,
    &[
        "Find the settings for notifications on the lock screen.",
        "Turn off showing the text of messages while the screen is locked.",
    ],
);

pub fn guide(key: &str) -> Option<&'static Guide> {
    Some(match key {
        "vbs.memory_integrity" | "Memory integrity" => &MEMORY_INTEGRITY,
        "vbs.kernel_stack_protection" => &KERNEL_STACK,
        "Device encryption" if secblitz::platform::windows_home() => &ENCRYPTION_HOME,
        "Device encryption" => &ENCRYPTION,
        "Secure Boot" => &SECURE_BOOT,
        "accounts.autologon" | "Automatic logon" => &AUTOLOGON,
        "remote_desktop.disabled" | "Remote Desktop" | "remote.rdp" => &REMOTE_DESKTOP,
        "smb1.disabled" | "SMB1" | "smb.v1" => &SMB1,
        "os.feature_release_support" | "Windows lifecycle" => &LIFECYCLE,
        "boot.secure_boot_certs" => &SECURE_BOOT_CERTS,
        "Windows updates" => &UPDATES,
        "update.reboot_overdue" => &REBOOT,
        "Management and mutation eligibility" => &WORK,
        "accounts.hello_configured" => &HELLO,
        "accounts.find_my_device" => &FIND_MY_DEVICE,
        "accounts.daily_admin" => &DAILY_ADMIN,
        "defender.tamper_protection" => &TAMPER,
        "net.wifi_security" => &WIFI,
        "net.dns_encryption" => &DNS,
        "defender.threats" => &THREATS,
        "persistence.wmi_subscriptions" => &HIDDEN_TASKS,
        "clickfix.run_history" => &RUN_HISTORY,
        _ => return None,
    })
}

const WIDGETS_YOURSELF: &str = "Not offered: Windows keeps this setting for you to change yourself";

/// Only reasons the person can act on get steps. Unsupported hardware, firmware locks, pending restarts and the like get none: following them would do nothing or harm. Matched on exact backend reasons.
pub fn guide_not_offered(key: &str, detail: &str) -> Option<&'static Guide> {
    use secblitz::vbs;
    match key {
        vbs::MEMORY_INTEGRITY if vbs::is_driver_reason(detail) => Some(&MEMORY_INTEGRITY),
        vbs::STACK_PROTECTION if detail == vbs::NEEDS_MEMORY_INTEGRITY => Some(&KERNEL_STACK),
        "debloat.widgets_policy" if detail == WIDGETS_YOURSELF => Some(&WIDGETS),
        "linux.recent_files" if detail == secblitz::linux::person::UNAVAILABLE => {
            Some(&RECENT_FILES)
        }
        "linux.lock_previews" if detail == secblitz::linux::person::UNAVAILABLE => {
            Some(&LOCK_PREVIEWS)
        }
        _ => None,
    }
}

/// how to reach it by hand.
pub fn failure_text(lang: crate::i18n::Lang, page: Page) -> String {
    if page == Page::PrivacySettings {
        return lang
            .t("We couldn't open {page}. Open your computer's Settings app and look for {page}.")
            .replace("{page}", &lang.t(page.name()));
    }
    lang.t("We couldn't open {page}. Press the Windows key, type {page} and press Enter.")
        .replace("{page}", &lang.t(page.name()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    const KEYS: &[&str] = &[
        "vbs.memory_integrity",
        "vbs.kernel_stack_protection",
        "Memory integrity",
        "Device encryption",
        "Secure Boot",
        "accounts.autologon",
        "Automatic logon",
        "remote_desktop.disabled",
        "Remote Desktop",
        "remote.rdp",
        "smb1.disabled",
        "SMB1",
        "smb.v1",
        "os.feature_release_support",
        "Windows lifecycle",
        "boot.secure_boot_certs",
        "Windows updates",
        "update.reboot_overdue",
        "Management and mutation eligibility",
        "accounts.hello_configured",
        "accounts.find_my_device",
        "accounts.daily_admin",
        "defender.tamper_protection",
        "net.wifi_security",
        "net.dns_encryption",
        "defender.threats",
        "persistence.wmi_subscriptions",
        "clickfix.run_history",
    ];

    #[test]
    fn every_required_key_has_a_short_plain_guide() {
        let guides = KEYS
            .iter()
            .map(|key| {
                (
                    *key,
                    guide(key).unwrap_or_else(|| panic!("no guide for {key}")),
                )
            })
            .chain([("Device encryption on Windows Home", &ENCRYPTION_HOME)]);
        for (key, g) in guides {
            assert!((2..=4).contains(&g.steps.len()), "{key}: 2 to 4 steps");
            for step in g.steps {
                assert!(step.len() <= 130, "{key}: keep steps short: {step}");
                assert!(!step.contains('\u{2014}'), "{key}: no em dash");
                assert!(step.ends_with('.'), "{key}: {step}");
            }
        }
        assert!(guide("nothing.here").is_none());
        assert!(guide("").is_none());
    }

    #[test]
    fn every_page_maps_to_one_request_and_one_action() {
        for (i, page) in Page::ALL.into_iter().enumerate() {
            assert_eq!(Page::from_request(page.request()), Some(page));
            assert_eq!(Page::from_action(page.action()), Some(page));
            assert!(page.button().starts_with("Open "));
            for other in &Page::ALL[i + 1..] {
                assert_ne!(page.request(), other.request());
                assert_ne!(page.action(), other.action());
                assert_ne!(page.button(), other.button());
            }
        }
    }

    #[test]
    fn guides_and_pages_are_translated_in_every_language() {
        let mut keys: Vec<&str> = ENCRYPTION_HOME.steps.to_vec();
        for key in KEYS {
            let g = guide(key).unwrap();
            keys.extend(g.steps);
        }
        for page in Page::ALL {
            keys.push(page.name());
            keys.push(page.button());
        }
        keys.push("We couldn't open {page}. Press the Windows key, type {page} and press Enter.");
        keys.push(
            "We couldn't open {page}. Open your computer's Settings app and look for {page}.",
        );
        keys.extend(RECENT_FILES.steps);
        keys.extend(LOCK_PREVIEWS.steps);
        // Product names stay as Microsoft spells them in every language.
        keys.retain(|k| !matches!(*k, "Windows Security" | "Windows Update" | "BitLocker"));
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for key in &keys {
                assert_ne!(lang.t(key), *key, "{}: {key}", lang.code());
            }
        }
    }

    #[test]
    fn the_privacy_steps_are_short_and_only_given_when_the_desktop_cannot_be_changed() {
        let unavailable = secblitz::linux::person::UNAVAILABLE;
        for (id, steps) in [
            ("linux.recent_files", &RECENT_FILES),
            ("linux.lock_previews", &LOCK_PREVIEWS),
        ] {
            let g = guide_not_offered(id, unavailable).unwrap();
            assert_eq!(g, steps);
            assert_eq!(g.page, Page::PrivacySettings);
            assert!((2..=4).contains(&g.steps.len()));
            for step in g.steps {
                assert!(step.len() <= 130 && step.ends_with('.'), "{step}");
                assert!(!step.contains('\u{2014}'), "{step}");
            }
            assert!(guide_not_offered(id, "").is_none());
            assert!(guide_not_offered(id, "Eligible unmanaged local preference").is_none());
        }
        assert!(guide_not_offered("linux.firewall", unavailable).is_none());
    }

    #[test]
    fn the_privacy_page_is_opened_with_words_that_fit_a_linux_desktop() {
        let text = failure_text(Lang::En, Page::PrivacySettings);
        assert_eq!(
            text,
            "We couldn't open Privacy settings. Open your computer's Settings app and look for Privacy settings."
        );
        assert!(!text.contains("Windows"));
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            let translated = failure_text(lang, Page::PrivacySettings);
            assert_ne!(translated, text, "{}", lang.code());
            assert!(!translated.contains('{'), "{translated}");
        }
    }

    #[test]
    fn windows_home_is_never_sent_to_bitlocker() {
        assert_eq!(ENCRYPTION_HOME.page, Page::Encryption);
        assert_eq!(ENCRYPTION_HOME.alt, None);
        assert!(ENCRYPTION_HOME
            .steps
            .iter()
            .all(|s| !s.contains("BitLocker")));
    }

    #[test]
    fn failure_text_names_the_page_and_the_way_in() {
        let text = failure_text(Lang::En, Page::CoreIsolation);
        assert_eq!(
            text,
            "We couldn't open Core isolation. Press the Windows key, type Core isolation and press Enter."
        );
    }

    #[test]
    fn not_offered_gets_steps_only_for_reasons_a_person_can_act_on() {
        use secblitz::vbs;
        let mi = vbs::MEMORY_INTEGRITY;
        assert!(guide_not_offered(mi, vbs::DRIVER).is_some());
        let named = format!("{}: old.sys, older.sys", vbs::DRIVER);
        assert!(guide_not_offered(mi, &named).is_some());
        // Every other reason, including "we could not check your drivers",
        // gets no steps: there is nothing safe for the person to do.
        for no in [
            vbs::NOT_SUPPORTED,
            vbs::LOCKED,
            vbs::DRIVERS_UNREADABLE,
            vbs::ALREADY_ON,
            vbs::NEEDS_RESTART,
            vbs::UNREADABLE,
            vbs::SET_BY_HAND,
            vbs::OLD_WINDOWS,
            "Not offered: a driver on this computer may not work with itself",
            "Not offered: this edition of Windows does not include it",
        ] {
            assert!(guide_not_offered(mi, no).is_none(), "{no}");
        }
        let ks = vbs::STACK_PROTECTION;
        assert!(guide_not_offered(ks, vbs::NEEDS_MEMORY_INTEGRITY).is_some());
        for no in [
            vbs::NO_SHADOW_STACKS,
            vbs::NEEDS_RESTART,
            vbs::DRIVER,
            vbs::OLD_WINDOWS,
            vbs::LOCKED,
            vbs::SET_BY_HAND,
        ] {
            assert!(guide_not_offered(ks, no).is_none(), "{no}");
        }
        for key in [
            "remote_desktop.disabled",
            "smb1.disabled",
            "accounts.autologon",
        ] {
            assert!(guide_not_offered(key, vbs::DRIVER).is_none(), "{key}");
        }
        let widgets = guide_not_offered("debloat.widgets_policy", WIDGETS_YOURSELF).expect("steps");
        assert_eq!(widgets.page, Page::Taskbar);
        let home = "Not offered: this setting is not available on Windows Home";
        assert!(guide_not_offered("debloat.widgets_policy", home).is_none());
    }

    #[test]
    fn risky_guides_warn_before_the_action() {
        assert!(guide("remote_desktop.disabled").unwrap().steps[0].contains("Stop here"));
        assert!(guide("smb1.disabled").unwrap().steps[0].contains("leave it on"));
        assert!(guide("Secure Boot").unwrap().steps[0].contains("recovery key"));
        assert!(guide("net.wifi_security").unwrap().steps[0].contains("Not your own network"));
    }

    #[test]
    fn older_findings_without_a_guide_still_get_their_page() {
        assert_eq!(Page::for_finding("Windows Firewall"), Some(Page::Firewall));
        assert_eq!(Page::for_finding("SmartScreen"), Some(Page::AppBrowser));
        assert_eq!(Page::for_finding("Defender"), None);
        assert_eq!(
            Page::for_finding("Management and mutation eligibility"),
            Some(Page::WorkAccounts)
        );
    }
}
