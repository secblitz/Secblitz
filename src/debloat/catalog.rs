//! The compiled app catalog and protected list. Package lists are inspired by
//! Raphire/Win11Debloat and ChrisTitusTech/winutil (MIT). The index is the stable
//! id stored in the journal and sent over the broker, so only ever append.
use super::{App, Group};

const fn app(
    family: &'static str,
    name: &'static str,
    group: Group,
    store_id: Option<&'static str>,
) -> App {
    App {
        family,
        name,
        group,
        store_id,
    }
}

pub static CATALOG: &[App] = &[
    app(
        "Microsoft.BingNews",
        "News",
        Group::Recommended,
        Some("9WZDNCRFHVFW"),
    ),
    app(
        "Microsoft.BingWeather",
        "Weather",
        Group::Recommended,
        Some("9WZDNCRFJ3Q2"),
    ),
    app(
        "Clipchamp.Clipchamp",
        "Clipchamp video editor",
        Group::Recommended,
        Some("9P1J8S7CCWWT"),
    ),
    app(
        "Microsoft.GetHelp",
        "Get Help",
        Group::Recommended,
        Some("9PKDZBMV1H3T"),
    ),
    app(
        "Microsoft.WindowsFeedbackHub",
        "Feedback Hub",
        Group::Recommended,
        Some("9NBLGGH4R32N"),
    ),
    app(
        "Microsoft.MicrosoftSolitaireCollection",
        "Solitaire games",
        Group::Recommended,
        Some("9WZDNCRFHWD2"),
    ),
    app(
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft 365 Copilot app",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.PowerAutomateDesktop",
        "Power Automate",
        Group::Recommended,
        Some("9NFTCH6J7FHV"),
    ),
    app(
        "Microsoft.BingSearch",
        "Bing search helper",
        Group::Recommended,
        None,
    ),
    app("Microsoft.WindowsMaps", "Maps", Group::Recommended, None),
    app(
        "Microsoft.ZuneVideo",
        "Movies & TV",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.3DBuilder",
        "3D Builder",
        Group::Recommended,
        None,
    ),
    app("Microsoft.Print3D", "Print 3D", Group::Recommended, None),
    app(
        "Microsoft.MixedReality.Portal",
        "Mixed Reality Portal",
        Group::Recommended,
        None,
    ),
    app("Microsoft.SkypeApp", "Skype", Group::Recommended, None),
    app("Microsoft.Messaging", "Messaging", Group::Recommended, None),
    app("Microsoft.People", "People", Group::Recommended, None),
    app(
        "Microsoft.Wallet",
        "Microsoft Pay",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.MicrosoftJournal",
        "Journal",
        Group::Recommended,
        None,
    ),
    app("Microsoft.Getstarted", "Tips", Group::Recommended, None),
    app(
        "Microsoft.549981C3F5F10",
        "Cortana",
        Group::Recommended,
        None,
    ),
    app(
        "king.com.*",
        "Candy Crush and other King games",
        Group::Sponsored,
        None,
    ),
    app("SpotifyAB.SpotifyMusic", "Spotify", Group::Sponsored, None),
    app("Disney.37853FC22B2CE", "Disney+", Group::Sponsored, None),
    app("4DF9E0F8.Netflix", "Netflix", Group::Sponsored, None),
    app("BytedancePte.Ltd.TikTok", "TikTok", Group::Sponsored, None),
    app(
        "AmazonVideo.PrimeVideo",
        "Prime Video",
        Group::Sponsored,
        None,
    ),
    app(
        "Facebook.*",
        "Facebook and Instagram",
        Group::Sponsored,
        None,
    ),
    app(
        "D5EA27B7.Duolingo-LearnLanguagesforFree",
        "Duolingo",
        Group::Sponsored,
        None,
    ),
    app("ROBLOXCORPORATION.ROBLOX", "Roblox", Group::Sponsored, None),
    app("9E2F88E3.Twitter", "X (Twitter)", Group::Sponsored, None),
    app(
        "AdobeSystemsIncorporated.AdobeExpress",
        "Adobe Express",
        Group::Sponsored,
        None,
    ),
    app(
        "Microsoft.Copilot",
        "Copilot",
        Group::Promotions,
        Some("9NHT9RB2F4HD"),
    ),
    app(
        "Microsoft.Windows.Ai.Copilot.Provider",
        "Copilot helper",
        Group::Promotions,
        None,
    ),
    app(
        "MicrosoftWindows.Client.WebExperience",
        "Widgets",
        Group::Promotions,
        None,
    ),
    app(
        "MSTeams",
        "Microsoft Teams",
        Group::Promotions,
        Some("XP8BT8DW290MPQ"),
    ),
    app(
        "MicrosoftTeams",
        "Microsoft Teams (older version)",
        Group::Promotions,
        None,
    ),
    app(
        "Microsoft.OutlookForWindows",
        "New Outlook",
        Group::Promotions,
        Some("9NRX63209R7B"),
    ),
    app(
        "Microsoft.Windows.DevHome",
        "Dev Home",
        Group::Promotions,
        // Retired: its Store id now opens "Windows Advanced Settings".
        None,
    ),
    app(
        "Microsoft.Todos",
        "Microsoft To Do",
        Group::Promotions,
        Some("9NBLGGH5R558"),
    ),
    app(
        "Microsoft.YourPhone",
        "Phone Link",
        Group::Promotions,
        Some("9NMPJ99VJBWV"),
    ),
    app(
        "MicrosoftWindows.CrossDevice",
        "Phone Link helper",
        Group::Promotions,
        None,
    ),
    app(
        "Microsoft.StartExperiencesApp",
        "Start suggestions",
        Group::Promotions,
        None,
    ),
    app(
        "Microsoft.WindowsAlarms",
        "Clock and alarms",
        Group::Utilities,
        Some("9WZDNCRFJ3PR"),
    ),
    app(
        "Microsoft.MicrosoftStickyNotes",
        "Sticky Notes",
        Group::Utilities,
        Some("9NBLGGH4QGHW"),
    ),
    app(
        "Microsoft.WindowsSoundRecorder",
        "Sound Recorder",
        Group::Utilities,
        Some("9WZDNCRFHWKN"),
    ),
    app(
        "Microsoft.ZuneMusic",
        "Media Player",
        Group::Utilities,
        Some("9WZDNCRFJ3PT"),
    ),
    app(
        "Microsoft.WindowsCamera",
        "Camera",
        Group::Utilities,
        Some("9WZDNCRFJBBG"),
    ),
    app(
        "Microsoft.Windows.Photos",
        "Photos",
        Group::Utilities,
        Some("9WZDNCRFJBH4"),
    ),
    app(
        "MicrosoftCorporationII.QuickAssist",
        "Quick Assist",
        Group::Utilities,
        Some("9P7BP5VNWKX5"),
    ),
    app(
        "Microsoft.GamingApp",
        "Xbox app",
        Group::Gaming,
        Some("9MV0B5HZVK9Z"),
    ),
    app(
        "Microsoft.XboxGamingOverlay",
        "Game Bar",
        Group::Gaming,
        Some("9NZKPSTSNW4P"),
    ),
    app(
        "Microsoft.XboxGameOverlay",
        "Game Bar overlay",
        Group::Gaming,
        None,
    ),
    app(
        "Microsoft.XboxSpeechToTextOverlay",
        "Game Bar voice typing",
        Group::Gaming,
        None,
    ),
    app(
        "Microsoft.Xbox.TCUI",
        "Xbox sign-in screens",
        Group::Gaming,
        None,
    ),
    app(
        "Microsoft.XboxApp",
        "Xbox app (older version)",
        Group::Gaming,
        None,
    ),
    app("Microsoft.BingFinance", "Finance", Group::Recommended, None),
    app("Microsoft.BingSports", "Sports", Group::Recommended, None),
    app("Microsoft.BingTravel", "Travel", Group::Recommended, None),
    app(
        "Microsoft.BingFoodAndDrink",
        "Food and Drink",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.BingHealthAndFitness",
        "Health and Fitness",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.BingTranslator",
        "Translator",
        Group::Recommended,
        None,
    ),
    app("Microsoft.News", "Microsoft News", Group::Recommended, None),
    app(
        "Microsoft.PCManager",
        "PC Manager",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.Microsoft3DViewer",
        "3D Viewer",
        Group::Recommended,
        None,
    ),
    app("Microsoft.MSPaint", "Paint 3D", Group::Recommended, None),
    app(
        "Microsoft.OneConnect",
        "Mobile Plans",
        Group::Recommended,
        None,
    ),
    app("Microsoft.Office.Sway", "Sway", Group::Recommended, None),
    app(
        "Microsoft.MicrosoftPowerBIForWindows",
        "Power BI",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.Office.OneNote",
        "OneNote for Windows 10",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.M365Companions",
        "Microsoft 365 Companions",
        Group::Recommended,
        None,
    ),
    app(
        "Microsoft.WidgetsPlatformRuntime",
        "Widgets helper",
        Group::Promotions,
        None,
    ),
    app(
        "microsoft.windowscommunicationsapps",
        "Mail and Calendar (older version)",
        Group::Promotions,
        None,
    ),
    app(
        "MicrosoftCorporationII.MicrosoftFamily",
        "Family Safety",
        Group::Utilities,
        None,
    ),
];

/// A short plain line shown under an app's name when there is something
/// worth knowing before removing it.
/// The note to show on this PC. Copilot keys only exist on Windows 11 PCs.
pub fn note_on(family: &str, windows_11: bool) -> Option<&'static str> {
    if family == "Microsoft.MicrosoftOfficeHub" && !windows_11 {
        return None;
    }
    note(family)
}

pub fn note(family: &str) -> Option<&'static str> {
    Some(match family {
        "Microsoft.MicrosoftOfficeHub" => {
            "Removing this may change what the Copilot key on your keyboard opens."
        }
        "MicrosoftWindows.Client.WebExperience" | "Microsoft.WidgetsPlatformRuntime" => {
            "Widgets stop working everywhere, including on the lock screen. Tick Widgets and Widgets helper together."
        }
        "microsoft.windowscommunicationsapps" => {
            "Microsoft stopped supporting this app at the end of 2024. Remove it only if you use another mail app."
        }
        "MicrosoftCorporationII.MicrosoftFamily" => {
            "Parents may use this to manage family screen time. Leave it alone if you use Family features."
        }
        "Microsoft.MSPaint" => "This is Paint 3D. The normal Paint app stays on your computer.",
        "Microsoft.Office.OneNote" => {
            "If you still keep notes in this older app, check them before you remove it."
        }
        "Microsoft.M365Companions" => {
            "If your work or school manages this computer, it may put this app back."
        }
        "Microsoft.BingFinance"
        | "Microsoft.BingSports"
        | "Microsoft.BingTravel"
        | "Microsoft.BingFoodAndDrink"
        | "Microsoft.BingHealthAndFitness"
        | "Microsoft.BingTranslator" => "An older Microsoft app that has mostly been retired.",
        _ => return None,
    })
}

pub fn matches(pattern: &str, package: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => starts_with_ci(package, prefix),
        None => pattern.eq_ignore_ascii_case(package),
    }
}

const PROTECTED_EXACT: &[&str] = &[
    "Microsoft.WindowsStore",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.SecHealthUI",
    "Microsoft.WindowsTerminal",
    "Microsoft.WindowsNotepad",
    "Microsoft.WindowsCalculator",
    "Microsoft.ScreenSketch",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.Windows.ShellExperienceHost",
    "Microsoft.Windows.StartMenuExperienceHost",
    "Microsoft.Windows.CloudExperienceHost",
    "Microsoft.StorePurchaseApp",
    "Microsoft.Services.Store.Engagement",
    "Microsoft.LockApp",
    "Microsoft.AAD.BrokerPlugin",
    "Microsoft.AccountsControl",
    "Microsoft.CredDialogHost",
    "Microsoft.ECApp",
    "Microsoft.Win32WebViewHost",
    "Microsoft.AsyncTextService",
    "Microsoft.BioEnrollment",
    "Microsoft.WebpImageExtension",
    "Microsoft.HEIFImageExtension",
    "Microsoft.VP9VideoExtensions",
    "Microsoft.WebMediaExtensions",
    "Microsoft.RawImageExtension",
    "Microsoft.HEVCVideoExtension",
    "Microsoft.AV1VideoExtension",
    "Microsoft.MPEG2VideoExtension",
];

const PROTECTED_PREFIX: &[&str] = &[
    "Microsoft.VCLibs",
    "Microsoft.UI.Xaml",
    "Microsoft.NET",
    "Microsoft.WindowsAppRuntime",
    "Microsoft.MicrosoftEdge",
    "Microsoft.OneDrive",
    "Microsoft.WindowsStore",
    "Microsoft.Windows.Search",
    "MicrosoftWindows.Client.CBS",
    "MicrosoftWindows.Client.Core",
    "MicrosoftWindows.Client.FileExp",
    "MicrosoftWindows.Client.OOBE",
    "Windows.",
    "NcsiUwpApp",
];

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn ends_with_ci(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.as_bytes()[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

pub fn is_protected(name: &str) -> bool {
    PROTECTED_EXACT.iter().any(|p| p.eq_ignore_ascii_case(name))
        || PROTECTED_PREFIX.iter().any(|p| starts_with_ci(name, p))
        || ends_with_ci(name, "Extension")
        || ends_with_ci(name, "Extensions")
        || ends_with_ci(name, ".Framework")
}

pub fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

pub fn owner(package: &str) -> Option<u16> {
    if !is_valid_package_name(package) || is_protected(package) {
        return None;
    }
    CATALOG
        .iter()
        .position(|app| matches(app.family, package))
        .map(|i| i as u16)
}
