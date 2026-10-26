//! Per-user settings (the signed-in person's own account).
use super::Explainer;

pub(super) fn get(id: &str) -> Option<Explainer> {
    Some(match id {
        "smartscreen.store_apps" => Explainer {
            what: "Windows can check the web addresses that Store apps open and warn you about unsafe ones.",
            risk: "A Store app could send you to a harmful website and Windows would not warn you.",
            change: "Nothing you'll notice. You may see a warning page now and then when an app opens a risky site.",
        },
        "files.show_extensions" => Explainer {
            what: "Windows can show the ending of a file name, like .pdf or .exe, which tells you what kind of file it is.",
            risk: "A program disguised as \"invoice.pdf\" can really be \"invoice.pdf.exe\", and you would not see the difference.",
            change: "File names in folders will show their ending, like .docx. Nothing else changes.",
        },
        "net.nearby_sharing" => Explainer {
            what: "Nearby sharing lets this computer send and receive files with other devices close to you.",
            risk: "While anyone nearby is allowed, people on a train or in a cafe can try to send you files.",
            change: "Only your own devices can share with this computer. Sending to a friend's computer may need you to switch it back.",
        },
        "privacy.tailored_experiences" => Explainer {
            what: "Windows can use the information it collects about how you use your computer to suggest tips and ads.",
            risk: "Your computer habits are used to personalize suggestions, which many people would rather keep private.",
            change: "You'll see more general tips and ads instead of ones based on how you use your computer. Nothing breaks.",
        },
        "office.internet_macros" => Explainer {
            what: "Office files downloaded from the internet can contain small programs, called macros, that run when you open them.",
            risk: "A document from an unexpected email could run a hidden program the moment you click Enable Content.",
            change: "Macros in files from email or the web stay off. Work files that need macros may need to be unblocked first.",
        },
        "debloat.lockscreen_tips" => Explainer {
            what: "The lock screen can show tips, fun facts and offers on top of its picture.",
            risk: "You keep seeing tips and offers each time you lock or wake your computer.",
            change: "The lock screen shows only its picture. Your picture and the way you sign in do not change.",
        },
        "debloat.start_settings_tips" => Explainer {
            what: "Windows can suggest apps, tips and offers inside Start and the Settings app.",
            risk: "You keep seeing suggestions and account reminders in Start and Settings.",
            change: "Start and Settings stop showing suggestions and reminders. Your apps and settings stay as they are.",
        },
        "debloat.explorer_ads" => Explainer {
            what: "File Explorer can show messages about OneDrive and other online storage at the top of your folders.",
            risk: "You may keep seeing offers to sign up or buy more storage in File Explorer.",
            change: "Those messages stop. OneDrive and your files are not touched.",
        },
        "debloat.search_web" => Explainer {
            what: "When you search in Start, Windows can also show results and ads from the web.",
            risk: "What you type in Start search can be sent to the web, and web results show next to your own files.",
            change: "Start search shows only your computer, with no web results or daily pictures. Searching in your browser is not affected.",
        },
        "debloat.gamebar_popups" => Explainer {
            what: "Windows opens Game Bar from the Xbox button on a controller and can ask you to get an app when Game Bar is missing.",
            risk: "After you remove Game Bar, you may see a message asking you to get a new app.",
            change: "The controller button stops opening Game Bar and game clip recording stops. The Game Bar app is not removed.",
        },
        "space.storage_sense" => Explainer {
            what: "Storage Sense is a Windows feature that removes temporary files when your drive gets full.",
            risk: "Temporary files keep building up until you remove them yourself.",
            change: "Windows removes temporary files and old Recycle Bin items on its own. It never touches your Downloads or documents unless you choose that in Settings.",
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDS: [&str; 11] = [
        "smartscreen.store_apps",
        "files.show_extensions",
        "net.nearby_sharing",
        "privacy.tailored_experiences",
        "office.internet_macros",
        "debloat.lockscreen_tips",
        "debloat.start_settings_tips",
        "debloat.explorer_ads",
        "debloat.search_web",
        "debloat.gamebar_popups",
        "space.storage_sense",
    ];

    #[test]
    fn every_user_id_is_explained_in_plain_short_lines() {
        for id in IDS {
            let e = get(id).unwrap_or_else(|| panic!("{id}"));
            for line in [e.what, e.risk, e.change] {
                assert!(!line.is_empty() && line.len() <= 165, "{id}: {line}");
                assert!(!line.contains('!'), "{id}: {line}");
                for jargon in ["HKCU", "registry", "SMB", "NTLM", "CDP", "WinGet", "winget"] {
                    assert!(!line.contains(jargon), "{id}: {line}");
                }
            }
        }
        assert!(get("nope").is_none());
    }

    #[test]
    fn user_ids_resolve_through_the_catalog() {
        for id in IDS {
            assert!(crate::explain::for_check(id).is_some(), "{id}");
        }
    }

    #[test]
    fn every_ads_and_tips_switch_is_explained() {
        for setting in crate::user_settings::Setting::ADS_AND_TIPS {
            assert!(get(setting.id()).is_some(), "{}", setting.id());
        }
    }
}
