use super::Explainer;

pub(super) fn get(id: &str) -> Option<Explainer> {
    Some(match id {
        "os.feature_release_support" => Explainer {
            what: "This checks whether your version of Windows still gets safety updates from Microsoft.",
            risk: "Once a version stops getting updates, you no longer get new security fixes.",
            change: "To fix it, install the newest Windows version in Windows Update. It takes a while and needs a restart. Back up first.",
        },
        "boot.secure_boot_certs" => Explainer {
            what: "This checks that your computer's startup security has received the newer certificates from Microsoft.",
            risk: "Old startup certificates expire, and a computer without the new ones may stop getting startup security fixes.",
            change: "If Secblitz offers Renew now on the Tools page, it can't be undone and finishes after a restart. Otherwise install Windows updates.",
        },
        "defender.tamper_protection" => Explainer {
            what: "Tamper Protection stops harmful programs from switching off your virus protection.",
            risk: "Without it, malware can quietly turn off your antivirus and then do whatever it likes.",
            change: "Turn it on in Windows Security. You won't notice anything, but some tools can no longer change virus settings.",
        },
        "defender.threats" => Explainer {
            what: "This looks for harmful files that Windows Security found and has not finished dealing with.",
            risk: "A harmful file left in place can read your passwords or damage your files.",
            change: "On the Tools page, choose Remove on the Virus protection safeguards tip. Windows Security usually keeps what it removes, so you can restore it.",
        },
        "defender.exclusions_risky" => Explainer {
            what: "Windows Security can be told to skip some places or programs. This checks that the skipped list is not risky.",
            risk: "Harmful programs can hide in a skipped place, because your virus protection never looks there.",
            change: "Look at the list in Windows Security and remove entries you don't know. Some games or tools may need a few.",
        },
        "defender.scan_age" => Explainer {
            what: "This checks when your computer was last scanned for viruses.",
            risk: "Without regular scans, a harmful file that slipped in can stay hidden for weeks.",
            change: "Run a quick scan. It takes a few minutes and you can keep using your computer.",
        },
        "smartscreen.apps" => Explainer {
            what: "This is the warning Windows shows before you run an unknown or risky download.",
            risk: "Without it, you could open an unrecognized installer from a website or email with no warning at all.",
            change: "Turn it on in Windows Security. You'll see an extra warning sometimes when you open unfamiliar downloads.",
        },
        "smartscreen.browser_policy" => Explainer {
            what: "This checks that Edge and Chrome can still warn you about dangerous websites.",
            risk: "A browser that doesn't warn you may let you open a look-alike bank or shopping page.",
            change: "Secblitz removes the setting that turned the warnings off, so risky sites get a warning page again. Undo puts it back.",
        },
        "smart_app_control.state" => Explainer {
            what: "Smart App Control blocks apps that Microsoft doesn't trust. This just shows whether it is on.",
            risk: "Without it, a brand-new harmful program is less likely to be stopped before it runs.",
            change: "Nothing to do here. Once it is off, Windows can only turn it back on after a fresh install, so this app leaves it alone.",
        },
        "update.paused" => Explainer {
            what: "This checks whether Windows updates are paused.",
            risk: "While updates are paused, your computer misses important security fixes.",
            change: "Resume updates in Windows Update. Your computer will download updates and may ask for a restart.",
        },
        "update.drivers_excluded" => Explainer {
            what: "This checks whether Windows is told to skip driver updates for your hardware.",
            risk: "Old drivers can keep bugs and missing security fixes in things like Wi-Fi and graphics.",
            change: "Nothing to change if it was on purpose. Some people skip drivers to avoid problems after updates.",
        },
        "update.reboot_overdue" => Explainer {
            what: "This checks whether your computer has been waiting a long time for a restart to finish an update.",
            risk: "Until you restart, the fixes are only half installed.",
            change: "Choose Restart now when it suits you. Save your work first. Secblitz only restarts when you ask.",
        },
        "ps.v2_engine" => Explainer {
            what: "This is a very old part of Windows' command tool that almost nobody needs anymore.",
            risk: "It skips newer safety checks, so harmful scripts can run unnoticed.",
            change: "You can remove it in Windows Features. Very old scripts may stop working; normal use isn't affected.",
        },
        "net.hosts_file" => Explainer {
            what: "This is a small file on your computer that can send website names to other places.",
            risk: "Malware can use it to send you to a look-alike bank website or to block your antivirus updates.",
            change: "Only the lines that redirect trusted websites are turned into notes. The rest stays as it is. You can undo this.",
        },
        "persistence.wmi_subscriptions" => Explainer {
            what: "This counts hidden triggers that can start programs on your computer without showing up in the usual start-up lists.",
            risk: "Some malware uses these to come back after you remove it, with nothing visible.",
            change: "Ask someone who knows computers to review them. Some hardware and management tools use them on purpose, so nothing is removed for you.",
        },
        "services.unquoted_paths" => Explainer {
            what: "This checks background programs whose location has spaces and no quotes, which Windows can misread.",
            risk: "Windows can mistake the location of the program and start the wrong file with full power.",
            change: "Quotes are added around the location and nothing else changes. The program works as before. You can undo this.",
        },
        "accounts.stale_enabled" => Explainer {
            what: "This counts accounts on your computer that are switched on but haven't been used in months.",
            risk: "A forgotten account is easy to overlook, so it is safer switched off.",
            change: "Secblitz switches them off and never deletes them. Your own account stays on, and Undo switches them back on.",
        },
        "smb.shares_exposed" => Explainer {
            what: "This shows who each shared folder on your computer is shared with.",
            risk: "On a shared or café network, other people can read or change files in a folder shared with the Everyone entry.",
            change: "Secblitz takes away the open access for everyone, so only the people listed on each folder can open it from other devices. Undo gives it back.",
        },
        "smb.server_encryption" => Explainer {
            what: "This shows whether file sharing on your computer scrambles its traffic so others can't read it.",
            risk: "Without it, someone on the same network could read files while they travel to another device.",
            change: "Shown for information only. Turning it on can stop very old devices, such as old scanners, from connecting.",
        },
        "firewall.user_dir_inbound_allow" => Explainer {
            what: "This looks for apps in your Downloads, Desktop or Temp folders that the firewall lets receive connections.",
            risk: "A harmful app in one of those folders could let others connect straight to your computer.",
            change: "Those allowances are switched off, not deleted. A game or app may ask again. You can undo this.",
        },
        "accounts.daily_admin" => Explainer {
            what: "This checks whether the account you use every day is an administrator account.",
            risk: "If a harmful program runs under an administrator account, it can change anything on your computer.",
            change: "Make a normal account for daily use and keep this one for installing things. You'll type a password to install apps.",
        },
        "accounts.hello_configured" => Explainer {
            what: "This checks whether you have a PIN or Windows Hello (face or fingerprint) set up to sign in.",
            risk: "Without one you sign in with your long password, which can be seen as you type it or leak from a website.",
            change: "Add a PIN in Sign-in options. It only works on this computer, and signing in gets faster. Your password still works.",
        },
        "accounts.find_my_device" => Explainer {
            what: "Find my device lets you see where a lost laptop is and lock it.",
            risk: "If your laptop is lost or stolen, you can't find it or lock it, so someone who finds it could try to get at your files.",
            change: "Turn it on in Settings. It shares your laptop's location with your Microsoft account. Only checked on laptops.",
        },
        "vbs.kernel_stack_protection" => Explainer {
            what: "This is an extra shield that keeps harmful code from misusing programs that run in the core of Windows.",
            risk: "Without it, a bug in a driver is more likely to cause serious trouble in Windows.",
            change: "If your computer supports it, Secblitz can turn it on after Core system protection runs. You restart once, and some older drivers may not load. You can undo it.",
        },
        "net.dns_encryption" => Explainer {
            what: "When you open a website, your computer first asks a server where it is. This checks whether that question is private.",
            risk: "Someone on the same café Wi-Fi could see, or change, which sites you are looking up.",
            change: "Choose encrypted lookups in your network settings. Nothing else changes. This app never changes those servers for you.",
        },
        "net.wifi_security" => Explainer {
            what: "This checks how well the Wi-Fi network you're connected to is protected.",
            risk: "On a network with no or weak protection, others nearby can watch what you do or join in.",
            change: "Switch your router to the newest security option, with a strong password. Very old devices may need to reconnect.",
        },
        "persistence.run_and_tasks" => Explainer {
            what: "This finds programs that start by themselves with Windows from risky places and aren't signed by a known maker.",
            risk: "Malware often hides in a folder like Temp or Downloads and starts again every time you turn your computer on.",
            change: "They stop starting with Windows. Nothing is deleted, and you can turn them back on by undoing this.",
        },
        "clickfix.run_history" => Explainer {
            what: "This looks at the commands recently typed into the Run box and counts the ones that match a known trick.",
            risk: "Fake check pages tell you to paste a command into the Run box. It can install a program that steals your passwords.",
            change: "Nothing changes. If something matches, scan your computer and change your passwords from another device. Your Run history is not deleted.",
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::get;

    const IDS: &[&str] = &[
        "os.feature_release_support",
        "boot.secure_boot_certs",
        "defender.tamper_protection",
        "defender.threats",
        "defender.exclusions_risky",
        "defender.scan_age",
        "smartscreen.apps",
        "smartscreen.browser_policy",
        "smart_app_control.state",
        "update.paused",
        "update.drivers_excluded",
        "update.reboot_overdue",
        "ps.v2_engine",
        "net.hosts_file",
        "persistence.wmi_subscriptions",
        "services.unquoted_paths",
        "accounts.stale_enabled",
        "smb.shares_exposed",
        "smb.server_encryption",
        "firewall.user_dir_inbound_allow",
        "accounts.daily_admin",
        "accounts.hello_configured",
        "accounts.find_my_device",
        "vbs.kernel_stack_protection",
        "net.dns_encryption",
        "net.wifi_security",
        "persistence.run_and_tasks",
        "clickfix.run_history",
    ];

    #[test]
    fn every_read_only_check_is_explained_in_plain_words() {
        for id in IDS {
            let e = get(id).unwrap_or_else(|| panic!("{id}"));
            for line in [e.what, e.risk, e.change] {
                assert!(line.len() <= 160, "{id}: {line}");
                assert!(!line.contains('!'), "{id}");
                for jargon in [
                    "NTLM", "SMB", "DNS", "WMI", "RID", "HVCI", "TKIP", "WEP", "WPA",
                ] {
                    assert!(!line.contains(jargon), "{id}: {jargon}");
                }
            }
        }
        assert!(get("not.a.check").is_none());
    }
}
