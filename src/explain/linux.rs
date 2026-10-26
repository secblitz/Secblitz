//! Explanations for the Linux checks and findings.
use super::Explainer;

const fn e(what: &'static str, risk: &'static str, change: &'static str) -> Explainer {
    Explainer { what, risk, change }
}

pub(super) fn get(id: &str) -> Option<Explainer> {
    Some(match id {
        "linux.firewall" => e(
            "The firewall decides which connections from other computers are allowed to reach this one.",
            "With it off, anyone on the same Wi-Fi or network can try to reach programs running here.",
            "Uninvited connections are blocked. Everything you do online works as before, and you can undo this.",
        ),
        "linux.fedora_open_ports" => e(
            "Fedora Workstation leaves a very wide range of network doors open to other computers.",
            "Any program you start can be reached from the network, even one with a weak spot you do not know about.",
            "Only the doors for common services stay open. A tool that needs to be reached may stop working. You can undo this.",
        ),
        "linux.auto_updates" => e(
            "Security updates close holes that attackers already know about. This checks that they install by themselves.",
            "Without them, holes stay open until you remember to update, which can be weeks or months.",
            "Security updates install in the background. Your computer is never restarted for you. You can undo this.",
        ),
        "linux.ssh_server" => e(
            "Remote sign-in lets someone use this computer from another one over the network. It is on, but nobody seems to be set up to use it.",
            "Attackers keep guessing passwords on every computer that offers it, day and night.",
            "Other computers can no longer sign in this way. Everything else works as before, and you can turn it back on.",
        ),
        "linux.ssh_password" => e(
            "Remote sign-in is on and still accepts a password, or the main administrator account, from other computers.",
            "A guessed or stolen password is then enough for a stranger to take over this computer.",
            "Remote sign-in needs a saved key from now on. Set one up first if you use it. You can undo this.",
        ),
        "linux.file_sharing" => e(
            "Your computer can offer folders to Windows computers on the network. This checks whether that service is on.",
            "Anyone on the same network may see what you share, and flaws in this kind of sharing have let malware spread.",
            "Your shared folders stop appearing on other computers. Nothing is deleted, and you can turn sharing back on.",
        ),
        "linux.autologin" => e(
            "Your computer signs in to your account by itself when it starts, without asking for a password.",
            "Anyone who can switch it on, or who finds it lost, gets straight into your files and accounts.",
            "Your computer asks for your password when it starts. Make sure you know it before you turn this on.",
        ),
        "linux.guest" => e(
            "The sign-in screen offers a guest session that anyone can open without a password.",
            "A visitor with a few minutes alone with your computer can use it without any account.",
            "The guest option disappears from the sign-in screen. Your own account and other accounts work as before.",
        ),
        "linux.kernel_protections" => e(
            "Linux has built-in protections that hide system details from ordinary programs. Some are off here.",
            "A harmful program can learn things about your computer that make it easier to break out of its limits.",
            "Programs see less about your system. A very old tool may complain about it. You can undo this.",
        ),
        "linux.crash_reports" => e(
            "When a program crashes, Ubuntu collects a report and offers to send it. This checks whether that is on.",
            "A report can hold pieces of what was in memory, such as parts of your documents or passwords.",
            "Ubuntu stops collecting crash reports. Fixing a crash may be harder later, and you can turn this back on.",
        ),
        "linux.countme" => e(
            "Fedora's software sources add a small request that counts how many computers use each version.",
            "It carries no name, but it tells Fedora's servers when your computer is online and what it runs.",
            "The counting stops. Updates and installs work exactly as before, and you can undo this.",
        ),
        "linux.connectivity_check" => e(
            "Your computer regularly contacts an outside website to find out whether the internet works.",
            "The company behind that address can see when your computer is online and from which network.",
            "The check stops. Wi-Fi sign-in pages at hotels and cafes may not open by themselves. You can undo this.",
        ),
        "linux.wifi_mac" => e(
            "Every Wi-Fi card has an address that networks can see. By default your computer shows its real one everywhere.",
            "Anyone running a Wi-Fi network can recognize your computer by it, even on a different day or in a different place.",
            "Each network sees a made-up address that stays the same for that network. You can undo this.",
        ),
        "linux.screen_lock" => e(
            "Your screen should lock when you walk away. This checks that locking is on and that it does not wait forever.",
            "Anyone who walks past can read your screen and use your accounts while you are gone.",
            "The screen locks after five minutes without use, and you sign in again with your password. You can undo this.",
        ),
        "linux.remote_desktop" => e(
            "Your desktop can let other computers see and control your screen over the network. This checks whether that is on.",
            "Someone who learns the password could watch everything you do and use your computer.",
            "Other computers can no longer connect to your screen. Everything else works as before, and you can undo this.",
        ),
        "linux.recent_files" => e(
            "Your computer keeps a list of the files you opened lately and shows it in menus and file windows, with no time limit.",
            "Anyone using your account can see what you worked on, even private files from months ago.",
            "The list is forgotten after 30 days. Your files are not touched, and you can undo this.",
        ),
        "linux.lock_previews" => e(
            "Notifications can show the text of your messages on the lock screen, where anyone can read them.",
            "A visitor can read private messages, codes and names on your screen without signing in.",
            "Notifications still arrive, but their text only shows after you sign in. You can undo this.",
        ),
        "linux.ubuntu_insights" => e(
            "Ubuntu can send reports about your computer's parts and how you use it to its makers. This checks whether that is on.",
            "The reports hold no files, but they describe your computer and software in detail.",
            "No more reports are sent. Ubuntu works exactly as before, and you can turn this back on.",
        ),
        "linux.time_sync" => e(
            "Your computer can set its clock from the internet by itself. This checks that it does.",
            "A wrong clock makes secure connections fail and hides expired security certificates.",
            "The clock keeps itself right using internet time servers. Nothing else changes, and you can undo this.",
        ),
        "linux.printer_sharing" => e(
            "Your printing service can share your printers with the network and let other computers manage it. This checks that it does not.",
            "Anyone on the same network may use your printers, read what you print or change how printing works.",
            "Your printers are used from this computer only. Sharing stops, and you can undo this.",
        ),
        "linux.printer_discovery" => e(
            "Your computer can add printers that other computers announce on the network, using an old method. This checks that the old method is off.",
            "A stranger on the network can announce a fake printer that attacks your computer as soon as it is added.",
            "Printers announced the old way are ignored. Printers you add yourself keep working, and you can undo this.",
        ),
        "linux.ubuntu_news" => e(
            "Ubuntu downloads news and advertising from its makers to show in update messages and in the text at sign-in.",
            "Each download tells the company that your computer is online and which version of Ubuntu it runs.",
            "Those messages stop. Updates still install as before, and you can undo this.",
        ),
        "linux.snap_updates" => e(
            "Apps from Ubuntu's app store update by themselves. Their updates can be held back for a long time, and this checks for that.",
            "Apps that are held back keep known security holes open, even when the fixes are already out.",
            "The hold ends and the apps update on their own again. You can undo this to put the hold back as it was.",
        ),
        "Linux disk encryption" => e(
            "Disk encryption scrambles everything on your drive so it can only be read after you sign in. It is off on this computer.",
            "Anyone who finds or steals your computer can take out the drive and read your files without a password.",
            "It cannot be turned on in place. It needs a fresh Linux install, which erases the disk, so back up first.",
        ),
        "Linux Secure Boot" => e(
            "Secure Boot makes your computer start only software that is signed by a trusted maker. It is off here.",
            "Malware that hides in the first moments of startup can survive a reinstall and is very hard to find.",
            "We cannot change it for you. It is set when the computer starts, and a few drivers may stop working with it on.",
        ),
        "Linux updates waiting" => e(
            "Updates are waiting to be installed. They fix problems and close security holes.",
            "Until they are installed, the holes they fix stay open and attackers can use them.",
            "We leave updating to you. It usually takes a few minutes, and you can keep using your computer.",
        ),
        "Linux restart needed" => e(
            "Some updates only take effect after the computer restarts, and this one is waiting for that.",
            "Until you restart, the old, unfixed version of the software keeps running.",
            "Restart when it suits you. Nothing is lost, and Secblitz never restarts your computer by itself.",
        ),
        "Linux program limits" => e(
            "Linux can keep each program inside a box of what it is allowed to do. This guard is not fully on here.",
            "A hacked program can then reach far more of your files and settings than it needs.",
            "We leave it as it is. Changing it can stop programs from working, so ask whoever set up this computer.",
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINDINGS: [&str; 5] = [
        crate::advice::DISK_ENCRYPTION,
        crate::advice::LINUX_SECURE_BOOT,
        crate::advice::UPDATES_WAITING,
        crate::advice::RESTART_NEEDED,
        crate::advice::PROGRAM_LIMITS,
    ];

    #[test]
    fn every_linux_check_and_finding_has_a_short_plain_explanation() {
        let ids = crate::linux::catalog::specs()
            .iter()
            .map(|s| s.id)
            .chain(FINDINGS);
        for id in ids {
            let x = get(id).unwrap_or_else(|| panic!("no explanation for {id}"));
            for (label, line) in [("what", x.what), ("risk", x.risk), ("change", x.change)] {
                crate::explain::tests::assert_short_sentence(id, label, line);
                assert!(
                    !line.contains('!') && !line.contains('\u{2014}'),
                    "{id} {label}"
                );
                crate::advice::assert_plain_linux_words(line);
            }
            assert!(crate::explain::for_check(id).is_some(), "{id}");
        }
        assert!(get("windows.only").is_none());
    }
}
