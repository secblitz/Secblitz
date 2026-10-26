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
        "linux.ptrace" => e(
            "Normally any program can look inside the other programs you run and read what they hold in memory. A safer rule is not on here.",
            "A harmful program you run by accident could read passwords and other secrets out of your browser or other programs.",
            "Programs can only look inside programs they started themselves. Tools for fixing programs still work when you start the program from them. You can undo this.",
        ),
        "linux.network_redirects" => e(
            "Other computers on your network can tell yours to send its traffic a different way, and this computer can tell others the same.",
            "Someone on the same Wi-Fi can use this to quietly send your traffic through their own computer and read it.",
            "Route changes from other computers are ignored and this computer stops sending them. Everything you do online works as before, and you can undo this.",
        ),
        "linux.llmnr" => e(
            "Your computer answers questions from other computers on the local network about names, such as the name of a shared folder.",
            "Someone on the same network can answer first and trick your computer into sending them a sign-in password.",
            "Your computer stops answering these questions. Names are still found through your normal internet settings, and you can undo this.",
        ),
        "linux.browser_data_collection" => e(
            "Your browsers can send Google, Mozilla and others details about how you use them and what interests you.",
            "Those details can include the sites you visit, and they are used to tailor ads and services to you.",
            "Browsers stop sending usage data and then say your organization manages them, which only means a setting was made here. You can undo this.",
        ),
        "linux.browser_https_only" => e(
            "Firefox can insist on secure connections and warn you before it opens a page that is not protected.",
            "On a page that is not protected, anyone on the same network can read what you type or change what you see.",
            "Firefox warns you first, and you can still open the page. It will say your organization manages it, which only means a setting was made here.",
        ),
        "linux.memory_shuffle" => e(
            "The system can place each program's memory in a different spot every time it runs, so attacks that count on a fixed spot fail.",
            "Without it, a harmful program can find the pieces it wants to attack much more easily.",
            "Each program gets a different layout every time it starts. Programs work as before, and you can undo this.",
        ),
        "linux.bpf_hardening" => e(
            "The system lets small programs run inside it for speed. Ordinary users should not be able to add their own, and the ones that run should be guarded.",
            "Flaws here are a common way for a harmful program to gain far more control than it should have.",
            "Small programs inside the system are guarded better. Everything you use works as before, and you can undo this.",
        ),
        "linux.terminal_drivers" => e(
            "Any program can make the system load old drivers for text terminals, even ones you never use.",
            "Some of these old drivers have flaws that let a harmful program take over the computer.",
            "Old terminal drivers only load when an administrator asks. Normal use is not affected, and you can undo this.",
        ),
        "linux.crash_memory" => e(
            "When a program that runs with extra rights crashes, the system can save a copy of its memory, which may hold secrets.",
            "Passwords and other secrets from that program can end up in a file on your disk.",
            "Such programs no longer leave a copy of their memory. Tools for finding faults may see less, and you can undo this.",
        ),
        "linux.crash_files" => e(
            "When a program crashes, the system can keep a copy of what it held in memory on your disk, to help find the fault.",
            "That copy can hold passwords and private text, and it stays on the disk until it is cleaned up.",
            "New crashes no longer save a copy. Files saved earlier stay where they are, and you can undo this.",
        ),
        "linux.rare_protocols" => e(
            "Your computer knows a few rarely used ways of talking over the network that almost nobody needs, yet any program can switch them on.",
            "Flaws in these rarely used features have been used to attack computers, so they are best left off.",
            "These features no longer start by themselves. Anything already running is left alone, and you can undo this.",
        ),
        "linux.app_sandbox_limits" => e(
            "Apps can make a private box for themselves to run in. Ubuntu asks for permission first, and this checks that it does.",
            "A harmful app can use such a box to get around the limits placed on it.",
            "Apps need permission to make a private box. A few apps from outside the store may ask for it, and you can undo this.",
        ),
        "linux.processor_updates" => e(
            "Processor makers send fixes for security flaws in their chips. Your computer loads them each time it starts.",
            "Without the fixes, flaws in the processor itself stay open, and no setting can close them.",
            "The processor update is installed from your software sources. Nothing else changes, and you can undo this.",
        ),
        "linux.root_account" => e(
            "The main administrator account can change everything on this computer. It is normally locked, so nobody can sign in to it with a password.",
            "An account with a password can be guessed from the network or the sign-in screen, and it has no limits at all.",
            "The account is locked and your other administrators keep working. You can undo this.",
        ),
        "linux.fake_sources" => e(
            "Network messages carry the address of their sender, and a sender can lie about it. This checks that impossible senders are turned away.",
            "Attackers can pretend to be another computer to get past simple protections or to hide where an attack comes from.",
            "Messages that could not have arrived from where they claim are thrown away. Everything you do online works as before, and you can undo this.",
        ),
        "linux.flood_protection" => e(
            "When someone floods a computer with fake requests to connect, it can run out of room for the real ones. A built-in defence stops that.",
            "Without the defence, one attacker on the network can make this computer stop answering anyone.",
            "The built-in defence is switched on. Nothing you do changes, and you can undo this.",
        ),
        "linux.source_routing" => e(
            "A network message can carry its own list of stops that tells computers which way it must go. This checks that such lists are ignored.",
            "An attacker can use such lists to slip messages past protections or to receive answers meant for someone else.",
            "Messages that choose their own route are ignored. Everything you do online works as before, and you can undo this.",
        ),
        "linux.broadcast_pings" => e(
            "One computer can send a single call to every computer on a network and wait for the answers. This checks whether yours answers.",
            "Attackers can use this to make many computers answer one victim at the same moment, which can knock it offline.",
            "This computer stops answering such calls. Everything you do online works as before, and you can undo this.",
        ),
        "linux.ipv6_privacy" => e(
            "Your computer can use an address that never changes, which lets websites recognise it. A temporary address changes now and then instead.",
            "A fixed address lets websites and networks follow this computer from day to day and from place to place.",
            "Temporary addresses are used instead. They start with your next connection to a network, so reconnect to use them now. You can undo this.",
        ),
        "linux.computer_name_sent" => e(
            "When you join a network, your computer tells it its name so that the network can list it. Many people have their own name in it.",
            "Anyone who runs a network, such as a cafe or a hotel, can see that name and use it to recognise you again.",
            "Networks stop seeing the name from your next connection. Some routers then list this computer as unknown, and you can undo this.",
        ),
        "linux.encrypted_dns" => e(
            "To open a website, your computer first asks a server where it is. By default anyone along the way can read that question.",
            "Whoever runs the network, or sits on it, can see every website you look up, even when the sites themselves are protected.",
            "Questions are scrambled whenever the server allows it and sent as before when it does not. Nothing is cut off, and you can undo this.",
        ),
        "linux.announce_name" => e(
            "Your computer tells everyone on the local network its name and what it offers, so that other devices can find it without setup.",
            "Anyone on the same network, such as public Wi-Fi, can see the name of your computer and what it offers.",
            "Your computer stops announcing itself but still finds other devices. Others may find what you share less easily, and you can undo this.",
        ),
        "linux.old_network_services" => e(
            "Some old programs let other computers connect to this one and send everything, even passwords, without protection. This looks for them.",
            "Anyone on the network can read what these programs send, and attackers keep searching for computers that run them.",
            "Those programs are stopped and no longer start by themselves. A shared folder from another computer may stop working, and you can undo this.",
        ),
        "linux.bluetooth_autostart" => e(
            "Your computer switches Bluetooth on by itself every time it starts. People with a Bluetooth keyboard or mouse need that.",
            "Bluetooth that is on can be found by devices nearby, and weak spots in it have let strangers in before.",
            "Bluetooth stays off after the next start until you turn it on. Do not choose this if you use a Bluetooth keyboard or mouse. You can undo this.",
        ),
        "linux.usage_survey" => e(
            "A program on this computer sends the list of your installed programs to its makers once a week.",
            "The list shows what software you use, which says more about you than you might expect.",
            "Nothing is sent any more. Your programs work as before, and you can undo this.",
        ),
        "linux.mint_app_updates" => e(
            "The Update Manager can update your Flatpak apps and your Cinnamon add-ons by itself. Right now it waits for you.",
            "Apps and add-ons that nobody remembers to update keep known security holes open.",
            "Those apps and add-ons update by themselves. Updates for Linux itself work as before, and you can undo this.",
        ),
        "linux.app_store_updates" => e(
            "The Software app can download and install updates for your apps by itself. This checks that it is allowed to.",
            "Apps that stay out of date keep known security holes open, even when the fixes are already out.",
            "The Software app downloads updates by itself again, and you can undo this.",
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
        "linux.media_autorun" => e(
            "When you plug in a drive or put in a disc, your computer can start programs from it by itself. This checks whether that is allowed.",
            "A drive that was found or lent by a stranger could start harmful software the moment it is plugged in.",
            "Plugged-in drives and discs no longer start anything by themselves. You can still open them yourself, and you can undo this.",
        ),
        "linux.location" => e(
            "Your computer can tell apps and websites where you are, using the networks around you. This checks whether that is on.",
            "Apps could learn where you live, where you work and where you travel.",
            "Apps are no longer told where you are. Maps and weather may ask you to type a place instead, and you can undo this.",
        ),
        "linux.problem_reports" => e(
            "Your desktop can send reports about crashes and about how you use your software to the people who make it.",
            "Reports describe your computer and what you run on it, and can say more about you than you would expect.",
            "No more reports are sent. Everything works as before, and you can undo this.",
        ),
        "linux.app_usage" => e(
            "Your desktop remembers which apps you open the most and shows them first.",
            "Anyone using your account can see which apps you use and how often.",
            "Your computer stops keeping track of which apps you use most. Search may list apps in a different order. You can undo this.",
        ),
        "linux.old_files" => e(
            "Your Trash and your temporary files can be emptied by themselves once they are old. By default nothing is ever deleted.",
            "Files you deleted long ago, and leftovers from programs, stay on your computer where anyone using your account can find them.",
            "Files in the Trash for over 30 days, and old temporary files, are deleted for good. Turning this off again cannot bring them back.",
        ),
        "linux.home_private" => e(
            "Your home folder holds your documents and settings. This checks whether other accounts on this computer are able to open it.",
            "Anyone else with an account here could read your files without needing your password.",
            "Only you can open your home folder. Your files are not touched, and you can undo this.",
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
        crate::advice::ACCOUNTS_WITHOUT_PASSWORD => e(
            "At least one account on this computer has no password, so anyone can sign in to it.",
            "Anyone who can reach the sign-in screen or the network could use that account and see what it can see.",
            "We leave it as it is. Give the account a password in your system settings, or ask whoever set up this computer.",
        ),
        crate::advice::ADMIN_WITHOUT_PASSWORD => e(
            "A rule on this computer lets some accounts use full admin rights without typing a password.",
            "A harmful program running in that account could change anything on the computer without asking you.",
            "We leave it as it is. The rule may be needed, so ask whoever set up this computer before removing it.",
        ),
        crate::advice::UNCHECKED_SOURCES => e(
            "A place your computer gets software from is set up to skip the safety check on what it downloads.",
            "Anyone who tampers with that download could slip harmful software onto your computer.",
            "We leave it as it is. Remove that source in your software settings, or ask whoever added it.",
        ),
        crate::advice::SECURITY_SUPPORT => e(
            "Each version of Linux gets security fixes for a limited time. The end date of yours is close or has passed.",
            "After that date, new security holes in your version are never fixed.",
            "We cannot change this for you. Move to a newer version of Linux, and back up your files first.",
        ),
        crate::advice::HARDWARE_UPDATES => e(
            "The makers of some parts inside your computer have released updates for them.",
            "Those updates fix weak spots in parts such as the startup software, which other updates do not reach.",
            "We leave updating to you. Open your software app and install them. Some need a restart afterwards.",
        ),
        crate::advice::EXTRA_ADMIN_ACCOUNTS => e(
            "Some accounts have full control of this computer, with no limits. Only the main administrator account should.",
            "An extra account like that can change anything on this computer, and it is a common way for attackers to stay hidden.",
            "We leave it as it is. Ask whoever set up this computer why the extra account is there, and remove it if it is not needed.",
        ),
        crate::advice::ADMIN_ACCOUNTS => e(
            "Some accounts on this computer can change anything on it. This lists them.",
            "Anyone who signs in to one of those accounts can install programs, read other accounts and remove protections.",
            "We leave it as it is. Take that right from an account in your system settings if it does not need it.",
        ),
        crate::advice::OPEN_PROGRAMS => e(
            "Some programs on this computer wait for connections from other computers. This lists the ones that are not part of a normal desktop.",
            "Each one is a door that a stranger on the same network can try, and a weak spot in the program could let them in.",
            "We leave it as it is. Close a program you do not use, or ask whoever set up this computer.",
        ),
        crate::advice::SWAP_PROTECTION => e(
            "When memory runs low, your computer copies some of it to the drive. That copy is not scrambled here.",
            "Passwords and open documents can end up on the drive and be read by anyone who gets hold of it.",
            "We cannot change this safely for you. Encrypting the drive when you install Linux protects it.",
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINDINGS: [&str; 14] = [
        crate::advice::DISK_ENCRYPTION,
        crate::advice::LINUX_SECURE_BOOT,
        crate::advice::UPDATES_WAITING,
        crate::advice::RESTART_NEEDED,
        crate::advice::PROGRAM_LIMITS,
        crate::advice::ACCOUNTS_WITHOUT_PASSWORD,
        crate::advice::ADMIN_WITHOUT_PASSWORD,
        crate::advice::UNCHECKED_SOURCES,
        crate::advice::SECURITY_SUPPORT,
        crate::advice::HARDWARE_UPDATES,
        crate::advice::EXTRA_ADMIN_ACCOUNTS,
        crate::advice::ADMIN_ACCOUNTS,
        crate::advice::OPEN_PROGRAMS,
        crate::advice::SWAP_PROTECTION,
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
