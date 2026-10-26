//! The compiled Linux catalog. Every control is a fixed list of named keys with u32 or short text values; the rules are
//! the same `hardening::Rule` ones the Windows table uses. A fix only moves a key from a recorded unsafe value to its
//! fixed value, and the backend chooses the mechanism. Journal data can only name an id listed here.
//!
//! Value shapes, one line per id: every value is `{"items": {<key>: <u32 | text | null>}}`; null is "not present".

use crate::hardening::{self, set, Item, Key};
use anyhow::ensure;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Changed by the root helper.
    System,
    /// Changed by the app itself, in the person's own session.
    Person,
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxSpec {
    pub id: &'static str,
    pub scope: Scope,
    /// Optional: never pre-selected, the person has to ask for it.
    pub ask: bool,
    pub reboot: bool,
    pub keys: &'static [Key],
}

const fn text(
    name: &'static str,
    safe: &'static [&'static str],
    absent_safe: bool,
    fix: Option<&'static str>,
) -> Key {
    hardening::text(name, "", safe, absent_safe, fix)
}

const fn flag(name: &'static str, absent_safe: bool) -> Key {
    set(name, "", &[0], absent_safe, Some(0), 1)
}

/// A setting that may be at the desktop's own default: 0 is the safe value, 1 is unsafe because the person set it,
/// 2 is unsafe because nothing was ever set. Undo puts 2 back with a reset, not by writing the value.
const fn unsafe_by_default(name: &'static str) -> Key {
    set(name, "", &[0], true, Some(0), 2)
}

/// A setting that is safe when on and that the desktop leaves off: 1 is safe, 0 is unsafe because the person set it,
/// 2 is unsafe because nothing was ever set. Undo puts 2 back with a reset, not by writing the value.
const fn off_by_default(name: &'static str) -> Key {
    set(name, "", &[1], false, Some(1), 2)
}

/// The longest wait, in seconds, that a delay setting can be read exactly. Longer waits are left alone.
pub const DELAY_CAP: u32 = 1_000_000;

/// A wait that is safe within a range: 0 is safe, any other value is `1 + 2 * seconds` for a wait the person set, and one
/// more when nothing was ever set. Undo puts back the exact seconds, or resets the setting when it was at its default.
const fn delay(name: &'static str) -> Key {
    set(name, "", &[0], false, Some(0), 2 * DELAY_CAP + 2)
}

const fn on(name: &'static str) -> Key {
    set(name, "", &[1], false, Some(1), 1)
}

const SPECS: &[LinuxSpec] = &[
    // enabled "yes"/"no"; incoming "deny"/"reject"/"allow": the policy for connections from other computers.
    LinuxSpec {
        id: "linux.firewall",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            text("enabled", &["yes"], false, Some("yes")),
            text("incoming", &["deny", "reject"], false, Some("deny")),
        ],
    },
    // open_ranges: the wide port ranges of the Fedora Workstation zone as text such as "1025-65535/tcp 1025-65535/udp"; null when none.
    LinuxSpec {
        id: "linux.fedora_open_ports",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[text("open_ranges", &[], true, None)],
    },
    // unattended: days between automatic security updates, 0 off.
    LinuxSpec {
        id: "linux.auto_updates",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set(
            "unattended",
            "",
            &[1, 2, 3, 4, 5, 6, 7],
            false,
            Some(1),
            365,
        )],
    },
    // enabled: 1 when the SSH server runs or starts at boot.
    LinuxSpec {
        id: "linux.ssh_server",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("enabled", true)],
    },
    // password: 1 when passwords may be used to sign in over SSH; root_login: "yes", "no", "prohibit-password" or "forced-commands-only".
    LinuxSpec {
        id: "linux.ssh_password",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            flag("password", false),
            text(
                "root_login",
                &["no", "prohibit-password", "forced-commands-only"],
                false,
                Some("prohibit-password"),
            ),
        ],
    },
    // samba: 1 when the Windows file sharing service is enabled.
    LinuxSpec {
        id: "linux.file_sharing",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("samba", true)],
    },
    // gdm_automatic: GDM's AutomaticLoginEnable as "true" or "false"; lightdm_user: LightDM's autologin-user, null when off.
    LinuxSpec {
        id: "linux.autologin",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            text("gdm_automatic", &["false"], true, Some("false")),
            text("lightdm_user", &[], true, None),
        ],
    },
    // allow_guest: LightDM's allow-guest as "true" or "false"; null when LightDM is not in use.
    LinuxSpec {
        id: "linux.guest",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[text("allow_guest", &["false"], true, Some("false"))],
    },
    // The running kernel settings: kptr_restrict 0-2, dmesg_restrict 0-1, protected_* 0-2 (hardlinks and symlinks 0-1).
    LinuxSpec {
        id: "linux.kernel_protections",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            set("kptr_restrict", "", &[1, 2], false, Some(1), 2),
            on("dmesg_restrict"),
            on("protected_hardlinks"),
            on("protected_symlinks"),
            set("protected_fifos", "", &[1, 2], false, Some(1), 2),
            set("protected_regular", "", &[1, 2], false, Some(2), 2),
        ],
    },
    // ptrace_scope: who may look inside other running programs, 0 anyone, 1 only a program's parent, 2 and 3 stricter; null without the module.
    LinuxSpec {
        id: "linux.ptrace",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("ptrace_scope", "", &[1, 2, 3], true, Some(1), 3)],
    },
    // accept_redirects, send_redirects: 1 when any network connection follows or hands out route changes; null when unreadable.
    LinuxSpec {
        id: "linux.network_redirects",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("accept_redirects", true), flag("send_redirects", true)],
    },
    // llmnr: whether systemd-resolved answers name lookups from the local network: "yes", "resolve" or "no"; null when it is not the resolver.
    LinuxSpec {
        id: "linux.llmnr",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[text("llmnr", &["no"], true, Some("no"))],
    },
    // rp_filter: the weakest check of sender addresses on any connection, 0 off, 1 strict, 2 loose; null when unreadable.
    LinuxSpec {
        id: "linux.fake_sources",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("rp_filter", "", &[1, 2], true, Some(2), 2)],
    },
    // syncookies: the defence against connection floods, 0 off, 1 on, 2 always on; null when unreadable.
    LinuxSpec {
        id: "linux.flood_protection",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("syncookies", "", &[1, 2], true, Some(1), 2)],
    },
    // accept_source_route: 1 when any connection follows messages that choose their own route, over either address family; null when unreadable.
    LinuxSpec {
        id: "linux.source_routing",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("accept_source_route", true)],
    },
    // ignore_broadcasts: 1 when this computer ignores calls sent to the whole network; null when unreadable.
    LinuxSpec {
        id: "linux.broadcast_pings",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("ignore_broadcasts", "", &[1], true, Some(1), 1)],
    },
    // use_tempaddr: the weakest rule for temporary addresses on any connection, 0 off, 1 allowed, 2 preferred; null without IPv6.
    LinuxSpec {
        id: "linux.ipv6_privacy",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("use_tempaddr", "", &[2], true, Some(2), 2)],
    },
    // sends: 1 when the network program tells every network the computer's name; null where it is not installed.
    LinuxSpec {
        id: "linux.computer_name_sent",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("sends", true)],
    },
    // dns_over_tls: whether website lookups are scrambled: "yes", "opportunistic" or "no"; null when systemd-resolved is not the resolver.
    LinuxSpec {
        id: "linux.encrypted_dns",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[text(
            "dns_over_tls",
            &["yes", "opportunistic"],
            true,
            Some("opportunistic"),
        )],
    },
    // announcing: 1 when avahi tells the local network this computer's name and services; null when it is not running.
    LinuxSpec {
        id: "linux.announce_name",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("announcing", true)],
    },
    // enabled: 1 when an old remote service (telnet, rsh, tftp, ftp servers, rpcbind, nfs, snmp) is on.
    LinuxSpec {
        id: "linux.old_network_services",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("enabled", true)],
    },
    // apport: 1 when Ubuntu's crash reporting is enabled.
    LinuxSpec {
        id: "linux.crash_reports",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("apport", true)],
    },
    // countme: 1 when a Fedora repository counts this computer.
    LinuxSpec {
        id: "linux.countme",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("countme", true)],
    },
    // enabled: 1 when NetworkManager checks the internet connection with an outside address.
    LinuxSpec {
        id: "linux.connectivity_check",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("enabled", true)],
    },
    // cloned_mac: the Wi-Fi address policy for new connections: "preserve", "permanent", "random" or "stable".
    LinuxSpec {
        id: "linux.wifi_mac",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[text(
            "cloned_mac",
            &["stable", "random"],
            false,
            Some("stable"),
        )],
    },
    // lock_enabled: 0 when the screen does not lock, 1 when it locks because the person set that, 2 when it locks by default;
    // idle_never: 1 when the screen never goes idle (idle-delay 0), fixed to 300 seconds.
    LinuxSpec {
        id: "linux.screen_lock",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[
            set("lock_enabled", "", &[1, 2], false, Some(1), 2),
            flag("idle_never", false),
        ],
    },
    // rdp, vnc: 1 when GNOME Remote Desktop accepts that kind of connection.
    LinuxSpec {
        id: "linux.remote_desktop",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[flag("rdp", true), flag("vnc", true)],
    },
    // keep_forever: 1 when recent files are remembered with no age limit that the person set, 2 when that is the default
    // (the age limit was never set); fixed to 30 days.
    LinuxSpec {
        id: "linux.recent_files",
        scope: Scope::Person,
        ask: true,
        reboot: false,
        keys: &[unsafe_by_default("keep_forever")],
    },
    // show_on_lock: 1 when notification text shows on the lock screen because the person set that, 2 when it shows by default.
    LinuxSpec {
        id: "linux.lock_previews",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[unsafe_by_default("show_on_lock")],
    },
    // linux, desktop_provision, release_upgrader: 1 when that Ubuntu Insights source may send data (consent_state = true),
    // 0 when its consent file says false, null when it has no consent file.
    LinuxSpec {
        id: "linux.ubuntu_insights",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[
            flag("linux", true),
            flag("desktop_provision", true),
            flag("release_upgrader", true),
        ],
    },
    // ntp: 1 when the clock sets itself from the internet.
    LinuxSpec {
        id: "linux.time_sync",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[on("ntp")],
    },
    // share_printers, remote_admin, remote_any: 1 when the printing service shares printers, lets other computers manage it,
    // or accepts connections from any address.
    LinuxSpec {
        id: "linux.printer_sharing",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            flag("share_printers", true),
            flag("remote_admin", true),
            flag("remote_any", true),
        ],
    },
    // cups_protocol: 1 when the finder of network printers is on and accepts announcements over the old printing protocol.
    LinuxSpec {
        id: "linux.printer_discovery",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("cups_protocol", true)],
    },
    // apt_news: 1 when Ubuntu downloads news for update messages; motd_news: 1 when it downloads news for the sign-in text.
    LinuxSpec {
        id: "linux.ubuntu_news",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("apt_news", true), flag("motd_news", true)],
    },
    // held: 1 when snap app updates are held back for good or for more than a week.
    LinuxSpec {
        id: "linux.snap_updates",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("held", true)],
    },
    // never: 1 when plugged-in drives and discs are never started by themselves, 0 when the person allowed it, 2 when that
    // is the desktop's default.
    LinuxSpec {
        id: "linux.media_autorun",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[off_by_default("never")],
    },
    // enabled: 1 when the desktop tells apps where the computer is.
    LinuxSpec {
        id: "linux.location",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[flag("enabled", true)],
    },
    // report_problems, send_usage_stats: 1 when the desktop sends crash reports or software usage statistics.
    LinuxSpec {
        id: "linux.problem_reports",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[
            flag("report_problems", true),
            flag("send_usage_stats", true),
        ],
    },
    // remember_usage: 1 when the desktop remembers which apps are used most because the person set it, 2 when that is the default.
    LinuxSpec {
        id: "linux.app_usage",
        scope: Scope::Person,
        ask: true,
        reboot: false,
        keys: &[unsafe_by_default("remember_usage")],
    },
    // trash, temp: 1 when old Trash files or old temporary files are deleted by themselves, 0 when the person turned that
    // off, 2 when that is the default (nothing is ever deleted).
    LinuxSpec {
        id: "linux.old_files",
        scope: Scope::Person,
        ask: true,
        reboot: false,
        keys: &[off_by_default("trash"), off_by_default("temp")],
    },
    // others: the "everyone else" permission bits of the person's home folder, 0 to 7; 0 is private.
    LinuxSpec {
        id: "linux.home_private",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[set("others", "", &[0], false, Some(0), 7)],
    },
    // delay: 0 when the screen goes dark after 1 to 600 seconds, otherwise the unsafe wait (0 means never, over 600 is too
    // long) as 1 + 2 * seconds, plus 1 when it is the desktop's own default; fixed to 300 seconds.
    LinuxSpec {
        id: "linux.screen_off_delay",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[delay("delay")],
    },
    // delay: 0 when the screen locks within 30 seconds of going dark, otherwise the unsafe wait as 1 + 2 * seconds, plus 1
    // when it is the desktop's own default; fixed to 0 seconds.
    LinuxSpec {
        id: "linux.lock_delay",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[delay("delay")],
    },
    // lock_on_suspend: 0 when the screen does not lock on sleep, 1 when it locks because the person set that, 2 when it locks by default.
    LinuxSpec {
        id: "linux.lock_on_suspend",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[set("lock_on_suspend", "", &[1, 2], false, Some(1), 2)],
    },
    // send: 1 when the desktop sends the makers of its software statistics about how it is used.
    LinuxSpec {
        id: "linux.usage_stats",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[flag("send", true)],
    },
    // firefox, chromium: 1 when that browser (Chromium means Chrome, Chromium or Brave) still shares usage data; null when none is installed.
    LinuxSpec {
        id: "linux.browser_data_collection",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("firefox", true), flag("chromium", true)],
    },
    // firefox: 1 when Firefox does not insist on secure connections; null when it is not installed.
    LinuxSpec {
        id: "linux.browser_https_only",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("firefox", true)],
    },
    // randomize_va_space: how randomly the system places a program's memory, 0 not at all, 1 partly, 2 fully; null when unreadable.
    LinuxSpec {
        id: "linux.memory_shuffle",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("randomize_va_space", "", &[2], true, Some(2), 2)],
    },
    // unprivileged_bpf_disabled: 0 when anyone may load small programs into the system, 1 when that is shut for good until a restart,
    // 2 when it is shut but an administrator can open it again; jit_harden: 0 off, 1 for ordinary users, 2 for everyone; null when unreadable.
    LinuxSpec {
        id: "linux.bpf_hardening",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[
            set("unprivileged_bpf_disabled", "", &[1, 2], true, Some(2), 2),
            set("jit_harden", "", &[2], true, Some(2), 2),
        ],
    },
    // ldisc_autoload: 1 when any program may make the system load old terminal drivers on demand; null when unreadable.
    LinuxSpec {
        id: "linux.terminal_drivers",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("ldisc_autoload", "", &[0], true, Some(0), 1)],
    },
    // suid_dumpable: 0 when programs that run with extra rights never leave a memory dump, 1 or 2 when they may; null when unreadable
    // or when Ubuntu's crash reports are on and need it.
    LinuxSpec {
        id: "linux.crash_memory",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("suid_dumpable", "", &[0], true, Some(0), 2)],
    },
    // stored: 1 when systemd-coredump keeps a program's memory on disk after it crashes; null when it does not handle crashes.
    LinuxSpec {
        id: "linux.crash_files",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("stored", true)],
    },
    // open: 1 when a rarely used network protocol that this computer has (dccp, sctp, rds or tipc) can be loaded on demand;
    // null when that cannot be told.
    LinuxSpec {
        id: "linux.rare_protocols",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("open", true)],
    },
    // restricted: 1 when AppArmor limits programs that make a private sandbox for themselves; null when the setting does not exist.
    LinuxSpec {
        id: "linux.app_sandbox_limits",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("restricted", "", &[1], true, Some(1), 1)],
    },
    // installed: 1 when the package that carries processor fixes for this computer's processor is installed; null when unknown.
    LinuxSpec {
        id: "linux.processor_updates",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[set("installed", "", &[1], true, Some(1), 1)],
    },
    // usable: 1 when the main administrator account can sign in with a password, 0 when that account is locked; null when unknown.
    LinuxSpec {
        id: "linux.root_account",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("usable", true)],
    },
    // auto_enable: 1 when Bluetooth adapters switch themselves on every time the computer starts, including when nothing says otherwise.
    LinuxSpec {
        id: "linux.bluetooth_autostart",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("auto_enable", true)],
    },
    // participate: 1 when the program that reports the installed programs every week is set to take part.
    LinuxSpec {
        id: "linux.usage_survey",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("participate", true)],
    },
    // flatpaks, spices: 1 when the Update Manager updates Flatpak apps or Cinnamon add-ons by itself because the person set that,
    // 0 when the person turned it off, 2 when it is off because nothing was ever set.
    LinuxSpec {
        id: "linux.mint_app_updates",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[off_by_default("flatpaks"), off_by_default("spices")],
    },
    // download: 0 when the Software app never downloads updates by itself, 1 when it does because the person set that, 2 when it does by default.
    LinuxSpec {
        id: "linux.app_store_updates",
        scope: Scope::Person,
        ask: false,
        reboot: false,
        keys: &[set("download", "", &[1, 2], false, Some(1), 2)],
    },
    // firefox, chromium: 1 when that browser (Chromium means Chrome, Chromium, Brave or Edge) does not block trackers; null when none supports it.
    LinuxSpec {
        id: "linux.browser_tracking",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("firefox", true), flag("chromium", true)],
    },
    // chromium: 1 when a Chromium browser still builds an ad interest list; null when none is installed.
    LinuxSpec {
        id: "linux.browser_ad_topics",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("chromium", true)],
    },
    // firefox: 1 when Firefox still shows sponsored shortcuts, stories or suggestions; null when it is not installed.
    LinuxSpec {
        id: "linux.browser_sponsored",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("firefox", true)],
    },
    // firefox: 1 when Pocket is not switched off in Firefox; null when it is not installed.
    LinuxSpec {
        id: "linux.browser_pocket",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("firefox", true)],
    },
    // firefox, chromium: 1 when a policy has turned the dangerous site warning off; null when no supporting browser is installed.
    LinuxSpec {
        id: "linux.browser_safe_browsing",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("firefox", true), flag("chromium", true)],
    },
    // chromium: 1 when leaked password warnings are not switched on by policy; null when none is installed.
    LinuxSpec {
        id: "linux.browser_password_leaks",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("chromium", true)],
    },
    // chromium: 1 when the browser may keep running after its windows close; null when none is installed.
    LinuxSpec {
        id: "linux.browser_background",
        scope: Scope::System,
        ask: false,
        reboot: false,
        keys: &[flag("chromium", true)],
    },
    // firefox, chromium: 1 when the browser still sends typing to a search company for suggestions; null when none is installed.
    LinuxSpec {
        id: "linux.browser_search_suggestions",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("firefox", true), flag("chromium", true)],
    },
    // firefox, chromium: 1 when the browser does not hide website lookups; null when none is installed.
    LinuxSpec {
        id: "linux.browser_encrypted_dns",
        scope: Scope::System,
        ask: true,
        reboot: false,
        keys: &[flag("firefox", true), flag("chromium", true)],
    },
];

/// The only words these keys can hold. Other text keys hold names or ranges, so they are only kept to plain ASCII.
fn closed_words(id: &str, key: &str) -> Option<&'static [&'static str]> {
    Some(match (id, key) {
        ("linux.firewall", "enabled") => &["yes", "no"],
        ("linux.firewall", "incoming") => &["deny", "reject", "allow"],
        ("linux.autologin", "gdm_automatic") | ("linux.guest", "allow_guest") => &["true", "false"],
        ("linux.llmnr", "llmnr") => &["yes", "resolve", "no"],
        ("linux.encrypted_dns", "dns_over_tls") => &["yes", "opportunistic", "no"],
        ("linux.ssh_password", "root_login") => {
            &["yes", "no", "prohibit-password", "forced-commands-only"]
        }
        _ => return None,
    })
}

pub fn specs() -> &'static [LinuxSpec] {
    SPECS
}

pub fn spec(id: &str) -> Option<&'static LinuxSpec> {
    SPECS.iter().find(|s| s.id == id)
}

impl LinuxSpec {
    fn key(&self, name: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.name == name)
    }

    pub fn catalog_target(&self) -> Value {
        hardening::fixed_target(self.keys)
    }

    /// Text ends up in files and commands run as root, so it is checked more tightly than the shared rules do.
    fn parse(&self, value: &Value) -> anyhow::Result<Vec<(String, Item)>> {
        let items = hardening::parse_items(self.id, value, |n| self.key(n), Some(self.keys.len()))?;
        for (name, item) in &items {
            if let Item::Text(t) = item {
                ensure!(
                    t.chars().all(|c| c.is_ascii_graphic() || c == ' '),
                    "{} holds text that is not a legal setting",
                    self.id
                );
                if let Some(words) = closed_words(self.id, name) {
                    ensure!(
                        words.contains(&t.as_str()),
                        "{} holds a setting that is not allowed",
                        self.id
                    );
                }
            }
        }
        Ok(items)
    }

    pub fn validate(&self, value: &Value) -> anyhow::Result<()> {
        self.parse(value).map(|_| ())
    }

    pub fn any_unsafe(&self, value: &Value) -> bool {
        self.parse(value).is_ok_and(|items| {
            items.iter().any(|(n, v)| {
                self.key(n)
                    .is_some_and(|k| !hardening::item_is_safe(k.rule, v))
            })
        })
    }

    pub fn derive_target(&self, before: &Value) -> anyhow::Result<Value> {
        hardening::derive_items(self.parse(before)?, |n| self.key(n))
    }

    /// Every key is always read, so there is nothing to narrow.
    pub fn view(&self, observed: &Value, _template: &Value) -> Value {
        observed.clone()
    }

    /// A control that is not on this computer is skipped by the backend, not read as protected.
    pub fn nothing_to_protect(&self, _value: &Value) -> bool {
        false
    }

    pub fn exact_recorded(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::Os;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_never_a_windows_id() {
        let mut seen = HashSet::new();
        for s in specs() {
            assert!(s.id.starts_with("linux."), "{}", s.id);
            assert!(seen.insert(s.id), "{} appears twice", s.id);
            assert!(!s.keys.is_empty(), "{}", s.id);
        }
        for windows in crate::engine::catalog::ids(Os::Windows) {
            assert!(spec(windows).is_none(), "{windows}");
        }
        assert_eq!(specs().len(), 69);
    }

    #[test]
    fn the_plan_scopes_and_optional_controls_are_as_agreed() {
        let person = [
            "linux.screen_lock",
            "linux.remote_desktop",
            "linux.recent_files",
            "linux.lock_previews",
            "linux.ubuntu_insights",
            "linux.media_autorun",
            "linux.location",
            "linux.problem_reports",
            "linux.app_usage",
            "linux.old_files",
            "linux.home_private",
            "linux.mint_app_updates",
            "linux.app_store_updates",
            "linux.screen_off_delay",
            "linux.lock_delay",
            "linux.lock_on_suspend",
            "linux.usage_stats",
        ];
        let optional = [
            "linux.fedora_open_ports",
            "linux.ssh_server",
            "linux.connectivity_check",
            "linux.wifi_mac",
            "linux.recent_files",
            "linux.app_usage",
            "linux.old_files",
            "linux.browser_https_only",
            "linux.root_account",
            "linux.computer_name_sent",
            "linux.encrypted_dns",
            "linux.announce_name",
            "linux.bluetooth_autostart",
            "linux.browser_search_suggestions",
            "linux.browser_encrypted_dns",
        ];
        for s in specs() {
            let want = if person.contains(&s.id) {
                Scope::Person
            } else {
                Scope::System
            };
            assert_eq!(s.scope, want, "{}", s.id);
            assert_eq!(s.ask, optional.contains(&s.id), "{}", s.id);
            assert!(!s.reboot, "{}", s.id);
        }
    }

    #[test]
    fn every_target_is_a_valid_value_with_every_key_present() {
        for s in specs() {
            let target = s.catalog_target();
            s.validate(&target)
                .unwrap_or_else(|e| panic!("{}: {e}", s.id));
            let items = target["items"].as_object().unwrap();
            assert_eq!(items.len(), s.keys.len(), "{}", s.id);
            assert!(
                !s.any_unsafe(&target),
                "{}: the fixed value is unsafe",
                s.id
            );
        }
    }

    #[test]
    fn key_names_are_unique_within_a_control() {
        for s in specs() {
            let names: HashSet<_> = s.keys.iter().map(|k| k.name).collect();
            assert_eq!(names.len(), s.keys.len(), "{}", s.id);
        }
    }

    #[test]
    fn a_value_with_a_missing_unknown_or_mistyped_key_is_refused() {
        let firewall = spec("linux.firewall").unwrap();
        let good = json!({"items": {"enabled": "no", "incoming": "allow"}});
        firewall.validate(&good).unwrap();
        for bad in [
            json!({"items": {"enabled": "no"}}),
            json!({"items": {"enabled": "no", "incoming": "allow", "extra": "x"}}),
            json!({"items": {"enabled": 1, "incoming": "allow"}}),
            json!({"enabled": "no", "incoming": "allow"}),
            json!(true),
            json!({"items": {"enabled": "no\nyes", "incoming": "allow"}}),
        ] {
            assert!(firewall.validate(&bad).is_err(), "{bad}");
        }
        let kernel = spec("linux.kernel_protections").unwrap();
        let mut value = kernel.catalog_target();
        value["items"]["kptr_restrict"] = json!(3);
        assert!(kernel.validate(&value).is_err());
    }

    #[test]
    fn text_is_plain_and_closed_keys_hold_only_their_words() {
        let firewall = spec("linux.firewall").unwrap();
        for bad in ["maybe", "Yes", "yes ", "ye\u{2028}s", "y\u{e9}s"] {
            let value = json!({"items": {"enabled": bad, "incoming": "deny"}});
            assert!(firewall.validate(&value).is_err(), "{bad:?}");
        }
        let root = spec("linux.ssh_password").unwrap();
        let value = json!({"items": {"password": 1, "root_login": "no\u{2029}yes"}});
        assert!(root.validate(&value).is_err());
        let mac = spec("linux.wifi_mac").unwrap();
        mac.validate(&json!({"items": {"cloned_mac": "00:11:22:33:44:55"}}))
            .unwrap();
        assert!(mac
            .validate(&json!({"items": {"cloned_mac": "caf\u{e9}"}}))
            .is_err());
        let autologin = spec("linux.autologin").unwrap();
        let value = json!({"items": {"gdm_automatic": "false", "lightdm_user": "sam"}});
        autologin.validate(&value).unwrap();
    }

    #[test]
    fn a_fix_moves_only_the_unsafe_keys_to_their_fixed_value() {
        let firewall = spec("linux.firewall").unwrap();
        let before = json!({"items": {"enabled": "no", "incoming": "reject"}});
        assert!(firewall.any_unsafe(&before));
        assert_eq!(
            firewall.derive_target(&before).unwrap(),
            json!({"items": {"enabled": "yes", "incoming": "reject"}})
        );

        let kernel = spec("linux.kernel_protections").unwrap();
        let before = json!({"items": {
            "kptr_restrict": 0, "dmesg_restrict": 1, "protected_hardlinks": 1,
            "protected_symlinks": 1, "protected_fifos": 0, "protected_regular": 1
        }});
        assert_eq!(
            kernel.derive_target(&before).unwrap(),
            json!({"items": {
                "kptr_restrict": 1, "dmesg_restrict": 1, "protected_hardlinks": 1,
                "protected_symlinks": 1, "protected_fifos": 1, "protected_regular": 1
            }})
        );
    }

    #[test]
    fn absent_values_follow_each_keys_own_rule() {
        let ssh = spec("linux.ssh_server").unwrap();
        assert!(!ssh.any_unsafe(&json!({"items": {"enabled": null}})));
        assert!(ssh.any_unsafe(&json!({"items": {"enabled": 1}})));
        let fw = spec("linux.firewall").unwrap();
        assert!(fw.any_unsafe(&json!({"items": {"enabled": null, "incoming": "deny"}})));
        let autologin = spec("linux.autologin").unwrap();
        assert!(
            !autologin.any_unsafe(&json!({"items": {"gdm_automatic": null, "lightdm_user": null}}))
        );
        let before = json!({"items": {"gdm_automatic": "true", "lightdm_user": "sam"}});
        assert_eq!(
            autologin.derive_target(&before).unwrap(),
            json!({"items": {"gdm_automatic": "false", "lightdm_user": null}})
        );
    }

    #[test]
    fn the_engine_catalog_lists_exactly_these_ids_for_linux() {
        let listed = crate::engine::catalog::ids(Os::Linux);
        let own: Vec<&str> = specs().iter().map(|s| s.id).collect();
        assert_eq!(listed, own);
    }
}
