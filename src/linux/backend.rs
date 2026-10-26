//! The Linux backend of the engine for the settings the whole computer shares: checks, fixes and undo, run by the root helper.
//!
//! Every control that needs a program the computer does not have reports "not eligible" with a plain reason. A fix writes
//! its exact before-image to the engine's journal first (the engine does that), changes one mechanism and is read back by
//! the engine; an undo writes the recorded value and is read back the same way.

use super::catalog::{self, Scope};
use super::cmd::Sys;
use super::controls::browser_policies::Ctl;
use super::controls::{self, detail, Cx, CHANGE_FAILED, MACHINE_ID_MISSING, READ_FAILED};
use super::distro::{self, Distro, Family};
use crate::model::{Backend, Control, Finding, Observation};
use anyhow::{bail, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn browser_control(id: &str) -> Option<Ctl> {
    Ctl::ALL.into_iter().find(|c| c.id() == id)
}

pub struct LinuxBackend<S: Sys> {
    sys: S,
    distro: Distro,
    memo: PathBuf,
}

const TEXT: [(&str, &str, &str); 51] = [
    (
        "linux.firewall",
        "Firewall",
        "Blocks connections from other computers that you did not ask for.",
    ),
    (
        "linux.fedora_open_ports",
        "Open network doors",
        "The standard Fedora setup leaves a wide range of network doors open to other computers.",
    ),
    (
        "linux.auto_updates",
        "Automatic security updates",
        "Installs important fixes by itself so the computer stays protected.",
    ),
    (
        "linux.ssh_server",
        "Remote sign-in",
        "Lets other computers sign in to this one over the network.",
    ),
    (
        "linux.ssh_password",
        "Remote sign-in passwords",
        "Whether people can sign in over the network with a password, and whether the main administrator account can.",
    ),
    (
        "linux.file_sharing",
        "Windows file sharing",
        "Shares folders with other computers on the network.",
    ),
    (
        "linux.autologin",
        "Automatic sign-in",
        "Signs in without asking for a password when the computer starts.",
    ),
    (
        "linux.guest",
        "Guest account",
        "Lets anyone use the computer without a password.",
    ),
    (
        "linux.kernel_protections",
        "Core protections",
        "Stops programs from reading private details of the system and of each other.",
    ),
    (
        "linux.crash_reports",
        "Crash reports",
        "Collects details about programs that crashed, which can include private information.",
    ),
    (
        "linux.countme",
        "Computer counting",
        "Lets Fedora count this computer each time it fetches updates.",
    ),
    (
        "linux.connectivity_check",
        "Internet check",
        "Contacts an outside address now and then to see if the internet works.",
    ),
    (
        "linux.wifi_mac",
        "Wi-Fi address",
        "Whether new Wi-Fi connections show the real hardware address of this computer to the network.",
    ),
    (
        "linux.ptrace",
        "Looking inside other programs",
        "Whether a program can look inside other programs that are running and read their secrets.",
    ),
    (
        "linux.network_redirects",
        "Network route changes",
        "Whether this computer obeys or hands out route changes that another computer on the network sends.",
    ),
    (
        "linux.llmnr",
        "Name lookups on the network",
        "Whether this computer answers name lookups from other computers on the local network.",
    ),
    (
        "linux.fake_sources",
        "Faked sender addresses",
        "Whether this computer throws away network messages that pretend to come from a place they could not have come from.",
    ),
    (
        "linux.flood_protection",
        "Protection from connection floods",
        "Whether this computer keeps answering real visitors when someone floods it with fake requests to connect.",
    ),
    (
        "linux.source_routing",
        "Messages that choose their own route",
        "Whether this computer follows network messages that say which way they must travel.",
    ),
    (
        "linux.broadcast_pings",
        "Calls to the whole network",
        "Whether this computer answers a single call that is sent to every computer on the network at once.",
    ),
    (
        "linux.ipv6_privacy",
        "Private network address",
        "Whether this computer uses a temporary address on newer networks, so websites cannot follow it by its address.",
    ),
    (
        "linux.computer_name_sent",
        "Computer name shared with networks",
        "Whether this computer tells every network it joins what its name is.",
    ),
    (
        "linux.encrypted_dns",
        "Private website lookups",
        "Whether this computer scrambles the questions it asks to find websites, so others on the network cannot read them.",
    ),
    (
        "linux.announce_name",
        "Announcing this computer",
        "Whether this computer tells others on the local network its name and what it offers.",
    ),
    (
        "linux.old_network_services",
        "Old network services",
        "Whether old remote services that send data without protection are running on this computer.",
    ),
    (
        "linux.time_sync",
        "Clock",
        "Sets the clock from the internet so it stays correct.",
    ),
    (
        "linux.printer_sharing",
        "Printer sharing",
        "Lets other computers on the network use your printers or manage printing here.",
    ),
    (
        "linux.printer_discovery",
        "Network printer finder",
        "Adds printers that other computers announce on the network without asking you.",
    ),
    (
        "linux.ubuntu_news",
        "Ubuntu news",
        "Downloads news and advertising from Ubuntu's makers to show in update messages and when you sign in.",
    ),
    (
        "linux.snap_updates",
        "App store updates",
        "Whether updates of apps from Ubuntu's app store are held back.",
    ),
    (
        "linux.browser_data_collection",
        "Browser usage data",
        "Whether your web browsers send details about how you use them to the companies that make them.",
    ),
    (
        "linux.browser_https_only",
        "Secure connections only",
        "Whether Firefox warns you before it opens a page that is not protected.",
    ),
    (
        "linux.memory_shuffle",
        "Memory layout",
        "Whether the system places each program's memory in a different spot every time, which makes attacks harder.",
    ),
    (
        "linux.bpf_hardening",
        "Small programs inside the system",
        "Whether ordinary users can load their own small programs into the system and how well those are guarded.",
    ),
    (
        "linux.terminal_drivers",
        "Old terminal drivers",
        "Whether any program can make the system load old drivers for text terminals.",
    ),
    (
        "linux.crash_memory",
        "Memory of crashed programs",
        "Whether programs that run with extra rights can leave a copy of their memory behind when they crash.",
    ),
    (
        "linux.crash_files",
        "Saved crash files",
        "Whether the memory of a crashed program is kept on the disk.",
    ),
    (
        "linux.rare_protocols",
        "Rarely used network protocols",
        "Whether rarely used ways of talking over the network can be switched on by any program.",
    ),
    (
        "linux.app_sandbox_limits",
        "Private boxes for apps",
        "Whether apps need permission before they make a private box for themselves.",
    ),
    (
        "linux.processor_updates",
        "Processor updates",
        "Whether the fixes for your computer's processor are installed.",
    ),
    (
        "linux.root_account",
        "Main administrator account",
        "Whether the account that can change everything on this computer can be signed in to with a password.",
    ),
    (
        "linux.bluetooth_autostart",
        "Bluetooth at start",
        "Whether Bluetooth switches itself on every time the computer starts.",
    ),
    (
        "linux.usage_survey",
        "Installed programs report",
        "Sends the list of programs installed on this computer to its makers once a week.",
    ),
    (
        "linux.browser_tracking",
        "Tracker blocking",
        "Whether your browsers stop websites from following you around the internet.",
    ),
    (
        "linux.browser_ad_topics",
        "Interest-based ads",
        "Whether Chrome and its relatives build a list of your interests and let sites use it for ads.",
    ),
    (
        "linux.browser_sponsored",
        "Sponsored shortcuts",
        "Whether Firefox shows paid shortcuts, stories and suggestions on the new tab page and in the address bar.",
    ),
    (
        "linux.browser_safe_browsing",
        "Warnings about dangerous sites",
        "Whether your browsers warn you before opening a site known to steal passwords or spread harmful programs.",
    ),
    (
        "linux.browser_password_leaks",
        "Leaked password warnings",
        "Whether your browser warns you when a saved password has shown up in a known data leak.",
    ),
    (
        "linux.browser_background",
        "Browser running after you close it",
        "Whether Chrome and its relatives keep running in the background after you close their windows.",
    ),
    (
        "linux.browser_search_suggestions",
        "Search suggestions while typing",
        "Whether your browsers send what you type in the address bar to a search company to suggest results.",
    ),
    (
        "linux.browser_encrypted_dns",
        "Private website lookups in browsers",
        "Whether your browsers hide which websites you look up from the network you are on.",
    ),
];

/// Every title and description a person can read, for the translation tests.
pub fn texts() -> Vec<&'static str> {
    TEXT.iter().flat_map(|(_, t, d)| [*t, *d]).collect()
}

impl<S: Sys> LinuxBackend<S> {
    /// `memo` is the folder, inside the protected state folder, where a fix keeps what its undo needs.
    pub fn new(sys: S, memo: PathBuf) -> Self {
        let os_release = ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|p| sys.read(Path::new(p)).ok().flatten())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let distro = distro::distro(&os_release, None);
        Self { sys, distro, memo }
    }

    pub fn with_distro(sys: S, distro: Distro, memo: PathBuf) -> Self {
        Self { sys, distro, memo }
    }

    fn cx(&self) -> Cx<'_> {
        Cx {
            sys: &self.sys,
            distro: &self.distro,
            memo: &self.memo,
        }
    }

    fn applies(&self, id: &str) -> bool {
        match id {
            "linux.fedora_open_ports" | "linux.countme" => self.distro.family == Family::Fedora,
            "linux.crash_reports" => self.distro.family == Family::Debian,
            "linux.ubuntu_news" | "linux.app_sandbox_limits" => self.distro.id == "ubuntu",
            "linux.crash_files" => self.distro.id != "ubuntu",
            "linux.bluetooth_autostart" => controls::devices::bluetooth_present(&self.cx()),
            "linux.usage_survey" => {
                self.distro.family == Family::Debian
                    && controls::devices::survey_present(&self.cx())
            }
            _ => true,
        }
    }

    fn system_spec(id: &str) -> Result<&'static catalog::LinuxSpec> {
        match catalog::spec(id) {
            Some(spec) if spec.scope == Scope::System => Ok(spec),
            _ => bail!("Unknown control id: {id}"),
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxBackend<super::cmd::RealSys> {
    /// The backend on this computer, keeping its notes inside the protected state folder.
    pub fn installed() -> Result<Self> {
        Ok(Self::new(super::cmd::RealSys, Self::notes_dir()?))
    }

    /// The protected folder for the helper's small notes, made if it is not there yet.
    pub fn notes_dir() -> Result<std::path::PathBuf> {
        use crate::platform::{unix, LINUX_NOTES};
        use anyhow::Context;
        let notes = crate::platform::state_dir()?.join(LINUX_NOTES);
        match std::fs::symlink_metadata(&notes) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => unix::create_private_dir(&notes)?,
            Err(e) => return Err(e.into()),
        }
        unix::check_private_dir(&notes, 0).context(
            "Secblitz cannot trust its data folder, so it will not change anything. Reinstall it from the software app.",
        )?;
        Ok(notes)
    }
}

impl<S: Sys> Backend for LinuxBackend<S> {
    fn machine_id(&mut self) -> Result<String> {
        let id = self
            .sys
            .read(Path::new("/etc/machine-id"))
            .ok()
            .flatten()
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_default();
        if id.is_empty() {
            return Err(controls::plain(MACHINE_ID_MISSING));
        }
        Ok(id)
    }

    fn controls(&self) -> Vec<Control> {
        TEXT.iter()
            .filter(|(id, _, _)| self.applies(id))
            .filter_map(|(id, title, description)| {
                let spec = Self::system_spec(id).ok()?;
                Some(Control {
                    id: (*id).into(),
                    title: (*title).into(),
                    description: (*description).into(),
                    target: spec.catalog_target(),
                    reboot: spec.reboot,
                })
            })
            .collect()
    }

    fn observe(&mut self, id: &str) -> Result<Observation> {
        Self::system_spec(id)?;
        let cx = self.cx();
        let result = match id {
            "linux.firewall" => controls::firewall::observe_firewall(&cx),
            "linux.fedora_open_ports" => controls::firewall::observe_open_ports(&cx),
            "linux.auto_updates" => controls::updates::observe(&cx),
            "linux.ssh_server" => controls::remote::observe_ssh_server(&cx),
            "linux.ssh_password" => controls::remote::observe_ssh_password(&cx),
            "linux.file_sharing" => controls::remote::observe_file_sharing(&cx),
            "linux.autologin" => controls::accounts::observe_autologin(&cx),
            "linux.guest" => controls::accounts::observe_guest(&cx),
            "linux.kernel_protections" => controls::kernel::observe(&cx),
            "linux.crash_reports" => controls::privacy::observe_crash_reports(&cx),
            "linux.countme" => controls::privacy::observe_countme(&cx),
            "linux.connectivity_check" => controls::privacy::observe_connectivity(&cx),
            "linux.wifi_mac" => controls::privacy::observe_wifi_mac(&cx),
            "linux.ptrace" => controls::kernel::observe_ptrace(&cx),
            "linux.network_redirects" => controls::network::observe_redirects(&cx),
            "linux.llmnr" => controls::network::observe_llmnr(&cx),
            "linux.fake_sources" => controls::netguard::observe_fake_sources(&cx),
            "linux.flood_protection" => controls::netguard::observe_flood_protection(&cx),
            "linux.source_routing" => controls::netguard::observe_source_routing(&cx),
            "linux.broadcast_pings" => controls::netguard::observe_broadcast_pings(&cx),
            "linux.ipv6_privacy" => controls::netguard::observe_ipv6_privacy(&cx),
            "linux.computer_name_sent" => controls::netguard::observe_computer_name(&cx),
            "linux.encrypted_dns" => controls::netguard::observe_encrypted_dns(&cx),
            "linux.announce_name" => controls::netguard::observe_announce_name(&cx),
            "linux.old_network_services" => controls::netguard::observe_old_services(&cx),
            "linux.time_sync" => controls::services::observe_time_sync(&cx),
            "linux.printer_sharing" => controls::services::observe_printer_sharing(&cx),
            "linux.printer_discovery" => controls::services::observe_printer_discovery(&cx),
            "linux.ubuntu_news" => controls::services::observe_ubuntu_news(&cx),
            "linux.snap_updates" => controls::services::observe_snap_updates(&cx),
            "linux.memory_shuffle" => controls::hardening::observe_memory_shuffle(&cx),
            "linux.bpf_hardening" => controls::hardening::observe_bpf(&cx),
            "linux.terminal_drivers" => controls::hardening::observe_terminal_drivers(&cx),
            "linux.crash_memory" => controls::hardening::observe_crash_memory(&cx),
            "linux.crash_files" => controls::hardening::observe_crash_files(&cx),
            "linux.rare_protocols" => controls::hardening::observe_rare_protocols(&cx),
            "linux.app_sandbox_limits" => controls::hardening::observe_app_sandbox(&cx),
            "linux.processor_updates" => controls::hardening::observe_processor_updates(&cx),
            "linux.root_account" => controls::hardening::observe_root_account(&cx),
            "linux.bluetooth_autostart" => controls::devices::observe_bluetooth(&cx),
            "linux.usage_survey" => controls::devices::observe_usage_survey(&cx),
            id if browser_control(id).is_some() => {
                controls::browsers::observe(&cx, browser_control(id).unwrap_or(Ctl::Data))
            }
            _ => bail!("Unknown control id: {id}"),
        };
        result.map_err(|e| detail(id, &e, READ_FAILED))
    }

    fn write(&mut self, id: &str, value: &Value) -> Result<()> {
        let spec = Self::system_spec(id)?;
        spec.validate(value)?;
        let want = controls::items_of(value)?;
        let cx = self.cx();
        let result = match id {
            "linux.firewall" => controls::firewall::write_firewall(&cx, &want),
            "linux.fedora_open_ports" => controls::firewall::write_open_ports(&cx, &want),
            "linux.auto_updates" => controls::updates::write(&cx, &want),
            "linux.ssh_server" => controls::remote::write_ssh_server(&cx, &want),
            "linux.ssh_password" => controls::remote::write_ssh_password(&cx, &want),
            "linux.file_sharing" => controls::remote::write_file_sharing(&cx, &want),
            "linux.autologin" => controls::accounts::write_autologin(&cx, &want),
            "linux.guest" => controls::accounts::write_guest(&cx, &want),
            "linux.kernel_protections" => controls::kernel::write(&cx, &want),
            "linux.crash_reports" => controls::privacy::write_crash_reports(&cx, &want),
            "linux.countme" => controls::privacy::write_countme(&cx, &want),
            "linux.connectivity_check" => controls::privacy::write_connectivity(&cx, &want),
            "linux.wifi_mac" => controls::privacy::write_wifi_mac(&cx, &want),
            "linux.ptrace" => controls::kernel::write_ptrace(&cx, &want),
            "linux.network_redirects" => controls::network::write_redirects(&cx, &want),
            "linux.llmnr" => controls::network::write_llmnr(&cx, &want),
            "linux.fake_sources" => controls::netguard::write_fake_sources(&cx, &want),
            "linux.flood_protection" => controls::netguard::write_flood_protection(&cx, &want),
            "linux.source_routing" => controls::netguard::write_source_routing(&cx, &want),
            "linux.broadcast_pings" => controls::netguard::write_broadcast_pings(&cx, &want),
            "linux.ipv6_privacy" => controls::netguard::write_ipv6_privacy(&cx, &want),
            "linux.computer_name_sent" => controls::netguard::write_computer_name(&cx, &want),
            "linux.encrypted_dns" => controls::netguard::write_encrypted_dns(&cx, &want),
            "linux.announce_name" => controls::netguard::write_announce_name(&cx, &want),
            "linux.old_network_services" => controls::netguard::write_old_services(&cx, &want),
            "linux.time_sync" => controls::services::write_time_sync(&cx, &want),
            "linux.printer_sharing" => controls::services::write_printer_sharing(&cx, &want),
            "linux.printer_discovery" => controls::services::write_printer_discovery(&cx, &want),
            "linux.ubuntu_news" => controls::services::write_ubuntu_news(&cx, &want),
            "linux.snap_updates" => controls::services::write_snap_updates(&cx, &want),
            id if browser_control(id).is_some() => {
                controls::browsers::write(&cx, browser_control(id).unwrap_or(Ctl::Data), &want)
            }
            "linux.memory_shuffle" => controls::hardening::write_memory_shuffle(&cx, &want),
            "linux.bpf_hardening" => controls::hardening::write_bpf(&cx, &want),
            "linux.terminal_drivers" => controls::hardening::write_terminal_drivers(&cx, &want),
            "linux.crash_memory" => controls::hardening::write_crash_memory(&cx, &want),
            "linux.crash_files" => controls::hardening::write_crash_files(&cx, &want),
            "linux.rare_protocols" => controls::hardening::write_rare_protocols(&cx, &want),
            "linux.app_sandbox_limits" => controls::hardening::write_app_sandbox(&cx, &want),
            "linux.processor_updates" => controls::hardening::write_processor_updates(&cx, &want),
            "linux.root_account" => controls::hardening::write_root_account(&cx, &want),
            "linux.bluetooth_autostart" => controls::devices::write_bluetooth(&cx, &want),
            "linux.usage_survey" => controls::devices::write_usage_survey(&cx, &want),
            _ => bail!("Unknown control id: {id}"),
        };
        result.map_err(|e| detail(id, &e, CHANGE_FAILED))
    }

    fn findings(&mut self) -> Result<Vec<Finding>> {
        Ok(controls::findings::collect(&self.cx()))
    }
}
