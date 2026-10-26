//! The Linux backend of the engine for the settings the whole computer shares: checks, fixes and undo, run by the root helper.
//!
//! Every control that needs a program the computer does not have reports "not eligible" with a plain reason. A fix writes
//! its exact before-image to the engine's journal first (the engine does that), changes one mechanism and is read back by
//! the engine; an undo writes the recorded value and is read back the same way.

use super::catalog::{self, Scope};
use super::cmd::Sys;
use super::controls::{self, detail, Cx, CHANGE_FAILED, MACHINE_ID_MISSING, READ_FAILED};
use super::distro::{self, Distro, Family};
use crate::model::{Backend, Control, Finding, Observation};
use anyhow::{bail, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct LinuxBackend<S: Sys> {
    sys: S,
    distro: Distro,
    memo: PathBuf,
}

const TEXT: [(&str, &str, &str); 21] = [
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
            "linux.ubuntu_news" => self.distro.id == "ubuntu",
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
        Ok(Self::new(super::cmd::RealSys, notes))
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
            "linux.time_sync" => controls::services::observe_time_sync(&cx),
            "linux.printer_sharing" => controls::services::observe_printer_sharing(&cx),
            "linux.printer_discovery" => controls::services::observe_printer_discovery(&cx),
            "linux.ubuntu_news" => controls::services::observe_ubuntu_news(&cx),
            "linux.snap_updates" => controls::services::observe_snap_updates(&cx),
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
            "linux.time_sync" => controls::services::write_time_sync(&cx, &want),
            "linux.printer_sharing" => controls::services::write_printer_sharing(&cx, &want),
            "linux.printer_discovery" => controls::services::write_printer_discovery(&cx, &want),
            "linux.ubuntu_news" => controls::services::write_ubuntu_news(&cx, &want),
            "linux.snap_updates" => controls::services::write_snap_updates(&cx, &want),
            _ => bail!("Unknown control id: {id}"),
        };
        result.map_err(|e| detail(id, &e, CHANGE_FAILED))
    }

    fn findings(&mut self) -> Result<Vec<Finding>> {
        Ok(controls::findings::collect(&self.cx()))
    }
}
