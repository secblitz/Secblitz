//! Things Secblitz can only report: drive encryption, Secure Boot, waiting updates, a needed restart and the program
//! that confines other programs (AppArmor or SELinux). None of these has a fix; each one that cannot be told is reported
//! as not known, never as a problem.

use super::Cx;
use crate::linux::distro::Family;
use crate::model::{CheckStatus, Finding};
use std::path::Path;

pub const ENCRYPTED: &str = "The main drive is encrypted.";
pub const NOT_ENCRYPTED: &str = "The main drive is not encrypted.";
pub const ENCRYPTION_UNKNOWN: &str = "Secblitz could not tell if the main drive is encrypted.";
pub const SECURE_BOOT_ON: &str = "Secure Boot is on.";
pub const SECURE_BOOT_OFF: &str = "Secure Boot is off.";
pub const SECURE_BOOT_UNKNOWN: &str = "Secblitz could not tell if Secure Boot is on.";
pub const NO_UPDATES: &str = "No updates are waiting.";
pub const UPDATES: &str = "Updates are waiting to be installed.";
pub const UPDATES_UNKNOWN: &str = "Secblitz could not tell if updates are waiting.";
pub const NO_RESTART: &str = "No restart is needed.";
pub const RESTART: &str = "A restart is needed to finish installing updates.";
pub const APPARMOR_ON: &str = "AppArmor is on and keeps some programs in check.";
pub const APPARMOR_OFF: &str = "AppArmor is not running.";
pub const SELINUX_ON: &str = "SELinux is on and enforcing its rules.";
pub const SELINUX_OFF: &str = "SELinux is not enforcing its rules.";

pub const SENTENCES: [&str; 15] = [
    ENCRYPTED,
    NOT_ENCRYPTED,
    ENCRYPTION_UNKNOWN,
    SECURE_BOOT_ON,
    SECURE_BOOT_OFF,
    SECURE_BOOT_UNKNOWN,
    NO_UPDATES,
    UPDATES,
    UPDATES_UNKNOWN,
    NO_RESTART,
    RESTART,
    APPARMOR_ON,
    APPARMOR_OFF,
    SELINUX_ON,
    SELINUX_OFF,
];

pub const TITLES: [&str; 6] = [
    "Device encryption",
    "Secure Boot",
    "Updates waiting",
    "Restart needed",
    "AppArmor",
    "SELinux",
];

const SECURE_BOOT_VARIABLE: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

fn finding(title: &str, ok: Option<bool>, good: &str, bad: &str, unknown: &str) -> Finding {
    let (status, detail) = match ok {
        Some(true) => (CheckStatus::Ok, good),
        Some(false) => (CheckStatus::Attention, bad),
        None => (CheckStatus::Unknown, unknown),
    };
    Finding {
        title: title.into(),
        status,
        detail: detail.into(),
    }
}

fn encrypted(cx: &Cx) -> Option<bool> {
    let source = cx
        .run("/usr/bin/findmnt", &["-n", "-o", "SOURCE", "/"])
        .ok()?;
    if !source.success() {
        return None;
    }
    let source = source.stdout.trim();
    let device = source.split('[').next().unwrap_or("");
    if !device.starts_with("/dev/") || device.contains(char::is_whitespace) {
        return None;
    }
    let chain = cx
        .run("/usr/bin/lsblk", &["-s", "-n", "-o", "TYPE", device])
        .ok()?;
    chain
        .success()
        .then(|| chain.stdout.lines().any(|l| l.trim() == "crypt"))
}

fn secure_boot(cx: &Cx) -> Option<bool> {
    let bytes = cx.sys.read(Path::new(SECURE_BOOT_VARIABLE)).ok()??;
    // Four bytes of attributes, then the value.
    (bytes.len() >= 5).then(|| bytes[4] == 1)
}

fn updates_waiting(cx: &Cx) -> Option<bool> {
    if let Ok(out) = cx.run("/usr/lib/update-notifier/apt-check", &[]) {
        if out.success() {
            let text = format!("{} {}", out.stdout, out.stderr);
            let count = text.split_whitespace().find_map(|w| {
                w.split(';')
                    .next()?
                    .parse::<u32>()
                    .ok()
                    .filter(|_| w.contains(';'))
            })?;
            return Some(count > 0);
        }
    }
    if cx.distro.family == Family::Fedora {
        let out = cx.run("/usr/bin/dnf5", &["-C", "check-upgrade"]).ok()?;
        return match out.status {
            0 => Some(false),
            100 => Some(true),
            _ => None,
        };
    }
    let out = cx.run("/usr/bin/apt-get", &["-s", "upgrade"]).ok()?;
    out.success()
        .then(|| out.stdout.lines().any(|l| l.starts_with("Inst ")))
}

fn restart_needed(cx: &Cx) -> Option<bool> {
    if cx.distro.family == Family::Fedora {
        let out = cx.run("/usr/bin/dnf5", &["needs-restarting", "-r"]).ok()?;
        return match out.status {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
    }
    Some(
        cx.sys
            .read(Path::new("/run/reboot-required"))
            .ok()?
            .is_some(),
    )
}

pub fn collect(cx: &Cx) -> Vec<Finding> {
    let mut found = vec![
        finding(
            TITLES[0],
            encrypted(cx),
            ENCRYPTED,
            NOT_ENCRYPTED,
            ENCRYPTION_UNKNOWN,
        ),
        finding(
            TITLES[1],
            secure_boot(cx),
            SECURE_BOOT_ON,
            SECURE_BOOT_OFF,
            SECURE_BOOT_UNKNOWN,
        ),
        finding(
            TITLES[2],
            updates_waiting(cx).map(|waiting| !waiting),
            NO_UPDATES,
            UPDATES,
            UPDATES_UNKNOWN,
        ),
    ];
    if let Some(needed) = restart_needed(cx) {
        found.push(finding(TITLES[3], Some(!needed), NO_RESTART, RESTART, ""));
    }
    if cx.distro.family == Family::Fedora {
        let enforcing = cx
            .sys
            .read(Path::new("/sys/fs/selinux/enforce"))
            .ok()
            .map(|b| b.is_some_and(|b| b.first() == Some(&b'1')));
        if enforcing.is_some() {
            found.push(finding(TITLES[5], enforcing, SELINUX_ON, SELINUX_OFF, ""));
        }
    } else {
        let on = cx
            .sys
            .read(Path::new("/sys/module/apparmor/parameters/enabled"))
            .ok()
            .map(|b| b.is_some_and(|b| b.first() == Some(&b'Y')));
        if on.is_some() {
            found.push(finding(TITLES[4], on, APPARMOR_ON, APPARMOR_OFF, ""));
        }
    }
    found
}
