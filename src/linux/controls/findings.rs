//! Things Secblitz can only report: drive encryption, Secure Boot, waiting updates, a needed restart and the program
//! that confines other programs (AppArmor or SELinux). None of these has a fix; each one that cannot be told is reported
//! as not known, never as a problem.

use super::Cx;
use crate::advice::{
    ACCOUNTS_WITHOUT_PASSWORD, ADMIN_WITHOUT_PASSWORD, DISK_ENCRYPTION, HARDWARE_UPDATES,
    LINUX_SECURE_BOOT, PROGRAM_LIMITS, RESTART_NEEDED, SECURITY_SUPPORT, UNCHECKED_SOURCES,
    UPDATES_WAITING,
};
use crate::linux::cmd::Output;
use crate::linux::distro::{field, Family};
use crate::model::{CheckStatus, Finding};
use std::path::Path;

pub const ENCRYPTED: &str = "The main drive is encrypted.";
pub const NOT_ENCRYPTED: &str = "The main drive is not encrypted.";
pub const ENCRYPTION_UNKNOWN: &str = "Secblitz could not tell if the main drive is encrypted.";
pub const SECURE_BOOT_ON: &str = "Secure Boot is on.";
pub const SECURE_BOOT_OFF: &str = "Secure Boot is off.";
pub const SECURE_BOOT_UNKNOWN: &str = "Secblitz could not tell if Secure Boot is on.";
pub const SECURE_BOOT_UNSUPPORTED: &str =
    "This computer cannot use Secure Boot, so there is nothing to turn on.";
pub const NO_UPDATES: &str = "No updates are waiting.";
pub const UPDATES: &str = "Updates are waiting to be installed.";
pub const UPDATES_UNKNOWN: &str = "Secblitz could not tell if updates are waiting.";
pub const NO_RESTART: &str = "No restart is needed.";
pub const RESTART: &str = "A restart is needed to finish installing updates.";
pub const APPARMOR_ON: &str = "AppArmor is on and keeps some programs in check.";
pub const APPARMOR_OFF: &str = "AppArmor is not running.";
pub const SELINUX_ON: &str = "SELinux is on and enforcing its rules.";
pub const SELINUX_OFF: &str = "SELinux is not enforcing its rules.";

pub const PASSWORDS_SET: &str = "Every account needs a password to sign in.";
pub const PASSWORD_MISSING: &str = "At least one account can be used without a password.";
pub const ADMIN_ASKS: &str = "No account can use admin rights without typing a password.";
pub const ADMIN_NEVER_ASKS: &str =
    "At least one account can use admin rights without typing a password.";
pub const SOURCES_CHECKED: &str = "All software sources are checked for safety.";
pub const SOURCES_UNCHECKED: &str = "At least one software source is not checked for safety.";
pub const SUPPORT_LONG: &str =
    "Your version of Linux still gets security updates for a good while.";
pub const SUPPORT_SOON: &str = "Security updates for your version of Linux end soon.";
pub const SUPPORT_ENDED: &str = "Security updates for your version of Linux have ended.";
pub const NO_HARDWARE_UPDATES: &str = "No updates are waiting for the parts inside your computer.";
pub const HARDWARE_WAITING: &str = "Updates are waiting for the parts inside your computer.";

pub const SENTENCES: [&str; 27] = [
    ENCRYPTED,
    NOT_ENCRYPTED,
    ENCRYPTION_UNKNOWN,
    SECURE_BOOT_ON,
    SECURE_BOOT_OFF,
    SECURE_BOOT_UNKNOWN,
    SECURE_BOOT_UNSUPPORTED,
    NO_UPDATES,
    UPDATES,
    UPDATES_UNKNOWN,
    NO_RESTART,
    RESTART,
    APPARMOR_ON,
    APPARMOR_OFF,
    SELINUX_ON,
    SELINUX_OFF,
    PASSWORDS_SET,
    PASSWORD_MISSING,
    ADMIN_ASKS,
    ADMIN_NEVER_ASKS,
    SOURCES_CHECKED,
    SOURCES_UNCHECKED,
    SUPPORT_LONG,
    SUPPORT_SOON,
    SUPPORT_ENDED,
    NO_HARDWARE_UPDATES,
    HARDWARE_WAITING,
];

pub const TITLES: [&str; 10] = [
    DISK_ENCRYPTION,
    LINUX_SECURE_BOOT,
    UPDATES_WAITING,
    RESTART_NEEDED,
    PROGRAM_LIMITS,
    ACCOUNTS_WITHOUT_PASSWORD,
    ADMIN_WITHOUT_PASSWORD,
    UNCHECKED_SOURCES,
    SECURITY_SUPPORT,
    HARDWARE_UPDATES,
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

enum SecureBoot {
    On(bool),
    Unsupported,
}

fn secure_boot(cx: &Cx) -> Option<SecureBoot> {
    match cx.sys.read(Path::new(SECURE_BOOT_VARIABLE)).ok()? {
        // Four bytes of attributes, then the value.
        Some(bytes) => (bytes.len() >= 5).then(|| SecureBoot::On(bytes[4] == 1)),
        // No variable is also what an unmounted efivarfs looks like, so only mokutil's own answer counts.
        None => {
            let out = cx.run("/usr/bin/mokutil", &["--sb-state"]).ok()?;
            format!("{}{}", out.stdout, out.stderr)
                .contains("doesn't support Secure Boot")
                .then_some(SecureBoot::Unsupported)
        }
    }
}

/// A fresh install has no package lists yet, and the cache-only call says so. Then the same question is asked once
/// again with downloading allowed, which also fills the cache for the next time.
fn dnf(cx: &Cx, args: &[&str]) -> Option<Output> {
    let cached: Vec<&str> = std::iter::once("-C").chain(args.iter().copied()).collect();
    let out = cx.run("/usr/bin/dnf5", &cached).ok()?;
    if !out.success() && format!("{}{}", out.stdout, out.stderr).contains("no cache") {
        return cx.sys.run_long("/usr/bin/dnf5", args).ok();
    }
    Some(out)
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
        let out = dnf(cx, &["check-upgrade"])?;
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
        // Exit 1 also means "nothing cached yet", so the answer comes from its sentence (the locale is C).
        let out = dnf(cx, &["needs-restarting", "-r"])?;
        return if out.stdout.contains("Reboot should not be necessary") {
            Some(false)
        } else if out.stdout.contains("Reboot is required") {
            Some(true)
        } else {
            None
        };
    }
    Some(
        cx.sys
            .read(Path::new("/run/reboot-required"))
            .ok()?
            .is_some(),
    )
}

fn without_password(cx: &Cx) -> Option<bool> {
    let shadow = cx.text("/etc/shadow").ok()??;
    Some(
        shadow
            .lines()
            .filter(|l| !l.trim().is_empty())
            .any(|l| l.split(':').nth(1) == Some("")),
    )
}

/// Whether a sudoers line gives some account every command without asking for a password.
fn rule_never_asks(line: &str) -> bool {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with("Defaults") {
        return false;
    }
    let Some((_, rest)) = line.split_once('=') else {
        return false;
    };
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix('(') {
        Some(after) => after.split_once(')').map_or("", |(_, r)| r),
        None => rest,
    };
    let mut no_password = false;
    for part in rest.split(',') {
        let mut part = part.trim();
        while let Some((tag, after)) = part.split_once(':') {
            if tag.is_empty() || !tag.chars().all(|c| c.is_ascii_alphabetic()) {
                break;
            }
            match tag {
                "NOPASSWD" => no_password = true,
                "PASSWD" => no_password = false,
                _ => {}
            }
            part = after.trim_start();
        }
        if no_password && part == "ALL" {
            return true;
        }
    }
    false
}

fn admin_never_asks(cx: &Cx) -> Option<bool> {
    let main = cx.text("/etc/sudoers").ok()??;
    let mut texts = vec![main.clone()];
    let includes_folder = main.lines().any(|l| {
        let l = l.trim();
        ["@includedir", "#includedir"]
            .iter()
            .any(|key| l.strip_prefix(key).map(str::trim) == Some("/etc/sudoers.d"))
    });
    if includes_folder {
        for name in cx.list("/etc/sudoers.d") {
            if name.contains('.') || name.ends_with('~') {
                continue;
            }
            if let Ok(Some(text)) = cx.text(&format!("/etc/sudoers.d/{name}")) {
                texts.push(text);
            }
        }
    }
    Some(texts.iter().any(|t| t.lines().any(rule_never_asks)))
}

fn is_yes(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("yes")
}

fn apt_list_unchecked(text: &str) -> bool {
    text.lines().map(str::trim).any(|l| {
        let l = l.to_ascii_lowercase();
        !l.starts_with('#') && (l.contains("trusted=yes") || l.contains("allow-insecure=yes"))
    })
}

fn apt_sources_unchecked(text: &str) -> bool {
    text.split("\n\n").any(|stanza| {
        let mut unchecked = false;
        let mut enabled = true;
        for line in stanza.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim().to_ascii_lowercase().as_str() {
                "trusted" | "allow-insecure" => unchecked |= is_yes(value),
                "enabled" => enabled = is_yes(value),
                _ => {}
            }
        }
        unchecked && enabled
    })
}

fn repo_unchecked(text: &str) -> bool {
    let mut checks_off = false;
    let mut enabled = true;
    let mut found = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            found |= checks_off && enabled;
            checks_off = false;
            enabled = true;
        } else if let Some((key, value)) = line.split_once('=') {
            match (key.trim(), value.trim()) {
                ("gpgcheck", "0") => checks_off = true,
                ("enabled", "0") => enabled = false,
                _ => {}
            }
        }
    }
    found || (checks_off && enabled)
}

fn unchecked_sources(cx: &Cx) -> Option<bool> {
    let mut seen = false;
    let mut bad = false;
    let mut look = |path: &str, test: fn(&str) -> bool| {
        if let Ok(Some(text)) = cx.text(path) {
            seen = true;
            bad |= test(&text);
        }
    };
    look("/etc/apt/sources.list", apt_list_unchecked);
    for name in cx.list("/etc/apt/sources.list.d") {
        let path = format!("/etc/apt/sources.list.d/{name}");
        if name.ends_with(".list") {
            look(&path, apt_list_unchecked);
        } else if name.ends_with(".sources") {
            look(&path, apt_sources_unchecked);
        }
    }
    look("/etc/dnf/dnf.conf", repo_unchecked);
    for name in cx.list("/etc/yum.repos.d") {
        if name.ends_with(".repo") {
            look(&format!("/etc/yum.repos.d/{name}"), repo_unchecked);
        }
    }
    seen.then_some(bad)
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date.
fn day_number(date: &str) -> Option<i64> {
    let mut parts = date.trim().splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn csv_end(csv: &str, codename: &str) -> Option<i64> {
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next()?.split(',').collect();
    let series = header.iter().position(|h| *h == "series")?;
    let eol = header.iter().position(|h| *h == "eol")?;
    lines.find_map(|l| {
        let cells: Vec<&str> = l.split(',').collect();
        (cells.get(series) == Some(&codename))
            .then(|| cells.get(eol).and_then(|c| day_number(c)))
            .flatten()
    })
}

fn support_end(cx: &Cx) -> Option<i64> {
    let release = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|p| cx.text(p).ok().flatten())?;
    if let Some(end) = field(&release, "SUPPORT_END").and_then(day_number) {
        return Some(end);
    }
    let named = |key| field(&release, key).filter(|n| !n.is_empty());
    let (file, codename) = if let Some(name) = named("UBUNTU_CODENAME") {
        ("ubuntu.csv", name)
    } else if field(&release, "ID") == Some("debian") {
        ("debian.csv", named("VERSION_CODENAME")?)
    } else {
        return None;
    };
    let csv = cx.text(&format!("/usr/share/distro-info/{file}")).ok()??;
    csv_end(&csv, codename)
}

fn today(cx: &Cx) -> Option<i64> {
    let out = cx.run("/usr/bin/date", &["-u", "+%F"]).ok()?;
    out.success().then(|| day_number(&out.stdout)).flatten()
}

fn security_support(cx: &Cx) -> Option<Finding> {
    let left = support_end(cx)? - today(cx)?;
    let (status, detail) = match left {
        l if l > 90 => (CheckStatus::Ok, SUPPORT_LONG),
        l if l >= 0 => (CheckStatus::Attention, SUPPORT_SOON),
        _ => (CheckStatus::Attention, SUPPORT_ENDED),
    };
    Some(Finding {
        title: SECURITY_SUPPORT.into(),
        status,
        detail: detail.into(),
    })
}

fn hardware_updates(cx: &Cx) -> Option<bool> {
    let out = cx
        .run(
            "/usr/bin/fwupdmgr",
            &[
                "get-updates",
                "--json",
                "--no-unreported-check",
                "--no-metadata-check",
            ],
        )
        .ok()?;
    let answer: serde_json::Value = serde_json::from_str(&out.stdout).ok()?;
    Some(!answer.get("Devices")?.as_array()?.is_empty())
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
        match secure_boot(cx) {
            Some(SecureBoot::Unsupported) => Finding {
                title: TITLES[1].into(),
                status: CheckStatus::Info,
                detail: SECURE_BOOT_UNSUPPORTED.into(),
            },
            other => finding(
                TITLES[1],
                match other {
                    Some(SecureBoot::On(on)) => Some(on),
                    _ => None,
                },
                SECURE_BOOT_ON,
                SECURE_BOOT_OFF,
                SECURE_BOOT_UNKNOWN,
            ),
        },
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
            found.push(finding(TITLES[4], enforcing, SELINUX_ON, SELINUX_OFF, ""));
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
    if let Some(none) = without_password(cx).map(|any| !any) {
        found.push(finding(
            TITLES[5],
            Some(none),
            PASSWORDS_SET,
            PASSWORD_MISSING,
            "",
        ));
    }
    if let Some(asks) = admin_never_asks(cx).map(|any| !any) {
        found.push(finding(
            TITLES[6],
            Some(asks),
            ADMIN_ASKS,
            ADMIN_NEVER_ASKS,
            "",
        ));
    }
    if let Some(checked) = unchecked_sources(cx).map(|any| !any) {
        found.push(finding(
            TITLES[7],
            Some(checked),
            SOURCES_CHECKED,
            SOURCES_UNCHECKED,
            "",
        ));
    }
    found.extend(security_support(cx));
    if let Some(waiting) = hardware_updates(cx) {
        let (status, detail) = if waiting {
            (CheckStatus::Info, HARDWARE_WAITING)
        } else {
            (CheckStatus::Ok, NO_HARDWARE_UPDATES)
        };
        found.push(Finding {
            title: TITLES[9].into(),
            status,
            detail: detail.into(),
        });
    }
    found
}
