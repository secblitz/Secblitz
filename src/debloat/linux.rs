//! Clean up apps on Linux: remote-control apps that keep a background service running.
//!
//! Only packages named in the catalog are ever listed or removed. Every removal is first
//! simulated with the package manager and refused unless it would take away nothing but that
//! app's own packages, so a meta-package, the desktop, a browser or the software app can never
//! go with it. Nothing like `autoremove` ever runs.
use super::{App, Group, Installed, PackageOutcome};
use crate::linux::cmd::Sys;
use crate::linux::distro::{detect, Family};
use anyhow::{bail, ensure, Result};
use std::path::Path;

const RECORD: &str = "/var/lib/secblitz/Linux/removed-apps.txt";
const RECORD_LIMIT: usize = 64;

/// An app Secblitz took off this computer, as the helper wrote it down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removed {
    pub index: u16,
    pub package: String,
    pub t: u64,
    /// The app's other packages that went with it, such as `transmission-gtk` with `transmission-common`.
    pub also: Vec<String>,
}

const ALSO_LIMIT: usize = 16;

/// The packages in `names` that belong to the same catalog app as the one at `index`, `package` itself left out.
fn same_app(index: u16, package: &str, names: &[String]) -> Vec<String> {
    let mut also: Vec<String> = Vec::new();
    for name in names {
        if name != package
            && is_valid_package(name)
            && owner(name) == Some(index)
            && !also.contains(name)
            && also.len() < ALSO_LIMIT
        {
            also.push(name.clone());
        }
    }
    also
}

pub static CATALOG: &[App] = &[
    app("teamviewer*", "TeamViewer"),
    app("anydesk", "AnyDesk"),
    app("rustdesk", "RustDesk"),
    app("xrdp", "xrdp"),
    app("x11vnc", "x11vnc"),
    app("vino", "Vino"),
    sharing("transmission-*", "Transmission"),
    sharing("warpinator", "Warpinator"),
];

const fn app(family: &'static str, name: &'static str) -> App {
    App {
        family,
        name,
        group: Group::RemoteAccess,
        store_id: None,
    }
}

const fn sharing(family: &'static str, name: &'static str) -> App {
    App {
        family,
        name,
        group: Group::Sharing,
        store_id: None,
    }
}

pub const LIST_FAILED: &str =
    "Secblitz could not look up the apps on this computer. Try again in a moment.";
pub const REFUSED: &str = "Removing this app would also remove other programs your computer needs, so Secblitz left it alone.";
pub const FAILED: &str =
    "The app could not be removed. Wait for any software installation to finish, then try again.";
pub const RUN_FAILED: &str =
    "Secblitz could not remove the apps. Nothing else was changed. Try again in a moment.";
pub const NOT_INSTALLED: &str =
    "Secblitz is not fully installed. Reinstall it from the software app.";
pub const NOT_ALLOWED: &str = "Secblitz needs your password to change this.";
pub const INSTALL_FAILED: &str =
    "The app could not be installed again. Check that this computer is online, then try again.";
pub const NOT_RECORDED: &str = "Secblitz has no record of removing this app, so it was left alone.";
pub const INSTALL_REFUSED: &str =
    "Installing this app again would remove other programs, so Secblitz left it alone.";

/// The sentences a Linux removal or reinstall can end with, so the page can show them as they are.
pub const SENTENCES: [&str; 9] = [
    LIST_FAILED,
    REFUSED,
    FAILED,
    RUN_FAILED,
    NOT_INSTALLED,
    NOT_ALLOWED,
    INSTALL_FAILED,
    NOT_RECORDED,
    INSTALL_REFUSED,
];

pub fn plain(raw: &str) -> Option<&'static str> {
    SENTENCES.iter().copied().find(|s| *s == raw)
}

/// A package name as both package managers write it.
pub fn is_valid_package(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+._-".contains(&b))
}

/// The catalog entry (as an index into [`super::catalog`]) a package belongs to.
pub fn owner(package: &str) -> Option<u16> {
    if !is_valid_package(package) {
        return None;
    }
    let first = super::catalog::CATALOG.len();
    CATALOG
        .iter()
        .position(|app| super::catalog::matches(app.family, package))
        .map(|i| (first + i) as u16)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Manager {
    Apt,
    Dnf,
}

pub fn manager(sys: &dyn Sys) -> Result<Manager> {
    match detect(sys, None).family {
        Family::Debian => Ok(Manager::Apt),
        Family::Fedora => Ok(Manager::Dnf),
        Family::Other => bail!(crate::space::linux::NOT_ON_THIS_SYSTEM),
    }
}

/// Everything installed that belongs to a catalog app.
pub fn inventory(sys: &dyn Sys) -> Result<Vec<Installed>> {
    let out = match manager(sys)? {
        Manager::Apt => sys.run(
            "/usr/bin/dpkg-query",
            &["-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"],
        )?,
        Manager::Dnf => sys.run(
            "/usr/bin/rpm",
            &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        )?,
    };
    ensure!(out.success(), LIST_FAILED);
    let mut found: Vec<Installed> = out
        .stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let (name, version) = (parts.next()?, parts.next()?);
            if let Some(status) = parts.next() {
                if !status.starts_with('i') {
                    return None;
                }
            }
            owner(name).map(|index| Installed {
                index,
                package: name.to_owned(),
                version: version.chars().take(64).collect(),
            })
        })
        .collect();
    found.sort_by(|a, b| (a.index, &a.package).cmp(&(b.index, &b.package)));
    found.dedup_by(|a, b| a.package == b.package);
    Ok(found)
}

/// The installed apps that can be taken off without taking anything else. One whose plan cannot be read right now stays listed; the removal checks again.
pub fn listable(sys: &dyn Sys) -> Result<Vec<Installed>> {
    let manager = manager(sys)?;
    Ok(inventory(sys)?
        .into_iter()
        .filter(|found| match simulate(sys, manager, &found.package) {
            Ok(plan) => gate(&found.package, &plan).is_ok(),
            Err(_) => true,
        })
        .collect())
}

/// The packages the package manager says removing `package` would take away.
pub fn simulate(sys: &dyn Sys, manager: Manager, package: &str) -> Result<Vec<String>> {
    ensure!(is_valid_package(package), REFUSED);
    match manager {
        Manager::Apt => {
            let out = sys.run("/usr/bin/apt-get", &["-s", "remove", package])?;
            ensure!(out.success(), FAILED);
            Ok(out
                .stdout
                .lines()
                .filter_map(|line| line.strip_prefix("Remv "))
                .filter_map(|rest| rest.split_whitespace().next())
                .map(|name| name.split(':').next().unwrap_or(name).to_owned())
                .collect())
        }
        Manager::Dnf => {
            let out = sys.run(
                "/usr/bin/dnf",
                &["remove", "--assumeno", "--no-autoremove", package],
            )?;
            let mut inside = false;
            let mut names = Vec::new();
            for line in out.stdout.lines() {
                if line.starts_with("Removing") {
                    inside = true;
                } else if !line.starts_with(' ') {
                    inside = false;
                } else if inside {
                    if let Some(name) = line.split_whitespace().next() {
                        names.push(name.to_owned());
                    }
                }
            }
            ensure!(
                !names.is_empty() || out.stdout.contains("No packages to remove"),
                FAILED
            );
            Ok(names)
        }
    }
}

/// Whether a simulated removal of `package` takes only packages that belong to the same catalog app.
pub fn gate(package: &str, planned: &[String]) -> Result<()> {
    let Some(index) = owner(package) else {
        bail!(REFUSED);
    };
    let first = super::catalog::CATALOG.len();
    let entry = &CATALOG[usize::from(index) - first];
    ensure!(
        planned
            .iter()
            .all(|name| super::catalog::matches(entry.family, name)),
        REFUSED
    );
    Ok(())
}

fn installed(sys: &dyn Sys, manager: Manager, package: &str) -> Result<bool> {
    Ok(match manager {
        Manager::Apt => {
            let out = sys.run(
                "/usr/bin/dpkg-query",
                &["-W", "-f=${db:Status-Abbrev}", package],
            )?;
            out.success() && out.stdout.trim_start().starts_with('i')
        }
        Manager::Dnf => sys.run("/usr/bin/rpm", &["-q", package])?.success(),
    })
}

/// Simulates, checks the plan and removes one app's package, then reads back that it is gone.
pub fn remove_package(sys: &dyn Sys, package: &str) -> PackageOutcome {
    let attempt = || -> Result<()> {
        let manager = manager(sys)?;
        gate(package, &simulate(sys, manager, package)?)?;
        if !installed(sys, manager, package)? {
            return Ok(());
        }
        let out = match manager {
            Manager::Apt => sys.run_long("/usr/bin/apt-get", &["remove", "-y", package])?,
            Manager::Dnf => sys.run_long(
                "/usr/bin/dnf",
                &["remove", "-y", "--no-autoremove", package],
            )?,
        };
        ensure!(out.success(), FAILED);
        ensure!(!installed(sys, manager, package)?, FAILED);
        Ok(())
    };
    match attempt() {
        Ok(()) => PackageOutcome::Removed,
        Err(e) => PackageOutcome::Failed(plain(&e.to_string()).unwrap_or(FAILED).to_owned()),
    }
}

fn read_record(sys: &dyn Sys) -> Result<Vec<Removed>> {
    let Some(bytes) = sys.read(Path::new(RECORD))? else {
        return Ok(Vec::new());
    };
    let mut seen: Vec<Removed> = Vec::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        let mut parts = line.split('\t');
        let (Some(package), Some(t)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Some(index), Ok(t)) = (owner(package), t.parse::<u64>()) else {
            continue;
        };
        let others: Vec<String> = parts
            .next()
            .unwrap_or("")
            .split(' ')
            .map(str::to_owned)
            .collect();
        seen.retain(|r| r.package != package);
        seen.push(Removed {
            index,
            package: package.to_owned(),
            t,
            also: same_app(index, package, &others),
        });
    }
    let extra = seen.len().saturating_sub(RECORD_LIMIT);
    seen.drain(..extra);
    Ok(seen)
}

fn write_record(sys: &dyn Sys, entries: &[Removed]) -> Result<()> {
    if entries.is_empty() {
        return sys.remove(Path::new(RECORD));
    }
    let mut text = String::new();
    for entry in entries {
        if entry.also.is_empty() {
            text.push_str(&format!("{}\t{}\n", entry.package, entry.t));
        } else {
            let also = entry.also.join(" ");
            text.push_str(&format!("{}\t{}\t{also}\n", entry.package, entry.t));
        }
    }
    sys.write_atomic(Path::new(RECORD), text.as_bytes(), 0o600)
}

/// Writes down that `package` was removed together with the packages in `taken` that belong to the same app,
/// replacing an earlier line for it and keeping the newest lines.
pub fn record_removal(sys: &dyn Sys, package: &str, taken: &[String], now: u64) -> Result<()> {
    let Some(index) = owner(package) else {
        bail!(NOT_RECORDED);
    };
    let mut entries = read_record(sys)?;
    entries.retain(|r| r.package != package);
    entries.push(Removed {
        index,
        package: package.to_owned(),
        t: now,
        also: same_app(index, package, taken),
    });
    let extra = entries.len().saturating_sub(RECORD_LIMIT);
    entries.drain(..extra);
    write_record(sys, &entries)
}

/// Removes `package` like [`remove_package`] and, when it really was installed and is now gone, writes it down so it can be put back.
pub fn remove_recorded(sys: &dyn Sys, package: &str, now: u64) -> PackageOutcome {
    let (was_installed, taken) = match manager(sys) {
        Ok(m) => (
            installed(sys, m, package).unwrap_or(false),
            simulate(sys, m, package).unwrap_or_default(),
        ),
        Err(_) => (false, Vec::new()),
    };
    let outcome = remove_package(sys, package);
    if was_installed && outcome == PackageOutcome::Removed {
        if let Err(error) = record_removal(sys, package, &taken, now) {
            eprintln!("Could not write down the removal of {package}: {error:#}");
        }
    }
    outcome
}

/// The recorded apps that are not on this computer now, oldest first.
pub fn removed(sys: &dyn Sys) -> Result<Vec<Removed>> {
    let manager = manager(sys)?;
    let mut gone = Vec::new();
    for entry in read_record(sys)? {
        if !installed(sys, manager, &entry.package)? {
            gone.push(entry);
        }
    }
    Ok(gone)
}

/// Installs a recorded catalog app again. The plan is simulated first and refused if it would take anything away.
pub fn reinstall_package(sys: &dyn Sys, package: &str) -> Result<()> {
    ensure!(owner(package).is_some(), NOT_RECORDED);
    let record = read_record(sys)?;
    let Some(entry) = record.iter().find(|r| r.package == package) else {
        bail!(NOT_RECORDED);
    };
    let names: Vec<&str> = std::iter::once(package)
        .chain(entry.also.iter().map(String::as_str))
        .collect();
    let manager = manager(sys)?;
    let drop_line = || {
        let rest: Vec<Removed> = record
            .iter()
            .filter(|r| r.package != package)
            .cloned()
            .collect();
        write_record(sys, &rest)
    };
    let mut missing = Vec::new();
    for name in &names {
        if !installed(sys, manager, name)? {
            missing.push(*name);
        }
    }
    if missing.is_empty() {
        return drop_line();
    }
    let with = |head: &[&'static str]| -> Vec<&str> {
        head.iter()
            .copied()
            .chain(missing.iter().copied())
            .collect()
    };
    let takes_something_away = match manager {
        Manager::Apt => {
            let out = sys.run("/usr/bin/apt-get", &with(&["-s", "install"]))?;
            ensure!(out.success(), INSTALL_FAILED);
            out.stdout.lines().any(|line| line.starts_with("Remv "))
        }
        Manager::Dnf => {
            let out = sys.run("/usr/bin/dnf", &with(&["install", "--assumeno"]))?;
            ensure!(
                out.success() || out.stdout.contains("Transaction Summary"),
                INSTALL_FAILED
            );
            out.stdout.lines().any(|line| line.starts_with("Removing"))
        }
    };
    ensure!(!takes_something_away, INSTALL_REFUSED);
    let out = match manager {
        Manager::Apt => sys.run_long("/usr/bin/apt-get", &with(&["install", "-y"]))?,
        Manager::Dnf => sys.run_long("/usr/bin/dnf", &with(&["install", "-y"]))?,
    };
    ensure!(out.success(), INSTALL_FAILED);
    for name in &missing {
        ensure!(installed(sys, manager, name)?, INSTALL_FAILED);
    }
    drop_line()
}

#[cfg(test)]
mod tests;
