//! Older copies of apps (Snap) and old system versions (Linux kernels on Debian family systems).
//!
//! Only what the package tools themselves call disabled or unneeded is ever a candidate, and a kernel is removed
//! only when a simulated removal takes nothing but the candidates.
use super::{
    gone, not_installed, Fs, Tally, APT_GET, CANNOT_CLEAN, DPKG_QUERY, KERNELS_KEPT, SNAP,
};
use crate::debloat::linux::is_valid_package;
use crate::linux::cmd::Sys;
use crate::linux::distro::{detect, Family};
use anyhow::{bail, ensure, Result};
use std::path::Path;

const SNAP_FILES: &str = "/var/lib/snapd/snaps";
const UNAME: &str = "/usr/bin/uname";
const KERNEL_PREFIXES: [&str; 5] = [
    "linux-image-",
    "linux-modules-",
    "linux-main-modules-",
    "linux-headers-",
    "linux-tools-",
];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct OldSnap {
    name: String,
    revision: String,
    bytes: u64,
}

fn valid_snap_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_revision(revision: &str) -> bool {
    !revision.is_empty() && revision.len() <= 12 && revision.bytes().all(|b| b.is_ascii_digit())
}

/// The name and revision of every row of `snap list --all` that is disabled and has an active revision of the same snap.
fn parse_disabled(text: &str) -> Vec<(String, String)> {
    let rows: Vec<(&str, &str, bool)> = text
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let [name, _, revision, .., notes] = words.as_slice() else {
                return None;
            };
            if words.len() < 6 || !valid_snap_name(name) || !valid_revision(revision) {
                return None;
            }
            Some((*name, *revision, notes.split(',').any(|n| n == "disabled")))
        })
        .collect();
    rows.iter()
        .filter(|(name, _, disabled)| *disabled && rows.iter().any(|(n, _, off)| n == name && !off))
        .map(|(name, revision, _)| ((*name).to_owned(), (*revision).to_owned()))
        .collect()
}

pub(super) fn snaps(sys: &dyn Sys, fs: &dyn Fs) -> Result<Vec<OldSnap>> {
    let out = match sys.run(SNAP, &["list", "--all"]) {
        Ok(out) => out,
        Err(e) if not_installed(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    ensure!(out.success(), CANNOT_CLEAN);
    let disabled = parse_disabled(&out.stdout);
    if disabled.is_empty() {
        return Ok(Vec::new());
    }
    let files = fs.list(Path::new(SNAP_FILES), crate::space::MAX_ENTRIES)?;
    Ok(disabled
        .into_iter()
        .map(|(name, revision)| {
            let path = Path::new(SNAP_FILES).join(format!("{name}_{revision}.snap"));
            let bytes = files
                .iter()
                .find(|f| f.path == path && !f.is_dir && !f.reparse)
                .map_or(0, |f| f.size);
            OldSnap {
                name,
                revision,
                bytes,
            }
        })
        .collect())
}

pub(super) fn tally(old: &[OldSnap]) -> Tally {
    Tally {
        bytes: old.iter().map(|s| s.bytes).sum(),
        files: old.len() as u64,
        left_alone: 0,
    }
}

pub(super) fn clean_snaps(sys: &dyn Sys, fs: &dyn Fs) -> Result<Tally> {
    let before = snaps(sys, fs)?;
    if before.is_empty() {
        return Ok(Tally::default());
    }
    let mut failed = false;
    for old in &before {
        let revision = format!("--revision={}", old.revision);
        let out = sys.run_long(SNAP, &["remove", &old.name, &revision])?;
        failed |= !out.success();
    }
    let after = snaps(sys, fs)?;
    let freed = gone(tally(&before), tally(&after));
    ensure!(!failed || freed.files > 0, CANNOT_CLEAN);
    Ok(freed)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct OldKernel {
    package: String,
    kib: u64,
}

/// The four numbers of a kernel version in a package or release name, such as `7.0.0-38` in `linux-image-7.0.0-38-generic`.
fn version_of(name: &str) -> Option<(u64, u64, u64, u64)> {
    let parts: Vec<&str> = name.split('-').collect();
    parts.windows(2).find_map(|pair| {
        let mut numbers = pair[0].split('.');
        let (a, b, c) = (numbers.next()?, numbers.next()?, numbers.next()?);
        if numbers.next().is_some() {
            return None;
        }
        let build: String = pair[1].chars().take_while(char::is_ascii_digit).collect();
        let number = |text: &str| {
            (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
                .then(|| text.parse().ok())
                .flatten()
        };
        Some((number(a)?, number(b)?, number(c)?, number(&build)?))
    })
}

fn is_kernel_package(name: &str) -> bool {
    KERNEL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The package names a simulated `apt-get` run says it would remove.
fn planned_removals(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("Remv "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|name| name.split(':').next().unwrap_or(name).to_owned())
        .collect()
}

pub(super) fn kernels(sys: &dyn Sys) -> Result<Vec<OldKernel>> {
    if detect(sys, None).family != Family::Debian {
        return Ok(Vec::new());
    }
    let release = sys.run(UNAME, &["-r"])?;
    ensure!(release.success(), CANNOT_CLEAN);
    let Some(running) = version_of(release.stdout.trim()) else {
        bail!(CANNOT_CLEAN);
    };
    let listing = sys.run(
        DPKG_QUERY,
        &[
            "-W",
            "-f=${Package}\t${Installed-Size}\t${db:Status-Abbrev}\n",
        ],
    )?;
    ensure!(listing.success(), CANNOT_CLEAN);
    let installed: Vec<(&str, u64)> = listing
        .stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let (name, size, status) = (fields.next()?, fields.next()?, fields.next()?);
            (status.starts_with("ii") && is_kernel_package(name) && is_valid_package(name))
                .then(|| (name, size.trim().parse().unwrap_or(0)))
        })
        .collect();
    let newest = installed
        .iter()
        .filter(|(name, _)| name.starts_with("linux-image-"))
        .filter_map(|(name, _)| version_of(name))
        .max()
        .unwrap_or(running);
    let candidates: Vec<(&str, u64)> = installed
        .into_iter()
        .filter(|(name, _)| {
            version_of(name).is_some_and(|version| version != running && version != newest)
        })
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let unneeded = sys.run(APT_GET, &["-s", "autoremove"])?;
    ensure!(unneeded.success(), CANNOT_CLEAN);
    let unneeded = planned_removals(&unneeded.stdout);
    let candidates: Vec<(&str, u64)> = candidates
        .into_iter()
        .filter(|(name, _)| unneeded.iter().any(|u| u == name))
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["-s", "remove"];
    args.extend(candidates.iter().map(|(name, _)| *name));
    let plan = sys.run(APT_GET, &args)?;
    ensure!(plan.success(), CANNOT_CLEAN);
    ensure!(
        planned_removals(&plan.stdout)
            .iter()
            .all(|name| candidates.iter().any(|(c, _)| c == name)),
        KERNELS_KEPT
    );
    Ok(candidates
        .into_iter()
        .map(|(name, kib)| OldKernel {
            package: name.to_owned(),
            kib,
        })
        .collect())
}

pub(super) fn kernel_tally(old: &[OldKernel]) -> Tally {
    Tally {
        bytes: old.iter().map(|k| k.kib.saturating_mul(1024)).sum(),
        files: old.len() as u64,
        left_alone: 0,
    }
}

pub(super) fn clean_kernels(sys: &dyn Sys) -> Result<Tally> {
    let before = kernels(sys)?;
    if before.is_empty() {
        return Ok(Tally::default());
    }
    let mut args = vec!["remove", "-y"];
    args.extend(before.iter().map(|k| k.package.as_str()));
    let out = sys.run_long(APT_GET, &args)?;
    ensure!(out.success(), CANNOT_CLEAN);
    let after = kernels(sys)?;
    Ok(gone(kernel_tally(&before), kernel_tally(&after)))
}

#[cfg(test)]
mod tests;
