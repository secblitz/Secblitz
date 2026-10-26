//! Windows built-in apps only, not apps the person installed or Secblitz itself:
//! remove preinstalled Windows apps the user doesn't want, and restore them.
//! Only catalog packages not on the protected list reach Windows, and names are
//! validated before any PowerShell starts.
pub mod backup;
pub mod catalog;
pub mod friendly;
pub mod icons;
pub mod journal;
pub mod linux;
pub mod offline;
pub mod suggested;
pub mod vault;
#[cfg(windows)]
pub(crate) mod wincrypto;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) mod winfs;

#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub use catalog::{is_protected, matches as pattern_matches, note, note_on};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    Recommended,
    Sponsored,
    Promotions,
    Utilities,
    Gaming,
    RemoteAccess,
}

impl Group {
    pub const ALL: [Group; 6] = [
        Group::Recommended,
        Group::Sponsored,
        Group::Promotions,
        Group::Utilities,
        Group::Gaming,
        Group::RemoteAccess,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct App {
    pub family: &'static str,
    pub name: &'static str,
    pub group: Group,
    pub store_id: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub index: u16,
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kept {
    NoSpace,
    NoCopy(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemResult {
    Removed,
    Kept(Kept),
    Protected,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Saving(u16),
    Started(u16),
    Finished(u16, ItemResult),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    pub index: u16,
    pub package: String,
    pub version: String,
    #[serde(default)]
    pub restored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub index: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub t: u64,
    pub removed: Vec<Removed>,
    pub skipped: Vec<u16>,
    pub failed: Vec<Failure>,
    #[serde(default)]
    pub kept: Vec<u16>,
}

impl Batch {
    pub fn removed_apps(&self) -> usize {
        let mut seen: Vec<u16> = self.removed.iter().map(|r| r.index).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.len()
    }
}

/// The Windows apps first, then the Linux apps, so an index never changes meaning. Only the
/// apps of the running system are ever found installed.
pub fn catalog() -> &'static [App] {
    static ALL: std::sync::OnceLock<Vec<App>> = std::sync::OnceLock::new();
    ALL.get_or_init(|| {
        catalog::CATALOG
            .iter()
            .chain(linux::CATALOG)
            .copied()
            .collect()
    })
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct RawPackage {
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    non_removable: bool,
    #[serde(default)]
    framework: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_inventory(json: &str) -> Result<Vec<Installed>> {
    let raw: Vec<RawPackage> = if json.trim_start().starts_with('{') {
        vec![serde_json::from_str(json).context("Read the app list")?]
    } else {
        serde_json::from_str(json).context("Read the app list")?
    };
    let mut found: Vec<Installed> = raw
        .into_iter()
        .filter(|p| !p.non_removable && !p.framework)
        .filter_map(|p| {
            catalog::owner(&p.name).map(|index| Installed {
                index,
                package: p.name,
                version: p.version.chars().take(64).collect(),
            })
        })
        .collect();
    found.sort_by(|a, b| (a.index, &a.package).cmp(&(b.index, &b.package)));
    found.dedup_by(|a, b| a.package.eq_ignore_ascii_case(&b.package));
    Ok(found)
}

pub fn inventory() -> Result<Vec<Installed>> {
    #[cfg(windows)]
    {
        let json = windows::run(windows::INVENTORY, &[], std::time::Duration::from_secs(180))?;
        parse_inventory(&json)
    }
    #[cfg(not(windows))]
    {
        bail!("Removing apps is only available on Windows")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageOutcome {
    Removed,
    Protected,
    Failed(String),
}

#[derive(Debug, Deserialize)]
#[cfg_attr(not(windows), allow(dead_code))]
struct RawOutcome {
    #[serde(default)]
    removed: bool,
    #[serde(default)]
    protected: bool,
    #[serde(default)]
    error: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_outcome(json: &str) -> PackageOutcome {
    match serde_json::from_str::<RawOutcome>(json) {
        Ok(o) if o.protected => PackageOutcome::Protected,
        Ok(o) if o.removed => PackageOutcome::Removed,
        Ok(o) => PackageOutcome::Failed(
            o.error
                .map(|e| crate::text::excerpt(&e, 300))
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| "Unknown result".into()),
        ),
        Err(_) => PackageOutcome::Failed("Unreadable answer from Windows".into()),
    }
}

pub(crate) fn validate_indices(indices: &[u16]) -> Result<Vec<u16>> {
    let mut clean = Vec::new();
    for &index in indices {
        let Some(app) = catalog().get(index as usize) else {
            bail!("Unknown app");
        };
        // A catalog entry that could ever match a protected package is a bug.
        if is_protected(app.family.trim_end_matches('*')) {
            bail!("That app can't be removed");
        }
        if !clean.contains(&index) {
            clean.push(index);
        }
    }
    Ok(clean)
}

/// Core of `remove`, with the PowerShell call injected so it is testable.
/// `installed` is a fresh inventory; every package is re-validated here.
#[cfg(test)]
pub(crate) fn remove_with(
    indices: &[u16],
    installed: &[Installed],
    backup: &dyn Fn(&Installed) -> std::result::Result<(), Kept>,
    run: &dyn Fn(&str) -> PackageOutcome,
    emit: &dyn Fn(Progress),
) -> Result<Batch> {
    remove_with_checkpoint(indices, installed, backup, run, emit, &|_| Ok(()))
}

/// Same, and `checkpoint` sees the batch after every app, so the record of
/// what is already removed is never lost if the run is cut short.
pub fn remove_with_checkpoint(
    indices: &[u16],
    installed: &[Installed],
    backup: &dyn Fn(&Installed) -> std::result::Result<(), Kept>,
    run: &dyn Fn(&str) -> PackageOutcome,
    emit: &dyn Fn(Progress),
    checkpoint: &dyn Fn(&Batch) -> Result<()>,
) -> Result<Batch> {
    let indices = validate_indices(indices)?;
    let mut batch = Batch {
        t: now(),
        ..Batch::default()
    };
    let mut stopped = false;
    for index in indices {
        if stopped {
            batch.failed.push(Failure {
                index,
                reason: "The list of removed apps could not be saved".into(),
            });
            emit(Progress::Finished(
                index,
                ItemResult::Failed("The list of removed apps could not be saved".into()),
            ));
            continue;
        }
        let packages: Vec<&Installed> = installed
            .iter()
            .filter(|p| p.index == index)
            .filter(|p| {
                catalog::owner(&p.package) == Some(index) || linux::owner(&p.package) == Some(index)
            })
            .collect();
        if packages.is_empty() {
            continue;
        }
        emit(Progress::Saving(index));
        let mut kept = None;
        for p in &packages {
            if let Err(k) = backup(p) {
                kept = Some(k);
                break;
            }
        }
        if let Some(k) = kept {
            batch.kept.push(index);
            emit(Progress::Finished(index, ItemResult::Kept(k)));
            continue;
        }
        emit(Progress::Started(index));
        let mut removed = Vec::new();
        let mut protected = false;
        let mut failure: Option<String> = None;
        for p in packages {
            match run(&p.package) {
                PackageOutcome::Removed => removed.push(Removed {
                    index,
                    package: p.package.clone(),
                    version: p.version.clone(),
                    restored: false,
                }),
                PackageOutcome::Protected => protected = true,
                PackageOutcome::Failed(e) => failure = Some(e),
            }
        }
        let result = if let Some(reason) = failure {
            batch.failed.push(Failure {
                index,
                reason: reason.clone(),
            });
            ItemResult::Failed(reason)
        } else if removed.is_empty() && protected {
            batch.skipped.push(index);
            ItemResult::Protected
        } else {
            ItemResult::Removed
        };
        batch.removed.append(&mut removed);
        stopped = checkpoint(&batch).is_err();
        emit(Progress::Finished(index, result));
    }
    Ok(batch)
}

/// Windows 11 starts at build 22000. A build that can't be read counts as
/// Windows 11, the more common case.
pub fn is_windows_11() -> bool {
    #[cfg(windows)]
    {
        static BUILD: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
        BUILD
            .get_or_init(winfs::windows_build)
            .is_none_or(|b| b >= 22000)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub fn remove(indices: &[u16], emit: &dyn Fn(Progress)) -> Result<Batch> {
    let indices = validate_indices(indices)?;
    let installed = inventory()?;
    #[cfg(windows)]
    let run = |package: &str| -> PackageOutcome {
        if !catalog::is_valid_package_name(package) || is_protected(package) {
            return PackageOutcome::Failed("Refused".into());
        }
        match windows::run(
            windows::REMOVE,
            &[("SECBLITZ_APP", package)],
            std::time::Duration::from_secs(300),
        ) {
            Ok(json) => parse_outcome(&json),
            Err(e) => PackageOutcome::Failed(format!("{e:#}")),
        }
    };
    #[cfg(not(windows))]
    let run =
        |_: &str| -> PackageOutcome { PackageOutcome::Failed("Only available on Windows".into()) };
    #[cfg(windows)]
    let store = backup::Store::open().inspect(|s| s.clean_staging());
    #[cfg(windows)]
    let backup = |p: &Installed| -> std::result::Result<(), Kept> {
        match &store {
            Ok(store) => {
                winfs::close_package(&p.package);
                offline::backup_family_with(&offline::WindowsHost, store, p.index, &p.package)
                    .map(|_| ())
            }
            Err(e) => Err(Kept::NoCopy(format!("{e:#}"))),
        }
    };
    #[cfg(not(windows))]
    let backup = |_: &Installed| -> std::result::Result<(), Kept> {
        Err(Kept::NoCopy("Only available on Windows".into()))
    };
    let recordable =
        |b: &Batch| !b.removed.is_empty() || !b.skipped.is_empty() || !b.failed.is_empty();
    // The record is saved after every app (replacing this run's own line), so
    // an app that is already gone is always on the list, even if the run stops.
    let checkpoint = |b: &Batch| -> Result<()> {
        if recordable(b) {
            journal::upsert(b)?;
        }
        Ok(())
    };
    let batch = remove_with_checkpoint(&indices, &installed, &backup, &run, emit, &checkpoint)?;
    if recordable(&batch) {
        journal::upsert(&batch)?;
    }
    Ok(batch)
}

/// Ask Windows (machine-wide policy) not to push suggested apps. Needs an
/// elevated caller. Fully enforced only on Enterprise and Education editions.
/// What was there before is recorded, so Remove Secblitz can put it back.
pub fn set_consumer_features_policy() -> Result<()> {
    #[cfg(windows)]
    {
        suggested::block(&mut suggested::MachinePolicy, &suggested::journal_path()?)
    }
    #[cfg(not(windows))]
    {
        bail!("Only available on Windows")
    }
}

pub fn finish_restore(index: u16) {
    if let Err(error) = journal::mark_restored(index) {
        eprintln!("Could not record restore of item {index}: {error:#}");
    }
    offline::forget(index);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreAll {
    pub restored: Vec<u16>,
    pub needs_store: Vec<u16>,
    pub failed: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bucket {
    Restored,
    NeedsStore,
    Failed,
}

pub(crate) fn classify(outcome: Option<Result<offline::Restored>>, has_store_id: bool) -> Bucket {
    use offline::Restored::*;
    match outcome {
        Some(Ok(Back | BackWithoutSomeData | AlreadyThere)) => Bucket::Restored,
        _ if has_store_id => Bucket::NeedsStore,
        _ => Bucket::Failed,
    }
}

pub fn restore_all(emit: &dyn Fn(u16, bool)) -> RestoreAll {
    let mut result = RestoreAll::default();
    for (index, _) in journal::still_removed(&journal::load(), catalog().len()) {
        let outcome = offline::has_copy(index).then(|| offline::restore_index(index));
        let has_store_id = catalog()[index as usize].store_id.is_some();
        match classify(outcome, has_store_id) {
            Bucket::Restored => {
                finish_restore(index);
                result.restored.push(index);
                emit(index, true);
            }
            Bucket::NeedsStore => {
                result.needs_store.push(index);
                emit(index, false);
            }
            Bucket::Failed => {
                result.failed.push(index);
                emit(index, false);
            }
        }
    }
    result
}
