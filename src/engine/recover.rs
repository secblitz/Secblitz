//! Damage to the saved undo history: read-only inspection, and starting fresh with a kept copy.
//! The damaged files are never repaired or edited. They move whole into `Damaged/<time>` with their hashes.

use super::fsio::{io_boundary, metadata_safe, sync_directory};
use super::{Engine, JournalRecoveryRequired, LEGACY_UPDATE_FILES, LOCK_NAME};
use crate::model::Backend;
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const DAMAGED: &str = "Damaged";
const KEEP_SETS: usize = 5;
const MANIFEST: &str = "damage.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DamageKind {
    /// Some saved records cannot be read; the rest are intact.
    Partial,
    /// The records contradict each other, or none can be read.
    Total,
    /// The history was written on another PC.
    OtherPc,
}

/// The saved undo history cannot be trusted. Starting fresh is the only way forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalDamaged {
    pub kind: DamageKind,
    pub files: usize,
}

impl std::fmt::Display for JournalDamaged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secblitz's undo history is damaged")
    }
}

impl std::error::Error for JournalDamaged {}

#[derive(Debug)]
pub(super) struct OtherPc;

impl std::fmt::Display for OtherPc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Journal schema, machine, or transaction identity mismatch")
    }
}

impl std::error::Error for OtherPc {}

/// A folder or permission problem that starting fresh would not fix.
#[derive(Debug)]
pub(super) struct Unrelated;

impl Unrelated {
    pub(super) fn wrap(error: anyhow::Error) -> anyhow::Error {
        error.context(Self)
    }
}

impl std::fmt::Display for Unrelated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("A Secblitz folder is not protected as expected")
    }
}

impl std::error::Error for Unrelated {}

#[derive(Debug)]
pub struct NotDamaged;

impl std::fmt::Display for NotDamaged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The undo history is not damaged")
    }
}

impl std::error::Error for NotDamaged {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamageReport {
    /// `None` when the history reads cleanly.
    pub kind: Option<DamageKind>,
    pub files: usize,
    /// One line per problem, for the log and the kept copy. Never shown on screen.
    pub causes: Vec<String>,
}

impl DamageReport {
    pub(super) fn of(
        readable: usize,
        bad: Vec<(&str, &anyhow::Error)>,
        shared: Vec<String>,
    ) -> Self {
        let mut causes: Vec<String> = bad
            .iter()
            .map(|(name, e)| format!("{name}: {e:#}"))
            .collect();
        causes.extend(shared.iter().cloned());
        if causes.is_empty() {
            return Self {
                kind: None,
                files: 0,
                causes,
            };
        }
        let other_pc = bad
            .iter()
            .any(|(_, e)| e.downcast_ref::<OtherPc>().is_some());
        let only_unreadable_journals = bad.iter().all(|(name, e)| {
            name.ends_with(".jsonl")
                && e.downcast_ref::<JournalRecoveryRequired>().is_none()
                && e.downcast_ref::<OtherPc>().is_none()
        });
        let kind = if other_pc {
            DamageKind::OtherPc
        } else if shared.is_empty() && readable > 0 && only_unreadable_journals {
            DamageKind::Partial
        } else {
            DamageKind::Total
        };
        let files = bad.len() + if shared.is_empty() { 0 } else { readable };
        Self {
            kind: Some(kind),
            files: files.max(1),
            causes,
        }
    }
}

/// Reads the saved history and says whether it is damaged. Changes nothing.
pub fn inspect(dir: &Path, backend: Box<dyn Backend>) -> Result<DamageReport> {
    if !dir.is_dir() {
        return Ok(DamageReport::of(0, Vec::new(), Vec::new()));
    }
    let mut engine = Engine::unopened(dir.to_owned(), backend)?;
    engine.identify()?;
    engine.survey()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedFresh {
    pub moved: usize,
    pub kept: PathBuf,
}

#[derive(Serialize)]
struct Manifest<'a> {
    engine_version: &'static str,
    created: u64,
    kind: DamageKind,
    reason: &'a [String],
    files: &'a [Kept],
}

#[derive(Serialize)]
struct Kept {
    name: String,
    size: u64,
    sha256: Option<String>,
}

fn is_ours(name: &str) -> bool {
    name != LOCK_NAME
        && !LEGACY_UPDATE_FILES.contains(&name)
        && !matches!(
            name,
            "Updates" | "operations" | "Patching" | "App" | DAMAGED
        )
        && name != crate::platform::WEB_PROTECTION
        && name != crate::platform::LINUX_NOTES
}

fn hash(path: &Path) -> Result<Option<(u64, String)>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Ok(None);
    }
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
        size += n as u64;
    }
    Ok(Some((size, hex::encode(digest.finalize()))))
}

fn utc_stamp(secs: u64) -> String {
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn make_dir(path: &Path) -> Result<()> {
    crate::platform::create_private_dir(path).with_context(|| format!("Create {}", path.display()))
}

fn is_set_name(name: &str) -> bool {
    name.len() >= 16
        && name.starts_with(|c: char| c.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn prune(damaged: &Path) {
    let Ok(entries) = fs::read_dir(damaged) else {
        return;
    };
    let mut sets: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let real_dir = fs::symlink_metadata(e.path())
                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink());
            (real_dir && is_set_name(&name)).then(|| (name, e.path()))
        })
        .collect();
    sets.sort();
    while sets.len() > KEEP_SETS {
        let (_, path) = sets.remove(0);
        if let Err(e) = fs::remove_dir_all(&path) {
            eprintln!("Could not remove an old damaged history copy: {e}");
        }
    }
}

/// Moves every saved-history file into `Damaged/<time>` and leaves an empty history behind.
/// Takes the journal lock and the update interlock, and refuses when nothing is damaged.
/// If any move fails, the moved files go back and nothing changes.
pub fn start_fresh(dir: &Path, backend: Box<dyn Backend>) -> Result<StartedFresh> {
    let mut engine = Engine::unopened(dir.to_owned(), backend)?;
    let lock = engine.lock()?;
    engine.mutation_interlocks(&lock)?;
    engine.identify()?;
    let report = engine.survey()?;
    let Some(kind) = report.kind else {
        return Err(NotDamaged.into());
    };

    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        let name = name
            .into_string()
            .map_err(|_| anyhow::anyhow!("Non-UTF8 journal filename"))?;
        if is_ours(&name) {
            names.push(name);
        }
    }
    names.sort();
    let mut kept = Vec::new();
    for name in &names {
        let (size, sha256) = match hash(&dir.join(name))? {
            Some((size, digest)) => (size, Some(digest)),
            None => (0, None),
        };
        kept.push(Kept {
            name: name.clone(),
            size,
            sha256,
        });
    }

    let damaged = dir.join(DAMAGED);
    match fs::symlink_metadata(&damaged) {
        Ok(m) => metadata_safe(&m, true)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => make_dir(&damaged)?,
        Err(e) => return Err(e.into()),
    }
    let stamp = utc_stamp(now());
    let newest_suffix = fs::read_dir(&damaged)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| {
            let rest = name.strip_prefix(&stamp)?;
            if rest.is_empty() {
                Some(1)
            } else {
                rest.strip_prefix('-')?.parse::<u32>().ok()
            }
        })
        .max();
    let set = damaged.join(match newest_suffix {
        None => stamp,
        Some(n) => format!("{stamp}-{:02}", n + 1),
    });
    make_dir(&set)?;

    let manifest = Manifest {
        engine_version: env!("CARGO_PKG_VERSION"),
        created: now(),
        kind,
        reason: &report.causes,
        files: &kept,
    };
    let abandon = |set: &Path| {
        let _ = fs::remove_file(set.join(MANIFEST));
        let _ = fs::remove_dir(set);
    };
    let written = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(set.join(MANIFEST))?;
        file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = written {
        abandon(&set);
        return Err(e);
    }

    let mut moved: Vec<&str> = Vec::new();
    for name in &names {
        let step = io_boundary("recover_move")
            .and_then(|()| fs::rename(dir.join(name), set.join(name)).map_err(Into::into));
        if let Err(e) = step {
            for back in moved.iter().rev() {
                if let Err(undo) = fs::rename(set.join(back), dir.join(back)) {
                    eprintln!("Could not put a saved history file back: {undo}");
                }
            }
            abandon(&set);
            return Err(e.context("Could not move the damaged undo history aside"));
        }
        moved.push(name);
    }
    for synced in [dir, set.as_path()] {
        if let Err(e) = sync_directory(synced) {
            eprintln!("Could not flush the fresh undo history to disk: {e:#}");
        }
    }
    prune(&damaged);
    eprintln!(
        "Undo history started fresh; {} files kept in {}: {}",
        names.len(),
        set.display(),
        report.causes.join("; ")
    );
    Ok(StartedFresh {
        moved: names.len(),
        kept: set,
    })
}

#[cfg(test)]
mod tests {
    use super::utc_stamp;

    #[test]
    fn stamps_are_utc_calendar_times() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_791_460_800), "20261008T120000Z");
        assert_eq!(utc_stamp(1_709_164_799), "20240228T235959Z");
        assert_eq!(utc_stamp(1_709_164_800), "20240229T000000Z");
    }
}
