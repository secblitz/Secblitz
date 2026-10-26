//! Serialized, crash-recoverable preference transactions.
//! Windows callers must use platform::state_dir(): its ACL/owner checks and pinned ancestors are the trust boundary. The engine also rejects links, opens files without delete sharing on Windows, and never interprets journal data as a path, command or target.
//! Appends publish a flushed copy-on-write snapshot. Only a recognizable, incomplete final append is recovered from old JSONL journals; other malformed records and damaged committed prefixes fail closed, and damaged files are kept as evidence.
//! Schema 1 has no checksum, so it cannot tell post-commit truncation or media corruption from a crash prefix.
mod apply;
mod audit;
pub mod catalog;
pub mod cfa;
mod fsio;
mod journal;
pub mod recover;
mod recovery;
mod revert;
pub use revert::{NOTHING_RECORDED, UNDO_FIRST};
mod store;
#[cfg(test)]
mod tests;

use crate::model::{
    validate_observation_for, Authority, Backend, CheckStatus, Control, EffectiveFirewall, Finding,
    Observation, Readiness,
};
use crate::os::Os;
use anyhow::{ensure, Context, Result};
use catalog::validate_value;
use fsio::metadata_safe;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    fs::File,
    path::PathBuf,
};

/// The items the person picked, by control id. Only controls that ask for a choice read it.
pub type ItemChoice = BTreeMap<String, Vec<String>>;
const MAX_CHOSEN: usize = 64;

/// The audit's rule for one setting, judged on its value alone, for the background check.
/// Its account can read settings it may not open for change, and it only raises settings
/// Secblitz already fixed, so who may change them now does not matter.
pub fn assessment(id: &str, o: &Observation) -> Result<CheckStatus> {
    let o = Observation {
        eligible: true,
        ..o.clone()
    };
    catalog::assessment_status(id, &o)
}

const SCHEMA: u32 = 1;
// Exact service descriptor envelopes can exceed 4 KiB. The descriptor parser
// imposes its own bound; the complete WAL remains capped at 1 MiB.
const MAX_LINE: usize = 128 * 1024;
const MAX_WAL: u64 = 1024 * 1024;
const MAX_TRANSACTIONS: usize = 2048;
const LOCK_NAME: &str = "engine.lock";
const MAX_EVIDENCE: usize = 4096;
const READ_BATCH: usize = 4;
const LEGACY_UPDATE_FILES: [&str; 5] = [
    "update.lock",
    "update-status.json",
    "update-manifest.json",
    "update-installer.exe",
    "update-worker.exe",
];

/// One progress notification: a control id, or a phase name such as `readiness`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress<'a> {
    pub id: &'a str,
    pub step: ProgressStep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressStep {
    Pending,
    Complete,
    Result(CheckStatus),
}

impl<'a> Progress<'a> {
    pub fn new(id: &'a str, step: ProgressStep) -> Self {
        Self { id, step }
    }
}

impl ProgressStep {
    /// Stable ASCII text for this step.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Complete => "complete",
            Self::Result(status) => status.as_str(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub transaction: Option<String>,
    pub results: Vec<Outcome>,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<Readiness>,
    /// The settings "undo your last fixes" would put back, oldest change first. Filled by a check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undo_next: Vec<String>,
}

impl Report {
    fn push(&mut self, result: Outcome, callback: &mut impl FnMut(Progress<'_>)) {
        callback(Progress::new(
            &result.id,
            ProgressStep::Result(result.status.clone()),
        ));
        self.results.push(result);
    }

    /// Reports every control as skipped for `reason`, keeping outcomes already computed in `owned`.
    fn skip_all(
        &mut self,
        controls: &[Control],
        owned: &mut Vec<Outcome>,
        reason: &str,
        callback: &mut impl FnMut(Progress<'_>),
    ) {
        for c in controls {
            let result = match owned.iter().position(|r| r.id == c.id) {
                Some(i) => owned.remove(i),
                None => Engine::outcome(c, CheckStatus::Skipped, reason),
            };
            self.push(result, callback);
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub title: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<EffectiveFirewall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Authority>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<crate::model::ItemLabel>,
    /// Secblitz changed this setting and can put it back on its own. Filled by a check.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub undoable: bool,
    /// Something Secblitz changed here needs a change again. Items found after the change
    /// do not count. Filled by a check.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub switched_back: bool,
}

/// How many sets of changes Secblitz has recorded, by state, and which checks they touch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChangeSummary {
    pub sets: usize,
    pub applied: usize,
    pub pending: usize,
    pub reverted: usize,
    pub checks: Vec<String>,
}

/// Approval alone cannot make an ambiguous original safe, so there is deliberately no force-truncate API. Restore a verified journal backup under engine.lock instead.
#[derive(Debug, Serialize)]
pub struct JournalRecoveryRequired {
    pub transaction: String,
    pub validated_bytes: usize,
    pub reason: &'static str,
}

impl std::fmt::Display for JournalRecoveryRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Journal {} requires review at byte {}: {}; original bytes retained",
            self.transaction, self.validated_bytes, self.reason
        )
    }
}

impl std::error::Error for JournalRecoveryRequired {}

/// The callback receives a control id or phase with its step. The OS lock lasts through validation, probes, writes, callbacks and the final findings probe.
pub struct Engine {
    dir: PathBuf,
    backend: Box<dyn Backend>,
    os: Os,
    controls: Vec<Control>,
    machine: String,
    storage_failed: bool,
    choice: ItemChoice,
    #[cfg(test)]
    mutation_check: Option<Box<MutationCheck>>,
}

#[cfg(test)]
type MutationCheck = dyn Fn(&File) -> Result<()>;

#[cfg(windows)]
fn native_mutation_interlocks(held: &File) -> Result<()> {
    crate::updater::interlock::ensure_others_idle(
        crate::updater::interlock::Activity::Hardening,
        held,
    )
}

/// Unit tests run on every host and exercise the Windows catalog; the engine for another system is opened with `open_for`.
const fn running_os() -> Os {
    if cfg!(test) {
        Os::Windows
    } else {
        Os::CURRENT
    }
}

impl Engine {
    pub fn open(dir: PathBuf, backend: Box<dyn Backend>) -> Result<Self> {
        Self::open_for(running_os(), dir, backend)
    }

    /// The catalog is fixed by the system the engine is opened for, never by anything read from disk or from the backend.
    pub fn open_for(os: Os, dir: PathBuf, backend: Box<dyn Backend>) -> Result<Self> {
        let mut engine = Self::unopened_for(os, dir, backend)?;
        let _lock = engine.lock()?;
        engine.identify()?;
        engine.load()?;
        Ok(engine)
    }

    /// Validates the directory and backend without taking the lock or reading any journal.
    fn unopened(dir: PathBuf, backend: Box<dyn Backend>) -> Result<Self> {
        Self::unopened_for(running_os(), dir, backend)
    }

    fn unopened_for(os: Os, dir: PathBuf, backend: Box<dyn Backend>) -> Result<Self> {
        #[cfg(all(windows, not(test)))]
        ensure!(
            dir == crate::platform::state_dir()?,
            "Engine requires the protected platform journal directory"
        );
        // Check existing ancestors before create_dir_all can follow a link.
        for ancestor in dir.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            match fs::symlink_metadata(ancestor) {
                Ok(m) => metadata_safe(&m, true)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        fs::create_dir_all(&dir)?;
        metadata_safe(&fs::symlink_metadata(&dir)?, true)?;
        let controls = backend.controls();
        let mut ids = HashSet::new();
        for c in &controls {
            ensure!(ids.insert(c.id.clone()), "Duplicate backend control");
            ensure!(
                c.target == catalog::target_in(os, &c.id)?,
                "Backend target differs from compiled target"
            );
        }
        Ok(Self {
            dir,
            backend,
            os,
            controls,
            machine: String::new(),
            storage_failed: false,
            choice: ItemChoice::new(),
            #[cfg(test)]
            mutation_check: None,
        })
    }

    fn identify(&mut self) -> Result<()> {
        let machine = self.backend.machine_id()?;
        ensure!(
            !machine.is_empty() && machine.len() <= 256 && !machine.chars().any(char::is_control),
            "Invalid machine identity"
        );
        self.machine = machine;
        Ok(())
    }

    pub(super) fn control(&self, id: &str) -> Result<&Control> {
        self.controls
            .iter()
            .find(|c| c.id == id)
            .context("Journal control is not supported by this backend")
    }

    pub(super) fn mutation_interlocks(&self, held: &File) -> Result<()> {
        #[cfg(test)]
        if let Some(check) = &self.mutation_check {
            return check(held);
        }
        #[cfg(all(windows, not(test)))]
        return native_mutation_interlocks(held);
        #[cfg(any(not(windows), test))]
        {
            let _ = held;
            Ok(())
        }
    }

    /// Replaces the picked items. A name that is not a legal item of its control is refused, and nothing is kept.
    pub fn choose_items(&mut self, choice: ItemChoice) -> Result<()> {
        for (id, names) in &choice {
            let spec = crate::hardening::spec(id).filter(|s| s.needs_choice());
            let spec = spec.with_context(|| format!("Items cannot be picked for {id}"))?;
            ensure!(names.len() <= MAX_CHOSEN, "Too many items picked for {id}");
            ensure!(
                names.iter().all(|n| spec.item_name_ok(n)),
                "An item picked for {id} is not valid"
            );
        }
        self.choice = choice;
        Ok(())
    }

    pub(super) fn chosen(&self, id: &str) -> Option<&[String]> {
        self.choice.get(id).map(Vec::as_slice)
    }

    pub(super) fn observe(&mut self, id: &str) -> Result<Observation> {
        let mut obs = Self::validated(self.os, id, self.backend.observe(id)?)?;
        if let (Some(names), Some(spec)) = (self.choice.get(id), crate::hardening::spec(id)) {
            obs.value = spec.narrow(&obs.value, names);
            obs.labels
                .retain(|l| l.key.is_empty() || names.contains(&l.key));
        }
        self.cfa_gate(id, &mut obs);
        Ok(obs)
    }

    fn validated(os: Os, id: &str, obs: Observation) -> Result<Observation> {
        catalog::target_in(os, id)?;
        validate_value(id, &obs.value)?;
        validate_observation_for(os, id, &obs)?;
        Ok(obs)
    }

    /// A reply of the wrong length fails the whole batch, so one control's reading never lands on another.
    pub(super) fn observe_many(&mut self, ids: &[&str]) -> Vec<Result<Observation>> {
        let mut observed = self.backend.observe_many(ids);
        if observed.len() != ids.len() {
            observed = ids
                .iter()
                .map(|_| {
                    Err(anyhow::anyhow!(
                        "Some details for a check could not be read."
                    ))
                })
                .collect();
        }
        let os = self.os;
        observed
            .into_iter()
            .zip(ids)
            .map(|(obs, id)| {
                let mut obs = Self::validated(os, id, obs?)?;
                self.cfa_gate(id, &mut obs);
                Ok(obs)
            })
            .collect()
    }

    pub fn available_controls(&self) -> &[Control] {
        &self.controls
    }
}
