//! Putting journaled changes back: the newest batch, every batch, or chosen settings.

use super::catalog::{recorded_scope, restore_eligible, scope, target_for, undo_first};
use super::journal::{Record, State, Transaction};
use super::{Engine, Outcome, Progress, ProgressStep, Report};
use crate::model::{CheckStatus, Control, Observation};
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::collections::HashSet;

const ALREADY_BACK: &str = "Original preference already present";
const DIFFERS: &str = "Preference differs from both target and before image; no write performed";
const CHANGED_AT_GATE: &str = "Preference changed immediately before restore; no write performed";
pub const NOTHING_RECORDED: &str = "Nothing recorded to put back";
const NEEDS_OTHER: &str = "Another protection needs this one";
pub const UNDO_FIRST: &str = "Revert the active transaction before undoing chosen controls";

/// When `RestorePending` becomes durable relative to the final read.
/// Undoing a whole batch records its intent first, so any failure at the gate stays recoverable by `revert`.
/// Undoing chosen settings checks first, so a setting the person changed since leaves no trace in the journal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Intent {
    BeforeGate,
    AfterGate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    AtBefore,
    AtTarget,
    Third,
}

struct Compared {
    control: Control,
    observation: Observation,
    before_eff: Value,
    expected_eff: Value,
    seen: Seen,
}

impl Engine {
    /// Reads the setting now and says whether it still has the value Secblitz set, the original, or something else.
    fn classify(&mut self, id: &str, before: &Value) -> Result<Compared> {
        let control = self.control(id)?.clone();
        let expected = target_for(id, before)?;
        let observation = self.observe(id)?;
        let before_eff = recorded_scope(id, before, &observation.value);
        let expected_eff = recorded_scope(id, &expected, &observation.value);
        let now = scope(id, &observation.value, Some(&before_eff));
        let seen = if now == before_eff {
            Seen::AtBefore
        } else if now != expected_eff {
            Seen::Third
        } else {
            Seen::AtTarget
        };
        Ok(Compared {
            control,
            observation,
            before_eff,
            expected_eff,
            seen,
        })
    }

    /// Puts one recorded setting back. Never overwrites a value that is neither the one Secblitz set nor the original.
    pub(super) fn restore_entry(
        &mut self,
        tx: &mut Transaction,
        i: usize,
        intent: Intent,
        callback: &mut impl FnMut(Progress<'_>),
    ) -> Result<Outcome> {
        let id = tx.entries[i].id.clone();
        let before = tx.entries[i].before.clone();
        let Compared {
            control: c,
            observation,
            before_eff,
            expected_eff,
            seen,
        } = self.classify(&id, &before)?;
        if seen == Seen::AtBefore {
            if tx.entries[i].state != State::Restoring {
                self.append(tx, Record::RestorePending { id: id.clone() })?;
            }
            self.append(tx, Record::Restored { id: id.clone() })?;
            tx.entries[i].state = State::Restored;
            return Ok(Self::observed_outcome(
                &c,
                CheckStatus::Unchanged,
                ALREADY_BACK,
                &observation,
            ));
        }
        if seen == Seen::Third {
            return Ok(Self::observed_outcome(
                &c,
                CheckStatus::Conflict,
                DIFFERS,
                &observation,
            ));
        }
        if !restore_eligible(&c, &observation) {
            return Ok(Self::observed_outcome(
                &c,
                CheckStatus::Skipped,
                &observation.reason,
                &observation,
            ));
        }
        if intent == Intent::BeforeGate && tx.entries[i].state != State::Restoring {
            self.append(tx, Record::RestorePending { id: id.clone() })?;
            tx.entries[i].state = State::Restoring;
        }
        let fresh = self.observe(&id)?;
        if scope(&id, &fresh.value, Some(&before_eff)) != expected_eff {
            return Ok(Self::observed_outcome(
                &c,
                CheckStatus::Conflict,
                CHANGED_AT_GATE,
                &fresh,
            ));
        }
        if !restore_eligible(&c, &fresh) {
            return Ok(Self::observed_outcome(
                &c,
                CheckStatus::Skipped,
                &fresh.reason,
                &fresh,
            ));
        }
        if intent == Intent::AfterGate && tx.entries[i].state != State::Restoring {
            self.append(tx, Record::RestorePending { id: id.clone() })?;
            tx.entries[i].state = State::Restoring;
        }
        if let Err(e) = self.backend.write(&id, &before_eff) {
            callback(Progress::new(&id, ProgressStep::Result(CheckStatus::Error)));
            return Err(e.context(format!(
                "Restore {id} has unknown outcome; pending transaction {} retained",
                tx.name
            )));
        }
        let readback = self.observe(&id)?;
        ensure!(
            scope(&id, &readback.value, Some(&before_eff)) == before_eff,
            "Restore {id} readback differs from original; pending transaction {} retained",
            tx.name
        );
        self.append(tx, Record::Restored { id: id.clone() })?;
        tx.entries[i].state = State::Restored;
        Ok(Self::observed_outcome(
            &c,
            CheckStatus::Restored,
            if c.reboot {
                "Original preference restored; restart required"
            } else {
                "Original preference restored"
            },
            &readback,
        ))
    }

    pub(super) fn revert_transaction(
        &mut self,
        tx: &mut Transaction,
        report: &mut Report,
        callback: &mut impl FnMut(Progress<'_>),
    ) -> Result<()> {
        if !tx.reverting {
            self.append(tx, Record::Reverting)?;
            tx.reverting = true;
        }
        for i in (0..tx.entries.len()).rev() {
            if tx.entries[i].state == State::Restored {
                continue;
            }
            let result = self.restore_entry(tx, i, Intent::BeforeGate, callback)?;
            report.push(result, callback);
        }
        if tx.entries.iter().all(|e| e.state == State::Restored) {
            self.append(tx, Record::Reverted)?;
            tx.reverted = true;
        }
        Ok(())
    }

    /// Closes every complete batch whose settings were all put back one at a time.
    pub(super) fn close_finished(&mut self, transactions: &mut [Transaction]) -> Result<()> {
        for tx in transactions.iter_mut().filter(|t| t.fully_restored()) {
            self.append(tx, Record::Reverted)?;
            tx.reverted = true;
        }
        Ok(())
    }

    /// Journal only. A setting whose undo was interrupted and whose system value is already the original gets its closing record. Nothing is written to Windows.
    pub(super) fn settle_restoring(
        &mut self,
        transactions: &mut [Transaction],
        only: Option<&HashSet<&str>>,
    ) -> Result<()> {
        for tx in transactions
            .iter_mut()
            .filter(|t| !t.reverted && t.sealed && !t.reverting)
        {
            for i in 0..tx.entries.len() {
                let entry = &tx.entries[i];
                if entry.state != State::Restoring
                    || only.is_some_and(|ids| !ids.contains(entry.id.as_str()))
                {
                    continue;
                }
                let (id, before) = (entry.id.clone(), entry.before.clone());
                if let Ok(c) = self.classify(&id, &before) {
                    if c.seen == Seen::AtBefore {
                        self.append(tx, Record::Restored { id })?;
                        tx.entries[i].state = State::Restored;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn revert(&mut self, mut callback: impl FnMut(Progress<'_>)) -> Result<Report> {
        let _lock = self.lock()?;
        self.mutation_interlocks(&_lock)?;
        let mut transactions = self.load()?;
        self.durable(&transactions)?;
        self.close_finished(&mut transactions)?;
        let mut report = Report::default();
        if let Some(tx) = transactions.iter_mut().rev().find(|t| !t.reverted) {
            report.transaction = Some(tx.name.clone());
            self.revert_transaction(tx, &mut report, &mut callback)?;
        }
        self.cfa_note(&report.results);
        report.findings = self.findings();
        if let Some(tx) = transactions.iter().rev().find(|t| !t.reverted) {
            report.findings.push(Self::journal_finding(tx));
        }
        Ok(report)
    }

    /// Puts back only the chosen settings, each to exactly how it was before Secblitz changed it. Settings the person changed since are left as they are and the journal is left untouched for them.
    pub fn revert_selected(
        &mut self,
        ids: &[String],
        mut callback: impl FnMut(Progress<'_>),
    ) -> Result<Report> {
        ensure!(!ids.is_empty(), "Select at least one control");
        ensure!(
            ids.len() <= self.controls.len(),
            "Too many selected controls"
        );
        let mut chosen = HashSet::new();
        for id in ids {
            ensure!(
                chosen.insert(id.as_str()),
                "Duplicate selected control: {id}"
            );
            self.control(id)
                .with_context(|| format!("Unknown selected control: {id}"))?;
        }
        let _lock = self.lock()?;
        self.mutation_interlocks(&_lock)?;
        let mut transactions = self.load()?;
        self.durable(&transactions)?;
        self.close_finished(&mut transactions)?;
        let mut report = Report::default();
        let mut plan: Vec<(usize, usize)> = Vec::new();
        for id in ids {
            match Self::owner_of(&transactions, id) {
                None => {
                    let c = self.control(id)?.clone();
                    report.push(
                        Self::outcome(&c, CheckStatus::Skipped, NOTHING_RECORDED),
                        &mut callback,
                    );
                }
                Some((t, e)) => {
                    let tx = &transactions[t];
                    if tx.sealed && !tx.reverting && !tx.incomplete() {
                        plan.push((t, e));
                    } else {
                        let c = self.control(id)?.clone();
                        report.push(
                            Self::outcome(&c, CheckStatus::Skipped, UNDO_FIRST),
                            &mut callback,
                        );
                    }
                }
            }
        }
        Self::order_for_undo(&transactions, &mut plan);
        for (t, e) in plan {
            let id = transactions[t].entries[e].id.clone();
            // Windows keeps this protection on only while the other one is on, so it waits until that one is really back.
            let waits =
                undo_first(&id).is_some_and(|first| Self::owner_of(&transactions, first).is_some());
            let result = if waits {
                let c = self.control(&id)?.clone();
                Self::outcome(&c, CheckStatus::Skipped, NEEDS_OTHER)
            } else {
                self.restore_entry(&mut transactions[t], e, Intent::AfterGate, &mut callback)?
            };
            report.push(result, &mut callback);
        }
        self.close_finished(&mut transactions)?;
        self.cfa_note(&report.results);
        report.findings = self.findings();
        Ok(report)
    }

    /// The one batch entry that still owns this setting, if Secblitz changed it and it has not been put back.
    fn owner_of(transactions: &[Transaction], id: &str) -> Option<(usize, usize)> {
        transactions
            .iter()
            .enumerate()
            .filter(|(_, t)| !t.reverted)
            .find_map(|(t, tx)| {
                tx.entries
                    .iter()
                    .position(|e| e.id == id && e.state != State::Restored)
                    .map(|e| (t, e))
            })
    }

    /// Newest batch first and last change first, except that a protection that another one needs is put back before it.
    fn order_for_undo(transactions: &[Transaction], plan: &mut Vec<(usize, usize)>) {
        plan.sort_by(|a, b| b.cmp(a));
        let id_at = |&(t, e): &(usize, usize)| transactions[t].entries[e].id.as_str();
        let mut i = 0;
        while i < plan.len() {
            let first = undo_first(id_at(&plan[i]));
            let later = first.and_then(|first| plan.iter().position(|p| id_at(p) == first));
            match later {
                Some(j) if j > i => {
                    let moved = plan.remove(j);
                    plan.insert(i, moved);
                }
                _ => i += 1,
            }
        }
    }

    pub(super) fn undo_blockers(&mut self, tx: &Transaction) -> Result<Vec<Outcome>> {
        let mut blockers = Vec::new();
        for entry in tx
            .entries
            .iter()
            .rev()
            .filter(|e| e.state != State::Restored)
        {
            let c = self.classify(&entry.id, &entry.before)?;
            blockers.push(match c.seen {
                Seen::AtBefore => continue,
                Seen::Third => Self::observed_outcome(
                    &c.control,
                    CheckStatus::Conflict,
                    DIFFERS,
                    &c.observation,
                ),
                Seen::AtTarget if !restore_eligible(&c.control, &c.observation) => {
                    Self::observed_outcome(
                        &c.control,
                        CheckStatus::Skipped,
                        &c.observation.reason,
                        &c.observation,
                    )
                }
                Seen::AtTarget => continue,
            });
        }
        Ok(blockers)
    }

    /// Newest first. A batch with a conflict stays unreverted and older batches are still processed.
    pub fn revert_all(&mut self, mut callback: impl FnMut(Progress<'_>)) -> Result<Report> {
        let _lock = self.lock()?;
        self.mutation_interlocks(&_lock)?;
        let mut transactions = self.load()?;
        self.durable(&transactions)?;
        self.close_finished(&mut transactions)?;
        let mut report = Report::default();
        // Only the newest unreverted batch may be left half undone (`load`
        // rejects an incomplete batch that precedes another active one). So once
        // a newer batch is left over, an older one is only touched if it can be
        // finished completely; otherwise it is reported and left as it was.
        let mut left_over = false;
        for tx in transactions.iter_mut().rev().filter(|t| !t.reverted) {
            if left_over {
                let blockers = self.undo_blockers(tx)?;
                if !blockers.is_empty() {
                    for b in blockers {
                        report.push(b, &mut callback);
                    }
                    continue;
                }
            }
            self.revert_transaction(tx, &mut report, &mut callback)?;
            left_over |= !tx.reverted;
        }
        self.cfa_note(&report.results);
        report.findings = self.findings();
        for tx in transactions.iter().rev().filter(|t| !t.reverted) {
            report.findings.push(Self::journal_finding(tx));
        }
        Ok(report)
    }
}
