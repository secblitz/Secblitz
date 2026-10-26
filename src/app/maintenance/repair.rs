//! Repair planning and the supervised system-file check and repair run.
use super::errors::{friendly_error, why_for_note};
use anyhow::{ensure, Result};
use secblitz::operations::{self as ops, OperationKind as Op};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairKind {
    Check,
    Repair,
}

pub const PLAN_SECONDS: u64 = 3600;
pub const APPROVAL_SECONDS: u64 = 900;
pub const GRANT_SECONDS: u64 = 2 * 3600;

impl RepairKind {
    /// Separate plans, run one after another. The engine lets an approval live
    /// at most 15 minutes and re-checks it before every step, so long jobs get
    /// a fresh, exact approval per part instead of one plan that would expire.
    pub fn chunks(self) -> Vec<Vec<Op>> {
        match self {
            Self::Check => vec![vec![Op::DismCheckHealth], vec![Op::SfcVerify]],
            Self::Repair => vec![vec![Op::DismRestoreHealth], vec![Op::SfcRepair]],
        }
    }
    pub fn all_operations(self) -> Vec<Op> {
        let mut all = Vec::new();
        for chunk in self.chunks() {
            for kind in expand(&chunk) {
                if !all.contains(&kind) {
                    all.push(kind);
                }
            }
        }
        all
    }
}

pub fn expand(requested: &[Op]) -> Vec<Op> {
    let mut selected = requested.to_vec();
    if selected.contains(&Op::DismRestoreHealth) && !selected.contains(&Op::DismScanHealth) {
        selected.push(Op::DismScanHealth);
    }
    if selected.contains(&Op::SfcRepair) && !selected.contains(&Op::SfcVerify) {
        selected.push(Op::SfcVerify);
    }
    [
        Op::DismCheckHealth,
        Op::DismScanHealth,
        Op::DismRestoreHealth,
        Op::SfcVerify,
        Op::SfcRepair,
        Op::DefenderQuickScan,
    ]
    .into_iter()
    .filter(|k| selected.contains(k))
    .collect()
}

pub fn plan_request(chunk: &[Op]) -> ops::PlanRequest {
    ops::PlanRequest {
        operations: chunk.to_vec(),
        valid_for_seconds: PLAN_SECONDS,
    }
}

pub fn policy_for(current: &ops::OwnerPolicy, needed: &[Op], now: u64) -> ops::OwnerPolicy {
    use ops::{ExceptionScope, PolicyException, Risk};
    let mut policy = current.clone();
    for kind in needed {
        if !policy.allowed.contains(kind) {
            policy.allowed.push(*kind);
        }
    }
    let changes_system = needed.iter().any(|k| k.spec().risk != Risk::DiagnosticIo);
    if changes_system {
        let until = now + GRANT_SECONDS;
        if policy.opt_in_until.is_none_or(|t| t < until) {
            policy.opt_in_until = Some(until);
        }
    }
    const SCOPES: [ExceptionScope; 2] =
        [ExceptionScope::ActiveUse, ExceptionScope::MaintenanceWindow];
    policy.exceptions.retain(|e| {
        e.expires_at > now && !(needed.contains(&e.operation) && SCOPES.contains(&e.scope))
    });
    for kind in needed {
        for scope in SCOPES {
            policy.exceptions.push(PolicyException {
                operation: *kind,
                scope,
                expires_at: now + GRANT_SECONDS,
            });
        }
    }
    policy
}

pub fn step_label(kind: Op) -> &'static str {
    match kind {
        Op::DismCheckHealth => "Taking a quick look at Windows",
        Op::DismScanHealth => "Scanning Windows for problems",
        Op::DismRestoreHealth => "Repairing Windows",
        Op::SfcVerify => "Checking your system files",
        Op::SfcRepair => "Repairing your system files",
        Op::DefenderQuickScan => "Scanning for viruses",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairResult {
    NoProblems,
    ProblemsFound,
    Repaired,
    NeedsRestart,
    Stopped,
    CouldNotFinish,
}

impl RepairResult {
    pub fn title(self) -> &'static str {
        match self {
            Self::NoProblems => "No problems found",
            Self::ProblemsFound => "Some problems were found",
            Self::Repaired => "Problems were repaired",
            Self::NeedsRestart => "Almost done. Please restart your computer.",
            Self::Stopped => "You stopped the repair",
            Self::CouldNotFinish => "We couldn't finish",
        }
    }
    pub fn detail(self) -> &'static str {
        match self {
            Self::NoProblems => "Windows looks healthy.",
            Self::ProblemsFound => "You can use Repair system files to fix them.",
            Self::Repaired => "Windows is healthy again.",
            Self::NeedsRestart => "Windows needs a restart to finish the repair.",
            Self::Stopped => "Nothing else was started. You can run it again any time.",
            Self::CouldNotFinish => "Nothing is broken by this. Try again in a few minutes.",
        }
    }
}

fn step_unresolved(step: &ops::StepRecord) -> bool {
    use ops::StepState as S;
    matches!(
        step.state,
        S::Intent | S::Running | S::Monitoring | S::Verifying | S::RebootRequired
    ) || (step.state == S::NeedsReview
        && matches!(step.evidence, None | Some(ops::Evidence::Inconclusive)))
}

pub fn classify(kind: RepairKind, records: &[ops::PlanRecord], stopped: bool) -> RepairResult {
    use ops::StepState as S;
    let steps: Vec<(Op, &ops::StepRecord)> = records
        .iter()
        .flat_map(|r| {
            r.plan
                .steps
                .iter()
                .map(|s| s.operation.kind)
                .zip(r.steps.iter())
        })
        .collect();
    if steps.iter().any(|(_, s)| s.state == S::Failed) {
        return RepairResult::CouldNotFinish;
    }
    if steps.iter().any(|(_, s)| s.state == S::RebootRequired) {
        return RepairResult::NeedsRestart;
    }
    if stopped {
        return RepairResult::Stopped;
    }
    let expected = kind.all_operations();
    let ran = |op: Op| steps.iter().any(|(k, _)| *k == op);
    if records.is_empty() || !expected.iter().all(|op| ran(*op)) {
        return RepairResult::CouldNotFinish;
    }
    match kind {
        RepairKind::Check => {
            if steps.iter().any(|(_, s)| s.state != S::Succeeded) {
                return RepairResult::CouldNotFinish;
            }
            let damaged = steps.iter().any(|(_, s)| {
                matches!(
                    s.evidence,
                    Some(ops::Evidence::ComponentStoreRepairable)
                        | Some(ops::Evidence::ComponentStoreNonRepairable)
                )
            });
            if damaged {
                RepairResult::ProblemsFound
            } else {
                RepairResult::NoProblems
            }
        }
        RepairKind::Repair => {
            let only_unproven_files = steps.iter().all(|(op, s)| {
                s.state == S::Succeeded
                    || (*op == Op::SfcRepair
                        && s.state == S::NeedsReview
                        && s.evidence == Some(ops::Evidence::DiagnosticCompleted))
            });
            if !only_unproven_files {
                RepairResult::CouldNotFinish
            } else if steps.iter().all(|(_, s)| s.state == S::Succeeded) {
                RepairResult::Repaired
            } else {
                RepairResult::NeedsRestart
            }
        }
    }
}

pub fn technical_lines(records: &[ops::PlanRecord]) -> String {
    let mut out = String::new();
    for record in records {
        for (step, state) in record.plan.steps.iter().zip(&record.steps) {
            out.push_str(&format!(
                "{}: {:?}, exit code {}, evidence {}\n",
                step.operation.kind.as_str(),
                state.state,
                state.exit_code.map_or("none".into(), |c| c.to_string()),
                state.evidence.map_or("none".into(), |e| format!("{e:?}")),
            ));
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct RepairProgress {
    pub label: &'static str,
    pub step: usize,
    pub total: usize,
    pub elapsed: u64,
    pub step_elapsed: u64,
}

#[derive(Debug, Clone)]
pub enum RepairEvent {
    Preparing,
    Progress(RepairProgress),
    Done {
        result: RepairResult,
        note: Option<&'static str>,
        technical: String,
    },
}

pub fn run_repair(kind: RepairKind, cancel: Arc<AtomicBool>, emit: &dyn Fn(RepairEvent)) {
    emit(RepairEvent::Preparing);
    let mut records = Vec::new();
    let outcome = repair_flow(kind, &cancel, emit, &mut records);
    let stopped = cancel.load(Ordering::SeqCst);
    let mut technical = technical_lines(&records);
    let (result, note) = match outcome {
        Ok(()) => (classify(kind, &records, stopped), None),
        Err(e) => {
            let raw = format!("{e:#}");
            technical.push_str(&format!("error: {raw}\n"));
            let result = if stopped && records.is_empty() {
                RepairResult::Stopped
            } else {
                RepairResult::CouldNotFinish
            };
            (result, Some(friendly_error(&raw)))
        }
    };
    emit(RepairEvent::Done {
        result,
        note,
        technical,
    });
}

fn repair_flow(
    kind: RepairKind,
    cancel: &AtomicBool,
    emit: &dyn Fn(RepairEvent),
    records: &mut Vec<ops::PlanRecord>,
) -> Result<()> {
    secblitz::platform::ensure_own_process_tree()?;
    let all = kind.all_operations();
    let original = ops::policy()?;
    let wanted = policy_for(&original, &all, unix_now()?);
    let changed = wanted != original;
    if changed {
        ops::set_policy(wanted)?;
    }
    let result = repair_steps(kind, cancel, emit, records, all.len());
    if changed {
        let _ = ops::set_policy(original);
    }
    result
}

fn repair_steps(
    kind: RepairKind,
    cancel: &AtomicBool,
    emit: &dyn Fn(RepairEvent),
    records: &mut Vec<ops::PlanRecord>,
    total: usize,
) -> Result<()> {
    for old in ops::list()? {
        if old.consumed && old.steps.iter().any(step_unresolved) {
            let kinds: Vec<Op> = old.plan.steps.iter().map(|s| s.operation.kind).collect();
            let task = ops::resume(old.plan.id)?;
            supervise_operation(&task, cancel, emit, &kinds, 0, total)?;
        }
    }
    let mut done = 0;
    for chunk in kind.chunks() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let kinds = expand(&chunk);
        let plan = ops::plan(plan_request(&chunk))?;
        let planned: Vec<Op> = plan.steps.iter().map(|s| s.operation.kind).collect();
        ensure!(
            planned == kinds,
            "The prepared plan did not match the request"
        );
        let approved = ops::approve(plan.id, &plan.digest, APPROVAL_SECONDS)?;
        ensure!(
            approved.plan.digest == plan.digest
                && approved
                    .approval
                    .as_ref()
                    .is_some_and(|a| a.digest == plan.digest)
                && !approved.consumed,
            "The approval did not match the prepared plan"
        );
        let task = ops::start(plan.id)?;
        let mut record = supervise_operation(&task, cancel, emit, &kinds, done, total)?;
        if record.steps.iter().any(step_unresolved) && !cancel.load(Ordering::SeqCst) {
            if let Ok(task) = ops::resume(plan.id) {
                if let Ok(verified) = supervise_operation(&task, cancel, emit, &kinds, done, total)
                {
                    record = verified;
                }
            }
        }
        done += record.steps.len();
        let finished = record
            .steps
            .iter()
            .all(|s| s.state == ops::StepState::Succeeded);
        records.push(record);
        if !finished {
            break;
        }
    }
    Ok(())
}

fn supervise_operation(
    task: &ops::Task,
    cancel: &AtomicBool,
    emit: &dyn Fn(RepairEvent),
    kinds: &[Op],
    done: usize,
    total: usize,
) -> Result<ops::PlanRecord> {
    let started = Instant::now();
    let mut last = Instant::now() - Duration::from_secs(1);
    let mut step = (0, Instant::now());
    let mut cancelled = false;
    loop {
        if cancel.load(Ordering::SeqCst) && !cancelled {
            task.request_cancel();
            cancelled = true;
        }
        if let Some(record) = task.wait(Duration::from_millis(500))? {
            return Ok(record);
        }
        if last.elapsed() >= Duration::from_secs(1) {
            last = Instant::now();
            let index = task.progress().ok().and_then(|p| p.step).unwrap_or(0);
            if index != step.0 {
                step = (index, Instant::now());
            }
            let kind = kinds
                .get(index)
                .or(kinds.first())
                .copied()
                .unwrap_or(Op::DismCheckHealth);
            emit(RepairEvent::Progress(RepairProgress {
                label: step_label(kind),
                step: (done + index + 1).min(total.max(1)),
                total: total.max(1),
                elapsed: started.elapsed().as_secs(),
                step_elapsed: step.1.elapsed().as_secs(),
            }));
        }
    }
}

pub fn repair_why(result: RepairResult, note: Option<&'static str>) -> &'static str {
    if let Some(n) = note {
        return why_for_note(n);
    }
    match result {
        RepairResult::NoProblems => "Windows checked itself and found nothing wrong.",
        RepairResult::ProblemsFound => {
            "Windows found files that need repairing. Choose Repair system files to fix them."
        }
        RepairResult::Repaired => {
            "Windows repaired the problems it found. You don't need to do anything else."
        }
        RepairResult::NeedsRestart => "Restart your computer to finish the repair.",
        RepairResult::Stopped => "You stopped the repair. Nothing else was started.",
        RepairResult::CouldNotFinish => {
            "The repair didn't finish. Restart your computer and try again."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn plan_requests_use_allowlisted_operations_and_valid_lifetimes() {
        for kind in [RepairKind::Check, RepairKind::Repair] {
            for chunk in kind.chunks() {
                let request = plan_request(&chunk);
                assert_eq!(request.operations, chunk);
                assert!((1..=86400).contains(&request.valid_for_seconds));
            }
        }
        const { assert!(APPROVAL_SECONDS <= 15 * 60) };
        const { assert!(GRANT_SECONDS <= 24 * 3600) };
    }

    #[test]
    fn dependencies_are_expanded_like_the_engine() {
        assert_eq!(
            expand(&[Op::DismRestoreHealth]),
            vec![Op::DismScanHealth, Op::DismRestoreHealth]
        );
        assert_eq!(expand(&[Op::SfcRepair]), vec![Op::SfcVerify, Op::SfcRepair]);
        assert_eq!(
            RepairKind::Repair.all_operations(),
            vec![
                Op::DismScanHealth,
                Op::DismRestoreHealth,
                Op::SfcVerify,
                Op::SfcRepair
            ]
        );
        assert_eq!(
            RepairKind::Check.all_operations(),
            vec![Op::DismCheckHealth, Op::SfcVerify]
        );
    }

    #[test]
    fn repair_policy_adds_only_what_is_needed_and_expires() {
        let now = 1_000_000;
        let current = ops::OwnerPolicy::default();
        let check = policy_for(&current, &RepairKind::Check.all_operations(), now);
        assert_eq!(
            check.allowed, current.allowed,
            "diagnostics already allowed"
        );
        assert_eq!(check.opt_in_until, None, "a check needs no opt-in");
        assert!(check
            .exceptions
            .iter()
            .all(|e| e.expires_at == now + GRANT_SECONDS));

        let repair = policy_for(&current, &RepairKind::Repair.all_operations(), now);
        assert!(repair.allowed.contains(&Op::DismRestoreHealth));
        assert!(repair.allowed.contains(&Op::SfcRepair));
        assert!(!repair.allowed.contains(&Op::DefenderQuickScan));
        assert_eq!(repair.opt_in_until, Some(now + GRANT_SECONDS));
        assert!(repair.allowed.len() <= 6);
        assert_eq!(repair.window, current.window);
        assert_eq!(repair.idle_seconds, current.idle_seconds);
        assert!(repair
            .exceptions
            .iter()
            .all(|e| { repair.allowed.contains(&e.operation) && e.expires_at - now <= 24 * 3600 }));
        let scopes: Vec<_> = repair
            .exceptions
            .iter()
            .map(|e| (e.operation, e.scope))
            .collect();
        assert!(
            scopes
                .iter()
                .enumerate()
                .all(|(i, s)| !scopes[..i].contains(s)),
            "no duplicate scoped exceptions"
        );
        let again = policy_for(&repair, &RepairKind::Repair.all_operations(), now + 5);
        assert_eq!(again.exceptions.len(), repair.exceptions.len());
    }

    #[test]
    fn expired_exceptions_are_dropped_and_longer_opt_in_is_kept() {
        let now = 5_000_000;
        let mut current = ops::OwnerPolicy::default();
        current.allowed.push(Op::SfcRepair);
        current.opt_in_until = Some(now + 10 * 3600);
        current.exceptions.push(ops::PolicyException {
            operation: Op::SfcRepair,
            scope: ops::ExceptionScope::MeteredNetwork,
            expires_at: now - 1,
        });
        let p = policy_for(&current, &[Op::SfcVerify], now);
        assert_eq!(p.opt_in_until, Some(now + 10 * 3600));
        assert!(p.exceptions.iter().all(|e| e.expires_at > now));
    }

    fn record(
        kind: RepairKind,
        states: &[(ops::StepState, Option<ops::Evidence>)],
    ) -> Vec<ops::PlanRecord> {
        let mut next = states.iter();
        let mut out = Vec::new();
        for chunk in kind.chunks() {
            let kinds = expand(&chunk);
            let mut steps = Vec::new();
            let mut recs = Vec::new();
            for k in kinds {
                let (state, evidence) = *next.next().unwrap();
                steps.push(ops::PlanStep {
                    operation: k.spec(),
                    depends_on: vec![],
                });
                recs.push(ops::StepRecord {
                    state,
                    evidence,
                    ..Default::default()
                });
            }
            out.push(ops::PlanRecord {
                plan: ops::Plan {
                    schema: 1,
                    id: Uuid::nil(),
                    machine: String::new(),
                    created_at: 0,
                    expires_at: 0,
                    policy: ops::OwnerPolicy::default(),
                    steps,
                    digest: String::new(),
                },
                approval: None,
                consumed: true,
                steps: recs,
            });
        }
        out
    }

    #[test]
    fn check_results_are_plain() {
        use ops::{Evidence as E, StepState as S};
        let ok = record(
            RepairKind::Check,
            &[
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::Succeeded, Some(E::DiagnosticCompleted)),
            ],
        );
        assert_eq!(
            classify(RepairKind::Check, &ok, false),
            RepairResult::NoProblems
        );
        let bad = record(
            RepairKind::Check,
            &[
                (S::Succeeded, Some(E::ComponentStoreRepairable)),
                (S::Succeeded, Some(E::DiagnosticCompleted)),
            ],
        );
        assert_eq!(
            classify(RepairKind::Check, &bad, false),
            RepairResult::ProblemsFound
        );
        let failed = record(
            RepairKind::Check,
            &[(S::Failed, None), (S::Cancelled, None)],
        );
        assert_eq!(
            classify(RepairKind::Check, &failed, false),
            RepairResult::CouldNotFinish
        );
        assert_eq!(
            classify(RepairKind::Check, &[], false),
            RepairResult::CouldNotFinish
        );
        let half = record(
            RepairKind::Check,
            &[
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::Cancelled, None),
            ],
        );
        assert_eq!(
            classify(RepairKind::Check, &half, true),
            RepairResult::Stopped
        );
    }

    #[test]
    fn repair_results_are_honest() {
        use ops::{Evidence as E, StepState as S};
        let finished = record(
            RepairKind::Repair,
            &[
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::Succeeded, Some(E::DiagnosticCompleted)),
                (S::NeedsReview, Some(E::DiagnosticCompleted)),
            ],
        );
        assert_eq!(
            classify(RepairKind::Repair, &finished, false),
            RepairResult::NeedsRestart
        );
        let reboot = record(
            RepairKind::Repair,
            &[
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::RebootRequired, None),
                (S::Pending, None),
                (S::Pending, None),
            ],
        );
        assert_eq!(
            classify(RepairKind::Repair, &reboot, false),
            RepairResult::NeedsRestart
        );
        let unproven = record(
            RepairKind::Repair,
            &[
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::NeedsReview, Some(E::Inconclusive)),
                (S::Cancelled, None),
                (S::Cancelled, None),
            ],
        );
        assert_eq!(
            classify(RepairKind::Repair, &unproven, false),
            RepairResult::CouldNotFinish
        );
    }

    #[test]
    fn technical_details_keep_the_raw_evidence() {
        use ops::{Evidence as E, StepState as S};
        let r = record(
            RepairKind::Check,
            &[
                (S::Succeeded, Some(E::ComponentStoreHealthy)),
                (S::Succeeded, Some(E::DiagnosticCompleted)),
            ],
        );
        let text = technical_lines(&r);
        assert!(text.contains("dism_check_health") && text.contains("sfc_verify"));
    }
}
