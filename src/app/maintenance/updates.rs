//! Windows update discovery and installation jobs.
use super::errors::{friendly_error, why_for_note};
use super::repair::{APPROVAL_SECONDS, PLAN_SECONDS};
use anyhow::{bail, ensure, Result};
use secblitz::patching as patch;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub identity: patch::UpdateIdentity,
    pub title: String,
    pub size_bytes: u64,
    pub license: String,
}

#[derive(Debug, Clone, Default)]
pub struct Found {
    pub updates: Vec<UpdateInfo>,
    #[allow(dead_code)] // raw evidence, never shown on screen
    pub technical: String,
}

impl Found {
    pub fn identities(&self) -> Vec<patch::UpdateIdentity> {
        self.updates.iter().map(|u| u.identity.clone()).collect()
    }
    pub fn total_bytes(&self) -> u64 {
        self.updates.iter().map(|u| u.size_bytes).sum()
    }
}

pub fn summarize_catalog(catalog: &patch::Catalog) -> Found {
    let mut technical = format!("Source: {}\n", catalog.source);
    let updates = catalog
        .updates
        .iter()
        .map(|u| {
            let kb = u.kb_articles.first().cloned().unwrap_or_default();
            technical.push_str(&format!(
                "{} (KB {}) severity {} bundled {}\n",
                u.title,
                kb,
                if u.severity.is_empty() {
                    "n/a"
                } else {
                    &u.severity
                },
                u.bundled.len()
            ));
            UpdateInfo {
                identity: u.identity.clone(),
                title: u.title.clone(),
                size_bytes: u.max_download_bytes,
                license: u.eula.clone(),
            }
        })
        .collect();
    Found { updates, technical }
}

pub use secblitz::space::size_phrase;

const SERVICING_WAIT: Duration = Duration::from_secs(90);

pub fn discover_updates() -> Result<Found, (String, &'static str)> {
    // Windows starts its own servicing workers (update orchestrator, Defender
    // maintenance) at any time and they usually finish within a minute. The
    // patching interlock refuses to search meanwhile; wait instead of failing
    // a search the person just asked for.
    let deadline = Instant::now() + SERVICING_WAIT;
    loop {
        match discover_once() {
            Err((raw, _))
                if raw.contains("servicing process is active") && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_secs(5));
            }
            other => return other,
        }
    }
}

fn discover_once() -> Result<Found, (String, &'static str)> {
    let fail = |e: anyhow::Error| {
        let raw = format!("{e:#}");
        let note = friendly_error(&raw);
        (raw, note)
    };
    let task = patch::discover().map_err(fail)?;
    loop {
        if let Some(catalog) = task.wait(Duration::from_millis(500)).map_err(fail)? {
            return Ok(summarize_catalog(&catalog));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallResult {
    Installed,
    NeedsRestart,
    NotConfirmed,
    Stopped,
    CouldNotFinish,
}

impl InstallResult {
    pub fn title(self) -> &'static str {
        match self {
            Self::Installed => "Your updates are installed",
            Self::NeedsRestart => "Almost done. Please restart your computer.",
            Self::NotConfirmed => "We couldn't confirm every update",
            Self::Stopped => "You stopped the update",
            Self::CouldNotFinish => "We couldn't finish",
        }
    }
    pub fn detail(self) -> &'static str {
        match self {
            Self::Installed => "Your computer has the latest important updates.",
            Self::NeedsRestart => "Windows needs a restart to finish installing.",
            Self::NotConfirmed => "Open Windows Update to see what is left.",
            Self::Stopped => "Nothing else was started. You can run it again any time.",
            Self::CouldNotFinish => "Try again in a few minutes.",
        }
    }
}

pub fn plan_matches(reviewed: &[patch::UpdateIdentity], plan: &patch::Plan) -> bool {
    let mut a: Vec<_> = reviewed.to_vec();
    let mut b: Vec<_> = plan.updates.iter().map(|u| u.identity.clone()).collect();
    a.sort();
    b.sort();
    !a.is_empty() && a == b
}

pub fn classify_install(record: &patch::Record, stopped: bool) -> InstallResult {
    use patch::Status as S;
    match record.status {
        S::RebootRequired => InstallResult::NeedsRestart,
        S::Succeeded => {
            let confirmed = record.verification.as_ref().is_some_and(|v| {
                record
                    .plan
                    .updates
                    .iter()
                    .all(|u| v.installed.contains(&u.identity))
            });
            if confirmed {
                InstallResult::Installed
            } else {
                InstallResult::NotConfirmed
            }
        }
        S::NeedsReview => InstallResult::NotConfirmed,
        _ if stopped => InstallResult::Stopped,
        _ => InstallResult::CouldNotFinish,
    }
}

fn install_in_flight(status: patch::Status) -> bool {
    use patch::Status as S;
    matches!(
        status,
        S::Consumed | S::Downloading | S::Downloaded | S::Installing | S::Verifying
    )
}

pub fn consent_for_sheet() -> patch::Consent {
    patch::Consent {
        owner_opt_in: true,
        accept_windows_update_source: true,
        accept_reviewed_eulas: true,
        acknowledge_no_automatic_rollback: true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStage {
    Preparing,
    Installing,
    Checking,
}

impl InstallStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Preparing => "Getting ready",
            Self::Installing => "Downloading and installing updates",
            Self::Checking => "Making sure everything installed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum InstallEvent {
    Stage {
        stage: InstallStage,
        elapsed: u64,
    },
    Done {
        result: InstallResult,
        note: Option<&'static str>,
        technical: String,
    },
}

pub fn run_install(
    reviewed: Vec<patch::UpdateIdentity>,
    cancel: Arc<AtomicBool>,
    emit: &dyn Fn(InstallEvent),
) {
    let mut technical = String::new();
    let outcome = install_flow(&reviewed, &cancel, emit, &mut technical);
    let stopped = cancel.load(Ordering::SeqCst);
    let (result, note) = match outcome {
        Ok(record) => {
            technical.push_str(&format!("status: {:?}\n", record.status));
            (classify_install(&record, stopped), None)
        }
        Err(e) => {
            let raw = format!("{e:#}");
            technical.push_str(&format!("error: {raw}\n"));
            (
                if stopped {
                    InstallResult::Stopped
                } else {
                    InstallResult::CouldNotFinish
                },
                Some(friendly_error(&raw)),
            )
        }
    };
    emit(InstallEvent::Done {
        result,
        note,
        technical,
    });
}

fn install_flow(
    reviewed: &[patch::UpdateIdentity],
    cancel: &AtomicBool,
    emit: &dyn Fn(InstallEvent),
    technical: &mut String,
) -> Result<patch::Record> {
    ensure!(
        (1..=32).contains(&reviewed.len()),
        "Select between 1 and 32 updates"
    );
    secblitz::platform::ensure_own_process_tree()?;
    for old in patch::list()? {
        if install_in_flight(old.status) {
            let task = patch::verify(old.plan.id)?;
            wait_patch(&task, cancel, emit, InstallStage::Checking)?;
        }
    }
    let plan = {
        let task = patch::plan(patch::PlanRequest {
            selected: reviewed.to_vec(),
            valid_for_seconds: PLAN_SECONDS,
        })?;
        wait_patch(&task, cancel, emit, InstallStage::Preparing)?
    };
    technical.push_str(&format!("plan: {} updates\n", plan.updates.len()));
    if !plan_matches(reviewed, &plan) {
        bail!("The updates changed since they were reviewed; look again");
    }
    patch::approve(plan.id, &plan.digest, consent_for_sheet(), APPROVAL_SECONDS)?;
    let task = patch::start(plan.id, &plan.digest)?;
    let mut record = wait_patch(&task, cancel, emit, InstallStage::Installing)?;
    if install_in_flight(record.status) || record.uncertain && record.verification.is_none() {
        if let Ok(task) = patch::verify(plan.id) {
            if let Ok(verified) = wait_patch(&task, cancel, emit, InstallStage::Checking) {
                record = verified;
            }
        }
    }
    Ok(record)
}

fn wait_patch<T>(
    task: &patch::Task<T>,
    cancel: &AtomicBool,
    emit: &dyn Fn(InstallEvent),
    stage: InstallStage,
) -> Result<T> {
    let started = Instant::now();
    let mut last = Instant::now() - Duration::from_secs(1);
    let mut cancelled = false;
    loop {
        if cancel.load(Ordering::SeqCst) && !cancelled {
            task.request_cancel();
            cancelled = true;
        }
        if let Some(value) = task.wait(Duration::from_millis(500))? {
            return Ok(value);
        }
        if last.elapsed() >= Duration::from_secs(1) {
            last = Instant::now();
            emit(InstallEvent::Stage {
                stage,
                elapsed: started.elapsed().as_secs(),
            });
        }
    }
}

pub fn install_why(result: InstallResult, note: Option<&'static str>) -> &'static str {
    if let Some(n) = note {
        return why_for_note(n);
    }
    match result {
        InstallResult::Installed => "Windows confirmed that every update you chose is installed.",
        InstallResult::NeedsRestart => {
            "The updates are installed. Restart your computer to finish."
        }
        InstallResult::NotConfirmed => {
            "Windows didn't confirm every update. Open Windows Update to see what is left."
        }
        InstallResult::Stopped => "You stopped the update. Nothing else was started.",
        InstallResult::CouldNotFinish => {
            "The update didn't finish. Restart your computer and try again."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn size_phrases_are_short() {
        assert_eq!(size_phrase(0), "");
        assert_eq!(size_phrase(1), "1 MB");
        assert_eq!(size_phrase(300 * 1024 * 1024), "300 MB");
        assert_eq!(size_phrase(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    fn update(n: u128) -> patch::Update {
        patch::Update {
            identity: patch::UpdateIdentity {
                update_id: Uuid::from_u128(n),
                revision: 1,
            },
            title: format!("2026-10 Cumulative Update {n}"),
            description: String::new(),
            kb_articles: vec![format!("50{n}")],
            categories: vec![],
            max_download_bytes: 10 * 1024 * 1024,
            last_changed: String::new(),
            severity: "Critical".into(),
            handler: String::new(),
            reboot_behavior: 1,
            eula: "Terms".into(),
            bundled: vec![],
        }
    }

    fn plan_of(updates: Vec<patch::Update>) -> patch::Plan {
        patch::Plan {
            schema: 1,
            id: Uuid::nil(),
            binding: patch::Binding {
                machine: String::new(),
                original_user: String::new(),
            },
            created_at: 0,
            expires_at: 0,
            source: String::new(),
            updates,
            digest: String::new(),
        }
    }

    #[test]
    fn plan_must_match_the_reviewed_updates() {
        let a = update(1);
        let b = update(2);
        let reviewed = vec![a.identity.clone(), b.identity.clone()];
        assert!(plan_matches(
            &reviewed,
            &plan_of(vec![b.clone(), a.clone()])
        ));
        assert!(!plan_matches(&reviewed, &plan_of(vec![a.clone()])));
        assert!(!plan_matches(&reviewed, &plan_of(vec![a, b, update(3)])));
        assert!(!plan_matches(&[], &plan_of(vec![])));
    }

    #[test]
    fn install_results_require_independent_confirmation() {
        let a = update(1);
        let record = |status, installed: Vec<patch::UpdateIdentity>| patch::Record {
            plan: plan_of(vec![a.clone()]),
            approval: None,
            status,
            process: None,
            uncertain: false,
            verification: Some(patch::Verification {
                installed,
                reboot_pending: false,
                checked_at: 0,
            }),
        };
        use patch::Status as S;
        assert_eq!(
            classify_install(&record(S::Succeeded, vec![a.identity.clone()]), false),
            InstallResult::Installed
        );
        assert_eq!(
            classify_install(&record(S::Succeeded, vec![]), false),
            InstallResult::NotConfirmed
        );
        assert_eq!(
            classify_install(&record(S::RebootRequired, vec![]), false),
            InstallResult::NeedsRestart
        );
        assert_eq!(
            classify_install(&record(S::NeedsReview, vec![]), false),
            InstallResult::NotConfirmed
        );
        assert_eq!(
            classify_install(&record(S::Installing, vec![]), true),
            InstallResult::Stopped
        );
        assert_eq!(
            classify_install(&record(S::Installing, vec![]), false),
            InstallResult::CouldNotFinish
        );
    }

    #[test]
    fn catalog_summary_counts_and_keeps_details_technical() {
        let catalog = patch::Catalog {
            binding: patch::Binding {
                machine: String::new(),
                original_user: String::new(),
            },
            searched_at: 0,
            source: "Microsoft Update".into(),
            updates: vec![update(1), update(2)],
        };
        let found = summarize_catalog(&catalog);
        assert_eq!(found.updates.len(), 2);
        assert_eq!(found.identities().len(), 2);
        assert_eq!(found.total_bytes(), 20 * 1024 * 1024);
        assert!(found.technical.contains("Microsoft Update"));
    }
}
