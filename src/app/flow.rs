use secblitz::advice::{self, Group, NextStep};
use secblitz::engine::Report;
use secblitz::model::CheckStatus;

const ADDONS: &str = "browser.extensions_off";

fn is_addon(item: &secblitz::model::ItemLabel) -> bool {
    item.key.starts_with("chromium:chrome:") || item.key.starts_with("chromium:edge:")
}

pub fn candidates(report: &Report, available: &[String]) -> Vec<String> {
    if report
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Pending)
        || report
            .results
            .iter()
            .any(|r| r.status == CheckStatus::Pending)
    {
        return Vec::new();
    }
    let mut ids = Vec::new();
    for r in &report.results {
        if r.status == CheckStatus::Attention
            && available.contains(&r.id)
            && advice::for_outcome(r).step == NextStep::Repair
            && !ids.contains(&r.id)
            && (r.id != ADDONS || r.items.iter().any(is_addon))
        {
            ids.push(r.id.clone());
        }
    }
    ids
}

pub fn recommended(report: &Report, available: &[String]) -> Vec<String> {
    candidates(report, available)
        .into_iter()
        .filter(|id| !advice::is_choice_check_id(id))
        .collect()
}

/// Turning off some add-ons is done once none of the picked ones is flagged, even while others are.
fn confirmed(verified: &Report, id: &str, picked: &[String]) -> bool {
    verified.results.iter().any(|o| {
        o.id == id
            && (advice::for_outcome(o).group == Group::Protected
                || (id == ADDONS
                    && !picked.is_empty()
                    && o.status == CheckStatus::Attention
                    && !o.items.iter().any(|i| picked.contains(&i.key))))
    })
}

pub fn payoff(
    attempted: &[String],
    picked: &[String],
    applied: &Report,
    verified: &Report,
) -> (Vec<String>, Vec<String>) {
    let mut now: Vec<String> = Vec::new();
    let mut after_restart: Vec<String> = Vec::new();
    for id in attempted {
        let impact = advice::control_impact(id);
        let Some(change) = applied
            .results
            .iter()
            .find(|r| r.id == *id && r.status == CheckStatus::Applied)
        else {
            continue;
        };
        if impact.is_empty() || !confirmed(verified, id, picked) {
            continue;
        }
        let list =
            if advice::for_control(id, &change.status, &change.detail).step == NextStep::Restart {
                &mut after_restart
            } else {
                &mut now
            };
        if !list.iter().any(|k| k == impact) {
            list.push(impact.to_owned());
        }
    }
    (now, after_restart)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub kind: SummaryKind,
    pub protected_now: Vec<String>,
    pub after_restart: Vec<String>,
    /// What the person is no longer protected from after settings were put back.
    pub less_protected: Vec<String>,
    pub done: Vec<String>,
    pub not_done: Vec<(String, String)>,
    pub unverified: bool,
    pub restart: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SummaryKind {
    #[default]
    Success,
    Partial,
    Failed,
}

pub const REASON_BLOCKED: &str =
    "Windows didn't allow this change. Restart your computer, then check again and try once more.";
pub const REASON_RESTART: &str = "Restart your computer first, then try again.";
pub const REASON_MANAGED: &str =
    "Your organization manages this setting, so we left it alone. Ask whoever looks after this computer.";
pub const REASON_UNDO_FIRST: &str = "Press Undo to put back your last fixes, then try again.";
pub const REASON_CHANGED: &str =
    "Something else changed this while we were working. Check again, then try again.";
pub const REASON_STILL_OPEN: &str =
    "This still needs attention after the fix. Restart your computer and check again.";
pub const REASON_KEPT: &str = "We kept your current setting to stay safe. Nothing needs doing.";
pub const REASON_LEFT_AS_IS: &str =
    "It has changed since Secblitz set it, so we left it as it is. Nothing needs doing.";
pub const REASON_NOTHING: &str = "Nothing is recorded to put back for this setting.";
pub const REASON_NEEDS_OTHER: &str =
    "Another protection that is still on needs this one, so we left it as it is.";

pub const REASON_DISK: &str = "Your disk is full or can't be written to right now, so Secblitz can't save changes safely. Free up some space, then check again.";
pub const REASON_BUSY: &str = "Secblitz is finishing another job, like an update or a repair. Wait for it to finish, then try again.";
pub const REASON_EARLIER: &str = "An earlier update or repair didn't finish cleanly, so Secblitz is waiting until it can check it. Restart your computer, then open Secblitz again.";
pub const NOTICE_DISK_READ_ONLY: &str =
    "Your disk can't be written to right now, so fixes will wait.";
pub const NOTICE_DISK_FULL: &str =
    "Your disk is full, so fixes will wait. Free up some space, then check again.";

pub const FAILURE_GENERAL: &str = "Something went wrong, so Secblitz stopped. Close Secblitz and open it again. If it keeps happening, restart your computer or check for a Secblitz update.";
pub const COULDNT_READ: &str = crate::app::os_text::COULDNT_READ;
pub const NOT_DONE: &str = "This change did not go through. Restart your computer, then try again.";

pub fn plain_failure(raw: &str) -> &'static str {
    let r = raw.to_ascii_lowercase();
    if r.contains("holds the journal lock") || r.contains("another secblitz") {
        "Another Secblitz window is already making changes. Close it, wait a moment, then try again."
    } else if r.contains("revert the active transaction") {
        REASON_UNDO_FIRST
    } else if r.contains("deferred:") && r.contains("servicing") {
        crate::app::maintenance::ERR_BUSY
    } else if r.contains("deferred:") && r.contains("busy") {
        REASON_BUSY
    } else if r.contains("deferred:") {
        REASON_EARLIER
    } else if r.contains("readiness blocks") {
        REASON_DISK
    } else if r.contains("journal") || r.contains("transaction completion") {
        "Secblitz can't read its record of your earlier changes, so it stopped to stay safe. Restart your computer and try again. If it keeps happening, check for a Secblitz update."
    } else if r.contains("administrator") || r.contains("elevat") || r.contains("split-token") {
        "Secblitz needs an account that can make changes to this computer. Sign in with one, then open Secblitz again."
    } else if r.contains("could not be read") || r.contains("could not be collected") {
        crate::app::os_text::here(COULDNT_READ)
    } else if r.contains("engine stopped") {
        "Secblitz stopped unexpectedly. Close it and open it again."
    } else if r.contains("select at least one") {
        "Pick at least one fix first."
    } else {
        FAILURE_GENERAL
    }
}

/// Whether waiting and trying again can clear a refusal from the pre-flight check.
pub fn can_retry(raw: &str) -> bool {
    let r = raw.to_ascii_lowercase();
    r.contains("holds the journal lock")
        || r.contains("another secblitz")
        || (r.contains("deferred:") && (r.contains("busy") || r.contains("servicing")))
}

/// The sentence that replaces the fix buttons when the last check found the disk unable to take changes.
pub fn repairs_blocked(report: &Report) -> Option<&'static str> {
    use secblitz::model::Probe;
    let r = report.readiness.as_ref()?;
    if !r.blocks_repairs() {
        return None;
    }
    let read_only = matches!(&r.system_volume, Probe::Known(v) if v.read_only)
        || matches!(&r.journal_volume, Probe::Known(v) if v.read_only);
    Some(if read_only {
        NOTICE_DISK_READ_ONLY
    } else {
        NOTICE_DISK_FULL
    })
}

pub fn plain_detail(status: &CheckStatus, a: &advice::Advice) -> (&'static str, &'static str) {
    match status {
        CheckStatus::Unknown | CheckStatus::Error => {
            ("Couldn't check", crate::app::os_text::here(COULDNT_READ))
        }
        CheckStatus::Skipped if a.status == "Needs your choice" => ("Left as it is", REASON_KEPT),
        CheckStatus::Applied
        | CheckStatus::Unchanged
        | CheckStatus::Restored
        | CheckStatus::Skipped
        | CheckStatus::Conflict
        | CheckStatus::Pending
        | CheckStatus::Attention
        | CheckStatus::Compliant
        | CheckStatus::Ok
        | CheckStatus::Info => (a.status, a.next),
        _ => ("Not done", NOT_DONE),
    }
}

fn reason(status: &CheckStatus, detail: &str, id: &str) -> &'static str {
    let advice = advice::for_control(id, status, detail);
    if advice.status == "Managed elsewhere" {
        REASON_MANAGED
    } else if *status == CheckStatus::Conflict {
        REASON_CHANGED
    } else if *status == CheckStatus::Pending || detail.starts_with("Revert the active transaction")
    {
        REASON_UNDO_FIRST
    } else if detail.to_ascii_lowercase().contains("restart") {
        REASON_RESTART
    } else if *status == CheckStatus::Skipped && detail.contains("readiness blocks") {
        REASON_DISK
    } else if *status == CheckStatus::Skipped {
        REASON_KEPT
    } else {
        REASON_BLOCKED
    }
}

/// What a person is told for one chosen setting that was not put back.
fn chosen_reason(r: &secblitz::engine::Outcome) -> &'static str {
    let detail = r.detail.as_str();
    if r.status == CheckStatus::Conflict {
        REASON_LEFT_AS_IS
    } else if r.status == CheckStatus::Skipped && detail.starts_with("Nothing recorded") {
        REASON_NOTHING
    } else if r.status == CheckStatus::Skipped && detail == "Another protection needs this one" {
        REASON_NEEDS_OTHER
    } else {
        reason(&r.status, detail, &r.id)
    }
}

fn restart_needed(r: &secblitz::engine::Outcome) -> bool {
    advice::for_control(&r.id, &r.status, &r.detail).step == NextStep::Restart
}

pub fn summarize(
    attempted: Option<&[String]>,
    picked: &[String],
    result: Result<&Report, &str>,
    verify: Result<&Report, &str>,
) -> Summary {
    let mut s = Summary {
        unverified: verify.is_err(),
        ..Summary::default()
    };
    let verified = verify.ok();
    match (attempted, result) {
        (Some(ids), Err(e)) => {
            let why = plain_failure(e);
            s.not_done = ids.iter().map(|id| (id.clone(), why.to_owned())).collect();
        }
        (Some(ids), Ok(report)) => {
            for id in ids {
                match report.results.iter().find(|r| r.id == *id) {
                    Some(r)
                        if r.status == CheckStatus::Applied
                            || (r.status == CheckStatus::Unchanged
                                && advice::for_control(&r.id, &r.status, &r.detail).group
                                    == Group::Protected) =>
                    {
                        if verified.is_none_or(|v| confirmed(v, id, picked)) {
                            s.restart |= r.status == CheckStatus::Applied && restart_needed(r);
                            s.done.push(id.clone());
                        } else {
                            s.not_done.push((id.clone(), REASON_STILL_OPEN.to_owned()));
                        }
                    }
                    Some(r) => s
                        .not_done
                        .push((id.clone(), reason(&r.status, &r.detail, id).to_owned())),
                    None => s.not_done.push((id.clone(), REASON_BLOCKED.to_owned())),
                }
            }
            if let Some(v) = verified {
                let (now, later) = payoff(ids, picked, report, v);
                s.protected_now = now;
                s.after_restart = later;
            }
        }
        (None, Err(e)) => {
            s.failure = Some(plain_failure(e).to_owned());
            s.kind = SummaryKind::Failed;
            return s;
        }
        (None, Ok(report)) => {
            for r in &report.results {
                match r.status {
                    CheckStatus::Restored => {
                        s.restart |= restart_needed(r);
                        s.done.push(r.id.clone());
                    }
                    CheckStatus::Unchanged | CheckStatus::Ok | CheckStatus::Compliant => {}
                    _ => s
                        .not_done
                        .push((r.id.clone(), reason(&r.status, &r.detail, &r.id).to_owned())),
                }
            }
        }
    }
    s.kind = if s.done.is_empty() {
        SummaryKind::Failed
    } else if s.not_done.is_empty() {
        SummaryKind::Success
    } else {
        SummaryKind::Partial
    };
    s
}

/// Windows only keeps stack protection on while memory integrity is on, so putting memory integrity back brings stack protection with it when that can be put back too. The flag says a protection was added.
pub fn with_dependents(mut chosen: Vec<String>, undoable: &[String]) -> (Vec<String>, bool) {
    use secblitz::vbs::{MEMORY_INTEGRITY, STACK_PROTECTION};
    let has = |list: &[String], id: &str| list.iter().any(|i| i == id);
    if !has(&chosen, STACK_PROTECTION) && has(undoable, STACK_PROTECTION) {
        if let Some(at) = chosen.iter().position(|i| i == MEMORY_INTEGRITY) {
            chosen.insert(at, STACK_PROTECTION.to_owned());
            return (chosen, true);
        }
    }
    (chosen, false)
}

/// The result of putting back chosen settings: each one is either back the way it was or left as it is, with a plain reason.
pub fn summarize_chosen(
    chosen: &[String],
    result: Result<&Report, &str>,
    verify: Result<&Report, &str>,
) -> Summary {
    let mut s = Summary {
        unverified: verify.is_err(),
        ..Summary::default()
    };
    match result {
        Err(e) => {
            let why = plain_failure(e);
            s.not_done = chosen
                .iter()
                .map(|id| (id.clone(), why.to_owned()))
                .collect();
        }
        Ok(report) => {
            for id in chosen {
                match report.results.iter().find(|r| r.id == *id) {
                    Some(r) if r.status == CheckStatus::Restored => {
                        s.restart |= restart_needed(r);
                        s.done.push(id.clone());
                    }
                    Some(r) if r.status == CheckStatus::Unchanged => s.done.push(id.clone()),
                    Some(r) => s.not_done.push((id.clone(), chosen_reason(r).to_owned())),
                    None => s.not_done.push((id.clone(), REASON_NOTHING.to_owned())),
                }
            }
        }
    }
    for id in &s.done {
        let impact = advice::control_impact(id);
        if !impact.is_empty() && !s.less_protected.iter().any(|k| k == impact) {
            s.less_protected.push(impact.to_owned());
        }
    }
    s.kind = if s.done.is_empty() {
        SummaryKind::Failed
    } else if s.not_done.is_empty() {
        SummaryKind::Success
    } else {
        SummaryKind::Partial
    };
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use secblitz::engine::Outcome;

    fn out(id: &str, status: &str, detail: &str) -> Outcome {
        Outcome {
            id: id.into(),
            status: status.into(),
            detail: detail.into(),
            ..Outcome::default()
        }
    }
    fn rep(results: Vec<Outcome>) -> Report {
        Report {
            results,
            ..Report::default()
        }
    }
    #[test]
    fn choices_are_candidates_but_never_pre_selected() {
        let r = rep(vec![
            out("printer.point_and_print", "attention", ""),
            out("lsa.run_as_ppl", "attention", ""),
            out("privacy.advertising_id", "attention", ""),
            out("autorun.disabled", "compliant", ""),
        ]);
        let available = ids(&[
            "printer.point_and_print",
            "lsa.run_as_ppl",
            "privacy.advertising_id",
            "autorun.disabled",
        ]);
        assert_eq!(
            candidates(&r, &available),
            ids(&[
                "printer.point_and_print",
                "lsa.run_as_ppl",
                "privacy.advertising_id"
            ])
        );
        assert_eq!(
            recommended(&r, &available),
            ids(&["printer.point_and_print"])
        );
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn payoff_only_counts_verified_protected_ids_from_attempted_list() {
        let applied = rep(vec![out("uac.enabled", "applied", "")]);
        let verified = rep(vec![out("uac.enabled", "compliant", "")]);
        let (now, restart) = payoff(&ids(&["uac.enabled"]), &[], &applied, &verified);
        assert!(now[0].contains("system-wide"), "{now:?}");
        assert!(restart.is_empty());
        let (none, _) = payoff(&[], &[], &applied, &verified);
        assert!(none.is_empty());
        let (none, _) = payoff(&ids(&["uac.enabled"]), &[], &applied, &Report::default());
        assert!(none.is_empty());
    }

    #[test]
    fn payoff_restart_required_id_lands_in_second_list() {
        let applied = rep(vec![out(
            "uac.enabled",
            "applied",
            "Preference applied; restart required",
        )]);
        let verified = rep(vec![out("uac.enabled", "compliant", "")]);
        let (now, restart) = payoff(&ids(&["uac.enabled"]), &[], &applied, &verified);
        assert!(now.is_empty());
        assert_eq!(restart.len(), 1);
    }

    #[test]
    fn payoff_still_broken_or_unknown_or_duplicate() {
        let applied = rep(vec![out("uac.enabled", "applied", "")]);
        let verified = rep(vec![out("uac.enabled", "attention", "")]);
        let (now, restart) = payoff(&ids(&["uac.enabled"]), &[], &applied, &verified);
        assert!(now.is_empty() && restart.is_empty());

        let applied = rep(vec![out("unknown.control", "applied", "")]);
        let verified = rep(vec![out("unknown.control", "compliant", "")]);
        let (now, restart) = payoff(&ids(&["unknown.control"]), &[], &applied, &verified);
        assert!(now.is_empty() && restart.is_empty());

        let both = ["permissions.service.bits", "permissions.service.wuauserv"];
        let applied = rep(both.iter().map(|i| out(i, "applied", "")).collect());
        let verified = rep(both.iter().map(|i| out(i, "compliant", "")).collect());
        let (now, _) = payoff(&ids(&both), &[], &applied, &verified);
        assert_eq!(now.len(), 1);
    }

    #[test]
    fn payoff_contradictory_firewall_evidence_excluded() {
        use secblitz::model::{Authority, EffectiveFirewall, InboundAction};
        let id = "firewall.public.inbound";
        let applied = rep(vec![Outcome {
            effective: Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            authority: Some(Authority::Local),
            ..out(id, "applied", "Preference applied; restart required")
        }]);
        let verified = rep(vec![Outcome {
            effective: Some(EffectiveFirewall::Inbound(InboundAction::Allow)),
            authority: Some(Authority::Local),
            ..out(id, "applied", "")
        }]);
        let (now, restart) = payoff(&ids(&[id]), &[], &applied, &verified);
        assert!(now.is_empty() && restart.is_empty());
    }

    #[test]
    fn candidates_are_attention_repairs_only() {
        let report = rep(vec![
            out("uac.enabled", "attention", ""),
            out("uac.consent", "compliant", ""),
            out("not.available", "attention", ""),
            out("uac.enabled", "attention", ""),
        ]);
        let available = ids(&["uac.enabled", "uac.consent"]);
        assert_eq!(candidates(&report, &available), ids(&["uac.enabled"]));
        assert_eq!(recommended(&report, &available), ids(&["uac.enabled"]));
    }

    #[test]
    fn pending_recovery_blocks_every_candidate() {
        let available = ids(&["uac.enabled"]);
        let mut report = rep(vec![out("uac.enabled", "attention", "")]);
        report.findings.push(secblitz::model::Finding {
            title: "Journal recovery".into(),
            status: CheckStatus::Pending,
            detail: String::new(),
        });
        assert!(candidates(&report, &available).is_empty());
        let report = rep(vec![
            out("uac.enabled", "attention", ""),
            out("uac.consent", "pending", ""),
        ]);
        assert!(candidates(&report, &available).is_empty());
    }

    #[test]
    fn apply_success_with_confirmation() {
        let a = ids(&["uac.enabled"]);
        let applied = rep(vec![out("uac.enabled", "applied", "")]);
        let verified = rep(vec![out("uac.enabled", "compliant", "")]);
        let s = summarize(Some(&a), &[], Ok(&applied), Ok(&verified));
        assert_eq!(s.kind, SummaryKind::Success);
        assert_eq!(s.done, a);
        assert_eq!(s.protected_now.len(), 1);
        assert!(!s.unverified && !s.restart && s.not_done.is_empty());
    }

    #[test]
    fn apply_restart_goes_to_after_restart() {
        let a = ids(&["uac.enabled"]);
        let applied = rep(vec![out(
            "uac.enabled",
            "applied",
            "Preference applied; restart required",
        )]);
        let verified = rep(vec![out("uac.enabled", "compliant", "")]);
        let s = summarize(Some(&a), &[], Ok(&applied), Ok(&verified));
        assert_eq!(s.kind, SummaryKind::Success);
        assert!(s.restart && s.protected_now.is_empty());
        assert_eq!(s.after_restart.len(), 1);
    }

    #[test]
    fn apply_partial_maps_reasons() {
        let a = ids(&["uac.enabled", "uac.consent", "defender.ioav"]);
        let applied = rep(vec![
            out("uac.enabled", "applied", ""),
            out(
                "uac.consent",
                "skipped",
                "Domain-managed machine: assessment only",
            ),
            out("defender.ioav", "error", "access denied"),
        ]);
        let verified = rep(vec![
            out("uac.enabled", "compliant", ""),
            out("uac.consent", "attention", ""),
            out("defender.ioav", "attention", ""),
        ]);
        let s = summarize(Some(&a), &[], Ok(&applied), Ok(&verified));
        assert_eq!(s.kind, SummaryKind::Partial);
        assert_eq!(s.done, ids(&["uac.enabled"]));
        assert_eq!(
            s.not_done,
            vec![
                ("uac.consent".to_owned(), REASON_MANAGED.to_owned()),
                ("defender.ioav".to_owned(), REASON_BLOCKED.to_owned()),
            ]
        );
    }

    #[test]
    fn failed_apply_is_failed_and_never_claims_protection() {
        let a = ids(&["uac.enabled"]);
        let verified = rep(vec![out("uac.enabled", "compliant", "")]);
        let s = summarize(Some(&a), &[], Err("disk full"), Ok(&verified));
        assert_eq!(s.kind, SummaryKind::Failed);
        assert!(s.protected_now.is_empty() && s.after_restart.is_empty() && s.done.is_empty());
        assert_eq!(s.not_done.len(), 1);
        assert!(!s.unverified);
        // The cause is technical and must not leak into the plain model.
        assert!(!format!("{s:?}").contains("disk full"));
    }

    #[test]
    fn failed_post_check_is_unverified_and_has_no_payoff() {
        let a = ids(&["uac.enabled"]);
        let applied = rep(vec![out("uac.enabled", "applied", "")]);
        let s = summarize(Some(&a), &[], Ok(&applied), Err("scan unavailable"));
        assert!(s.unverified);
        assert!(s.protected_now.is_empty() && s.after_restart.is_empty());
        assert_eq!(s.done, a);
        let s = summarize(Some(&a), &[], Err("x"), Err("y"));
        assert!(s.unverified);
        assert_eq!(s.kind, SummaryKind::Failed);
    }

    #[test]
    fn applied_but_still_open_after_check_is_not_done() {
        let a = ids(&["uac.enabled"]);
        let applied = rep(vec![out("uac.enabled", "applied", "")]);
        let verified = rep(vec![out("uac.enabled", "attention", "")]);
        let s = summarize(Some(&a), &[], Ok(&applied), Ok(&verified));
        assert_eq!(s.kind, SummaryKind::Failed);
        assert_eq!(s.not_done[0].1, REASON_STILL_OPEN);
    }

    #[test]
    fn turning_off_some_add_ons_is_done_while_others_stay_on() {
        let a = ids(&[ADDONS]);
        let addon = |n: char| secblitz::model::ItemLabel {
            kind: "addon".into(),
            name: n.to_string(),
            key: format!("chromium:edge:{}", n.to_string().repeat(32)),
            why: "sites".into(),
        };
        let applied = rep(vec![out(ADDONS, "applied", "")]);
        let left = |items| {
            rep(vec![Outcome {
                items,
                ..out(ADDONS, "attention", "")
            }])
        };
        let picked = vec![addon('a').key];
        let s = summarize(Some(&a), &picked, Ok(&applied), Ok(&left(vec![addon('b')])));
        assert_eq!(s.kind, SummaryKind::Success);
        assert_eq!(s.done, a);
        assert_eq!(s.protected_now.len(), 1);
        let s = summarize(Some(&a), &picked, Ok(&applied), Ok(&left(vec![addon('a')])));
        assert_eq!(s.not_done[0].1, REASON_STILL_OPEN);
        let s = summarize(Some(&a), &[], Ok(&applied), Ok(&left(vec![addon('b')])));
        assert_eq!(s.not_done[0].1, REASON_STILL_OPEN);
    }

    #[test]
    fn missing_result_and_restart_detail_reasons() {
        let a = ids(&["uac.enabled", "uac.consent"]);
        let applied = rep(vec![out(
            "uac.consent",
            "skipped",
            "restart the computer first",
        )]);
        let s = summarize(Some(&a), &[], Ok(&applied), Ok(&Report::default()));
        assert_eq!(s.not_done[0].1, REASON_BLOCKED);
        assert_eq!(s.not_done[1].1, REASON_RESTART);
    }

    #[test]
    fn undo_success_partial_failed() {
        let verified = rep(vec![]);
        let ok = rep(vec![out("uac.enabled", "restored", "")]);
        let s = summarize(None, &[], Ok(&ok), Ok(&verified));
        assert_eq!(s.kind, SummaryKind::Success);
        assert_eq!(s.done, ids(&["uac.enabled"]));
        assert!(s.protected_now.is_empty());

        let mixed = rep(vec![
            out(
                "uac.enabled",
                "restored",
                "Original preference restored; restart required",
            ),
            out("uac.consent", "conflict", ""),
        ]);
        let s = summarize(None, &[], Ok(&mixed), Err("no"));
        assert_eq!(s.kind, SummaryKind::Partial);
        assert!(s.restart && s.unverified);
        assert_eq!(s.not_done[0].1, REASON_CHANGED);

        assert_eq!(
            summarize(None, &[], Err("boom"), Ok(&verified)).kind,
            SummaryKind::Failed
        );
        assert_eq!(
            summarize(None, &[], Ok(&Report::default()), Ok(&verified)).kind,
            SummaryKind::Failed
        );
    }

    #[test]
    fn chosen_settings_put_back_are_done_and_say_what_is_less_protected() {
        let chosen = ids(&["uac.enabled", "defender.ioav"]);
        let result = rep(vec![
            out("uac.enabled", "restored", "Original preference restored"),
            out(
                "defender.ioav",
                "unchanged",
                "Original preference already present",
            ),
        ]);
        let s = summarize_chosen(&chosen, Ok(&result), Ok(&rep(vec![])));
        assert_eq!(s.kind, SummaryKind::Success);
        assert_eq!(s.done, chosen);
        assert!(s.not_done.is_empty() && !s.unverified && !s.restart);
        assert!(s.protected_now.is_empty() && s.after_restart.is_empty());
        let impacts: Vec<&str> = chosen.iter().map(|i| advice::control_impact(i)).collect();
        assert!(impacts.iter().all(|i| !i.is_empty()));
        assert_eq!(s.less_protected, impacts);
    }

    #[test]
    fn chosen_settings_left_as_they_are_get_plain_reasons() {
        let chosen = ids(&[
            "uac.enabled",
            "uac.consent",
            "defender.ioav",
            "defender.archive",
            "lsa.restrict_anonymous_sam",
        ]);
        let result = rep(vec![
            out(
                "uac.enabled",
                "conflict",
                "Preference differs from both target and before image; no write performed",
            ),
            out("uac.consent", "skipped", "Nothing recorded to put back"),
            out(
                "defender.ioav",
                "skipped",
                "Another protection needs this one",
            ),
            out(
                "defender.archive",
                "restored",
                "Original preference restored; restart required",
            ),
        ]);
        let s = summarize_chosen(&chosen, Ok(&result), Ok(&rep(vec![])));
        assert_eq!(s.kind, SummaryKind::Partial);
        assert_eq!(s.done, ids(&["defender.archive"]));
        assert!(s.restart);
        assert_eq!(
            s.not_done,
            vec![
                ("uac.enabled".to_owned(), REASON_LEFT_AS_IS.to_owned()),
                ("uac.consent".to_owned(), REASON_NOTHING.to_owned()),
                ("defender.ioav".to_owned(), REASON_NEEDS_OTHER.to_owned()),
                (
                    "lsa.restrict_anonymous_sam".to_owned(),
                    REASON_NOTHING.to_owned()
                ),
            ]
        );
        assert_eq!(s.less_protected.len(), 1);
    }

    #[test]
    fn memory_integrity_brings_stack_protection_when_that_can_be_put_back() {
        use secblitz::vbs::{MEMORY_INTEGRITY, STACK_PROTECTION};
        let both = ids(&[STACK_PROTECTION, MEMORY_INTEGRITY]);
        assert_eq!(
            with_dependents(ids(&[MEMORY_INTEGRITY]), &both),
            (both.clone(), true)
        );
        assert_eq!(
            with_dependents(ids(&[MEMORY_INTEGRITY, STACK_PROTECTION]), &both),
            (ids(&[MEMORY_INTEGRITY, STACK_PROTECTION]), false)
        );
        assert_eq!(
            with_dependents(ids(&[MEMORY_INTEGRITY]), &ids(&[MEMORY_INTEGRITY])),
            (ids(&[MEMORY_INTEGRITY]), false)
        );
        assert_eq!(
            with_dependents(ids(&[STACK_PROTECTION]), &both),
            (ids(&[STACK_PROTECTION]), false)
        );
    }

    #[test]
    fn a_failed_chosen_undo_changes_nothing_and_says_why() {
        let chosen = ids(&["uac.enabled"]);
        let s = summarize_chosen(
            &chosen,
            Err("Another Secblitz operation holds the journal lock"),
            Err("x"),
        );
        assert_eq!(s.kind, SummaryKind::Failed);
        assert!(s.done.is_empty() && s.less_protected.is_empty() && s.unverified);
        assert!(s.not_done[0].1.contains("Close it"));
        let s = summarize_chosen(&chosen, Err("boom 0xdead"), Ok(&rep(vec![])));
        assert_eq!(s.not_done[0].1, FAILURE_GENERAL);
        assert!(!format!("{s:?}").contains("0xdead"));
    }

    #[test]
    fn managed_and_unfinished_chosen_settings_use_the_shared_reasons() {
        let chosen = ids(&["uac.consent", "uac.enabled"]);
        let result = rep(vec![
            out(
                "uac.consent",
                "skipped",
                "Domain-managed machine: assessment only",
            ),
            out(
                "uac.enabled",
                "skipped",
                "Revert the active transaction before undoing chosen controls",
            ),
        ]);
        let s = summarize_chosen(&chosen, Ok(&result), Ok(&rep(vec![])));
        assert_eq!(s.not_done[0].1, REASON_MANAGED);
        assert_eq!(s.not_done[1].1, REASON_UNDO_FIRST);
    }

    #[test]
    fn known_raw_failures_get_a_friendly_fix() {
        assert!(
            plain_failure("Another Secblitz operation holds the journal lock").contains("Close it")
        );
        assert!(plain_failure("Interactive split-token administrator required; service/over-the-shoulder elevation unsupported")
            .contains("Sign in with"));
        assert!(plain_failure("Journal exceeds size limit").contains("Restart your computer"));
    }

    #[test]
    fn unknown_failures_never_echo_raw_text() {
        let raw = "HRESULT 0x80070005 at C:\\secret\\path";
        let msg = plain_failure(raw);
        assert_eq!(msg, FAILURE_GENERAL);
        assert!(!msg.contains("HRESULT") && !msg.contains("secret"));
    }

    #[test]
    fn detail_lines_never_use_raw_detail() {
        let a = advice::for_control("uac.enabled", &CheckStatus::Error, "boom 0xdead");
        let (st, next) = plain_detail(&CheckStatus::Error, &a);
        assert_eq!(st, "Couldn't check");
        assert!(!next.contains("0xdead"));
        let (st, next) = plain_detail(&CheckStatus::Other("weird".into()), &a);
        assert_eq!((st, next), ("Not done", NOT_DONE));
    }

    #[test]
    fn failure_precedence_and_narrow_matching() {
        assert_eq!(
            plain_failure("Revert the active transaction before applying"),
            REASON_UNDO_FIRST
        );
        assert!(
            plain_failure("Another Secblitz operation holds the journal lock").contains("Close it")
        );
        assert_eq!(
            plain_failure("Access is denied. (os error 5)"),
            FAILURE_GENERAL
        );
        assert_eq!(plain_failure("permission denied"), FAILURE_GENERAL);
    }

    #[test]
    fn whole_apply_failure_uses_the_matching_plain_reason() {
        let a = ids(&["uac.enabled"]);
        let verified = rep(vec![out("uac.enabled", "compliant", "")]);
        let s = summarize(
            Some(&a),
            &[],
            Err("Another Secblitz operation holds the journal lock"),
            Ok(&verified),
        );
        assert!(s.not_done[0].1.contains("Close it"));
    }

    #[test]
    fn refusals_from_the_pre_flight_get_their_own_plain_line() {
        assert_eq!(
            plain_failure("Deferred: shared engine.lock is busy"),
            REASON_BUSY
        );
        assert_eq!(
            plain_failure(
                "Deferred: unresolved patching intent/reboot; independent verification required"
            ),
            REASON_EARLIER
        );
        assert_eq!(
            plain_failure("Repair readiness blocks new changes"),
            REASON_DISK
        );
        assert_eq!(
            plain_failure("Deferred: a Windows servicing process is active"),
            crate::app::maintenance::ERR_BUSY
        );
        assert!(can_retry("Deferred: shared engine.lock is busy"));
        assert!(can_retry("Deferred: a Windows servicing process is active"));
        assert!(!can_retry(
            "Deferred: updater installation requires completion"
        ));
        assert!(can_retry(
            "Another Secblitz operation holds the journal lock"
        ));
        assert!(!can_retry("Repair readiness blocks new changes"));
        assert!(!can_retry(
            "Revert the active transaction before applying again"
        ));
    }

    #[test]
    fn a_full_disk_is_never_reported_as_a_kept_setting() {
        let r = rep(vec![out(
            "defender.realtime",
            "skipped",
            "Repair readiness blocks new changes",
        )]);
        let s = summarize(Some(&ids(&["defender.realtime"])), &[], Ok(&r), Ok(&r));
        assert_eq!(s.not_done[0].1, REASON_DISK);
    }

    #[test]
    fn a_failed_undo_says_why() {
        let s = summarize(
            None,
            &[],
            Err("Another Secblitz operation holds the journal lock"),
            Err("x"),
        );
        assert_eq!(s.kind, SummaryKind::Failed);
        assert!(s.failure.unwrap().contains("Close it"));
    }

    #[test]
    fn blocked_repairs_name_the_disk_problem() {
        use secblitz::model::{Probe, Readiness, VolumeReadiness};
        let with = |readiness| Report {
            readiness: Some(readiness),
            ..Report::default()
        };
        assert_eq!(repairs_blocked(&Report::default()), None);
        assert_eq!(repairs_blocked(&with(Readiness::default())), None);
        let vol = |bytes, read_only| {
            Probe::Known(VolumeReadiness {
                available_bytes: bytes,
                read_only,
            })
        };
        let ro = Readiness {
            system_volume: vol(5, true),
            ..Default::default()
        };
        assert_eq!(repairs_blocked(&with(ro)), Some(NOTICE_DISK_READ_ONLY));
        let full = Readiness {
            journal_volume: vol(0, false),
            ..Default::default()
        };
        assert_eq!(repairs_blocked(&with(full)), Some(NOTICE_DISK_FULL));
    }

    #[test]
    fn every_plain_message_is_translated() {
        use crate::i18n::Lang;
        let raws = [
            "Another Secblitz operation holds the journal lock",
            "Journal exceeds size limit",
            "Interactive split-token administrator required",
            "Findings could not be read",
            "engine stopped",
            "Select at least one fix",
            "Revert the active transaction",
            "Deferred: a Windows servicing process is active",
            "Repair readiness blocks new changes",
            "anything else",
        ];
        let mut all: Vec<&str> = raws.iter().map(|r| plain_failure(r)).collect();
        all.extend([
            REASON_BLOCKED,
            REASON_RESTART,
            REASON_MANAGED,
            REASON_UNDO_FIRST,
            REASON_CHANGED,
            REASON_STILL_OPEN,
            REASON_KEPT,
            REASON_LEFT_AS_IS,
            REASON_NOTHING,
            REASON_NEEDS_OTHER,
            REASON_DISK,
            REASON_BUSY,
            REASON_EARLIER,
            NOTICE_DISK_READ_ONLY,
            NOTICE_DISK_FULL,
            FAILURE_GENERAL,
            COULDNT_READ,
            NOT_DONE,
            "Couldn't check",
            "Not done",
            "Left as it is",
        ]);
        for text in all {
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                assert_ne!(lang.t(text), text, "{} missing for {text}", lang.code());
            }
        }
    }
}
