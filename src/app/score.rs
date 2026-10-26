//! Protection score: protected checks over all checks (findings excluded).
use secblitz::advice::{self, Group};
use secblitz::engine::{cfa, Outcome, Report};
use secblitz::model::{Authority, CheckStatus};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Score {
    pub protected: usize,
    pub total: usize,
    pub attention: usize,
    pub unknown: usize,
    pub managed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Protected,
    Attention,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Protected,
    Fixable,
    Review,
    Managed,
    Unknown,
    Excluded,
}

pub fn classify(r: &Outcome) -> Class {
    let unavailable = r.authority == Some(Authority::Unknown)
        || (r.id.starts_with("firewall.")
            && !secblitz::hardening::is_hardening_check_id(&r.id)
            && (r.effective.is_none() || r.authority.is_none()));
    let known = matches!(
        r.status.as_str(),
        "compliant"
            | "ok"
            | "applied"
            | "restored"
            | "unchanged"
            | "attention"
            | "skipped"
            | "conflict"
            | "pending"
            | "info"
            | "review"
    );
    if r.status == CheckStatus::Error
        || unavailable
        || matches!(r.status.as_str(), "unknown" | "unsupported")
        || !known
    {
        return Class::Unknown;
    }
    let a = advice::for_outcome(r);
    if managed(&a) {
        return Class::Managed;
    }
    if a.step == advice::NextStep::CheckAgain {
        return Class::Unknown;
    }
    if a.status == "Left as it is" {
        // Deliberately not edited (an unusual permission layout): nothing for
        // the person to do and never claimed as protected. A note only.
        return Class::Excluded;
    }
    class_of_group(&a)
}

fn class_of_group(a: &advice::Advice) -> Class {
    match a.group {
        Group::Protected => Class::Protected,
        Group::Recommended => Class::Fixable,
        Group::Choice => Class::Review,
        Group::Information => Class::Excluded,
    }
}

fn managed(a: &advice::Advice) -> bool {
    a.status == "Managed elsewhere"
}

/// Classify a diagnostic finding. `info` findings are "Good to know" notes:
/// `Class::Excluded` means they are never counted as something to check.
pub fn classify_finding(f: &secblitz::model::Finding) -> Class {
    match f.status.as_str() {
        "error" | "unknown" | "unsupported" => return Class::Unknown,
        "info" | "compliant" | "ok" | "attention" | "review" | "pending" => {}
        _ => return Class::Unknown,
    }
    let a = advice::for_finding(&f.title, &f.status, &f.detail);
    if managed(&a) {
        return Class::Managed;
    }
    if a.step == advice::NextStep::CheckAgain {
        return Class::Unknown;
    }
    class_of_group(&a)
}

#[derive(Debug, Clone, Copy)]
pub enum ToCheck<'a> {
    Control(&'a Outcome),
    Finding(&'a secblitz::model::Finding),
}

pub fn core_not_running(report: &Report, id: &str) -> bool {
    report.findings.iter().any(|f| {
        (secblitz::vbs::finding_control(&f.title) == Some(id)
            && f.title != secblitz::vbs::DEVICE_BLOCKED)
            || (advice::control_for_finding(&f.title) == Some(id)
                && f.status == CheckStatus::Attention)
    })
}

pub fn classify_in(report: &Report, r: &Outcome) -> Class {
    match classify(r) {
        Class::Protected
            if secblitz::vbs::is_vbs_check_id(&r.id) && core_not_running(report, &r.id) =>
        {
            Class::Excluded
        }
        other => other,
    }
}

pub fn to_check(report: &Report) -> Vec<ToCheck<'_>> {
    let controls = report
        .results
        .iter()
        .filter(|r| matches!(classify_in(report, r), Class::Fixable | Class::Review))
        .map(ToCheck::Control);
    let findings = report
        .findings
        .iter()
        .filter(|f| !finding_has_fix(report, f))
        .filter(|f| matches!(classify_finding(f), Class::Fixable | Class::Review))
        .map(ToCheck::Finding);
    controls.chain(findings).collect()
}

/// The one rule for "a fix row replaces the old tip". True when the control
/// that [`advice::control_for_finding`] maps this finding to has a row on this
/// report that says it better, so the finding is hidden and counted once.
/// Protection rows, the to-check list (Home and tray counts) all use this.
///
/// Per control:
/// - Memory integrity: the control row replaces the tip whenever it exists,
///   also when Not offered (unsupported hardware, a locked setting or a driver:
///   the row gives the reason, and a manual "turn it on" tip would not help).
///   Kept only when the control reads set (compliant) while the older check
///   says it is not running and none of our own core protection notes says so.
/// - Automatic sign-in: a saved password with automatic sign-in itself off is
///   a different warning and always stays.
/// - Everything else (automatic sign-in, Remote Desktop, SMB1): replaced when
///   the control is a fix, a choice, a restart-needed state or already
///   protected, and for the Not offered reasons that already explain on the
///   control's own row why the manual tip would contradict it (connected from
///   another device, kiosk). Other Not offered reasons, managed elsewhere and
///   unchecked controls leave the tip and its steps.
pub fn finding_has_fix(report: &Report, f: &secblitz::model::Finding) -> bool {
    let Some(id) = advice::control_for_finding(&f.title) else {
        return false;
    };
    let mut rows = report.results.iter().filter(|r| r.id == id);
    match id {
        "vbs.memory_integrity" => rows.any(|r| {
            let set_but_not_running = r.status == CheckStatus::Compliant
                && f.status == CheckStatus::Attention
                && !report
                    .findings
                    .iter()
                    .any(|n| secblitz::vbs::finding_control(&n.title) == Some(id));
            !set_but_not_running
        }),
        "accounts.autologon" if f.detail.contains("AutoAdminLogon enabled=False") => false,
        _ => rows.any(|r| {
            matches!(
                classify_in(report, r),
                Class::Fixable | Class::Review | Class::Protected
            ) || REASONS_THAT_REPLACE_THE_TIP.contains(&r.detail.as_str())
        }),
    }
}

pub fn waits_for_restart(report: &Report, f: &secblitz::model::Finding) -> bool {
    f.title == "Memory integrity"
        && f.status == CheckStatus::Attention
        && !finding_has_fix(report, f)
        && report
            .results
            .iter()
            .any(|r| r.id == secblitz::vbs::MEMORY_INTEGRITY && classify(r) == Class::Protected)
}

pub fn finding_advice(report: &Report, f: &secblitz::model::Finding) -> advice::Advice {
    let mut a = advice::for_finding(&f.title, &f.status, &f.detail);
    if waits_for_restart(report, f) {
        a.status = "Restart needed";
        a.next = RESTART_TO_START;
        a.step = advice::NextStep::Restart;
        a.impact = "";
    }
    a
}

pub const RESTART_TO_START: &str =
    "Core system protection is on but is not running. Restart your computer (choose Restart, not Shut down).";

const REASONS_THAT_REPLACE_THE_TIP: [&str; 2] = [
    "Not offered: you are connected to this computer from another device right now",
    "Not offered: this computer is set up as a kiosk",
];

pub fn to_check_count(report: &Report) -> usize {
    to_check(report).len()
}

pub fn overall(report: &Report) -> Verdict {
    match Score::of(report).verdict() {
        Verdict::Protected if to_check_count(report) > 0 => Verdict::Attention,
        v => v,
    }
}

pub fn to_check_ids(report: &Report) -> Vec<String> {
    to_check(report)
        .into_iter()
        .map(|item| match item {
            ToCheck::Control(r) => r.id.clone(),
            ToCheck::Finding(f) => {
                let slug: String = f
                    .title
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_lowercase()
                        } else {
                            '-'
                        }
                    })
                    .collect();
                format!("finding.{slug}")
            }
        })
        .map(|id| id.chars().take(64).collect())
        .collect()
}

pub fn changed_ids(report: &Report) -> Vec<String> {
    report
        .results
        .iter()
        .filter(|r| r.undoable)
        .map(|r| r.id.clone())
        .collect()
}

/// Only these can later count as switched back by Windows. Full folder protection and the
/// watch share one Windows switch, so while full protection is armed it stands for both.
pub fn armed_ids(report: &Report) -> Vec<String> {
    let armed = |r: &&Outcome| r.undoable && r.status == CheckStatus::Compliant;
    let full = report
        .results
        .iter()
        .any(|r| r.id == cfa::BLOCK && armed(&r));
    report
        .results
        .iter()
        .filter(armed)
        .filter(|r| !(full && r.id == cfa::WATCH))
        .map(|r| r.id.clone())
        .collect()
}

impl Score {
    pub fn of(report: &Report) -> Self {
        let mut s = Score::default();
        // Optional switches say they are not part of the score, on or off.
        for r in report
            .results
            .iter()
            .filter(|r| advice::extra_section(&r.id).is_none())
        {
            match classify_in(report, r) {
                Class::Protected => s.protected += 1,
                Class::Fixable | Class::Review => s.attention += 1,
                Class::Unknown => s.unknown += 1,
                Class::Managed => s.managed += 1,
                Class::Excluded => continue,
            }
            s.total += 1;
        }
        s
    }
    pub fn verdict(&self) -> Verdict {
        if self.total == 0 {
            Verdict::Unknown
        } else if self.protected == self.total {
            Verdict::Protected
        } else if self.attention > 0 {
            Verdict::Attention
        } else if self.unknown > 0 {
            Verdict::Unknown
        } else {
            Verdict::Protected
        }
    }
    pub fn ratio(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            self.protected as f32 / self.total as f32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secblitz::model::{EffectiveFirewall, InboundAction};

    fn out(id: &str, status: &str) -> Outcome {
        Outcome {
            id: id.into(),
            status: status.into(),
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
    fn only_fixed_settings_seen_working_are_armed() {
        let mut fixed_then_off = out("defender.realtime", "attention");
        fixed_then_off.undoable = true;
        let mut fixed_and_on = out("uac.enabled", "compliant");
        fixed_and_on.undoable = true;
        let never_fixed = out("firewall.public.enabled", "compliant");
        let r = rep(vec![fixed_then_off, fixed_and_on, never_fixed]);
        assert_eq!(armed_ids(&r), ["uac.enabled"]);
        let attention = to_check_ids(&r);
        assert!(
            secblitz::status::reverted_of(&attention, &armed_ids(&r)).is_empty(),
            "still flagged right after a fix is not switched back"
        );
        assert_eq!(
            secblitz::status::reverted_of(&attention, &["defender.realtime".to_string()]),
            ["defender.realtime"],
            "it was working at the previous check, now it is not"
        );
    }

    #[test]
    fn full_folder_protection_is_armed_for_the_watch_it_includes() {
        let fixed = |id: &str| {
            let mut o = out(id, "compliant");
            o.undoable = true;
            o
        };
        let both = rep(vec![fixed(cfa::WATCH), fixed(cfa::BLOCK)]);
        assert_eq!(armed_ids(&both), [cfa::BLOCK]);
        let watch_only = rep(vec![fixed(cfa::WATCH), out(cfa::BLOCK, "skipped")]);
        assert_eq!(armed_ids(&watch_only), [cfa::WATCH]);
    }

    #[test]
    fn optional_switches_never_change_the_score() {
        let off = rep(vec![
            out("uac.enabled", "compliant"),
            out("ai.paint", "attention"),
            out("privacy.advertising_id", "attention"),
        ]);
        let on = rep(vec![
            out("uac.enabled", "compliant"),
            out("ai.paint", "compliant"),
            out("privacy.advertising_id", "compliant"),
        ]);
        for report in [&off, &on] {
            let s = Score::of(report);
            assert_eq!((s.protected, s.total), (1, 1));
        }
        assert_eq!(
            classify(&on.results[1]),
            Class::Protected,
            "still listed with its undo"
        );
    }

    #[test]
    fn a_linux_finding_that_needs_attention_is_something_to_check_like_any_other() {
        for title in secblitz::linux::controls::findings::TITLES {
            let mut r = rep(vec![]);
            r.findings.push(secblitz::model::Finding {
                title: title.into(),
                status: CheckStatus::Attention,
                detail: String::new(),
            });
            assert_eq!(classify_finding(&r.findings[0]), Class::Review, "{title}");
            assert_eq!(to_check_count(&r), 1, "{title}");
            assert!(matches!(to_check(&r)[0], ToCheck::Finding(_)), "{title}");
        }
    }

    #[test]
    fn a_finding_is_replaced_by_its_own_fix_row() {
        let finding = secblitz::model::Finding {
            title: "SMB1".into(),
            status: CheckStatus::Attention,
            detail: String::new(),
        };
        let mut report = rep(vec![]);
        report.findings.push(finding.clone());
        assert!(
            !finding_has_fix(&report, &finding),
            "no fix in this report yet"
        );
        assert_eq!(to_check_count(&report), 1);
        report.results.push(out("smb1.disabled", "compliant"));
        assert!(finding_has_fix(&report, &finding));
        let other = secblitz::model::Finding {
            title: "Secure Boot".into(),
            ..finding
        };
        assert!(!finding_has_fix(&report, &other));
        assert!(to_check_ids(&report)
            .iter()
            .all(|id| !id.starts_with("finding.")));
    }

    #[test]
    fn a_finding_stays_when_its_control_could_not_be_checked_or_is_managed() {
        let finding = secblitz::model::Finding {
            title: "SMB1".into(),
            status: CheckStatus::Attention,
            detail: String::new(),
        };
        let mut report = rep(vec![out("smb1.disabled", "unknown")]);
        report.findings.push(finding.clone());
        assert_eq!(classify(&report.results[0]), Class::Unknown);
        assert!(!finding_has_fix(&report, &finding));
        let mut done = rep(vec![out("smb1.disabled", "compliant")]);
        done.findings.push(finding.clone());
        assert_eq!(classify(&done.results[0]), Class::Protected);
        assert!(finding_has_fix(&done, &finding));
    }

    #[test]
    fn every_fix_candidate_is_counted_or_a_privacy_extra() {
        let report = rep(vec![
            out("uac.enabled", "attention"),
            out("autorun.disabled", "attention"),
            out("privacy.advertising_id", "attention"),
            out("privacy.clipboard_sync", "attention"),
        ]);
        let available: Vec<String> = report.results.iter().map(|r| r.id.clone()).collect();
        let counted = to_check_ids(&report);
        let mut extras = Vec::new();
        for id in crate::app::flow::candidates(&report, &available) {
            let r = report.results.iter().find(|r| r.id == id).unwrap();
            match classify(r) {
                Class::Fixable | Class::Review => assert!(counted.contains(&id), "{id}"),
                Class::Excluded => extras.push(id),
                other => panic!("{id} is a fix candidate classified {other:?}"),
            }
        }
        assert_eq!(counted, ["uac.enabled", "autorun.disabled"]);
        assert_eq!(extras, ["privacy.advertising_id", "privacy.clipboard_sync"]);
    }

    #[test]
    fn empty_report_is_unknown() {
        let s = Score::of(&Report::default());
        assert_eq!((s.protected, s.total), (0, 0));
        assert_eq!(s.verdict(), Verdict::Unknown);
        assert_eq!(s.ratio(), 0.0);
    }

    #[test]
    fn all_protected() {
        let s = Score::of(&rep(vec![
            out("uac.enabled", "compliant"),
            out("uac.consent", "ok"),
        ]));
        assert_eq!((s.protected, s.total), (2, 2));
        assert_eq!(s.verdict(), Verdict::Protected);
        assert_eq!(s.ratio(), 1.0);
    }

    #[test]
    fn attention_and_unknown_count_in_total() {
        let s = Score::of(&rep(vec![
            out("uac.enabled", "compliant"),
            out("uac.consent", "attention"),
            out("defender.ioav", "unknown"),
            out("defender.archive", "error"),
            out("lsa.restrict_anonymous_sam", "mystery"),
        ]));
        assert_eq!((s.protected, s.total, s.attention, s.unknown), (1, 5, 1, 3));
        assert_eq!(s.verdict(), Verdict::Attention);
    }

    #[test]
    fn only_unknown_is_unknown_verdict() {
        let s = Score::of(&rep(vec![
            out("uac.enabled", "compliant"),
            out("uac.consent", "unknown"),
        ]));
        assert_eq!(s.verdict(), Verdict::Unknown);
    }

    #[test]
    fn firewall_without_evidence_is_unknown_not_protected() {
        let s = Score::of(&rep(vec![out("firewall.public.enabled", "compliant")]));
        assert_eq!((s.protected, s.unknown, s.total), (0, 1, 1));
        let verified = Outcome {
            effective: Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            authority: Some(Authority::Local),
            ..out("firewall.public.inbound", "compliant")
        };
        assert_eq!(classify(&verified), Class::Protected);
        let managed = Outcome {
            authority: Some(Authority::Unknown),
            ..verified
        };
        assert_eq!(classify(&managed), Class::Unknown);
    }

    #[test]
    fn informational_findings_are_good_to_know_not_to_check() {
        let find = |title: &str, status: &str| secblitz::model::Finding {
            title: title.into(),
            status: status.into(),
            detail: String::new(),
        };
        let mut r = rep(vec![out("uac.consent", "attention")]);
        for t in ["Windows updates", "Secure Boot", "SMB1"] {
            r.findings.push(find(t, "info"));
        }
        r.findings.push(find("Remote Desktop", "attention"));
        assert_eq!(classify_finding(&r.findings[0]), Class::Excluded);
        assert_ne!(classify_finding(&r.findings[3]), Class::Excluded);
        assert_eq!(to_check_count(&r), 2);
        assert_eq!(classify_finding(&find("SMB1", "error")), Class::Unknown);
    }

    #[test]
    fn safe_default_skips_are_protected_in_the_score() {
        let o = Outcome {
            detail: "Preserving absent or already-safe machine preference".into(),
            ..out("wdigest.use_logon_credential", "skipped")
        };
        assert_eq!(classify(&o), Class::Protected);
        let u = Outcome {
            detail: "Preserving absent or nonzero UAC preference".into(),
            ..out("uac.enabled", "skipped")
        };
        assert_eq!(classify(&u), Class::Protected);
    }

    #[test]
    fn a_fix_row_replaces_the_manual_tip_for_the_same_thing() {
        let tip = |title: &str| secblitz::model::Finding {
            title: title.into(),
            status: CheckStatus::Attention,
            detail: String::new(),
        };
        let eligible = |id: &str| Outcome {
            detail: "Eligible unmanaged local preference".into(),
            ..out(id, "attention")
        };
        for (title, id) in [
            ("Automatic logon", "accounts.autologon"),
            ("Remote Desktop", "remote_desktop.disabled"),
            ("SMB1", "smb1.disabled"),
        ] {
            let mut r = rep(vec![out("uac.enabled", "compliant")]);
            r.findings.push(tip(title));
            assert_eq!(to_check_count(&r), 1, "{title}");
            let mut r = rep(vec![eligible(id)]);
            r.findings.push(tip(title));
            assert!(finding_has_fix(&r, &r.findings[0]), "{title}");
            assert_eq!(to_check_count(&r), 1, "{title}");
            assert!(matches!(to_check(&r)[0], ToCheck::Control(_)));
            let not_offered = Outcome {
                detail: "Not offered: this edition of Windows does not include it".into(),
                ..out(id, "skipped")
            };
            let mut r = rep(vec![not_offered]);
            r.findings.push(tip(title));
            assert!(!finding_has_fix(&r, &r.findings[0]), "{title}");
            assert_eq!(to_check_count(&r), 1, "{title}");
        }
        let mut r = rep(vec![eligible("accounts.autologon")]);
        r.findings.push(tip("Secure Boot"));
        assert_eq!(to_check_count(&r), 2);
        let mut r = rep(vec![out("accounts.autologon", "compliant")]);
        r.findings.push(secblitz::model::Finding {
            title: "Automatic logon".into(),
            status: CheckStatus::Attention,
            detail: "AutoAdminLogon enabled=False; Winlogon DefaultPassword value present=True."
                .into(),
        });
        assert!(!finding_has_fix(&r, &r.findings[0]));
        assert_eq!(to_check_count(&r), 1);
        for reason in [
            "Not offered: you are connected to this computer from another device right now",
            "Not offered: this computer is set up as a kiosk",
        ] {
            let id = if reason.contains("kiosk") {
                "accounts.autologon"
            } else {
                "remote_desktop.disabled"
            };
            let title = if reason.contains("kiosk") {
                "Automatic logon"
            } else {
                "Remote Desktop"
            };
            let mut r = rep(vec![Outcome {
                detail: reason.into(),
                ..out(id, "skipped")
            }]);
            r.findings.push(tip(title));
            assert!(finding_has_fix(&r, &r.findings[0]), "{reason}");
        }
    }

    #[test]
    fn memory_integrity_and_the_other_mapped_controls_follow_their_own_rules() {
        let tip = |title: &str| secblitz::model::Finding {
            title: title.into(),
            status: CheckStatus::Attention,
            detail: String::new(),
        };
        let row = |id: &str, status: &str, detail: &str| Outcome {
            detail: detail.into(),
            ..out(id, status)
        };
        for (status, detail) in [
            ("skipped", secblitz::vbs::NOT_SUPPORTED),
            ("skipped", secblitz::vbs::LOCKED),
            (
                "skipped",
                "Not offered: a driver on this computer may not work with it: a.sys",
            ),
            ("skipped", "Relevant policy is configured: assessment only"),
            ("unknown", ""),
            ("applied", "Preference applied; restart required"),
        ] {
            let mut r = rep(vec![row("vbs.memory_integrity", status, detail)]);
            r.findings.push(tip("Memory integrity"));
            assert!(finding_has_fix(&r, &r.findings[0]), "{status} {detail}");
            assert!(
                to_check_ids(&r)
                    .iter()
                    .all(|id| !id.starts_with("finding.")),
                "{status} {detail}"
            );
        }
        for id in [
            "accounts.autologon",
            "remote_desktop.disabled",
            "smb1.disabled",
        ] {
            let title = match id {
                "accounts.autologon" => "Automatic logon",
                "remote_desktop.disabled" => "Remote Desktop",
                _ => "SMB1",
            };
            for (status, detail) in [
                ("skipped", "Relevant policy is configured: assessment only"),
                ("unknown", ""),
                (
                    "skipped",
                    "Not offered: this edition of Windows does not include it",
                ),
            ] {
                let mut r = rep(vec![row(id, status, detail)]);
                r.findings.push(tip(title));
                assert!(
                    !finding_has_fix(&r, &r.findings[0]),
                    "{id} {status} {detail}"
                );
                assert_eq!(
                    to_check_ids(&r),
                    vec![format!(
                        "finding.{}",
                        title.to_lowercase().replace(' ', "-")
                    )]
                );
            }
            let mut r = rep(vec![row(
                id,
                "applied",
                "Preference applied; restart required",
            )]);
            r.findings.push(tip(title));
            assert!(finding_has_fix(&r, &r.findings[0]), "{id}");
        }
        let mut r = rep(vec![row(
            "accounts.autologon",
            "skipped",
            "Not offered: this computer is set up as a kiosk",
        )]);
        r.findings.push(tip("Remote Desktop"));
        assert!(!finding_has_fix(&r, &r.findings[0]));
        r.findings.push(secblitz::model::Finding {
            title: "Automatic logon".into(),
            status: CheckStatus::Attention,
            detail: "AutoAdminLogon enabled=False; Winlogon DefaultPassword value present=True."
                .into(),
        });
        assert!(!finding_has_fix(&r, &r.findings[1]));
    }

    #[test]
    fn a_fix_row_replaces_the_old_tip_for_the_same_thing() {
        let find = |title: &str| secblitz::model::Finding {
            title: title.into(),
            status: CheckStatus::Attention,
            detail: String::new(),
        };
        let mut r = rep(vec![out("vbs.memory_integrity", "attention")]);
        r.findings.push(find("Memory integrity"));
        r.findings.push(find("Memory integrity not running"));
        assert!(finding_has_fix(&r, &r.findings[0]));
        assert!(!finding_has_fix(&r, &r.findings[1]));
        assert_eq!(to_check_count(&r), 2);
        let mut r = rep(vec![]);
        r.findings.push(find("Memory integrity"));
        assert!(!finding_has_fix(&r, &r.findings[0]));
        assert_eq!(to_check_count(&r), 1);
    }

    #[test]
    fn a_core_protection_that_is_set_but_not_running_is_never_counted_as_protected() {
        let find = |title: &str, status: &str| secblitz::model::Finding {
            title: title.into(),
            status: status.into(),
            detail: String::new(),
        };
        let mut r = rep(vec![out("vbs.memory_integrity", "compliant")]);
        r.findings.push(find("Memory integrity", "ok"));
        assert_eq!(classify_in(&r, &r.results[0]), Class::Protected);
        assert_eq!(Score::of(&r).protected, 1);
        assert!(finding_has_fix(&r, &r.findings[0]) || r.findings[0].status == CheckStatus::Ok);
        let mut r = rep(vec![out("vbs.memory_integrity", "compliant")]);
        r.findings.push(find("Memory integrity", "attention"));
        assert!(!finding_has_fix(&r, &r.findings[0]));
        assert_eq!(classify_in(&r, &r.results[0]), Class::Excluded);
        assert_eq!(Score::of(&r).protected, 0);
        assert_eq!(to_check_count(&r), 1);
        assert!(waits_for_restart(&r, &r.findings[0]));
        let a = finding_advice(&r, &r.findings[0]);
        assert_eq!(a.next, RESTART_TO_START);
        assert_eq!(a.step, advice::NextStep::Restart);
        assert_eq!(a.status, "Restart needed");
        let mut off = rep(vec![out("vbs.memory_integrity", "attention")]);
        off.findings.push(find("Memory integrity", "attention"));
        assert!(!waits_for_restart(&off, &off.findings[0]));
        let mut none = rep(vec![]);
        none.findings.push(find("Memory integrity", "attention"));
        assert!(!waits_for_restart(&none, &none.findings[0]));
        assert_ne!(
            finding_advice(&none, &none.findings[0]).next,
            RESTART_TO_START
        );
        r.findings
            .push(find("Memory integrity not running", "attention"));
        assert!(finding_has_fix(&r, &r.findings[0]));
        assert!(!finding_has_fix(&r, &r.findings[1]));
        assert_eq!(to_check_count(&r), 1);
        let mut r = rep(vec![out("vbs.kernel_stack_protection", "compliant")]);
        assert_eq!(classify_in(&r, &r.results[0]), Class::Protected);
        r.findings
            .push(find("Kernel stack protection not running", "attention"));
        assert_eq!(classify_in(&r, &r.results[0]), Class::Excluded);
        let mut r = rep(vec![out("vbs.memory_integrity", "compliant")]);
        r.findings
            .push(find("A device may not be working", "attention"));
        assert_eq!(classify_in(&r, &r.results[0]), Class::Protected);
        assert_eq!(to_check_count(&r), 1);
        // Running already (not offered because it is on) counts as protected.
        let mut on = out("vbs.memory_integrity", "skipped");
        on.detail = secblitz::vbs::ALREADY_ON.into();
        assert_eq!(classify(&on), Class::Protected);
    }

    #[test]
    fn findings_never_count() {
        let mut r = rep(vec![out("uac.enabled", "compliant")]);
        r.findings.push(secblitz::model::Finding {
            title: "SMB1".into(),
            status: CheckStatus::Attention,
            detail: String::new(),
        });
        assert_eq!(Score::of(&r).total, 1);
    }

    #[test]
    fn managed_is_apart_and_applied_restart_is_review() {
        let managed = Outcome {
            detail: "Domain-managed machine: assessment only".into(),
            ..out("uac.enabled", "skipped")
        };
        assert_eq!(classify(&managed), Class::Managed);
        let again = || Outcome {
            detail: "Domain-managed machine: assessment only".into(),
            ..out("uac.enabled", "skipped")
        };
        let s = Score::of(&rep(vec![out("uac.consent", "compliant"), again()]));
        assert_eq!((s.attention, s.managed, s.total), (0, 1, 2));
        assert_eq!(s.verdict(), Verdict::Protected);
        assert_eq!(to_check_count(&rep(vec![again()])), 0);
        let restart = Outcome {
            detail: "Preference applied; restart required".into(),
            ..out("uac.enabled", "applied")
        };
        assert_eq!(classify(&restart), Class::Review);
        let kept = Outcome {
            detail: "Service permissions preserved: deny ACE".into(),
            ..out("permissions.service.bits", "skipped")
        };
        assert_eq!(classify(&kept), Class::Excluded);
    }
}
