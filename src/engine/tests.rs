use super::catalog::*;
use super::fsio::*;
use super::journal::*;
use super::*;
use crate::model::{CheckStatus, InboundAction, Probe};
use anyhow::bail;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    rc::Rc,
};
use tempfile::TempDir;

const FIREWALL: &str = "firewall.public.inbound";
const DEFENDER: &str = "defender.realtime";

#[test]
fn all_default_block_profiles_are_protected_without_preference_or_wal_changes() {
    let ids = [
        "firewall.domain.inbound",
        "firewall.private.inbound",
        FIREWALL,
    ];
    let (dir, state, e) = fixture(ids[0], json!("NotConfigured"));
    drop(e);
    for id in ids {
        state
            .borrow_mut()
            .values
            .insert(id.into(), json!("NotConfigured"));
        state.borrow_mut().evidence.insert(
            id.into(),
            (
                Some(EffectiveFirewall::Inbound(InboundAction::Block)),
                Some(Authority::Local),
            ),
        );
    }
    let mut e = reopen(&dir, &state, &ids);
    assert!(e
        .audit()
        .unwrap()
        .results
        .iter()
        .all(|r| r.status == CheckStatus::Compliant
            && r.authority == Some(Authority::Local)
            && r.effective == Some(EffectiveFirewall::Inbound(InboundAction::Block))));
    let selected = ids.map(str::to_owned);
    for report in [
        e.apply(|_| {}).unwrap(),
        e.apply_selected(&selected, |_| {}).unwrap(),
    ] {
        assert!(report.transaction.is_none());
        assert!(report
            .results
            .iter()
            .all(|r| r.status == CheckStatus::Unchanged));
    }
    assert!(e.history().unwrap().is_empty());
    assert!(state.borrow().writes.is_empty());
    assert!(state.borrow().values.values().all(|v| v == "NotConfigured"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1); // base lock only
}

#[test]
fn genuine_firewall_gaps_repair_and_undo_exact_raw_schema_one_originals() {
    for raw in [json!("Allow"), json!("NotConfigured")] {
        let (dir, state, mut e) = fixture(FIREWALL, raw.clone());
        assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Attention);
        let report = e.apply_selected(&[FIREWALL.into()], |_| {}).unwrap();
        assert_eq!(report.results[0].status, CheckStatus::Applied);
        assert_eq!(
            report.results[0].effective,
            Some(EffectiveFirewall::Inbound(InboundAction::Block))
        );
        let tx = e.load().unwrap().pop().unwrap();
        assert_eq!(tx.entries[0].before, raw);
        let text = fs::read_to_string(dir.path().join(format!("{}.jsonl", tx.name))).unwrap();
        assert!(text.contains("\"schema\":1"));
        assert!(!text.contains("effective") && !text.contains("authority"));
        drop(tx);
        drop(e);
        let mut e = reopen(&dir, &state, &[FIREWALL]);
        e.revert(|_| {}).unwrap();
        assert_eq!(state.borrow().values[FIREWALL], raw);
        assert_eq!(state.borrow().writes.len(), 2);
    }
}

#[test]
fn missing_contradictory_and_managed_firewall_evidence_never_writes_or_claims_protection() {
    for (id, raw, effective, authority, managed, status) in [
        (
            FIREWALL,
            json!("NotConfigured"),
            None,
            Some(Authority::Local),
            false,
            CheckStatus::Error,
        ),
        (
            FIREWALL,
            json!("Block"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            None,
            false,
            CheckStatus::Error,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Local),
            false,
            CheckStatus::Error,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Managed),
            true,
            CheckStatus::Skipped,
        ),
        (
            FIREWALL,
            json!("Block"),
            None,
            Some(Authority::Unknown),
            true,
            CheckStatus::Skipped,
        ),
        (
            "firewall.public.enabled",
            json!(true),
            None,
            Some(Authority::Local),
            false,
            CheckStatus::Error,
        ),
        (
            "firewall.public.enabled",
            json!(true),
            Some(EffectiveFirewall::Enabled(false)),
            Some(Authority::Local),
            false,
            CheckStatus::Error,
        ),
    ] {
        let (_dir, state, mut e) = fixture(id, raw);
        state.borrow_mut().blocked = managed;
        state
            .borrow_mut()
            .evidence
            .insert(id.into(), (effective, authority));
        assert_eq!(e.audit().unwrap().results[0].status, status);
        assert_eq!(
            e.apply_selected(&[id.into()], |_| {}).unwrap().results[0].status,
            status
        );
        assert!(state.borrow().writes.is_empty());
        assert!(e.history().unwrap().is_empty());
    }
}

#[test]
fn owned_firewall_uses_raw_drift_and_final_gate_rechecks_evidence() {
    let (_dir, state, mut e) = fixture(FIREWALL, json!("Allow"));
    state.borrow_mut().evidence_at = Some((2, None, Some(Authority::Local)));
    assert!(e.apply_selected(&[FIREWALL.into()], |_| {}).is_err());
    assert!(state.borrow().writes.is_empty());
    assert_eq!(e.load().unwrap()[0].entries[0].before, json!("Allow"));
    e.revert(|_| {}).unwrap(); // original already present, no write needed
    state.borrow_mut().evidence.clear();
    e.apply_selected(&[FIREWALL.into()], |_| {}).unwrap();
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("NotConfigured"));
    state.borrow_mut().evidence.insert(
        FIREWALL.into(),
        (
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Local),
        ),
    );
    assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Compliant);
    assert_eq!(
        e.apply_selected(&[FIREWALL.into()], |_| {})
            .unwrap()
            .results[0]
            .status,
        CheckStatus::Conflict
    );
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Conflict
    );
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("Block"));
    state.borrow_mut().evidence.clear();
    e.revert(|_| {}).unwrap();
    assert_eq!(state.borrow().values[FIREWALL], json!("Allow"));
}

#[test]
fn default_becoming_protected_after_prepare_requires_explicit_recovery() {
    let (_dir, state, mut e) = fixture(FIREWALL, json!("NotConfigured"));
    state.borrow_mut().evidence_at = Some((
        2,
        Some(EffectiveFirewall::Inbound(InboundAction::Block)),
        Some(Authority::Local),
    ));
    assert!(e.apply_selected(&[FIREWALL.into()], |_| {}).is_err());
    let tx = e.load().unwrap().pop().unwrap();
    assert!(!tx.sealed);
    assert_eq!(tx.entries[0].state, State::Pending);
    assert_eq!(tx.entries[0].before, json!("NotConfigured"));
    assert!(state.borrow().writes.is_empty());
    drop(tx);
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Unchanged
    );
    assert!(e.load().unwrap()[0].reverted);
    assert!(state.borrow().writes.is_empty());
}

#[test]
fn firewall_readback_requires_effective_protection_before_sealing() {
    for (id, before, evidence, authority, blocked) in [
        (
            FIREWALL,
            json!("Allow"),
            None,
            Some(Authority::Local),
            false,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Allow)),
            Some(Authority::Local),
            false,
        ),
        (
            "firewall.public.enabled",
            json!(false),
            Some(EffectiveFirewall::Enabled(false)),
            Some(Authority::Local),
            false,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            None,
            false,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Managed),
            true,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Unknown),
            true,
        ),
        (
            FIREWALL,
            json!("Allow"),
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Local),
            true,
        ),
    ] {
        for selected in [false, true] {
            let (dir, state, mut e) = fixture(id, before.clone());
            state.borrow_mut().evidence_at = Some((3, evidence, authority));
            if blocked {
                state.borrow_mut().block_at = Some(3);
            }
            let result = if selected {
                e.apply_selected(&[id.into()], |_| {})
            } else {
                e.apply(|_| {})
            };
            assert!(
                result.is_err(),
                "unverified readback must retain pending intent"
            );
            assert_eq!(state.borrow().writes.len(), 1);
            let tx = e.load().unwrap().pop().unwrap();
            assert!(!tx.sealed);
            assert_eq!(tx.entries[0].state, State::Pending);
            assert_eq!(tx.entries[0].before, before);
            drop(tx);
            drop(e);
            state.borrow_mut().evidence.clear();
            state.borrow_mut().blocked = false;
            let mut e = reopen(&dir, &state, &[id]);
            e.revert(|_| {}).unwrap();
            assert_eq!(state.borrow().values[id], before);
        }
    }
}

#[test]
fn blocked_readiness_preserves_owned_noops_and_existing_wal_bytes() {
    let (dir, state, e) = fixture(DEFENDER, json!(true));
    drop(e);
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("Allow"));
    let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
    let name = e
        .apply_selected(&[DEFENDER.into()], |_| {})
        .unwrap()
        .transaction
        .unwrap();
    let path = dir.path().join(format!("{name}.jsonl"));
    let original = fs::read(&path).unwrap();
    state.borrow_mut().readiness.journal_volume = Probe::Known(crate::model::VolumeReadiness {
        available_bytes: 0,
        read_only: true,
    });
    for ids in [
        vec![DEFENDER.into()],
        vec![DEFENDER.into(), FIREWALL.into()],
    ] {
        let report = e.apply_selected(&ids, |_| {}).unwrap();
        assert_eq!(report.results[0].status, CheckStatus::Unchanged);
        if ids.len() == 2 {
            assert_eq!(report.results[1].status, CheckStatus::Skipped);
        }
        assert!(report.readiness.is_some());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(e.load().unwrap().len(), 1);
        assert_eq!(state.borrow().writes.len(), 1);
    }
    e.apply(|_| {}).unwrap();
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(state.borrow().writes.len(), 1);
}

#[test]
fn readiness_refresh_blocks_only_confirmed_storage_conditions_and_never_undo() {
    use crate::model::{PowerReadiness, VolumeReadiness};
    let volume = |bytes, read_only| {
        Probe::Known(VolumeReadiness {
            available_bytes: bytes,
            read_only,
        })
    };
    for readiness in [
        Readiness {
            system_volume: volume(100, true),
            ..Default::default()
        },
        Readiness {
            journal_volume: volume(100, true),
            ..Default::default()
        },
        Readiness {
            journal_volume: volume(0, false),
            ..Default::default()
        },
    ] {
        let (_dir, state, mut e) = fixture(DEFENDER, json!(true));
        let audit = e.audit().unwrap();
        assert_eq!(audit.readiness, Some(Readiness::default()));
        assert_eq!(state.borrow().readiness_count, 1);
        state.borrow_mut().readiness = readiness.clone();
        let report = e.apply_selected(&[DEFENDER.into()], |_| {}).unwrap();
        assert_eq!(report.readiness, Some(readiness.clone()));
        assert_eq!(report.results[0].status, CheckStatus::Skipped);
        assert_eq!(state.borrow().readiness_count, 2);
        assert!(state.borrow().writes.is_empty());
        assert!(e.history().unwrap().is_empty());
        state.borrow_mut().readiness = Readiness::default();
        e.apply_selected(&[DEFENDER.into()], |_| {}).unwrap();
        state.borrow_mut().readiness = readiness;
        let calls = state.borrow().readiness_count;
        e.revert(|_| {}).unwrap();
        assert_eq!(state.borrow().readiness_count, calls);
        assert_eq!(state.borrow().values[DEFENDER], json!(true));
    }
    for readiness in [
        Readiness::default(),
        Readiness {
            system_volume: volume(0, false),
            journal_volume: volume(1u64 << 40, false),
            power: Probe::Known(PowerReadiness {
                ac_connected: Some(false),
                battery_percent: Some(1),
                battery_present: Some(true),
            }),
            windows_update_reboot: Probe::Known(true),
        },
    ] {
        let (_dir, state, mut e) = fixture(DEFENDER, json!(true));
        state.borrow_mut().readiness = readiness.clone();
        let report = e.apply(|_| {}).unwrap();
        assert_eq!(report.readiness, Some(readiness));
        assert_eq!(report.results[0].status, CheckStatus::Applied);
    }
}

#[test]
fn updater_reserved_entries_coexist_with_exact_journal_roundtrip() {
    let (dir, state, e) = fixture(DEFENDER, json!(true));
    drop(e);
    let mut held = Vec::new();
    for name in LEGACY_UPDATE_FILES {
        let path = dir.path().join(name);
        // Deliberately not JSON, including the manifest/status files.
        fs::write(&path, b"updater data\0not a journal").unwrap();
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0x1);
        }
        held.push(options.open(path).unwrap());
    }
    fs::create_dir(dir.path().join("Updates")).unwrap();
    fs::write(dir.path().join("Updates/staged-data.bin"), b"staged").unwrap();
    let mut e = reopen(&dir, &state, &[DEFENDER]);
    assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Attention);
    assert!(e.history().unwrap().is_empty());
    let applied = e.apply_selected(&[DEFENDER.into()], |_| {}).unwrap();
    let name = applied.transaction.unwrap();
    assert_eq!(e.history().unwrap(), vec![format!("{name} applied")]);
    assert_eq!(e.load().unwrap().len(), 1);
    assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Compliant);
    let reverted = e.revert(|_| {}).unwrap();
    assert_eq!(reverted.transaction.as_deref(), Some(name.as_str()));
    assert_eq!(reverted.results[0].status, CheckStatus::Restored);
    assert_eq!(e.history().unwrap(), vec![format!("{name} reverted")]);
    assert_eq!(state.borrow().values[DEFENDER], json!(true));
    for file in LEGACY_UPDATE_FILES {
        assert_eq!(
            fs::read(dir.path().join(file)).unwrap(),
            b"updater data\0not a journal"
        );
    }
    assert_eq!(
        fs::read(dir.path().join("Updates/staged-data.bin")).unwrap(),
        b"staged"
    );
    drop(held);
}

fn assert_reserved_history_rejected(e: &mut Engine, state: &Rc<RefCell<FakeState>>) {
    assert!(e.audit().is_err());
    assert!(e.apply_selected(&[DEFENDER.into()], |_| {}).is_err());
    assert!(e.revert(|_| {}).is_err());
    assert!(e.history().is_err());
    assert!(state.borrow().events.is_empty());
}

#[test]
fn updater_exceptions_reject_wrong_types_unknown_names_and_corrupt_wal() {
    for name in LEGACY_UPDATE_FILES {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        fs::create_dir(dir.path().join(name)).unwrap();
        assert_reserved_history_rejected(&mut e, &state);
    }
    for name in [
        "Updates", // reserved directory cannot be a file
        "updates",
        "Updates.jsonl",
        "update-extra.exe",
        "update-worker.exe.jsonl",
        "update-status.json.jsonl",
        "update.lock.backup",
        "junk",
    ] {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        fs::write(dir.path().join(name), b"{}").unwrap();
        assert_reserved_history_rejected(&mut e, &state);
    }
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    for name in LEGACY_UPDATE_FILES {
        fs::write(dir.path().join(name), b"reserved").unwrap();
    }
    fs::create_dir(dir.path().join("Updates")).unwrap();
    let tx = prepare(&mut e, 1, DEFENDER, json!(true));
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    drop(tx);
    fs::write(&path, b"{corrupt WAL}\n").unwrap();
    assert_reserved_history_rejected(&mut e, &state);
    assert_eq!(fs::read(path).unwrap(), b"{corrupt WAL}\n");
}

#[test]
fn updater_reserved_files_reject_hardlinks() {
    for name in LEGACY_UPDATE_FILES {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        let outside = tempfile::tempdir().unwrap();
        let source = outside.path().join("source");
        fs::write(&source, b"data").unwrap();
        fs::hard_link(source, dir.path().join(name)).unwrap();
        assert_reserved_history_rejected(&mut e, &state);
    }
}

#[cfg(unix)]
#[test]
fn updater_reserved_entries_reject_symlinks() {
    use std::os::unix::fs::symlink;
    for name in LEGACY_UPDATE_FILES.into_iter().chain(["Updates"]) {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        let outside = tempfile::tempdir().unwrap();
        let source = outside.path().join("source");
        if name == "Updates" {
            fs::create_dir(&source).unwrap();
        } else {
            fs::write(&source, b"data").unwrap();
        }
        symlink(source, dir.path().join(name)).unwrap();
        assert_reserved_history_rejected(&mut e, &state);
    }
}

#[test]
fn selected_validation_and_probe_isolation() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    // Advertised but unsupported at runtime: probing this missing value panics.
    e.controls.push(Control {
        id: FIREWALL.into(),
        title: FIREWALL.into(),
        description: String::new(),
        target: target(FIREWALL).unwrap(),
        reboot: false,
    });
    for ids in [
        vec![],
        vec!["ALL".into()],
        vec!["".into()],
        vec![DEFENDER.into(), DEFENDER.into()],
        vec![DEFENDER.into(), "unknown".into()],
    ] {
        assert!(e
            .apply_selected(&ids, |_| panic!("invalid callback"))
            .is_err());
        assert!(e.load().unwrap().is_empty());
        assert!(state.borrow().events.is_empty());
        assert_eq!(state.borrow().readiness_count, 0);
    }
    let mut callbacks = Vec::new();
    let r = e
        .apply_selected(&[DEFENDER.into()], |p| {
            callbacks.push((p.id.to_owned(), p.step.as_str().to_owned()))
        })
        .unwrap();
    assert_eq!(r.results.len(), 1);
    assert_eq!(
        callbacks,
        vec![
            ("readiness".into(), "pending".into()),
            ("readiness".into(), "complete".into()),
            (DEFENDER.into(), "applied".into()),
        ]
    );
    assert!(state.borrow().events.iter().all(|s| s.ends_with(DEFENDER)));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn selected_disjoint_batches_reopen_and_reverse_undo() {
    let (dir, state, e) = fixture(DEFENDER, json!(true));
    drop(e);
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("Allow"));
    let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
    e.apply_selected(&[DEFENDER.into()], |_| {}).unwrap();
    let original = e.load().unwrap()[0].length;
    e.apply_selected(&[DEFENDER.into(), FIREWALL.into()], |_| {})
        .unwrap();
    assert_eq!(e.load().unwrap()[0].length, original);
    assert_eq!(e.load().unwrap().len(), 2);
    drop(e);
    let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
    assert_eq!(e.revert(|_| {}).unwrap().results[0].id, FIREWALL);
    assert_eq!(state.borrow().values[DEFENDER], json!(false));
    assert_eq!(e.revert(|_| {}).unwrap().results[0].id, DEFENDER);
    assert_eq!(state.borrow().values[DEFENDER], json!(true));
    assert_eq!(state.borrow().values[FIREWALL], json!("Allow"));
}

#[test]
fn not_running_notes_for_core_protections_are_only_about_our_own_undoable_change() {
    let id = crate::vbs::MEMORY_INTEGRITY;
    let note = |boot: i64| Finding {
        title: crate::vbs::MEMORY_INTEGRITY_NOT_RUNNING.into(),
        status: CheckStatus::Attention,
        detail: format!("Not running. {}{boot}.", crate::vbs::BOOT_PREFIX),
    };
    let later = i64::MAX / 4;
    let (dir, state, mut e) = fixture(
        id,
        json!({"items": {"Enabled": null, "WasEnabledBy": null}}),
    );
    state.borrow_mut().extra_findings = vec![note(later)];
    assert!(e.findings().is_empty());
    e.apply_selected(&[id.into()], |_| {}).unwrap();
    state.borrow_mut().extra_findings = vec![note(0)];
    assert!(e.findings().is_empty());
    state.borrow_mut().extra_findings = vec![note(later)];
    let found = e.findings();
    assert_eq!(found.len(), 1);
    assert!(found[0].detail.starts_with(crate::vbs::UNDO_READY));
    state.borrow_mut().extra_findings = vec![Finding {
        detail: "Not running.".into(),
        ..note(later)
    }];
    assert!(e.findings().is_empty());
    drop(e);
    state
        .borrow_mut()
        .values
        .insert(DEFENDER.into(), json!(true));
    let mut e = reopen(&dir, &state, &[id, DEFENDER]);
    e.apply_selected(&[DEFENDER.into()], |_| {}).unwrap();
    state.borrow_mut().extra_findings = vec![note(later)];
    let found = e.findings();
    assert_eq!(found.len(), 1);
    assert!(!found[0].detail.starts_with(crate::vbs::UNDO_READY));
    e.revert(|_| {}).unwrap();
    e.revert(|_| {}).unwrap();
    assert!(e.findings().is_empty());
}

#[test]
fn selected_exact_acl_conflict_blocks_entire_mixed_batch() {
    let id = "permissions.service.bits";
    let before = acl_snapshot(0x0002_0012, 1);
    let (dir, state, e) = fixture(id, before.clone());
    drop(e);
    state
        .borrow_mut()
        .values
        .insert(DEFENDER.into(), json!(true));
    let mut e = reopen(&dir, &state, &[DEFENDER, id]);
    e.apply_selected(&[id.into()], |_| {}).unwrap();
    state
        .borrow_mut()
        .values
        .insert(id.into(), acl_snapshot(0x0002_0030, 1));
    let r = e
        .apply_selected(&[DEFENDER.into(), id.into()], |_| {})
        .unwrap();
    assert_eq!(r.results[0].status, CheckStatus::Skipped);
    assert_eq!(r.results[1].status, CheckStatus::Conflict);
    assert_eq!(state.borrow().writes.len(), 1);
    assert_eq!(e.load().unwrap().len(), 1);
    assert_eq!(e.load().unwrap()[0].entries[0].before, before);
}

#[test]
fn selected_pending_and_reverting_block_new_batches_and_earlier_undo() {
    let (dir, state, e) = fixture(DEFENDER, json!(true));
    drop(e);
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("Allow"));
    let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
    e.apply_selected(&[DEFENDER.into()], |_| {}).unwrap();
    state.borrow_mut().fail_write = true;
    assert!(e.apply_selected(&[FIREWALL.into()], |_| {}).is_err());
    state.borrow_mut().fail_write = false;
    let n = state.borrow().observe_count;
    assert_eq!(
        e.apply_selected(&[DEFENDER.into()], |_| {})
            .unwrap()
            .results[0]
            .status,
        CheckStatus::Pending
    );
    assert_eq!(state.borrow().observe_count, n);
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("NotConfigured"));
    for _ in 0..2 {
        let r = e.revert(|_| {}).unwrap();
        assert_eq!(r.results.len(), 1);
        assert_eq!(r.results[0].status, CheckStatus::Conflict);
        assert_eq!(state.borrow().values[DEFENDER], json!(false));
        assert_eq!(
            e.apply_selected(&[DEFENDER.into()], |_| {})
                .unwrap()
                .results[0]
                .status,
            CheckStatus::Pending
        );
    }
}

#[test]
fn selected_final_gate_rejects_race_and_audit_reports_progress() {
    let (_dir, state, mut e) = fixture(DEFENDER, json!(true));
    let mut progress = Vec::new();
    assert_eq!(
        e.audit_with_progress(|p| progress.push((p.id.to_owned(), p.step.as_str().to_owned())))
            .unwrap()
            .results[0]
            .status,
        CheckStatus::Attention
    );
    assert_eq!(
        progress,
        vec![
            (DEFENDER.into(), "attention".into()),
            ("readiness".into(), "pending".into()),
            ("readiness".into(), "complete".into()),
            ("findings".into(), "pending".into()),
            ("findings".into(), "complete".into())
        ]
    );
    state.borrow_mut().block_at = Some(3);
    assert!(e.apply_selected(&[DEFENDER.into()], |_| {}).is_err());
    assert!(state.borrow().writes.is_empty());
    assert!(!e.load().unwrap()[0].sealed);
}

#[test]
fn selected_initial_probe_errors_preserve_success_and_allow_later_batches() {
    for invalid_value in [false, true] {
        let (dir, state, e) = fixture(DEFENDER, json!(true));
        drop(e);
        state.borrow_mut().values.insert(
            FIREWALL.into(),
            if invalid_value {
                json!("invalid")
            } else {
                json!("Allow")
            },
        );
        if !invalid_value {
            state.borrow_mut().fail_observe = Some(FIREWALL.into());
        }
        let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
        let mut statuses = Vec::new();
        let report = e
            .apply_selected(&[DEFENDER.into(), FIREWALL.into()], |p| {
                statuses.push(p.step.as_str().to_owned());
            })
            .unwrap();
        assert_eq!(statuses, ["pending", "complete", "applied", "error"]);
        assert_eq!(report.results.len(), 2);
        let tx = e.load().unwrap().pop().unwrap();
        assert!(tx.sealed);
        assert_eq!(tx.entries.len(), 1);
        assert_eq!(tx.entries[0].before, json!(true));
        drop(tx);
        drop(e);
        state.borrow_mut().fail_observe = None;
        state
            .borrow_mut()
            .values
            .insert(FIREWALL.into(), json!("Allow"));
        let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
        e.apply_selected(&[FIREWALL.into()], |_| {}).unwrap();
        assert_eq!(e.revert(|_| {}).unwrap().results[0].id, FIREWALL);
        assert_eq!(e.revert(|_| {}).unwrap().results[0].id, DEFENDER);
        assert_eq!(state.borrow().values[DEFENDER], json!(true));
    }
}

#[test]
fn incomplete_older_batch_rejects_disjoint_active_history_without_changes() {
    for reverting in [false, true] {
        let (dir, state, e) = fixture(DEFENDER, json!(true));
        drop(e);
        let mut e = reopen(&dir, &state, &[DEFENDER, FIREWALL]);
        let mut older = prepare(&mut e, 1, DEFENDER, json!(true));
        if reverting {
            e.append(&mut older, Record::Reverting).unwrap();
        }
        let newer = prepare(&mut e, 2, FIREWALL, json!("Allow"));
        let paths: Vec<_> = [&older, &newer]
            .iter()
            .map(|tx| {
                let path = dir.path().join(format!("{}.jsonl", tx.name));
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        drop((older, newer));
        assert!(e.audit().is_err());
        assert!(e.history().is_err());
        assert!(e.apply_selected(&[DEFENDER.into()], |_| {}).is_err());
        assert!(e.revert(|_| {}).is_err());
        assert!(Engine::open(
            dir.path().into(),
            backend(&state, &[DEFENDER, FIREWALL], "machine-a")
        )
        .is_err());
        assert!(state.borrow().events.is_empty());
        for (path, bytes) in paths {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}

#[derive(Default)]
struct FakeState {
    values: HashMap<String, Value>,
    writes: Vec<(String, Value)>,
    events: Vec<String>,
    blocked: bool,
    fail_write: bool,
    fail_before_write: bool,
    fail_findings: bool,
    fail_machine: bool,
    catalog_target: Option<Value>,
    observe_count: usize,
    drift_at: Option<(usize, Value)>,
    block_at: Option<usize>,
    fail_observe: Option<String>,
    evidence: HashMap<String, (Option<EffectiveFirewall>, Option<Authority>)>,
    evidence_at: Option<(usize, Option<EffectiveFirewall>, Option<Authority>)>,
    readiness: Readiness,
    readiness_count: usize,
    short_batch: bool,
    extra_findings: Vec<Finding>,
    /// A write changes only the items it names, the way a real dynamic control does.
    merge_items: bool,
}
struct Fake {
    state: Rc<RefCell<FakeState>>,
    ids: Vec<String>,
    machine: String,
}
impl Backend for Fake {
    fn observe_many(&mut self, ids: &[&str]) -> Vec<Result<Observation>> {
        let mut all: Vec<_> = ids.iter().map(|id| self.observe(id)).collect();
        if self.state.borrow().short_batch {
            all.pop();
        }
        all
    }
    fn machine_id(&mut self) -> Result<String> {
        if self.state.borrow().fail_machine {
            bail!("Simulated machine identity transport failure");
        }
        Ok(self.machine.clone())
    }
    fn controls(&self) -> Vec<Control> {
        self.ids
            .iter()
            .map(|id| Control {
                id: id.clone(),
                title: id.clone(),
                description: String::new(),
                target: self
                    .state
                    .borrow()
                    .catalog_target
                    .clone()
                    .unwrap_or_else(|| target(id).unwrap()),
                reboot: false,
            })
            .collect()
    }
    fn observe(&mut self, id: &str) -> Result<Observation> {
        let mut s = self.state.borrow_mut();
        s.events.push(format!("observe:{id}"));
        s.observe_count += 1;
        if let Some((n, effective, authority)) = s.evidence_at {
            if n == s.observe_count {
                s.evidence.insert(id.into(), (effective, authority));
            }
        }
        if s.fail_observe.as_deref() == Some(id) {
            bail!("Simulated unsupported observation");
        }
        if s.block_at == Some(s.observe_count) {
            s.blocked = true;
        }
        if let Some((n, value)) = s.drift_at.clone() {
            if s.observe_count == n {
                s.values.insert(id.into(), value);
            }
        }
        let value = s.values[id].clone();
        let (eligible, reason) = if s.blocked {
            (false, "Managed device")
        } else if id.starts_with("uac.") && value != json!({"present":true,"value":0}) {
            (false, "Preserving absent or nonzero UAC preference")
        } else if machine_registry_control(id)
            && (value["present"] == false || value == target(id)?)
        {
            (
                false,
                "Preserving absent or already-safe machine preference",
            )
        } else {
            (true, "Eligible")
        };
        let (effective, authority) = if firewall_control(id) {
            let effective = if id.ends_with(".enabled") {
                EffectiveFirewall::Enabled(value.as_bool().unwrap())
            } else {
                // Legacy fixtures intentionally treat NotConfigured as an
                // effective gap; explicit default-proof tests override it.
                EffectiveFirewall::Inbound(if value == "Block" {
                    InboundAction::Block
                } else {
                    InboundAction::Allow
                })
            };
            s.evidence.get(id).copied().unwrap_or((
                Some(effective),
                Some(if s.blocked {
                    Authority::Managed
                } else {
                    Authority::Local
                }),
            ))
        } else {
            (None, None)
        };
        Ok(Observation {
            value,
            eligible,
            reason: reason.into(),
            effective,
            authority,
            ..Observation::default()
        })
    }
    fn write(&mut self, id: &str, value: &Value) -> Result<()> {
        validate_value(id, value)?;
        let mut s = self.state.borrow_mut();
        assert_eq!(
            s.events.last(),
            Some(&format!("observe:{id}")),
            "write must immediately follow a fresh probe"
        );
        s.events.push(format!("write:{id}"));
        if s.fail_before_write {
            bail!("Simulated failure before mutation");
        }
        let mut stored = value.clone();
        if let (true, Some(old), Some(new)) = (
            s.merge_items,
            s.values.get(id).and_then(|v| v["items"].as_object()),
            value["items"].as_object(),
        ) {
            let mut items = old.clone();
            items.extend(new.clone());
            stored = json!({ "items": items });
        }
        s.values.insert(id.into(), stored);
        s.writes.push((id.into(), value.clone()));
        if s.fail_write {
            bail!("Simulated crash after mutation");
        }
        Ok(())
    }
    fn findings(&mut self) -> Result<Vec<Finding>> {
        if self.state.borrow().fail_findings {
            bail!("Simulated findings transport failure");
        }
        Ok(self.state.borrow().extra_findings.clone())
    }
    fn readiness(&mut self) -> Readiness {
        let mut state = self.state.borrow_mut();
        state.readiness_count += 1;
        state.readiness.clone()
    }
}

fn backend(state: &Rc<RefCell<FakeState>>, ids: &[&str], machine: &str) -> Box<dyn Backend> {
    Box::new(Fake {
        state: state.clone(),
        ids: ids.iter().map(|s| (*s).into()).collect(),
        machine: machine.into(),
    })
}
fn fixture(id: &str, before: Value) -> (TempDir, Rc<RefCell<FakeState>>, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let state = Rc::new(RefCell::new(FakeState::default()));
    state.borrow_mut().values.insert(id.into(), before);
    let engine = Engine::open(dir.path().into(), backend(&state, &[id], "machine-a")).unwrap();
    (dir, state, engine)
}
fn prepare(engine: &mut Engine, sequence: u64, id: &str, before: Value) -> Transaction {
    let mut tx = engine.create(sequence).unwrap();
    engine
        .append(
            &mut tx,
            Record::Prepare {
                id: id.into(),
                before,
            },
        )
        .unwrap();
    tx
}
fn reopen(dir: &TempDir, state: &Rc<RefCell<FakeState>>, ids: &[&str]) -> Engine {
    Engine::open(dir.path().into(), backend(state, ids, "machine-a")).unwrap()
}

const MACHINE_REGISTRY: [(&str, u32); 4] = [
    ("installer.always_install_elevated", 0),
    ("lsa.restrict_anonymous_sam", 1),
    ("lsa.limit_blank_password_use", 1),
    ("wdigest.use_logon_credential", 0),
];

// Canonical self-relative descriptor: SYSTEM owner, Administrators group,
// explicit Authenticated Users ACE(s), then an untouched administrator ACE.
// The fixture builds actual bytes independently of repair_target.
fn acl_snapshot(mask: u32, count: usize) -> Value {
    acl_snapshot_principals(mask, count, &[18], &[32, 544])
}

fn acl_snapshot_principals(mask: u32, count: usize, owner: &[u32], group: &[u32]) -> Value {
    fn sid(subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, 5];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend(sid(owner));
    let group_offset = sd.len() as u32;
    sd[8..12].copy_from_slice(&group_offset.to_le_bytes());
    sd.extend(sid(group));
    let offset = sd.len();
    sd[16..20].copy_from_slice(&(offset as u32).to_le_bytes());
    let mut acl = vec![2, 0, 0, 0, 0, 0, 0, 0];
    acl[4..6].copy_from_slice(&((count + 1) as u16).to_le_bytes());
    for (rights, subs) in std::iter::repeat_n((mask, &[11][..]), count)
        .chain(std::iter::once((0x000f_01ff, &[32, 544][..])))
    {
        let principal = sid(subs);
        acl.extend([0, 0]);
        acl.extend(((8 + principal.len()) as u16).to_le_bytes());
        acl.extend(rights.to_le_bytes());
        acl.extend(principal);
    }
    let size = acl.len() as u16;
    acl[2..4].copy_from_slice(&size.to_le_bytes());
    sd.extend(acl);
    let mut text = String::from("dacl-v1:");
    for byte in sd {
        text.push_str(&format!("{byte:02x}"));
    }
    json!(text)
}

#[test]
fn exact_readback_failure_keeps_apply_and_restore_recoverable() {
    for id in ["permissions.service.bits", "permissions.service.wuauserv"] {
        let before = acl_snapshot(0x0002_0012, 1);
        let after = acl_snapshot(0x0002_0010, 1);
        let safe_drift = acl_snapshot(0x0002_0030, 1);
        let (dir, state, mut e) = fixture(id, before.clone());
        // A successful write acknowledgment followed by a different, still
        // compliant ACL must not seal the transaction.
        state.borrow_mut().drift_at = Some((3, safe_drift.clone()));
        assert!(e.apply(|_| {}).is_err());
        let tx = e.load().unwrap().pop().unwrap();
        assert_eq!(tx.entries[0].state, State::Pending);
        assert_eq!(tx.entries[0].before, before);
        assert!(!tx.sealed);
        drop(tx);
        drop(e);
        let mut e = reopen(&dir, &state, &[id]);
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Conflict
        );
        assert_eq!(state.borrow().writes.len(), 1);

        state.borrow_mut().values.insert(id.into(), after.clone());
        let n = state.borrow().observe_count;
        state.borrow_mut().drift_at = Some((n + 3, safe_drift));
        assert!(e.revert(|_| {}).is_err());
        assert_eq!(e.load().unwrap()[0].entries[0].state, State::Restoring);
        assert!(!e.load().unwrap()[0].reverted);
        drop(e);
        let mut e = reopen(&dir, &state, &[id]);
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Conflict
        );
        assert_eq!(state.borrow().writes.len(), 2);
        state.borrow_mut().values.insert(id.into(), after);
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Restored
        );
        assert_eq!(state.borrow().values[id], before);
    }
}

#[test]
fn owner_group_and_protection_are_exact_engine_drift_fingerprints() {
    let mut protected = acl_snapshot(0x0002_0010, 1).as_str().unwrap().to_owned();
    let prefix = "dacl-v1:".len();
    protected.replace_range(prefix + 2 * 2..prefix + 4 * 2, "0490");
    for id in ["permissions.service.bits", "permissions.service.wuauserv"] {
        for drift in [
            acl_snapshot_principals(0x0002_0010, 1, &[32, 544], &[32, 544]),
            acl_snapshot_principals(0x0002_0010, 1, &[18], &[32, 545]),
            json!(protected),
        ] {
            validate_value(id, &drift).unwrap();
            assert_eq!(target_for(id, &drift).unwrap(), drift);
            let before = acl_snapshot(0x0002_0012, 1);
            let (dir, state, mut e) = fixture(id, before.clone());
            e.apply(|_| {}).unwrap();
            state.borrow_mut().values.insert(id.into(), drift.clone());
            drop(e);
            let mut e = reopen(&dir, &state, &[id]);
            assert_eq!(
                e.apply(|_| {}).unwrap().results[0].status,
                CheckStatus::Conflict
            );
            assert_eq!(
                e.revert(|_| {}).unwrap().results[0].status,
                CheckStatus::Conflict
            );
            assert_eq!(state.borrow().values[id], drift);
            assert_eq!(state.borrow().writes.len(), 1);
            assert_eq!(e.load().unwrap()[0].entries[0].before, before);
        }
    }
}

#[test]
fn restore_reason_exceptions_are_exact_and_control_scoped() {
    let uac_reason = "Preserving absent or nonzero UAC preference";
    let registry_reason = "Preserving absent or already-safe machine preference";
    for id in MACHINE_REGISTRY.iter().map(|(id, _)| *id).chain([
        "uac.enabled",
        "uac.consent",
        DEFENDER,
        "permissions.service.bits",
    ]) {
        let current = if permission_control(id) {
            acl_snapshot(0x0002_0010, 1)
        } else {
            target(id).unwrap()
        };
        let (_dir, _state, e) = fixture(id, current.clone());
        for reason in [
            uac_reason,
            registry_reason,
            "Managed device",
            "Eligible",
            "Preserving absent or already-safe machine preference ",
        ] {
            let o = Observation {
                value: current.clone(),
                eligible: false,
                reason: reason.into(),
                ..Observation::default()
            };
            assert_eq!(
                restore_eligible(e.control(id).unwrap(), &o),
                (id.starts_with("uac.") && reason == uac_reason)
                    || (machine_registry_control(id) && reason == registry_reason),
                "{id}: {reason}"
            );
            let absent = Observation {
                value: json!({"present":false,"value":null}),
                ..o
            };
            assert!(!restore_eligible(e.control(id).unwrap(), &absent));
        }
    }
}

#[test]
fn wal_and_line_bounds_reject_before_observation_or_mutation() {
    let id = "permissions.service.bits";
    let (dir, state, mut e) = fixture(id, acl_snapshot(0x0002_0010, 1));
    let tx = prepare(&mut e, 1, id, acl_snapshot(0x0002_0012, 1));
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    drop(tx);
    let prefix = fs::read(&path).unwrap();
    // Valid JSON plus whitespace proves the line-size guard, rather than
    // an incidental syntax/truncation error, rejects the oversized record.
    let mut oversized_line = prefix.clone();
    oversized_line.extend_from_slice(b"{\"kind\":\"applied\",\"id\":\"permissions.service.bits\"}");
    oversized_line.extend(vec![b' '; MAX_LINE]);
    oversized_line.push(b'\n');
    let mut oversized_wal = prefix;
    oversized_wal.resize(MAX_WAL as usize, b' ');
    oversized_wal.push(b'\n');
    for (bytes, message) in [
        (oversized_line, "Invalid journal record size"),
        (oversized_wal, "Journal exceeds size limit"),
    ] {
        fs::write(&path, &bytes).unwrap();
        assert!(format!("{:#}", e.revert(|_| {}).unwrap_err()).contains(message));
        assert!(state.borrow().events.is_empty());
        assert!(state.borrow().writes.is_empty());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn service_acl_targets_are_exact_deterministic_and_not_catalog_sentinels() {
    for id in ["permissions.service.bits", "permissions.service.wuauserv"] {
        let before = acl_snapshot(0x0002_0012, 1);
        let after = acl_snapshot(0x0002_0010, 1);
        assert_eq!(target_for(id, &before).unwrap(), after);
        assert_eq!(target_for(id, &after).unwrap(), after);
        assert!(validate_value(id, &target(id).unwrap()).is_err());
        let (_dir, state, mut e) = fixture(id, before.clone());
        assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Attention);
        assert_eq!(
            e.apply(|_| {}).unwrap().results[0].status,
            CheckStatus::Applied
        );
        assert_eq!(state.borrow().writes, vec![(id.into(), after.clone())]);
        assert_eq!(e.load().unwrap()[0].entries[0].before, before);
        assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Compliant);
        assert_eq!(
            e.apply(|_| {}).unwrap().results[0].status,
            CheckStatus::Unchanged
        );
        state.borrow_mut().blocked = true;
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Skipped
        );
        state.borrow_mut().blocked = false;
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Restored
        );
        assert_eq!(state.borrow().values[id], before);

        let (_dir, state, mut e) = fixture(id, after);
        assert!(e.apply(|_| {}).unwrap().transaction.is_none());
        assert!(state.borrow().writes.is_empty());
    }
}

#[test]
fn service_catalog_accepts_only_the_compiled_marker_and_fixed_ids() {
    let id = "permissions.service.bits";
    let before = acl_snapshot(0x0002_0012, 1);
    let (dir, state, e) = fixture(id, before.clone());
    drop(e);
    for wrong in [before.clone(), json!(true), json!("service-dacl-repair-v2")] {
        state.borrow_mut().catalog_target = Some(wrong);
        assert!(Engine::open(dir.path().into(), backend(&state, &[id], "machine-a")).is_err());
    }
    state.borrow_mut().catalog_target = Some(json!("service-dacl-repair-v1"));
    assert!(reopen(&dir, &state, &[id]).history().unwrap().is_empty());
    for unknown in [
        "permissions.service.anything",
        "permissions.service.BITS",
        "permissions.file.bits",
    ] {
        assert!(target(unknown).is_err());
        assert!(validate_value(unknown, &before).is_err());
        assert!(target_for(unknown, &before).is_err());
    }
    assert!(state.borrow().writes.is_empty());
}

#[test]
fn service_acl_unknown_apply_and_restore_outcomes_recover_exactly() {
    for id in ["permissions.service.bits", "permissions.service.wuauserv"] {
        for mutated in [false, true] {
            let before = acl_snapshot(0x0002_0012, 1);
            let (dir, state, mut e) = fixture(id, before.clone());
            state.borrow_mut().fail_before_write = !mutated;
            state.borrow_mut().fail_write = mutated;
            assert!(e.apply(|_| {}).is_err());
            assert_eq!(e.load().unwrap()[0].entries[0].state, State::Pending);
            drop(e);
            state.borrow_mut().fail_before_write = false;
            let mut e = reopen(&dir, &state, &[id]);
            assert_eq!(
                e.apply(|_| {}).unwrap().results[0].status,
                CheckStatus::Pending
            );
            if mutated {
                assert!(e.revert(|_| {}).is_err());
                assert_eq!(e.load().unwrap()[0].entries[0].state, State::Restoring);
                drop(e);
                e = reopen(&dir, &state, &[id]);
            }
            state.borrow_mut().fail_write = false;
            e.revert(|_| {}).unwrap();
            assert_eq!(state.borrow().values[id], before);
            assert_eq!(state.borrow().writes.len(), if mutated { 2 } else { 0 });
            assert!(e.load().unwrap()[0].reverted);
        }
    }
}

#[test]
fn intervening_safe_acl_changes_conflict_with_exact_recorded_after_image() {
    let id = "permissions.service.bits";
    let before = acl_snapshot(0x0002_0012, 1);
    let (dir, state, mut e) = fixture(id, before.clone());
    e.apply(|_| {}).unwrap();
    let safe_drift = acl_snapshot(0x0002_0030, 1); // additional safe STOP grant
    assert_eq!(target_for(id, &safe_drift).unwrap(), safe_drift);
    state
        .borrow_mut()
        .values
        .insert(id.into(), safe_drift.clone());
    drop(e);
    let mut e = reopen(&dir, &state, &[id]);
    assert_eq!(
        e.apply(|_| {}).unwrap().results[0].status,
        CheckStatus::Conflict
    );
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Conflict
    );
    assert_eq!(state.borrow().values[id], safe_drift);
    assert_eq!(state.borrow().writes.len(), 1);
    assert_eq!(e.load().unwrap()[0].entries[0].before, before);
    assert!(!e.load().unwrap()[0].reverted);
}

#[test]
fn malformed_impossible_and_already_safe_acl_before_images_are_rejected() {
    let id = "permissions.service.bits";
    let valid = acl_snapshot(0x0002_0012, 1);
    let mut unsupported = valid.as_str().unwrap().to_owned();
    // The first ACE begins at byte 56: DENY is structurally valid but cannot
    // be emitted by this repair algorithm as a repairable original.
    let prefix = "dacl-v1:".len();
    unsupported.replace_range(prefix + 56 * 2..prefix + 56 * 2 + 2, "01");
    validate_value(id, &json!(unsupported)).unwrap();
    assert!(target_for(id, &json!(unsupported)).is_err());
    for bad in [
        json!(null),
        json!(true),
        target(id).unwrap(),
        json!("dacl-v1:00"),
        json!("dacl-v1:GG"),
        json!(format!("dacl-v1:{}", "00".repeat(16 * 1024 + 1))),
        json!("powershell.exe -Command Write-Output untrusted"),
        json!("D:(A;;GA;;;WD)"),
        json!("Block"),
        json!(unsupported),
        acl_snapshot(0x0002_0010, 1),
    ] {
        let (_dir, state, mut e) = fixture(id, valid.clone());
        drop(prepare(&mut e, 1, id, bad));
        assert!(e.revert(|_| {}).is_err());
        assert!(e.apply(|_| {}).is_err());
        assert!(state.borrow().writes.is_empty());
    }
}

#[test]
fn ineligible_complex_acl_is_skipped_without_stranding_prior_registry_repairs() {
    let registry = "lsa.limit_blank_password_use";
    let id = "permissions.service.bits";
    let mut complex = acl_snapshot(0x0002_0012, 1).as_str().unwrap().to_owned();
    let prefix = "dacl-v1:".len();
    complex.replace_range(prefix + 56 * 2..prefix + 56 * 2 + 2, "01");
    let complex = json!(complex);
    crate::permissions::validate_value(id, &complex).unwrap();
    assert!(target_for(id, &complex).is_err());
    let (dir, state, e) = fixture(registry, json!({"present":true,"value":0}));
    drop(e);
    state.borrow_mut().values.insert(id.into(), complex.clone());
    // Three registry probes precede the ACL observation. The native backend
    // advertises valid-but-unsupported descriptors as ineligible.
    state.borrow_mut().block_at = Some(4);
    let mut e = reopen(&dir, &state, &[registry, id]);
    let report = e.apply(|_| {}).unwrap();
    assert_eq!(report.results[0].status, CheckStatus::Applied);
    assert_eq!(report.results[1].status, CheckStatus::Skipped);
    assert!(e.load().unwrap()[0].sealed);
    assert_eq!(e.audit().unwrap().results[1].status, CheckStatus::Skipped);
    assert_eq!(
        e.apply(|_| {}).unwrap().results[1].status,
        CheckStatus::Skipped
    );
    assert_eq!(state.borrow().values[id], complex);
    assert_eq!(state.borrow().writes.len(), 1);
}

#[test]
fn bounded_large_acl_before_image_survives_wal_roundtrip() {
    let id = "permissions.service.wuauserv";
    let before = acl_snapshot(0x0002_0012, 400);
    assert!(before.as_str().unwrap().len() > 4096);
    let (dir, state, mut e) = fixture(id, before.clone());
    e.apply(|_| {}).unwrap();
    drop(e);
    let mut e = reopen(&dir, &state, &[id]);
    assert_eq!(e.load().unwrap()[0].entries[0].before, before);
    e.revert(|_| {}).unwrap();
    assert_eq!(state.borrow().values[id], before);
}

#[test]
fn binary_registry_controls_preserve_absence_and_restore_exact_originals() {
    for (id, bit) in MACHINE_REGISTRY {
        let safe = json!({"present":true,"value":bit});
        let unsafe_value = json!({"present":true,"value":1-bit});
        let absent = json!({"present":false,"value":null});
        assert_eq!(target(id).unwrap(), safe);
        for before in [&absent, &safe] {
            let (_dir, state, mut e) = fixture(id, before.clone());
            let report = e.apply(|_| {}).unwrap();
            assert!(report.transaction.is_none());
            assert!(e.history().unwrap().is_empty());
            assert!(state.borrow().writes.is_empty());
            assert!(!apply_eligible(
                id,
                &Observation {
                    value: before.clone(),
                    eligible: true,
                    reason: String::new(),
                    ..Observation::default()
                }
            ));
        }
        let (dir, state, mut e) = fixture(id, unsafe_value.clone());
        e.apply(|_| {}).unwrap();
        assert_eq!(state.borrow().values[id], safe);
        assert_eq!(e.load().unwrap()[0].entries[0].before, unsafe_value);
        assert_eq!(
            e.apply(|_| {}).unwrap().results[0].status,
            CheckStatus::Unchanged
        );
        state.borrow_mut().blocked = true;
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Skipped
        );
        assert_eq!(state.borrow().writes.len(), 1);
        drop(e);
        state.borrow_mut().blocked = false;
        let mut e = reopen(&dir, &state, &[id]);
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Restored
        );
        assert_eq!(state.borrow().values[id], unsafe_value);
        assert_eq!(state.borrow().writes.len(), 2);

        // Absence remains a supported journal original, although automatic
        // apply never invents an explicit value for it.
        let (_dir, state, mut e) = fixture(id, safe);
        drop(prepare(&mut e, 1, id, absent.clone()));
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Restored
        );
        assert_eq!(state.borrow().values[id], absent);
    }
}

#[test]
fn binary_registry_malformed_values_fail_before_replay() {
    for (id, _) in MACHINE_REGISTRY {
        for bad in [
            json!(true),
            json!(1),
            json!("1"),
            json!({"present":true,"value":2}),
            json!({"present":true,"value":5}),
            json!({"present":true,"value":-1}),
            json!({"present":true,"value":1.0}),
            json!({"present":true,"value":null}),
            json!({"present":false,"value":0}),
            json!({"present":false}),
            json!({"present":true,"value":1,"path":"HKCU"}),
        ] {
            assert!(validate_value(id, &bad).is_err(), "{id}: {bad}");
            let (_dir, state, mut e) = fixture(id, target(id).unwrap());
            drop(prepare(&mut e, 1, id, bad));
            assert!(e.revert(|_| {}).is_err());
            assert!(e.apply(|_| {}).is_err());
            assert!(state.borrow().writes.is_empty());
        }
        let (_dir, state, mut e) = fixture(id, target(id).unwrap());
        drop(prepare(&mut e, 1, id, target(id).unwrap()));
        assert!(e.revert(|_| {}).is_err()); // already-compliant before-image
        assert!(state.borrow().writes.is_empty());
    }
}

#[test]
fn legacy_twelve_control_schema_one_wal_replays_with_extended_catalog() {
    let originals = [
        ("defender.realtime", json!(true)),
        ("defender.behavior", json!(true)),
        ("defender.ioav", json!(true)),
        ("defender.archive", json!(true)),
        ("firewall.domain.enabled", json!(false)),
        ("firewall.private.enabled", json!(false)),
        ("firewall.public.enabled", json!(false)),
        ("firewall.domain.inbound", json!("Allow")),
        ("firewall.private.inbound", json!("Allow")),
        ("firewall.public.inbound", json!("NotConfigured")),
        ("uac.enabled", json!({"present":true,"value":0})),
        ("uac.consent", json!({"present":true,"value":0})),
    ];
    let dir = tempfile::tempdir().unwrap();
    let name = "00000000000000000001-00000000-0000-4000-8000-000000000001";
    let mut wal = format!("{{\"kind\":\"header\",\"schema\":1,\"machine\":\"machine-a\",\"transaction\":\"{name}\",\"sequence\":1}}\n");
    let state = Rc::new(RefCell::new(FakeState::default()));
    for (id, before) in &originals {
        wal.push_str(&format!("{{\"kind\":\"prepare\",\"id\":\"{id}\",\"before\":{before}}}\n{{\"kind\":\"applied\",\"id\":\"{id}\"}}\n"));
        state
            .borrow_mut()
            .values
            .insert((*id).into(), target(id).unwrap());
    }
    wal.push_str("{\"kind\":\"sealed\"}\n");
    fs::write(dir.path().join(format!("{name}.jsonl")), wal).unwrap();
    let mut ids: Vec<&str> = originals.iter().map(|(id, _)| *id).collect();
    ids.extend(MACHINE_REGISTRY.iter().map(|(id, _)| *id));
    ids.extend(["permissions.service.bits", "permissions.service.wuauserv"]);
    let mut e = reopen(&dir, &state, &ids);
    // Old raw NotConfigured originals must still restore even when the
    // current inherited default is effectively Block after that restore.
    state.borrow_mut().evidence.insert(
        FIREWALL.into(),
        (
            Some(EffectiveFirewall::Inbound(InboundAction::Block)),
            Some(Authority::Local),
        ),
    );
    assert_eq!(e.revert(|_| {}).unwrap().results.len(), 12);
    for (id, before) in originals {
        assert_eq!(state.borrow().values[id], before);
    }
    assert_eq!(state.borrow().writes.len(), 12);
    assert!(e.load().unwrap()[0].reverted);
}

#[test]
fn apply_is_idempotent_and_audit_never_mutates_preferences() {
    let (_dir, state, mut e) = fixture(DEFENDER, json!(true));
    assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Attention);
    assert!(state.borrow().writes.is_empty());
    assert!(e.history().unwrap().is_empty());
    let mut statuses = Vec::new();
    let first = e
        .apply(|p| statuses.push((p.id.to_string(), p.step.as_str().to_string())))
        .unwrap();
    assert_eq!(
        statuses,
        vec![
            ("readiness".into(), "pending".into()),
            ("readiness".into(), "complete".into()),
            (DEFENDER.into(), "applied".into()),
        ]
    );
    let second = e.apply(|p| assert!(p.step.as_str().is_ascii())).unwrap();
    assert_eq!(first.transaction, second.transaction);
    assert_eq!(state.borrow().writes.len(), 1);
    assert_eq!(e.load().unwrap()[0].entries[0].before, json!(true));
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Restored
    );
    assert_eq!(state.borrow().values[DEFENDER], json!(true));
    assert!(e.revert(|_| {}).unwrap().transaction.is_none());
    assert_eq!(state.borrow().writes.len(), 2);
}

#[test]
fn prepared_apply_recovery_handles_both_sides_of_write() {
    for written in [false, true] {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        drop(prepare(&mut e, 1, DEFENDER, json!(true)));
        if written {
            state
                .borrow_mut()
                .values
                .insert(DEFENDER.into(), json!(false));
        }
        drop(e);
        let mut e = reopen(&dir, &state, &[DEFENDER]);
        assert_eq!(
            e.apply(|_| {}).unwrap().results[0].status,
            CheckStatus::Pending
        );
        e.audit().unwrap();
        assert!(state.borrow().writes.is_empty());
        e.revert(|_| {}).unwrap();
        assert_eq!(state.borrow().values[DEFENDER], json!(true));
        assert_eq!(state.borrow().writes.len(), usize::from(written));
        assert!(e.history().unwrap()[0].ends_with(" reverted"));
    }
}

#[test]
fn write_error_preserves_pending_and_restore_error_is_retryable() {
    for before_write in [false, true] {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        state.borrow_mut().fail_write = !before_write;
        state.borrow_mut().fail_before_write = before_write;
        assert!(e.apply(|_| {}).is_err());
        assert_eq!(e.load().unwrap()[0].entries[0].state, State::Pending);
        drop(e);
        state.borrow_mut().fail_before_write = false;
        let mut e = reopen(&dir, &state, &[DEFENDER]);
        if !before_write {
            // Restore mutates, then reports failure. Retrying recognizes the
            // before image rather than performing a second restore write.
            assert!(e.revert(|_| {}).is_err());
            assert_eq!(e.load().unwrap()[0].entries[0].state, State::Restoring);
        }
        let writes = state.borrow().writes.len();
        state.borrow_mut().fail_write = false;
        e.revert(|_| {}).unwrap();
        assert_eq!(state.borrow().writes.len(), writes);
        assert_eq!(state.borrow().values[DEFENDER], json!(true));
    }
}

#[test]
fn overlapping_active_owners_fail_closed_before_replay() {
    let (_dir, state, mut e) = fixture(FIREWALL, json!("Allow"));
    let mut older = prepare(&mut e, 1, FIREWALL, json!("Allow"));
    e.append(
        &mut older,
        Record::Applied {
            id: FIREWALL.into(),
        },
    )
    .unwrap();
    e.append(&mut older, Record::Sealed).unwrap();
    drop(older);
    let newer = prepare(&mut e, 2, FIREWALL, json!("NotConfigured"));
    drop(newer);
    assert!(e.revert(|_| {}).is_err());
    assert!(e.apply(|_| {}).is_err());
    assert!(e.apply_selected(&[FIREWALL.into()], |_| {}).is_err());
    assert!(e.audit().is_err());
    assert!(e.history().is_err());
    assert!(state.borrow().events.is_empty());
    assert!(state.borrow().writes.is_empty());
}

#[test]
fn final_probe_detects_apply_and_restore_races() {
    let (_dir, state, mut e) = fixture(FIREWALL, json!("Allow"));
    state.borrow_mut().drift_at = Some((2, json!("NotConfigured")));
    assert!(e.apply(|_| {}).is_err());
    assert!(state.borrow().writes.is_empty());
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Conflict
    );
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("Block"));
    let count = state.borrow().observe_count;
    state.borrow_mut().drift_at = Some((count + 2, json!("NotConfigured")));
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Conflict
    );
    assert!(state.borrow().writes.is_empty());
    assert_eq!(e.load().unwrap()[0].entries[0].state, State::Restoring);
}

#[test]
fn eligibility_blocks_changes_but_allows_uac_restore_after_gate() {
    let (_dir, state, mut e) = fixture("uac.consent", json!({"present":true,"value":0}));
    state.borrow_mut().blocked = true;
    assert_eq!(
        e.apply(|_| {}).unwrap().results[0].status,
        CheckStatus::Skipped
    );
    assert!(e.history().unwrap().is_empty());
    state.borrow_mut().blocked = false;
    e.apply(|_| {}).unwrap();
    state.borrow_mut().blocked = true;
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Skipped
    );
    assert_eq!(state.borrow().writes.len(), 1);
    state.borrow_mut().blocked = false;
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Restored
    );
    assert_eq!(
        state.borrow().values["uac.consent"],
        json!({"present":true,"value":0})
    );
}

#[test]
fn before_images_reject_duplicate_missing_unknown_and_executable_fields() {
    for before in [
        r#"{"present":true,"value":0,"value":1}"#,
        r#"{"present":true,"present":false,"value":null}"#,
        r#"{"present":false}"#,
        r#"{"present":true,"value":0,"command":"execute"}"#,
        r#"{"present":true,"value":"execute"}"#,
    ] {
        let line = format!(r#"{{"kind":"prepare","id":"uac.enabled","before":{before}}}"#);
        assert!(
            serde_json::from_str::<Record>(&line).is_err(),
            "accepted {before}"
        );
    }
    let line = r#"{"kind":"prepare","id":"uac.enabled","before":{"present":false,"value":null}}"#;
    assert!(serde_json::from_str::<Record>(line).is_ok());
}

#[test]
fn all_transactions_are_validated_before_any_replay() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(false));
    let older = prepare(&mut e, 1, DEFENDER, json!(true));
    let path = dir.path().join(format!("{}.jsonl", older.name));
    drop(older);
    drop(prepare(&mut e, 2, DEFENDER, json!(true)));
    let original = fs::read(&path).unwrap();
    for bad in [
        b"{not json}\n".to_vec(),
        b"{\"kind\":\"prepare\",\"id\":\"arbitrary.command\",\"before\":true}\n".to_vec(),
        b"{\"kind\":\"prepare\",\"id\":\"defender.realtime\",\"before\":\"execute\"}\n".to_vec(),
        b"{\"kind\":\"applied\",\"id\":\"defender.realtime\",\"extra\":1}\n".to_vec(),
        b"{\"kind\":\"reverted\"}\n".to_vec(),
        vec![b'x'; MAX_LINE + 1],
        b"{}".to_vec(),
    ] {
        let mut corrupt = original.clone();
        corrupt.extend(bad);
        fs::write(&path, &corrupt).unwrap();
        assert!(e.revert(|_| {}).is_err());
        assert!(e.apply(|_| {}).is_err());
        assert!(e.audit().is_err());
        assert!(e.history().is_err());
        assert!(state.borrow().writes.is_empty());
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    }
    fs::write(&path, &original).unwrap();
    assert!(Engine::open(dir.path().into(), backend(&state, &[DEFENDER], "machine-b")).is_err());
    let mut lines: Vec<Value> = String::from_utf8(original)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    lines[0]["schema"] = json!(999);
    fs::write(
        &path,
        lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
    )
    .unwrap();
    assert!(e.revert(|_| {}).is_err());
    assert!(state.borrow().writes.is_empty());
}

#[test]
fn result_storage_failure_retains_recoverable_prepare() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    let mut tx = prepare(&mut e, 1, DEFENDER, json!(true));
    e.observe(DEFENDER).unwrap();
    e.backend.write(DEFENDER, &json!(false)).unwrap();
    IO_FAULT.with(|f| *f.borrow_mut() = Some(("snapshot_sync", 0)));
    assert!(e
        .append(
            &mut tx,
            Record::Applied {
                id: DEFENDER.into()
            }
        )
        .is_err());
    assert!(e.history().is_err()); // poisoned instance cannot continue
    drop(tx);
    drop(e);
    let mut e = reopen(&dir, &state, &[DEFENDER]);
    assert_eq!(e.load().unwrap()[0].entries[0].state, State::Pending);
    e.revert(|_| {}).unwrap();
    assert_eq!(state.borrow().values[DEFENDER], json!(true));
}

#[test]
fn journal_creation_failure_prevents_mutation_and_lock_is_nonblocking() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    let held = e.lock().unwrap();
    assert!(e.audit().is_err());
    assert!(e.apply(|_| {}).is_err());
    assert!(e.revert(|_| {}).is_err());
    assert!(e.history().is_err());
    assert!(Engine::open(dir.path().into(), backend(&state, &[DEFENDER], "machine-a")).is_err());
    drop(held);
    fs::create_dir(dir.path().join("invalid.jsonl")).unwrap();
    assert!(e.apply(|_| {}).is_err());
    assert!(state.borrow().writes.is_empty());
}

#[test]
fn append_rejects_changed_length_without_repairing_the_tail() {
    for truncate in [false, true] {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        let mut tx = prepare(&mut e, 1, DEFENDER, json!(true));
        let path = dir.path().join(format!("{}.jsonl", tx.name));
        if truncate {
            // Truncate precisely at a valid record boundary, not only in
            // malformed JSON: appending Applied would lose its before image.
            let bytes = fs::read(&path).unwrap();
            let header_end = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(header_end as u64)
                .unwrap();
        } else {
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"{\"kind\":")
                .unwrap();
        }
        let damaged = fs::read(&path).unwrap();
        assert!(e
            .append(
                &mut tx,
                Record::Applied {
                    id: DEFENDER.into()
                }
            )
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), damaged);
        assert!(e.storage_failed);
        assert!(e.apply(|_| {}).is_err());
        assert!(state.borrow().writes.is_empty());
    }
}

#[test]
fn legacy_partial_result_preserves_evidence_but_complete_unterminated_json_requires_review() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(false));
    let tx = prepare(&mut e, 1, DEFENDER, json!(true));
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    drop(tx);
    let prefix = fs::read(&path).unwrap();
    let result = b"{\"kind\":\"applied\",\"id\":\"defender.realtime\"}\n";
    for end in 1..result.len() {
        let mut torn = prefix.clone();
        torn.extend_from_slice(&result[..end]);
        fs::write(&path, &torn).unwrap();
        if end == result.len() - 1 {
            let error = Engine::open(dir.path().into(), backend(&state, &[DEFENDER], "machine-a"))
                .err()
                .unwrap();
            assert!(error.downcast_ref::<JournalRecoveryRequired>().is_some());
            assert!(e.revert(|_| {}).is_err());
        } else {
            let recovered = reopen(&dir, &state, &[DEFENDER]);
            assert_eq!(recovered.load().unwrap()[0].entries[0].before, json!(true));
            let evidence = dir.path().join(format!(
                "{}.evidence-{}",
                path.file_stem().unwrap().to_str().unwrap(),
                hex::encode(Sha256::digest(&torn))
            ));
            assert_eq!(fs::read(evidence).unwrap(), torn);
        }
        assert_eq!(fs::read(&path).unwrap(), torn);
        assert!(state.borrow().writes.is_empty());
    }
    fs::write(&path, prefix).unwrap();
    e.revert(|_| {}).unwrap();
    assert_eq!(state.borrow().values[DEFENDER], json!(true));
}

#[test]
fn legacy_torn_restore_records_recover_without_repeating_a_completed_write() {
    for record in [
        Record::RestorePending {
            id: DEFENDER.into(),
        },
        Record::Restored {
            id: DEFENDER.into(),
        },
        Record::Reverted,
    ] {
        let (dir, state, mut e) = fixture(DEFENDER, json!(true));
        e.apply(|_| {}).unwrap();
        let mut tx = e.load().unwrap().pop().unwrap();
        e.append(&mut tx, Record::Reverting).unwrap();
        let restore_happened = !matches!(&record, Record::RestorePending { .. });
        if restore_happened {
            e.append(
                &mut tx,
                Record::RestorePending {
                    id: DEFENDER.into(),
                },
            )
            .unwrap();
            e.observe(DEFENDER).unwrap();
            e.backend.write(DEFENDER, &json!(true)).unwrap();
        }
        if matches!(&record, Record::Reverted) {
            e.append(
                &mut tx,
                Record::Restored {
                    id: DEFENDER.into(),
                },
            )
            .unwrap();
        }
        let path = dir.path().join(format!("{}.jsonl", tx.name));
        drop(tx);
        drop(e);
        let prefix = fs::read(&path).unwrap();
        let mut bytes = serde_json::to_vec(&record).unwrap();
        bytes.push(b'\n');
        let writes = state.borrow().writes.len();
        for end in 1..bytes.len() {
            let mut torn = prefix.clone();
            torn.extend_from_slice(&bytes[..end]);
            fs::write(&path, &torn).unwrap();
            if end == bytes.len() - 1 {
                assert!(
                    Engine::open(dir.path().into(), backend(&state, &[DEFENDER], "machine-a"))
                        .is_err()
                );
            } else {
                let mut recovered = reopen(&dir, &state, &[DEFENDER]);
                assert!(recovered.history().unwrap()[0].ends_with(" reverting"));
            }
            assert_eq!(fs::read(&path).unwrap(), torn);
            assert_eq!(state.borrow().writes.len(), writes);
        }
        // Zero result bytes is also recoverable. A completed restore must
        // not be repeated, with or without an incomplete result append.
        fs::write(&path, &prefix).unwrap();
        let mut e = reopen(&dir, &state, &[DEFENDER]);
        e.revert(|_| {}).unwrap();
        assert!(e.load().unwrap()[0].reverted);
        assert_eq!(state.borrow().values[DEFENDER], json!(true));
        assert_eq!(
            state.borrow().writes.len(),
            writes + usize::from(!restore_happened)
        );
    }
}

#[test]
fn repeated_failed_restores_reuse_durable_intent() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    e.apply(|_| {}).unwrap();
    state.borrow_mut().fail_before_write = true;
    assert!(e.revert(|_| {}).is_err());
    let tx = e.load().unwrap().pop().unwrap();
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    let intent = fs::read(&path).unwrap();
    drop(tx);
    for _ in 0..4 {
        drop(e);
        e = reopen(&dir, &state, &[DEFENDER]);
        assert!(e.revert(|_| {}).is_err());
        assert_eq!(fs::read(&path).unwrap(), intent);
        assert_eq!(
            e.apply(|_| {}).unwrap().results[0].status,
            CheckStatus::Pending
        );
    }
    state.borrow_mut().fail_before_write = false;
    e.revert(|_| {}).unwrap();
    assert_eq!(state.borrow().writes.len(), 2);
    assert!(e.load().unwrap()[0].reverted);
}

#[test]
fn noop_apply_and_empty_crash_transaction_do_not_hide_before_images() {
    let (_dir, state, mut e) = fixture(DEFENDER, json!(false));
    for _ in 0..2 {
        assert!(e.apply(|_| {}).unwrap().transaction.is_none());
        assert!(e.history().unwrap().is_empty());
    }
    drop(e.create(1).unwrap()); // crash after header, before first Prepare
    assert_eq!(
        e.apply(|_| {}).unwrap().results[0].status,
        CheckStatus::Pending
    );
    assert!(state.borrow().writes.is_empty());
    e.revert(|_| {}).unwrap();
    assert!(e.load().unwrap()[0].reverted);
    assert!(e.apply(|_| {}).unwrap().transaction.is_none());
}

#[test]
fn audit_reads_in_order_and_fails_a_short_batch_whole() {
    let dir = tempfile::tempdir().unwrap();
    let state = Rc::new(RefCell::new(FakeState::default()));
    state
        .borrow_mut()
        .values
        .insert(DEFENDER.into(), json!(true));
    state
        .borrow_mut()
        .values
        .insert(FIREWALL.into(), json!("Allow"));
    let mut e = Engine::open(
        dir.path().into(),
        backend(&state, &[DEFENDER, FIREWALL], "machine-a"),
    )
    .unwrap();
    let report = e.audit().unwrap();
    let ids: Vec<&str> = report.results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, [DEFENDER, FIREWALL]);
    assert!(report
        .results
        .iter()
        .all(|r| r.status != CheckStatus::Error));
    state.borrow_mut().short_batch = true;
    let report = e.audit().unwrap();
    assert!(report
        .results
        .iter()
        .all(|r| r.status == CheckStatus::Error));
}

#[test]
fn audit_marks_unknown_apply_and_interrupted_rollback_as_pending() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    state.borrow_mut().fail_write = true;
    assert!(e.apply(|_| {}).is_err()); // mutation happened, acknowledgment failed
    drop(e);
    let mut e = reopen(&dir, &state, &[DEFENDER]);
    let report = e.audit().unwrap();
    assert_eq!(report.results[0].status, CheckStatus::Compliant);
    assert!(report
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Pending));
    assert!(e.revert(|_| {}).is_err()); // restore happened, acknowledgment failed
    let report = e.audit().unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Pending));
    assert_eq!(state.borrow().writes.len(), 2);
    state.borrow_mut().fail_write = false;
    e.revert(|_| {}).unwrap();
    assert!(!e
        .audit()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.title == "Journal recovery"));
    assert_eq!(state.borrow().writes.len(), 2);
}

#[test]
fn findings_failure_preserves_reports_and_journal_outcomes() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    state.borrow_mut().fail_findings = true;
    let audit = e
        .audit()
        .expect("Assessment transport failure must be an unknown finding");
    assert_eq!(audit.results[0].status, CheckStatus::Attention);
    assert!(audit
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Unknown));
    let applied = e
        .apply(|_| {})
        .expect("Completed mutation report must survive findings failure");
    assert_eq!(applied.results[0].status, CheckStatus::Applied);
    assert!(applied.transaction.is_some());
    assert!(applied
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Unknown));
    assert!(e.load().unwrap()[0].sealed);
    drop(e);
    let mut e = reopen(&dir, &state, &[DEFENDER]);
    let repeated = e.apply(|_| {}).unwrap();
    assert_eq!(repeated.transaction, applied.transaction);
    assert_eq!(repeated.results[0].status, CheckStatus::Unchanged);
    let restored = e.revert(|_| {}).unwrap();
    assert_eq!(restored.results[0].status, CheckStatus::Restored);
    assert!(restored
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Unknown));
    assert!(e.load().unwrap()[0].reverted);
    assert_eq!(state.borrow().writes.len(), 2);
}

#[test]
fn gate_rejection_does_not_poison_journal_and_recovery_never_bypasses_it() {
    let (dir, state, mut e) = fixture(FIREWALL, json!("Allow"));
    state.borrow_mut().blocked = true;
    let skipped = e.apply(|_| {}).unwrap();
    assert_eq!(skipped.results[0].status, CheckStatus::Skipped);
    assert!(skipped.transaction.is_none());
    assert!(e.history().unwrap().is_empty());
    assert!(state.borrow().writes.is_empty());

    state.borrow_mut().blocked = false; // backend corrected its false positive
    let applied = e.apply(|_| {}).unwrap();
    assert_eq!(applied.results[0].status, CheckStatus::Applied);
    state.borrow_mut().blocked = true;
    let skipped = e.revert(|_| {}).unwrap();
    assert_eq!(skipped.results[0].status, CheckStatus::Skipped);
    assert!(skipped
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Pending));
    assert_eq!(state.borrow().writes.len(), 1);
    drop(e);
    let mut e = reopen(&dir, &state, &[FIREWALL]);
    assert_eq!(
        e.apply(|_| {}).unwrap().results[0].status,
        CheckStatus::Pending
    );
    assert_eq!(e.load().unwrap()[0].entries[0].before, json!("Allow"));
    state.borrow_mut().blocked = false;
    let restored = e.revert(|_| {}).unwrap();
    assert_eq!(restored.transaction, applied.transaction);
    assert_eq!(restored.results[0].status, CheckStatus::Restored);
    assert_eq!(state.borrow().values[FIREWALL], json!("Allow"));
    assert!(e.load().unwrap()[0].reverted);
    assert_eq!(state.borrow().writes.len(), 2);
}

#[test]
fn rejection_after_prepare_can_be_closed_without_a_managed_write() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    state.borrow_mut().block_at = Some(2);
    assert!(e.apply(|_| {}).is_err());
    assert_eq!(e.load().unwrap()[0].entries[0].state, State::Pending);
    assert!(state.borrow().writes.is_empty());
    drop(e);
    let mut e = reopen(&dir, &state, &[DEFENDER]);
    assert!(e
        .audit()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.status == CheckStatus::Pending));
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Unchanged
    );
    assert!(state.borrow().writes.is_empty());
    assert!(e.load().unwrap()[0].reverted);
    state.borrow_mut().blocked = false;
    assert_eq!(
        e.apply(|_| {}).unwrap().results[0].status,
        CheckStatus::Applied
    );
}

#[test]
fn machine_probe_failure_releases_lock_and_creates_no_transaction() {
    let (dir, state, e) = fixture(DEFENDER, json!(true));
    drop(e);
    state.borrow_mut().fail_machine = true;
    assert!(Engine::open(dir.path().into(), backend(&state, &[DEFENDER], "machine-a")).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1); // lock only
    state.borrow_mut().fail_machine = false;
    let mut e = reopen(&dir, &state, &[DEFENDER]);
    assert!(e.history().unwrap().is_empty());
    assert_eq!(
        e.apply(|_| {}).unwrap().results[0].status,
        CheckStatus::Applied
    );
}

#[test]
fn sealed_success_is_informational_but_header_only_crash_requires_review() {
    let (_dir, _state, mut e) = fixture(DEFENDER, json!(true));
    e.apply(|_| {}).unwrap();
    let report = e.audit().unwrap();
    assert_eq!(report.results[0].status, CheckStatus::Compliant);
    assert_eq!(
        report
            .findings
            .iter()
            .find(|f| f.title == "Journal recovery")
            .unwrap()
            .status,
        CheckStatus::Info
    );
    e.revert(|_| {}).unwrap();
    drop(e.create(2).unwrap());
    let report = e.audit().unwrap();
    assert_eq!(
        report
            .findings
            .iter()
            .find(|f| f.title == "Journal recovery")
            .unwrap()
            .status,
        CheckStatus::Pending
    );
}

#[cfg(windows)]
#[test]
fn windows_handles_deny_delete_and_release_locks_on_drop() {
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    let held = e.lock().unwrap();
    let lock_path = dir.path().join(LOCK_NAME);
    let other = open_file(&lock_path, false).unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&other).is_err());
    assert!(fs::remove_file(&lock_path).is_err());
    drop(held);
    fs2::FileExt::try_lock_exclusive(&other).unwrap();
    drop(other);
    e.audit().unwrap();

    let tx = prepare(&mut e, 1, DEFENDER, json!(true));
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    let renamed = dir.path().join("moved");
    same_file(tx.file.as_ref().unwrap(), &path).unwrap();
    assert!(fs::rename(&path, &renamed).is_err());
    assert!(fs::remove_file(&path).is_err());
    drop(tx);
    fs::rename(&path, &renamed).unwrap();
    fs::rename(&renamed, &path).unwrap();
    assert_eq!(
        e.revert(|_| {}).unwrap().results[0].status,
        CheckStatus::Unchanged
    );
    assert!(state.borrow().writes.is_empty());
}

#[cfg(windows)]
#[test]
fn windows_native_link_count_rejects_lock_and_wal_hardlinks() {
    for lock in [false, true] {
        let (dir, state, mut e) = fixture(DEFENDER, json!(false));
        let tx = prepare(&mut e, 1, DEFENDER, json!(true));
        let path = if lock {
            dir.path().join(LOCK_NAME)
        } else {
            dir.path().join(format!("{}.jsonl", tx.name))
        };
        drop(tx);
        let outside = tempfile::tempdir().unwrap();
        let alias = outside.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(e.revert(|_| {}).is_err());
        assert!(state.borrow().writes.is_empty());
        fs::remove_file(&alias).unwrap();
        assert_eq!(
            e.revert(|_| {}).unwrap().results[0].status,
            CheckStatus::Restored
        );
    }
}

#[cfg(unix)]
#[test]
fn append_rejects_replacement_file_even_with_matching_length() {
    let (dir, _state, mut e) = fixture(DEFENDER, json!(true));
    let mut tx = prepare(&mut e, 1, DEFENDER, json!(true));
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    let bytes = fs::read(&path).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let moved = outside.path().join("original");
    fs::rename(&path, &moved).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(e
        .append(
            &mut tx,
            Record::Applied {
                id: DEFENDER.into()
            }
        )
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read(&moved).unwrap(), bytes);
    assert!(e.storage_failed);
}

#[cfg(unix)]
#[test]
fn symlinks_and_hardlinks_are_rejected_for_lock_and_journals() {
    use std::os::unix::fs::symlink;
    let (dir, state, mut e) = fixture(DEFENDER, json!(true));
    let tx = prepare(&mut e, 1, DEFENDER, json!(true));
    let path = dir.path().join(format!("{}.jsonl", tx.name));
    drop(tx);
    let outside = tempfile::tempdir().unwrap();
    let linked = outside.path().join("linked");
    fs::hard_link(&path, &linked).unwrap();
    assert!(e.revert(|_| {}).is_err());
    fs::remove_file(&linked).unwrap();
    fs::rename(&path, &linked).unwrap();
    symlink(&linked, &path).unwrap();
    assert!(e.revert(|_| {}).is_err());
    assert!(state.borrow().writes.is_empty());
    fs::remove_file(dir.path().join(LOCK_NAME)).unwrap();
    symlink(&linked, dir.path().join(LOCK_NAME)).unwrap();
    assert!(e.history().is_err());
}

#[test]
fn skipping_a_batch_keeps_computed_outcomes_and_reports_each_control_once() {
    let ids = [DEFENDER, FIREWALL];
    let controls: Vec<Control> = ids
        .iter()
        .map(|id| Control {
            id: (*id).into(),
            title: (*id).into(),
            description: String::new(),
            target: json!(false),
            reboot: false,
        })
        .collect();
    let mut owned = vec![Engine::outcome(&controls[1], CheckStatus::Conflict, "kept")];
    let mut seen = Vec::new();
    let mut report = Report::default();
    report.skip_all(&controls, &mut owned, "why", &mut |p| {
        seen.push(format!("{}:{}", p.id, p.step.as_str()))
    });
    assert!(owned.is_empty());
    assert_eq!(
        seen,
        [
            format!("{DEFENDER}:skipped"),
            format!("{FIREWALL}:conflict")
        ]
    );
    assert_eq!(report.results[0].detail, "why");
    assert_eq!(report.results[1].detail, "kept");
}

include!("recovery_tests.rs");
include!("recover_tests.rs");
include!("hardening_tests.rs");
include!("revert_all_tests.rs");

#[test]
fn can_change_answers_without_writing_and_names_what_blocks() {
    use crate::model::{Readiness, VolumeReadiness};
    let (_dir, state, mut e) = fixture(DEFENDER, json!(true));
    e.can_change(false).unwrap();
    e.can_change(true).unwrap();
    state.borrow_mut().readiness = Readiness {
        journal_volume: Probe::Known(VolumeReadiness {
            available_bytes: 0,
            read_only: false,
        }),
        ..Default::default()
    };
    let err = e.can_change(false).unwrap_err();
    assert!(format!("{err:#}").contains("readiness blocks"));
    e.can_change(true).unwrap();
    state.borrow_mut().readiness = Readiness::default();
    e.mutation_check = Some(Box::new(|_| bail!("Deferred: updater installation")));
    assert!(e.can_change(false).is_err());
    assert!(e.can_change(true).is_err());
    e.mutation_check = None;
    prepare(&mut e, 1, DEFENDER, json!(true));
    let err = e.can_change(false).unwrap_err();
    assert!(format!("{err:#}").contains("Revert the active transaction"));
    assert!(state.borrow().writes.is_empty());
}

#[test]
fn progress_steps_keep_their_stable_text() {
    assert_eq!(ProgressStep::Pending.as_str(), "pending");
    assert_eq!(ProgressStep::Complete.as_str(), "complete");
    for status in [
        CheckStatus::Applied,
        CheckStatus::Error,
        CheckStatus::Other("x".into()),
    ] {
        assert_eq!(
            ProgressStep::Result(status.clone()).as_str(),
            status.as_str()
        );
    }
}
include!("selective_undo_tests.rs");
include!("os_tests.rs");

#[test]
fn background_judgement_uses_the_value_even_when_the_account_cannot_change_it() {
    let seen = |value: Value| Observation {
        value,
        eligible: false,
        reason: "Requested registry access is not allowed.".into(),
        ..Observation::default()
    };
    assert_eq!(
        assessment("defender.pua", &seen(json!({"items":{"PUAProtection":0}}))).unwrap(),
        CheckStatus::Attention
    );
    assert_eq!(
        assessment("defender.pua", &seen(json!({"items":{"PUAProtection":1}}))).unwrap(),
        CheckStatus::Compliant
    );
}
