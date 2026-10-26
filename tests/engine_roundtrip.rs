//! Drives the public engine end to end against an in-memory backend.
// On Windows the engine only opens its protected state folder; its unit tests cover this flow there.
#![cfg(not(windows))]
use anyhow::Result;
use secblitz::engine::{Engine, Report};
use secblitz::model::{Authority, Backend, Control, EffectiveFirewall, Finding, Observation};
use secblitz::os::Os;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::rc::Rc;

const ID: &str = "firewall.public.enabled";

struct Memory {
    value: Rc<RefCell<Value>>,
}

impl Backend for Memory {
    fn machine_id(&mut self) -> Result<String> {
        Ok("test-machine".into())
    }
    fn controls(&self) -> Vec<Control> {
        vec![Control {
            id: ID.into(),
            title: "Public firewall".into(),
            description: String::new(),
            target: json!(true),
            reboot: false,
        }]
    }
    fn observe(&mut self, id: &str) -> Result<Observation> {
        assert_eq!(id, ID);
        let value = self.value.borrow().clone();
        Ok(Observation {
            effective: Some(EffectiveFirewall::Enabled(value == json!(true))),
            authority: Some(Authority::Local),
            value,
            eligible: true,
            reason: "Eligible".into(),
            ..Observation::default()
        })
    }
    fn write(&mut self, _id: &str, value: &Value) -> Result<()> {
        *self.value.borrow_mut() = value.clone();
        Ok(())
    }
    fn findings(&mut self) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }
}

fn open(dir: &std::path::Path, value: &Rc<RefCell<Value>>) -> Engine {
    let backend = Memory {
        value: value.clone(),
    };
    Engine::open_for(Os::Windows, dir.to_path_buf(), Box::new(backend)).unwrap()
}

fn status_of(report: &Report) -> &str {
    report.results[0].status.as_str()
}

#[test]
fn a_fix_is_applied_verified_and_undone() {
    let dir = tempfile::tempdir().unwrap();
    let value = Rc::new(RefCell::new(json!(false)));
    let mut engine = open(dir.path(), &value);
    assert_eq!(engine.available_controls().len(), 1);

    assert_eq!(status_of(&engine.audit().unwrap()), "attention");
    assert_eq!(*value.borrow(), json!(false), "an audit never writes");

    engine.apply_selected(&[ID.to_owned()], |_| {}).unwrap();
    assert_eq!(*value.borrow(), json!(true));
    assert_eq!(status_of(&engine.audit().unwrap()), "compliant");
    assert_eq!(engine.undoable_changes().unwrap(), 1);

    engine.revert(|_| {}).unwrap();
    assert_eq!(*value.borrow(), json!(false));
    assert_eq!(status_of(&engine.audit().unwrap()), "attention");
}

#[test]
fn saved_changes_survive_reopening_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let value = Rc::new(RefCell::new(json!(false)));
    open(dir.path(), &value)
        .apply_selected(&[ID.to_owned()], |_| {})
        .unwrap();

    let mut reopened = open(dir.path(), &value);
    assert_eq!(reopened.undoable_changes().unwrap(), 1);
    assert!(!reopened.history().unwrap().is_empty());
    reopened.revert(|_| {}).unwrap();
    assert_eq!(*value.borrow(), json!(false));
}

#[test]
fn selecting_an_unknown_control_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let value = Rc::new(RefCell::new(json!(false)));
    let mut engine = open(dir.path(), &value);
    assert!(engine
        .apply_selected(&["no.such.control".to_owned()], |_| {})
        .is_err());
    assert_eq!(*value.borrow(), json!(false));
}

#[test]
fn a_report_survives_a_json_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let value = Rc::new(RefCell::new(json!(false)));
    let report = open(dir.path(), &value).audit().unwrap();

    let text = serde_json::to_string(&report).unwrap();
    let back: Report = serde_json::from_str(&text).unwrap();
    assert_eq!(back.results.len(), report.results.len());
    assert_eq!(back.results[0].id, ID);
    assert_eq!(back.results[0].status, report.results[0].status);
    assert_eq!(back.results[0].authority, Some(Authority::Local));
    assert_eq!(
        serde_json::to_string(&back).unwrap(),
        text,
        "serialising again gives the same document"
    );
}

#[test]
fn a_report_without_optional_fields_still_loads() {
    let report: Report = serde_json::from_str(
        r#"{"transaction":null,"results":[{"id":"a","title":"A","status":"ok","detail":""}],"findings":[]}"#,
    )
    .unwrap();
    assert_eq!(report.results[0].effective, None);
    assert!(report.results[0].items.is_empty());
    assert!(report.readiness.is_none());
}
