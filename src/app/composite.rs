//! One session over two: the root helper for system settings and the person's own engine for desktop settings. The
//! window sees a single `Session`; each id goes to the half that owns it in the Linux catalog.

use super::worker::Session;
use anyhow::{bail, Result};
use secblitz::engine::{ItemChoice, Outcome, Progress, Report};
use secblitz::linux::catalog::{self, Scope};
use secblitz::model::CheckStatus;

pub struct Composite {
    pub system: Box<dyn Session>,
    pub person: Box<dyn Session>,
}

type Part = Option<(Vec<String>, Result<Report>)>;

/// Splits ids by the half that owns them. An id that belongs to neither refuses the whole request, before anything runs.
fn split(ids: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let (mut system, mut person) = (Vec::new(), Vec::new());
    for id in ids {
        match catalog::spec(id).map(|s| s.scope) {
            Some(Scope::System) => system.push(id.clone()),
            Some(Scope::Person) => person.push(id.clone()),
            None => bail!("Unknown control id: {id}"),
        }
    }
    Ok((system, person))
}

fn failed(id: &str, error: &anyhow::Error) -> Outcome {
    Outcome {
        id: id.to_owned(),
        title: id.to_owned(),
        status: CheckStatus::Error,
        detail: format!("{error:#}"),
        ..Outcome::default()
    }
}

/// The settings an undo that failed left waiting, read from a fresh check of that half. Only when that check fails too
/// is every setting of the half named.
fn left_to_undo(session: &mut dyn Session, result: &Result<Report>) -> Vec<String> {
    if result.is_ok() {
        return Vec::new();
    }
    match session.audit(&mut |_| {}) {
        Ok(report) => report.undo_next,
        Err(_) => session.available(),
    }
}

/// System results first. A half that failed is reported as an error on each of its ids, so the other half's results
/// still show; only when every half that ran failed is the first error returned.
fn join(parts: [Part; 2]) -> Result<Report> {
    let mut report = Report::default();
    let mut first_error = None;
    let mut succeeded = false;
    for (ids, result) in parts.into_iter().flatten() {
        match result {
            Ok(part) => {
                succeeded = true;
                report.transaction = report.transaction.take().or(part.transaction);
                report.results.extend(part.results);
                report.findings.extend(part.findings);
                report.readiness = report.readiness.take().or(part.readiness);
                report.undo_next.extend(part.undo_next);
            }
            Err(error) => {
                report
                    .results
                    .extend(ids.iter().map(|id| failed(id, &error)));
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) if !succeeded => Err(error),
        _ => Ok(report),
    }
}

impl Session for Composite {
    fn available(&self) -> Vec<String> {
        let mut ids = self.system.available();
        ids.extend(self.person.available());
        ids
    }

    fn restart_ids(&self) -> Vec<String> {
        let mut ids = self.system.restart_ids();
        ids.extend(self.person.restart_ids());
        ids
    }

    fn audit(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> Result<Report> {
        let mut part = |session: &mut dyn Session| -> Part {
            let ids = session.available();
            (!ids.is_empty()).then(|| (ids, session.audit(&mut *progress)))
        };
        let system = part(self.system.as_mut());
        let person = part(self.person.as_mut());
        join([system, person])
    }

    fn apply(&mut self, ids: &[String], progress: &mut dyn FnMut(Progress<'_>)) -> Result<Report> {
        let (system_ids, person_ids) = split(ids)?;
        let system = (!system_ids.is_empty()).then(|| {
            let result = self.system.apply(&system_ids, &mut *progress);
            (system_ids, result)
        });
        let person = (!person_ids.is_empty()).then(|| {
            let result = self.person.apply(&person_ids, &mut *progress);
            (person_ids, result)
        });
        join([system, person])
    }

    fn undo(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> Result<Report> {
        let person = self.person.undo(&mut *progress);
        let person_ids = left_to_undo(self.person.as_mut(), &person);
        let system = self.system.undo(&mut *progress);
        let system_ids = left_to_undo(self.system.as_mut(), &system);
        join([Some((system_ids, system)), Some((person_ids, person))])
    }

    fn undo_selected(
        &mut self,
        ids: &[String],
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> Result<Report> {
        let (system_ids, person_ids) = split(ids)?;
        let person = (!person_ids.is_empty()).then(|| {
            let result = self.person.undo_selected(&person_ids, &mut *progress);
            (person_ids, result)
        });
        let system = (!system_ids.is_empty()).then(|| {
            let result = self.system.undo_selected(&system_ids, &mut *progress);
            (system_ids, result)
        });
        join([system, person])
    }

    /// The two journals keep no common clock, so the system's entries come first, then the person's.
    fn history(&mut self) -> Result<Vec<String>> {
        let mut lines = self.system.history()?;
        lines.extend(self.person.history()?);
        Ok(lines)
    }

    fn can_start(&mut self, undo: bool) -> Result<()> {
        self.system.can_start(undo)?;
        self.person.can_start(undo)
    }

    fn choose_items(&mut self, picked: ItemChoice) -> Result<()> {
        let ids: Vec<String> = picked.keys().cloned().collect();
        split(&ids)?;
        let (mut system, mut person) = (ItemChoice::new(), ItemChoice::new());
        for (id, items) in picked {
            let half = match catalog::spec(&id).map(|s| s.scope) {
                Some(Scope::Person) => &mut person,
                _ => &mut system,
            };
            half.insert(id, items);
        }
        self.system.choose_items(system)?;
        self.person.choose_items(person)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use secblitz::engine::ProgressStep;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Log(RefCell<Vec<String>>);

    struct Half {
        name: &'static str,
        ids: Vec<&'static str>,
        fail: bool,
        log: Rc<Log>,
        undo_next: Vec<String>,
        undo_breaks: bool,
    }

    impl Half {
        fn note(&self, what: &str) {
            self.log
                .0
                .borrow_mut()
                .push(format!("{} {what}", self.name));
        }

        fn report(&self, ids: &[String]) -> Result<Report> {
            if self.fail {
                return Err(anyhow!("{} is broken", self.name));
            }
            Ok(Report {
                transaction: Some(format!("{}-tx", self.name)),
                results: ids
                    .iter()
                    .map(|id| Outcome {
                        id: id.clone(),
                        title: id.clone(),
                        status: CheckStatus::Applied,
                        ..Outcome::default()
                    })
                    .collect(),
                undo_next: self.undo_next.clone(),
                ..Report::default()
            })
        }
    }

    impl Session for Half {
        fn available(&self) -> Vec<String> {
            self.ids.iter().map(|s| s.to_string()).collect()
        }
        fn restart_ids(&self) -> Vec<String> {
            self.ids.iter().take(1).map(|s| s.to_string()).collect()
        }
        fn audit(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> Result<Report> {
            self.note("audit");
            progress(Progress::new(self.ids[0], ProgressStep::Pending));
            self.report(&self.available())
        }
        fn apply(&mut self, ids: &[String], _: &mut dyn FnMut(Progress<'_>)) -> Result<Report> {
            self.note(&format!("apply {}", ids.join(",")));
            self.report(ids)
        }
        fn undo(&mut self, _: &mut dyn FnMut(Progress<'_>)) -> Result<Report> {
            self.note("undo");
            if self.undo_breaks {
                bail!("{} stopped halfway", self.name);
            }
            self.report(&self.available())
        }
        fn undo_selected(
            &mut self,
            ids: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> Result<Report> {
            self.note(&format!("undo {}", ids.join(",")));
            self.report(ids)
        }
        fn history(&mut self) -> Result<Vec<String>> {
            Ok(vec![format!("{} applied", self.name)])
        }
        fn can_start(&mut self, _: bool) -> Result<()> {
            self.note("can_start");
            if self.fail {
                bail!("{} cannot start", self.name)
            }
            Ok(())
        }
        fn choose_items(&mut self, picked: ItemChoice) -> Result<()> {
            self.note(&format!("choose {}", picked.len()));
            Ok(())
        }
    }

    fn composite(system_fails: bool, person_fails: bool) -> (Composite, Rc<Log>) {
        let log = Rc::new(Log::default());
        let half = |name, ids, fail, undo_next: &[&str]| -> Box<dyn Session> {
            Box::new(Half {
                name,
                ids,
                fail,
                log: Rc::clone(&log),
                undo_next: undo_next.iter().map(|s| s.to_string()).collect(),
                undo_breaks: false,
            })
        };
        (
            Composite {
                system: half(
                    "system",
                    vec!["linux.firewall", "linux.guest"],
                    system_fails,
                    &["linux.firewall"],
                ),
                person: half(
                    "person",
                    vec!["linux.screen_lock", "linux.recent_files"],
                    person_fails,
                    &["linux.screen_lock"],
                ),
            },
            log,
        )
    }

    fn ids(report: &Report) -> Vec<(&str, &str)> {
        report
            .results
            .iter()
            .map(|r| (r.id.as_str(), r.status.as_str()))
            .collect()
    }

    fn strings(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_catalog_is_the_union_of_both_halves() {
        let (c, _) = composite(false, false);
        assert_eq!(
            c.available(),
            [
                "linux.firewall",
                "linux.guest",
                "linux.screen_lock",
                "linux.recent_files"
            ]
        );
        assert_eq!(c.restart_ids(), ["linux.firewall", "linux.screen_lock"]);
    }

    #[test]
    fn a_check_runs_both_halves_and_lists_the_system_first() {
        let (mut c, log) = composite(false, false);
        let mut seen = Vec::new();
        let report = c.audit(&mut |p| seen.push(p.id.to_owned())).unwrap();
        assert_eq!(
            ids(&report),
            [
                ("linux.firewall", "applied"),
                ("linux.guest", "applied"),
                ("linux.screen_lock", "applied"),
                ("linux.recent_files", "applied")
            ]
        );
        assert_eq!(seen, ["linux.firewall", "linux.screen_lock"]);
        assert_eq!(*log.0.borrow(), ["system audit", "person audit"]);
        assert_eq!(report.transaction.as_deref(), Some("system-tx"));
        assert_eq!(report.undo_next, ["linux.firewall", "linux.screen_lock"]);
    }

    #[test]
    fn a_fix_goes_to_the_half_that_owns_each_id() {
        let (mut c, log) = composite(false, false);
        let report = c
            .apply(
                &strings(&["linux.screen_lock", "linux.guest", "linux.firewall"]),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(
            ids(&report),
            [
                ("linux.guest", "applied"),
                ("linux.firewall", "applied"),
                ("linux.screen_lock", "applied")
            ]
        );
        assert_eq!(
            *log.0.borrow(),
            [
                "system apply linux.guest,linux.firewall",
                "person apply linux.screen_lock"
            ]
        );
    }

    #[test]
    fn a_half_with_nothing_to_do_is_not_called() {
        let (mut c, log) = composite(false, false);
        c.apply(&strings(&["linux.screen_lock"]), &mut |_| {})
            .unwrap();
        c.undo_selected(&strings(&["linux.guest"]), &mut |_| {})
            .unwrap();
        assert_eq!(
            *log.0.borrow(),
            ["person apply linux.screen_lock", "system undo linux.guest"]
        );
    }

    #[test]
    fn an_id_from_neither_half_refuses_the_whole_request() {
        let (mut c, log) = composite(false, false);
        for bad in ["uac.enabled", "linux.nope", ""] {
            let ids = strings(&["linux.firewall", bad]);
            assert!(c.apply(&ids, &mut |_| {}).is_err(), "{bad}");
            assert!(c.undo_selected(&ids, &mut |_| {}).is_err(), "{bad}");
            let mut picked = ItemChoice::new();
            picked.insert(bad.to_owned(), vec![]);
            assert!(c.choose_items(picked).is_err(), "{bad}");
        }
        assert!(log.0.borrow().is_empty());
    }

    #[test]
    fn undo_puts_the_person_back_before_the_system() {
        let (mut c, log) = composite(false, false);
        let report = c.undo(&mut |_| {}).unwrap();
        assert_eq!(*log.0.borrow(), ["person undo", "system undo"]);
        assert_eq!(report.results.len(), 4);
        assert_eq!(report.results[0].id, "linux.firewall");
    }

    #[test]
    fn an_undo_that_stops_halfway_names_only_what_is_still_waiting_to_be_put_back() {
        let log = Rc::new(Log::default());
        let mut c = Composite {
            system: Box::new(Half {
                name: "system",
                ids: vec!["linux.firewall", "linux.guest", "linux.llmnr"],
                fail: false,
                log: Rc::clone(&log),
                undo_next: vec!["linux.llmnr".into()],
                undo_breaks: true,
            }),
            person: Box::new(Half {
                name: "person",
                ids: vec!["linux.screen_lock"],
                fail: false,
                log: Rc::clone(&log),
                undo_next: Vec::new(),
                undo_breaks: false,
            }),
        };
        let report = c.undo(&mut |_| {}).unwrap();
        assert_eq!(
            ids(&report),
            [("linux.llmnr", "error"), ("linux.screen_lock", "applied")]
        );
        assert_eq!(report.results[0].detail, "system stopped halfway");
    }

    #[test]
    fn one_half_failing_is_shown_on_its_own_ids_and_keeps_the_other_halfs_results() {
        let (mut c, _) = composite(true, false);
        let report = c.audit(&mut |_| {}).unwrap();
        assert_eq!(
            ids(&report),
            [
                ("linux.firewall", "error"),
                ("linux.guest", "error"),
                ("linux.screen_lock", "applied"),
                ("linux.recent_files", "applied")
            ]
        );
        assert_eq!(report.results[0].detail, "system is broken");
        assert_eq!(report.transaction.as_deref(), Some("person-tx"));

        let (mut c, _) = composite(false, true);
        let report = c
            .apply(
                &strings(&["linux.firewall", "linux.recent_files"]),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(
            ids(&report),
            [
                ("linux.firewall", "applied"),
                ("linux.recent_files", "error")
            ]
        );
    }

    #[test]
    fn when_every_half_that_ran_fails_the_first_error_is_returned() {
        let (mut c, _) = composite(true, true);
        let error = c.audit(&mut |_| {}).unwrap_err();
        assert_eq!(format!("{error}"), "system is broken");
        let (mut c, _) = composite(false, true);
        let error = c
            .apply(&strings(&["linux.screen_lock"]), &mut |_| {})
            .unwrap_err();
        assert_eq!(format!("{error}"), "person is broken");
    }

    #[test]
    fn starting_needs_both_halves_and_history_lists_both() {
        let (mut c, log) = composite(false, false);
        c.can_start(false).unwrap();
        assert_eq!(*log.0.borrow(), ["system can_start", "person can_start"]);
        assert_eq!(c.history().unwrap(), ["system applied", "person applied"]);
        let (mut c, log) = composite(true, false);
        assert!(c.can_start(true).is_err());
        assert_eq!(*log.0.borrow(), ["system can_start"]);
        let (mut c, _) = composite(false, true);
        assert!(c.can_start(true).is_err());
    }

    #[test]
    fn picked_items_go_to_the_half_that_owns_the_control() {
        let (mut c, log) = composite(false, false);
        let mut picked = ItemChoice::new();
        picked.insert("linux.screen_lock".into(), vec!["a".into()]);
        c.choose_items(picked).unwrap();
        assert_eq!(*log.0.borrow(), ["system choose 0", "person choose 1"]);
    }
}
