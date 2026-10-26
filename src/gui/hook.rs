//! A test hook for the machines that drive the window from outside, since the toolkit offers no accessibility tree.
//! When `SECBLITZ_TEST_HOOK` names a file, the current page and the last report are written there as JSON after each
//! update that changes them. Only debug builds and builds with the `test-hook` feature ever read the variable.
use super::Page;
use secblitz::engine::Report;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

pub const ENABLED: bool = cfg!(any(debug_assertions, feature = "test-hook"));
const VARIABLE: &str = "SECBLITZ_TEST_HOOK";

/// The file to write, from the variable's value. Nothing when the hook is not built in or the value is empty.
fn path_from(enabled: bool, value: Option<OsString>) -> Option<PathBuf> {
    value
        .filter(|v| enabled && !v.is_empty())
        .map(PathBuf::from)
}

fn page_id(page: Page) -> &'static str {
    match page {
        Page::Home => "home",
        Page::Fixes => "fixes",
        Page::Debloat => "debloat",
        Page::Web => "web",
        Page::Tools => "tools",
        Page::History => "history",
        Page::Settings => "settings",
    }
}

fn snapshot(page: Page, checking: bool, report: Option<&Report>) -> serde_json::Value {
    serde_json::json!({ "page": page_id(page), "checking": checking, "report": report })
}

#[derive(Default)]
pub struct Hook {
    path: Option<PathBuf>,
    last: Option<(Page, bool, usize)>,
}

impl Hook {
    pub fn from_env() -> Self {
        let value = if ENABLED {
            std::env::var_os(VARIABLE)
        } else {
            None
        };
        Self {
            path: path_from(ENABLED, value),
            last: None,
        }
    }

    pub fn after_update(&mut self, page: Page, checking: bool, report: Option<&Arc<Report>>) {
        let Some(path) = &self.path else {
            return;
        };
        let key = (
            page,
            checking,
            report.map_or(0, |r| Arc::as_ptr(r) as usize),
        );
        if self.last == Some(key) {
            return;
        }
        let bytes = match serde_json::to_vec(&snapshot(page, checking, report.map(|r| &**r))) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("The test hook could not write the page: {error}");
                return;
            }
        };
        let mut part = path.clone().into_os_string();
        part.push(".part");
        let part = PathBuf::from(part);
        match std::fs::write(&part, bytes).and_then(|()| std::fs::rename(&part, path)) {
            Ok(()) => self.last = Some(key),
            Err(error) => eprintln!("The test hook could not write {}: {error}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_is_ignored_unless_the_hook_is_built_in() {
        let value = Some(OsString::from("/tmp/page.json"));
        assert_eq!(path_from(false, value.clone()), None);
        assert_eq!(
            path_from(true, value),
            Some(PathBuf::from("/tmp/page.json"))
        );
        assert_eq!(path_from(true, Some(OsString::new())), None);
        assert_eq!(path_from(true, None), None);
    }

    #[test]
    fn the_page_and_report_are_written_once_per_change() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("page.json");
        let mut hook = Hook {
            path: Some(file.clone()),
            last: None,
        };
        let read = || -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap()
        };

        hook.after_update(Page::Home, true, None);
        let first = read();
        assert_eq!(first["page"], "home");
        assert_eq!(first["checking"], true);
        assert!(first["report"].is_null());

        let report = Arc::new(Report {
            transaction: Some("tx".into()),
            ..Report::default()
        });
        hook.after_update(Page::Fixes, false, Some(&report));
        let second = read();
        assert_eq!(second["page"], "fixes");
        assert_eq!(second["report"]["transaction"], "tx");

        std::fs::remove_file(&file).unwrap();
        hook.after_update(Page::Fixes, false, Some(&report));
        assert!(!file.exists(), "nothing changed, so nothing is written");
        assert!(!dir.path().join("page.json.part").exists());
    }

    #[test]
    fn a_hook_with_no_file_writes_nothing() {
        let mut hook = Hook::default();
        hook.after_update(Page::Home, false, None);
        assert!(hook.last.is_none());
    }

    #[test]
    fn every_page_has_its_own_id_that_the_window_also_accepts() {
        for page in Page::ALL {
            assert_eq!(Page::parse(page_id(page)), Some(page));
        }
    }
}
