//! The short list of what this version added, shown once after an update or a reinstall.
use std::path::Path;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Empty for a version with nothing worth announcing: then nothing is shown.
pub const NOTES: &[&str] = &[
    "Secblitz now runs on Linux too: Ubuntu, Linux Mint, Fedora and Debian.",
    "Updates and block lists now download over newer, safer connections.",
];

pub fn due(seen: Option<&str>, used_before: bool) -> bool {
    !NOTES.is_empty() && updated(seen, VERSION, used_before)
}

/// A fresh install has no notes to show; an older version leaves its files behind.
fn updated(seen: Option<&str>, current: &str, used_before: bool) -> bool {
    match seen {
        Some(seen) => older(seen, current),
        None => used_before,
    }
}

pub fn used_before(app_dir: &Path) -> bool {
    [
        super::history::FILE,
        super::last_check::FILE,
        super::settings::FILE,
    ]
    .iter()
    .any(|file| app_dir.join(file).exists())
}

fn older(seen: &str, current: &str) -> bool {
    match (parse(seen), parse(current)) {
        (Some(seen), Some(current)) => seen < current,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn parse(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.').map(|n| n.parse().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_once_after_an_update_or_reinstall_and_never_on_a_fresh_install() {
        assert!(!updated(None, "0.11.0", false));
        assert!(updated(None, "0.11.0", true));
        assert!(updated(Some("0.10.0"), "0.11.0", false));
        assert!(updated(Some("0.9.3"), "0.11.0", true));
        assert!(updated(Some("damaged"), "0.11.0", true));
        assert!(!updated(Some("0.11.0"), "0.11.0", true));
        assert!(!updated(Some("99.0.0"), "0.11.0", true));
        assert!(!due(Some(VERSION), true));
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(older("0.9.3", "0.10.0"));
        assert!(older("0.10.0", "0.10.1"));
        assert!(!older("0.10.0", "0.10.0"));
        assert!(!older("1.0.0", "0.11.0"));
        assert_eq!(parse("0.11"), None);
        assert_eq!(parse("0.11.0.1"), None);
        assert_eq!(parse("0.11.0"), Some((0, 11, 0)));
    }

    #[test]
    fn earlier_use_is_any_file_an_older_version_saves() {
        let dir = std::env::temp_dir().join(format!("secblitz-whats-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!used_before(&dir));
        std::fs::write(dir.join(super::super::history::FILE), b"").unwrap();
        assert!(used_before(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_note_is_translated() {
        use crate::i18n::Lang;
        for note in NOTES {
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                assert_ne!(lang.t(note), *note, "{note} in {lang:?}");
            }
        }
    }
}
