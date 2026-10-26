//! Sentences that name Windows on Windows and say the same thing in plain words on other systems.
//! The Windows sentence is the key everywhere, so Windows keeps its own wording and its translations.
use secblitz::os::Os;

pub const WORTH_A_LOOK_NOTE: &str = "You do these in Windows itself. We show the steps.";
pub const WELCOME_CHECKS: &str = "It looks at the security and privacy settings of Windows and your browsers. Checking never changes anything.";
pub const COULDNT_READ: &str = "We couldn't read this from Windows. Check again in a moment. If it keeps happening, restart your computer.";
pub const HELP_WHAT_IT_DOES: &str = "Secblitz checks the security and privacy settings of your computer and your web browsers. It shows what could be safer and fixes it when you say yes. It can also remove apps you don't want and block dangerous websites.";
pub const HELP_BRING_BACK: &str = "Open Clean up apps, then the Removed apps tab, and choose Restore next to the app. If Secblitz didn't keep a copy, it gets the app from the Microsoft Store, which needs an internet connection.";
pub const HELP_VERSIONS: &str = "Your Secblitz and Windows versions and a few settings";

/// (Windows sentence, Linux sentence, macOS sentence)
pub const ROWS: [(&str, &str, &str); 6] = [
    (
        WORTH_A_LOOK_NOTE,
        "You do these in your computer's own settings. We show what to do.",
        "You do these in your computer's own settings. We show what to do.",
    ),
    (
        WELCOME_CHECKS,
        "It looks at the security and privacy settings of your computer. Checking never changes anything.",
        "It looks at the security and privacy settings of your computer. Checking never changes anything.",
    ),
    (
        COULDNT_READ,
        "We couldn't read this from your computer. Check again in a moment. If it keeps happening, restart your computer.",
        "We couldn't read this from your computer. Check again in a moment. If it keeps happening, restart your computer.",
    ),
    (
        HELP_WHAT_IT_DOES,
        "Secblitz checks the security and privacy settings of your computer. It shows what could be safer and fixes it when you say yes. It can also remove remote-control apps you don't use.",
        "Secblitz checks the security and privacy settings of your computer. It shows what could be safer and fixes it when you say yes. It can also remove remote-control apps you don't use.",
    ),
    (
        HELP_BRING_BACK,
        "Install it again from your software app, the way you did the first time. Secblitz does not keep copies of removed apps.",
        "Install it again from the App Store or the app's own website, the way you did the first time. Secblitz does not keep copies of removed apps.",
    ),
    (
        HELP_VERSIONS,
        "Your Secblitz and Linux versions and a few settings",
        "Your Secblitz and macOS versions and a few settings",
    ),
];

/// The sentence for this system. A sentence with no row is the same everywhere.
pub fn text(os: Os, windows: &'static str) -> &'static str {
    match ROWS.iter().find(|row| row.0 == windows) {
        Some(row) => match os {
            Os::Windows => windows,
            Os::Linux => row.1,
            Os::Macos => row.2,
        },
        None => windows,
    }
}

/// The sentence for the system this build runs on.
pub fn here(windows: &'static str) -> &'static str {
    text(Os::CURRENT, windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    #[test]
    fn windows_keeps_its_own_sentences() {
        for row in ROWS {
            assert_eq!(text(Os::Windows, row.0), row.0);
        }
        assert_eq!(text(Os::Linux, "Check again"), "Check again");
    }

    #[test]
    fn other_systems_get_plain_sentences_that_never_name_windows() {
        for row in ROWS {
            for (os, line) in [(Os::Linux, row.1), (Os::Macos, row.2)] {
                assert_eq!(text(os, row.0), line);
                assert_ne!(line, row.0);
                for word in [
                    "Windows",
                    "Microsoft",
                    "BitLocker",
                    "browsers",
                    "Start menu",
                ] {
                    assert!(!line.contains(word), "{line}");
                }
                assert!(!line.contains('\u{2014}'), "{line}");
            }
        }
    }

    #[test]
    fn every_sentence_is_translated_into_every_language() {
        for row in ROWS {
            for line in [row.0, row.1, row.2] {
                for lang in ["es", "fr", "de", "pt", "it"] {
                    let lang = Lang::parse(lang).unwrap();
                    assert_ne!(lang.t(line), line, "{line} in {lang:?}");
                    assert!(!lang.t(line).contains('\u{2014}'), "{line}");
                }
            }
        }
    }
}
