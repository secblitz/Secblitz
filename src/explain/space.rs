//! Leftover files that Windows and apps keep, which Free up space removes.
use super::Explainer;

pub(super) fn get(id: &str) -> Option<Explainer> {
    Some(match id {
        "space.temp" => Explainer {
            what: "Apps and installers keep working files here and often forget to remove them.",
            risk: "Old ones only take up space.",
            change: "Files older than a week that nothing is using are deleted for good. No app needs them.",
        },
        "space.update_leftovers" => Explainer {
            what: "Windows keeps older copies of system files for a while after updating.",
            risk: "They only take up space.",
            change: "Secblitz asks Windows to tidy them. An update that causes trouble can still be uninstalled. This can take several minutes and can't be undone.",
        },
        "space.crash_dumps" => Explainer {
            what: "When Windows or an app crashes, it can save a copy of what was in memory.",
            risk: "That copy can include passwords or parts of open documents.",
            change: "Files older than two weeks are deleted for good. Newer ones stay in case you need to report a crash.",
        },
        "space.thumbnails" => Explainer {
            what: "Windows saves small previews of your pictures so folders open faster.",
            risk: "These previews can stay after you delete the pictures.",
            change: "Windows makes new previews as you browse. This can't be undone.",
        },
        "space.package_caches" => Explainer {
            what: "When you install or update programs, your computer keeps the files it downloaded.",
            risk: "They only take up space. Your computer can download them again whenever it needs them.",
            change: "The saved downloads are deleted. Nothing installed is touched. This can't be undone, and nothing is lost.",
        },
        "space.crash_reports" => Explainer {
            what: "When a program crashes, your computer can save a report of what the program was doing.",
            risk: "A report can include parts of your documents or passwords, and it can keep a crash warning coming back.",
            change: "Reports older than a week are deleted for good. Newer ones stay in case you need to share them.",
        },
        "space.thumbnail_cache" => Explainer {
            what: "Your computer saves small previews of your pictures so folders open faster.",
            risk: "These previews can stay after you delete the pictures.",
            change: "Your computer makes new previews as you browse. This can't be undone.",
        },
        "space.flatpak_runtimes" => Explainer {
            what: "Some apps need shared parts to run. After those apps are removed, the parts can stay on the disk.",
            risk: "They only take up space, sometimes a lot.",
            change: "Parts that no app uses are removed. If a new app needs one later, it is downloaded again.",
        },
        "space.trash" => Explainer {
            what: "Files you delete usually wait in the Trash until you empty it.",
            risk: "They keep using space, and anyone who can use your account can still open them.",
            change: "Everything in the Trash is deleted for good. This can't be undone.",
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_item_is_explained_in_short_sentences() {
        for item in crate::space::Item::ALL {
            let e = get(item.id()).unwrap_or_else(|| panic!("{}", item.id()));
            for (label, line) in [("what", e.what), ("risk", e.risk), ("change", e.change)] {
                super::super::tests::assert_short_sentence(item.id(), label, line);
            }
        }
        assert!(get("space.nope").is_none());
    }

    #[test]
    fn every_linux_item_is_explained_in_short_sentences() {
        for item in crate::space::Item::LINUX {
            let e = get(item.id()).unwrap_or_else(|| panic!("{}", item.id()));
            for (label, line) in [("what", e.what), ("risk", e.risk), ("change", e.change)] {
                super::super::tests::assert_short_sentence(item.id(), label, line);
            }
        }
    }
}
