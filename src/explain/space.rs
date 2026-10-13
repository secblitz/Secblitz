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
}
