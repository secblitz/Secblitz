//! Source-keyed translations.

mod checks;
mod engine_advice;
mod engine_errors;
mod engine_permissions;
mod engine_status;
mod fixes;
mod guided;
mod interface;
mod italian;
mod linux;
mod linux_browsers;
mod linux_cleanup;
mod linux_feeds;
mod linux_findings;
mod linux_network;
mod linux_person;
mod linux_services;
mod linux_space;
mod linux_updates;
mod maintenance;
mod results;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Es,
    Fr,
    De,
    Pt,
    It,
}

impl Lang {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "en" => Self::En,
            "es" => Self::Es,
            "fr" => Self::Fr,
            "de" => Self::De,
            "pt" => Self::Pt,
            "it" => Self::It,
            _ => return None,
        })
    }
    pub fn code(self) -> &'static str {
        ["en", "es", "fr", "de", "pt", "it"][self as usize]
    }
    pub fn detect() -> Self {
        #[cfg(windows)]
        {
            #[link(name = "kernel32")]
            extern "system" {
                fn GetUserDefaultUILanguage() -> u16;
            }
            Self::from_windows_language(unsafe { GetUserDefaultUILanguage() })
        }
        #[cfg(not(windows))]
        {
            Self::En
        }
    }
    #[cfg(any(windows, test))]
    fn from_windows_language(id: u16) -> Self {
        match id & 0x3ff {
            0x0a => Self::Es,
            0x0c => Self::Fr,
            0x07 => Self::De,
            0x16 => Self::Pt,
            0x10 => Self::It,
            _ => Self::En,
        }
    }
    pub fn t(self, source: &str) -> String {
        if let Some(row) = maintenance_rows().find(|row| row[0] == source) {
            return row[self as usize].to_owned();
        }
        text_rows()
            .find(|row| row[0] == source)
            .map_or_else(|| source.to_owned(), |row| self.translation(row).to_owned())
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn detail(self, source: &str) -> String {
        if maintenance_rows().any(|row| row[0] == source) {
            return self.t(source);
        }
        if self == Self::En {
            return source.to_owned();
        }
        if DETAIL_EXACT_ONLY.contains(&source) {
            return self.t(source);
        }
        let mut remaining = source;
        let mut out = String::new();
        while !remaining.is_empty() {
            let offset = source.len() - remaining.len();
            let previous = source[..offset].chars().next_back();
            if let Some(row) = text_rows()
                .filter(|r| {
                    if DETAIL_EXACT_ONLY.contains(&r[0]) || !remaining.starts_with(r[0]) {
                        return false;
                    }
                    let word =
                        |c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | '/' | '\\' | '-');
                    !(r[0].chars().next().is_some_and(word) && previous.is_some_and(word)
                        || r[0].chars().next_back().is_some_and(word)
                            && remaining[r[0].len()..].chars().next().is_some_and(word))
                })
                .max_by_key(|r| r[0].len())
            {
                out.push_str(self.translation(row));
                remaining = &remaining[row[0].len()..];
            } else {
                let ch = remaining.chars().next().unwrap();
                out.push(ch);
                remaining = &remaining[ch.len_utf8()..];
            }
        }
        out
    }
    pub fn control(self, id: &str) -> String {
        let source = secblitz::advice::control_label(id);
        if source == "Protection check" {
            return id.to_owned();
        }
        self.t(source)
    }

    fn translation(self, row: &[&'static str; 5]) -> &'static str {
        if self == Self::It {
            italian::ROWS
                .iter()
                .find(|entry| entry[0] == row[0])
                .map_or(row[0], |entry| entry[1])
        } else {
            row[self as usize]
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
const DETAIL_EXACT_ONLY: &[&str] = &["all", "none", "complete", "opened", "returned", "running"];

const MAINTENANCE_PARTS: &[&[[&str; 6]]] = &[
    maintenance::ROWS,
    interface::ROWS,
    checks::ROWS,
    fixes::ROWS,
    results::ROWS,
    guided::ROWS,
    linux::ROWS,
    linux_updates::ROWS,
    linux_cleanup::ROWS,
    linux_network::ROWS,
    linux_services::ROWS,
    linux_person::ROWS,
    linux_browsers::ROWS,
    linux_findings::ROWS,
    linux_space::ROWS,
    linux_feeds::ROWS,
];

const TEXT_PARTS: &[&[[&str; 5]]] = &[
    engine_status::ROWS,
    engine_permissions::ROWS,
    engine_errors::ROWS,
    engine_advice::ROWS,
];

fn maintenance_rows() -> impl Iterator<Item = &'static [&'static str; 6]> + Clone {
    MAINTENANCE_PARTS.iter().flat_map(|part| part.iter())
}

fn text_rows() -> impl Iterator<Item = &'static [&'static str; 5]> + Clone {
    TEXT_PARTS.iter().flat_map(|part| part.iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_keys() -> impl Iterator<Item = &'static str> {
        text_rows()
            .map(|r| r[0])
            .chain(maintenance_rows().map(|r| r[0]))
    }

    #[test]
    fn maintenance_catalog_covers_all_six_locales_without_ambiguous_keys() {
        let mut keys: std::collections::HashSet<_> = text_rows().map(|r| r[0]).collect();
        for row in maintenance_rows() {
            assert!(keys.insert(row[0]), "duplicate maintenance key: {}", row[0]);
            for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                assert!(!row[lang as usize].is_empty());
                assert!(lang == Lang::En || !row[lang as usize].contains('\u{2014}'));
                assert_eq!(lang.t(row[0]), row[lang as usize]);
                assert_eq!(lang.detail(row[0]), row[lang as usize]);
            }
        }
    }

    #[test]
    fn the_linux_clean_up_texts_are_translated() {
        for key in [
            "Downloaded install files",
            "Old crash reports",
            "Unused app parts",
            "Trash",
            "Remote control apps",
            "Your computer will ask for your password first.",
            "You can install it again later from your software app. That needs the internet.",
        ] {
            assert!(
                maintenance_rows().any(|r| r[0] == key) || text_rows().any(|r| r[0] == key),
                "missing translations for {key}"
            );
            assert_ne!(Lang::Es.t(key), key, "{key}");
            assert_ne!(Lang::De.t(key), key, "{key}");
        }
    }

    const GUI_FIRST_KEY: &str = "1 important update is ready to install.";

    fn placeholders(s: &str) -> Vec<&str> {
        let mut found: Vec<&str> = s
            .match_indices('{')
            .filter_map(|(i, _)| s[i..].find('}').map(|end| &s[i..=i + end]))
            .collect();
        found.sort_unstable();
        found
    }

    #[test]
    fn every_gui_key_has_all_five_translations() {
        let gui: Vec<_> = maintenance_rows()
            .skip_while(|row| row[0] != GUI_FIRST_KEY)
            .collect();
        assert!(gui.len() > 400, "GUI catalog unexpectedly small");
        for row in gui {
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                let text = row[lang as usize];
                assert!(!text.trim().is_empty(), "{:?} empty for {:?}", lang, row[0]);
                assert!(!text.contains('\u{2014}'), "em dash in {:?}", text);
                assert_eq!(
                    placeholders(text),
                    placeholders(row[0]),
                    "placeholders differ for {:?} in {:?}",
                    row[0],
                    lang
                );
            }
        }
    }

    /// Rust sources under `src/` for the given files or folders, test files excluded.
    fn rust_sources(roots: &[&str]) -> Vec<(String, String)> {
        fn walk(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            if path.is_dir() {
                let mut entries: Vec<_> = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                entries.sort();
                for entry in entries {
                    walk(&entry, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path.to_path_buf());
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        for root in roots {
            let path = src.join(root);
            assert!(path.exists(), "missing source {root}");
            walk(&path, &mut files);
        }
        files
            .into_iter()
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name != "tests.rs" && !name.ends_with("_tests.rs") && name != "testing.rs"
            })
            .map(|path| {
                let name = path
                    .strip_prefix(&src)
                    .unwrap()
                    .display()
                    .to_string()
                    .replace('\\', "/");
                (name, std::fs::read_to_string(&path).unwrap())
            })
            .collect()
    }

    #[test]
    fn literal_gui_keys_are_in_the_catalog() {
        let sources = rust_sources(&["gui", "tray"]);
        const UNTRANSLATED: &[&str] = &["Secblitz"];
        let known: std::collections::HashSet<_> = all_keys().collect();
        let mut missing = Vec::new();
        for (file, text) in &sources {
            let code = text.split("#[cfg(test)]").next().unwrap_or(text);
            let mut rest = code;
            while let Some(i) = rest.find(".t(\"") {
                rest = &rest[i + 4..];
                let mut end = 0;
                let bytes = rest.as_bytes();
                while end < bytes.len() && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let key = rest[..end.min(rest.len())].replace("\\'", "'");
                if !known.contains(key.as_str()) && !UNTRANSLATED.contains(&key.as_str()) {
                    missing.push(format!("{file}: {key}"));
                }
            }
        }
        assert!(missing.is_empty(), "untranslated GUI keys: {missing:#?}");
    }

    #[test]
    fn every_app_name_and_note_in_the_catalog_is_translated() {
        let known: std::collections::HashSet<_> = all_keys().collect();
        let mut missing = Vec::new();
        for app in secblitz::debloat::catalog() {
            let added_later = secblitz::debloat::catalog()
                .iter()
                .position(|a| a.family == app.family)
                .is_some_and(|i| i >= 56 || app.family == "Microsoft.MicrosoftOfficeHub");
            if added_later && !known.contains(app.name) {
                missing.push(app.name);
            }
            if let Some(note) = secblitz::debloat::note(app.family) {
                if !known.contains(note) {
                    missing.push(note);
                }
            }
        }
        assert!(missing.is_empty(), "untranslated apps: {missing:#?}");
    }

    #[test]
    fn every_linux_and_macos_check_is_explained_and_translated() {
        let known: std::collections::HashSet<_> = all_keys().collect();
        for os in [secblitz::os::Os::Linux, secblitz::os::Os::Macos] {
            for id in secblitz::engine::catalog::ids(os) {
                let e = secblitz::explain::for_check(id)
                    .unwrap_or_else(|| panic!("{id} has no explainer"));
                for line in [e.what, e.risk, e.change] {
                    assert!(known.contains(line), "{id}: not translated: {line}");
                }
            }
        }
    }

    #[test]
    fn the_system_topic_name_is_translated() {
        let row = maintenance_rows()
            .find(|r| r[0] == "System")
            .expect("System row");
        assert!(row.iter().all(|t| !t.is_empty()));
    }

    #[test]
    fn the_ads_and_tips_switches_are_translated_in_all_six_languages() {
        let known: std::collections::HashSet<_> = all_keys().collect();
        for setting in secblitz::user_settings::Setting::ADS_AND_TIPS {
            let e = secblitz::explain::for_check(setting.id()).expect("explainer");
            for line in [e.what, e.risk, e.change] {
                assert!(known.contains(line), "{line}");
            }
            assert!(known.contains(crate::uninstall::personal_title(setting.id())));
        }
    }

    #[test]
    fn permission_evidence_and_identifiers_survive_all_languages() {
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for control in secblitz::permissions::controls() {
                assert_ne!(lang.control(&control.id), control.id);
                assert_eq!(
                    lang.control(&control.id),
                    lang.t(secblitz::advice::control_label(&control.id))
                );
            }
            for name in [
                "BITS",
                "wuauserv",
                "WinDefend",
                "Schedule",
                "SecblitzMonitor",
            ] {
                assert_eq!(
                    lang.detail(&format!("Service permissions: {name}")),
                    format!("{}{name}", lang.t("Service permissions: "))
                );
            }
            let evidence = "S-1-5-32-545: ALLOW mask 0x000d0002, risky bits 0x000d0002";
            let detail = lang.detail(&format!("Candidate dangerous broad-principal grants: {evidence}. This is an ACE scan, not effective access or proof of exploitability. Consult the fixed service repair control for gated eligibility."));
            for raw in ["S-1-5-32-545", "0x000d0002"] {
                assert!(detail.contains(raw));
            }
            assert!(detail.contains(&lang.t("ALLOW mask")));
            assert!(detail.contains(&lang.t("risky bits")));
            let native = "Access is denied (os error 5)";
            let rendered = lang.detail(&format!("Service permissions preserved: {native}"));
            assert!(rendered.starts_with(&lang.t("Service permissions preserved: ")));
            assert!(rendered.contains("Access is denied"));
            assert!(rendered.contains('5'));
            let ids = "permissions.service.bits permissions.service.wuauserv review_flag C:\\review\\errorlog S-1-5-11 0x80070005";
            assert_eq!(lang.detail(ids), ids);
            if lang != Lang::En {
                assert_ne!(lang.t("review"), "review");
                assert!(!detail.contains("Consult the fixed service repair control"));
            }
        }
    }

    #[test]
    fn windows_italian_regional_variants_are_detected() {
        for id in [0x0010, 0x0410, 0x0810] {
            assert_eq!(Lang::from_windows_language(id), Lang::It);
        }
        assert_eq!(Lang::from_windows_language(0x0411), Lang::En);
    }

    #[test]
    fn privilege_controls_and_autologon_evidence_are_localized() {
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for id in [
                "installer.always_install_elevated",
                "lsa.restrict_anonymous_sam",
                "lsa.limit_blank_password_use",
                "wdigest.use_logon_credential",
            ] {
                assert_ne!(lang.control(id), id);
                assert_ne!(lang.control(id), Lang::En.control(id));
            }
            let detail = lang.detail("AutoAdminLogon enabled=True; Winlogon DefaultPassword value present=False. Presence only: no password data is read. Passwords kept in the Windows secret store are not checked. Review who can use this computer; automatic logon is kept to avoid disrupting kiosk or sign-in workflows.");
            assert!(detail.contains("True"));
            assert!(detail.contains("False"));
            assert!(!detail.contains("no password data is read"));
        }
    }
    fn literals(source: &str) -> Vec<String> {
        let source = source
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .split("#[cfg(all(test,")
            .next()
            .unwrap();
        let mut chars = source.chars().peekable();
        let mut out = Vec::new();
        let mut previous = '\0';
        while let Some(c) = chars.next() {
            if c == '/' && chars.peek() == Some(&'/') {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                previous = '\n';
                continue;
            }
            if c == '"' && previous != '\'' {
                let mut text = String::new();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    text.push(c);
                    if c == '\\' {
                        if let Some(c) = chars.next() {
                            text.push(c);
                        }
                    }
                }
                out.push(text);
            }
            previous = c;
        }
        out
    }

    #[test]
    fn fixed_rust_diagnostic_prose_has_catalog_coverage() {
        let mut missing = Vec::new();
        for (name, source) in rust_sources(&[
            "main.rs",
            "advice.rs",
            "advice",
            "actions.rs",
            "actions",
            "software_install.rs",
            "engine.rs",
            "engine",
            "model.rs",
            "readiness.rs",
            "readiness",
            "platform.rs",
            "platform",
            "service.rs",
            "service",
            "permissions.rs",
            "permissions",
        ]) {
            // Journal integrity and VBS probe errors never reach the screen:
            // callers replace them with fixed plain text (friendly_problem,
            // vbs::UNREADABLE) before anything is shown.
            if matches!(
                name.as_str(),
                "engine/journal.rs"
                    | "engine/recovery.rs"
                    | "engine/recover.rs"
                    | "engine/fsio.rs"
                    | "platform/vbs_native.rs"
            ) {
                continue;
            }
            let source = source.as_str();
            for text in literals(source) {
                if all_keys().any(|key| key == text) {
                    continue;
                }
                if !text.contains(' ')
                    || text.contains('\\')
                    || text.starts_with("[Console]")
                    || text.starts_with("$global:ProgressPreference = ")
                    || text == "Secblitz · v{}"
                    || matches!(
                        text.as_str(),
                        " -k netsvcs"
                            | " -k netsvcs -p"
                            | "Windows Update"
                            | "/Library/Application Support/Secblitz"
                    )
                {
                    continue;
                }
                let mut rest = text.as_str();
                let mut leftover = String::new();
                while !rest.is_empty() {
                    if rest.starts_with('{') {
                        if let Some(end) = rest.find('}') {
                            rest = &rest[end + 1..];
                            continue;
                        }
                    }
                    if let Some(key) = all_keys()
                        .filter(|key| rest.starts_with(key))
                        .max_by_key(|key| key.len())
                    {
                        rest = &rest[key.len()..];
                    } else {
                        let c = rest.chars().next().unwrap();
                        leftover.push(c);
                        rest = &rest[c.len_utf8()..];
                    }
                }
                let words: Vec<_> = leftover
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .filter(|s| s.chars().any(|c| c.is_ascii_alphabetic()))
                    .filter(|s| {
                        ![
                            "WinGet",
                            "Win32",
                            "HRESULT",
                            "GetPackagesByPackageFamily",
                            "SecblitzMonitor",
                            "BITS",
                            "wuauserv",
                            "WinDefend",
                            "Schedule",
                            "LocalService",
                            "SCM",
                            "SID",
                            "0x",
                            "s",     // SI time suffix next to a formatted duration.
                            "bytes", // Native byte counts in the catalog listing.
                        ]
                        .contains(s)
                    })
                    .collect();
                if !words.is_empty() {
                    missing.push(format!("{name}: {text} => {words:?}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "Untranslated application prose:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn scoped_policy_messages_render_in_every_language() {
        let messages = [
            "Relevant policy is configured or its authority is unknown: assessment only",
            "Group Policy authority is unknown: assessment only",
            "Relevant resultant Group Policy: assessment only",
            "Firewall preference/effective readback did not match; mutation outcome requires review",
            "No device-management registration or UAC policy authority found by the available probes. Each control repeats scoped policy and capability checks before mutation.",
        ];
        for message in messages {
            assert!(include_str!("platform/backend.ps1").contains(message));
            for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                let translated = lang.t(message);
                if lang != Lang::En {
                    assert_ne!(translated, message, "{}: {message}", lang.code());
                }
                let input = format!(
                    "Assessment unavailable: {message} [firewall.public.inbound; 0x80041003]"
                );
                let rendered = lang.detail(&input);
                assert!(rendered.contains(&translated));
                assert!(rendered.starts_with(&lang.t("Assessment unavailable: ")));
                assert!(rendered.ends_with("[firewall.public.inbound; 0x80041003]"));
            }
        }
    }

    #[test]
    fn backend_fixed_errors_titles_and_advice_are_translated() {
        let source = include_str!("platform/backend.ps1");
        for marker in [
            "throw '",
            "ThrowGate '",
            "Finding '",
            "title='",
            "detail='",
            "reason='",
        ] {
            for part in source.split(marker).skip(1) {
                let key = part.split('\'').next().unwrap();
                if ["Defender", "SMB1", "SmartScreen"].contains(&key) {
                    continue;
                }
                assert!(
                    text_rows().any(|row| row[0] == key),
                    "Missing backend translation: {key}"
                );
            }
        }
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            let detail = lang.detail("Apply firewall.public.inbound has unknown outcome; pending transaction 00042-abc retained");
            assert!(detail.contains("firewall.public.inbound"));
            assert!(detail.contains("00042-abc"));
            assert!(!detail.contains("has unknown outcome"));
            assert!(!detail.contains("retained"));
        }
    }

    #[test]
    fn defender_action_script_diagnostics_have_exact_translations() {
        for part in include_str!("actions/defender.ps1")
            .split("throw '")
            .skip(1)
        {
            let key = part.split('\'').next().unwrap();
            assert!(
                text_rows().any(|row| row[0] == key),
                "Missing action diagnostic: {key}"
            );
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                assert_ne!(lang.t(key), key, "{}: {key}", lang.code());
            }
        }
    }

    #[test]
    fn automatic_flow_and_readiness_copy_is_complete_and_preserves_placeholders() {
        for key in include_str!("../tests/fixtures/auto-flow-keys.txt")
            .lines()
            .filter(|key| !key.is_empty())
        {
            assert!(
                text_rows().any(|row| row[0] == key),
                "Missing automatic-flow key: {key}"
            );
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                assert_ne!(lang.t(key), key, "{}: {key}", lang.code());
            }
        }
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for (key, placeholder, value) in [
                ("{gb} GB free", "{gb}", "1099.5"),
                ("Battery: {percent}%", "{percent}", "20"),
            ] {
                let text = lang.t(key);
                assert_eq!(text.matches(placeholder).count(), 1);
                let rendered = text.replace(placeholder, value);
                assert!(rendered.contains(value));
                assert!(!rendered.contains(['{', '}']));
            }
            for key in ["EffectiveFirewallMismatch", "EffectiveFirewallUnavailable"] {
                assert!(text_rows().any(|row| row[0] == key));
                let raw_id = format!("native_{key} C:\\{key}\\evidence.json");
                assert_eq!(lang.detail(&raw_id), raw_id);
            }
        }
    }

    #[test]
    fn report_handoff_copy_has_exact_catalog_entries() {
        let mut text_block = false;
        for line in include_str!("../docs/report-copy-keys.md").lines() {
            if line == "```text" {
                text_block = true;
                continue;
            }
            if line == "```" {
                text_block = false;
                continue;
            }
            if text_block && !line.is_empty() {
                assert!(
                    text_rows().any(|row| row[0] == line),
                    "Missing report key: {line}"
                );
            }
        }
    }
    #[test]
    fn catalog_is_complete_and_unambiguous() {
        for (name, source) in [
            ("i18n", include_str!("i18n.rs")),
            (
                "guided-copy-keys",
                include_str!("../docs/guided-copy-keys.md"),
            ),
        ] {
            assert!(
                !source.contains('\u{2014}'),
                "U+2014 is not permitted in {name}"
            );
        }
        let mut keys = std::collections::HashSet::new();
        for row in text_rows() {
            assert!(keys.insert(row[0]), "duplicate source: {}", row[0]);
            assert!(
                row.iter().all(|s| !s.is_empty()),
                "missing translation: {}",
                row[0]
            );
            assert!(
                row.iter().all(|s| !s.contains('\u{2014}')),
                "em dash in catalog: {}",
                row[0]
            );
        }
        let mut italian_keys = std::collections::HashSet::new();
        for [key, translated] in italian::ROWS {
            assert!(italian_keys.insert(*key), "duplicate Italian source: {key}");
            assert!(!translated.is_empty(), "missing Italian translation: {key}");
            assert!(
                !key.contains('\u{2014}') && !translated.contains('\u{2014}'),
                "em dash in Italian catalog: {key}"
            );
            if !["antivirus=", "build="].contains(key) {
                assert_ne!(key, translated, "Italian placeholder: {key}");
            }
        }
        assert_eq!(
            keys, italian_keys,
            "Italian catalog must cover every source key"
        );
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for row in text_rows() {
                assert_eq!(
                    lang.detail(row[0]),
                    lang.translation(row),
                    "rendered catalog key: {}",
                    row[0]
                );
            }
            assert_eq!(Lang::parse(lang.code()), Some(lang));
            assert!(!lang
                .control("firewall.private.inbound")
                .contains("firewall.private"));
        }
    }
    #[test]
    fn dynamic_evidence_survives_prose_translation() {
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            let text = lang.detail("Transaction 00042-abc remains unreverted; use revert to restore its recorded preferences.");
            assert!(text.contains("00042-abc"));
            assert!(!text.contains("remains unreverted"));
            let text = lang.detail("Preference applied; restart required");
            assert!(!text.contains("Preference applied"));
            assert!(!text.contains("restart required"));
            assert_eq!(
                lang.detail("Notebook information public_key errorlog"),
                "Notebook information public_key errorlog"
            );
            assert_eq!(
                lang.control("firewall.private.future"),
                "firewall.private.future"
            );
        }
    }

    #[test]
    fn advice_impact_keys_are_translated_in_all_six_languages() {
        let control_ids = [
            "defender.realtime",
            "defender.behavior",
            "defender.ioav",
            "defender.archive",
            "firewall.domain.enabled",
            "firewall.private.enabled",
            "firewall.public.enabled",
            "firewall.domain.inbound",
            "firewall.private.inbound",
            "firewall.public.inbound",
            "uac.enabled",
            "uac.consent",
            "installer.always_install_elevated",
            "lsa.restrict_anonymous_sam",
            "lsa.limit_blank_password_use",
            "wdigest.use_logon_credential",
            "permissions.service.bits",
            "permissions.service.wuauserv",
        ];
        for id in control_ids {
            let impact = secblitz::advice::control_impact(id);
            assert!(!impact.is_empty(), "control_impact({id}) is empty");
            assert!(
                text_rows().any(|row| row[0] == impact),
                "impact phrase not in TEXT catalog: {impact}"
            );
            for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                let translated = lang.t(impact);
                assert!(
                    !translated.is_empty(),
                    "empty translation for {id} impact in {}",
                    lang.code()
                );
                if lang != Lang::En {
                    assert_ne!(
                        translated,
                        impact,
                        "{}: impact phrase not translated for {id}",
                        lang.code()
                    );
                }
            }
        }
        let finding_titles = [
            "Windows lifecycle",
            "Device encryption",
            "Secure Boot",
            "Windows updates",
            "Remote Desktop",
            "SMB1",
            "SmartScreen",
            "Memory integrity",
            "Automatic logon",
        ];
        for title in finding_titles {
            let impact = secblitz::advice::finding_impact(title);
            assert!(!impact.is_empty(), "finding_impact({title}) is empty");
            assert!(
                text_rows().any(|row| row[0] == impact),
                "finding impact phrase not in TEXT catalog: {impact}"
            );
            for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                let translated = lang.t(impact);
                assert!(
                    !translated.is_empty(),
                    "empty translation for {title} impact in {}",
                    lang.code()
                );
                if lang != Lang::En {
                    assert_ne!(
                        translated,
                        impact,
                        "{}: finding impact phrase not translated for {title}",
                        lang.code()
                    );
                }
            }
        }
        for prefix in ["Risk:", "Protects you from:", "Why it matters:"] {
            assert!(
                text_rows().any(|row| row[0] == prefix),
                "prefix not in TEXT catalog: {prefix}"
            );
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                let translated = lang.t(prefix);
                assert_ne!(
                    translated,
                    prefix,
                    "{}: prefix not translated: {prefix}",
                    lang.code()
                );
                assert!(!translated.is_empty());
            }
        }
        for key in [
            "Why it matters / Next step",
            "You're now protected from:",
            "After you restart, you'll be protected from:",
        ] {
            assert!(
                text_rows().any(|row| row[0] == key),
                "key not in catalog: {key}"
            );
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                let translated = lang.t(key);
                assert_ne!(
                    translated,
                    key,
                    "{}: key not translated: {key}",
                    lang.code()
                );
                assert!(!translated.is_empty());
            }
        }
    }
}
