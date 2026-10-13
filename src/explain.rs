//! Plain-language what / if-off / if-on text for every check. Every string is a translation source key.

mod access;
mod core;
mod detect;
mod network;
mod space;
mod system;
mod user;
mod web;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Explainer {
    pub what: &'static str,
    pub risk: &'static str,
    pub change: &'static str,
}

pub fn for_check(id: &str) -> Option<Explainer> {
    core::get(id)
        .or_else(|| access::get(id))
        .or_else(|| network::get(id))
        .or_else(|| system::get(id))
        .or_else(|| user::get(id))
        .or_else(|| space::get(id))
        .or_else(|| web::get(id))
        .or_else(|| detect::get(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn assert_short_sentence(id: &str, label: &str, line: &str) {
        assert!(line.chars().count() <= 160, "{id} {label} is too long");
        assert!(line.ends_with('.'), "{id} {label} must be a sentence");
    }

    fn dotted_literals(source: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (index, piece) in source.split('"').enumerate() {
            if index % 2 == 0 || !piece.contains('.') {
                continue;
            }
            let segments: Vec<&str> = piece.split('.').collect();
            let ok = segments.len() >= 2
                && segments.iter().all(|s| {
                    !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                })
                && segments[0].starts_with(|c: char| c.is_ascii_lowercase());
            if ok && !out.iter().any(|x| x == piece) {
                out.push(piece.to_owned());
            }
        }
        out
    }

    fn script_finding_titles() -> Vec<String> {
        include_str!("platform/backend.ps1")
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("Finding '")?;
                Some(rest.split('\'').next()?.to_owned())
            })
            .collect()
    }

    fn engine_ids() -> Vec<String> {
        let mut ids = vec!["readiness".to_owned()];
        ids.extend(crate::platform::control_ids());
        ids
    }

    fn rule_ids() -> Vec<String> {
        let mut ids = dotted_literals(include_str!("diagnostics/rules.rs"));
        for id in dotted_literals(include_str!("diagnostics/checks.rs")) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        ids
    }

    const RUST_FINDINGS: [&str; 11] = [
        "Journal recovery",
        "Memory integrity not running",
        "Kernel stack protection not running",
        "A device may not be working",
        "Assessment unavailable",
        "Windows service settings",
        "Service permissions: BITS",
        "Service permissions: wuauserv",
        "Service permissions: WinDefend",
        "Service permissions: Schedule",
        "Service permissions: SecblitzMonitor",
    ];

    fn every_id() -> Vec<String> {
        let mut ids: Vec<String> = engine_ids();
        ids.extend(crate::hardening::all().iter().map(|s| s.id.to_owned()));
        ids.extend(script_finding_titles());
        ids.extend(RUST_FINDINGS.iter().map(|s| (*s).to_owned()));
        ids.extend(rule_ids());
        ids
    }

    #[test]
    fn every_existing_check_has_an_explanation() {
        assert!(script_finding_titles().len() >= 12);
        assert!(rule_ids().len() >= 70);
        let ids = every_id();
        assert!(
            ids.len() > 100,
            "id enumeration looks broken: {}",
            ids.len()
        );
        let missing: Vec<&String> = ids.iter().filter(|id| for_check(id).is_none()).collect();
        assert!(missing.is_empty(), "no explanation for: {missing:?}");
    }

    #[test]
    fn unknown_ids_have_no_explanation() {
        assert!(for_check("no.such.check").is_none());
        assert!(for_check("").is_none());
    }

    fn all_text() -> Vec<(String, &'static str)> {
        let mut out = Vec::new();
        for id in every_id() {
            if let Some(e) = for_check(&id) {
                out.push((id.clone(), e.what));
                out.push((id.clone(), e.risk));
                out.push((id, e.change));
            }
        }
        out
    }

    #[test]
    fn lines_are_short_plain_and_calm() {
        const JARGON: [&str; 15] = [
            "NTLM", "SMB", "LLMNR", "LSA", "LSASS", "ASR", "WMI", "PPL", "DNS", "TLS", "SSL",
            "mDNS", "NetBIOS", "WPAD", "UAC",
        ];
        for (id, line) in all_text() {
            assert!(!line.trim().is_empty(), "{id}: empty line");
            assert!(line.chars().count() <= 170, "{id}: too long: {line}");
            assert!(!line.contains('!'), "{id}: exclamation mark: {line}");
            assert_eq!(line, line.trim(), "{id}: stray space: {line}");
            let lower = line.to_lowercase();
            assert!(!lower.contains("registry"), "{id}: jargon: {line}");
            assert!(!lower.contains("policy key"), "{id}: jargon: {line}");
            for word in line.split(|c: char| !c.is_ascii_alphanumeric()) {
                assert!(!JARGON.contains(&word), "{id}: jargon {word}: {line}");
            }
        }
    }

    #[test]
    fn lines_have_no_developer_words() {
        for (id, line) in all_text() {
            for bad in ["PowerShell", "DWORD", "HKLM", "journal", "RID "] {
                assert!(!line.contains(bad), "{id}: dev word {bad}: {line}");
            }
        }
    }
}
