//! Removing Secblitz itself, never other apps: the put-back logic behind the hidden
//! uninstaller commands, which can first undo the changes Secblitz made.
#![allow(dead_code)] // the GUI part of Remove Secblitz uses the rest
use crate::i18n::Lang;
use anyhow::Result;
use secblitz::debloat::suggested::Undo;
use secblitz::debloat::RestoreAll;
use secblitz::engine::Outcome as SettingOutcome;
use secblitz::model::CheckStatus;
use secblitz::user_settings::{Outcome as UserOutcome, Setting};
use serde::Serialize;

#[derive(Serialize, Default, Clone, Debug, PartialEq)]
pub struct Plan {
    pub settings: usize,
    pub apps_with_copy: usize,
    pub apps_store_only: usize,
    /// Apps with a saved copy that the Microsoft Store does not offer.
    pub apps_copy_only: usize,
    pub suggested: bool,
    pub web_on: bool,
    /// The saved undo history cannot be read, so earlier fixes cannot be put back.
    pub history_damaged: bool,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeftReason {
    ChangedSince,
    NotPossible,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub enum Left {
    Setting { title: String, reason: LeftReason },
    App { name: String },
    AppNeedsStore { name: String },
    Personal { id: &'static str },
    SuggestedOlderVersion,
    SuggestedChangedSince,
    HistoryDamaged,
}

#[derive(Serialize, Default, Debug)]
pub struct Summary {
    pub restored: usize,
    pub left: Vec<Left>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Settings,
    Apps,
    Suggested,
}

const SETTING_CHANGED: &str =
    "{title}: it has changed since Secblitz set it, so it was left as it is. No action is needed.";
const SETTING_MACHINE_NOT_POSSIBLE: &str = "{title}: this could not be put back, so it was left as it is. Restart your PC and try again. If it still does not work, you can leave it as it is.";
const SETTING_NOT_POSSIBLE: &str = "{title}: this could not be put back, so it was left as it is. You can change it yourself in Windows Settings.";
const APP_FAILED: &str =
    "{name} could not be brought back. Try again later, or get it again from the Microsoft Store.";
const APP_NEEDS_STORE: &str =
    "{name} could not be brought back. You can get it again from the Microsoft Store.";
const SUGGESTED_OLDER: &str =
    "Suggested apps were blocked by an older version of Secblitz, so they were left as they are. You can allow them again yourself in Windows Settings, under Personalization, then Start.";
const SUGGESTED_CHANGED: &str =
    "Suggested apps were left as they are, because they changed since Secblitz set them or could not be checked. You can change them yourself in Windows Settings.";
pub const HISTORY_DAMAGED: &str = "Secblitz's undo history is damaged, so its earlier fixes can't be undone. They stay as they are.";
const WINDOWS_SETTINGS: &str = "Windows settings";

pub(crate) fn personal_title(id: &str) -> &'static str {
    match id {
        "smartscreen.store_apps" => "Web check for Store apps",
        "files.show_extensions" => "Show file endings",
        "net.nearby_sharing" => "Nearby sharing",
        "privacy.tailored_experiences" => "Tailored tips and ads",
        "office.internet_macros" => "Office macros from the internet",
        "debloat.suggested_apps" => "Suggested apps in Start",
        "debloat.lockscreen_tips" => "Tips on the lock screen",
        "debloat.start_settings_tips" => "Suggestions in Start and Settings",
        "debloat.explorer_ads" => "Ads in File Explorer",
        "debloat.search_web" => "Web results in Start search",
        "debloat.gamebar_popups" => "Game Bar pop-ups",
        "space.storage_sense" => "Storage Sense",
        _ => WINDOWS_SETTINGS,
    }
}

pub fn left_line(left: &Left, lang: Lang) -> String {
    match left {
        Left::Setting { title, reason } => {
            let template = match reason {
                LeftReason::ChangedSince => SETTING_CHANGED,
                LeftReason::NotPossible => SETTING_MACHINE_NOT_POSSIBLE,
            };
            lang.t(template).replace("{title}", &lang.t(title))
        }
        Left::App { name } => lang.t(APP_FAILED).replace("{name}", &lang.t(name)),
        Left::AppNeedsStore { name } => lang.t(APP_NEEDS_STORE).replace("{name}", &lang.t(name)),
        Left::Personal { id } => lang
            .t(SETTING_NOT_POSSIBLE)
            .replace("{title}", &lang.t(personal_title(id))),
        Left::SuggestedOlderVersion => lang.t(SUGGESTED_OLDER),
        Left::SuggestedChangedSince => lang.t(SUGGESTED_CHANGED),
        Left::HistoryDamaged => lang.t(HISTORY_DAMAGED),
    }
}

pub fn left_reason_from_status(status: &CheckStatus) -> LeftReason {
    if *status == CheckStatus::Conflict {
        LeftReason::ChangedSince
    } else {
        LeftReason::NotPossible
    }
}

fn fold_settings(results: &[SettingOutcome], summary: &mut Summary) {
    for r in results {
        match &r.status {
            CheckStatus::Restored => summary.restored += 1,
            CheckStatus::Unchanged => {}
            other => summary.left.push(Left::Setting {
                title: r.title.clone(),
                reason: left_reason_from_status(other),
            }),
        }
    }
}

fn fold_apps(done: &RestoreAll, name: impl Fn(u16) -> String, summary: &mut Summary) {
    summary.restored += done.restored.len();
    summary.left.extend(
        done.needs_store
            .iter()
            .map(|i| Left::AppNeedsStore { name: name(*i) }),
    );
    summary
        .left
        .extend(done.failed.iter().map(|i| Left::App { name: name(*i) }));
}

fn fold_suggested(result: Result<Undo>, legacy_block: bool, summary: &mut Summary) {
    match result {
        Ok(Undo::Restored) => summary.restored += 1,
        Ok(Undo::NothingRecorded) if legacy_block => summary.left.push(Left::SuggestedOlderVersion),
        Ok(Undo::NothingRecorded) => {}
        Ok(Undo::ChangedSince) | Err(_) => summary.left.push(Left::SuggestedChangedSince),
    }
}

fn fold_user(results: Vec<(Setting, UserOutcome)>) -> Summary {
    let mut summary = Summary::default();
    for (setting, outcome) in results {
        if outcome == UserOutcome::Done {
            summary.restored += 1;
        } else if outcome == UserOutcome::ChangedSince {
            summary.left.push(Left::Setting {
                title: personal_title(setting.id()).to_owned(),
                reason: LeftReason::ChangedSince,
            });
        } else {
            summary.left.push(Left::Personal { id: setting.id() });
        }
    }
    summary
}

#[cfg(windows)]
fn open_engine() -> Result<secblitz::engine::Engine> {
    secblitz::engine::Engine::open(
        secblitz::platform::state_dir()?,
        secblitz::permissions::with_permissions(secblitz::platform::backend()?),
    )
}

#[cfg(windows)]
fn is_damaged(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<secblitz::engine::recover::JournalDamaged>()
        .is_some()
}

#[cfg(windows)]
pub fn plan() -> Result<Plan> {
    use secblitz::debloat::{self, journal, offline, suggested};
    let (settings, history_damaged) = match open_engine() {
        Ok(mut engine) => (engine.undoable_changes()?, false),
        Err(e) if is_damaged(&e) => (0, true),
        Err(e) => return Err(e),
    };
    let (mut apps_with_copy, mut apps_store_only, mut apps_copy_only) = (0, 0, 0);
    let catalog = debloat::catalog();
    for (index, _) in journal::still_removed(&journal::load(), catalog.len()) {
        if offline::has_copy(index) {
            apps_with_copy += 1;
            if catalog[index as usize].store_id.is_none() {
                apps_copy_only += 1;
            }
        } else {
            apps_store_only += 1;
        }
    }
    Ok(Plan {
        settings,
        apps_with_copy,
        apps_store_only,
        apps_copy_only,
        suggested: suggested::journal_path()
            .map(|p| suggested::recorded(&p))
            .unwrap_or(false),
        web_on: secblitz::filter::config::config_path()
            .is_ok_and(|p| secblitz::filter::config::load_config(&p).needs_service()),
        history_damaged,
    })
}

#[cfg(windows)]
pub fn revert_machine(progress: &dyn Fn(Step, bool)) -> Summary {
    use secblitz::debloat::{self, suggested};
    let mut summary = Summary::default();

    let before = summary.left.len();
    match open_engine().and_then(|mut e| e.revert_all(|_| {})) {
        Ok(report) => fold_settings(&report.results, &mut summary),
        Err(e) if is_damaged(&e) => summary.left.push(Left::HistoryDamaged),
        Err(_) => summary.left.push(Left::Setting {
            title: WINDOWS_SETTINGS.into(),
            reason: LeftReason::NotPossible,
        }),
    }
    progress(Step::Settings, summary.left.len() == before);

    let before = summary.left.len();
    let done = debloat::restore_all(&|_, _| {});
    fold_apps(
        &done,
        |i| {
            debloat::catalog()
                .get(usize::from(i))
                .map_or_else(String::new, |a| a.name.to_owned())
        },
        &mut summary,
    );
    progress(Step::Apps, summary.left.len() == before);

    let before = summary.left.len();
    match suggested::journal_path() {
        Ok(path) => {
            let result = suggested::undo(&mut suggested::MachinePolicy, &path);
            let legacy = matches!(result, Ok(Undo::NothingRecorded))
                && suggested::legacy_block(&suggested::MachinePolicy, &path);
            fold_suggested(result, legacy, &mut summary);
        }
        Err(e) => fold_suggested(Err(e), false, &mut summary),
    }
    progress(Step::Suggested, summary.left.len() == before);
    summary
}

#[cfg(windows)]
pub fn revert_user() -> Summary {
    use secblitz::user_settings::{journal_path, undo_all, SystemRegistry};
    match journal_path() {
        Some(path) => fold_user(undo_all(&mut SystemRegistry, &path)),
        None => Summary::default(),
    }
}

#[cfg(windows)]
pub fn cleanup_user() -> Result<()> {
    use anyhow::{bail, ensure};
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no per-user data folder"))?;
    let dir = std::path::PathBuf::from(base).join("Secblitz");
    let meta = match std::fs::symlink_metadata(&dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    {
        use std::os::windows::fs::MetadataExt;
        const REPARSE_POINT: u32 = 0x400;
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.file_attributes() & REPARSE_POINT == 0,
            "The per-user data folder is not a plain directory"
        );
    }
    if !owned_by_person_or_admins(&dir)? {
        bail!("The per-user data folder is not owned by this user");
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[cfg(windows)]
fn owned_by_person_or_admins(path: &std::path::Path) -> Result<bool> {
    use anyhow::{bail, ensure};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
            "Cannot read the current user"
        );
        let mut bytes = 0u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes);
        let mut buf = vec![0u64; (bytes as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), bytes, &mut bytes);
        CloseHandle(token);
        ensure!(ok != 0, "Cannot read the current user");
        let user: PSID = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut owner: PSID = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let status = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if status != 0 || owner.is_null() {
            if !sd.is_null() {
                LocalFree(sd);
            }
            bail!("Cannot read the folder owner ({status})");
        }
        let mut admins: PSID = null_mut();
        let admins_text: Vec<u16> = "S-1-5-32-544".encode_utf16().chain(Some(0)).collect();
        let same = EqualSid(owner, user) != 0
            || (ConvertStringSidToSidW(admins_text.as_ptr(), &mut admins) != 0
                && EqualSid(owner, admins) != 0);
        if !admins.is_null() {
            LocalFree(admins);
        }
        LocalFree(sd);
        Ok(same)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_LANGS: [Lang; 6] = [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It];

    fn outcome(title: &str, status: CheckStatus) -> SettingOutcome {
        SettingOutcome {
            id: "x".into(),
            title: title.into(),
            status,
            ..Default::default()
        }
    }

    fn every_variant() -> Vec<Left> {
        vec![
            Left::Setting {
                title: "Firewall at home".into(),
                reason: LeftReason::ChangedSince,
            },
            Left::Setting {
                title: "Firewall at home".into(),
                reason: LeftReason::NotPossible,
            },
            Left::App {
                name: "Clipchamp".into(),
            },
            Left::AppNeedsStore {
                name: "Clipchamp".into(),
            },
            Left::Personal {
                id: "office.internet_macros",
            },
            Left::SuggestedOlderVersion,
            Left::SuggestedChangedSince,
            Left::HistoryDamaged,
        ]
    }

    #[test]
    fn left_reason_from_status_maps_conflict_and_the_rest() {
        assert_eq!(
            left_reason_from_status(&CheckStatus::Conflict),
            LeftReason::ChangedSince
        );
        assert_eq!(
            left_reason_from_status(&CheckStatus::Skipped),
            LeftReason::NotPossible
        );
        assert_eq!(
            left_reason_from_status(&CheckStatus::Other("failed".into())),
            LeftReason::NotPossible
        );
    }

    #[test]
    fn left_lines_are_plain() {
        for lang in ALL_LANGS {
            for left in every_variant() {
                let line = left_line(&left, lang);
                assert!(!line.is_empty());
                assert!(!line.contains('{') && !line.contains('}'), "{line}");
                for jargon in ["HKCU", "DNS", "\u{2014}"] {
                    assert!(!line.contains(jargon), "{line}");
                }
            }
        }
        assert_eq!(
            left_line(&every_variant()[0], Lang::En),
            "Firewall at home: it has changed since Secblitz set it, so it was left as it is. No action is needed."
        );
        assert_eq!(
            left_line(&every_variant()[3], Lang::En),
            "Clipchamp could not be brought back. You can get it again from the Microsoft Store."
        );
        assert_eq!(
            left_line(&Left::SuggestedOlderVersion, Lang::En),
            "Suggested apps were blocked by an older version of Secblitz, so they were left as they are. You can allow them again yourself in Windows Settings, under Personalization, then Start."
        );
    }

    #[test]
    fn lines_that_could_not_be_put_back_say_what_to_do_next() {
        let machine = left_line(
            &Left::Setting {
                title: "Firewall at home".into(),
                reason: LeftReason::NotPossible,
            },
            Lang::En,
        );
        assert!(
            machine.contains("Restart your PC and try again"),
            "{machine}"
        );
        assert!(!machine.contains("Windows Settings"), "{machine}");
        let changed = left_line(
            &Left::Setting {
                title: "Firewall at home".into(),
                reason: LeftReason::ChangedSince,
            },
            Lang::En,
        );
        assert!(changed.contains("No action is needed"), "{changed}");
        assert!(!changed.contains("you changed"), "{changed}");
        for left in [
            Left::Personal { id: "x.unknown" },
            Left::SuggestedChangedSince,
            Left::SuggestedOlderVersion,
        ] {
            let line = left_line(&left, Lang::En);
            assert!(line.contains("Windows Settings"), "{line}");
        }
        let app = left_line(
            &Left::App {
                name: "Clipchamp".into(),
            },
            Lang::En,
        );
        assert!(app.contains("Microsoft Store"), "{app}");
        assert!(!app.contains("internet"), "{app}");
        let unknown = left_line(&Left::Personal { id: "x.unknown" }, Lang::En);
        assert!(unknown.starts_with("Windows settings:"), "{unknown}");
        assert!(!unknown.contains("x.unknown"), "{unknown}");
    }

    #[test]
    fn every_personal_setting_has_a_plain_title() {
        for setting in Setting::ALL {
            assert_ne!(
                personal_title(setting.id()),
                WINDOWS_SETTINGS,
                "{}",
                setting.id()
            );
        }
    }

    #[test]
    fn every_line_has_all_six_translations() {
        let sources = [
            SETTING_CHANGED,
            SETTING_MACHINE_NOT_POSSIBLE,
            SETTING_NOT_POSSIBLE,
            APP_FAILED,
            APP_NEEDS_STORE,
            SUGGESTED_OLDER,
            SUGGESTED_CHANGED,
            WINDOWS_SETTINGS,
            "Web check for Store apps",
            "Show file endings",
            "Nearby sharing",
            "Tailored tips and ads",
            "Office macros from the internet",
            "Suggested apps in Start",
            "Tips on the lock screen",
            "Suggestions in Start and Settings",
            "Ads in File Explorer",
            "Web results in Start search",
            "Game Bar pop-ups",
        ];
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/i18n-pending/a4.tsv");
        let pending = std::fs::read_to_string(path).ok();
        for source in sources {
            let row = pending.as_deref().and_then(|t| {
                t.lines()
                    .map(|l| l.split('\t').collect::<Vec<_>>())
                    .find(|c| c[0] == source)
            });
            if let Some(cols) = row {
                assert_eq!(cols.len(), 6, "{source}");
                assert!(cols
                    .iter()
                    .all(|c| !c.trim().is_empty() && !c.contains('\u{2014}')));
                for placeholder in ["{title}", "{name}"] {
                    for c in &cols {
                        assert_eq!(
                            source.contains(placeholder),
                            c.contains(placeholder),
                            "{source}"
                        );
                    }
                }
            } else {
                for lang in &ALL_LANGS[1..] {
                    assert_ne!(lang.t(source), source, "{source}");
                }
            }
        }
    }

    #[test]
    fn settings_fold_counts_restored_and_lists_the_rest() {
        let mut s = Summary::default();
        fold_settings(
            &[
                outcome("A", CheckStatus::Restored),
                outcome("B", CheckStatus::Unchanged),
                outcome("C", CheckStatus::Conflict),
                outcome("D", CheckStatus::Skipped),
            ],
            &mut s,
        );
        assert_eq!(s.restored, 1);
        assert_eq!(
            s.left,
            vec![
                Left::Setting {
                    title: "C".into(),
                    reason: LeftReason::ChangedSince
                },
                Left::Setting {
                    title: "D".into(),
                    reason: LeftReason::NotPossible
                },
            ]
        );
    }

    #[test]
    fn apps_fold_splits_store_only_from_failed() {
        let done = RestoreAll {
            restored: vec![1, 2],
            needs_store: vec![3],
            failed: vec![4],
        };
        let mut s = Summary::default();
        fold_apps(&done, |i| format!("app{i}"), &mut s);
        assert_eq!(s.restored, 2);
        assert_eq!(
            s.left,
            vec![
                Left::AppNeedsStore {
                    name: "app3".into()
                },
                Left::App {
                    name: "app4".into()
                }
            ]
        );
    }

    #[test]
    fn suggested_fold_handles_every_outcome() {
        let run = |r: Result<Undo>, legacy| {
            let mut s = Summary::default();
            fold_suggested(r, legacy, &mut s);
            s
        };
        assert_eq!(run(Ok(Undo::Restored), false).restored, 1);
        assert!(run(Ok(Undo::NothingRecorded), false).left.is_empty());
        assert_eq!(
            run(Ok(Undo::NothingRecorded), true).left,
            vec![Left::SuggestedOlderVersion]
        );
        assert_eq!(
            run(Ok(Undo::ChangedSince), false).left,
            vec![Left::SuggestedChangedSince]
        );
        assert_eq!(
            run(Err(anyhow::anyhow!("x")), false).left,
            vec![Left::SuggestedChangedSince]
        );
    }

    #[test]
    fn user_fold_lists_every_setting_that_did_not_come_back() {
        let s = fold_user(vec![
            (Setting::ShowExtensions, UserOutcome::Done),
            (Setting::NearbySharing, UserOutcome::Failed),
            (Setting::OfficeMacros, UserOutcome::Blocked),
            (Setting::TailoredExperiences, UserOutcome::ChangedSince),
        ]);
        assert_eq!(s.restored, 1);
        assert_eq!(
            s.left,
            vec![
                Left::Personal {
                    id: "net.nearby_sharing"
                },
                Left::Personal {
                    id: "office.internet_macros"
                },
                Left::Setting {
                    title: "Tailored tips and ads".into(),
                    reason: LeftReason::ChangedSince
                }
            ]
        );
    }

    #[test]
    fn summary_json_shape() {
        let s = Summary {
            restored: 2,
            left: vec![Left::SuggestedOlderVersion],
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"restored":2,"left":["SuggestedOlderVersion"]}"#);
    }
}
