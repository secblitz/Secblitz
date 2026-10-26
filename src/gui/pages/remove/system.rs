//! What the Remove sheet asks of Windows: the uninstaller, the plan and putting changes back.
use super::*;

/// On Linux the package manager owns the install, so only the packaged program counts as installed.
#[cfg(target_os = "linux")]
pub fn uninstaller() -> Option<PathBuf> {
    const PACKAGED: &str = "/usr/bin/secblitz";
    let exe = std::env::current_exe().ok()?;
    (exe == std::path::Path::new(PACKAGED)).then_some(exe)
}

#[cfg(not(target_os = "linux"))]
pub fn uninstaller() -> Option<PathBuf> {
    let exe = crate::app::settings::installed_exe()?;
    let path = exe.parent()?.join("unins000.exe");
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return None;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & REPARSE_POINT != 0 || !trusted_owner(&path) {
            return None;
        }
    }
    Some(path)
}

#[cfg(windows)]
fn trusted_owner(path: &std::path::Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; the OS-allocated `sd` and SID
    // text are freed with LocalFree on every path.
    unsafe {
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
            return false;
        }
        let mut text: *mut u16 = null_mut();
        // A SID string is never longer than 184 characters; scanning no further keeps a
        // missing terminator from running past the buffer.
        let trusted = ConvertSidToStringSidW(owner, &mut text) != 0 && !text.is_null() && {
            const MAX_SID_CHARS: usize = 184;
            let mut len = 0;
            while len < MAX_SID_CHARS && *text.add(len) != 0 {
                len += 1;
            }
            len < MAX_SID_CHARS && {
                let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
                matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544")
            }
        };
        if !text.is_null() {
            LocalFree(text.cast());
        }
        LocalFree(sd);
        trusted
    }
}

/// A check holds the journal for as long as it runs, so the plan waits for it instead of
/// leaving out what Secblitz changed.
#[cfg(windows)]
pub(super) fn load_plan() -> Result<Plan, String> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        match crate::uninstall::plan().map_err(|e| format!("{e:#}")) {
            Err(e) if e.contains("holds the journal lock") && std::time::Instant::now() < until => {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            plan => return plan,
        }
    }
}

/// How many settings the last check showed Secblitz can put back. Without a check there is no number, and the sheet then
/// offers to put back whatever is recorded.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn plan_from_report(report: Option<&secblitz::engine::Report>) -> Result<Plan, String> {
    report
        .map(|report| Plan {
            settings: report.results.iter().filter(|o| o.undoable).count(),
            ..Plan::default()
        })
        .ok_or_else(String::new)
}

pub(super) fn plan_task(
    report: Option<&secblitz::engine::Report>,
    generation: u32,
) -> Task<Message> {
    #[cfg(windows)]
    {
        let _ = report;
        Task::perform(blocking(load_plan), move |r| {
            wrap(Msg::Planned(generation, r))
        })
    }
    #[cfg(not(windows))]
    {
        Task::done(wrap(Msg::Planned(generation, plan_from_report(report))))
    }
}

pub(super) fn launch_uninstaller() -> bool {
    let Some(path) = uninstaller() else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        crate::linux_bus::client::remove_self().is_ok()
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new(path)
            .args([
                "/VERYSILENT",
                "/SUPPRESSMSGBOXES",
                "/NORESTART",
                "/SECBLITZDONE",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = path;
        false
    }
}

#[cfg(windows)]
pub(super) fn still_removed_names() -> Vec<String> {
    use secblitz::debloat::{self, journal};
    journal::still_removed(&journal::load(), debloat::catalog().len())
        .into_iter()
        .filter_map(|(i, _)| {
            debloat::catalog()
                .get(usize::from(i))
                .map(|a| a.name.to_owned())
        })
        .collect()
}

#[cfg(windows)]
const STORE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(windows)]
pub(super) fn reinstall_from_store(client: Option<&crate::broker::Client>) -> Vec<String> {
    use secblitz::debloat::{self, journal};
    use std::time::Duration;
    let Some(client) = client else {
        return Vec::new();
    };
    let mut pending: Vec<u16> = journal::still_removed(&journal::load(), debloat::catalog().len())
        .into_iter()
        .map(|(index, _)| index)
        .filter(|index| debloat::catalog()[usize::from(*index)].store_id.is_some())
        .filter(|index| matches!(client.send(Request::StartStoreApp(*index)), Ok(Reply::Done)))
        .collect();
    let deadline = Instant::now() + STORE_WAIT;
    while !pending.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        pending.retain(|index| match client.send(Request::StoreAppStatus(*index)) {
            Ok(Reply::Working) => true,
            Ok(Reply::Done) => {
                let _ = journal::mark_restored(*index);
                false
            }
            _ => false,
        });
    }
    pending
        .into_iter()
        .filter_map(|index| {
            debloat::catalog()
                .get(usize::from(index))
                .map(|a| a.name.to_owned())
        })
        .collect()
}

#[cfg(windows)]
pub(super) fn web_protection_off() -> bool {
    use secblitz::filter::config::{config_path, load_config, Config};
    let Ok(path) = config_path() else {
        return true;
    };
    if !load_config(&path).needs_service() {
        return true;
    }
    secblitz::filter::control::apply_switches(Config::default()).is_ok()
}

#[cfg(any(windows, test))]
pub(super) fn put_back_left(
    setting: Setting,
    was_ours: bool,
    reply: Option<Option<&Reply>>,
) -> Option<Left> {
    match reply {
        Some(Some(Reply::Done)) => None,
        Some(Some(Reply::ChangedSince)) => Some(Left::Setting {
            title: crate::uninstall::personal_title(setting.id()).to_owned(),
            reason: crate::uninstall::LeftReason::ChangedSince,
        }),
        Some(Some(Reply::Unavailable)) if !was_ours => None,
        None if !was_ours => None,
        _ => Some(Left::Personal { id: setting.id() }),
    }
}

#[cfg(windows)]
pub(super) fn run_put_back(
    client: Option<std::sync::Arc<crate::broker::Client>>,
    safe: Vec<Setting>,
    lang: Lang,
    emit: &dyn Fn(Event),
) {
    use crate::uninstall::{left_line, revert_machine, Step};
    let mut left: Vec<Left> = Vec::new();

    emit(Event::Started(Item::Personal));
    for setting in Setting::ALL {
        let reply = client
            .as_ref()
            .map(|c| c.send(Request::UserSetting(setting, Op::Undo)));
        let reply = reply.as_ref().map(|r| r.as_ref().ok());
        if let Some(l) = put_back_left(setting, safe.contains(&setting), reply) {
            left.push(l);
        }
    }
    emit(Event::Finished(Item::Personal, left.is_empty()));

    emit(Event::Started(Item::Settings));
    let downloading = std::cell::RefCell::new(Vec::new());
    let still_removed = || -> Vec<String> {
        let downloading = downloading.borrow();
        still_removed_names()
            .into_iter()
            .filter(|name| !downloading.contains(name))
            .collect()
    };
    let summary = revert_machine(&|step, ok| match step {
        Step::Settings => {
            emit(Event::Finished(Item::Settings, ok));
            emit(Event::Started(Item::Apps));
        }
        Step::Apps => {
            *downloading.borrow_mut() = reinstall_from_store(client.as_deref());
            emit(Event::Finished(Item::Apps, still_removed().is_empty()));
            emit(Event::Started(Item::Suggested));
        }
        Step::Suggested => emit(Event::Finished(Item::Suggested, ok)),
    });
    left.extend(summary.left);
    let left = prune_apps(left, &still_removed());

    emit(Event::Started(Item::Web));
    let web = web_protection_off();
    emit(Event::Finished(Item::Web, web));

    let mut lines: Vec<String> = left.iter().map(|l| left_line(l, lang)).collect();
    if !web {
        lines.push(lang.t(WEB_LEFT));
    }
    emit(Event::Done(lines));
}

/// What is left after one half put its settings back, as lines for the person.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn put_back_lines(report: &secblitz::engine::Report, lang: Lang) -> Vec<String> {
    use crate::uninstall::{left_reason_from_status, linux_left_line};
    use secblitz::model::CheckStatus;
    report
        .results
        .iter()
        .filter(|o| match o.status {
            CheckStatus::Restored | CheckStatus::Unchanged => false,
            CheckStatus::Skipped => o.detail != secblitz::engine::NOTHING_RECORDED,
            _ => true,
        })
        .map(|o| linux_left_line(&o.title, left_reason_from_status(&o.status), lang))
        .collect()
}

/// An interrupted fix is put back as a whole first, since the chosen settings cannot be undone one by one while it is open.
#[cfg(any(target_os = "linux", test))]
pub(super) fn put_back_all(
    session: &mut dyn crate::app::worker::Session,
) -> anyhow::Result<secblitz::engine::Report> {
    let ids = session.available();
    if ids.is_empty() {
        return Ok(secblitz::engine::Report::default());
    }
    let report = session.undo_selected(&ids, &mut |_| {})?;
    if report
        .results
        .iter()
        .any(|o| o.detail == secblitz::engine::UNDO_FIRST)
    {
        session.undo(&mut |_| {})?;
        return session.undo_selected(&ids, &mut |_| {});
    }
    Ok(report)
}

/// Puts back everything one half of the settings recorded. A half that cannot be reached leaves its own sentence.
#[cfg(target_os = "linux")]
fn put_back_half(
    open: impl FnOnce() -> anyhow::Result<Box<dyn crate::app::worker::Session>>,
    lang: Lang,
) -> Vec<String> {
    let result = open().and_then(|mut session| put_back_all(session.as_mut()));
    match result {
        Ok(report) => put_back_lines(&report, lang),
        Err(error)
            if error
                .downcast_ref::<secblitz::engine::recover::JournalDamaged>()
                .is_some() =>
        {
            vec![crate::uninstall::left_line(
                &crate::uninstall::Left::HistoryDamaged,
                lang,
            )]
        }
        Err(error) => vec![lang.t(&format!("{error:#}"))],
    }
}

/// The person's own settings first, which need no password, then the whole computer's through the helper.
#[cfg(target_os = "linux")]
pub(super) fn run_put_back(
    _client: Option<std::sync::Arc<crate::broker::Client>>,
    _safe: Vec<Setting>,
    lang: Lang,
    emit: &dyn Fn(Event),
) {
    let mut lines = Vec::new();

    emit(Event::Started(Item::Personal));
    let own = put_back_half(
        || Ok(Box::new(secblitz::linux::person::open_engine()?) as Box<_>),
        lang,
    );
    emit(Event::Finished(Item::Personal, own.is_empty()));
    lines.extend(own);

    emit(Event::Started(Item::Settings));
    let machine = put_back_half(
        || Ok(Box::new(crate::linux_bus::client::session()?) as Box<_>),
        lang,
    );
    emit(Event::Finished(Item::Settings, machine.is_empty()));
    lines.extend(machine);

    emit(Event::Done(lines));
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) fn run_put_back(
    _client: Option<std::sync::Arc<crate::broker::Client>>,
    _safe: Vec<Setting>,
    _lang: Lang,
    emit: &dyn Fn(Event),
) {
    for item in Item::ALL {
        emit(Event::Started(item));
        emit(Event::Finished(item, true));
    }
    emit(Event::Done(Vec::new()));
}
