//! Unelevated entry point: serves the broker pipe and launches the elevated GUI.
use crate::i18n::Lang;

pub fn message_box(title: &str, text: &str) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND,
        };
        let title: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
        let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND,
            );
        }
    }
    #[cfg(not(windows))]
    eprintln!("{title}: {text}");
}

const DAMAGED_HISTORY: &str = "Secblitz's undo history is damaged. Open Home and choose Start fresh. Secblitz keeps a copy of the damaged files.";

pub const NOT_INSTALLED: &str =
    "Secblitz is not fully installed. Reinstall it from the software app.";
pub const SESSION_UNUSUAL: &str = "Secblitz cannot start because this sign-in session is not set up the usual way. Sign out, sign back in, then open Secblitz again.";

pub fn friendly_problem(raw: &str) -> &'static str {
    for known in [NOT_INSTALLED, SESSION_UNUSUAL] {
        if raw.contains(known) {
            return known;
        }
    }
    let r = raw.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| r.contains(n));
    if has(&[
        "requires windows",
        "only supported on windows",
        "windows 10/11",
        "64-bit windows",
    ]) {
        "Secblitz works on Windows 10 and Windows 11 (64-bit) only. Open it on a computer that runs one of them."
    } else if has(&["undo history is damaged"]) {
        DAMAGED_HISTORY
    } else if has(&["declined", "cancel"]) {
        "Secblitz needs your permission to open. Open it again and choose Yes when Windows asks."
    } else if has(&[
        "access is denied",
        "os error 5",
        "permission denied",
        "administrator",
        "elevat",
    ]) {
        "Windows wouldn't let Secblitz open its files. Sign in with an account that can make changes to this computer, then open Secblitz again."
    } else if has(&["journal lock", "another secblitz", "already running"]) {
        "Secblitz is already busy with another task. Wait a minute, then open it again."
    } else if has(&["no space", "os error 112", "disk full"]) {
        "Your computer is almost out of space. Free up some space, then open Secblitz again."
    } else if has(&["journal", "corrupt", "missing header", "utf8"]) {
        "Secblitz couldn't read its saved information. Restart your computer and open Secblitz again. If it keeps happening, install the latest Secblitz."
    } else if has(&[
        "timed out",
        "did not answer",
        "broker",
        "powershell",
        "script",
        "backend",
    ]) {
        "Windows didn't answer in time. Restart your computer, then open Secblitz again."
    } else {
        "Something unexpected got in the way. Restart your computer and open Secblitz again. If it keeps happening, check for a Secblitz update."
    }
}

pub fn friendly_check_problem(raw: &str) -> &'static str {
    let found = friendly_problem(raw);
    if found.starts_with("Secblitz works on Windows 10") || found == DAMAGED_HISTORY {
        found
    } else {
        "Something unexpected got in the way. Press Check again. If it keeps happening, restart your computer."
    }
}

pub fn show_failure(lang: Lang, error: &anyhow::Error) {
    eprintln!("{error:#}");
    let text = format!(
        "{}\n\n{}",
        lang.t("Secblitz couldn't open."),
        lang.t(friendly_problem(&format!("{error:#}")))
    );
    message_box("Secblitz", &text);
}

#[cfg_attr(not(windows), allow(dead_code))]
fn args_are_plain(args: &[String]) -> bool {
    args.iter()
        .all(|a| !a.is_empty() && a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

/// Plain words, then one site name that is already in its clean form.
#[cfg_attr(not(windows), allow(dead_code))]
fn site_args_are_plain(args: &[String]) -> bool {
    match args.split_last() {
        Some((site, words)) => {
            args_are_plain(words)
                && secblitz::filter::config::normalized_site(site).as_deref() == Some(site)
        }
        None => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum AllowOnce {
    Done,
    /// The person said no at the Windows permission prompt.
    Declined,
    Failed,
}

/// Lets one site through Web protection for a short while. Windows asks for permission first.
pub fn allow_site_once(site: &str, lang: Lang) -> AllowOnce {
    #[cfg(windows)]
    {
        let args: Vec<String> = ["--lang", lang.code(), "filter", "allow-once", site]
            .map(String::from)
            .into();
        match imp::elevate_for_site(&args) {
            Ok(Some(child)) => match child.wait() {
                Ok(0) => AllowOnce::Done,
                _ => AllowOnce::Failed,
            },
            Ok(None) => AllowOnce::Declined,
            Err(_) => AllowOnce::Failed,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (site, lang);
        AllowOnce::Failed
    }
}

const OPEN_PAGES: [&str; 4] = ["protection", "web", "tools", "history"];

pub fn open_page(value: &str) -> Option<&'static str> {
    OPEN_PAGES
        .into_iter()
        .find(|p| p.eq_ignore_ascii_case(value))
}

/// Every word is a fixed or generated plain word.
#[cfg_attr(not(windows), allow(dead_code))]
fn gui_args(id: &str, lang: Lang, open: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["gui", "--broker", id, "--lang", lang.code()]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(page) = open.and_then(open_page) {
        args.extend(["--open".to_owned(), page.to_owned()]);
    }
    args
}

pub fn run(lang: Lang, open: Option<&str>) -> anyhow::Result<i32> {
    #[cfg(windows)]
    {
        imp::run(lang, open)
    }
    #[cfg(not(windows))]
    {
        let _ = (lang, open);
        anyhow::bail!("Secblitz requires Windows")
    }
}

pub fn elevate_and_wait(args: &[String]) -> anyhow::Result<i32> {
    #[cfg(windows)]
    {
        match imp::elevate(args)? {
            Some(child) => child.wait(),
            None => anyhow::bail!("The administrator prompt was declined"),
        }
    }
    #[cfg(not(windows))]
    {
        secblitz::platform::elevate(args)?;
        Ok(0)
    }
}

/// A "Run as administrator" start has no broker: start again the normal way
/// and let this copy close. False when that is not possible or not needed.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn reopen_normally(lang: Lang, open: Option<&str>) -> bool {
    #[cfg(windows)]
    {
        matches!(imp::split_token_elevated(), Ok(true)) && imp::reopen_normally(lang, open).is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = (lang, open);
        false
    }
}

/// True when this account has normal rights to fall back to (a UAC split token).
pub fn has_split_token() -> bool {
    #[cfg(windows)]
    {
        imp::split_token_elevated().unwrap_or(true)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub enum Instance {
    First(#[allow(dead_code)] Guard),
    #[cfg_attr(not(windows), allow(dead_code))]
    Existing,
}

pub struct Guard {
    #[cfg(windows)]
    _handle: imp::Owned,
    #[cfg(windows)]
    _namespace: Option<imp::Namespace>,
    #[cfg(unix)]
    _lock: std::fs::File,
}

pub fn single_instance(open: Option<&str>) -> anyhow::Result<Instance> {
    #[cfg(windows)]
    {
        imp::single_instance(open)
    }
    #[cfg(unix)]
    {
        let _ = open;
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| anyhow::anyhow!(SESSION_UNUSUAL))?;
        unix_lock::acquire(&runtime)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = open;
        Ok(Instance::First(Guard {}))
    }
}

#[cfg(unix)]
mod unix_lock {
    use super::{Guard, Instance, SESSION_UNUSUAL};
    use std::fs::{DirBuilder, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;

    /// Takes the one-window lock under `runtime/secblitz`, a folder only this user can use.
    pub fn acquire(runtime: &Path) -> anyhow::Result<Instance> {
        let dir = runtime.join("secblitz");
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(anyhow::Error::new(e).context(SESSION_UNUSUAL)),
        }
        let meta = std::fs::symlink_metadata(&dir)
            .map_err(|e| anyhow::Error::new(e).context(SESSION_UNUSUAL))?;
        let mine = unsafe { libc::geteuid() };
        if !meta.is_dir() || meta.uid() != mine || meta.mode() & 0o077 != 0 {
            anyhow::bail!(SESSION_UNUSUAL);
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join("gui.lock"))
            .map_err(|e| anyhow::Error::new(e).context(SESSION_UNUSUAL))?;
        let meta = file
            .metadata()
            .map_err(|e| anyhow::Error::new(e).context(SESSION_UNUSUAL))?;
        if !meta.is_file() || meta.uid() != mine {
            anyhow::bail!(SESSION_UNUSUAL);
        }
        match file.try_lock() {
            Ok(()) => Ok(Instance::First(Guard { _lock: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(Instance::Existing),
            Err(std::fs::TryLockError::Error(e)) => {
                Err(anyhow::Error::new(e).context(SESSION_UNUSUAL))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn runtime() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        #[test]
        fn a_second_window_is_told_one_is_open() {
            let rt = runtime();
            let first = acquire(rt.path()).unwrap();
            assert!(matches!(first, Instance::First(_)));
            assert!(matches!(acquire(rt.path()).unwrap(), Instance::Existing));
            drop(first);
            assert!(matches!(acquire(rt.path()).unwrap(), Instance::First(_)));
        }

        #[test]
        fn the_lock_folder_is_private() {
            let rt = runtime();
            let _ = acquire(rt.path()).unwrap();
            let mode = std::fs::metadata(rt.path().join("secblitz"))
                .unwrap()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        #[test]
        fn a_symlinked_lock_file_is_refused() {
            let rt = runtime();
            let dir = rt.path().join("secblitz");
            DirBuilder::new().mode(0o700).create(&dir).unwrap();
            let target = rt.path().join("elsewhere");
            std::fs::write(&target, b"keep").unwrap();
            symlink(&target, dir.join("gui.lock")).unwrap();
            assert!(acquire(rt.path()).is_err());
            assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        }

        #[test]
        fn a_symlinked_or_open_folder_is_refused() {
            let rt = runtime();
            let real = rt.path().join("real");
            DirBuilder::new().mode(0o700).create(&real).unwrap();
            symlink(&real, rt.path().join("secblitz")).unwrap();
            assert!(acquire(rt.path()).is_err());

            let rt = runtime();
            let dir = rt.path().join("secblitz");
            DirBuilder::new().mode(0o755).create(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(acquire(rt.path()).is_err());
        }
    }
}

pub fn user_sid() -> Option<String> {
    #[cfg(windows)]
    {
        imp::user_sid_string().ok()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
mod imp {
    use super::{args_are_plain, Guard, Instance};
    use crate::app::app_access::{self, Capability, Target};
    use crate::broker::{self, Reply, Request};
    use crate::i18n::Lang;
    use anyhow::{ensure, Context, Result};
    use secblitz::user_settings::{self, Op, Setting, SystemRegistry};
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut, time::Duration};
    use windows_sys::core::BOOL;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_CANCELLED,
            ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                ConvertStringSidToSidW, SDDL_REVISION_1,
            },
            DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevation,
            TokenPrimary, TokenUser, PSID, SECURITY_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
            TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION,
            TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            PIPE_ACCESS_DUPLEX,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeClientProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            RemoteDesktop::ProcessIdToSessionId,
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                AddIntegrityLabelToBoundaryDescriptor, AddSIDToBoundaryDescriptor,
                ClosePrivateNamespace, CreateBoundaryDescriptorW, CreateEventW, CreateMutexW,
                CreatePrivateNamespaceW, CreateProcessWithTokenW, DeleteBoundaryDescriptor,
                GetCurrentProcess, GetExitCodeProcess, GetProcessId, OpenPrivateNamespaceW,
                OpenProcess, OpenProcessToken, ResetEvent, WaitForMultipleObjects,
                WaitForSingleObject, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                STARTUPINFOW,
            },
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        },
        UI::{
            Shell::{ShellExecuteExW, ShellExecuteW, SHELLEXECUTEINFOW},
            WindowsAndMessaging::{
                AllowSetForegroundWindow, EnumWindows, GetShellWindow, GetWindowTextW,
                GetWindowThreadProcessId, IsIconic, IsWindowVisible, SetForegroundWindow,
                ShowWindow, SW_RESTORE, SW_SHOWNORMAL,
            },
        },
    };

    pub struct Owned(pub HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub struct Elevated(Owned);

    impl Elevated {
        fn pid(&self) -> u32 {
            unsafe { GetProcessId((self.0).0) }
        }
        pub fn wait(&self) -> Result<i32> {
            if unsafe { WaitForSingleObject((self.0).0, u32::MAX) } != WAIT_OBJECT_0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut code = 1;
            if unsafe { GetExitCodeProcess((self.0).0, &mut code) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(code as i32)
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub fn elevate(args: &[String]) -> Result<Option<Elevated>> {
        ensure!(args_are_plain(args), "Invalid elevation arguments");
        start(args)
    }

    pub fn elevate_for_site(args: &[String]) -> Result<Option<Elevated>> {
        ensure!(
            super::site_args_are_plain(args),
            "Invalid elevation arguments"
        );
        start(args)
    }

    fn start(args: &[String]) -> Result<Option<Elevated>> {
        let exe: Vec<u16> = std::env::current_exe()?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let params = wide(&args.join(" "));
        let verb = wide("runas");
        let mut dir = vec![0u16; 32768];
        let n = unsafe { GetSystemDirectoryW(dir.as_mut_ptr(), dir.len() as u32) } as usize;
        ensure!(
            n > 0 && n < dir.len(),
            "Cannot resolve the System32 directory"
        );
        dir.truncate(n);
        dir.push(0);
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = 0x40 | 0x100; // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
        info.lpVerb = verb.as_ptr();
        info.lpFile = exe.as_ptr();
        info.lpParameters = params.as_ptr();
        info.lpDirectory = dir.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            if unsafe { GetLastError() } == ERROR_CANCELLED {
                return Ok(None);
            }
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(
            !info.hProcess.is_null(),
            "Elevation returned no process handle"
        );
        Ok(Some(Elevated(Owned(info.hProcess))))
    }

    pub fn user_sid_string() -> Result<String> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let token = Owned(token);
            let mut needed = 0u32;
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
            ensure!(needed > 0 && needed < 4096, "token information unavailable");
            let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut raw: *mut u16 = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut raw) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let s = secblitz::platform::security::wide_str(raw).map(String::from_utf16_lossy);
            LocalFree(raw.cast());
            s.context("token information unavailable")
        }
    }

    /// True for the elevated half of a split (UAC) admin token: someone chose
    /// "Run as administrator". The broker must then not run, because its
    /// user-context actions (winget, HKCU, protocol handlers) would carry the
    /// admin token while the same user's unelevated programs can steer them.
    /// Built-in Administrator and UAC-off accounts have no split token.
    pub fn split_token_elevated() -> Result<bool> {
        secblitz::actions::split_token_elevated()
    }

    /// Starts Secblitz again with the desktop user's normal rights, so it goes
    /// through the launcher (and its UAC prompt) and gets a broker.
    pub fn reopen_normally(lang: Lang, open: Option<&str>) -> Result<()> {
        // SAFETY: GetShellWindow has no preconditions.
        let shell = unsafe { GetShellWindow() };
        ensure!(!shell.is_null(), "No desktop shell");
        let mut pid = 0;
        // SAFETY: `shell` is non-null and `pid` is a valid out pointer.
        ensure!(
            unsafe { GetWindowThreadProcessId(shell, &mut pid) } != 0 && pid != 0,
            "No desktop shell"
        );
        // SAFETY: plain value arguments; a null result is checked below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        ensure!(!process.is_null(), "Cannot open the desktop shell");
        let process = Owned(process);
        let mut token: HANDLE = null_mut();
        // SAFETY: `process` is a live handle and `token` a valid out pointer.
        ensure!(
            unsafe { OpenProcessToken(process.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) } != 0,
            "Cannot read the desktop shell's rights"
        );
        let token = Owned(token);
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 1 };
        let mut len = 0u32;
        // SAFETY: `elevation` is a live TOKEN_ELEVATION and the length passed is exactly its size.
        let read = unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        };
        ensure!(
            read != 0 && elevation.TokenIsElevated == 0,
            "The desktop shell has no normal rights to start from"
        );
        let mut primary: HANDLE = null_mut();
        // SAFETY: `token` is a live handle opened with TOKEN_DUPLICATE; `primary` is a valid out pointer.
        ensure!(
            unsafe {
                DuplicateTokenEx(
                    token.0,
                    TOKEN_QUERY
                        | TOKEN_DUPLICATE
                        | TOKEN_ASSIGN_PRIMARY
                        | TOKEN_ADJUST_DEFAULT
                        | TOKEN_ADJUST_SESSIONID,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenPrimary,
                    &mut primary,
                )
            } != 0,
            "Cannot copy the desktop shell's rights"
        );
        let primary = Owned(primary);
        let exe = std::env::current_exe()?;
        let application: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut line = format!("\"{}\" gui --lang {}", exe.display(), lang.code());
        if let Some(page) = open.and_then(super::open_page) {
            line.push_str(" --open ");
            line.push_str(page);
        }
        let mut command = wide(&line);
        // SAFETY: plain C structs for which all-zero bytes are valid initial values.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        // SAFETY: as above.
        let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer refers to a live, NUL-terminated buffer or struct owned above.
        ensure!(
            unsafe {
                CreateProcessWithTokenW(
                    primary.0,
                    0,
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                    &startup,
                    &mut started,
                )
            } != 0,
            "Cannot start Secblitz with normal rights"
        );
        drop(Owned(started.hThread));
        drop(Owned(started.hProcess));
        Ok(())
    }

    fn create_pipe(id: &str) -> Result<Owned> {
        let sddl = wide(&format!("D:P(A;;GA;;;{})(A;;GA;;;BA)", user_sid_string()?));
        let mut descriptor: *mut c_void = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide(&broker::pipe_name(id));
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64,
                64,
                0,
                &attributes,
            )
        };
        let error = std::io::Error::last_os_error();
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error).context("Cannot create the broker channel");
        }
        Ok(Owned(handle))
    }

    enum Wake {
        Io,
        Child,
    }

    fn wait_io(event: HANDLE, child: HANDLE) -> Wake {
        let handles = [event, child];
        match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, u32::MAX) } {
            WAIT_OBJECT_0 => Wake::Io,
            _ => Wake::Child,
        }
    }

    enum Read {
        Full,
        Closed,
        ChildGone,
    }

    fn read_full(pipe: HANDLE, event: HANDLE, child: HANDLE, buf: &mut [u8]) -> Read {
        let mut done = 0usize;
        while done < buf.len() {
            // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = event;
            unsafe { ResetEvent(event) };
            let rest = &mut buf[done..];
            let started = unsafe {
                ReadFile(
                    pipe,
                    rest.as_mut_ptr(),
                    rest.len() as u32,
                    null_mut(),
                    &mut overlapped,
                )
            };
            if started == 0 {
                if unsafe { GetLastError() } != ERROR_IO_PENDING {
                    return Read::Closed;
                }
                if let Wake::Child = wait_io(event, child) {
                    unsafe {
                        CancelIoEx(pipe, &overlapped);
                        let mut n = 0u32;
                        GetOverlappedResult(pipe, &overlapped, &mut n, 1);
                    }
                    return Read::ChildGone;
                }
            }
            let mut n = 0u32;
            if unsafe { GetOverlappedResult(pipe, &overlapped, &mut n, 0) } == 0 || n == 0 {
                return Read::Closed;
            }
            done += n as usize;
        }
        Read::Full
    }

    fn write_reply(pipe: HANDLE, event: HANDLE, child: HANDLE, reply: &[u8]) -> bool {
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event;
        unsafe { ResetEvent(event) };
        let started = unsafe {
            WriteFile(
                pipe,
                reply.as_ptr(),
                reply.len() as u32,
                null_mut(),
                &mut overlapped,
            )
        };
        if started == 0 {
            if unsafe { GetLastError() } != ERROR_IO_PENDING {
                return false;
            }
            if let Wake::Child = wait_io(event, child) {
                unsafe {
                    CancelIoEx(pipe, &overlapped);
                    let mut n = 0u32;
                    GetOverlappedResult(pipe, &overlapped, &mut n, 1);
                }
                return false;
            }
        }
        let mut n = 0u32;
        unsafe {
            GetOverlappedResult(pipe, &overlapped, &mut n, 0) != 0 && n as usize == reply.len()
        }
    }

    fn serve(pipe: &Owned, child: &Elevated) {
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return;
        }
        let event = Owned(event);
        let child_pid = child.pid();
        let child_handle = (child.0).0;
        let mut strangers = 0;
        loop {
            // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = event.0;
            unsafe { ResetEvent(event.0) };
            if unsafe { ConnectNamedPipe(pipe.0, &mut overlapped) } == 0 {
                match unsafe { GetLastError() } {
                    ERROR_PIPE_CONNECTED => {}
                    ERROR_IO_PENDING => {
                        if let Wake::Child = wait_io(event.0, child_handle) {
                            unsafe {
                                CancelIoEx(pipe.0, &overlapped);
                                let mut n = 0u32;
                                GetOverlappedResult(pipe.0, &overlapped, &mut n, 1);
                            }
                            return;
                        }
                    }
                    _ => return,
                }
            }
            let mut client = 0u32;
            let verified = unsafe { GetNamedPipeClientProcessId(pipe.0, &mut client) } != 0
                && client == child_pid;
            if !verified {
                unsafe { DisconnectNamedPipe(pipe.0) };
                strangers += 1;
                if strangers >= 5 {
                    return;
                }
                continue;
            }
            loop {
                let mut request = [0u8; 3];
                match read_full(pipe.0, event.0, child_handle, &mut request) {
                    Read::Full => {}
                    Read::Closed => break,
                    Read::ChildGone => return,
                }
                let reply = match Request::decode(request) {
                    Some(Request::SaveSupportFile) => {
                        let mut header = [0u8; broker::FileHeader::SIZE];
                        match read_full(pipe.0, event.0, child_handle, &mut header) {
                            Read::Full => {}
                            Read::Closed => break,
                            Read::ChildGone => return,
                        }
                        // Too big or empty: the rest can't be skipped safely, so hang up.
                        let Some(header) = broker::FileHeader::decode(header) else {
                            break;
                        };
                        let mut zip = vec![0u8; header.len];
                        match read_full(pipe.0, event.0, child_handle, &mut zip) {
                            Read::Full => {}
                            Read::Closed => break,
                            Read::ChildGone => return,
                        }
                        let (reply, n) = save_support_file(header.at, &zip);
                        if !write_reply(pipe.0, event.0, child_handle, &[reply.encode(), n]) {
                            break;
                        }
                        continue;
                    }
                    Some(Request::Space(area, op)) => {
                        let tally = match op {
                            broker::SpaceOp::Measure => secblitz::space::measure_user(area),
                            broker::SpaceOp::Clean => secblitz::space::clean_user(area),
                        };
                        let reply = broker::encode_space_reply(Reply::Done, tally);
                        if !write_reply(pipe.0, event.0, child_handle, &reply) {
                            break;
                        }
                        continue;
                    }
                    Some(request) => handle(request),
                    None => Reply::Unavailable,
                };
                if !write_reply(pipe.0, event.0, child_handle, &[reply.encode()]) {
                    break;
                }
            }
            unsafe { DisconnectNamedPipe(pipe.0) };
            if unsafe { WaitForSingleObject(child_handle, 0) } == WAIT_OBJECT_0 {
                return;
            }
        }
    }

    pub fn run(lang: Lang, open: Option<&str>) -> Result<i32> {
        if split_token_elevated()? {
            if reopen_normally(lang, open).is_ok() {
                return Ok(0);
            }
            super::message_box(
                "Secblitz",
                &lang.t("Please open Secblitz the usual way, not with “Run as administrator”. It asks for permission by itself when it needs it."),
            );
            return Ok(1);
        }
        if show_existing(open) {
            return Ok(0);
        }
        let id = broker::new_id();
        let pipe = create_pipe(&id)?;
        let args = super::gui_args(&id, lang, open);
        let Some(child) = elevate(&args)? else {
            return Ok(0);
        };
        serve(&pipe, &child);
        drop(pipe);
        child.wait()
    }

    fn handle(request: Request) -> Reply {
        use secblitz::software_install::ToolError;
        let open = |action| match secblitz::actions::run(action) {
            Ok(_) => Reply::Done,
            Err(_) => Reply::Failed,
        };
        match request {
            Request::InstallBitwarden => match secblitz::software_install::install_bitwarden() {
                Ok(()) => Reply::Done,
                Err(e) => match ToolError::of(&e) {
                    Some(ToolError::Offline) => Reply::Offline,
                    Some(ToolError::NotHere) => Reply::Unavailable,
                    None => Reply::Failed,
                },
            },
            Request::BitwardenStatus => match secblitz::software_install::bitwarden_installed() {
                Ok(true) => Reply::Done,
                Err(_) => Reply::Unknown,
                Ok(false) => match secblitz::software_install::bitwarden_installable() {
                    Ok(()) => Reply::NotApplicable,
                    Err(e) if ToolError::of(&e) == Some(ToolError::NotHere) => Reply::Unavailable,
                    Err(_) => Reply::Unknown,
                },
            },
            Request::BlockSuggestedApps => user_setting(Setting::SuggestedApps, Op::Apply),
            Request::ReinstallStoreApp(index) => reinstall_store_app(index),
            Request::StartStoreApp(index) => start_store_app(index),
            Request::StoreAppStatus(index) => store_app_status(index),
            Request::UserSetting(setting, op) => user_setting(setting, op),
            Request::StartTray => start_tray(),
            Request::ShowSupportFile => {
                if crate::app::support::show_in_folder() {
                    Reply::Done
                } else {
                    Reply::Failed
                }
            }
            Request::AppAccessList(capability) => app_access_list(capability),
            Request::AppAccessSet {
                capability,
                target,
                tag,
                allow,
            } => app_access_set(capability, target, tag, allow),
            _ => request.page().map_or(Reply::Failed, open),
        }
    }

    fn start_tray() -> Reply {
        use std::os::windows::process::CommandExt;
        let Some(exe) = crate::app::settings::installed_exe() else {
            return Reply::Unavailable;
        };
        if !crate::app::settings::tray_enabled() {
            return Reply::Failed;
        }
        match std::process::Command::new(exe)
            .arg("tray")
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
        {
            Ok(_) => Reply::Done,
            Err(_) => Reply::Failed,
        }
    }

    /// Runs as the signed-in person, so the file lands in their own Downloads, never in a
    /// folder of the account the window was elevated with.
    fn save_support_file(at: u64, zip: &[u8]) -> (Reply, u8) {
        use crate::app::support;
        if !broker::looks_like_zip(zip) {
            return (Reply::Failed, 0);
        }
        let Some(dir) = support::downloads() else {
            return (Reply::Unavailable, 0);
        };
        match support::save_new(&dir, &support::file_name(at), zip) {
            Ok((_, n)) => (Reply::Done, n),
            Err(_) => (Reply::Failed, 0),
        }
    }

    /// Runs as the signed-in person, so Explorer opens unelevated and in their own Downloads.
    fn user_setting(setting: Setting, op: Op) -> Reply {
        let mut registry = SystemRegistry;
        let journal = user_settings::journal_path();
        match user_settings::handle(&mut registry, journal.as_deref(), setting, op) {
            Ok(result) => Reply::from_result(result),
            Err(_) if op == Op::Query => Reply::Unknown,
            Err(_) => Reply::Failed,
        }
    }

    fn app_access_listings() -> &'static std::sync::Mutex<[Option<app_access::Listing>; 3]> {
        static LISTINGS: std::sync::OnceLock<std::sync::Mutex<[Option<app_access::Listing>; 3]>> =
            std::sync::OnceLock::new();
        LISTINGS.get_or_init(Default::default)
    }

    fn app_access_list(capability: Capability) -> Reply {
        let listing = app_access::read_listing(
            &app_access::SystemStore,
            capability,
            crate::app::last_check::boot_time(crate::app::history::now()),
            &app_access::describe_exe,
        );
        let Some(path) = app_access::handoff_path(capability) else {
            return Reply::Failed;
        };
        if app_access::write_handoff(&path, &listing).is_err() {
            return Reply::Failed;
        }
        match app_access_listings().lock() {
            Ok(mut remembered) => {
                remembered[usize::from(capability.to_byte())] = Some(listing);
                Reply::Done
            }
            Err(_) => Reply::Failed,
        }
    }

    fn app_access_set(capability: Capability, target: Target, tag: u8, allow: bool) -> Reply {
        let Ok(remembered) = app_access_listings().lock() else {
            return Reply::Failed;
        };
        let Some(listing) = &remembered[usize::from(capability.to_byte())] else {
            return Reply::Unavailable;
        };
        match app_access::set_access(&mut app_access::SystemStore, listing, target, tag, allow) {
            Ok(()) => Reply::Done,
            Err(app_access::SetError::Unknown) => Reply::Unavailable,
            Err(app_access::SetError::Failed | app_access::SetError::Controlled) => Reply::Failed,
        }
    }

    fn valid_store_id(id: &str) -> bool {
        (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
    }

    fn store_id(index: u16) -> Option<&'static str> {
        secblitz::debloat::catalog()
            .get(usize::from(index))
            .and_then(|app| app.store_id)
            .filter(|id| valid_store_id(id))
    }

    fn store_install(store_id: &str) -> Option<std::process::Child> {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let winget = secblitz::software_install::winget_path().ok()?;
        Command::new(winget)
            .args([
                "install",
                "--id",
                store_id,
                "--source",
                "msstore",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--exact",
                "--silent",
                "--disable-interactivity",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    }

    fn store_jobs() -> &'static std::sync::Mutex<std::collections::HashMap<u16, std::process::Child>>
    {
        static JOBS: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<u16, std::process::Child>>,
        > = std::sync::OnceLock::new();
        JOBS.get_or_init(Default::default)
    }

    fn start_store_app(index: u16) -> Reply {
        let Some(store_id) = store_id(index) else {
            return Reply::Unavailable;
        };
        let Ok(mut jobs) = store_jobs().lock() else {
            return Reply::Failed;
        };
        if jobs.contains_key(&index) {
            return Reply::Done;
        }
        match store_install(store_id) {
            Some(child) => {
                jobs.insert(index, child);
                Reply::Done
            }
            None => Reply::Failed,
        }
    }

    fn store_app_status(index: u16) -> Reply {
        let Ok(mut jobs) = store_jobs().lock() else {
            return Reply::Failed;
        };
        let Some(child) = jobs.get_mut(&index) else {
            return Reply::Unavailable;
        };
        let code = match child.try_wait() {
            Ok(None) => return Reply::Working,
            Ok(Some(status)) => status.code().map(|c| c as u32),
            Err(_) => None,
        };
        jobs.remove(&index);
        if code == Some(0) {
            Reply::Done
        } else if code.is_some_and(secblitz::software_install::is_offline_code)
            || secblitz::software_install::dns_offline()
        {
            Reply::Offline
        } else {
            Reply::Failed
        }
    }

    fn reinstall_store_app(index: u16) -> Reply {
        let Some(store_id) = store_id(index) else {
            return Reply::Unavailable;
        };
        let exit = store_install(store_id).and_then(|mut child| {
            let deadline = std::time::Instant::now() + Duration::from_secs(14 * 60);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Some(status.code().map(|c| c as u32)),
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(500))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                }
            }
        });
        if exit == Some(Some(0)) {
            return Reply::Done;
        }
        let code = exit.flatten();
        if code.is_some_and(secblitz::software_install::is_offline_code)
            || secblitz::software_install::dns_offline()
        {
            return Reply::Offline;
        }
        let uri = wide(&format!("ms-windows-store://pdp/?ProductId={store_id}"));
        let verb = wide("open");
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                uri.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result as usize > 32 {
            Reply::OpenedStore
        } else {
            Reply::Failed
        }
    }

    pub struct Namespace(HANDLE);
    impl Drop for Namespace {
        fn drop(&mut self) {
            unsafe {
                ClosePrivateNamespace(self.0, 0);
            }
        }
    }

    struct Boundary(HANDLE);
    impl Drop for Boundary {
        fn drop(&mut self) {
            unsafe { DeleteBoundaryDescriptor(self.0) }
        }
    }

    struct Sid(PSID);
    impl Drop for Sid {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    fn sid(text: &str) -> Result<Sid> {
        let mut raw: PSID = null_mut();
        if unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut raw) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Sid(raw))
    }

    fn private_namespace() -> Result<Namespace> {
        let raw = unsafe { CreateBoundaryDescriptorW(wide("Secblitz").as_ptr(), 0) };
        ensure!(!raw.is_null(), "boundary descriptor unavailable");
        let mut boundary = Boundary(raw);
        let admins = sid("S-1-5-32-544")?;
        let high = sid("S-1-16-12288")?;
        unsafe {
            ensure!(
                AddSIDToBoundaryDescriptor(&mut boundary.0, admins.0) != 0
                    && AddIntegrityLabelToBoundaryDescriptor(&mut boundary.0, high.0) != 0,
                "boundary descriptor rejected"
            );
        }
        let sddl = wide("D:P(A;;GA;;;BA)(A;;GA;;;SY)");
        let mut descriptor: *mut c_void = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let prefix = wide("Secblitz");
        let mut handle =
            unsafe { CreatePrivateNamespaceW(&attributes, boundary.0, prefix.as_ptr()) };
        if handle.is_null() && unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            handle = unsafe { OpenPrivateNamespaceW(boundary.0, prefix.as_ptr()) };
        }
        let error = std::io::Error::last_os_error();
        unsafe { LocalFree(descriptor) };
        if handle.is_null() {
            return Err(error.into());
        }
        Ok(Namespace(handle))
    }

    pub fn single_instance(open: Option<&str>) -> Result<Instance> {
        let mut session = 0u32;
        unsafe { ProcessIdToSessionId(std::process::id(), &mut session) };
        let namespace = private_namespace().ok();
        let name = match namespace {
            Some(_) => wide(&format!("Secblitz\\Gui-{session}")),
            None => wide("Local\\SecblitzGui"),
        };
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let handle = Owned(handle);
        if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Ok(Instance::First(Guard {
                _handle: handle,
                _namespace: namespace,
            }));
        }
        for _ in 0..20 {
            if show_existing(open) {
                return Ok(Instance::Existing);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(Instance::Existing)
    }

    struct Search {
        exe: String,
        found: Option<(HANDLE, u32)>,
    }

    unsafe extern "system" fn visit(hwnd: HANDLE, param: isize) -> BOOL {
        let search = &mut *(param as *mut Search);
        if IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let mut title = [0u16; 64];
        let n = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
        if n <= 0 || String::from_utf16_lossy(&title[..n as usize]) != "Secblitz" {
            return 1;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        let same = broker::image_path(pid)
            .map(|p| p.eq_ignore_ascii_case(&search.exe))
            .unwrap_or(false);
        if !same || pid == std::process::id() {
            return 1;
        }
        search.found = Some((hwnd, pid));
        0
    }

    fn existing_window() -> Option<(HANDLE, u32)> {
        let exe = std::env::current_exe().ok()?;
        let mut search = Search {
            exe: exe.to_string_lossy().into_owned(),
            found: None,
        };
        unsafe {
            EnumWindows(Some(visit), &mut search as *mut Search as isize);
        }
        search.found
    }

    /// Brings the open window forward on the asked page; false when none is open.
    fn show_existing(open: Option<&str>) -> bool {
        let Some((hwnd, pid)) = existing_window() else {
            return false;
        };
        crate::app::open_request::write(open.unwrap_or(""), crate::app::history::now());
        // Windows stops a process without administrator rights from restoring an
        // administrator window, so the window restores itself and needs leave to
        // come to the front.
        unsafe {
            AllowSetForegroundWindow(pid);
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            SetForegroundWindow(hwnd);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_clean_site_name_follows_the_plain_words() {
        let words = |last: &str| -> Vec<String> {
            ["--lang", "en", "filter", "allow-once", last]
                .map(String::from)
                .into()
        };
        assert!(site_args_are_plain(&words("evil-site.example")));
        assert!(site_args_are_plain(&words("a_b.example")));
        for bad in [
            "Evil.example",
            "evil.example.",
            "evil.example evil2.example",
            "evil.example\\",
            "\"evil.example",
            "evil",
            "",
            "-x.example",
        ] {
            assert!(!site_args_are_plain(&words(bad)), "{bad}");
        }
        assert!(!site_args_are_plain(&[]));
        let mut loose = words("evil.example");
        loose[2] = "filter now".into();
        assert!(!site_args_are_plain(&loose));
    }

    #[test]
    fn unix_start_problems_keep_their_text_and_are_translated() {
        for known in [NOT_INSTALLED, SESSION_UNUSUAL] {
            let chained = format!("{known}: Permission denied (os error 13)");
            assert_eq!(friendly_problem(&chained), known);
            for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
                assert_ne!(lang.t(known), known, "{lang:?}");
            }
        }
    }

    #[test]
    fn known_start_problems_get_a_fix_and_unknown_ones_get_the_general_text() {
        assert!(friendly_problem("The administrator prompt was declined").contains("choose Yes"));
        assert!(friendly_problem("Secblitz requires Windows").contains("Windows 10"));
        let damaged =
            friendly_problem("Secblitz's undo history is damaged: Invalid journal record");
        assert!(
            damaged.contains("Start fresh") && !damaged.contains("Restart"),
            "{damaged}"
        );
        for raw in [
            "The monitor requires 64-bit Windows",
            "Secblitz supports 64-bit Windows only",
            "Web protection requires 64-bit Windows",
        ] {
            assert!(friendly_problem(raw).contains("Windows 10"), "{raw}");
        }
        assert!(
            friendly_problem("Another Secblitz operation holds the journal lock").contains("busy")
        );
        let raw = "zxq 0x80004005 src/engine.rs:42 panicked";
        let text = friendly_problem(raw);
        assert!(text.starts_with("Something unexpected"));
        assert!(!text.contains("0x8") && !text.contains("engine.rs"));
    }

    #[test]
    fn broad_words_do_not_misroute() {
        for raw in [
            "blocked by policy",
            "clock skew",
            "unlock failed",
            "invalid argument",
            "bad schema",
        ] {
            assert!(
                friendly_problem(raw).starts_with("Something unexpected"),
                "{raw}"
            );
        }
    }

    #[test]
    fn check_problems_say_to_check_again() {
        let text = friendly_check_problem("The administrator prompt was declined");
        assert!(text.contains("Press Check again") && !text.contains("open"));
        assert!(friendly_check_problem("Secblitz requires Windows").contains("Windows 10"));
        assert!(
            friendly_check_problem("Secblitz's undo history is damaged").contains("Start fresh")
        );
    }

    #[test]
    fn open_names_only_known_pages() {
        for page in ["protection", "web", "tools", "history"] {
            assert_eq!(open_page(page), Some(page));
        }
        assert_eq!(open_page("Protection"), Some("protection"));
        for other in [
            "",
            "home",
            "settings",
            "fixes",
            "../x",
            "protection ",
            "web&x",
        ] {
            assert_eq!(open_page(other), None, "{other}");
        }
    }

    #[test]
    fn the_elevated_copy_gets_the_page_as_plain_words() {
        let id = "a".repeat(32);
        let with = gui_args(&id, Lang::En, Some("web"));
        assert_eq!(with[with.len() - 2..], ["--open", "web"]);
        assert!(args_are_plain(&with));
        let none = gui_args(&id, Lang::En, None);
        assert!(!none.iter().any(|a| a == "--open"));
        let unknown = gui_args(&id, Lang::En, Some("x y; calc"));
        assert_eq!(unknown, none);
    }

    #[test]
    fn elevation_arguments_are_plain_words_only() {
        let ok: Vec<String> = ["gui", "--broker", &"a".repeat(32), "--lang", "en"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(args_are_plain(&ok));
        for bad in ["a b", "a&b", "a\"b", "", "..\\x", "a;b"] {
            assert!(!args_are_plain(&[bad.to_string()]), "{bad}");
        }
    }
}
