use super::Target;
use anyhow::{ensure, Context, Result};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, IsWellKnownSid, LookupPrivilegeValueW,
    TokenElevationType, TokenElevationTypeFull, TokenUser, WinLocalServiceSid, WinLocalSystemSid,
    WinNetworkServiceSid, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION_TYPE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Shutdown::InitiateShutdownW;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::ShellExecuteW;

const SETTINGS_UNAVAILABLE: &str = "Windows could not open settings";
const RESTART_REFUSED: &str =
    "Windows would not let us restart this computer. Restart it from the Start menu instead.";

/// The current process token, closed on drop.
struct Token(HANDLE);

impl Token {
    fn open(access: u32) -> Option<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the current-process pseudo handle is always valid and `token` is a valid out pointer.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) };
        (ok != 0).then_some(Self(token))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

fn enable_shutdown_privilege(token: &Token) -> bool {
    let name = wide("SeShutdownPrivilege");
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: `name` is NUL-terminated UTF-16 and `luid` is a valid out pointer.
    if unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut luid) } == 0 {
        return false;
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: the token is live with TOKEN_ADJUST_PRIVILEGES and `privileges` outlives the call.
    // GetLastError must be read right after, because success can still mean "not all assigned".
    unsafe {
        AdjustTokenPrivileges(token.0, 0, &privileges, 0, null_mut(), null_mut()) != 0
            && GetLastError() != ERROR_NOT_ALL_ASSIGNED
    }
}

/// Planned "Security fix" restart through the shutdown API. Open programs may still stop it, so unsaved work is never lost.
pub(super) fn restart_for_updates() -> Result<()> {
    let token = Token::open(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY).context(RESTART_REFUSED)?;
    let enabled = enable_shutdown_privilege(&token);
    drop(token);
    ensure!(enabled, RESTART_REFUSED);
    // SAFETY: null machine and message select this PC with no message text.
    let code = unsafe {
        InitiateShutdownW(
            null(),
            null(),
            0,
            super::RESTART_FLAGS,
            super::RESTART_REASON,
        )
    };
    ensure!(
        code == 0,
        "Windows could not start the restart. Restart it from the Start menu instead."
    );
    Ok(())
}

/// Elevated half of a split token only: a full-token administrator reports TokenElevationTypeDefault but may open pages.
pub fn split_token_elevated() -> Result<bool> {
    let token = Token::open(TOKEN_QUERY).context(SETTINGS_UNAVAILABLE)?;
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut len = 0u32;
    // SAFETY: `kind` is a live TOKEN_ELEVATION_TYPE and the length passed is exactly its size.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            (&mut kind as *mut TOKEN_ELEVATION_TYPE).cast(),
            std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut len,
        )
    };
    ensure!(ok != 0, SETTINGS_UNAVAILABLE);
    Ok(kind == TokenElevationTypeFull)
}

/// LocalSystem, LocalService and NetworkService also report TokenElevationTypeDefault; pages are for signed-in people only.
fn service_account() -> Result<bool> {
    let token = Token::open(TOKEN_QUERY).context(SETTINGS_UNAVAILABLE)?;
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    // 8-byte aligned buffer for the TOKEN_USER the call fills in.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    ensure!(ok != 0, SETTINGS_UNAVAILABLE);
    // SAFETY: the successful call filled `buf` with an aligned TOKEN_USER, and the SID it points to lives in `buf`.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    Ok(
        [WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid]
            .into_iter()
            // SAFETY: `sid` stays valid while `buf` is alive.
            .any(|kind| unsafe { IsWellKnownSid(sid, kind) } != 0),
    )
}

const CONTROL_SWITCH: &str = "/name";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub(super) fn open(target: Target) -> Result<()> {
    // Check the actual token here, even when a caller bypasses the UI routing.
    ensure!(
        !service_account()?,
        "Open Settings from the non-elevated interactive application"
    );
    let split = split_token_elevated()?;
    match target {
        Target::Uri(uri) => {
            super::validate_settings_request(uri, split)?;
            shell_open(&wide(uri), None)
        }
        Target::Control(name) => {
            super::validate_control_request(name, split)?;
            // control.exe by absolute path under the system directory: never
            // found through PATH or the current directory. It is a windowed
            // program, so no console appears.
            let mut buf = [0u16; 260];
            // SAFETY: the pointer and length describe `buf`.
            let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
            ensure!(n > 0 && n < buf.len(), SETTINGS_UNAVAILABLE);
            let dir = String::from_utf16(&buf[..n])?;
            let exe = format!("{dir}\\control.exe");
            shell_open(
                &wide(&exe),
                Some(&wide(&format!("{} {}", CONTROL_SWITCH, name))),
            )
        }
    }
}

fn shell_open(file: &[u16], params: Option<&[u16]>) -> Result<()> {
    let verb = wide("open");
    // SAFETY: every string is NUL-terminated UTF-16 that outlives the call; null is allowed for the rest.
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.map_or(null(), |p| p.as_ptr()),
            null(),
            1,
        )
    } as isize;
    ensure!(
        result > 32,
        "Windows could not open settings (ShellExecute code {result})"
    );
    Ok(())
}
