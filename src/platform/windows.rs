use super::validate_value;
use crate::model::{Backend, Control, Finding, Observation};
use anyhow::{bail, ensure, Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{
    ffi::{c_void, OsStr},
    io::{Read, Write},
    mem::{size_of, zeroed},
    os::windows::{ffi::OsStrExt, io::AsRawHandle, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    ptr::{null, null_mut},
    sync::mpsc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{SystemInformation::GetWindowsDirectoryW, Threading::*},
    UI::Shell::*,
};

#[path = "journal.rs"]
mod journal;
#[path = "vbs_native.rs"]
mod vbs_native;
pub use journal::{create_private_dir, state_dir};

/// Runs a fixed script through the hidden PowerShell runner and returns its JSON reply.
pub(crate) fn run_json(script: &str, timeout: Duration) -> Result<Value> {
    run_script(script.to_owned(), timeout)
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(s: impl AsRef<OsStr>) -> Result<Vec<u16>> {
    let mut v: Vec<_> = s.as_ref().encode_wide().collect();
    ensure!(!v.contains(&0), "Embedded NUL in Windows string");
    v.push(0);
    Ok(v)
}
fn winerr() -> anyhow::Error {
    std::io::Error::last_os_error().into()
}

fn windows_dir() -> Result<PathBuf> {
    let mut buf = vec![0u16; 32768];
    let n = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    ensure!(
        n > 0 && n < buf.len(),
        "Cannot resolve trusted Windows directory"
    );
    let p = PathBuf::from(String::from_utf16(&buf[..n])?);
    ensure!(p.is_absolute(), "Windows directory is not absolute");
    Ok(p)
}

#[cfg(target_arch = "x86_64")]
pub fn x64_on_arm() -> bool {
    use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM64;
    let (mut process, mut native) = (0u16, 0u16);
    // SAFETY: both out-pointers are valid for the call and the handle is the current process.
    let ok = unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) };
    ok != 0 && native == IMAGE_FILE_MACHINE_ARM64
}

pub fn windows_home() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let mut buf = [0u16; 64];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: both names are NUL-terminated; `buf` and `size` describe one writable buffer.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").as_ptr(),
            wide("EditionID").as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    let len = (size as usize / 2).saturating_sub(1).min(buf.len());
    status == 0 && String::from_utf16_lossy(&buf[..len]).starts_with("Core")
}

/// The running account's own temp folder, from its profile rather than inherited variables.
/// Windows PowerShell 5.1 locks itself down when it cannot write its policy test file, and
/// without TEMP it falls back to the Windows folder, which LocalService cannot write.
pub fn own_temp_dir() -> Option<PathBuf> {
    let mut raw = null_mut();
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            KF_FLAG_DONT_VERIFY as u32,
            null_mut(),
            &mut raw,
        )
    };
    let path = (hr >= 0 && !raw.is_null()).then(|| {
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        PathBuf::from(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(raw, len)
        }))
    });
    unsafe { windows_sys::Win32::System::Com::CoTaskMemFree(raw.cast()) };
    let temp = path?.join("Temp");
    (temp.is_absolute() && temp.is_dir()).then_some(temp)
}

pub fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(winerr());
        }
        let token = Handle(token);
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut elevation: TOKEN_ELEVATION = zeroed();
        let mut len = 0;
        if GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        ) == 0
        {
            return Err(winerr());
        }
        ensure!(
            len as usize == size_of::<TOKEN_ELEVATION>(),
            "Invalid elevation information"
        );
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn quote_arg(s: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in s.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            out.push_str(&"\\".repeat(slashes));
        }
        slashes = 0;
        out.push(ch);
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}
pub fn elevate(args: &[String]) -> Result<()> {
    let exe = wide(std::env::current_exe()?.as_os_str())?;
    let params = wide(
        args.iter()
            .map(|s| quote_arg(s))
            .collect::<Vec<_>>()
            .join(" "),
    )?;
    let cwd = wide(windows_dir()?.join("System32"))?;
    let verb = wide("runas")?;
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            params.as_ptr(),
            cwd.as_ptr(),
            1,
        )
    } as isize;
    ensure!(
        result > 32,
        "Elevation was cancelled or failed (ShellExecute code {result})"
    );
    Ok(())
}

#[repr(C)]
struct BasicLimits {
    process_time: i64,
    job_time: i64,
    flags: u32,
    min_working_set: usize,
    max_working_set: usize,
    active_processes: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}
#[repr(C)]
struct IoCounters {
    counts: [u64; 6],
}
#[repr(C)]
struct ExtendedLimits {
    basic: BasicLimits,
    io: IoCounters,
    process_memory: usize,
    job_memory: usize,
    peak_process_memory: usize,
    peak_job_memory: usize,
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *const SECURITY_ATTRIBUTES, name: *const u16) -> HANDLE;
    fn SetInformationJobObject(job: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) -> i32;
    fn IsProcessInJob(process: HANDLE, job: HANDLE, result: *mut i32) -> i32;
    fn QueryInformationJobObject(
        job: HANDLE,
        class: i32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
}

/// The job another program started this process in (Program Compatibility Assistant does this for Explorer launches).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclosingJob {
    None,
    Breakaway,
    Locked,
}

pub fn enclosing_job() -> Result<EnclosingJob> {
    let mut in_job = 0;
    if unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job) } == 0 {
        return Err(winerr());
    }
    if in_job == 0 {
        return Ok(EnclosingJob::None);
    }
    // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
    let mut limits: ExtendedLimits = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            null_mut(),
            9, // JobObjectExtendedLimitInformation
            (&mut limits as *mut ExtendedLimits).cast(),
            size_of::<ExtendedLimits>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(winerr());
    }
    Ok(if limits.basic.flags & 0x800 != 0 {
        EnclosingJob::Breakaway
    } else {
        EnclosingJob::Locked
    })
}

pub fn enclosing_job_contains(pid: u32) -> Result<bool> {
    const CAPACITY: usize = 4096;
    // JOBOBJECT_BASIC_PROCESS_ID_LIST: two u32 counts, then pointer-sized ids.
    let mut list = vec![0usize; 1 + CAPACITY];
    if unsafe {
        QueryInformationJobObject(
            null_mut(),
            3, // JobObjectBasicProcessIdList
            list.as_mut_ptr().cast(),
            (list.len() * size_of::<usize>()) as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(winerr());
    }
    let assigned = list[0] & 0xFFFF_FFFF;
    let listed = list[0] >> 32;
    ensure!(
        listed == assigned && listed <= CAPACITY,
        "Incomplete enclosing job process list"
    );
    Ok(list[1..=listed].contains(&(pid as usize)))
}
/// `processes` is the job's active-process limit: 1 (PowerShell only, no
/// descendants) everywhere except the one DISM feature write.
fn job(processes: u32) -> Result<Handle> {
    unsafe {
        let h = CreateJobObjectW(null(), null());
        ensure!(
            !h.is_null(),
            "Cannot create bounded process job: {}",
            winerr()
        );
        let h = Handle(h);
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut limits: ExtendedLimits = zeroed();
        limits.basic.flags = 0x2000 | 0x8; // KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
        limits.basic.active_processes = processes;
        if SetInformationJobObject(
            h.0,
            9,
            &limits as *const _ as *const c_void,
            size_of::<ExtendedLimits>() as u32,
        ) == 0
        {
            return Err(winerr());
        }
        Ok(h)
    }
}
fn run<T: DeserializeOwned>(action: &str, id: Option<&str>, value: Option<&Value>) -> Result<T> {
    ensure!(
        crate::platform::NATIVE_64,
        "Secblitz supports 64-bit Windows only"
    );
    super::validate_request(action, id, value)?;
    if let Some(id) = id.filter(|id| crate::hardening::is_hardening_check_id(id)) {
        // Changing a Windows feature goes through DISM, which is slow and
        // works through its own DismHost.exe helper. Only that fixed, compiled
        // write may start helpers; every other script runs with no descendants.
        // Turning the recovery tools on or off goes through the inbox
        // ReAgentc.exe, which copies the recovery image: only that write may
        // start it. Reading their state never needs a helper. Random Wi-Fi
        // addresses are changed with the inbox netsh.exe in the same way.
        let (limit, processes) = match (id, action) {
            ("ps.v2_engine" | "smb1.disabled", "write") => (900, DISM_PROCESSES),
            ("recovery.winre_enabled", "write") => (600, RECOVERY_PROCESSES),
            ("privacy.wifi_random_address", "write") => (60, WIFI_PROCESSES),
            _ => (90, 1),
        };
        return run_script_in(
            super::hardening_script(action, id, value)?,
            Duration::from_secs(limit),
            processes,
        );
    }
    let script = format!(
        "$action='{action}'\n$id='{}'\n$inputJson={}\n{}",
        id.unwrap_or(""),
        value
            .map(|v| super::ps_text(&v.to_string()))
            .unwrap_or_else(|| "$null".into()),
        include_str!("backend.ps1")
    );
    run_script(script, Duration::from_secs(90))
}

pub fn permission_gate(id: &str) -> Result<()> {
    let reply: Value = run("permission_gate", Some(id), None)?;
    super::validate_permission_reply(&reply)
}

pub fn support_action(id: &str) -> Result<()> {
    let script = super::support_script(id)?;
    ensure!(
        crate::platform::NATIVE_64,
        "Secblitz supports 64-bit Windows only"
    );
    crate::platform::require_admin("Defender support actions require Administrator elevation")?;
    let timeout = match id {
        "defender_update" => Duration::from_secs(120),
        "defender_quickscan" => Duration::from_secs(15 * 60),
        _ => bail!("Unknown support action id"),
    };
    let reply: Value = run_script(script, timeout).context(
        "Defender support action failed; work may continue in Defender. Review Windows Security; no completion or rollback is assumed")?;
    ensure!(
        reply == serde_json::json!({"ok":true}),
        "Defender command return was not acknowledged; review Windows Security"
    );
    Ok(())
}

pub fn remove_threats() -> Result<super::ThreatRemoval> {
    let script = super::threats_script()?;
    ensure!(
        crate::platform::NATIVE_64,
        "Secblitz supports 64-bit Windows only"
    );
    crate::platform::require_admin("Defender support actions require Administrator elevation")?;
    let reply: Value = run_script(script, Duration::from_secs(10 * 60))
        .context("Windows Security could not finish removing them. Nothing else was changed")?;
    super::parse_threat_reply(&reply)
}

/// The script lists firmware boot entries with the inbox bcdedit.exe, so one helper may start.
const RENEWAL_PROCESSES: u32 = 2;

pub fn start_secure_boot_renewal() -> Result<super::RenewalOutcome> {
    let script = super::renewal_script()?;
    ensure!(
        crate::platform::NATIVE_64,
        "Secblitz supports 64-bit Windows only"
    );
    crate::platform::require_admin("The startup security renewal needs Administrator elevation")?;
    let reply: Value = run_script_in(script, Duration::from_secs(150), RENEWAL_PROCESSES)
        .context("Windows could not start the renewal. Check again in a few minutes")?;
    super::parse_renewal_reply(&reply)
}

const DISM_PROCESSES: u32 = 4;
const RECOVERY_PROCESSES: u32 = 4;
const WIFI_PROCESSES: u32 = 4;

fn run_script<T: DeserializeOwned>(script: String, timeout: Duration) -> Result<T> {
    run_script_in(script, timeout, 1)
}

fn run_script_in<T: DeserializeOwned>(
    script: String,
    timeout: Duration,
    processes: u32,
) -> Result<T> {
    let win = windows_dir()?;
    let ps = win.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    // Only this small fixed bootstrap is on the command line, in plain text
    // (Windows has a 32K command-line limit). It holds no double quote, so it
    // stays one argument. All inserted data is validated booleans, fixed enum
    // strings, or a strict numeric registry object. The embedded script arrives
    // over a private pipe.
    // PowerShell 5.1 module initialization reports progress in the outer host
    // scope as CLIXML on stderr, even when the invoked script suppresses its
    // own progress. Set this before creating/invoking the script block. Keep
    // stderr rejection: real errors must not be filtered out as "progress".
    let bootstrap = "$global:ProgressPreference = 'SilentlyContinue'; [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); & ([ScriptBlock]::Create([Console]::In.ReadToEnd()))";
    let job = job(processes)?;
    let mut command = Command::new(ps);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            // The script itself comes from stdin and is not a file, so policy only
            // touches the inbox module files it imports. Those are local, so the
            // RemoteSigned policy always allows them; nothing needs Bypass.
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            bootstrap,
        ])
        .env_clear()
        .env("SystemRoot", &win)
        .env("WINDIR", &win)
        .env("PATH", win.join("System32"))
        .env(
            "PSModulePath",
            win.join("System32/WindowsPowerShell/v1.0/Modules"),
        )
        .env("PSModuleAnalysisCachePath", "NUL")
        .current_dir(win.join("System32"))
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(temp) = own_temp_dir() {
        command.env("TEMP", &temp).env("TMP", &temp);
    }
    let mut child = command.spawn().context("Start inbox Windows PowerShell")?;
    // The fixed script waits on stdin before any probes. Failure to assign never
    // releases that gate. Job closure kills PowerShell and disallows descendants.
    if unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) } == 0 {
        let e = winerr();
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.context("Assign PowerShell job"));
    }
    let result = (|| -> Result<T> {
        let mut input = child.stdin.take().context("Missing stdin")?;
        let writer = std::thread::spawn(move || input.write_all(script.as_bytes()));
        let (tx, rx) = mpsc::sync_channel(16);
        fn pump(
            mut r: impl Read + Send + 'static,
            tx: mpsc::SyncSender<(bool, std::io::Result<Vec<u8>>)>,
            err: bool,
        ) {
            std::thread::spawn(move || loop {
                let mut b = vec![0; 8192];
                let result = r.read(&mut b).map(|n| {
                    b.truncate(n);
                    b
                });
                let done = result.as_ref().map_or(true, Vec::is_empty);
                if tx.send((err, result)).is_err() || done {
                    break;
                }
            });
        }
        pump(
            child.stdout.take().context("Missing stdout")?,
            tx.clone(),
            false,
        );
        pump(child.stderr.take().context("Missing stderr")?, tx, true);
        let deadline = Instant::now() + timeout;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut eof = 0;
        while eof < 2 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("PowerShell timed out; mutation outcome may be unknown")?;
            let (err, bytes) = rx
                .recv_timeout(remaining)
                .context("PowerShell output timeout/disconnect; mutation outcome may be unknown")?;
            let bytes = bytes?;
            if bytes.is_empty() {
                eof += 1;
                continue;
            }
            ensure!(
                stdout.len() + stderr.len() + bytes.len() <= 2 * 1024 * 1024,
                "PowerShell exceeded 2 MiB output limit; mutation outcome may be unknown"
            );
            if err {
                stderr.extend(bytes);
            } else {
                stdout.extend(bytes);
            }
        }
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            ensure!(
                Instant::now() < deadline,
                "PowerShell exit timed out; mutation outcome may be unknown"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        ensure!(
            status.success() && stderr.is_empty(),
            "PowerShell failed ({status}): {}",
            crate::text::excerpt(&String::from_utf8_lossy(&stderr), 300)
        );
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("PowerShell input writer failed"))??;
        serde_json::from_slice(&stdout).context("Invalid PowerShell response (no result assumed)")
    })();
    drop(job);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

struct WindowsBackend;
pub fn backend() -> Result<Box<dyn Backend>> {
    ensure!(
        crate::platform::NATIVE_64,
        "Secblitz supports 64-bit Windows only"
    );
    // Fail early if the trusted inbox interpreter is absent. OS/client capability
    // gates run independently before every mutation, not just construction.
    ensure!(
        windows_dir()?
            .join("System32/WindowsPowerShell/v1.0/powershell.exe")
            .is_file(),
        "Inbox Windows PowerShell is unavailable"
    );
    Ok(Box::new(WindowsBackend))
}
fn observe_one(id: &str) -> Result<Observation> {
    let mut obs: Observation = run("observe", Some(id), None)?;
    validate_value(id, &obs.value)?;
    crate::model::validate_observation(id, &obs)?;
    vbs_gate(id, &mut obs);
    Ok(obs)
}

/// Memory integrity and kernel stack protection are only offered when it is
/// safe on this PC: supported hardware, nothing locked, and every driver
/// passing the static scan. The extra checks run only for a fix that would be
/// offered, so a safe state and an undo are never held back by them. Any
/// doubt means "not offered", never a guess.
fn vbs_gate(id: &str, obs: &mut Observation) {
    use crate::vbs::{decide, Decision};
    let Some(spec) = crate::hardening::spec(id).filter(|_| crate::vbs::is_vbs_check_id(id)) else {
        return;
    };
    if !obs.eligible || !spec.any_unsafe(&obs.value) {
        return;
    }
    let verdict = (|| -> Result<Decision> {
        let facts = vbs_native::facts()?;
        let windows = windows_dir()?.to_string_lossy().into_owned();
        let cpu = crate::vbs::cpu_has_shadow_stacks();
        Ok(decide(id, &facts, cpu, &mut || {
            vbs_native::scan_drivers(&windows)
        }))
    })();
    match verdict {
        Ok(Decision::Offer) => {}
        Ok(Decision::NotOffered(reason)) => {
            obs.eligible = false;
            obs.reason = reason;
        }
        Err(_) => {
            obs.eligible = false;
            obs.reason = crate::vbs::UNREADABLE.into();
        }
    }
}
impl Backend for WindowsBackend {
    fn machine_id(&mut self) -> Result<String> {
        let id: String = run("machine", None, None)?;
        uuid::Uuid::parse_str(&id).context("Invalid Windows machine identity")?;
        Ok(id)
    }
    fn controls(&self) -> Vec<Control> {
        super::controls()
    }
    fn observe(&mut self, id: &str) -> Result<Observation> {
        observe_one(id)
    }
    fn observe_many(&mut self, ids: &[&str]) -> Vec<Result<Observation>> {
        std::thread::scope(|s| {
            let reads: Vec<_> = ids
                .iter()
                .map(|id| s.spawn(move || observe_one(id)))
                .collect();
            reads
                .into_iter()
                .map(|read| {
                    read.join().unwrap_or_else(|_| {
                        Err(anyhow::anyhow!(
                            "Some details for a check could not be read."
                        ))
                    })
                })
                .collect()
        })
    }
    fn write(&mut self, id: &str, value: &Value) -> Result<()> {
        validate_value(id, value)?;
        crate::platform::require_admin("Administrator elevation is required")?;
        let reply: Value = run("write", Some(id), Some(value))?;
        ensure!(
            reply == serde_json::json!({"ok":true}),
            "Write was not acknowledged"
        );
        let actual = self.observe(id)?;
        // Dynamic controls may see items that appeared since; compare only the
        // items that were written.
        let seen = match crate::hardening::spec(id) {
            Some(spec) => spec.view(&actual.value, value),
            None => actual.value.clone(),
        };
        ensure!(
            &seen == value,
            "Preference readback did not match; mutation outcome requires review"
        );
        Ok(())
    }
    fn findings(&mut self) -> Result<Vec<Finding>> {
        let mut found: Vec<Finding> = run("findings", None, None)?;
        found.extend(vbs_native::verification_findings());
        Ok(found)
    }
    fn readiness(&mut self) -> crate::model::Readiness {
        crate::readiness::collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_arguments() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("C:\\"), "\"C:\\\\\"");
    }
    #[test]
    fn native_boundary_rejects_unknown_requests_before_launch() {
        for id in [
            "",
            "defender_update ",
            "Defender_update",
            "defender.realtime",
            "defender_update'; exit",
            "defender_quickscan\0",
        ] {
            assert!(support_action(id)
                .unwrap_err()
                .to_string()
                .contains("Unknown support action"));
        }
        for action in [
            "defender_update",
            "defender_quickscan",
            "support",
            "write; exit",
        ] {
            assert!(run::<Value>(action, None, None)
                .unwrap_err()
                .to_string()
                .contains("Invalid platform action"));
        }
        for id in [
            "defender_update",
            "defender_quickscan",
            "defender.realtime; exit",
        ] {
            assert!(
                run::<Value>("write", Some(id), Some(&serde_json::json!(false)))
                    .unwrap_err()
                    .to_string()
                    .contains("Unknown control id")
            );
        }
    }
    #[test]
    fn inbox_powershell_pipe_encoding_and_output_bounds() {
        let reply: String = run_script(
            "[Console]::Write('\"Grüße 世界\"')".into(),
            Duration::from_secs(15),
        )
        .unwrap();
        assert_eq!(reply, "Grüße 世界");
        assert!(run_script::<Value>(
            "[Console]::Error.Write('fixture error'); [Console]::Write('{}')".into(),
            Duration::from_secs(15)
        )
        .is_err());
        assert!(run_script::<Value>(
            "[Console]::Write(('x' * 2200000))".into(),
            Duration::from_secs(15)
        )
        .is_err());
        let start = Instant::now();
        let error = run_script::<Value>(
            "[Threading.Thread]::Sleep(60000)".into(),
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("timeout") || format!("{error:#}").contains("timed out")
        );
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "Timeout failed to bound the child process"
        );
    }
    #[test]
    fn inbox_powershell_actual_backend_read_only() {
        // Synthetic Console.Write tests don't initialize the inbox modules and
        // missed 5.1's outer-scope CLIXML progress. Exercise real production
        let mut backend = WindowsBackend;
        let machine = backend
            .machine_id()
            .expect("Actual machine probe must not emit progress on stderr");
        uuid::Uuid::parse_str(&machine).unwrap();
        let observation = backend
            .observe("uac.enabled")
            .expect("Actual observation transport");
        validate_value("uac.enabled", &observation.value).unwrap();
        assert!(!observation.reason.is_empty());
        let findings = backend
            .findings()
            .expect("Actual findings must be a single valid JSON array");
        assert_eq!(findings.len(), 13);
        let mut titles = std::collections::HashSet::new();
        for finding in findings {
            assert!(titles.insert(finding.title));
            assert!(matches!(
                finding.status.as_str(),
                "ok" | "info" | "attention" | "unknown"
            ));
            assert!(!finding.detail.is_empty());
        }
    }
    #[test]
    fn inbox_powershell_native_mdm_registration() {
        // Exercise the real .NET Framework P/Invoke emitter and inbox DLL,
        // without requiring the machine to be unmanaged or weakening Gate.
        // An Observation alone would hide an emitter/API error as ineligible.
        let source = include_str!("backend.ps1").replace('\'', "''");
        let script = format!(
            r#"
$source='{source}'
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'Backend parse failed' }}
foreach ($node in $ast.EndBlock.Statements) {{
    if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('QueryMdmRegistration','MdmRegistered')) {{
        . ([scriptblock]::Create($node.Extent.Text))
    }}
}}
if (MdmRegistered) {{ [Console]::Write('true') }} else {{ [Console]::Write('false') }}
"#
        );
        let _: bool = run_script(script, Duration::from_secs(30))
            .expect("Documented MDM registration API probe");
    }
}
