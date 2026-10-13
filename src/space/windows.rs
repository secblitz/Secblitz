use super::{
    clean, component_cleanup_outcome, measure, single_file, Entry, Fs, Item, Rule, Tally, UserArea,
    CLEAN_BUDGET, DUMP_RULE, MEASURE_BUDGET, TEMP_RULE, THUMB_RULE,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    ffi::OsString,
    io::{Error, ErrorKind},
    mem::{size_of, zeroed},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND,
        FILETIME, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FileBasicInfo, FileDispositionInfo, FileStandardInfo, FindClose,
        FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
        GetDiskFreeSpaceExW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
        SetFileInformationByHandle, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FIND_FIRST_EX_LARGE_FETCH, OPEN_EXISTING, VOLUME_NAME_DOS, WIN32_FIND_DATAW,
    },
    System::{Com::CoTaskMemFree, SystemInformation::GetSystemWindowsDirectoryW},
    UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
    },
};

const TICKS_PER_SECOND: u64 = 10_000_000;
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
const PATH_LIMIT: usize = 32_768;

fn unix_seconds(ticks: u64) -> u64 {
    ticks.saturating_sub(UNIX_EPOCH_TICKS) / TICKS_PER_SECOND
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle returned by CreateFileW and closed once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct FindHandle(HANDLE);
impl Drop for FindHandle {
    fn drop(&mut self) {
        // SAFETY: a handle returned by FindFirstFileExW and closed once.
        unsafe {
            FindClose(self.0);
        }
    }
}

/// The long-path form of an absolute drive path. Anything else is refused, so a name can never
/// be read as a device path, a network path or a relative path.
fn api_path(path: &Path) -> std::io::Result<Vec<u16>> {
    let mut parts = path.components();
    let drive = matches!(
        parts.next(),
        Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))
    );
    let plain = parts.all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !drive || !plain {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "not a plain drive path",
        ));
    }
    let mut wide: Vec<u16> = r"\\?\".encode_utf16().collect();
    wide.extend(path.as_os_str().encode_wide());
    if wide.contains(&0) {
        return Err(Error::new(ErrorKind::InvalidInput, "path holds a NUL"));
    }
    wide.push(0);
    Ok(wide)
}

fn last_error() -> Error {
    Error::last_os_error()
}

fn open(path: &Path, access: u32, shared: bool) -> std::io::Result<Handle> {
    let wide = api_path(path)?;
    let sharing = if shared {
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    } else {
        FILE_SHARE_READ
    };
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            sharing,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(last_error())
    } else {
        Ok(Handle(h))
    }
}

fn final_path(handle: &Handle) -> std::io::Result<PathBuf> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: the buffer length is passed with the buffer.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle.0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return Err(last_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            break;
        }
        if n > PATH_LIMIT {
            return Err(Error::new(ErrorKind::InvalidData, "path too long"));
        }
        buf.resize(n + 1, 0);
    }
    let text = OsString::from_wide(&buf);
    let text = text.to_string_lossy();
    let drive_form = text.strip_prefix(r"\\?\").filter(|rest| {
        let b = rest.as_bytes();
        b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
    });
    Ok(PathBuf::from(drive_form.unwrap_or(&text)))
}

fn info<T>(handle: &Handle, class: i32) -> std::io::Result<T> {
    // SAFETY: the buffer is a zeroed plain-data struct of exactly the size the class needs.
    unsafe {
        let mut out: T = zeroed();
        if GetFileInformationByHandleEx(
            handle.0,
            class,
            (&mut out as *mut T).cast(),
            size_of::<T>() as u32,
        ) == 0
        {
            return Err(last_error());
        }
        Ok(out)
    }
}

/// What the handle itself says, not what an earlier listing said.
fn entry_from_handle(handle: &Handle) -> std::io::Result<Entry> {
    let basic: FILE_BASIC_INFO = info(handle, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = info(handle, FileStandardInfo)?;
    Ok(Entry {
        path: final_path(handle)?,
        is_dir: basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        reparse: basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        size: standard.EndOfFile.max(0) as u64,
        created: unix_seconds(basic.CreationTime.max(0) as u64),
        written: unix_seconds(basic.LastWriteTime.max(0) as u64),
    })
}

/// Plain delete-on-close: a file that is read-only, or that a program still holds, is not
/// removed.
fn mark_for_deletion(handle: &Handle) -> std::io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: a valid handle and a struct of the size the class expects.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle.0,
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

fn gone(error: &Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32
    )
}

struct WinFs;

impl Fs for WinFs {
    fn list(&self, dir: &Path, max: usize) -> std::io::Result<Vec<Entry>> {
        let mut pattern = api_path(dir)?;
        pattern.pop();
        pattern.extend(r"\*".encode_utf16());
        pattern.push(0);
        // SAFETY: the pattern is NUL-terminated; the find data is plain data the call fills in.
        let mut data: WIN32_FIND_DATAW = unsafe { zeroed() };
        let found = unsafe {
            FindFirstFileExW(
                pattern.as_ptr(),
                FindExInfoBasic,
                (&mut data as *mut WIN32_FIND_DATAW).cast(),
                FindExSearchNameMatch,
                null(),
                FIND_FIRST_EX_LARGE_FETCH,
            )
        };
        if found == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        let find = FindHandle(found);
        let mut out = Vec::new();
        loop {
            let len = data
                .cFileName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(data.cFileName.len());
            let name = OsString::from_wide(&data.cFileName[..len]);
            if name != "." && name != ".." {
                let attrs = data.dwFileAttributes;
                out.push(Entry {
                    path: dir.join(&name),
                    is_dir: attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
                    reparse: attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                    size: (u64::from(data.nFileSizeHigh) << 32) | u64::from(data.nFileSizeLow),
                    created: unix_seconds(filetime(&data.ftCreationTime)),
                    written: unix_seconds(filetime(&data.ftLastWriteTime)),
                });
            }
            if out.len() >= max {
                return Ok(out);
            }
            // SAFETY: a live find handle and the same data buffer.
            if unsafe { FindNextFileW(find.0, &mut data) } == 0 {
                if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                    return Ok(out);
                }
                return Err(last_error());
            }
        }
    }

    fn delete_checked(
        &self,
        path: &Path,
        shared: bool,
        check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        // The handle is opened, checked and marked for deletion, so a swap after the walk cannot
        // send the delete somewhere else.
        let handle = match open(path, DELETE | FILE_READ_ATTRIBUTES, shared) {
            Ok(h) => h,
            Err(e) if gone(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        let fresh = entry_from_handle(&handle)?;
        if fresh.is_dir || fresh.reparse || !check(&fresh) {
            return Ok(false);
        }
        mark_for_deletion(&handle)?;
        Ok(true)
    }

    fn remove_empty_dir(
        &self,
        path: &Path,
        shared: bool,
        check: &dyn Fn(&Entry) -> bool,
    ) -> std::io::Result<bool> {
        let handle = match open(path, DELETE | FILE_READ_ATTRIBUTES, shared) {
            Ok(h) => h,
            Err(e) if gone(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        let fresh = entry_from_handle(&handle)?;
        if !fresh.is_dir || fresh.reparse || !check(&fresh) {
            return Ok(false);
        }
        mark_for_deletion(&handle)?;
        Ok(true)
    }
}

fn filetime(ft: &FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// The folder as Windows spells it, with short names and links resolved, so the containment
/// check compares like with like. A folder that is itself a link is refused.
fn canonical_root(path: &Path) -> Option<PathBuf> {
    let handle = open(path, FILE_READ_ATTRIBUTES, true).ok()?;
    let entry = entry_from_handle(&handle).ok()?;
    (entry.is_dir && !entry.reparse).then_some(entry.path)
}

fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    let mut raw = null_mut();
    // SAFETY: valid GUID and out pointer; the allocation is freed below even after a failure.
    let hr = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, null_mut(), &mut raw) };
    let path = if hr >= 0 && !raw.is_null() {
        let mut len = 0;
        // SAFETY: success returns a NUL-terminated string; the scan is bounded.
        while len < PATH_LIMIT && unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units were read above.
        let units = unsafe { std::slice::from_raw_parts(raw, len) };
        (len < PATH_LIMIT).then(|| PathBuf::from(OsString::from_wide(units)))
    } else {
        None
    };
    // SAFETY: null or the allocation returned above.
    unsafe { CoTaskMemFree(raw.cast()) };
    path.filter(|p| p.is_absolute())
}

fn windows_dir() -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    // SAFETY: the length is passed with the buffer.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(OsString::from_wide(&buf[..n])))
}

fn user_rule(area: UserArea) -> &'static Rule {
    match area {
        UserArea::Temp => &TEMP_RULE,
        UserArea::CrashDumps => &DUMP_RULE,
        UserArea::Thumbnails => &THUMB_RULE,
    }
}

/// The signed-in person's own folders. Always under their local app data folder as Windows
/// reports it; the TEMP variable is not trusted to point somewhere safe.
pub fn user_roots(area: UserArea) -> Vec<PathBuf> {
    let Some(local) = known_folder(&FOLDERID_LocalAppData) else {
        return Vec::new();
    };
    let folder = match area {
        UserArea::Temp => local.join("Temp"),
        UserArea::CrashDumps => local.join("CrashDumps"),
        UserArea::Thumbnails => local.join("Microsoft").join("Windows").join("Explorer"),
    };
    canonical_root(&folder).into_iter().collect()
}

pub fn machine_roots(item: Item) -> Vec<(PathBuf, &'static Rule)> {
    let Some(win) = windows_dir() else {
        return Vec::new();
    };
    let folders: Vec<(PathBuf, &'static Rule)> = match item {
        Item::Temp => vec![(win.join("Temp"), &TEMP_RULE)],
        Item::CrashDumps => {
            let mut v = vec![
                (win.join("Minidump"), &DUMP_RULE),
                (win.join("LiveKernelReports"), &DUMP_RULE),
            ];
            if let Some(data) = known_folder(&FOLDERID_ProgramData) {
                let wer = data.join("Microsoft").join("Windows").join("WER");
                v.push((wer.join("ReportArchive"), &DUMP_RULE));
                v.push((wer.join("ReportQueue"), &DUMP_RULE));
            }
            v
        }
        Item::UpdateLeftovers | Item::Thumbnails => Vec::new(),
    };
    folders
        .into_iter()
        .filter_map(|(path, rule)| canonical_root(&path).map(|root| (root, rule)))
        .collect()
}

pub fn measure_user(area: UserArea) -> Tally {
    run_user(area, false)
}

pub fn clean_user(area: UserArea) -> Tally {
    run_user(area, true)
}

fn run_user(area: UserArea, delete: bool) -> Tally {
    let rule = user_rule(area);
    let deadline = Instant::now() + if delete { CLEAN_BUDGET } else { MEASURE_BUDGET };
    let mut total = Tally::default();
    for root in user_roots(area) {
        total.add(if delete {
            clean(&WinFs, &root, rule, now(), deadline)
        } else {
            measure(&WinFs, &root, rule, now(), deadline)
        });
    }
    total
}

fn run_machine(item: Item, delete: bool) -> Tally {
    let deadline = Instant::now() + if delete { CLEAN_BUDGET } else { MEASURE_BUDGET };
    let mut total = Tally::default();
    for (root, rule) in machine_roots(item) {
        total.add(if delete {
            clean(&WinFs, &root, rule, now(), deadline)
        } else {
            measure(&WinFs, &root, rule, now(), deadline)
        });
    }
    if item == Item::CrashDumps {
        if let Some(win) = windows_dir().and_then(|w| canonical_root(&w)) {
            total.add(single_file(
                &WinFs,
                &win,
                "MEMORY.DMP",
                &DUMP_RULE,
                now(),
                delete,
            ));
        }
    }
    total
}

pub fn measure_machine(item: Item) -> Tally {
    match item {
        Item::UpdateLeftovers => Tally {
            bytes: delivery_cache_bytes().unwrap_or(0),
            ..Tally::default()
        },
        _ => run_machine(item, false),
    }
}

pub fn clean_machine(item: Item) -> Result<Tally> {
    match item {
        Item::UpdateLeftovers => clean_update_leftovers(),
        _ => Ok(run_machine(item, true)),
    }
}

fn run_json(script: &str, timeout: Duration) -> Result<Value> {
    crate::platform::run_json(script, timeout)
}

fn delivery_cache_bytes() -> Option<u64> {
    let reply = run_json(
        "$WarningPreference = 'SilentlyContinue'; [pscustomobject]@{ bytes = [int64](Get-DeliveryOptimizationPerfSnap).CacheSizeBytes } | ConvertTo-Json -Compress",
        Duration::from_secs(60),
    )
    .ok()?;
    reply.get("bytes")?.as_u64()
}

fn free_bytes() -> Option<u64> {
    let win = windows_dir()?;
    let mut wide: Vec<u16> = win.as_os_str().encode_wide().collect();
    wide.push(0);
    let (mut caller, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: NUL-terminated path and three valid out pointers.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut caller, &mut total, &mut free) };
    (ok != 0).then_some(free)
}

// The Servicing\StartComponentCleanup task can sit queued for a long time when started on
// demand, so this runs the same cleanup through the inbox DISM module and reports its result.
const COMPONENT_CLEANUP: &str = r"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
$modules = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$null = Import-Module ([IO.Path]::Combine($modules, 'Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1'))
$null = Import-Module ([IO.Path]::Combine($modules, 'Dism\Dism.psd1'))
$code = 0
try { $null = Repair-WindowsImage -Online -StartComponentCleanup -NoRestart } catch { $code = [int64]$_.Exception.HResult }
[pscustomobject]@{ code = $code } | ConvertTo-Json -Compress
";

fn clean_update_leftovers() -> Result<Tally> {
    let before = free_bytes();
    let reply = crate::platform::run_dism_json(COMPONENT_CLEANUP, Duration::from_secs(60 * 60))
        .context("Windows could not tidy the leftovers from updates")?;
    component_cleanup_outcome(&reply)?;
    let _ = run_json(
        "$WarningPreference = 'SilentlyContinue'; Delete-DeliveryOptimizationCache -Force; [pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress",
        Duration::from_secs(5 * 60),
    );
    let bytes = match (before, free_bytes()) {
        (Some(before), Some(after)) => after.saturating_sub(before),
        _ => 0,
    };
    Ok(Tally {
        bytes,
        ..Tally::default()
    })
}
