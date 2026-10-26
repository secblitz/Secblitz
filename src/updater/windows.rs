use super::*;
use fs2::FileExt;
use std::{
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::Write,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, CREATE_NO_WINDOW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
    UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};

#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(p: *const c_void);
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
    fn Process32FirstW(snapshot: HANDLE, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: HANDLE, entry: *mut ProcessEntry) -> i32;
}
#[repr(C)]
struct ProcessEntry {
    size: u32,
    usage: u32,
    pid: u32,
    heap: usize,
    module: u32,
    threads: u32,
    parent: u32,
    priority: i32,
    flags: u32,
    exe: [u16; 260],
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
fn sid(s: &str) -> Result<Local> {
    let mut p = null_mut();
    ensure!(
        unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut p) } != 0,
        "SID conversion failed"
    );
    Ok(Local(p))
}
fn inspect(f: &File, directory: bool, strict: bool, ancestor: bool) -> Result<()> {
    inspect_pinned(f, directory, strict, ancestor, false)
}
fn inspect_pinned(
    f: &File,
    directory: bool,
    strict: bool,
    ancestor: bool,
    system_image: bool,
) -> Result<()> {
    unsafe {
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut i: BY_HANDLE_FILE_INFORMATION = zeroed();
        ensure!(
            GetFileInformationByHandle(f.as_raw_handle(), &mut i) != 0,
            "File inspection failed"
        );
        ensure!(
            i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && (i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory
                && (directory || i.nNumberOfLinks == 1 || system_image),
            "Unsafe update object"
        );
        let (mut owner, mut acl, mut sd) = (null_mut(), null_mut(), null_mut());
        ensure!(
            GetSecurityInfo(
                f.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut sd
            ) == 0,
            "Security inspection failed"
        );
        let _sd = Local(sd);
        let root = ancestor && crate::platform::security::is_volume_root(f);
        inspect_acl(owner, acl, directory, strict, ancestor, root)?;
    }
    Ok(())
}
unsafe fn inspect_acl(
    owner: PSID,
    acl: *mut ACL,
    directory: bool,
    strict: bool,
    ancestor: bool,
    root: bool,
) -> Result<()> {
    unsafe {
        let sy = sid("S-1-5-18")?;
        let ba = sid("S-1-5-32-544")?;
        let ti = sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")?;
        let trusted = |s| {
            EqualSid(s, sy.0) != 0 || EqualSid(s, ba.0) != 0 || (!strict && EqualSid(s, ti.0) != 0)
        };
        ensure!(
            !owner.is_null() && IsValidSid(owner) != 0 && trusted(owner),
            "Untrusted update owner"
        );
        ensure!(
            !acl.is_null() && IsValidAcl(acl) != 0,
            "Missing update DACL"
        );
        for n in 0..(*acl).AceCount as u32 {
            let mut p = null_mut();
            ensure!(GetAce(acl, n, &mut p) != 0, "ACE query failed");
            let h = &*(p as *const ACE_HEADER);
            ensure!(
                h.AceType <= 1 && h.AceSize as usize >= size_of::<ACCESS_ALLOWED_ACE>(),
                "Unsupported update ACE"
            );
            if h.AceFlags & INHERIT_ONLY_ACE as u8 != 0 || h.AceType == 1 {
                continue;
            }
            let a = &*(p as *const ACCESS_ALLOWED_ACE);
            let s = &a.SidStart as *const u32 as *mut c_void;
            let len = h.AceSize as usize - 8;
            ensure!(
                len >= 8 && 8 + *s.cast::<u8>().add(1) as usize * 4 <= len && IsValidSid(s) != 0,
                "Invalid ACE SID"
            );
            if !trusted(s) {
                let benign = if strict {
                    0
                } else if directory && ancestor {
                    // Default ProgramData grants Users child creation plus EA/
                    // attribute writes (0x116). These do not authorize replacing
                    // the protected child or changing its DACL. Ancestors retain
                    // trusted owners and data/list-access pins denying deletion;
                    // DAC/owner/delete/delete-child and generic write stay denied.
                    FILE_GENERIC_READ
                        | FILE_GENERIC_EXECUTE
                        | FILE_ADD_FILE
                        | FILE_ADD_SUBDIRECTORY
                        | FILE_WRITE_EA
                        | FILE_WRITE_ATTRIBUTES
                        | GENERIC_READ
                        | GENERIC_EXECUTE
                        | if root {
                            crate::platform::security::VOLUME_ROOT_EXTRA
                        } else {
                            0
                        }
                } else {
                    FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | GENERIC_READ | GENERIC_EXECUTE
                };
                ensure!(
                    a.Mask & !benign == 0,
                    "Untrusted update write/execution rights"
                );
            }
        }
    }
    Ok(())
}
fn open(path: &Path, directory: bool, strict: bool) -> Result<File> {
    open_object(path, directory, strict, false)
}
fn open_object(path: &Path, directory: bool, strict: bool, ancestor: bool) -> Result<File> {
    open_pinned(path, directory, strict, ancestor, false)
}
fn open_pinned(
    path: &Path,
    directory: bool,
    strict: bool,
    ancestor: bool,
    system_image: bool,
) -> Result<File> {
    // Directory-entry operations need write sharing on the parent. Keep list
    // (data) access and deny delete sharing so the directory itself stays pinned.
    // Payload handles must still exclude both writers and replacement.
    let (access, sharing) = if directory {
        (
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    } else {
        (GENERIC_READ | READ_CONTROL, FILE_SHARE_READ)
    };
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            sharing,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    ensure!(
        h != INVALID_HANDLE_VALUE,
        "Cannot pin update object: {}",
        std::io::Error::last_os_error()
    );
    let f = unsafe { File::from_raw_handle(h) };
    inspect_pinned(&f, directory, strict, ancestor, system_image)?;
    Ok(f)
}
fn create(path: &Path) -> Result<File> {
    let mut p = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)").as_ptr(),
                1,
                &mut p,
                null_mut(),
            )
        } != 0,
        "Cannot build update DACL"
    );
    let _sd = Local(p);
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: p,
        bInheritHandle: 0,
    };
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0,
            &sa,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    ensure!(
        h != INVALID_HANDLE_VALUE,
        "Cannot exclusively create update file: {}",
        std::io::Error::last_os_error()
    );
    let f = unsafe { File::from_raw_handle(h) };
    inspect(&f, false, true, false)?;
    Ok(f)
}
fn replace(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    replace_with(root, name, |file| Ok(file.write_all(bytes)?))
}
fn exists_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
struct PendingReplacement {
    file: Option<File>,
    path: Option<PathBuf>,
}
impl Drop for PendingReplacement {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path); // Only this call's exclusively created UUID file.
        }
    }
}
fn replace_with(
    root: &Path,
    name: &str,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    let path = root.join(name);
    // Root is pinned and SYSTEM/Admin-only; no unverified bytes enter a payload
    // here. A failed write/flush/rename must leave the previous destination intact.
    let temp = root.join(format!("update-tmp-{}.tmp", uuid::Uuid::new_v4()));
    let file = create(&temp)?;
    let mut pending = PendingReplacement {
        file: Some(file),
        path: Some(temp),
    };
    let file = pending.file.as_mut().unwrap();
    write(file)?;
    file.sync_all()?;
    drop(pending.file.take());
    if exists_no_follow(&path)? {
        let f = open(&path, false, true)?;
        drop(f);
    }
    ensure!(
        unsafe {
            MoveFileExW(
                wide(pending.path.as_ref().unwrap()).as_ptr(),
                wide(&path).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } != 0,
        "Atomic update replacement failed: {}",
        std::io::Error::last_os_error()
    );
    pending.path = None;
    Ok(())
}
fn read_floor(root: &Path) -> Result<Option<ReleaseFloor>> {
    let path = root.join("release-floor.json");
    if !exists_no_follow(&path)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    open(&path, false, true)?
        .take((FLOOR_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(Some(parse_floor(&bytes)?))
}
// Both callers hold update.lock. Persist before download/launch, including an
// UpToDate feed, so a failed payload does not forget the highest signed release.
fn remember_release(root: &Path, m: &Manifest, current: &str) -> Result<()> {
    let previous = read_floor(root)?;
    let floor = advance_floor(m, current, previous.as_ref())?;
    if previous.as_ref() != Some(&floor) {
        let bytes = serde_json::to_vec(&floor)?;
        ensure!(bytes.len() <= FLOOR_LIMIT, "Release floor too large");
        replace(root, "release-floor.json", &bytes)?;
    }
    Ok(())
}
fn read_bounded(root: &Path, name: &str, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open(&root.join(name), false, true)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "Protected updater state too large");
    Ok(bytes)
}
fn read_delivery(root: &Path, origin: &reqwest::Url) -> Result<Option<delivery::Authorization>> {
    if !exists_no_follow(&root.join(arch::DELIVERY_FLOOR))? {
        return Ok(None);
    }
    Ok(Some(delivery::decode(
        &read_bounded(root, arch::DELIVERY_FLOOR, MANIFEST_LIMIT)?,
        &key()?,
        origin,
    )?))
}
fn device_id(root: &Path, create_missing: bool) -> Result<[u8; 16]> {
    let name = "rollout-device-id";
    if !exists_no_follow(&root.join(name))? {
        ensure!(create_missing, "Missing staged rollout identity");
        // Local random identity, never sent to the server. Persist under the
        // updater lock with the same protected ACL as floors; never regenerate
        // malformed state. Cloned state intentionally retains its cohort.
        replace(root, name, uuid::Uuid::new_v4().as_bytes())?;
    }
    read_bounded(root, name, 16)?
        .try_into()
        .map_err(|v: Vec<u8>| {
            eprintln!("{} bytes", v.len());
            anyhow::anyhow!("Invalid rollout identity")
        })
}
fn select_delivery(
    client: &reqwest::blocking::Client,
    root: &Path,
    origin: &reqwest::Url,
) -> Result<Option<delivery::Authorization>> {
    let previous = read_delivery(root, origin)?;
    let response = client.get(origin.join(arch::DELIVERY_FEED)?).send()?;
    if response.status() == reqwest::StatusCode::NOT_FOUND && previous.is_none() {
        return Ok(None);
    }
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Delivery metadata missing or unavailable"
    );
    let mut raw = Vec::new();
    response
        .take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut raw)?;
    let a = delivery::decode(&raw, &key()?, origin)?;
    delivery::fresh(&a, now()?)?;
    delivery::advance(&a, previous.as_ref())?;
    ensure!(
        stable(&a.version)? >= stable(env!("CARGO_PKG_VERSION"))?,
        "Delivery downgrade rejected"
    );
    // Commit authorization before fetching the candidate: stale keys cannot be
    // revived by a failed download, crash, deletion/404, or v1 fallback.
    if previous.as_ref() != Some(&a) {
        replace(root, arch::DELIVERY_FLOOR, &raw)?;
    }
    Ok(Some(a))
}
fn lock(root: &Path, name: &str) -> Result<Option<File>> {
    let path = root.join(name);
    if !path.try_exists()? {
        match create(&path) {
            Ok(f) => drop(f),
            Err(_) if path.try_exists()? => {}
            Err(e) => return Err(e),
        }
    }
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    inspect(&f, false, true, false)?;
    match f.try_lock_exclusive() {
        Ok(()) => Ok(Some(f)),
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn installed() -> Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?
        .join("Secblitz")
        .join("secblitz.exe"))
}
fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    let mut p = null_mut();
    ensure!(
        unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut p) } >= 0 && !p.is_null(),
        "Native machine known folder unavailable"
    );
    let result = (|| {
        // SAFETY: success returns a NUL-terminated UTF-16 string, freed only below.
        let text =
            unsafe { crate::platform::security::wide_str(p) }.context("Invalid known folder")?;
        Ok(PathBuf::from(String::from_utf16(text)?))
    })();
    unsafe {
        CoTaskMemFree(p.cast());
    }
    result
}
fn same(a: &Path, b: &Path) -> bool {
    a.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
}
fn trusted_installed(path: &Path) -> Result<Vec<File>> {
    trusted_image(path, false)
}
fn require_local_path(path: &Path) -> Result<()> {
    let mut components = path.components();
    ensure!(
        matches!(components.next(), Some(std::path::Component::Prefix(p))
            if matches!(p.kind(), std::path::Prefix::Disk(_)))
            && matches!(components.next(), Some(std::path::Component::RootDir))
            && components.all(|c| matches!(c, std::path::Component::Normal(_))),
        "Updater path must be an absolute local drive path"
    );
    Ok(())
}
fn trusted_image(path: &Path, system_image: bool) -> Result<Vec<File>> {
    ensure!(
        crate::platform::NATIVE_64,
        "Updates require native 64-bit Windows"
    );
    require_local_path(path)?;
    let mut prefix = PathBuf::new();
    let mut held = Vec::new();
    for c in path.components() {
        prefix.push(c.as_os_str());
        if matches!(c, std::path::Component::Prefix(_)) {
            continue;
        }
        held.push(open_pinned(
            &prefix,
            prefix != path,
            false,
            Some(prefix.as_path()) != path.parent() && prefix != path,
            system_image && prefix == path,
        )?);
    }
    Ok(held)
}
fn require_admin() -> Result<()> {
    crate::platform::require_admin("Updates require elevation")?;
    let admin = sid("S-1-5-32-544")?;
    let mut member = 0;
    ensure!(
        unsafe { CheckTokenMembership(null_mut(), admin.0, &mut member) } != 0 && member != 0,
        "Updates require an enabled Administrators token (including LocalSystem)"
    );
    Ok(())
}
fn update_root() -> Result<(PathBuf, Vec<File>)> {
    let base = crate::platform::state_dir()?;
    let mut held = Vec::new();
    let mut prefix = PathBuf::new();
    for c in base.components() {
        prefix.push(c.as_os_str());
        if matches!(c, std::path::Component::Prefix(_)) {
            continue;
        }
        // Independently inspect ancestor DACLs and pin with READ_DATA, not only
        // READ_ATTRIBUTES: metadata-only handles do not reliably block renames.
        held.push(open_object(&prefix, true, prefix == base, prefix != base)?);
    }
    let root = base.join("Updates");
    held.push(protected_update_directory(&root)?);
    Ok((root, held))
}
fn protected_update_directory(path: &Path) -> Result<File> {
    let mut sd = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").as_ptr(),
                1,
                &mut sd,
                null_mut(),
            )
        } != 0,
        "Cannot build update directory DACL"
    );
    let _sd = Local(sd);
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &sa) } == 0 {
        ensure!(
            unsafe { GetLastError() } == ERROR_ALREADY_EXISTS,
            "Cannot create protected update directory: {}",
            std::io::Error::last_os_error()
        );
    }
    // Never repair/adopt a foreign directory. Validate the opened, non-reparse
    // object even after ERROR_ALREADY_EXISTS, while the base is already pinned.
    pin_update_directory(path)
}
fn pin_update_directory(path: &Path) -> Result<File> {
    pin_private_directory(path, true)
}
fn pin_private_directory(path: &Path, exact: bool) -> Result<File> {
    let f = open(path, true, true)?;
    unsafe {
        let (mut acl, mut actual_sd) = (null_mut(), null_mut());
        ensure!(
            GetSecurityInfo(
                f.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut actual_sd
            ) == 0,
            "Cannot inspect update directory DACL"
        );
        let _actual_sd = Local(actual_sd);
        let (mut control, mut revision) = (0, 0);
        ensure!(
            GetSecurityDescriptorControl(actual_sd, &mut control, &mut revision) != 0
                && control & SE_DACL_PROTECTED != 0
                && !acl.is_null()
                && (!exact || (*acl).AceCount == 2),
            "Update directory requires a protected SYSTEM/Administrators DACL"
        );
        let system = sid("S-1-5-18")?;
        let admins = sid("S-1-5-32-544")?;
        let (mut seen_system, mut seen_admins) = (false, false);
        for n in 0..(*acl).AceCount as u32 {
            let mut ace = null_mut();
            ensure!(
                GetAce(acl, n, &mut ace) != 0,
                "Update directory ACE query failed"
            );
            let a = &*(ace as *const ACCESS_ALLOWED_ACE);
            ensure!(
                a.Header.AceType == 0
                    && a.Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                        == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                    && a.Header.AceFlags
                        & !(OBJECT_INHERIT_ACE
                            | CONTAINER_INHERIT_ACE
                            | if exact { 0 } else { INHERITED_ACE })
                            as u8
                        == 0
                    && a.Mask == FILE_ALL_ACCESS,
                "Unexpected update directory ACE"
            );
            let trustee = &a.SidStart as *const u32 as PSID;
            seen_system |= EqualSid(trustee, system.0) != 0;
            seen_admins |= EqualSid(trustee, admins.0) != 0;
        }
        ensure!(
            seen_system && seen_admins,
            "Missing update directory trustees"
        );
    }
    Ok(f)
}
fn engine_lock_root(root: &Path) -> Result<&Path> {
    let base = root.parent().context("Missing update base")?;
    let expected = known_folder(&FOLDERID_ProgramData)?.join("Secblitz");
    ensure!(
        same(base, &expected) && same(root, &expected.join("Updates")),
        "Unexpected protected update layout"
    );
    Ok(base)
}

pub(crate) struct LockedEngineRoot {
    pub(crate) base: PathBuf,
    _pins: Vec<File>,
}
pub(crate) fn inspect_engine_lock(held: &File) -> Result<LockedEngineRoot> {
    let base = known_folder(&FOLDERID_ProgramData)?.join("Secblitz");
    require_local_path(&base)?;
    let mut pins = Vec::new();
    let mut prefix = PathBuf::new();
    for part in base.components() {
        prefix.push(part.as_os_str());
        if matches!(part, std::path::Component::Prefix(_)) {
            continue;
        }
        if matches!(part, std::path::Component::RootDir) {
            ensure!(
                unsafe { GetDriveTypeW(wide(&prefix).as_ptr()) } == 3,
                "Shared engine state requires a fixed local drive"
            );
        }
        pins.push(if prefix == base {
            pin_private_directory(&prefix, false)?
        } else {
            open_object(&prefix, true, false, true)?
        });
    }
    validate_engine_lock(held, &base)?;
    Ok(LockedEngineRoot { base, _pins: pins })
}
fn validate_engine_lock(held: &File, base: &Path) -> Result<()> {
    inspect(held, false, true, false)?;
    // OPEN_EXISTING only. A read-only inspector must never create a replacement
    // lock or adopt a foreign namespace, even when called with a wrong handle.
    let expected = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(base.join("engine.lock"))?;
    inspect(&expected, false, true, false)?;
    let id = |file: &File| -> Result<(u32, u32, u32)> {
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "Cannot inspect shared lock identity"
        );
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    };
    ensure!(
        id(held)? == id(&expected)?,
        "Different shared engine.lock object"
    );
    // Nonblocking misuse check, never a wait/reentrant acquisition. The caller
    // must hold its OWN handle, rather than rely on an unrelated owner's lock.
    match expected.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&expected)?;
            anyhow::bail!("Caller must retain its exclusive engine.lock");
        }
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Ok(()),
        Err(e) => Err(e.into()),
    }
}
pub(super) fn ensure_install_idle(held: &File) -> Result<()> {
    let root = inspect_engine_lock(held)?;
    inspect_install_state(&root.base)
}
fn inspect_install_state(base: &Path) -> Result<()> {
    let root = base.join("Updates");
    if !exists_no_follow(&root)? {
        return Ok(());
    }
    let _root = pin_update_directory(&root)?;
    if exists_no_follow(&root.join("install-attempt.json"))? {
        install_idle(&read_bounded(&root, "install-attempt.json", ATTEMPT_LIMIT)?)?;
    }
    Ok(())
}
// Never propagate caller-controlled COM/CLR/profiler, DLL search, proxy, or
// temporary-directory settings into privileged children.
fn child_command(path: &Path, root: &Path) -> Result<Command> {
    let mut buf = vec![0u16; 32768];
    let n = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    } as usize;
    ensure!(n > 0 && n < buf.len(), "Windows directory unavailable");
    let win = PathBuf::from(String::from_utf16(&buf[..n])?);
    ensure!(win.is_absolute(), "Windows directory is not absolute");
    let drive = match win.components().next() {
        Some(std::path::Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_)) => {
            p.as_os_str().to_owned()
        }
        _ => anyhow::bail!("Windows directory must be on a local drive"),
    };
    // All production callers retain update_root()'s validated namespace pins.
    // Known-folder registry paths may expand SystemDrive/ALLUSERSPROFILE even
    // under SYSTEM; omitting them breaks SHGetKnownFolderPath in clean children.
    let program_data = engine_lock_root(root)?
        .parent()
        .context("Missing ProgramData parent")?;
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("SystemRoot", &win)
        .env("WINDIR", &win)
        .env("SystemDrive", drive)
        .env("ProgramData", program_data)
        .env("ALLUSERSPROFILE", program_data)
        .env("PATH", win.join("System32"))
        .env("TEMP", root)
        .env("TMP", root)
        .current_dir(root)
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}
fn wait_read_only_child(child: &mut std::process::Child) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    wait_read_only_child_until(child, deadline)
}
fn wait_read_only_child_until(child: &mut std::process::Child, deadline: Instant) -> Result<()> {
    loop {
        if let Some(exit) = child.try_wait()? {
            ensure!(
                exit.success(),
                "Clean worker environment preflight failed ({exit})"
            );
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Clean worker environment preflight timed out"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
struct ReadOnlyChild(std::process::Child);
impl Drop for ReadOnlyChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
// A failed wait must not release the shared locks/payload pin while setup may
// still be running. Unlike read-only probes this guard never kills the child,
// including during unwinding. Persistent wait failure conservatively stays busy.
struct InstallerChild(std::process::Child);
impl Drop for InstallerChild {
    fn drop(&mut self) {
        while self.0.wait().is_err() {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
fn read_only_output(mut command: Command, limit: usize) -> Result<Vec<u8>> {
    read_only_output_until(
        &mut command,
        limit,
        Instant::now() + Duration::from_secs(30),
    )
}
fn read_only_output_until(
    command: &mut Command,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    read_only_output_fed(command, None, limit, deadline)
}
fn read_only_output_fed(
    command: &mut Command,
    input: Option<&'static str>,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = ReadOnlyChild(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    if let Some(text) = input {
        let mut stdin = child.0.stdin.take().context("Missing probe input")?;
        std::thread::spawn(move || {
            let _ = stdin.write_all(text.as_bytes());
        });
    }
    let mut stdout = child.0.stdout.take().context("Missing probe output")?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .by_ref()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = tx.send(result);
    });
    wait_read_only_child_until(&mut child.0, deadline)?;
    let bytes = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .context("Read-only probe output incomplete")??;
    ensure!(bytes.len() <= limit, "Read-only probe output too large");
    Ok(bytes)
}
fn preflight_worker(path: &Path, root: &Path) -> Result<()> {
    // Parent retains update.lock: status validates the native root first, then
    // returns DeferredBusy without waiting, networking, or launching an installer.
    let mut child = ReadOnlyChild(
        child_command(path, root)?
            .args(["update", "status", "--json"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    wait_read_only_child(&mut child.0)
}
const INSTALL_ARGS: [&str; 6] = [
    "/VERYSILENT",
    "/SUPPRESSMSGBOXES",
    "/NORESTART",
    "/SP-",
    "/TASKS=",
    "/SECBLITZUPDATE=1",
];
fn reported_version(bytes: &[u8]) -> Result<Version> {
    ensure!(bytes.len() <= 256, "Installed version output too large");
    let text = std::str::from_utf8(bytes)?.trim_end_matches(['\r', '\n']);
    stable(
        text.strip_prefix("secblitz ")
            .context("Unexpected installed product")?,
    )
}
fn validate_installed_version(path: &Path, root: &Path, expected: &str) -> Result<()> {
    // The signed installer is trusted to supply the executable; the manifest
    // authenticates the installer, not a separate hash of the resulting image.
    let _held = trusted_installed(path)?;
    let mut command = child_command(path, root)?;
    command.arg("--version");
    let bytes = read_only_output(command, 256)?;
    ensure!(
        reported_version(&bytes)? == stable(expected)?,
        "Installed version does not match signed release"
    );
    Ok(())
}
fn installation_health(path: &Path, root: &Path, version: &str) -> Result<UpdateHealth> {
    use windows_service::{
        service::{ServiceAccess, ServiceExitCode, ServiceState, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let _held = trusted_installed(path)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let monitor = match manager.open_service(
        "SecblitzMonitor",
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(service) => {
            let cfg = service.query_config()?;
            ensure!(
                cfg.executable_path == Path::new(&format!("\"{}\" service run", path.display()))
                    && cfg.service_type == ServiceType::OWN_PROCESS
                    && cfg.account_name.as_ref().is_some_and(|s| s
                        .to_string_lossy()
                        .eq_ignore_ascii_case(r"NT AUTHORITY\LocalService")),
                "Unexpected monitor configuration"
            );
            let status = service.query_status()?;
            // 1077 (ERROR_SERVICE_NEVER_STARTED): installed by Setup, starts
            // with the next restart. That is a normal stopped state.
            ensure!(
                status.exit_code == ServiceExitCode::Win32(0)
                    || (status.current_state == ServiceState::Stopped
                        && status.exit_code == ServiceExitCode::Win32(1077)),
                "Monitor reports a failure"
            );
            match status.current_state {
                ServiceState::Stopped => MonitorHealth::Stopped,
                ServiceState::Running => MonitorHealth::Running,
                _ => anyhow::bail!("Monitor state is not stable"),
            }
        }
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
            MonitorHealth::Absent
        }
        Err(e) => return Err(e.into()),
    };
    let mut buf = vec![0u16; 32768];
    let n = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    } as usize;
    ensure!(
        n > 0 && n < buf.len(),
        "Native system directory unavailable"
    );
    let powershell = PathBuf::from(String::from_utf16(&buf[..n])?)
        .join(r"WindowsPowerShell\v1.0\powershell.exe");
    // Windows-serviced system images may have WinSxS hardlinks. Permit those
    // only for this fixed native system tool; still pin the image against writes
    // through ANY link, reject reparse points, and validate owner/DACL/ancestors.
    // Installed Secblitz, staged workers and all updater data retain single-link
    // requirements. Never pass a metadata/caller-supplied path to this exception.
    let _shell_pins = trusted_image(&powershell, true)?;
    let mut command = child_command(&powershell, root)?;
    if let Some(home) = powershell.parent() {
        command.env("PSModulePath", home.join("Modules"));
    }
    // Only this fixed bootstrap is on the command line, in plain text. The
    // compiled probe arrives over a private pipe, as for every other script.
    let bootstrap = "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); & ([ScriptBlock]::Create([Console]::In.ReadToEnd()))";
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        bootstrap,
    ]);
    let bytes = read_only_output_fed(
        &mut command,
        Some(include_str!("health.ps1")),
        32,
        Instant::now() + Duration::from_secs(30),
    )?;
    let task = match std::str::from_utf8(&bytes)?.trim_end_matches(['\r', '\n']) {
        "absent" => TaskHealth::Absent,
        "ready" => TaskHealth::Ready,
        _ => anyhow::bail!("Unexpected task health output"),
    };
    Ok(UpdateHealth {
        schema: 1,
        version: version.into(),
        task,
        monitor,
    })
}
pub(super) fn health() -> Result<UpdateHealth> {
    require_admin()?;
    let path = installed()?;
    ensure!(
        same(&std::env::current_exe()?, &path),
        "Health must run from the installed executable"
    );
    let (root, _pins) = health_root()?;
    installation_health(&path, &root, env!("CARGO_PKG_VERSION"))
}
fn health_root() -> Result<(PathBuf, Vec<File>)> {
    let base = known_folder(&FOLDERID_ProgramData)?.join("Secblitz");
    let root = base.join("Updates");
    require_local_path(&root)?;
    engine_lock_root(&root)?;
    let mut held = Vec::new();
    let mut prefix = PathBuf::new();
    for component in root.components() {
        prefix.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        held.push(open_object(
            &prefix,
            true,
            prefix == base || prefix == root,
            prefix != base && prefix != root,
        )?);
    }
    Ok((root, held))
}
fn validate_installed_health(
    path: &Path,
    root: &Path,
    expected: &str,
    health: InstallHealth,
    before: &UpdateHealth,
) -> Result<()> {
    let _held = trusted_installed(path)?;
    validate_installed_version(path, root, expected)?;
    if matches!(health, InstallHealth::DeliveryV1) {
        let mut command = child_command(path, root)?;
        command.args(delivery::HealthCommand::UpdateHealthV1.args());
        health::validate(
            &read_only_output(command, health::LIMIT)?,
            expected,
            Some(before),
        )?;
    } else {
        // v1 can target older installed executables without the health CLI. An
        // independent query checks version plus task/service preservation. Never
        // fall back to this after a delivery-lane health command has failed.
        let after = installation_health(path, root, expected)?;
        health::validate(&serde_json::to_vec(&after)?, expected, Some(before))?;
    }
    Ok(())
}
fn remove_leftover(root: &Path, name: &str) -> Result<()> {
    let path = root.join(name);
    if !exists_no_follow(&path)? {
        return Ok(());
    }
    drop(open(&path, false, true)?);
    match fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}
// A file that cannot go now (scanner, sharing, rights) is left for the next
// hourly check. Cleanup never changes the update status or fails the check.
fn clean_leftovers(root: &Path, from_worker: bool) {
    let attempt = match read_attempt(root) {
        Ok(attempt) => attempt,
        Err(_) => return,
    };
    for name in leftover_files(attempt.as_ref(), from_worker) {
        if let Err(error) = remove_leftover(root, name) {
            eprintln!("Update leftover {name} kept: {error:#}");
        }
    }
}
fn read_attempt(root: &Path) -> Result<Option<InstallAttempt>> {
    if !exists_no_follow(&root.join("install-attempt.json"))? {
        return Ok(None);
    }
    parse_attempt(&read_bounded(root, "install-attempt.json", ATTEMPT_LIMIT)?)
}
fn write_attempt(root: &Path, attempt: Option<&InstallAttempt>) -> Result<()> {
    let bytes = serde_json::to_vec(&attempt)?;
    parse_attempt(&bytes)?;
    replace(root, "install-attempt.json", &bytes)
}
// A crash before recording that exit cannot prove whether setup is still alive
// (including extracted Inno children), so never replay setup or claim UpToDate.
fn recover_installation(root: &Path, path: &Path) -> Result<Option<UpdateOutcome>> {
    if !exists_no_follow(&root.join("install-attempt.json"))? {
        return Ok(None);
    }
    let Some(attempt) = parse_attempt(&read_bounded(root, "install-attempt.json", ATTEMPT_LIMIT)?)?
    else {
        return Ok(None);
    };
    // Keep the attempt on a publication failure. A crash between status and
    // this atomic reset simply repeats independent health checks on the retry.
    finish_attempt(
        &attempt,
        |a| validate_installed_health(path, root, &a.version, a.health, &a.before),
        |version| {
            record(
                root,
                UpdateOutcome::Installed {
                    version: version.into(),
                },
            )
        },
        || write_attempt(root, None),
    )
    .map(Some)
}
#[path = "tray_session.rs"]
mod tray_session;

fn busy(path: &Path, root: &Path) -> Result<bool> {
    Ok(scan_busy(path, root)?.0)
}
/// `(busy, tray pids)`. Tray agents (command line exactly `secblitz.exe tray`)
/// never make the app busy; they are returned so an update can ask them to exit
/// before installing. The monitor and web protection services never make it busy
/// either: the installer stops and restarts them. An unreadable command line is
/// conservatively busy.
fn scan_busy(path: &Path, root: &Path) -> Result<(bool, Vec<u32>)> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service_pid = |name: &str| -> Result<Option<u32>> {
        match manager.open_service(name, ServiceAccess::QUERY_STATUS) {
            Ok(s) => Ok(s.query_status()?.process_id),
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => Ok(None),
            Err(e) => Err(e.into()),
        }
    };
    let service_pids = [
        service_pid("SecblitzMonitor")?,
        service_pid(crate::filter::SERVICE_NAME)?,
    ];
    let snapshot = unsafe { CreateToolhelp32Snapshot(2, 0) }; // TH32CS_SNAPPROCESS
    ensure!(
        snapshot != INVALID_HANDLE_VALUE,
        "Cannot enumerate active sessions"
    );
    struct Snapshot(HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let _snapshot = Snapshot(snapshot);
    // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
    let mut entry: ProcessEntry = unsafe { zeroed() };
    entry.size = size_of::<ProcessEntry>() as u32;
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    let mut candidates = Vec::new();
    while ok != 0 {
        let n = entry
            .exe
            .iter()
            .position(|c| *c == 0)
            .context("Invalid process name")?;
        let name = String::from_utf16(&entry.exe[..n])?;
        if name.eq_ignore_ascii_case("secblitz.exe")
            || name.eq_ignore_ascii_case("update-installer.exe")
            || name.eq_ignore_ascii_case("update-worker.exe")
        {
            candidates.push(entry.pid);
        }
        ok = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    ensure!(
        unsafe { GetLastError() } == ERROR_NO_MORE_FILES,
        "Incomplete process enumeration"
    );
    let mut trays = Vec::new();
    for id in candidates {
        if id == std::process::id() || service_pids.contains(&Some(id)) {
            continue;
        }
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, id) };
        if h.is_null() {
            return Ok((true, trays)); // An uninspectable Secblitz session is conservatively busy.
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
        if ok == 0 {
            unsafe {
                CloseHandle(h);
            }
            return Ok((true, trays));
        }
        let image = PathBuf::from(String::from_utf16(&buf[..len as usize])?);
        // Also defer for an installer surviving a crashed worker. A portable UI
        // (or a same-named installer elsewhere) does not block the installed app.
        if same(&image, path) {
            let line = tray_session::command_line(h);
            unsafe {
                CloseHandle(h);
            }
            match line {
                Ok(line) if super::tray_cmd::is_tray_command_line(&line) => trays.push(id),
                _ => return Ok((true, trays)),
            }
            continue;
        }
        unsafe {
            CloseHandle(h);
        }
        if same(&image, &root.join("update-installer.exe"))
            || same(&image, &root.join("update-worker.exe"))
        {
            return Ok((true, trays));
        }
    }
    Ok((false, trays))
}
fn record(root: &Path, result: UpdateOutcome) -> Result<UpdateOutcome> {
    replace(
        root,
        "update-status.json",
        &serde_json::to_vec(&UpdateStatus {
            checked_at: now()?,
            result: result.clone(),
        })?,
    )?;
    Ok(result)
}
pub(super) fn status() -> Result<UpdateStatus> {
    if config()?.is_none() {
        return Ok(UpdateStatus {
            checked_at: now()?,
            result: UpdateOutcome::NotConfigured,
        });
    }
    let (root, _root_pins) = update_root()?;
    let Some(_lock) = lock(&root, "update.lock")? else {
        // A check or install is running right now. `checked_at: 0` tells
        // callers this is "in progress", not a recorded result.
        return Ok(UpdateStatus {
            checked_at: 0,
            result: UpdateOutcome::DeferredBusy,
        });
    };
    let p = root.join("update-status.json");
    if !p.try_exists()? {
        return Ok(UpdateStatus {
            checked_at: 0,
            result: UpdateOutcome::NotConfigured,
        });
    }
    let mut bytes = Vec::new();
    open(&p, false, true)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "Update status too large");
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) fn check_and_stage() -> Result<UpdateOutcome> {
    let Some(origin) = config()? else {
        return Ok(UpdateOutcome::NotConfigured);
    };
    require_admin()?;
    let (root, _root_pins) = update_root()?;
    let Some(_update) = lock(&root, "update.lock")? else {
        return Ok(UpdateOutcome::DeferredBusy);
    };
    let result = (|| {
        let path = installed()?;
        ensure!(
            same(&std::env::current_exe()?, &path),
            "Updates must originate from the installed executable"
        );
        let held = trusted_installed(&path)?;
        let Some(_engine) = lock(engine_lock_root(&root)?, "engine.lock")? else {
            return Ok(UpdateOutcome::DeferredBusy);
        };
        interlock::ensure_others_idle(interlock::Activity::Updater, &_engine)?;
        if busy(&path, &root)? {
            return Ok(UpdateOutcome::DeferredBusy);
        }
        if let Some(outcome) = recover_installation(&root, &path)? {
            return Ok(outcome);
        }
        clean_leftovers(&root, false);
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let authorization = select_delivery(&client, &root, &origin)?;
        let raw = fetch_manifest(
            &client,
            origin.join(if authorization.is_some() {
                arch::CANDIDATE_FEED
            } else {
                arch::STABLE_FEED
            })?,
        )?;
        let m = match authorization.as_ref() {
            Some(a) => delivery::candidate(&raw, a, now()?)?,
            None => verify(&raw, &key()?, now()?)?,
        };
        remember_release(&root, &m, env!("CARGO_PKG_VERSION"))?;
        if !newer(&m, env!("CARGO_PKG_VERSION"))? {
            return record(&root, UpdateOutcome::UpToDate);
        }
        if let Some(a) = authorization.as_ref() {
            if !delivery::eligible(&device_id(&root, true)?, a)? {
                return record(&root, UpdateOutcome::DeferredRollout { version: m.version });
            }
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("Update download deadline exceeded")?;
        let response = client
            .get(origin.join(&format!("downloads/{}", m.filename))?)
            .timeout(remaining)
            .send()?;
        ensure!(
            response.status().is_success(),
            "Installer HTTP request failed"
        );
        let bytes = installer(response, &m)?;
        ensure!(
            Instant::now() <= deadline,
            "Update download deadline exceeded"
        );
        replace(&root, "update-installer.exe", &bytes)?;
        replace(&root, "update-manifest.json", &raw)?;
        let mut image = Vec::new();
        held.last()
            .context("Missing installed image")?
            .try_clone()?
            .take(INSTALLER_LIMIT + 1)
            .read_to_end(&mut image)?;
        ensure!(
            image.len() as u64 <= INSTALLER_LIMIT,
            "Worker image too large"
        );
        replace(&root, "update-worker.exe", &image)?;
        let worker = open(&root.join("update-worker.exe"), false, true)?;
        preflight_worker(&root.join("update-worker.exe"), &root)?;
        record(
            &root,
            UpdateOutcome::WorkerStarted {
                version: m.version.clone(),
            },
        )?;
        child_command(&root.join("update-worker.exe"), &root)?
            .args(["update", "install-staged"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        drop(worker);
        Ok(UpdateOutcome::WorkerStarted { version: m.version })
    })();
    if result.is_err() {
        let _ = record(
            &root,
            UpdateOutcome::Failed {
                reason: "Update check or staging failed".into(),
            },
        );
    }
    result
}
pub(super) fn install_staged() -> Result<UpdateOutcome> {
    let Some(origin) = config()? else {
        return Ok(UpdateOutcome::NotConfigured);
    };
    require_admin()?;
    let (root, _root_pins) = update_root()?;
    ensure!(
        same(&std::env::current_exe()?, &root.join("update-worker.exe")),
        "Installer must run from the fixed protected worker"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let _update = loop {
        if let Some(f) = lock(&root, "update.lock")? {
            break f;
        }
        ensure!(Instant::now() < deadline, "Updater handoff timed out");
        std::thread::sleep(Duration::from_millis(100));
    };
    let result = (|| {
        let Some(_engine) = lock(engine_lock_root(&root)?, "engine.lock")? else {
            return record(&root, UpdateOutcome::DeferredBusy);
        };
        interlock::ensure_others_idle(interlock::Activity::Updater, &_engine)?;
        let path = installed()?;
        while busy(&path, &root)? {
            if Instant::now() >= deadline {
                return record(&root, UpdateOutcome::DeferredBusy);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if let Some(outcome) = recover_installation(&root, &path)? {
            return Ok(outcome);
        }
        // Bind this worker to the installed build it was copied from. In
        // particular, a retained old worker must not downgrade a newer install.
        let held = trusted_installed(&path)?;
        let worker = open(&root.join("update-worker.exe"), false, true)?;
        let digest = |mut file: File| -> Result<Vec<u8>> {
            let mut hash = Sha256::new();
            let mut count = 0u64;
            let mut buf = [0u8; 65536];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                count += n as u64;
                ensure!(count <= INSTALLER_LIMIT, "Installed image too large");
                hash.update(&buf[..n]);
            }
            Ok(hash.finalize().to_vec())
        };
        ensure!(
            digest(worker.try_clone()?)?
                == digest(
                    held.last()
                        .context("Missing installed image")?
                        .try_clone()?
                )?,
            "Worker does not match current installed build"
        );
        drop(held); // Installer must be able to replace the installed image.
        let mut raw = Vec::new();
        let manifest = open(&root.join("update-manifest.json"), false, true)?;
        manifest
            .take((MANIFEST_LIMIT + 1) as u64)
            .read_to_end(&mut raw)?;
        let authorization = read_delivery(&root, &origin)?;
        let m = match authorization.as_ref() {
            Some(a) => delivery::candidate(&raw, a, now()?)?,
            None => verify(&raw, &key()?, now()?)?,
        };
        remember_release(&root, &m, env!("CARGO_PKG_VERSION"))?;
        if !newer(&m, env!("CARGO_PKG_VERSION"))? {
            return record(&root, UpdateOutcome::UpToDate);
        }
        if let Some(a) = authorization.as_ref() {
            if !delivery::eligible(&device_id(&root, false)?, a)? {
                return record(&root, UpdateOutcome::DeferredRollout { version: m.version });
            }
        }
        let before = installation_health(&path, &root, env!("CARGO_PKG_VERSION"))?;
        let executable = open(&root.join("update-installer.exe"), false, true)?;
        installer(executable.try_clone()?, &m)?;
        validate_manifest(&m, now()?)?;
        if let Some(a) = authorization.as_ref() {
            delivery::fresh(a, now()?)?;
        }
        // Ask the per-user tray agents to leave (never killed) and make sure
        // they are gone before the installer replaces the image. The guard
        // closes the event and restarts the tray, unelevated, however we exit.
        let (is_busy, trays) = scan_busy(&path, &root)?;
        if is_busy {
            return record(&root, UpdateOutcome::DeferredBusy);
        }
        let mut tray_guard = tray_session::TrayRestore::new(&path, &trays);
        tray_guard.quiesce()?;
        if !tray_session::wait_for_exit(&trays, Duration::from_secs(15)) {
            return record(&root, UpdateOutcome::DeferredBusy);
        }
        let mut attempt = InstallAttempt {
            schema: 1,
            version: m.version.clone(),
            before,
            health: if authorization.is_some() {
                InstallHealth::DeliveryV1
            } else {
                InstallHealth::LegacyV1
            },
            phase: InstallPhase::Started,
        };
        // Publish before spawning. Display status is deliberately not the
        // recovery authority; later checks can overwrite status but not intent.
        let mut command = child_command(&root.join("update-installer.exe"), &root)?;
        command.args(INSTALL_ARGS);
        write_attempt(&root, Some(&attempt))?;
        // The read handle denies write/delete sharing through process exit, closing
        // the verification-to-execution replacement race.
        let mut child = match command.spawn() {
            Ok(child) => InstallerChild(child),
            Err(error) => {
                write_attempt(&root, None)?; // CreateProcess failed: no installer ran.
                return Err(error.into());
            }
        };
        // Keep both locks and the verified payload pin until the installer exits.
        // Killing it, or timing out and releasing locks while it is still running,
        // can leave a partial installation or permit overlapping installers.
        ensure!(
            child.0.wait()?.code() == Some(0),
            "Installer failed; completion unconfirmed"
        );
        drop(executable);
        attempt.phase = InstallPhase::Exited;
        write_attempt(&root, Some(&attempt))?;
        let outcome = recover_installation(&root, &path)?
            .context("Missing completed installation attempt")?;
        clean_leftovers(&root, true);
        Ok(outcome)
    })();
    if result.is_err() {
        let _ = record(
            &root,
            UpdateOutcome::Failed {
                reason: "Staged installation failed".into(),
            },
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "elevated Windows storage-only interlock test; no installer/maintenance execution"]
    fn interlock_inspection_is_read_only_and_outlives_a_lost_lock_owner() {
        let (root, _pins) = update_root().unwrap();
        let base = root.join(format!("interlock-test-{}", uuid::Uuid::new_v4()));
        let base_pin = protected_update_directory(&base).unwrap();
        let foreign_path = base.join("foreign.lock");
        drop(create(&foreign_path).unwrap());
        let foreign = lock(&base, "foreign.lock").unwrap().unwrap();
        assert!(validate_engine_lock(&foreign, &base).is_err());
        assert!(
            !base.join("engine.lock").exists(),
            "inspection cannot create a lock"
        );
        inspect_install_state(&base).unwrap();
        assert!(
            !base.join("Updates").exists(),
            "inspection cannot create updater state"
        );

        let supervisor = lock(&base, "engine.lock").unwrap().unwrap();
        validate_engine_lock(&supervisor, &base).unwrap();
        assert!(validate_engine_lock(&foreign, &base).is_err());
        assert!(
            super::ensure_install_idle(&supervisor).is_err(),
            "public API must reject a non-native root"
        );
        let updates = base.join("Updates");
        let updates_pin = protected_update_directory(&updates).unwrap();
        let attempt_path = updates.join("install-attempt.json");
        for phase in [InstallPhase::Started, InstallPhase::Exited] {
            write_attempt(&updates, Some(&super::super::tests::attempt(phase))).unwrap();
            let bytes = fs::read(&attempt_path).unwrap();
            assert!(inspect_install_state(&base).is_err());
            assert_eq!(fs::read(&attempt_path).unwrap(), bytes);
        }
        drop(supervisor); // supervisor lost; the durable Exited intent survives
        let next = lock(&base, "engine.lock").unwrap().unwrap();
        validate_engine_lock(&next, &base).unwrap();
        assert!(inspect_install_state(&base).is_err());
        FileExt::unlock(&next).unwrap();
        assert!(
            validate_engine_lock(&next, &base).is_err(),
            "unlocked handle is not a permit"
        );
        next.try_lock_exclusive().unwrap();
        for bytes in [b"{".as_slice(), b"{\"schema\":99}", b"[]"] {
            replace(&updates, "install-attempt.json", bytes).unwrap();
            assert!(inspect_install_state(&base).is_err());
            assert_eq!(fs::read(&attempt_path).unwrap(), bytes);
        }
        write_attempt(&updates, None).unwrap();
        inspect_install_state(&base).unwrap();
        let alias = base.join("attempt-alias");
        fs::hard_link(&attempt_path, &alias).unwrap();
        assert!(inspect_install_state(&base).is_err());
        fs::remove_file(alias).unwrap();
        fs::remove_file(attempt_path).unwrap();
        drop((updates_pin, next, foreign));
        fs::remove_dir(updates).unwrap();
        fs::remove_file(base.join("engine.lock")).unwrap();
        fs::remove_file(foreign_path).unwrap();
        drop(base_pin);
        fs::remove_dir(base).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner; protected state only, no installer launched"]
    fn uncertain_installation_blocks_before_health_and_failed_reset_retains_intent() {
        let (root, _pins) = update_root().unwrap();
        let test_root = root.join(format!("attempt-test-{}", uuid::Uuid::new_v4()));
        let pin = protected_update_directory(&test_root).unwrap();
        let attempt = super::super::tests::attempt(InstallPhase::Started);
        write_attempt(&test_root, Some(&attempt)).unwrap();
        let path = test_root.join("install-attempt.json");
        let original = fs::read(&path).unwrap();
        let error = recover_installation(&test_root, &test_root.join("missing.exe")).unwrap_err();
        assert!(error.to_string().contains("completion is unconfirmed"));
        assert_eq!(fs::read(&path).unwrap(), original);
        let held = open(&path, false, true).unwrap();
        assert!(write_attempt(&test_root, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(held);
        write_attempt(&test_root, None).unwrap();
        assert!(
            recover_installation(&test_root, &test_root.join("missing.exe"))
                .unwrap()
                .is_none()
        );
        fs::remove_file(path).unwrap();
        drop(pin);
        fs::remove_dir(test_root).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner; read-only child fixtures"]
    fn probe_output_exit_size_and_timeout_are_enforced() {
        const CHILD: &str = "SECBLITZ_TEST_HEALTH_CHILD";
        if let Some(mode) = std::env::var_os(CHILD) {
            match mode.to_str().unwrap() {
                "failure" => std::process::exit(7),
                "flood" => {
                    std::io::stdout().write_all(&[b'x'; 8192]).unwrap();
                }
                "timeout" => std::thread::sleep(Duration::from_secs(60)),
                _ => unreachable!(),
            }
            return;
        }
        require_admin().unwrap();
        let (root, _pins) = update_root().unwrap();
        for mode in ["failure", "flood", "timeout"] {
            let mut command = child_command(&std::env::current_exe().unwrap(), &root).unwrap();
            command
                .args([
                    "--exact",
                    "updater::windows::tests::probe_output_exit_size_and_timeout_are_enforced",
                    "--ignored",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, mode);
            let start = Instant::now();
            assert!(read_only_output_until(
                &mut command,
                health::LIMIT,
                start + Duration::from_secs(2)
            )
            .is_err());
            assert!(start.elapsed() < Duration::from_secs(10));
        }
    }
    #[test]
    #[ignore = "requires elevated Windows runner with installed Secblitz; no installer launched"]
    fn independent_health_probe_completes_while_both_locks_are_held() {
        require_admin().unwrap();
        let (root, _pins) = update_root().unwrap();
        let _update = lock(&root, "update.lock").unwrap().expect("run serially");
        let _engine = lock(engine_lock_root(&root).unwrap(), "engine.lock")
            .unwrap()
            .expect("run serially");
        let report =
            installation_health(&installed().unwrap(), &root, env!("CARGO_PKG_VERSION")).unwrap();
        health::validate(
            &serde_json::to_vec(&report).unwrap(),
            env!("CARGO_PKG_VERSION"),
            Some(&report),
        )
        .unwrap();
        assert!(lock(&root, "update.lock").unwrap().is_none());
        assert!(lock(engine_lock_root(&root).unwrap(), "engine.lock")
            .unwrap()
            .is_none());
    }
    #[test]
    #[ignore = "requires installed build with coordinator's update health CLI; elevated Windows"]
    fn installed_health_command_completes_while_both_locks_are_held() {
        require_admin().unwrap();
        let (root, _pins) = update_root().unwrap();
        let _update = lock(&root, "update.lock").unwrap().expect("run serially");
        let _engine = lock(engine_lock_root(&root).unwrap(), "engine.lock")
            .unwrap()
            .expect("run serially");
        let path = installed().unwrap();
        let _image = trusted_installed(&path).unwrap();
        let before = installation_health(&path, &root, env!("CARGO_PKG_VERSION")).unwrap();
        let mut command = child_command(&path, &root).unwrap();
        command.args(delivery::HealthCommand::UpdateHealthV1.args());
        let bytes = read_only_output(command, health::LIMIT).unwrap();
        health::validate(&bytes, env!("CARGO_PKG_VERSION"), Some(&before)).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn rollout_identity_is_persistent_and_corruption_never_reassigns_cohort() {
        let (root, _pins) = update_root().unwrap();
        let test_root = root.join(format!("cohort-test-{}", std::process::id()));
        let pin = protected_update_directory(&test_root).unwrap();
        assert!(device_id(&test_root, false).is_err());
        let first = device_id(&test_root, true).unwrap();
        assert_eq!(device_id(&test_root, false).unwrap(), first);
        assert_eq!(device_id(&test_root, true).unwrap(), first);
        replace(&test_root, "rollout-device-id", b"bad").unwrap();
        assert!(device_id(&test_root, true).is_err());
        assert!(device_id(&test_root, false).is_err());
        fs::remove_file(test_root.join("rollout-device-id")).unwrap();
        drop(pin);
        fs::remove_dir(test_root).unwrap();
    }
    fn check_acl(sddl: &str, directory: bool, strict: bool, ancestor: bool) -> Result<()> {
        check_acl_at(sddl, directory, strict, ancestor, false)
    }
    fn check_acl_at(
        sddl: &str,
        directory: bool,
        strict: bool,
        ancestor: bool,
        root: bool,
    ) -> Result<()> {
        unsafe {
            let mut sd = null_mut();
            ensure!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(sddl).as_ptr(),
                    1,
                    &mut sd,
                    null_mut(),
                ) != 0,
                "Test descriptor conversion failed"
            );
            let _sd = Local(sd);
            let (mut owner, mut acl) = (null_mut(), null_mut());
            let (mut defaulted, mut present) = (0, 0);
            ensure!(
                GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) != 0,
                "Test owner query failed"
            );
            ensure!(
                GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) != 0
                    && present != 0,
                "Test DACL query failed"
            );
            inspect_acl(owner, acl, directory, strict, ancestor, root)
        }
    }
    #[test]
    fn default_programdata_acl_is_allowed_only_as_an_ancestor() {
        let sddl = "O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)";
        check_acl(sddl, true, false, true).unwrap();
        assert!(check_acl(sddl, true, false, false).is_err());
        assert!(check_acl(sddl, true, true, false).is_err());
        assert!(check_acl(&sddl.replace("O:SY", "O:BU"), true, false, true)
            .unwrap_err()
            .to_string()
            .contains("Untrusted update owner"));
        check_acl(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            true,
            true,
            false,
        )
        .unwrap();
    }
    #[test]
    fn ancestor_exception_never_allows_acl_or_replacement_rights() {
        for right in [
            WRITE_DAC,
            WRITE_OWNER,
            DELETE,
            FILE_DELETE_CHILD,
            GENERIC_WRITE,
            GENERIC_ALL,
            0x02000000, // MAXIMUM_ALLOWED
        ] {
            let sddl = format!(
                "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{:x};;;BU)",
                0x116 | right
            );
            assert!(
                check_acl(&sddl, true, false, true)
                    .unwrap_err()
                    .to_string()
                    .contains("Untrusted update write/execution rights"),
                "{right:#x}"
            );
        }
    }
    #[test]
    fn fresh_volume_root_acl_is_allowed_only_at_a_volume_root() {
        let sddl = "O:SYG:SYD:(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1301bf;;;AU)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)";
        check_acl_at(sddl, true, false, true, true).unwrap();
        assert!(check_acl(sddl, true, false, true).is_err());
        assert!(check_acl_at(sddl, true, true, false, true).is_err());
        for right in [
            WRITE_DAC,
            WRITE_OWNER,
            FILE_DELETE_CHILD,
            GENERIC_WRITE,
            GENERIC_ALL,
        ] {
            let sddl = format!(
                "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{:x};;;AU)",
                0x1301bf | right
            );
            assert!(
                check_acl_at(&sddl, true, false, true, true).is_err(),
                "{right:#x}"
            );
        }
    }
    #[test]
    fn attribute_exception_never_applies_to_owned_roots_or_files() {
        for right in [FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, GENERIC_WRITE] {
            let sddl = format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{right:x};;;BU)");
            for (directory, strict, ancestor) in [
                (true, true, false),
                (true, true, true),
                (true, false, false),
                (false, true, false),
                (false, false, false),
                (false, false, true),
            ] {
                assert!(
                    check_acl(&sddl, directory, strict, ancestor).is_err(),
                    "{right:#x}: directory={directory} strict={strict} ancestor={ancestor}"
                );
            }
        }
    }
    #[test]
    fn completion_requires_exact_product_and_stable_version() {
        assert_eq!(
            reported_version(b"secblitz 0.4.0\r\n").unwrap(),
            stable("0.4.0").unwrap()
        );
        for bad in [
            "other 0.4.0",
            "secblitz 0.4.0-rc.1",
            "secblitz 0.4.0+build",
            "secblitz 0.4.0\nextra",
            "secblitz 00.4.0",
            "",
            "secblitz 0.4.0 ",
        ] {
            assert!(reported_version(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(reported_version(&[b'x'; 257]).is_err());
    }
    #[test]
    fn privileged_children_use_only_native_environment_and_fixed_arguments() {
        let root = known_folder(&FOLDERID_ProgramData)
            .unwrap()
            .join("Secblitz")
            .join("Updates");
        let root = root.as_path();
        let mut command = child_command(&root.join("update-installer.exe"), root).unwrap();
        command.args(INSTALL_ARGS);
        let keys: Vec<_> = command
            .get_envs()
            .map(|(key, value)| {
                assert!(value.is_some());
                key.to_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(keys.len(), 8);
        for key in keys {
            assert!([
                "SYSTEMROOT",
                "WINDIR",
                "SYSTEMDRIVE",
                "PROGRAMDATA",
                "ALLUSERSPROFILE",
                "PATH",
                "TEMP",
                "TMP"
            ]
            .contains(&key.to_uppercase().as_str()));
        }
        for key in ["PROGRAMDATA", "ALLUSERSPROFILE"] {
            let value = command
                .get_envs()
                .find(|(k, _)| k.to_str().unwrap().eq_ignore_ascii_case(key))
                .and_then(|(_, value)| value)
                .unwrap();
            assert_eq!(Path::new(value), root.parent().unwrap().parent().unwrap());
        }
        let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
        assert!(args.contains(&"/SECBLITZUPDATE=1"));
        assert!(args.contains(&"/TASKS=")); // Empty value; no literal quote characters in argv.
        assert!(args.contains(&"/NORESTART"));
    }
    #[test]
    fn update_layout_requires_the_native_base_and_exact_child() {
        let base = known_folder(&FOLDERID_ProgramData)
            .unwrap()
            .join("Secblitz");
        assert_eq!(engine_lock_root(&base.join("Updates")).unwrap(), base);
        for wrong in [
            base.clone(),
            base.join("Other"),
            base.join("Updates/child"),
            base.join("Other/../Updates"),
            base.parent().unwrap().join("Foreign/Updates"),
        ] {
            assert!(engine_lock_root(&wrong).is_err(), "{}", wrong.display());
        }
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn update_directory_is_protected_reopenable_and_engine_lock_stays_shared() {
        let (root, _pins) = update_root().unwrap();
        let base = crate::platform::state_dir().unwrap();
        assert_eq!(root, base.join("Updates"));
        assert_eq!(engine_lock_root(&root).unwrap(), base);
        let engine = lock(&base, "engine.lock")
            .unwrap()
            .expect("Run serially without an engine");
        assert!(lock(engine_lock_root(&root).unwrap(), "engine.lock")
            .unwrap()
            .is_none());
        let update = lock(&root, "update.lock").unwrap().unwrap();
        drop(update);
        drop(engine);
        let path = root.join(format!("update-directory-test-{}", std::process::id()));
        let first = protected_update_directory(&path).unwrap();
        let second = protected_update_directory(&path).unwrap();
        drop(second);
        drop(first);
        fs::remove_dir(&path).unwrap();
        // A pre-existing regular file must not be adopted as a directory.
        drop(create(&path).unwrap());
        assert!(protected_update_directory(&path).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner; also run as SYSTEM/session 0"]
    fn clean_child_environment_resolves_native_update_paths() {
        const CHILD: &str = "SECBLITZ_TEST_KNOWN_FOLDERS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            require_admin().unwrap();
            let (root, _pins) = update_root().unwrap();
            assert_eq!(
                root.parent().unwrap().parent().unwrap(),
                Path::new(&std::env::var_os("ProgramData").unwrap())
            );
            assert!(installed().unwrap().is_absolute());
            let status = status().unwrap();
            if config().unwrap().is_some() {
                assert_eq!(status.result, UpdateOutcome::DeferredBusy);
            }
            return;
        }
        require_admin().unwrap();
        let (root, _pins) = update_root().unwrap();
        let _update = lock(&root, "update.lock")
            .unwrap()
            .expect("Run updater tests serially");
        let mut child = child_command(&std::env::current_exe().unwrap(), &root)
            .unwrap()
            .args([
                "--exact",
                "updater::windows::tests::clean_child_environment_resolves_native_update_paths",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1") // Test-only recursion guard; production stays at eight keys.
            .spawn()
            .unwrap();
        wait_read_only_child(&mut child).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn pinned_verified_payload_cannot_be_replaced_or_written() {
        let (root, _pins) = update_root().unwrap();
        let name = format!("update-race-test-{}.bin", std::process::id());
        let path = root.join(name);
        let mut created = create(&path).unwrap();
        created.write_all(b"verified").unwrap();
        drop(created);
        let pinned = open(&path, false, true).unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::rename(&path, root.join("update-race-replaced.bin")).is_err());
        assert!(fs::remove_file(&path).is_err());
        assert!(create(&path).is_err());
        drop(pinned);
        fs::remove_file(path).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn update_lock_excludes_duplicate_worker() {
        let (root, _pins) = update_root().unwrap();
        let name = format!("update-lock-test-{}", std::process::id());
        let first = lock(&root, &name).unwrap().unwrap();
        assert!(lock(&root, &name).unwrap().is_none());
        drop(first);
        assert!(lock(&root, &name).unwrap().is_some());
        fs::remove_file(root.join(name)).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn staged_objects_reject_hardlinks_and_reparse_points() {
        let (root, _pins) = update_root().unwrap();
        let base = root.join(format!("update-links-test-{}", std::process::id()));
        let hard = base.with_extension("hard");
        let symbolic = base.with_extension("symlink");
        drop(create(&base).unwrap());
        fs::hard_link(&base, &hard).unwrap();
        for path in [&base, &hard] {
            assert!(open(path, false, true)
                .unwrap_err()
                .to_string()
                .contains("Unsafe update object"));
        }
        fs::remove_file(&hard).unwrap();
        std::os::windows::fs::symlink_file(&base, &symbolic).unwrap();
        assert!(open(&symbolic, false, true)
            .unwrap_err()
            .to_string()
            .contains("Unsafe update object"));
        fs::remove_file(&symbolic).unwrap();
        drop(open(&base, false, true).unwrap());
        fs::remove_file(&base).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn cleanup_removes_only_staged_payloads_and_tolerates_held_files() {
        let (root, _pins) = update_root().unwrap();
        let dir = root.join(format!("leftover-test-{}", uuid::Uuid::new_v4()));
        let pin = protected_update_directory(&dir).unwrap();
        let staged = [
            "update-installer.exe",
            "update-manifest.json",
            "update-worker.exe",
        ];
        let kept = [
            "release-floor.json",
            "delivery-floor.json",
            "rollout-device-id",
            "update-status.json",
        ];
        for name in staged.iter().chain(&kept) {
            replace(&dir, name, b"x").unwrap();
        }
        replace(&dir, "update-tmp-stranded.tmp", b"x").unwrap();
        let lock = lock(&dir, "update.lock").unwrap().unwrap();

        write_attempt(
            &dir,
            Some(&super::super::tests::attempt(InstallPhase::Started)),
        )
        .unwrap();
        clean_leftovers(&dir, false);
        assert!(staged.iter().all(|n| dir.join(n).exists()));

        write_attempt(&dir, None).unwrap();
        clean_leftovers(&dir, true);
        assert!(!dir.join("update-installer.exe").exists());
        assert!(!dir.join("update-manifest.json").exists());
        assert!(dir.join("update-worker.exe").exists());

        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(dir.join("update-worker.exe"))
            .unwrap();
        clean_leftovers(&dir, false);
        assert!(dir.join("update-worker.exe").exists());
        drop(held);
        clean_leftovers(&dir, false);
        assert!(!dir.join("update-worker.exe").exists());
        clean_leftovers(&dir, false);

        for name in kept.iter().chain(&["update-tmp-stranded.tmp"]) {
            assert!(dir.join(name).exists(), "{name} must stay");
        }
        for name in kept
            .iter()
            .chain(&["update-tmp-stranded.tmp", "install-attempt.json"])
        {
            fs::remove_file(dir.join(name)).unwrap();
        }
        drop((lock, pin));
        fs::remove_file(dir.join("update.lock")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn data_access_directory_pin_blocks_prefix_rename() {
        let (root, _pins) = update_root().unwrap();
        let path = root.join(format!("update-prefix-test-{}", std::process::id()));
        let renamed = path.with_extension("renamed");
        fs::create_dir(&path).unwrap();
        let pin = open(&path, true, true).unwrap();
        let child = path.join("child.bin");
        let moved_child = path.join("renamed.bin");
        drop(create(&child).unwrap());
        fs::rename(&child, &moved_child).unwrap();
        fs::remove_file(&moved_child).unwrap();
        assert_eq!(
            fs::rename(&path, &renamed).unwrap_err().raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32)
        );
        drop(pin);
        fs::rename(&path, &renamed).unwrap();
        fs::remove_dir(renamed).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn staging_replace_works_with_ancestor_pins_and_respects_payload_pin() {
        let (root, _pins) = update_root().unwrap();
        let name = format!("update-replace-test-{}.bin", std::process::id());
        let legacy_path = engine_lock_root(&root).unwrap().join(&name);
        assert!(!legacy_path.exists());
        let path = root.join(&name);
        replace(&root, &name, b"first").unwrap();
        replace(&root, &name, b"second").unwrap();
        let mut payload = open(&path, false, true).unwrap();
        let mut bytes = Vec::new();
        payload.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"second");
        assert!(replace(&root, &name, b"blocked").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"second");
        drop(payload);
        replace(&root, &name, b"third").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"third");
        assert!(!legacy_path.exists());
        fs::remove_file(&path).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn failed_or_interrupted_atomic_status_write_preserves_previous_json() {
        let (root, _pins) = update_root().unwrap();
        let name = format!("atomic-status-test-{}.json", std::process::id());
        let path = root.join(&name);
        let previous = serde_json::to_vec(&UpdateStatus {
            checked_at: 123,
            result: UpdateOutcome::UpToDate,
        })
        .unwrap();
        replace(&root, &name, &previous).unwrap();
        let names = || {
            fs::read_dir(&root)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = names();
        assert!(replace_with(&root, &name, |file| {
            file.write_all(b"{\"checked_at\":")?;
            anyhow::bail!("injected disk write failure")
        })
        .is_err());
        assert_eq!(names(), before); // RAII removed only our failed temporary file.
        assert_eq!(fs::read(&path).unwrap(), previous);
        // A process crash can strand a partial protected temp. It is not status.
        let partial = root.join(format!("update-tmp-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = create(&partial).unwrap();
        file.write_all(b"{").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let status: UpdateStatus = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(status.result, UpdateOutcome::UpToDate);
        replace(&root, &name, &previous).unwrap();
        assert!(partial.exists()); // No cleanup of another invocation's temp.
        fs::remove_file(partial).unwrap();
        fs::remove_file(path).unwrap();
    }
    #[test]
    #[ignore = "requires elevated Windows runner"]
    fn protected_floor_is_durable_and_write_or_parse_failure_stops_advancement() {
        let (root, _pins) = update_root().unwrap();
        let test_root = root.join(format!("floor-test-{}", std::process::id()));
        let pin = protected_update_directory(&test_root).unwrap();
        let mut m = Manifest {
            schema: 1,
            version: "9.2.0".into(),
            filename: setup_filename("9.2.0"),
            sha256: hex::encode(Sha256::digest(b"test")),
            size: 4,
            published_at: 1000,
            expires_at: 2000,
            target: arch::TARGET.into(),
        };
        remember_release(&test_root, &m, "9.0.0").unwrap();
        assert!(installer(&b"fail"[..], &m).is_err());
        assert_eq!(read_floor(&test_root).unwrap().unwrap().version, "9.2.0");
        m.version = "9.1.0".into();
        m.filename = setup_filename("9.1.0");
        assert!(remember_release(&test_root, &m, "9.0.0").is_err());
        m.version = "9.3.0".into();
        m.filename = setup_filename("9.3.0");
        let floor_path = test_root.join("release-floor.json");
        let payload_pin = open(&floor_path, false, true).unwrap();
        assert!(remember_release(&test_root, &m, "9.0.0").is_err());
        assert_eq!(read_floor(&test_root).unwrap().unwrap().version, "9.2.0");
        drop(payload_pin);
        remember_release(&test_root, &m, "9.0.0").unwrap();
        assert_eq!(read_floor(&test_root).unwrap().unwrap().version, "9.3.0");
        replace(&test_root, "release-floor.json", b"{").unwrap();
        assert!(remember_release(&test_root, &m, "9.0.0").is_err());
        assert_eq!(fs::read(&floor_path).unwrap(), b"{"); // Never reset corrupt state.
        fs::remove_file(floor_path).unwrap();
        drop(pin);
        fs::remove_dir(test_root).unwrap();
    }
}
