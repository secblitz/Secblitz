//! Native journal trust boundary. No environment-derived paths, ACL repair, or
//! adoption of a pre-existing untrusted directory. Handles deny delete sharing.
use super::*;
use std::sync::{Mutex, OnceLock};

#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(p: *const c_void);
}

fn sid(text: &str) -> Result<Local> {
    let text = wide(text)?;
    let mut p = null_mut();
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut p) } == 0 {
        return Err(winerr());
    }
    Ok(Local(p))
}

fn open(path: &Path) -> Result<Handle> {
    let path = wide(path)?;
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())
            .context("Cannot open journal path safely"));
    }
    Ok(Handle(h))
}

/// Settings are saved by renaming a temporary file over the old one, so an
/// entry listed a moment ago can already be gone. Nothing is left to trust or pin.
fn vanished(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

fn planted(handle: &Handle) -> Result<bool> {
    unsafe {
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut info: BY_HANDLE_FILE_INFORMATION = zeroed();
        if GetFileInformationByHandle(handle.0, &mut info) == 0 {
            return Err(winerr());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(true);
        }
        let mut owner = null_mut();
        let mut sd = null_mut();
        let error = GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        ensure!(
            error == 0,
            "Cannot query journal security (Windows error {error})"
        );
        let _sd = Local(sd);
        let system = sid("S-1-5-18")?;
        let admins = sid("S-1-5-32-544")?;
        Ok(owner.is_null() || (EqualSid(owner, system.0) == 0 && EqualSid(owner, admins.0) == 0))
    }
}

/// Rename a planted entry (the entry itself, never a link's target) to a
/// fresh random name next to it. Its contents are left untouched.
fn set_aside(base: &Path, path: &Path) -> Result<()> {
    use rand::TryRng;
    let mut tag = [0u8; 8];
    rand::rngs::SysRng.try_fill_bytes(&mut tag)?;
    let aside = base.join(format!("Secblitz.untrusted-{}", hex::encode(tag)));
    let (from, to) = (wide(path)?, wide(&aside)?);
    ensure!(
        unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } != 0,
        "A folder at {} was not created by Secblitz and could not be moved aside: {}",
        path.display(),
        winerr()
    );
    Ok(())
}

fn inspect(handle: &Handle, strict: bool, root: bool) -> Result<bool> {
    unsafe {
        // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
        let mut info: BY_HANDLE_FILE_INFORMATION = zeroed();
        if GetFileInformationByHandle(handle.0, &mut info) == 0 {
            return Err(winerr());
        }
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "Journal path contains a reparse point"
        );
        let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        ensure!(
            directory || info.nNumberOfLinks == 1,
            "Journal file has multiple hard links"
        );
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut sd = null_mut();
        let error = GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        );
        ensure!(
            error == 0,
            "Cannot query journal security (Windows error {error})"
        );
        let _sd = Local(sd);
        let system = sid("S-1-5-18")?;
        let admins = sid("S-1-5-32-544")?;
        ensure!(
            !owner.is_null() && (EqualSid(owner, system.0) != 0 || EqualSid(owner, admins.0) != 0),
            "Journal path owner is not SYSTEM or Administrators"
        );
        if !strict {
            return Ok(directory);
        }
        ensure!(
            !acl.is_null() && IsValidAcl(acl) != 0,
            "Journal DACL is missing or invalid"
        );
        let mut control = 0;
        let mut revision = 0;
        if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 {
            return Err(winerr());
        }
        ensure!(
            control & SE_DACL_PRESENT != 0,
            "Journal DACL is not present"
        );
        if root {
            ensure!(
                control & SE_DACL_PROTECTED != 0,
                "Journal root DACL permits inheritance"
            );
        }
        let mut seen_system = false;
        let mut seen_admins = false;
        // Only SYSTEM/Admin full-control allow ACEs are accepted, with no
        // inherit-only/conditional/object ACEs or extra trustees.
        for i in 0..(*acl).AceCount as u32 {
            let mut ace = null_mut();
            if GetAce(acl, i, &mut ace) == 0 {
                return Err(winerr());
            }
            let header = &*(ace as *const ACE_HEADER);
            ensure!(
                header.AceType == 0 && header.AceSize as usize >= size_of::<ACCESS_ALLOWED_ACE>(),
                "Unexpected journal ACE type"
            );
            ensure!(
                header.AceFlags
                    & !(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE) as u8
                    == 0,
                "Unexpected journal ACE flags"
            );
            if directory {
                ensure!(
                    header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                        == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                    "Journal directory does not propagate its restricted DACL"
                );
            }
            let allow = &*(ace as *const ACCESS_ALLOWED_ACE);
            ensure!(
                allow.Mask == FILE_ALL_ACCESS,
                "Unexpected journal access mask"
            );
            let trustee = &allow.SidStart as *const u32 as *mut c_void;
            ensure!(IsValidSid(trustee) != 0, "Invalid journal trustee SID");
            if EqualSid(trustee, system.0) != 0 {
                seen_system = true;
            } else if EqualSid(trustee, admins.0) != 0 {
                seen_admins = true;
            } else {
                bail!("Untrusted journal trustee");
            }
        }
        ensure!(
            seen_system && seen_admins,
            "Journal must grant full control to SYSTEM and Administrators"
        );
        Ok(directory)
    }
}

fn program_data() -> Result<PathBuf> {
    unsafe {
        let mut raw = null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut raw);
        ensure!(
            hr >= 0 && !raw.is_null(),
            "Cannot resolve ProgramData known folder ({hr:#x})"
        );
        let result = (|| {
            // SAFETY: success returns a NUL-terminated UTF-16 string, freed only below.
            let text =
                crate::platform::security::wide_str(raw).context("Invalid known-folder path")?;
            Ok(PathBuf::from(String::from_utf16(text)?))
        })();
        CoTaskMemFree(raw as *const c_void);
        result
    }
}

/// Inspect every entry under `path`. `opaque` folders are inspected but not walked (thousands of
/// files, or the installer TEMP). `foreign` (web protection's folder) has wider permissions: it
/// only has to be a real folder owned by SYSTEM or Administrators, and is not walked.
fn secure_tree(
    path: &Path,
    opaque: &[PathBuf],
    foreign: &Path,
    handles: &mut Vec<Handle>,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 8 && handles.len() < 4096,
        "Journal directory exceeds inspection limits"
    );
    for entry in std::fs::read_dir(path)? {
        let path = entry?.path();
        let h = match open(&path) {
            Ok(h) => h,
            Err(e) if vanished(&e) => continue,
            Err(e) => return Err(e.context(format!("Inspect {}", path.display()))),
        };
        if path == foreign {
            inspect(&h, false, false)
                .and_then(|directory| {
                    ensure!(directory, "Wrong object type");
                    Ok(())
                })
                .with_context(|| format!("Untrusted journal entry {}", path.display()))?;
            handles.push(h);
            continue;
        }
        let directory = inspect(&h, true, false)
            .with_context(|| format!("Untrusted journal entry {}", path.display()))?;
        handles.push(h);
        if directory && !opaque.contains(&path) {
            secure_tree(&path, opaque, foreign, handles, depth + 1)?;
        }
        ensure!(handles.len() < 4096, "Too many journal entries");
    }
    Ok(())
}

fn private_descriptor() -> Result<Local> {
    let sddl = wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let mut descriptor = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } != 0,
        "Cannot construct journal security descriptor"
    );
    Ok(Local(descriptor))
}

/// Creates a new folder only SYSTEM and Administrators can open. Fails if it already exists.
pub fn create_private_dir(path: &Path) -> Result<()> {
    let descriptor = private_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path_w = wide(path)?;
    if unsafe { CreateDirectoryW(path_w.as_ptr(), &attributes) } == 0 {
        let error = unsafe { GetLastError() };
        bail!("Cannot create protected journal directory (Windows error {error})");
    }
    Ok(())
}

/// Returned paths are safe only while normal Windows ACL enforcement applies.
/// The caller must write journal/lock files under this directory, never follow
/// user-provided paths, and use atomic create/replace operations for new files.
/// An already privileged administrator is outside this trust boundary.
pub fn state_dir() -> Result<PathBuf> {
    // Serialize native directory establishment in this process. Retain only
    // ancestor/root handles, allowing the engine to atomically replace journals.
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = LOCK.get_or_init(|| Mutex::new(())).lock().map_err(|e| {
        eprintln!("{e}");
        anyhow::anyhow!("Journal lock poisoned")
    })?;
    crate::platform::require_admin("Protected journal access requires Administrator elevation")?;
    let base = program_data()?;
    let mut components = base.components();
    ensure!(
        matches!(components.next(),Some(Component::Prefix(p)) if matches!(p.kind(),std::path::Prefix::Disk(_))),
        "ProgramData must be on a local drive"
    );
    ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "ProgramData is not absolute"
    );
    let mut prefix = PathBuf::new();
    let mut held = Vec::new();
    for c in base.components() {
        ensure!(
            !matches!(c, Component::ParentDir | Component::CurDir),
            "Noncanonical ProgramData path"
        );
        prefix.push(c.as_os_str());
        if matches!(c, Component::Prefix(_)) {
            continue;
        }
        let h = open(&prefix)?;
        // Drive roots commonly have TrustedInstaller ownership; they need only
        // be local non-reparse directories. ProgramData and intermediate folders
        // must have a trusted SYSTEM/Admin owner.
        if matches!(c, Component::RootDir) {
            // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
            let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            ensure!(
                unsafe { GetFileInformationByHandle(h.0, &mut i) } != 0,
                "Cannot inspect volume root"
            );
            ensure!(
                i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    && i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                "Invalid volume root"
            );
            let root = wide(&prefix)?;
            ensure!(
                unsafe { GetDriveTypeW(root.as_ptr()) } == 3,
                "Journal requires a fixed local drive"
            ); // DRIVE_FIXED
        } else {
            ensure!(
                inspect(&h, false, false)?,
                "ProgramData ancestor is not a directory"
            );
        }
        held.push(h);
    }
    let path = base.join("Secblitz");
    let descriptor = private_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path_w = wide(&path)?;
    if unsafe { CreateDirectoryW(path_w.as_ptr(), &attributes) } == 0 {
        let error = unsafe { GetLastError() };
        ensure!(
            error == ERROR_ALREADY_EXISTS,
            "Cannot create protected journal directory (Windows error {error})"
        );
        // Secblitz always creates it owned by Administrators and never as a
        // link. Anything else was planted (any user may create folders in
        // ProgramData) to block Secblitz: move it aside, never adopt it.
        if planted(&open(&path)?)? {
            set_aside(&base, &path)?;
            if unsafe { CreateDirectoryW(path_w.as_ptr(), &attributes) } == 0 {
                bail!(
                    "Cannot create protected journal directory (Windows error {})",
                    unsafe { GetLastError() }
                );
            }
        }
    }
    let root = open(&path)?;
    ensure!(
        inspect(&root, true, true)?,
        "Journal root is not a directory"
    );
    held.push(root);
    let mut entries = Vec::new();
    let opaque = [
        path.join("App").join(crate::platform::APP_BACKUPS),
        path.join(crate::platform::UPDATES),
        path.join(crate::engine::recover::DAMAGED),
    ];
    let foreign = path.join(crate::platform::WEB_PROTECTION);
    secure_tree(&path, &opaque, &foreign, &mut entries, 0)?;
    // Keep one set of non-delete-sharing root/ancestor handles for process
    // lifetime. This prevents directory replacement after returning PathBuf.
    static PINNED: OnceLock<PathBuf> = OnceLock::new();
    if let Some(previous) = PINNED.get() {
        ensure!(previous == &path, "ProgramData changed during this process");
    }
    PINNED.get_or_init(|| {
        for h in held {
            std::mem::forget(h);
        }
        path.clone()
    });
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_gone_before_it_is_opened_counts_as_vanished() {
        let dir = tempfile::tempdir().unwrap();
        let gone = open(&dir.path().join("notify.1.2.tmp")).err().unwrap();
        assert!(vanished(&gone), "{gone:#}");
        assert!(format!("{gone:#}").starts_with("Cannot open journal path safely: "));
        let other = anyhow::anyhow!("Cannot open journal path safely: Access is denied.");
        assert!(!vanished(&other));
    }
}
