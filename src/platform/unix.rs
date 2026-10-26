//! Protected state folder on Linux and macOS. The folder is trusted only after
//! every part of its path passes the ownership and permission checks.
use anyhow::{bail, Context, Result};
use std::fs::{DirBuilder, Metadata};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

pub const LINUX_STATE: &str = "/var/lib/secblitz";
pub const MACOS_STATE: &str = "/Library/Application Support/Secblitz";

// Detail lines are "reason:path" for the log. What a person reads is the one
// sentence `state_dir` puts on top.
fn refusal(reason: &str, path: &Path) -> anyhow::Error {
    anyhow::anyhow!("{reason}:{}", path.display())
}

fn real_dir(path: &Path) -> Result<Metadata> {
    let meta = std::fs::symlink_metadata(path).with_context(|| refusal("unreadable", path))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(refusal("not-a-plain-folder", path));
    }
    Ok(meta)
}

/// Accepts `dir` only if it is a real directory (not a symlink) owned by `owner_uid`,
/// with no group or other permission bits, and every ancestor up to `/` is a real
/// directory owned by `owner_uid` or root and not group- or world-writable
/// (the sticky bit does not make a writable ancestor acceptable).
pub fn check_private_dir(dir: &Path, owner_uid: u32) -> Result<()> {
    check_private_dir_from(dir, owner_uid, Path::new("/"))
}

/// Like `check_private_dir`, but the walk up stops at `trusted_root`, which is
/// itself taken as trusted. A `trusted_root` of `/` checks every ancestor including `/`.
pub fn check_private_dir_from(dir: &Path, owner_uid: u32, trusted_root: &Path) -> Result<()> {
    if !dir.is_absolute() {
        return Err(refusal("relative-path", dir));
    }
    if dir
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(refusal("indirect-path", dir));
    }
    let meta = real_dir(dir)?;
    if meta.uid() != owner_uid {
        return Err(refusal("wrong-owner", dir));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(refusal("open-to-others", dir));
    }
    let whole_path = trusted_root == Path::new("/");
    let mut reached_root = whole_path;
    for ancestor in dir.ancestors().skip(1) {
        if !whole_path && ancestor == trusted_root {
            reached_root = true;
            break;
        }
        let meta = real_dir(ancestor)?;
        if meta.uid() != owner_uid && meta.uid() != 0 {
            return Err(refusal("untrusted-ancestor-owner", ancestor));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(refusal("writable-ancestor", ancestor));
        }
    }
    if !reached_root {
        return Err(refusal("outside-trusted-root", dir));
    }
    Ok(())
}

/// A new folder only the owner can open; the parent must already exist.
pub fn create_private_dir(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

pub(crate) fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn state_path() -> &'static str {
    if cfg!(target_os = "macos") {
        MACOS_STATE
    } else {
        LINUX_STATE
    }
}

pub fn state_dir() -> Result<PathBuf> {
    state_dir_at(Path::new(state_path()), is_root(), 0, Path::new("/"))
}

fn state_dir_at(path: &Path, root: bool, owner_uid: u32, trusted_root: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !root {
                bail!("Secblitz is not fully installed. Reinstall it from the software app.");
            }
            create_private_dir(path)?;
        }
        Err(e) => return Err(e.into()),
    }
    check_private_dir_from(path, owner_uid, trusted_root).context(
        "Secblitz cannot trust its data folder, so it will not change anything. Reinstall it from the software app.",
    )?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn mode(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }

    struct Chain {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    fn chain() -> Chain {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("top");
        std::fs::create_dir(&top).unwrap();
        mode(&top, 0o700);
        Chain { _tmp: tmp, top }
    }

    fn child(parent: &Path, name: &str, bits: u32) -> PathBuf {
        let path = parent.join(name);
        std::fs::create_dir(&path).unwrap();
        mode(&path, bits);
        path
    }

    #[test]
    fn accepts_a_private_folder() {
        let c = chain();
        let dir = child(&c.top, "state", 0o700);
        check_private_dir_from(&dir, uid(), &c.top).unwrap();
    }

    #[test]
    fn refuses_group_or_other_permission_bits() {
        let c = chain();
        for bits in [0o750, 0o705, 0o770, 0o701, 0o740] {
            let dir = child(&c.top, &format!("m{bits:o}"), bits);
            assert!(
                check_private_dir_from(&dir, uid(), &c.top).is_err(),
                "{bits:o}"
            );
        }
    }

    #[test]
    fn refuses_a_symlink_to_a_good_folder() {
        let c = chain();
        let real = child(&c.top, "real", 0o700);
        let link = c.top.join("link");
        symlink(&real, &link).unwrap();
        assert!(check_private_dir_from(&link, uid(), &c.top).is_err());
    }

    #[test]
    fn refuses_a_folder_with_another_owner() {
        let c = chain();
        let dir = child(&c.top, "state", 0o700);
        assert!(check_private_dir_from(&dir, uid() + 1, &c.top).is_err());
    }

    #[test]
    fn refuses_a_writable_ancestor() {
        let c = chain();
        let open = child(&c.top, "open", 0o777);
        let dir = child(&open, "state", 0o700);
        assert!(check_private_dir_from(&dir, uid(), &c.top).is_err());
        mode(&open, 0o1777);
        assert!(check_private_dir_from(&dir, uid(), &c.top).is_err());
        mode(&open, 0o720);
        assert!(check_private_dir_from(&dir, uid(), &c.top).is_err());
        mode(&open, 0o700);
        check_private_dir_from(&dir, uid(), &c.top).unwrap();
    }

    #[test]
    fn refuses_a_symlinked_ancestor() {
        let c = chain();
        let real = child(&c.top, "real", 0o700);
        child(&real, "state", 0o700);
        let link = c.top.join("link");
        symlink(&real, &link).unwrap();
        assert!(check_private_dir_from(&link.join("state"), uid(), &c.top).is_err());
    }

    #[test]
    fn refuses_a_path_that_climbs_out_of_the_checked_ancestors() {
        let c = chain();
        let open = child(&c.top, "open", 0o777);
        let dir = child(&c.top, "state", 0o700);
        let sneaky = open.join("..").join("state");
        assert!(sneaky.exists());
        assert!(check_private_dir_from(&sneaky, uid(), &c.top).is_err());
        check_private_dir_from(&dir, uid(), &c.top).unwrap();
    }

    #[test]
    fn refuses_a_folder_outside_the_trusted_root() {
        let c = chain();
        let other = chain();
        let dir = child(&other.top, "state", 0o700);
        assert!(check_private_dir_from(&dir, uid(), &c.top).is_err());
    }

    #[test]
    fn the_real_check_walks_up_to_the_filesystem_root() {
        let c = chain();
        let dir = child(&c.top, "state", 0o700);
        if std::fs::metadata(std::env::temp_dir()).unwrap().mode() & 0o022 != 0 {
            assert!(check_private_dir(&dir, uid()).is_err());
        }
    }

    #[test]
    fn a_missing_folder_is_created_privately_only_by_root() {
        let c = chain();
        let dir = c.top.join("state");
        let err = state_dir_at(&dir, false, uid(), &c.top).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Secblitz is not fully installed. Reinstall it from the software app."
        );
        assert!(!dir.exists());
        assert_eq!(state_dir_at(&dir, true, uid(), &c.top).unwrap(), dir);
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn an_existing_loose_state_folder_is_refused_not_repaired() {
        let c = chain();
        let dir = child(&c.top, "state", 0o755);
        let err = state_dir_at(&dir, true, uid(), &c.top).unwrap_err();
        assert!(err
            .to_string()
            .starts_with("Secblitz cannot trust its data folder"));
        assert!(format!("{err:#}").contains("open-to-others"));
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn private_dirs_are_created_with_mode_0700() {
        let c = chain();
        let dir = c.top.join("new");
        create_private_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    }
}
