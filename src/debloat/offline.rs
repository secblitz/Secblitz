//! Saving a copy before removal and bringing an app back from it. Decisions live
//! here (tested with a fake `Host`); `WindowsHost` does the real work.
use super::backup::{self, FileEntry, Kind, Store};
#[cfg(any(windows, test))]
use super::backup::{FrameworkCopy, Manifest, SCHEMA};
use super::vault::Sealer;
#[cfg(any(windows, test))]
use super::Kept;
use anyhow::{bail, Result};
#[cfg(any(windows, test))]
use anyhow::{ensure, Context};
#[cfg(any(windows, test))]
use serde::Deserialize;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkg {
    pub full_name: String,
    pub kind: Kind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Described {
    pub packages: Vec<Pkg>,
    pub frameworks: Vec<String>,
    pub provisioned: bool,
    pub users: Vec<String>,
    pub template_family: String,
}

pub type Template = backup::Sddl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    Back,
    BackWithoutSomeData,
    AlreadyThere,
    Damaged,
    NoCopy,
}

pub struct BackupOutcome {
    pub bytes: u64,
}

pub trait Host {
    fn describe(&self, name: &str) -> Result<Described>;
    fn free_bytes(&self) -> Result<u64>;
    fn copy_out(&self, full: &str, dst: &Path) -> Result<Vec<FileEntry>>;
    fn present(&self, full: &str) -> bool;
    fn save_data(
        &self,
        sid: &str,
        family: &str,
        sealer: &dyn Sealer,
        out: &mut dyn Write,
    ) -> Result<u64>;
    fn new_key(&self) -> Result<(Box<dyn Sealer>, Vec<u8>)>;
    fn open_key(&self, sealed: &[u8]) -> Result<Box<dyn Sealer>>;
    fn template(&self, family: &str) -> Result<Template>;
    fn package_sddl(&self, full: &str) -> Result<Template>;
    fn copy_in(
        &self,
        full: &str,
        src: &Path,
        files: &[FileEntry],
        template: &Template,
    ) -> Result<()>;
    fn remove_copy(&self, full: &str) -> Result<()>;
    /// Register, in order; then optionally provision `family` for all accounts.
    fn register(&self, fulls: &[String], provision: Option<&str>) -> Result<()>;
    fn restore_data(
        &self,
        sid: &str,
        family: &str,
        sealer: &dyn Sealer,
        input: &mut dyn Read,
    ) -> Result<()>;
    fn registered_ok(&self, family: &str) -> Result<bool>;
    fn data_folder_ready(&self, sid: &str, family: &str) -> bool;
    fn current_sid(&self) -> Result<String>;
    /// Whether Windows has the app registered. Folders a removal leaves in
    /// WindowsApps do not count.
    fn family_installed(&self, family: &str) -> Result<bool>;
    /// Windows refuses an older copy of a shared part when a newer one is
    /// installed, and apps accept the newer one, so either counts.
    fn framework_present(&self, full: &str) -> bool {
        self.present(full)
    }
}

/// True when `installed` holds `full` or a newer version of the same package
/// (same name, architecture and publisher).
#[cfg(any(windows, test))]
pub(crate) fn same_or_newer<'a>(full: &str, installed: impl IntoIterator<Item = &'a str>) -> bool {
    let Ok(want) = backup::parse_full_name(full) else {
        return false;
    };
    let version = |v: &str| -> Option<[u16; 4]> {
        let mut out = [0u16; 4];
        for (slot, n) in out.iter_mut().zip(v.split('.')) {
            *slot = n.parse().ok()?;
        }
        Some(out)
    };
    let Some(wanted) = version(&want.version) else {
        return false;
    };
    installed.into_iter().any(|name| {
        backup::parse_full_name(name).is_ok_and(|have| {
            have.name.eq_ignore_ascii_case(&want.name)
                && have.arch == want.arch
                && have.resource == want.resource
                && have.publisher == want.publisher
                && version(&have.version).is_some_and(|v| v >= wanted)
        })
    })
}

#[cfg(any(windows, test))]
#[derive(Debug)]
struct LowSpace;
#[cfg(any(windows, test))]
impl std::fmt::Display for LowSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Not enough free space")
    }
}
#[cfg(any(windows, test))]
impl std::error::Error for LowSpace {}

pub const PENDING: &str = "pending.json";

#[cfg(any(windows, test))]
fn no_copy(e: impl std::fmt::Display) -> Kept {
    Kept::NoCopy(crate::text::excerpt(&e.to_string(), 300))
}

#[cfg(any(windows, test))]
pub(crate) fn backup_family_with(
    host: &dyn Host,
    store: &Store,
    index: u16,
    name: &str,
) -> std::result::Result<BackupOutcome, Kept> {
    let d = host.describe(name).map_err(no_copy)?;
    ensure_or(!d.packages.is_empty(), "Nothing to save")?;
    let mut family = None::<String>;
    for p in &d.packages {
        let id = backup::parse_full_name(&p.full_name).map_err(no_copy)?;
        ensure_or(
            super::catalog::owner(&id.name) == Some(index),
            "Package outside the app",
        )?;
        ensure_or(
            family.get_or_insert_with(|| id.family()) == &id.family(),
            "Mixed families",
        )?;
    }
    let family = family.expect("non-empty");
    let free = host.free_bytes().map_err(no_copy)?;
    if free < backup::HEADROOM.saturating_mul(2) {
        return Err(Kept::NoSpace);
    }
    let staging = store.new_staging().map_err(no_copy)?;
    let result = (|| -> Result<Manifest> {
        let mut packages = Vec::new();
        for p in &d.packages {
            let dst = staging.join(backup::PACKAGES).join(&p.full_name);
            let files = host.copy_out(&p.full_name, &dst)?;
            packages.push(backup::Package {
                full_name: p.full_name.clone(),
                kind: p.kind,
                files,
                sddl: recorded_sddl(host, &p.full_name),
            });
            ensure!(host.free_bytes()? >= backup::HEADROOM, LowSpace);
        }
        let mut frameworks = Vec::new();
        for f in &d.frameworks {
            let id = backup::parse_full_name(f)?;
            if id.publisher != backup::MICROSOFT {
                continue;
            }
            if store.load_framework(f).ok().flatten().is_none() && host.present(f) {
                let tmp = store.new_staging()?;
                let files = host.copy_out(f, &tmp.join("files"))?;
                let copy = FrameworkCopy {
                    schema: SCHEMA,
                    full_name: f.clone(),
                    files,
                    sddl: recorded_sddl(host, f),
                };
                std::fs::write(
                    tmp.join(backup::FRAMEWORK_MANIFEST),
                    serde_json::to_vec(&copy)?,
                )?;
                let target = store.framework_dir(f);
                std::fs::create_dir_all(target.parent().context("framework folder")?)?;
                let _ = std::fs::remove_dir_all(&target);
                std::fs::rename(&tmp, &target)?;
            }
            frameworks.push(f.clone());
        }
        let (sealer, sealed_key) = host.new_key()?;
        std::fs::write(staging.join(backup::KEY), &sealed_key)?;
        std::fs::create_dir_all(staging.join(backup::DATA))?;
        let mut data = Vec::new();
        for sid in &d.users {
            if !backup::valid_sid(sid) || !host.data_folder_ready(sid, &family) {
                continue;
            }
            let path = staging.join(backup::DATA).join(format!("{sid}.bin"));
            let mut out = std::fs::File::create(&path)?;
            // Removal deletes this data, so data that can't be saved keeps
            // the app installed.
            let plain_size = host
                .save_data(sid, &family, sealer.as_ref(), &mut out)
                .context("Couldn't save an account's app data")?;
            out.sync_all()?;
            drop(out);
            let (_, sha256) = backup::hash_file(&path)?;
            data.push(backup::DataBlob {
                sid: sid.clone(),
                plain_size,
                sha256,
            });
        }
        let manifest = Manifest {
            schema: SCHEMA,
            created: super::now(),
            index,
            family: family.clone(),
            packages,
            frameworks,
            data,
            provisioned: d.provisioned,
        };
        manifest.check(index)?;
        std::fs::write(
            staging.join(backup::MANIFEST),
            serde_json::to_vec(&manifest)?,
        )?;
        for p in &manifest.packages {
            backup::verify_tree(&staging.join(backup::PACKAGES).join(&p.full_name), &p.files)?;
        }
        Ok(manifest)
    })();
    match result {
        Ok(manifest) => {
            store.commit(&staging, &manifest.family).map_err(no_copy)?;
            let _ = store.gc_frameworks();
            Ok(BackupOutcome {
                bytes: manifest
                    .packages
                    .iter()
                    .flat_map(|p| &p.files)
                    .map(|f| f.size)
                    .sum(),
            })
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            if e.downcast_ref::<LowSpace>().is_some() {
                return Err(Kept::NoSpace);
            }
            Err(no_copy(format!("{e:#}")))
        }
    }
}

/// The package's own permissions, if they pass the same checks restore
/// applies (otherwise restore falls back to a live app's permissions).
#[cfg(any(windows, test))]
fn recorded_sddl(host: &dyn Host, full: &str) -> Option<Template> {
    let family = backup::parse_full_name(full).ok()?.family();
    let s = host.package_sddl(full).ok()?;
    Some(Template {
        dir: backup::own_sddl(&s.dir, &family).ok()?,
        file: backup::own_sddl(&s.file, &family).ok()?,
    })
}

#[cfg(any(windows, test))]
fn permissions_for(
    host: &dyn Host,
    full: &str,
    recorded: &Option<Template>,
    app_family: &str,
    fallback: &mut Option<Template>,
) -> Result<Template> {
    let family = backup::parse_full_name(full)?.family();
    if let Some(r) = recorded {
        if let (Ok(dir), Ok(file)) = (
            backup::own_sddl(&r.dir, &family),
            backup::own_sddl(&r.file, &family),
        ) {
            return Ok(Template { dir, file });
        }
    }
    if fallback.is_none() {
        *fallback = Some(host.template(app_family)?);
    }
    Ok(fallback.clone().expect("set above"))
}

#[cfg(any(windows, test))]
fn ensure_or(ok: bool, why: &str) -> std::result::Result<(), Kept> {
    if ok {
        Ok(())
    } else {
        Err(Kept::NoCopy(why.into()))
    }
}

#[cfg(any(windows, test))]
fn verify(store: &Store, m: &Manifest) -> Result<()> {
    let dir = store.family_dir(&m.family);
    for p in &m.packages {
        backup::verify_tree(&dir.join(backup::PACKAGES).join(&p.full_name), &p.files)?;
    }
    for f in &m.frameworks {
        if let Some(copy) = store.load_framework(f)? {
            backup::verify_tree(&store.framework_dir(f).join("files"), &copy.files)?;
        }
    }
    for b in &m.data {
        let (_, sha) = backup::hash_file(&dir.join(backup::DATA).join(format!("{}.bin", b.sid)))?;
        ensure!(sha == b.sha256, "Saved data changed");
    }
    Ok(())
}

#[cfg(any(windows, test))]
pub(crate) fn restore_with(host: &dyn Host, store: &Store, index: u16) -> Result<Restored> {
    let manifests = store.for_index(index);
    if manifests.is_empty() {
        return Ok(Restored::NoCopy);
    }
    let mut outcome = Restored::Back;
    for m in &manifests {
        if verify(store, m).is_err() {
            return Ok(Restored::Damaged);
        }
        if host.family_installed(&m.family)? {
            outcome = Restored::AlreadyThere;
            continue;
        }
        let mut fallback: Option<Template> = None;
        let dir = store.family_dir(&m.family);
        let mut copied: Vec<String> = Vec::new();
        let mut order: Vec<String> = Vec::new();
        let attempt = (|| -> Result<()> {
            for f in &m.frameworks {
                if host.framework_present(f) {
                    continue;
                }
                let copy = store
                    .load_framework(f)?
                    .context("A part the app needs is missing")?;
                let template = permissions_for(host, f, &copy.sddl, &m.family, &mut fallback)?;
                host.copy_in(
                    f,
                    &store.framework_dir(f).join("files"),
                    &copy.files,
                    &template,
                )?;
                copied.push(f.clone());
                order.push(f.clone());
            }
            for p in &m.packages {
                // Nothing has the app registered, so a folder already there is
                // a leftover and would block the copy.
                if host.present(&p.full_name) {
                    host.remove_copy(&p.full_name)?;
                }
                let template =
                    permissions_for(host, &p.full_name, &p.sddl, &m.family, &mut fallback)?;
                host.copy_in(
                    &p.full_name,
                    &dir.join(backup::PACKAGES).join(&p.full_name),
                    &p.files,
                    &template,
                )?;
                copied.push(p.full_name.clone());
            }
            let bundles: Vec<String> = m
                .packages
                .iter()
                .filter(|p| p.kind == Kind::Bundle)
                .map(|p| p.full_name.clone())
                .collect();
            if bundles.is_empty() {
                order.extend(
                    m.packages
                        .iter()
                        .filter(|p| p.kind == Kind::Main)
                        .map(|p| p.full_name.clone()),
                );
            } else {
                order.extend(bundles);
            }
            let provision = (m.provisioned || m.data.len() > 1).then_some(m.family.as_str());
            host.register(&order, provision)?;
            ensure!(
                host.registered_ok(&m.family)?,
                "Windows did not accept the saved copy"
            );
            Ok(())
        })();
        if let Err(e) = attempt {
            for full in copied.iter().rev() {
                let _ = host.remove_copy(full);
            }
            return Err(e);
        }
        let mut pending = Vec::new();
        for b in &m.data {
            if !host.data_folder_ready(&b.sid, &m.family) {
                // Windows makes the folder at that account's next sign-in;
                // finish_pending writes it when that account opens Secblitz.
                pending.push(b.sid.clone());
            } else if put_back(host, store, m, &b.sid).is_err() {
                outcome = Restored::BackWithoutSomeData;
            }
        }
        if pending.is_empty() {
            let _ = std::fs::remove_file(dir.join(PENDING));
        } else {
            std::fs::write(dir.join(PENDING), serde_json::to_vec(&pending)?)?;
        }
    }
    Ok(outcome)
}

#[cfg(any(windows, test))]
fn put_back(host: &dyn Host, store: &Store, m: &Manifest, sid: &str) -> Result<()> {
    let dir = store.family_dir(&m.family);
    let sealer = host.open_key(&std::fs::read(dir.join(backup::KEY))?)?;
    let mut f = std::fs::File::open(dir.join(backup::DATA).join(format!("{sid}.bin")))?;
    host.restore_data(sid, &m.family, sealer.as_ref(), &mut f)
}

fn read_pending(store: &Store, family: &str) -> Vec<String> {
    std::fs::read(store.family_dir(family).join(PENDING))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|s| backup::valid_sid(s))
        .collect()
}

#[cfg(any(windows, test))]
pub(crate) fn finish_pending_with(host: &dyn Host, store: &Store) -> Result<()> {
    let me = host.current_sid()?;
    for index in 0..super::catalog().len() as u16 {
        for m in store.for_index(index) {
            let mut pending = read_pending(store, &m.family);
            if !pending.contains(&me) || !m.data.iter().any(|b| b.sid == me) {
                continue;
            }
            if !host.data_folder_ready(&me, &m.family) {
                continue;
            }
            // Data that changed on disk is never decrypted.
            if verify(store, &m).is_err() {
                continue;
            }
            if put_back(host, store, &m, &me).is_ok() {
                pending.retain(|s| s != &me);
                if pending.is_empty() {
                    store.delete(&m.family)?;
                    store.gc_frameworks()?;
                } else {
                    let path = store.family_dir(&m.family).join(PENDING);
                    std::fs::write(path, serde_json::to_vec(&pending)?)?;
                }
            }
        }
    }
    Ok(())
}

pub fn finish_pending() {
    #[cfg(windows)]
    if let Ok(store) = Store::open() {
        let _ = finish_pending_with(&WindowsHost, &store);
    }
}

/// The app is installed again (from its copy or from the Store): its saved
/// copy has done its job. A copy still holding data for an account that
/// hasn't signed in yet (`pending.json`) is kept. Damaged copies are removed
/// too, so they are matched by folder name, not by a readable manifest.
pub(crate) fn forget_with(store: &Store, index: u16) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(store.root()) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let Some(family) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((name, _)) = family.rsplit_once('_') else {
            continue;
        };
        if family.starts_with('.')
            || family == backup::FRAMEWORKS
            || super::catalog::owner(name) != Some(index)
            || !read_pending(store, &family).is_empty()
        {
            continue;
        }
        store.delete(&family)?;
    }
    store.gc_frameworks()
}

pub fn forget(index: u16) {
    if let Ok(store) = Store::open() {
        let _ = forget_with(&store, index);
    }
}

pub fn has_copy(index: u16) -> bool {
    Store::open()
        .map(|s| !s.for_index(index).is_empty())
        .unwrap_or(false)
}

pub fn delete_index(index: u16) -> Result<()> {
    let store = Store::open()?;
    for m in store.for_index(index) {
        store.delete(&m.family)?;
    }
    store.gc_frameworks()
}

pub fn saved_bytes() -> u64 {
    Store::open().map(|s| s.total_bytes()).unwrap_or(0)
}

pub fn restore_index(index: u16) -> Result<Restored> {
    #[cfg(windows)]
    {
        let store = Store::open()?;
        store.clean_staging();
        restore_with(&WindowsHost, &store, index)
    }
    #[cfg(not(windows))]
    {
        let _ = index;
        bail!("Only available on Windows")
    }
}

#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDescribed {
    #[serde(default)]
    packages: Vec<RawPkg>,
    #[serde(default)]
    frameworks: Vec<String>,
    #[serde(default)]
    provisioned: bool,
    #[serde(default)]
    users: Vec<String>,
    template: Option<RawTemplate>,
    error: Option<String>,
}
#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPkg {
    full_name: String,
    kind: String,
}
#[cfg(any(windows, test))]
#[derive(Deserialize)]
struct RawTemplate {
    family: String,
}

#[cfg(any(windows, test))]
pub(crate) fn parse_described(json: &str) -> Result<Described> {
    let raw: RawDescribed = serde_json::from_str(json).context("Read the app description")?;
    if let Some(e) = raw.error {
        bail!("{}", crate::text::excerpt(&e, 300));
    }
    let packages = raw
        .packages
        .into_iter()
        .map(|p| {
            let kind = match p.kind.as_str() {
                "bundle" => Kind::Bundle,
                "main" => Kind::Main,
                "resource" => Kind::Resource,
                _ => bail!("Unexpected package kind"),
            };
            backup::parse_full_name(&p.full_name)?;
            Ok(Pkg {
                full_name: p.full_name,
                kind,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Described {
        packages,
        frameworks: raw
            .frameworks
            .into_iter()
            .filter(|f| backup::parse_full_name(f).is_ok())
            .collect(),
        provisioned: raw.provisioned,
        users: raw
            .users
            .into_iter()
            .filter(|s| backup::valid_sid(s))
            .collect(),
        template_family: raw.template.map(|t| t.family).unwrap_or_default(),
    })
}

#[cfg(windows)]
pub struct WindowsHost;

#[cfg(windows)]
impl Host for WindowsHost {
    fn describe(&self, name: &str) -> Result<Described> {
        ensure!(
            super::catalog::is_valid_package_name(name) && super::catalog::owner(name).is_some(),
            "Unknown app"
        );
        let json = super::windows::run(
            super::windows::DESCRIBE,
            &[("SECBLITZ_APP", name)],
            std::time::Duration::from_secs(180),
        )?;
        parse_described(&json)
    }
    fn free_bytes(&self) -> Result<u64> {
        super::winfs::free_bytes(&crate::platform::app_dir()?)
    }
    fn copy_out(&self, full: &str, dst: &Path) -> Result<Vec<FileEntry>> {
        backup::parse_full_name(full)?;
        super::winfs::enable_privileges()?;
        super::winfs::copy_out(&super::winfs::windows_apps()?.join(full), dst)
    }
    fn present(&self, full: &str) -> bool {
        backup::parse_full_name(full).is_ok()
            && super::winfs::windows_apps()
                .is_ok_and(|w| std::fs::symlink_metadata(w.join(full)).is_ok())
    }
    fn framework_present(&self, full: &str) -> bool {
        if self.present(full) {
            return true;
        }
        let Ok(dir) = super::winfs::windows_apps().and_then(|w| Ok(std::fs::read_dir(w)?)) else {
            return false;
        };
        let names: Vec<String> = dir
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        same_or_newer(full, names.iter().map(String::as_str))
    }
    fn save_data(
        &self,
        sid: &str,
        family: &str,
        sealer: &dyn Sealer,
        out: &mut dyn Write,
    ) -> Result<u64> {
        super::winfs::enable_privileges()?;
        let mut source = super::winfs::TreeSource::open(sid, family)?;
        super::vault::encrypt(&mut source, sealer, family, sid, out)
    }
    fn new_key(&self) -> Result<(Box<dyn Sealer>, Vec<u8>)> {
        let key = super::wincrypto::Key::random();
        let sealed = super::wincrypto::seal_key(&key)?;
        Ok((Box::new(super::wincrypto::Aes::new(&key)?), sealed))
    }
    fn open_key(&self, sealed: &[u8]) -> Result<Box<dyn Sealer>> {
        let key = super::wincrypto::unseal_key(sealed)?;
        Ok(Box::new(super::wincrypto::Aes::new(&key)?))
    }
    fn template(&self, family: &str) -> Result<Template> {
        let name = family.rsplit_once('_').context("family")?.0;
        let d = self
            .describe(name)
            .or_else(|_| self.describe("Microsoft.WindowsCalculator"))?;
        let from = d.template_family;
        ensure!(!from.is_empty(), "No app to copy folder permissions from");
        let apps = super::winfs::windows_apps()?;
        let dir = std::fs::read_dir(&apps)?
            .flatten()
            .find(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                backup::parse_full_name(&n)
                    .is_ok_and(|id| id.family() == from && id.resource.is_empty())
            })
            .context("No app to copy folder permissions from")?
            .path();
        let file = std::fs::read_dir(&dir)?
            .flatten()
            .find(|e| e.file_name() == "AppxManifest.xml")
            .context("No app to copy folder permissions from")?
            .path();
        Ok(Template {
            dir: backup::template_sddl(&super::winfs::security_sddl(&dir)?, &from, family)?,
            file: backup::template_sddl(&super::winfs::security_sddl(&file)?, &from, family)?,
        })
    }
    fn package_sddl(&self, full: &str) -> Result<Template> {
        backup::parse_full_name(full)?;
        let dir = super::winfs::windows_apps()?.join(full);
        Ok(Template {
            dir: super::winfs::security_sddl(&dir)?,
            file: super::winfs::security_sddl(&dir.join("AppxBlockMap.xml"))?,
        })
    }
    fn copy_in(
        &self,
        full: &str,
        src: &Path,
        files: &[FileEntry],
        template: &Template,
    ) -> Result<()> {
        backup::parse_full_name(full)?;
        super::winfs::enable_privileges()?;
        super::winfs::copy_in(
            src,
            files,
            &super::winfs::windows_apps()?.join(full),
            &template.dir,
            &template.file,
        )
    }
    fn remove_copy(&self, full: &str) -> Result<()> {
        backup::parse_full_name(full)?;
        super::winfs::enable_privileges()?;
        super::winfs::remove_tree(&super::winfs::windows_apps()?.join(full))
    }
    fn register(&self, fulls: &[String], provision: Option<&str>) -> Result<()> {
        let apps = super::winfs::windows_apps()?;
        let manifests: Vec<String> = fulls
            .iter()
            .map(|f| {
                let id = backup::parse_full_name(f)?;
                let m = if id.resource == "~" {
                    apps.join(f)
                        .join("AppxMetadata")
                        .join("AppxBundleManifest.xml")
                } else {
                    apps.join(f).join("AppxManifest.xml")
                };
                Ok(m.to_string_lossy().into_owned())
            })
            .collect::<Result<_>>()?;
        let request =
            serde_json::json!({ "manifests": manifests, "provision": provision.unwrap_or("") });
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(request.to_string());
        let json = super::windows::run(
            super::windows::REGISTER,
            &[("SECBLITZ_REGISTER", &encoded)],
            std::time::Duration::from_secs(900),
        )?;
        let v: serde_json::Value = serde_json::from_str(&json).context("Read the answer")?;
        ensure!(
            v.get("ok") == Some(&serde_json::Value::Bool(true)),
            "{}",
            v.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Windows did not accept the saved copy")
        );
        Ok(())
    }
    fn restore_data(
        &self,
        sid: &str,
        family: &str,
        sealer: &dyn Sealer,
        input: &mut dyn Read,
    ) -> Result<()> {
        super::winfs::enable_privileges()?;
        let mut sink = super::winfs::DataSink::open(sid, family)?;
        super::vault::decrypt(input, sealer, family, sid, &mut sink)
    }
    fn registered_ok(&self, _family: &str) -> Result<bool> {
        Ok(true)
    }
    fn data_folder_ready(&self, sid: &str, family: &str) -> bool {
        super::winfs::profile_dir(sid).is_ok_and(|p| {
            std::fs::symlink_metadata(
                p.join("AppData")
                    .join("Local")
                    .join("Packages")
                    .join(family),
            )
            .is_ok_and(|m| m.is_dir())
        })
    }
    fn current_sid(&self) -> Result<String> {
        super::winfs::current_sid()
    }
    fn family_installed(&self, family: &str) -> Result<bool> {
        let (name, _) = family.rsplit_once('_').context("Unexpected app family")?;
        Ok(self
            .describe(name)?
            .packages
            .iter()
            .any(|p| p.kind != Kind::Resource))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    const MAIN: &str = "Microsoft.BingWeather_4.54.63045.0_x64__8wekyb3d8bbwe";
    const MAIN2: &str = "Microsoft.BingWeather_4.55.1.0_x64__8wekyb3d8bbwe";
    const BUNDLE: &str = "Microsoft.BingWeather_4.54.63045.0_neutral_~_8wekyb3d8bbwe";
    const FW: &str = "Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe";
    const FAMILY: &str = "Microsoft.BingWeather_8wekyb3d8bbwe";
    const TESTER: &str = "S-1-5-21-1-2-3-1001";

    fn index() -> u16 {
        crate::debloat::catalog::owner("Microsoft.BingWeather").unwrap()
    }

    #[derive(Default)]
    struct Fake {
        described: Described,
        free: u64,
        installed: RefCell<BTreeSet<String>>, // full names in WindowsApps
        registered: RefCell<Vec<Vec<String>>>,
        log: RefCell<Vec<String>>,
        fail_register: bool,
        fail_data_restore: bool,
        fail_save: bool,
        sddls: RefCell<BTreeMap<String, Template>>, // full name -> permissions
        used: RefCell<BTreeMap<String, Template>>,  // permissions given on restore
        data: RefCell<BTreeMap<String, Vec<u8>>>,   // sid -> plaintext marker
        signed_out: RefCell<BTreeSet<String>>,      // accounts with no data folder yet
        me: RefCell<String>,
        leftover: RefCell<BTreeSet<String>>, // folders in WindowsApps nothing has registered
        fail_lookup: bool,
    }

    impl Host for Fake {
        fn describe(&self, _name: &str) -> Result<Described> {
            Ok(self.described.clone())
        }
        fn free_bytes(&self) -> Result<u64> {
            Ok(self.free)
        }
        fn copy_out(&self, full: &str, dst: &Path) -> Result<Vec<FileEntry>> {
            self.log.borrow_mut().push(format!("out {full}"));
            std::fs::create_dir_all(dst)?;
            std::fs::write(dst.join("AppxManifest.xml"), full.as_bytes())?;
            crate::debloat::backup::hash_tree(dst)
        }
        fn present(&self, full: &str) -> bool {
            self.installed.borrow().contains(full)
        }
        fn framework_present(&self, full: &str) -> bool {
            same_or_newer(full, self.installed.borrow().iter().map(String::as_str))
        }
        fn family_installed(&self, family: &str) -> Result<bool> {
            ensure!(!self.fail_lookup, "Windows didn't answer");
            let leftover = self.leftover.borrow();
            Ok(self.installed.borrow().iter().any(|full| {
                !leftover.contains(full)
                    && crate::debloat::backup::parse_full_name(full)
                        .is_ok_and(|id| id.family() == family)
            }))
        }
        fn save_data(
            &self,
            sid: &str,
            _family: &str,
            sealer: &dyn Sealer,
            out: &mut dyn Write,
        ) -> Result<u64> {
            self.log.borrow_mut().push(format!("save {sid}"));
            ensure!(!self.fail_save, "too much data");
            let plain = self.data.borrow().get(sid).cloned().unwrap_or_default();
            crate::debloat::vault::encrypt(&mut OneFile(plain), sealer, FAMILY, sid, out)
        }
        fn new_key(&self) -> Result<(Box<dyn Sealer>, Vec<u8>)> {
            Ok((Box::new(Plain), b"sealed-key".to_vec()))
        }
        fn open_key(&self, sealed: &[u8]) -> Result<Box<dyn Sealer>> {
            ensure!(sealed == b"sealed-key", "bad key");
            Ok(Box::new(Plain))
        }
        fn copy_in(
            &self,
            full: &str,
            _src: &Path,
            _files: &[FileEntry],
            template: &Template,
        ) -> Result<()> {
            self.log.borrow_mut().push(format!("in {full}"));
            self.used
                .borrow_mut()
                .insert(full.to_owned(), template.clone());
            self.installed.borrow_mut().insert(full.to_owned());
            Ok(())
        }
        fn remove_copy(&self, full: &str) -> Result<()> {
            self.log.borrow_mut().push(format!("undo {full}"));
            self.installed.borrow_mut().remove(full);
            Ok(())
        }
        fn template(&self, _family: &str) -> Result<Template> {
            Ok(Template {
                dir: "D".into(),
                file: "F".into(),
            })
        }
        fn package_sddl(&self, full: &str) -> Result<Template> {
            self.sddls
                .borrow()
                .get(full)
                .cloned()
                .context("no permissions")
        }
        fn register(&self, fulls: &[String], provision: Option<&str>) -> Result<()> {
            self.log.borrow_mut().push(format!(
                "register {} provision={}",
                fulls.join(","),
                provision.unwrap_or("")
            ));
            ensure!(!self.fail_register, "Windows said no");
            self.registered.borrow_mut().push(fulls.to_vec());
            Ok(())
        }
        fn restore_data(
            &self,
            sid: &str,
            _family: &str,
            sealer: &dyn Sealer,
            input: &mut dyn Read,
        ) -> Result<()> {
            self.log.borrow_mut().push(format!("data {sid}"));
            ensure!(!self.fail_data_restore, "link found");
            let mut sink = Capture::default();
            crate::debloat::vault::decrypt(input, sealer, FAMILY, sid, &mut sink)?;
            self.data.borrow_mut().insert(sid.to_owned(), sink.0);
            Ok(())
        }
        fn registered_ok(&self, _family: &str) -> Result<bool> {
            Ok(!self.registered.borrow().is_empty())
        }
        fn data_folder_ready(&self, sid: &str, _family: &str) -> bool {
            !self.signed_out.borrow().contains(sid)
        }
        fn current_sid(&self) -> Result<String> {
            Ok(self.me.borrow().clone())
        }
    }

    struct Plain;
    impl Sealer for Plain {
        fn seal(&self, _: &[u8; 12], _: &[u8], p: &[u8]) -> Result<Vec<u8>> {
            let mut v = p.to_vec();
            v.extend_from_slice(&[0u8; 16]);
            Ok(v)
        }
        fn open(&self, _: &[u8; 12], _: &[u8], s: &[u8]) -> Result<Vec<u8>> {
            Ok(s[..s.len() - 16].to_vec())
        }
    }
    struct OneFile(Vec<u8>);
    impl crate::debloat::vault::Source for OneFile {
        fn items(&mut self) -> Result<Vec<crate::debloat::vault::Item>> {
            Ok(vec![crate::debloat::vault::Item::File(
                "LocalState/marker".into(),
                self.0.len() as u64,
            )])
        }
        fn read(&mut self, _: &str, out: &mut dyn Write) -> Result<u64> {
            out.write_all(&self.0)?;
            Ok(self.0.len() as u64)
        }
    }
    #[derive(Default)]
    struct Capture(Vec<u8>);
    impl crate::debloat::vault::Sink for Capture {
        fn dir(&mut self, _: &str) -> Result<()> {
            Ok(())
        }
        fn file(&mut self, _: &str, _: u64, data: &mut dyn Read) -> Result<()> {
            data.read_to_end(&mut self.0)?;
            Ok(())
        }
    }

    fn weather() -> Fake {
        let fake = Fake {
            described: Described {
                packages: vec![
                    Pkg {
                        full_name: BUNDLE.into(),
                        kind: Kind::Bundle,
                    },
                    Pkg {
                        full_name: MAIN.into(),
                        kind: Kind::Main,
                    },
                ],
                frameworks: vec![FW.into()],
                provisioned: false,
                users: vec![TESTER.into()],
                template_family: "Microsoft.WindowsCalculator_8wekyb3d8bbwe".into(),
            },
            free: 100 * GB,
            ..Fake::default()
        };
        fake.installed
            .borrow_mut()
            .extend([BUNDLE.to_string(), MAIN.to_string(), FW.to_string()]);
        fake.data
            .borrow_mut()
            .insert(TESTER.into(), b"favourite city".to_vec());
        fake
    }
    const GB: u64 = 1024 * 1024 * 1024;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join(crate::debloat::backup::DIR));
        (dir, store)
    }

    #[test]
    fn backup_saves_packages_frameworks_and_data_then_commits() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        let m = store.load(FAMILY, index()).unwrap().expect("committed");
        assert_eq!(m.packages.len(), 2);
        assert_eq!(m.frameworks, vec![FW.to_string()]);
        assert_eq!(m.data.len(), 1);
        assert!(store.load_framework(FW).unwrap().is_some());
        assert!(store.family_dir(FAMILY).join("key.bin").exists());
    }

    #[test]
    fn shared_framework_is_copied_once() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.log.borrow_mut().clear();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        assert!(!host.log.borrow().iter().any(|l| l == &format!("out {FW}")));
    }

    #[test]
    fn backup_keeps_every_version_of_the_family() {
        let (_d, store) = store();
        let mut host = weather();
        host.described.packages.push(Pkg {
            full_name: MAIN2.into(),
            kind: Kind::Main,
        });
        host.installed.borrow_mut().insert(MAIN2.into());
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        let m = store.load(FAMILY, index()).unwrap().unwrap();
        assert!(m.packages.iter().any(|p| p.full_name == MAIN2));
    }

    #[test]
    fn low_space_keeps_the_app() {
        let (_d, store) = store();
        let mut host = weather();
        host.free = GB / 2;
        assert!(matches!(
            backup_family_with(&host, &store, index(), "Microsoft.BingWeather"),
            Err(Kept::NoSpace)
        ));
        assert!(store.for_index(index()).is_empty());
    }

    #[test]
    fn foreign_package_in_description_is_refused() {
        let (_d, store) = store();
        let mut host = weather();
        host.described.packages.push(Pkg {
            full_name: "Microsoft.WindowsStore_1.0.0.0_x64__8wekyb3d8bbwe".into(),
            kind: Kind::Main,
        });
        assert!(matches!(
            backup_family_with(&host, &store, index(), "Microsoft.BingWeather"),
            Err(Kept::NoCopy(_))
        ));
        assert!(store.for_index(index()).is_empty());
    }

    #[test]
    fn restore_runs_frameworks_then_app_then_data() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().clear();
        host.data.borrow_mut().clear();
        host.log.borrow_mut().clear();
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::Back
        );
        let log = host.log.borrow().clone();
        let pos = |s: &str| {
            log.iter()
                .position(|l| l.starts_with(s))
                .unwrap_or_else(|| panic!("{s} in {log:?}"))
        };
        assert!(pos(&format!("in {FW}")) < pos(&format!("in {MAIN}")));
        assert!(pos("register") > pos(&format!("in {BUNDLE}")));
        assert!(pos("data") > pos("register"));
        assert_eq!(
            host.registered.borrow()[0],
            vec![FW.to_string(), BUNDLE.to_string()]
        );
        assert_eq!(host.data.borrow().get(TESTER).unwrap(), b"favourite city");
    }

    #[test]
    fn restore_skips_frameworks_already_present() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().retain(|f| f == FW);
        host.log.borrow_mut().clear();
        restore_with(&host, &store, index()).unwrap();
        assert!(!host.log.borrow().iter().any(|l| l == &format!("in {FW}")));
        assert_eq!(host.registered.borrow()[0], vec![BUNDLE.to_string()]);
    }

    #[test]
    fn restore_accepts_a_newer_framework_already_installed() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        let newer = "Microsoft.VCLibs.140.00_14.0.33728.0_x64__8wekyb3d8bbwe";
        *host.installed.borrow_mut() = [newer.to_string()].into_iter().collect();
        host.log.borrow_mut().clear();
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::Back
        );
        assert!(!host.log.borrow().iter().any(|l| l == &format!("in {FW}")));
        assert_eq!(host.registered.borrow()[0], vec![BUNDLE.to_string()]);
    }

    #[test]
    fn only_a_matching_framework_of_the_same_or_higher_version_counts() {
        let fw = "Microsoft.VCLibs.140.00.UWPDesktop_14.0.27629.0_x64__8wekyb3d8bbwe";
        let yes = |installed: &[&str]| same_or_newer(fw, installed.iter().copied());
        assert!(yes(&[fw]));
        assert!(yes(&[
            "Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__8wekyb3d8bbwe"
        ]));
        assert!(yes(&[
            "Microsoft.VCLibs.140.00.UWPDesktop_14.0.27629.1_x64__8wekyb3d8bbwe"
        ]));
        assert!(!yes(&[
            "Microsoft.VCLibs.140.00.UWPDesktop_14.0.27000.0_x64__8wekyb3d8bbwe"
        ]));
        assert!(!yes(&[
            "Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x86__8wekyb3d8bbwe"
        ]));
        assert!(!yes(&[
            "Microsoft.VCLibs.140.00_14.0.33728.0_x64__8wekyb3d8bbwe"
        ]));
        assert!(!yes(&[
            "Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__0000000000000"
        ]));
        assert!(!yes(&[
            "Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__8wekyb3d8bbwe.tmp",
            "Deleted"
        ]));
        assert!(!same_or_newer("not a package", [fw]));
    }

    #[test]
    fn a_folder_left_after_removal_is_not_mistaken_for_the_app() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        *host.installed.borrow_mut() = [MAIN.to_string(), FW.to_string()].into_iter().collect();
        *host.leftover.borrow_mut() = [MAIN.to_string()].into_iter().collect();
        host.log.borrow_mut().clear();
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::Back
        );
        let log = host.log.borrow().clone();
        let pos = |s: &str| {
            log.iter()
                .position(|l| l == s)
                .unwrap_or_else(|| panic!("{s} in {log:?}"))
        };
        assert!(pos(&format!("undo {MAIN}")) < pos(&format!("in {MAIN}")));
        assert_eq!(host.registered.borrow()[0], vec![BUNDLE.to_string()]);
    }

    #[test]
    fn restore_stops_and_keeps_the_copy_when_windows_cannot_say_what_is_installed() {
        let (_d, store) = store();
        let mut host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().clear();
        host.log.borrow_mut().clear();
        host.fail_lookup = true;
        assert!(restore_with(&host, &store, index()).is_err());
        assert!(host.log.borrow().is_empty());
        assert!(!store.for_index(index()).is_empty());
    }

    #[test]
    fn restore_skips_when_already_installed() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::AlreadyThere
        );
        assert!(!host
            .log
            .borrow()
            .iter()
            .any(|l| l.starts_with("in ") || l.starts_with("register")));
    }

    #[test]
    fn damaged_copy_touches_nothing() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().clear();
        let file = store
            .family_dir(FAMILY)
            .join("packages")
            .join(MAIN)
            .join("AppxManifest.xml");
        std::fs::write(&file, b"tampered").unwrap();
        host.log.borrow_mut().clear();
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::Damaged
        );
        assert!(host.log.borrow().is_empty(), "{:?}", host.log.borrow());
    }

    #[test]
    fn windows_refusal_undoes_copied_folders() {
        let (_d, store) = store();
        let mut host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().clear();
        host.fail_register = true;
        assert!(restore_with(&host, &store, index()).is_err());
        assert!(
            host.installed.borrow().is_empty(),
            "copied folders removed again"
        );
    }

    #[test]
    fn data_problem_still_restores_the_app() {
        let (_d, store) = store();
        let mut host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().clear();
        host.fail_data_restore = true;
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::BackWithoutSomeData
        );
    }

    #[test]
    fn other_accounts_data_waits_until_they_open_secblitz() {
        const OTHER: &str = "S-1-5-21-1-2-3-1002";
        let (_d, store) = store();
        let mut host = weather();
        host.described.users.push(OTHER.into());
        host.data
            .borrow_mut()
            .insert(OTHER.into(), b"other city".to_vec());
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        host.installed.borrow_mut().clear();
        host.data.borrow_mut().clear();
        host.signed_out.borrow_mut().insert(OTHER.into());
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::Back
        );
        assert!(host.data.borrow().get(OTHER).is_none());
        assert_eq!(read_pending(&store, FAMILY), vec![OTHER.to_string()]);

        *host.me.borrow_mut() = OTHER.into();
        finish_pending_with(&host, &store).unwrap();
        assert!(host.data.borrow().get(OTHER).is_none());

        host.signed_out.borrow_mut().clear();
        finish_pending_with(&host, &store).unwrap();
        assert_eq!(host.data.borrow().get(OTHER).unwrap(), b"other city");
        assert!(read_pending(&store, FAMILY).is_empty());
        assert!(
            !store.family_dir(FAMILY).exists(),
            "every account has its data back: the copy is gone"
        );
    }

    #[test]
    fn data_that_cannot_be_saved_keeps_the_app() {
        let (_d, store) = store();
        let mut host = weather();
        host.fail_save = true;
        assert!(matches!(
            backup_family_with(&host, &store, index(), "Microsoft.BingWeather"),
            Err(Kept::NoCopy(_))
        ));
        assert!(store.for_index(index()).is_empty());
    }

    #[test]
    fn account_without_a_data_folder_is_skipped_not_fatal() {
        let (_d, store) = store();
        let host = weather();
        host.signed_out.borrow_mut().insert(TESTER.into());
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        assert!(store
            .load(FAMILY, index())
            .unwrap()
            .unwrap()
            .data
            .is_empty());
        assert!(!host.log.borrow().iter().any(|l| l.starts_with("save")));
    }

    #[test]
    fn copy_is_forgotten_once_the_app_is_back() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        let other = store.family_dir("Microsoft.BingNews_8wekyb3d8bbwe");
        std::fs::create_dir_all(&other).unwrap();
        let damaged = store.family_dir("Microsoft.BingWeather_abcdefghijklm");
        std::fs::create_dir_all(&damaged).unwrap();
        std::fs::write(damaged.join(crate::debloat::backup::MANIFEST), b"junk").unwrap();
        forget_with(&store, index()).unwrap();
        assert!(!store.family_dir(FAMILY).exists());
        assert!(!damaged.exists());
        assert!(other.exists());
        assert!(
            !store.framework_dir(FW).exists(),
            "unused framework removed"
        );
    }

    #[test]
    fn copy_with_waiting_data_is_kept() {
        let (_d, store) = store();
        let host = weather();
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        std::fs::write(
            store.family_dir(FAMILY).join(PENDING),
            serde_json::to_vec(&vec!["S-1-5-21-1-2-3-1002"]).unwrap(),
        )
        .unwrap();
        forget_with(&store, index()).unwrap();
        assert!(store.family_dir(FAMILY).exists());
    }

    #[test]
    fn restore_gives_each_package_its_own_permissions() {
        const APP: &str = "O:SYG:SYD:AI(XA;OICI;0x1200a9;;;BU;(WIN://SYSAPPID Contains \"Microsoft.BingWeather_8wekyb3d8bbwe\"))(A;OICIID;FA;;;SY)";
        const SHARED: &str =
            "O:BAG:SYD:AI(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;AC)(A;OICIID;FA;;;SY)";
        let own = |dir: &str| Template {
            dir: dir.into(),
            file: dir.replace("OICI", ""),
        };
        let (_d, store) = store();
        let host = weather();
        host.sddls.borrow_mut().insert(MAIN.into(), own(APP));
        host.sddls.borrow_mut().insert(FW.into(), own(SHARED));
        host.sddls
            .borrow_mut()
            .insert(BUNDLE.into(), own("O:SYG:SYD:(A;;FA;;;WD)"));
        backup_family_with(&host, &store, index(), "Microsoft.BingWeather").unwrap();
        let m = store.load(FAMILY, index()).unwrap().unwrap();
        assert!(m
            .packages
            .iter()
            .find(|p| p.full_name == BUNDLE)
            .unwrap()
            .sddl
            .is_none());
        host.installed.borrow_mut().clear();
        restore_with(&host, &store, index()).unwrap();
        let used = host.used.borrow();
        assert_eq!(used[MAIN], own(APP));
        assert_eq!(
            used[FW],
            own(SHARED),
            "a shared part keeps its open permissions"
        );
        assert_eq!(
            used[BUNDLE].dir, "D",
            "no usable record: the live-app template"
        );
    }

    #[test]
    fn no_copy_means_store_fallback() {
        let (_d, store) = store();
        let host = weather();
        assert_eq!(
            restore_with(&host, &store, index()).unwrap(),
            Restored::NoCopy
        );
    }

    #[test]
    fn failed_removal_keeps_app_and_copy() {
        let (_d, store) = store();
        let host = weather();
        let installed = vec![crate::debloat::Installed {
            index: index(),
            package: "Microsoft.BingWeather".into(),
            version: "4.54".into(),
        }];
        let backup = |i: &crate::debloat::Installed| {
            backup_family_with(&host, &store, i.index, &i.package).map(|_| ())
        };
        let batch = crate::debloat::remove_with(
            &[index()],
            &installed,
            &backup,
            &|_| crate::debloat::PackageOutcome::Failed("busy".into()),
            &|_| {},
        )
        .unwrap();
        assert!(batch.removed.is_empty());
        assert_eq!(batch.failed.len(), 1);
        assert!(store.load(FAMILY, index()).unwrap().is_some());
    }

    #[test]
    fn parses_description_and_drops_junk() {
        let json = r#"{"packages":[{"fullName":"Microsoft.BingWeather_4.54.63045.0_x64__8wekyb3d8bbwe","kind":"main","family":"x"}],
            "frameworks":["Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe","bad name"],
            "provisioned":true,"users":["S-1-5-21-1-2-3-1001","S-1-5-18"],
            "template":{"family":"Microsoft.WindowsCalculator_8wekyb3d8bbwe","fullName":"x"},"error":null}"#;
        let d = parse_described(json).unwrap();
        assert_eq!(d.packages.len(), 1);
        assert_eq!(d.frameworks.len(), 1);
        assert_eq!(d.users, vec!["S-1-5-21-1-2-3-1001".to_string()]);
        assert!(d.provisioned);
        assert!(parse_described(r#"{"error":"boom"}"#).is_err());
        assert!(parse_described(r#"{"packages":[{"fullName":"../x","kind":"main"}]}"#).is_err());
    }
}
