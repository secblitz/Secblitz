//! Per-user GUI preferences and the system switches behind the Settings page.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    #[default]
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolsTab {
    #[default]
    Tips,
    Viruses,
    Updates,
    Account,
}

impl ToolsTab {
    pub const ALL: [Self; 4] = [Self::Tips, Self::Viruses, Self::Updates, Self::Account];

    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "tips" => Self::Tips,
            "viruses" => Self::Viruses,
            "updates" => Self::Updates,
            "account" => Self::Account,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    #[serde(default)]
    pub theme: ThemeChoice,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub tools_tab: ToolsTab,
    #[serde(default)]
    pub protection_topic: Option<super::topics::Topic>,
    #[serde(default = "on")]
    pub notify_reverted: bool,
    #[serde(default = "on")]
    pub notify_dangerous: bool,
    #[serde(default)]
    pub processor_tip_seen: bool,
    #[serde(default)]
    pub whats_new_seen: Option<String>,
    #[serde(default)]
    pub welcome_seen: bool,
}

fn on() -> bool {
    true
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            theme: ThemeChoice::default(),
            lang: None,
            tools_tab: ToolsTab::default(),
            protection_topic: None,
            notify_reverted: true,
            notify_dangerous: true,
            processor_tip_seen: false,
            whats_new_seen: None,
            welcome_seen: false,
        }
    }
}

impl Prefs {
    pub fn notify(&self) -> secblitz::status::Notify {
        secblitz::status::Notify::new(self.notify_reverted, self.notify_dangerous)
    }
}

pub const FILE: &str = "gui-prefs.json";
const LIMIT: u64 = 8 * 1024;

fn path() -> anyhow::Result<PathBuf> {
    // Tests run elevated on Windows and must not share or overwrite the machine's file.
    if cfg!(test) {
        anyhow::bail!("Preferences are not stored during tests");
    }
    Ok(secblitz::platform::app_dir()?.join(FILE))
}

/// Parse untrusted bytes. Unknown fields and bad values fall back to defaults
/// one field at a time, so one bad value never resets the others.
pub fn parse(bytes: &[u8]) -> Prefs {
    let mut prefs = Prefs::default();
    if bytes.len() as u64 > LIMIT {
        return prefs;
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(bytes)
    else {
        return prefs;
    };
    match map.get("theme").and_then(|v| v.as_str()) {
        Some("dark") => prefs.theme = ThemeChoice::Dark,
        _ => prefs.theme = ThemeChoice::Light,
    }
    prefs.lang = map
        .get("lang")
        .and_then(|v| v.as_str())
        .filter(|code| crate::i18n::Lang::parse(code).is_some())
        .map(str::to_owned);
    for (key, slot) in [
        ("notify_reverted", &mut prefs.notify_reverted),
        ("notify_dangerous", &mut prefs.notify_dangerous),
    ] {
        *slot = map.get(key).and_then(|v| v.as_bool()).unwrap_or(true);
    }
    prefs.processor_tip_seen = map
        .get("processor_tip_seen")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    prefs.welcome_seen = map
        .get("welcome_seen")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    prefs.whats_new_seen = map
        .get("whats_new_seen")
        .and_then(|v| v.as_str())
        .filter(|v| v.len() <= 32 && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        .map(str::to_owned);
    if let Some(tab) = map
        .get("tools_tab")
        .and_then(|v| v.as_str())
        .and_then(ToolsTab::parse)
    {
        prefs.tools_tab = tab;
    }
    prefs.protection_topic = map
        .get("protection_topic")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    prefs
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

pub fn load() -> Prefs {
    path()
        .ok()
        .and_then(|p| read_bounded(&p))
        .map(|bytes| parse(&bytes))
        .unwrap_or_default()
}

pub fn save(prefs: &Prefs) -> anyhow::Result<()> {
    write_to(&path()?, prefs)
}

fn write_to(path: &Path, prefs: &Prefs) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(prefs)?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, bytes)?;
    std::fs::rename(&temp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })?;
    Ok(())
}

#[cfg_attr(not(windows), allow(dead_code))]
pub const TRAY_VALUE: &str = "SecblitzTray";

#[cfg_attr(not(windows), allow(dead_code))]
pub fn tray_command(exe: &Path) -> String {
    format!("\"{}\" tray", exe.display())
}

/// The running exe, but only when it is the installed copy
/// (`%ProgramFiles%\Secblitz\secblitz.exe`). A copy elsewhere must never
/// become a logon autostart target.
pub fn installed_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    #[cfg(windows)]
    {
        // Resolved with SHGetKnownFolderPath, never from the inherited environment.
        crate::service::trusted_status_dir()?;
        Some(exe)
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("ProgramFiles")?;
        let expected = Path::new(&base).join("Secblitz").join("secblitz.exe");
        same_path(&exe, &expected).then_some(exe)
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&b.to_string_lossy().replace('/', "\\"))
}

pub fn tray_enabled() -> bool {
    #[cfg(windows)]
    {
        run_key::get().is_some()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// True only when Windows confirms the startup entry is gone, never on a failed read,
/// so a running tray closes when the user turns it off and not on a passing error.
#[cfg(windows)]
pub fn tray_turned_off() -> bool {
    run_key::absent()
}

pub fn set_tray_enabled(on: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if on {
            let exe = installed_exe()
                .ok_or_else(|| anyhow::anyhow!("Only the installed copy can start with Windows"))?;
            run_key::set(&tray_command(&exe))
        } else {
            run_key::remove()
        }
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        anyhow::bail!("The taskbar icon is only available on Windows")
    }
}

#[cfg(windows)]
mod run_key {
    use super::TRAY_VALUE;
    use std::ptr::null_mut;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_SZ,
    };

    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const ERROR_FILE_NOT_FOUND: u32 = 2;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key was opened by `open` and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(access: u32) -> Result<Key, u32> {
        let mut key: HKEY = null_mut();
        let path = wide(RUN);
        // SAFETY: `path` is NUL-terminated and `key` is a valid out pointer.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                access | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if status == 0 {
            Ok(Key(key))
        } else {
            Err(status)
        }
    }

    pub fn get() -> Option<String> {
        let key = open(KEY_QUERY_VALUE).ok()?;
        let name = wide(TRAY_VALUE);
        let mut size = 0u32;
        // SAFETY: a null data pointer only asks for the value size.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut size,
            )
        };
        if status == 0 && size > 0 && size <= 4096 {
            let mut buf = vec![0u16; (size as usize).div_ceil(2)];
            let mut size = (buf.len() * 2) as u32;
            // SAFETY: `buf` holds `size` bytes, as passed in.
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    null_mut(),
                    null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            (status == 0).then(|| {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                String::from_utf16_lossy(&buf[..end])
            })
        } else {
            None
        }
    }

    pub fn absent() -> bool {
        let Ok(key) = open(KEY_QUERY_VALUE) else {
            return false;
        };
        let name = wide(TRAY_VALUE);
        let mut size = 0u32;
        // SAFETY: a null data pointer only asks for the value size.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut size,
            )
        };
        status == ERROR_FILE_NOT_FOUND
    }

    pub fn set(command: &str) -> anyhow::Result<()> {
        let key = open(KEY_SET_VALUE)
            .map_err(|s| anyhow::anyhow!("Cannot open the startup list ({s})"))?;
        let name = wide(TRAY_VALUE);
        let data = wide(command);
        // SAFETY: `name` and `data` are NUL-terminated and the byte length matches `data`.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        anyhow::ensure!(status == 0, "Cannot save the startup entry ({status})");
        Ok(())
    }

    pub fn remove() -> anyhow::Result<()> {
        let key = open(KEY_SET_VALUE)
            .map_err(|s| anyhow::anyhow!("Cannot open the startup list ({s})"))?;
        let name = wide(TRAY_VALUE);
        // SAFETY: `name` is NUL-terminated and the key is open for writing.
        let status = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        anyhow::ensure!(
            status == 0 || status == ERROR_FILE_NOT_FOUND,
            "Cannot remove the startup entry ({status})"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn background_on() -> anyhow::Result<bool> {
    secblitz::updater::linux::monitor_timer_on(&secblitz::linux::cmd::RealSys)
}

#[cfg(target_os = "linux")]
pub fn enable_background() -> anyhow::Result<()> {
    super::remote::set_monitor_timer(&mut crate::linux_bus::client::DbusTransport::system(), true)
}

#[cfg(target_os = "linux")]
pub fn disable_background() -> anyhow::Result<()> {
    super::remote::set_monitor_timer(
        &mut crate::linux_bus::client::DbusTransport::system(),
        false,
    )
}

/// What the last update check found. On Linux the result is kept in a folder only the helper can open.
pub fn update_status() -> anyhow::Result<secblitz::updater::UpdateStatus> {
    #[cfg(target_os = "linux")]
    {
        super::remote::update_status(&mut crate::linux_bus::client::DbusTransport::system())
    }
    #[cfg(not(target_os = "linux"))]
    {
        secblitz::updater::status()
    }
}

#[cfg(target_os = "linux")]
pub fn install_update() -> anyhow::Result<secblitz::updater::UpdateStatus> {
    super::remote::install_update(&mut crate::linux_bus::client::DbusTransport::system())
}

#[cfg(target_os = "linux")]
pub fn updates_by_software_app() -> bool {
    secblitz::updater::linux::repository_configured(&secblitz::linux::cmd::RealSys)
}

#[cfg(not(target_os = "linux"))]
pub fn background_on() -> anyhow::Result<bool> {
    use secblitz::service::MonitorState;
    Ok(!matches!(
        secblitz::service::query_status()?.state,
        MonitorState::NotInstalled | MonitorState::Stopped
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn enable_background() -> anyhow::Result<()> {
    use secblitz::service::{self, MonitorState};
    if service::query_status()?.state == MonitorState::NotInstalled {
        service::install()?;
    }
    if !matches!(
        service::query_status()?.state,
        MonitorState::Running | MonitorState::StartPending
    ) {
        service::start()?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn disable_background() -> anyhow::Result<()> {
    #[cfg(windows)]
    stop_monitor()?;
    secblitz::service::uninstall()
}

#[cfg(windows)]
fn stop_monitor() -> anyhow::Result<()> {
    use std::time::{Duration, Instant};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let scm = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match scm.open_service(
        "SecblitzMonitor",
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    ) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(30);
        while service.query_status()?.current_state != ServiceState::Stopped {
            anyhow::ensure!(
                Instant::now() < deadline,
                "The background check did not stop in time"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_tolerant_and_validates_fields() {
        assert_eq!(parse(b""), Prefs::default());
        assert_eq!(parse(b"not json"), Prefs::default());
        assert_eq!(parse(b"[1,2]"), Prefs::default());
        let p = parse(br#"{"theme":"dark","lang":"es","extra":1}"#);
        assert_eq!(p.theme, ThemeChoice::Dark);
        assert_eq!(p.lang.as_deref(), Some("es"));
        let p = parse(br#"{"theme":"neon","lang":"fr"}"#);
        assert_eq!(p.theme, ThemeChoice::Light);
        assert_eq!(p.lang.as_deref(), Some("fr"));
        let p = parse(br#"{"theme":"dark","lang":"../../etc"}"#);
        assert_eq!(p.theme, ThemeChoice::Dark);
        assert_eq!(p.lang, None);
        let p = parse(br#"{"tools_tab":"updates"}"#);
        assert_eq!(p.tools_tab, ToolsTab::Updates);
        assert_eq!(parse(br#"{"tools_tab":"bogus"}"#).tools_tab, ToolsTab::Tips);
        assert_eq!(parse(br#"{"tools_tab":7}"#).tools_tab, ToolsTab::Tips);
        assert_eq!(parse(br#"{"theme":"dark"}"#).tools_tab, ToolsTab::Tips);
        let big = format!(r#"{{"theme":"dark","pad":"{}"}}"#, "x".repeat(9000));
        assert_eq!(parse(big.as_bytes()), Prefs::default());
    }

    #[test]
    fn save_and_load_round_trip_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(FILE);
        let prefs = Prefs {
            theme: ThemeChoice::Dark,
            lang: Some("de".into()),
            tools_tab: ToolsTab::Account,
            protection_topic: Some(crate::app::topics::Topic::Browsers),
            notify_reverted: false,
            notify_dangerous: true,
            processor_tip_seen: true,
            whats_new_seen: Some("0.11.0".into()),
            welcome_seen: true,
        };
        write_to(&file, &prefs).unwrap();
        assert_eq!(parse(&read_bounded(&file).unwrap()), prefs);
        assert!(!dir.path().join("gui-prefs.json.tmp").exists());
        std::fs::write(&file, b"{broken").unwrap();
        assert_eq!(parse(&read_bounded(&file).unwrap()), Prefs::default());
    }

    #[test]
    fn the_processor_tip_is_unseen_until_recorded() {
        assert!(!Prefs::default().processor_tip_seen);
        assert!(!parse(b"{}").processor_tip_seen);
        assert!(!parse(br#"{"processor_tip_seen":"yes"}"#).processor_tip_seen);
        let seen = parse(br#"{"processor_tip_seen":true,"theme":"dark"}"#);
        assert!(seen.processor_tip_seen);
        assert_eq!(seen.theme, ThemeChoice::Dark);
    }

    #[test]
    fn the_welcome_is_unseen_until_recorded() {
        assert!(!Prefs::default().welcome_seen);
        assert!(!parse(b"{}").welcome_seen);
        assert!(!parse(br#"{"welcome_seen":"yes"}"#).welcome_seen);
        let seen = parse(br#"{"welcome_seen":true,"theme":"dark"}"#);
        assert!(seen.welcome_seen);
        assert_eq!(seen.theme, ThemeChoice::Dark);
        let bytes = serde_json::to_vec(&seen).unwrap();
        assert!(parse(&bytes).welcome_seen);
    }

    #[test]
    fn only_a_version_number_is_kept_as_the_last_news_seen() {
        assert_eq!(parse(b"{}").whats_new_seen, None);
        assert_eq!(
            parse(br#"{"whats_new_seen":"0.10.0"}"#)
                .whats_new_seen
                .as_deref(),
            Some("0.10.0")
        );
        assert_eq!(parse(br#"{"whats_new_seen":"<b>"}"#).whats_new_seen, None);
        assert_eq!(parse(br#"{"whats_new_seen":10}"#).whats_new_seen, None);
    }

    #[test]
    fn a_bad_tools_value_keeps_the_other_choices() {
        let p = parse(br#"{"theme":"dark","lang":"it","tools_tab":["nope"]}"#);
        assert_eq!(p.theme, ThemeChoice::Dark);
        assert_eq!(p.lang.as_deref(), Some("it"));
        assert_eq!(p.tools_tab, ToolsTab::Tips);
    }

    #[test]
    fn a_bad_topic_is_forgotten_and_a_good_one_kept() {
        use crate::app::topics::Topic;
        let p = parse(br#"{"theme":"dark","protection_topic":"sign_in"}"#);
        assert_eq!(p.protection_topic, Some(Topic::SignIn));
        assert_eq!(p.theme, ThemeChoice::Dark);
        for bad in [r#""nope""#, "7", "null", "[1]", r#"{"a":1}"#] {
            let text = format!(r#"{{"lang":"fr","protection_topic":{bad}}}"#);
            let p = parse(text.as_bytes());
            assert_eq!(p.protection_topic, None, "{bad}");
            assert_eq!(p.lang.as_deref(), Some("fr"), "{bad}");
        }
        assert_eq!(parse(b"{}").protection_topic, None);
    }

    #[test]
    fn notices_are_on_unless_switched_off() {
        let p = Prefs::default();
        assert!(p.notify_reverted && p.notify_dangerous);
        let old = parse(br#"{"theme":"dark","lang":"es"}"#);
        assert!(old.notify_reverted && old.notify_dangerous);
        let off = parse(br#"{"notify_reverted":false,"notify_dangerous":false}"#);
        assert!(!off.notify_reverted && !off.notify_dangerous);
        assert_eq!(off.notify(), secblitz::status::Notify::new(false, false));
        let one = parse(br#"{"notify_reverted":false}"#);
        assert!(!one.notify_reverted && one.notify_dangerous);
        let junk = parse(br#"{"notify_reverted":"no","notify_dangerous":0}"#);
        assert!(junk.notify_reverted && junk.notify_dangerous);
    }

    #[test]
    fn older_preferences_with_open_sections_still_load() {
        let p = parse(br#"{"theme":"dark","lang":"fr","tools_open":["repair","virus"]}"#);
        assert_eq!(p.theme, ThemeChoice::Dark);
        assert_eq!(p.lang.as_deref(), Some("fr"));
        assert_eq!(p.tools_tab, ToolsTab::Tips);
        let direct: Prefs =
            serde_json::from_slice(br#"{"tools_open":["virus"],"tools_tab":"viruses"}"#).unwrap();
        assert_eq!(direct.tools_tab, ToolsTab::Viruses);
    }

    #[test]
    fn tray_command_quotes_the_exe_and_uses_only_the_tray_word() {
        let c = tray_command(Path::new(r"C:\Program Files\Secblitz\secblitz.exe"));
        assert_eq!(c, r#""C:\Program Files\Secblitz\secblitz.exe" tray"#);
    }

    #[test]
    fn path_comparison_ignores_case_and_slashes() {
        assert!(same_path(
            Path::new(r"C:\Program Files\Secblitz\secblitz.exe"),
            Path::new("c:/program files/secblitz/SECBLITZ.EXE")
        ));
        assert!(!same_path(
            Path::new(r"C:\Users\x\Downloads\secblitz.exe"),
            Path::new(r"C:\Program Files\Secblitz\secblitz.exe")
        ));
    }
}
