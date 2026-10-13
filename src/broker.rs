//! Launcher <-> elevated GUI broker: a closed set of user-context actions.

use crate::app::app_access::{self, Capability, Target};
use secblitz::space::{Tally, UserArea};
use secblitz::user_settings::{Op, Setting};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceOp {
    Measure,
    Clean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    OpenWindowsUpdate,
    OpenWindowsSecurity,
    OpenEncryption,
    OpenSignIn,
    InstallBitwarden,
    BlockSuggestedApps,
    ReinstallStoreApp(u16),
    StartStoreApp(u16),
    StoreAppStatus(u16),
    OpenTamperProtection,
    OpenProtectionHistory,
    OpenProtectionHistoryList,
    OpenNetwork,
    OpenAppBrowserControl,
    OpenOptionalFeatures,
    OpenAccounts,
    OpenCoreIsolation,
    OpenFirewall,
    OpenDeviceSecurity,
    OpenWorkAccounts,
    OpenRecovery,
    OpenRemoteDesktop,
    OpenFindMyDevice,
    OpenBitLocker,
    OpenWifi,
    OpenBackup,
    OpenStorage,
    OpenInstalledApps,
    OpenTaskbar,
    OpenReportProblem,
    OpenSuggestFeature,
    OpenPrivacyPolicy,
    OpenRecoveryKey,
    StartTray,
    OpenDownloadPage,
    ShowSupportFile,
    /// Followed on the wire by a `FileHeader` and the zip itself; sent with `Client::save_file`.
    SaveSupportFile,
    UserSetting(Setting, Op),
    /// Answered with `SPACE_REPLY` bytes; sent with `Client::space`.
    Space(UserArea, SpaceOp),
    BitwardenStatus,
    AppAccessList(Capability),
    AppAccessSet {
        capability: Capability,
        target: Target,
        tag: u8,
        allow: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum Reply {
    Done,
    Failed,
    OpenedStore,
    Unavailable,
    Offline,
    Safe,
    SafeByUs,
    NeedsAttention,
    NotApplicable,
    Unknown,
    Working,
    ChangedSince,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Reply {
    pub fn from_result(result: secblitz::user_settings::HandleResult) -> Self {
        use secblitz::user_settings::{HandleResult, Outcome, Report};
        match result {
            HandleResult::Report(Report::Safe) => Reply::Safe,
            HandleResult::Report(Report::SafeByUs) => Reply::SafeByUs,
            HandleResult::Report(Report::Unsafe) => Reply::NeedsAttention,
            HandleResult::Report(Report::NotApplicable) => Reply::NotApplicable,
            HandleResult::Report(Report::Unknown) => Reply::Unknown,
            HandleResult::Outcome(Outcome::Done) => Reply::Done,
            HandleResult::Outcome(Outcome::Failed) => Reply::Failed,
            HandleResult::Outcome(Outcome::Blocked) => Reply::Unavailable,
            HandleResult::Outcome(Outcome::ChangedSince) => Reply::ChangedSince,
        }
    }

    pub fn encode(self) -> u8 {
        match self {
            Reply::Done => 1,
            Reply::Failed => 2,
            Reply::OpenedStore => 3,
            Reply::Unavailable => 4,
            Reply::Offline => 5,
            Reply::Safe => 6,
            Reply::SafeByUs => 7,
            Reply::NeedsAttention => 8,
            Reply::NotApplicable => 9,
            Reply::Unknown => 10,
            Reply::Working => 12,
            Reply::ChangedSince => 13,
        }
    }
    pub fn decode(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Reply::Done,
            2 => Reply::Failed,
            3 => Reply::OpenedStore,
            4 => Reply::Unavailable,
            5 => Reply::Offline,
            6 => Reply::Safe,
            7 => Reply::SafeByUs,
            8 => Reply::NeedsAttention,
            9 => Reply::NotApplicable,
            10 => Reply::Unknown,
            12 => Reply::Working,
            13 => Reply::ChangedSince,
            _ => return None,
        })
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Request {
    pub fn is_read_only(self) -> bool {
        match self {
            Request::StoreAppStatus(_)
            | Request::StartStoreApp(_)
            | Request::BitwardenStatus
            | Request::AppAccessList(_)
            | Request::UserSetting(_, Op::Query)
            | Request::OpenReportProblem
            | Request::OpenSuggestFeature
            | Request::OpenPrivacyPolicy
            | Request::OpenRecoveryKey
            | Request::OpenDownloadPage
            | Request::ShowSupportFile
            | Request::SaveSupportFile
            | Request::Space(..) => true,
            Request::UserSetting(_, Op::Apply | Op::Undo)
            | Request::InstallBitwarden
            | Request::BlockSuggestedApps
            | Request::ReinstallStoreApp(_)
            | Request::AppAccessSet { .. } => false,
            Request::OpenWindowsUpdate
            | Request::OpenWindowsSecurity
            | Request::OpenEncryption
            | Request::OpenSignIn
            | Request::OpenTamperProtection
            | Request::OpenProtectionHistory
            | Request::OpenProtectionHistoryList
            | Request::OpenNetwork
            | Request::OpenAppBrowserControl
            | Request::OpenOptionalFeatures
            | Request::OpenAccounts
            | Request::OpenCoreIsolation
            | Request::OpenFirewall
            | Request::OpenDeviceSecurity
            | Request::OpenWorkAccounts
            | Request::OpenRecovery
            | Request::OpenRemoteDesktop
            | Request::OpenFindMyDevice
            | Request::OpenBitLocker
            | Request::OpenWifi
            | Request::OpenBackup
            | Request::OpenStorage
            | Request::OpenInstalledApps
            | Request::OpenTaskbar
            | Request::StartTray => false,
        }
    }

    pub fn opens_window(self) -> bool {
        self.page().is_some() || self == Request::ShowSupportFile
    }

    /// The settings page or web page this request opens, if that is all it does.
    pub fn page(self) -> Option<secblitz::actions::Action> {
        use secblitz::actions::Action;
        Some(match self {
            Request::OpenWindowsUpdate => Action::OpenWindowsUpdate,
            Request::OpenWindowsSecurity => Action::OpenWindowsSecurity,
            Request::OpenEncryption => Action::OpenEncryptionSettings,
            Request::OpenSignIn => Action::OpenSignInSettings,
            Request::OpenTamperProtection => Action::OpenTamperProtection,
            Request::OpenProtectionHistory => Action::OpenProtectionHistory,
            Request::OpenProtectionHistoryList => Action::OpenProtectionHistoryList,
            Request::OpenNetwork => Action::OpenNetwork,
            Request::OpenAppBrowserControl => Action::OpenAppBrowserControl,
            Request::OpenOptionalFeatures => Action::OpenOptionalFeatures,
            Request::OpenAccounts => Action::OpenAccounts,
            Request::OpenCoreIsolation => Action::OpenCoreIsolation,
            Request::OpenFirewall => Action::OpenFirewall,
            Request::OpenDeviceSecurity => Action::OpenDeviceSecurity,
            Request::OpenWorkAccounts => Action::OpenWorkAccounts,
            Request::OpenRecovery => Action::OpenRecovery,
            Request::OpenRemoteDesktop => Action::OpenRemoteDesktop,
            Request::OpenFindMyDevice => Action::OpenFindMyDevice,
            Request::OpenBitLocker => Action::OpenBitLocker,
            Request::OpenWifi => Action::OpenWifi,
            Request::OpenBackup => Action::OpenBackup,
            Request::OpenStorage => Action::OpenStorage,
            Request::OpenInstalledApps => Action::OpenInstalledApps,
            Request::OpenTaskbar => Action::OpenTaskbar,
            Request::OpenReportProblem => Action::OpenReportProblem,
            Request::OpenSuggestFeature => Action::OpenSuggestFeature,
            Request::OpenPrivacyPolicy => Action::OpenPrivacyPolicy,
            Request::OpenRecoveryKey => Action::OpenRecoveryKey,
            Request::OpenDownloadPage => Action::OpenDownloadPage,
            Request::InstallBitwarden
            | Request::BlockSuggestedApps
            | Request::ReinstallStoreApp(_)
            | Request::StartStoreApp(_)
            | Request::StoreAppStatus(_)
            | Request::UserSetting(..)
            | Request::BitwardenStatus
            | Request::AppAccessList(_)
            | Request::AppAccessSet { .. }
            | Request::StartTray
            | Request::ShowSupportFile
            | Request::SaveSupportFile
            | Request::Space(..) => return None,
        })
    }

    pub fn encode(self) -> [u8; 3] {
        let (kind, arg) = match self {
            Request::OpenWindowsUpdate => (1, 0),
            Request::OpenWindowsSecurity => (2, 0),
            Request::OpenEncryption => (3, 0),
            Request::OpenSignIn => (4, 0),
            Request::InstallBitwarden => (5, 0),
            Request::BlockSuggestedApps => (6, 0),
            Request::ReinstallStoreApp(i) => (7, i),
            Request::OpenTamperProtection => (8, 0),
            Request::OpenProtectionHistory => (9, 0),
            Request::OpenAppBrowserControl => (10, 0),
            Request::OpenOptionalFeatures => (11, 0),
            Request::OpenAccounts => (12, 0),
            Request::OpenCoreIsolation => (20, 0),
            Request::OpenFirewall => (21, 0),
            Request::OpenDeviceSecurity => (22, 0),
            Request::OpenWorkAccounts => (23, 0),
            Request::OpenRecovery => (24, 0),
            Request::OpenRemoteDesktop => (25, 0),
            Request::OpenFindMyDevice => (26, 0),
            Request::OpenBitLocker => (27, 0),
            Request::OpenWifi => (28, 0),
            Request::OpenProtectionHistoryList => (29, 0),
            Request::OpenNetwork => (30, 0),
            Request::OpenBackup => (31, 0),
            Request::OpenStorage => (32, 0),
            Request::OpenInstalledApps => (33, 0),
            Request::OpenReportProblem => (34, 0),
            Request::OpenSuggestFeature => (35, 0),
            Request::OpenPrivacyPolicy => (37, 0),
            Request::OpenTaskbar => (38, 0),
            Request::OpenRecoveryKey => (41, 0),
            Request::StartTray => (42, 0),
            Request::OpenDownloadPage => (43, 0),
            Request::ShowSupportFile => (44, 0),
            Request::SaveSupportFile => (45, 0),
            Request::UserSetting(setting, op) => (
                13,
                u16::from(setting.to_byte()) | (u16::from(op.to_byte()) << 8),
            ),
            Request::Space(area, op) => (46, u16::from(area.to_byte()) | ((op as u16) << 8)),
            Request::BitwardenStatus => (17, 0),
            Request::StartStoreApp(i) => (18, i),
            Request::StoreAppStatus(i) => (19, i),
            Request::AppAccessList(capability) => (39, u16::from(capability.to_byte())),
            Request::AppAccessSet {
                capability,
                target,
                tag,
                allow,
            } => {
                let (lo, hi) = app_access::encode_set(capability, target, tag, allow);
                (40, u16::from(lo) | (u16::from(hi) << 8))
            }
        };
        let [lo, hi] = arg.to_le_bytes();
        [kind, lo, hi]
    }

    pub fn decode(bytes: [u8; 3]) -> Option<Self> {
        Self::decode_with(bytes, secblitz::debloat::catalog().len())
    }

    pub fn decode_with(bytes: [u8; 3], catalog_len: usize) -> Option<Self> {
        let [kind, lo, hi] = bytes;
        let arg = u16::from_le_bytes([lo, hi]);
        if !matches!(kind, 7 | 13 | 18 | 19 | 39 | 40 | 46) && arg != 0 {
            return None;
        }
        Some(match kind {
            1 => Request::OpenWindowsUpdate,
            2 => Request::OpenWindowsSecurity,
            3 => Request::OpenEncryption,
            4 => Request::OpenSignIn,
            5 => Request::InstallBitwarden,
            6 => Request::BlockSuggestedApps,
            7 if usize::from(arg) < catalog_len => Request::ReinstallStoreApp(arg),
            8 => Request::OpenTamperProtection,
            9 => Request::OpenProtectionHistory,
            10 => Request::OpenAppBrowserControl,
            11 => Request::OpenOptionalFeatures,
            12 => Request::OpenAccounts,
            20 => Request::OpenCoreIsolation,
            21 => Request::OpenFirewall,
            22 => Request::OpenDeviceSecurity,
            23 => Request::OpenWorkAccounts,
            24 => Request::OpenRecovery,
            25 => Request::OpenRemoteDesktop,
            26 => Request::OpenFindMyDevice,
            27 => Request::OpenBitLocker,
            28 => Request::OpenWifi,
            29 => Request::OpenProtectionHistoryList,
            30 => Request::OpenNetwork,
            31 => Request::OpenBackup,
            32 => Request::OpenStorage,
            33 => Request::OpenInstalledApps,
            34 => Request::OpenReportProblem,
            35 => Request::OpenSuggestFeature,
            37 => Request::OpenPrivacyPolicy,
            38 => Request::OpenTaskbar,
            41 => Request::OpenRecoveryKey,
            42 => Request::StartTray,
            43 => Request::OpenDownloadPage,
            44 => Request::ShowSupportFile,
            45 => Request::SaveSupportFile,
            13 => Request::UserSetting(Setting::from_byte(lo)?, Op::from_byte(hi)?),
            46 => Request::Space(
                UserArea::from_byte(lo)?,
                match hi {
                    0 => SpaceOp::Measure,
                    1 => SpaceOp::Clean,
                    _ => return None,
                },
            ),
            17 => Request::BitwardenStatus,
            18 if usize::from(arg) < catalog_len => Request::StartStoreApp(arg),
            19 if usize::from(arg) < catalog_len => Request::StoreAppStatus(arg),
            39 => Request::AppAccessList(Capability::from_byte(u8::try_from(arg).ok()?)?),
            40 => {
                let (capability, target, tag, allow) = app_access::decode_set(lo, hi)?;
                Request::AppAccessSet {
                    capability,
                    target,
                    tag,
                    allow,
                }
            }
            _ => return None,
        })
    }

    pub fn timeout(self) -> Duration {
        match self {
            Request::ReinstallStoreApp(_) | Request::InstallBitwarden => {
                Duration::from_secs(15 * 60)
            }
            Request::Space(_, SpaceOp::Clean) => Duration::from_secs(10 * 60),
            Request::Space(_, SpaceOp::Measure) => Duration::from_secs(2 * 60),
            _ => Duration::from_secs(30),
        }
    }
}

/// The largest support file the launcher accepts; the zip itself stays under 1 MB.
pub const MAX_FILE: usize = 1 << 20;

/// Status byte, then the bytes found or freed and the files left alone, each 8 bytes little endian.
pub const SPACE_REPLY: usize = 17;

#[cfg_attr(not(windows), allow(dead_code))]
pub fn encode_space_reply(reply: Reply, tally: Tally) -> [u8; SPACE_REPLY] {
    let mut out = [0u8; SPACE_REPLY];
    out[0] = reply.encode();
    out[1..9].copy_from_slice(&tally.bytes.to_le_bytes());
    out[9..].copy_from_slice(&tally.left_alone.to_le_bytes());
    out
}

pub fn decode_space_reply(bytes: [u8; SPACE_REPLY]) -> Option<(Reply, Tally)> {
    let reply = Reply::decode(bytes[0])?;
    let tally = Tally {
        bytes: u64::from_le_bytes(bytes[1..9].try_into().ok()?),
        files: 0,
        left_alone: u64::from_le_bytes(bytes[9..].try_into().ok()?),
    };
    Some((reply, tally))
}

/// When the file was made, which names it, and how many bytes follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub at: u64,
    pub len: usize,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl FileHeader {
    pub const SIZE: usize = 12;

    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..8].copy_from_slice(&self.at.to_le_bytes());
        out[8..].copy_from_slice(&(self.len as u32).to_le_bytes());
        out
    }

    pub fn decode(bytes: [u8; Self::SIZE]) -> Option<Self> {
        let at = u64::from_le_bytes(bytes[..8].try_into().ok()?);
        let len = u32::from_le_bytes(bytes[8..].try_into().ok()?) as usize;
        (len > 0 && len <= MAX_FILE).then_some(FileHeader { at, len })
    }
}

/// A whole zip as `app::support` writes it: a first entry, and the end record with no comment.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 52
        && bytes.len() <= MAX_FILE
        && bytes.starts_with(b"PK\x03\x04")
        && bytes[bytes.len() - 22..].starts_with(b"PK\x05\x06")
        && bytes.ends_with(&[0, 0])
}

#[cfg_attr(not(windows), allow(dead_code))]
const PREFIX: &str = r"\\.\pipe\secblitz-broker-";

pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn new_id() -> String {
    use rand::TryRng;
    let mut bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the system random generator failed");
    hex::encode(bytes)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn pipe_name(id: &str) -> String {
    format!("{PREFIX}{id}")
}

pub struct Client {
    #[cfg(windows)]
    inner: std::sync::Mutex<imp::Pipe>,
    #[cfg(not(windows))]
    _private: (),
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("broker::Client")
    }
}

impl Client {
    pub fn connect(id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(valid_id(id), "invalid broker id");
        #[cfg(windows)]
        {
            Ok(Self {
                inner: std::sync::Mutex::new(imp::Pipe::connect(&pipe_name(id))?),
            })
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("The broker is only available on Windows")
        }
    }

    pub fn send(&self, request: Request) -> anyhow::Result<Reply> {
        anyhow::ensure!(
            request != Request::SaveSupportFile && !matches!(request, Request::Space(..)),
            "this request has its own method"
        );
        #[cfg(windows)]
        {
            let mut pipe = self.inner.lock().map_err(|e| {
                eprintln!("{e}");
                anyhow::anyhow!("broker unavailable")
            })?;
            let byte = pipe.round_trip(request.encode(), request.timeout())?;
            Reply::decode(byte).ok_or_else(|| anyhow::anyhow!("invalid broker reply"))
        }
        #[cfg(not(windows))]
        {
            let _ = request;
            anyhow::bail!("The broker is only available on Windows")
        }
    }

    /// Asks the launcher, which runs as the signed-in person, to measure or clear one of
    /// that person's own leftover folders.
    pub fn space(&self, area: UserArea, op: SpaceOp) -> anyhow::Result<(Reply, Tally)> {
        #[cfg(windows)]
        {
            let request = Request::Space(area, op);
            let mut pipe = self.inner.lock().map_err(|e| {
                eprintln!("{e}");
                anyhow::anyhow!("broker unavailable")
            })?;
            let bytes =
                pipe.round_trip_fixed::<SPACE_REPLY>(request.encode(), request.timeout())?;
            decode_space_reply(bytes).ok_or_else(|| anyhow::anyhow!("invalid broker reply"))
        }
        #[cfg(not(windows))]
        {
            let _ = (area, op);
            anyhow::bail!("The broker is only available on Windows")
        }
    }

    /// Hands a support file to the launcher, which saves it in the person's own Downloads.
    /// On success, returns the number `app::support::numbered` adds to the file name.
    pub fn save_file(&self, at: u64, zip: &[u8]) -> anyhow::Result<Result<u8, Reply>> {
        anyhow::ensure!(looks_like_zip(zip), "not a support file");
        #[cfg(windows)]
        {
            let mut pipe = self.inner.lock().map_err(|e| {
                eprintln!("{e}");
                anyhow::anyhow!("broker unavailable")
            })?;
            let header = FileHeader { at, len: zip.len() }.encode();
            let mut message = Vec::with_capacity(3 + header.len() + zip.len());
            message.extend_from_slice(&Request::SaveSupportFile.encode());
            message.extend_from_slice(&header);
            message.extend_from_slice(zip);
            let [reply, number] =
                pipe.round_trip_bytes(message, Request::SaveSupportFile.timeout())?;
            match Reply::decode(reply) {
                Some(Reply::Done) => Ok(Ok(number)),
                Some(other) => Ok(Err(other)),
                None => anyhow::bail!("invalid broker reply"),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = at;
            anyhow::bail!("The broker is only available on Windows")
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::{ptr::null_mut, time::Duration};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE,
            WAIT_OBJECT_0,
        },
        Storage::FileSystem::{
            CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Pipes::GetNamedPipeServerProcessId,
            Threading::{
                CreateEventW, GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW,
                WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            },
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        },
    };

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;

    pub struct Pipe {
        handle: HANDLE,
        event: HANDLE,
        broken: bool,
    }
    unsafe impl Send for Pipe {}

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
                CloseHandle(self.event);
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn parent_pid() -> Option<u32> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return None;
            }
            let me = GetCurrentProcessId();
            // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found = None;
            let mut ok = Process32FirstW(snap, &mut entry);
            while ok != 0 {
                if entry.th32ProcessID == me {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                ok = Process32NextW(snap, &mut entry);
            }
            CloseHandle(snap);
            found
        }
    }

    pub fn image_path(pid: u32) -> Option<String> {
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(process);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    impl Pipe {
        pub fn connect(name: &str) -> anyhow::Result<Self> {
            let wide_name = wide(name);
            let handle = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error().into());
            }
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                unsafe { CloseHandle(handle) };
                return Err(std::io::Error::last_os_error().into());
            }
            let pipe = Pipe {
                handle,
                event,
                broken: false,
            };
            let mut server = 0u32;
            anyhow::ensure!(
                unsafe { GetNamedPipeServerProcessId(pipe.handle, &mut server) } != 0,
                "broker server unknown"
            );
            let parent_ok = parent_pid() == Some(server);
            let same_image = match (image_path(server), std::env::current_exe().ok()) {
                (Some(theirs), Some(ours)) => theirs.eq_ignore_ascii_case(&ours.to_string_lossy()),
                _ => false,
            };
            anyhow::ensure!(parent_ok || same_image, "broker server is not the launcher");
            Ok(pipe)
        }

        fn io(&mut self, write: bool, buf: &mut [u8], timeout: Duration) -> anyhow::Result<()> {
            let mut done = 0usize;
            while done < buf.len() {
                // SAFETY: plain C struct for which all-zero bytes are a valid initial value.
                let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                overlapped.hEvent = self.event;
                let rest = &mut buf[done..];
                let started = unsafe {
                    if write {
                        WriteFile(
                            self.handle,
                            rest.as_ptr(),
                            rest.len() as u32,
                            null_mut(),
                            &mut overlapped,
                        )
                    } else {
                        ReadFile(
                            self.handle,
                            rest.as_mut_ptr(),
                            rest.len() as u32,
                            null_mut(),
                            &mut overlapped,
                        )
                    }
                };
                if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
                    return Err(std::io::Error::last_os_error().into());
                }
                let millis = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
                if unsafe { WaitForSingleObject(self.event, millis) } != WAIT_OBJECT_0 {
                    unsafe {
                        CancelIoEx(self.handle, &overlapped);
                        let mut n = 0u32;
                        GetOverlappedResult(self.handle, &overlapped, &mut n, 1);
                    }
                    anyhow::bail!("The launcher did not answer in time");
                }
                let mut n = 0u32;
                if unsafe { GetOverlappedResult(self.handle, &overlapped, &mut n, 0) } == 0
                    || n == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                done += n as usize;
            }
            Ok(())
        }

        pub fn round_trip(
            &mut self,
            mut request: [u8; 3],
            timeout: Duration,
        ) -> anyhow::Result<u8> {
            anyhow::ensure!(!self.broken, "broker unavailable");
            let result = (|| {
                self.io(true, &mut request, Duration::from_secs(10))?;
                let mut reply = [0u8; 1];
                self.io(false, &mut reply, timeout)?;
                Ok(reply[0])
            })();
            if result.is_err() {
                self.broken = true;
            }
            result
        }

        pub fn round_trip_fixed<const N: usize>(
            &mut self,
            mut request: [u8; 3],
            timeout: Duration,
        ) -> anyhow::Result<[u8; N]> {
            anyhow::ensure!(!self.broken, "broker unavailable");
            let result = (|| {
                self.io(true, &mut request, Duration::from_secs(10))?;
                let mut reply = [0u8; N];
                self.io(false, &mut reply, timeout)?;
                Ok(reply)
            })();
            if result.is_err() {
                self.broken = true;
            }
            result
        }

        pub fn round_trip_bytes(
            &mut self,
            mut message: Vec<u8>,
            timeout: Duration,
        ) -> anyhow::Result<[u8; 2]> {
            anyhow::ensure!(!self.broken, "broker unavailable");
            let result = (|| {
                self.io(true, &mut message, Duration::from_secs(10))?;
                let mut reply = [0u8; 2];
                self.io(false, &mut reply, timeout)?;
                Ok(reply)
            })();
            if result.is_err() {
                self.broken = true;
            }
            result
        }
    }
}

#[cfg(windows)]
pub(crate) use imp::image_path;

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Request> {
        vec![
            Request::OpenWindowsUpdate,
            Request::OpenWindowsSecurity,
            Request::OpenEncryption,
            Request::OpenSignIn,
            Request::InstallBitwarden,
            Request::BlockSuggestedApps,
            Request::ReinstallStoreApp(0),
            Request::ReinstallStoreApp(41),
            Request::OpenTamperProtection,
            Request::OpenProtectionHistory,
            Request::OpenAppBrowserControl,
            Request::OpenOptionalFeatures,
            Request::OpenAccounts,
            Request::OpenCoreIsolation,
            Request::OpenFirewall,
            Request::OpenDeviceSecurity,
            Request::OpenWorkAccounts,
            Request::OpenRecovery,
            Request::OpenRemoteDesktop,
            Request::OpenFindMyDevice,
            Request::OpenBitLocker,
            Request::OpenWifi,
            Request::OpenProtectionHistoryList,
            Request::OpenNetwork,
            Request::OpenBackup,
            Request::OpenStorage,
            Request::OpenInstalledApps,
            Request::OpenTaskbar,
            Request::OpenReportProblem,
            Request::OpenSuggestFeature,
            Request::OpenPrivacyPolicy,
            Request::OpenRecoveryKey,
            Request::StartTray,
            Request::OpenDownloadPage,
            Request::ShowSupportFile,
            Request::SaveSupportFile,
            Request::BitwardenStatus,
            Request::StartStoreApp(0),
            Request::StartStoreApp(41),
            Request::StoreAppStatus(0),
            Request::StoreAppStatus(41),
            Request::AppAccessList(Capability::Camera),
            Request::AppAccessList(Capability::Location),
        ]
        .into_iter()
        .chain(Capability::ALL.iter().flat_map(|capability| {
            [
                (Target::Master, 0),
                (Target::DesktopApps, 0),
                (Target::App(0), 0),
                (Target::App(199), 31),
            ]
            .into_iter()
            .flat_map(move |(target, tag)| {
                [false, true]
                    .into_iter()
                    .map(move |allow| Request::AppAccessSet {
                        capability: *capability,
                        target,
                        tag,
                        allow,
                    })
            })
        }))
        .chain(
            [UserArea::Temp, UserArea::CrashDumps, UserArea::Thumbnails]
                .into_iter()
                .flat_map(|area| {
                    [SpaceOp::Measure, SpaceOp::Clean]
                        .into_iter()
                        .map(move |op| Request::Space(area, op))
                }),
        )
        .chain(Setting::ALL.iter().flat_map(|s| {
            [Op::Query, Op::Apply, Op::Undo]
                .into_iter()
                .map(|op| Request::UserSetting(*s, op))
        }))
        .collect()
    }

    #[test]
    fn requests_round_trip() {
        for request in all() {
            assert_eq!(Request::decode_with(request.encode(), 100), Some(request));
        }
    }

    #[test]
    fn ads_and_tips_requests_have_fixed_wire_bytes() {
        let expected = [
            (Setting::LockScreenTips, 6),
            (Setting::StartSettingsTips, 7),
            (Setting::ExplorerAds, 8),
            (Setting::SearchWebResults, 9),
            (Setting::GameBarPopups, 10),
        ];
        for (setting, byte) in expected.into_iter().chain([(Setting::StorageSense, 11)]) {
            for (op, op_byte) in [(Op::Query, 0), (Op::Apply, 1), (Op::Undo, 2)] {
                let request = Request::UserSetting(setting, op);
                assert_eq!(request.encode(), [13, byte, op_byte]);
                assert_eq!(
                    Request::decode_with([13, byte, op_byte], 100),
                    Some(request)
                );
            }
        }
        assert_eq!(expected.map(|(s, _)| s), Setting::ADS_AND_TIPS);
    }

    #[test]
    fn only_page_requests_bring_a_window_forward() {
        for request in all() {
            let page = format!("{request:?}").starts_with("Open");
            let folder = request == Request::ShowSupportFile;
            assert_eq!(request.opens_window(), page || folder, "{request:?}");
        }
    }

    #[test]
    fn only_queries_keep_the_saved_check() {
        let feedback = [
            Request::OpenReportProblem,
            Request::OpenSuggestFeature,
            Request::OpenPrivacyPolicy,
            Request::OpenRecoveryKey,
            Request::OpenDownloadPage,
            Request::ShowSupportFile,
        ];
        assert!(
            Request::SaveSupportFile.is_read_only() && !Request::SaveSupportFile.opens_window()
        );
        for request in all() {
            if request.opens_window() && !feedback.contains(&request) {
                assert!(!request.is_read_only(), "{request:?}");
            }
        }
        for request in feedback {
            assert!(request.opens_window() && request.is_read_only());
        }
        assert!(Request::UserSetting(Setting::SuggestedApps, Op::Query).is_read_only());
        assert!(!Request::UserSetting(Setting::SuggestedApps, Op::Apply).is_read_only());
        assert!(!Request::UserSetting(Setting::SuggestedApps, Op::Undo).is_read_only());
        assert!(!Request::BlockSuggestedApps.is_read_only());
        for setting in Setting::ADS_AND_TIPS {
            assert!(Request::UserSetting(setting, Op::Query).is_read_only());
            assert!(!Request::UserSetting(setting, Op::Apply).is_read_only());
            assert!(!Request::UserSetting(setting, Op::Undo).is_read_only());
        }
        assert!(Request::AppAccessList(Capability::Camera).is_read_only());
        let set = Request::AppAccessSet {
            capability: Capability::Camera,
            target: Target::Master,
            tag: 0,
            allow: false,
        };
        assert!(!set.is_read_only() && !set.opens_window());
    }

    #[test]
    fn decode_is_strict() {
        for kind in [0u8, 47, 100, 255] {
            assert_eq!(Request::decode_with([kind, 0, 0], 100), None);
        }
        for kind in (1..=6u8)
            .chain(8..=12)
            .chain(20..=38)
            .chain([17, 41, 42, 43, 44, 45])
        {
            assert_eq!(Request::decode_with([kind, 1, 0], 100), None);
            assert_eq!(Request::decode_with([kind, 0, 1], 100), None);
        }
        assert!(Request::decode_with([13, 0, 0], 100).is_some());
        assert_eq!(
            Request::decode_with([13, Setting::ALL.len() as u8, 0], 100),
            None
        );
        assert_eq!(Request::decode_with([13, 0, 3], 100), None);
        assert_eq!(
            Request::decode_with([13, 5, 2], 100),
            Some(Request::UserSetting(Setting::SuggestedApps, Op::Undo))
        );
        assert_eq!(
            Request::decode_with([13, 6, 0], 100),
            Some(Request::UserSetting(Setting::LockScreenTips, Op::Query))
        );
        assert_eq!(
            Request::decode_with([13, 10, 1], 100),
            Some(Request::UserSetting(Setting::GameBarPopups, Op::Apply))
        );
        assert_eq!(
            Request::decode_with([13, 11, 2], 100),
            Some(Request::UserSetting(Setting::StorageSense, Op::Undo))
        );
        assert_eq!(Request::decode_with([13, 12, 0], 100), None);
        assert_eq!(Request::decode_with([13, 12, 2], 100), None);
        assert_eq!(Request::decode_with([13, 255, 255], 100), None);
        assert!(Request::decode_with([13, 0, 0], 0).is_some());
        assert_eq!(Request::decode_with([14, 1, 0], 100), None);
        assert_eq!(Request::decode_with([14, 0, 1], 100), None);
        for kind in [14u8, 15, 16, 36] {
            assert_eq!(Request::decode_with([kind, 0, 0], 100), None);
        }
        assert_eq!(Request::decode_with([7, 0, 0], 0), None);
        assert_eq!(Request::decode_with([7, 5, 0], 5), None);
        assert_eq!(
            Request::decode_with([7, 4, 0], 5),
            Some(Request::ReinstallStoreApp(4))
        );
        assert_eq!(Request::decode_with([7, 255, 255], 100), None);
        assert_eq!(Request::decode([7, 255, 255]), None);
        assert_eq!(
            Request::decode_with([39, 2, 0], 100),
            Some(Request::AppAccessList(Capability::Location))
        );
        for bad in [[39, 3, 0], [39, 0, 1], [39, 255, 255]] {
            assert_eq!(Request::decode_with(bad, 100), None);
        }
        assert_eq!(
            Request::decode_with([40, 0b101, 1], 100),
            Some(Request::AppAccessSet {
                capability: Capability::Microphone,
                target: Target::DesktopApps,
                tag: 0,
                allow: true,
            })
        );
        assert_eq!(
            Request::decode_with([40, 0b1_1101, 2], 100),
            Some(Request::AppAccessSet {
                capability: Capability::Microphone,
                target: Target::App(0),
                tag: 3,
                allow: true,
            })
        );
        for bad in [
            [40, 3, 0],
            [40, 8, 0],
            [40, 0b1_1101, 1],
            [40, 0, 202],
            [40, 0, 255],
            [40, 255, 255],
        ] {
            assert_eq!(Request::decode_with(bad, 100), None);
        }
        for kind in [18u8, 19] {
            assert!(Request::decode_with([kind, 4, 0], 5).is_some());
            assert_eq!(Request::decode_with([kind, 5, 0], 5), None);
            assert_eq!(Request::decode_with([kind, 255, 255], 100), None);
        }
    }

    #[test]
    fn space_requests_have_fixed_wire_bytes_and_strict_decode() {
        assert_eq!(
            Request::Space(UserArea::Temp, SpaceOp::Measure).encode(),
            [46, 0, 0]
        );
        assert_eq!(
            Request::Space(UserArea::Thumbnails, SpaceOp::Clean).encode(),
            [46, 2, 1]
        );
        assert_eq!(Request::decode([46, 3, 0]), None);
        assert_eq!(Request::decode([46, 0, 2]), None);
        assert_eq!(Request::decode([46, 255, 255]), None);
    }

    #[test]
    fn space_replies_round_trip() {
        let t = Tally {
            bytes: 5 << 30,
            files: 0,
            left_alone: 3,
        };
        assert_eq!(
            decode_space_reply(encode_space_reply(Reply::Done, t)),
            Some((Reply::Done, t))
        );
        let mut bad = encode_space_reply(Reply::Done, t);
        bad[0] = 0;
        assert_eq!(decode_space_reply(bad), None);
    }

    #[test]
    fn space_requests_keep_the_saved_check_and_get_long_timeouts() {
        assert!(Request::Space(UserArea::Temp, SpaceOp::Clean).is_read_only());
        assert!(!Request::Space(UserArea::Temp, SpaceOp::Clean).opens_window());
        assert_eq!(
            Request::Space(UserArea::Temp, SpaceOp::Clean).timeout(),
            Duration::from_secs(10 * 60)
        );
        assert_eq!(
            Request::Space(UserArea::Temp, SpaceOp::Measure).timeout(),
            Duration::from_secs(2 * 60)
        );
    }

    #[test]
    fn replies_round_trip_and_reject_unknown() {
        for reply in [
            Reply::Done,
            Reply::Failed,
            Reply::OpenedStore,
            Reply::Unavailable,
            Reply::Offline,
            Reply::Safe,
            Reply::SafeByUs,
            Reply::NeedsAttention,
            Reply::NotApplicable,
            Reply::Unknown,
            Reply::Working,
            Reply::ChangedSince,
        ] {
            assert_eq!(Reply::decode(reply.encode()), Some(reply));
        }
        for byte in [0u8, 11, 14, 15, 100, 255] {
            assert_eq!(Reply::decode(byte), None);
        }
    }

    #[test]
    fn setting_results_map_to_distinct_calm_replies() {
        use secblitz::user_settings::{HandleResult as H, Outcome, Report};
        assert_eq!(
            Reply::from_result(H::Report(Report::Unsafe)),
            Reply::NeedsAttention
        );
        assert_eq!(Reply::from_result(H::Report(Report::Safe)), Reply::Safe);
        assert_eq!(
            Reply::from_result(H::Report(Report::SafeByUs)),
            Reply::SafeByUs
        );
        assert_eq!(
            Reply::from_result(H::Report(Report::Unknown)),
            Reply::Unknown
        );
        assert_eq!(
            Reply::from_result(H::Outcome(Outcome::Blocked)),
            Reply::Unavailable
        );
        assert_eq!(Reply::from_result(H::Outcome(Outcome::Done)), Reply::Done);
        assert_eq!(
            Reply::from_result(H::Outcome(Outcome::ChangedSince)),
            Reply::ChangedSince
        );
    }

    #[test]
    fn ids_are_validated_and_random() {
        let id = new_id();
        assert!(valid_id(&id));
        assert_ne!(id, new_id());
        for bad in [
            "",
            "abc",
            &"A".repeat(32),
            &"g".repeat(32),
            &"a".repeat(31),
            &"a".repeat(33),
            "..\\..\\evil0000000000000000000000",
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert!(Client::connect("../x").is_err());
        assert_eq!(pipe_name(&"a".repeat(32)).len(), PREFIX.len() + 32);
    }

    #[test]
    fn a_file_header_round_trips_and_refuses_empty_or_huge_files() {
        let header = FileHeader {
            at: 1_791_000_000,
            len: 40_000,
        };
        assert_eq!(FileHeader::decode(header.encode()), Some(header));
        for len in [0, MAX_FILE + 1, u32::MAX as usize] {
            let bytes = FileHeader { at: 1, len }.encode();
            assert_eq!(FileHeader::decode(bytes), None, "{len}");
        }
        let full = FileHeader {
            at: 1,
            len: MAX_FILE,
        };
        assert_eq!(FileHeader::decode(full.encode()), Some(full));
    }

    #[cfg(not(windows))]
    #[test]
    fn a_support_file_is_only_sent_with_its_bytes() {
        let client = Client { _private: () };
        assert!(client.send(Request::SaveSupportFile).is_err());
        assert!(client.save_file(1, b"not a zip").is_err());
    }

    #[test]
    fn long_operations_get_long_timeouts() {
        assert!(Request::ReinstallStoreApp(0).timeout() >= Duration::from_secs(900));
        assert_eq!(Request::OpenSignIn.timeout(), Duration::from_secs(30));
        assert_eq!(
            Request::UserSetting(Setting::ShowExtensions, Op::Apply).timeout(),
            Duration::from_secs(30)
        );
    }
}
