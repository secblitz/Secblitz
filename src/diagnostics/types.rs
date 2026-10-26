use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Healthy,
    Attention,
    Unknown,
    Unsupported,
    Informational,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    #[default]
    Everyday,
    Gaming,
    Development,
    HigherSecurity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Machine,
    OriginalUser,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OriginalUserScope {
    #[default]
    Omit,
    VerifyCurrentDesktopUser,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityNeeds {
    pub printers: bool,
    pub nas: bool,
    pub vpn: bool,
    pub games: bool,
    pub development: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub original_user: OriginalUserScope,
    pub compatibility: CompatibilityNeeds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnknownReason {
    NotCollected,
    NotRequested,
    OriginalUserNotVerified,
    PlatformUnsupported,
    Unavailable,
    MissingData,
    InvalidData,
    Timeout,
    CollectionDeadline,
    OutputLimit,
    ProcessFailed,
    NotAssessed,
    Busy,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "state", content = "value")]
pub enum Reading<T> {
    Known(T),
    Unknown(UnknownReason),
}

impl<T> Default for Reading<T> {
    fn default() -> Self {
        Self::Unknown(UnknownReason::MissingData)
    }
}
impl<T> Reading<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }
}
impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Reading<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "state", content = "value", deny_unknown_fields)]
        enum Wire<T> {
            Known(T),
            Unknown(UnknownReason),
        }
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(match serde_json::from_value::<Wire<T>>(value) {
            Ok(Wire::Known(v)) => Self::Known(v),
            Ok(Wire::Unknown(r)) => Self::Unknown(r),
            Err(_) => Self::Unknown(UnknownReason::InvalidData),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

macro_rules! probe_ids {
    ($($name:ident => $source:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum ProbeId { $($name),+ }
        impl ProbeId {
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
            pub fn source(self) -> &'static str { match self { $(Self::$name => $source),+ } }
            pub fn scope(self) -> Scope {
                if matches!(self, Self::BrowserExtensions | Self::RunHistory) { Scope::OriginalUser } else { Scope::Machine }
            }
        }
    };
}
probe_ids! {
    UpdateCache => "Windows Update Agent: offline software-update search (cached metadata)",
    UpdateHistory => "Windows Update Agent: last 256 local history entries",
    DefenderHealth => "Defender/Get-MpComputerStatus",
    DefenderPolicy => "Defender/Get-MpPreference: ASR and CFA only",
    SecurityProviders => "root/SecurityCenter2: AntiVirusProduct and FirewallProduct",
    Management => "Win32_ComputerSystem, MDMRegistration API and scoped HKLM policy indicators",
    SecureBoot => "SecureBoot/Confirm-SecureBootUEFI",
    Tpm => "TrustedPlatformModule/Get-Tpm",
    BitLocker => "Win32_EncryptableVolume: GetProtectionStatus/GetConversionStatus only, no key protectors",
    Vbs => "root/Microsoft/Windows/DeviceGuard: Win32_DeviceGuard",
    WinRe => "Trusted System32/reagentc.exe /info: reported Windows RE status only",
    Accounts => "LocalAccounts: built-in Administrators membership and Guest RID 501",
    RemoteAccess => "HKLM RDP settings and SmbShare configuration",
    Software => "Read-only HKLM uninstall registration, Registry64 and Registry32",
    BrowserExtensions => "Verified original desktop user's bounded Chrome/Edge manifests and Firefox extensions.json",
    Storage => "Storage/Get-PhysicalDisk and Get-StorageReliabilityCounter",
    Ntfs => "Win32_Volume: fixed-volume filesystem/dirty bit/capacity",
    Backup => "Win32_ShadowCopy, bounded Microsoft-Windows-Backup and File History event metadata, and OneDrive folder redirection",
    Adapters => "NetAdapter/Get-NetAdapter: operational state only",
    Dns => "DnsClient/Get-DnsClientServerAddress: configured server counts only",
    Proxy => "WinHTTP/WinHttpGetDefaultProxyConfiguration: access type only",
    Vpn => "VpnClient/Get-VpnConnection -AllUserConnection: status only",
    Permissions => "permissions::audit: bounded fixed-service broad-principal DACL audit",
    OsSupport => "HKLM Windows version values: DisplayVersion, build and edition id only",
    SecureBootCerts => "System event ids, Secure Boot servicing values, the renewal task state, db certificate presence, virtual computer, BitLocker and other-system hints (no firmware data or event text emitted)",
    DefenderProtection => "Defender/Get-MpComputerStatus, Get-MpThreat, Get-MpThreatDetection and exclusion counts only (no paths)",
    SmartScreen => "HKLM SmartScreen, Smart App Control and browser safe-browsing policy indicators",
    UpdatePolicy => "HKLM Windows Update policy and pause values, service start types, pending restart and uptime",
    LegacyFeatures => "CIM Win32_OptionalFeature: legacy PowerShell 2.0 engine state",
    HostsFile => "Hosts file size and bounded counts of redirects and blocks (no host names or contents)",
    Persistence => "root/subscription WMI consumers and bounded service image path shape (counts only)",
    AccountHygiene => "LocalAccounts: built-in Administrator RID 500 state and stale enabled account count",
    Sharing => "SmbShare: non-special share counts, broad access and server encryption setting",
    FirewallRules => "NetSecurity: enabled inbound allow rules whose program sits in a risky user folder (counts only)",
    AccountSetup => "LocalAccounts and Win32_Battery: whether the signed-in account is an administrator, and the Find my device setting (no names or IDs)",
    WindowsHello => "Trusted System32/dsregcmd.exe /status: the PIN / Windows Hello set-up flag only, no other line is kept",
    DnsEncryption => "DnsClient: configured DNS server counts against registered encrypted-DNS servers (no addresses)",
    WifiSecurity => "WLAN API: security type of the connected Wi-Fi network only (no network name or address)",
    RunHistory => "The signed-in user's Run box history (RunMRU): counts of entries that match known fake check page tricks (no command text is kept)",
    Autostart => "Run/RunOnce keys, Startup folders and non-Microsoft scheduled tasks: counts of risky unsigned entries only (no names or paths)",
}

macro_rules! facts {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(#[serde(default)] pub $field: Reading<$ty>),* }
    };
}
facts!(Updates { result_code: u32, missing: Inventory<MissingUpdate> });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingUpdate {
    pub quality_classification: bool,
    pub kb: Vec<String>,
    #[serde(default)]
    pub hidden: Reading<bool>,
}
facts!(UpdateHistory { entries: Inventory<UpdateEvent> });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEvent {
    pub operation: u32,
    pub result_code: u32,
    pub hresult: i32,
    pub date_unix_seconds: u64,
    pub quality_title_hint: bool,
}
facts!(DefenderHealth {
    service_enabled: bool,
    antivirus_enabled: bool,
    realtime_enabled: bool,
    behavior_enabled: bool,
    ioav_enabled: bool,
    nis_enabled: bool,
    signatures_age_days: u32,
    signatures_out_of_date: bool,
    tamper_protected: bool,
    running_mode: String,
});
facts!(DefenderPolicy { asr: Inventory<AsrRule>, cfa_mode: u32 });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsrRule {
    pub id: String,
    pub mode: u32,
}
facts!(Providers { antivirus: Inventory<SecurityProvider>, firewall: Inventory<SecurityProvider> });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityProvider {
    pub name: String,
    pub instance_guid: String,
    pub product_state: u32,
}
facts!(Management {
    domain_joined: bool,
    mdm_registered: bool,
    cloud_join_indicator: bool,
    defender_policy_values: bool,
    update_policy_values: bool,
    policy_manager_values: bool,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagementStatus {
    Managed,
    PolicyPresent,
    NoIndicatorsObserved,
    Unknown,
}
facts!(SecureBoot { enabled: bool });
facts!(Tpm {
    present: bool,
    ready: bool,
    enabled: bool,
    activated: bool
});
facts!(BitLocker { volumes: Inventory<EncryptedVolume> });
facts!(EncryptedVolume {
    protection_status: u32,
    volume_status: u32,
    encryption_percentage: u32
});
facts!(Vbs {
    status: u32,
    configured_services: Vec<u32>,
    running_services: Vec<u32>,
    kernel_shadow_stacks: String,
});
facts!(WinRe { enabled: bool });
facts!(Accounts {
    administrator_count: u32,
    guest_enabled: bool
});
facts!(RemoteAccess {
    rdp_denied: bool,
    rdp_nla_required: bool,
    smb1_enabled: bool,
    smb2_enabled: bool,
    smb_server_signing_required: bool,
    smb_client_signing_required: bool,
    smb_guest_logons_enabled: bool,
});
facts!(Software { applications: Inventory<Application> });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    pub publisher: String,
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SupportAssessment {
    KnownEndOfSupport { ended_on: String, reference: String },
    NotAssessed,
}
facts!(BrowserInventory { extensions: Inventory<BrowserExtension>, profiles_examined: u32 });
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserExtension {
    pub browser: Browser,
    /// Local ordinal only; profile names and paths never leave the collector.
    pub profile_index: u32,
    pub id: String,
    /// The add-on's own name; empty when it could not be read.
    #[serde(default)]
    pub name: String,
    pub version: String,
    pub enabled: Reading<bool>,
    pub broad_host_access: Reading<bool>,
    pub native_messaging: Reading<bool>,
}
facts!(Storage { disks: Inventory<PhysicalDisk> });
facts!(PhysicalDisk {
    health_status: u32,
    temperature_celsius: i32,
    wear_percent: u32,
    read_errors_uncorrected: u64,
    write_errors_uncorrected: u64,
});
facts!(Ntfs { volumes: Inventory<Volume> });
facts!(Volume {
    filesystem: String,
    dirty: bool,
    capacity_bytes: u64,
    free_bytes: u64
});
facts!(Backup {
    shadow_copy_count: u32,
    success_events: Inventory<BackupEvent>,
    file_history_last_unix_seconds: u64,
    onedrive_folders: u32,
    file_history_drive_removable_connected: bool
});
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEvent {
    pub date_unix_seconds: u64,
}
facts!(Adapters { adapters: Inventory<Adapter> });
facts!(Adapter {
    operational_status: u32,
    hardware_interface: bool
});
facts!(Dns { interfaces: Inventory<DnsInterface> });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsInterface {
    pub address_family: u32,
    pub server_count: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    Direct,
    NamedProxy,
    Automatic,
}
facts!(Proxy {
    default_mode: ProxyMode
});
facts!(Vpn { connections: Inventory<VpnConnection> });
facts!(VpnConnection {
    connected: bool,
    split_tunneling: bool
});
facts!(OsSupport {
    display_version: String,
    build: u32,
    edition_id: String,
});
facts!(SecureBootCerts {
    update_completed_event: bool,
    update_staged_event: bool,
    update_error_event: bool,
    servicing_status: String,
    ca2023_in_db: bool,
    secure_boot_enabled: bool,
    maker_blocked_event: bool,
    available_updates: u32,
    servicing_error: u32,
    capable: u32,
    task_state: String,
    is_vm: bool,
    bitlocker_on: bool,
    other_os: bool,
});
facts!(DefenderProtection {
    running_mode: String,
    tamper_protected: bool,
    tamper_feature_value: u32,
    active_threats: u32,
    recent_detections: u32,
    // Days since the last quick scan; u32::MAX means never.
    quick_scan_age_days: u32,
    full_scan_age_days: u32,
    exclusion_count: u32,
    risky_exclusion_count: u32,
});
facts!(SmartScreen {
    apps_off_local: bool,
    apps_off_policy: bool,
    edge_off_policy: bool,
    chrome_off_policy: bool,
    smart_app_control: String,
});
facts!(UpdatePolicy {
    paused: bool,
    drivers_excluded: bool,
    reboot_pending: bool,
    uptime_days: u32,
});
facts!(LegacyFeatures {
    powershell_v2_enabled: bool
});
facts!(HostsFile {
    size_bytes: u64,
    redirect_count: u32,
    sensitive_redirect_count: u32,
    sensitive_block_count: u32,
});
facts!(Persistence {
    wmi_consumers: u32,
    unquoted_service_paths: u32,
    unquoted_service_paths_writable: u32,
});
facts!(AccountHygiene {
    stale_enabled_accounts: u32,
});
facts!(Sharing {
    share_count: u32,
    broad_access_shares: u32,
    encrypt_data: bool,
});
facts!(FirewallRules {
    risky_inbound_allow_rules: u32,
    user_folder_inbound_allow_rules: u32,
});
facts!(AccountSetup {
    current_user_is_admin: bool,
    find_my_device: String,
});
facts!(WindowsHello { pin_set: bool });
facts!(DnsEncryption {
    dns_servers: u32,
    encrypted_dns_servers: u32,
    upgradeable_dns_servers: u32,
});
facts!(WifiSecurity {
    current_network: String
});
facts!(Autostart {
    entries_checked: u32,
    risky_unsigned: u32,
    suspicious_command: u32,
});
facts!(RunHistory {
    entries_checked: u32,
    suspicious_entries: u32,
    encoded_command: u32,
    web_script: u32,
    mshta: u32,
    download_tool: u32,
    hidden_window: u32,
});
facts!(Permissions { services: Inventory<PermissionFinding> });
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionFinding {
    pub service: String,
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum Evidence {
    UpdateCache(Updates),
    UpdateHistory(UpdateHistory),
    DefenderHealth(DefenderHealth),
    DefenderPolicy(DefenderPolicy),
    SecurityProviders(Providers),
    Management(Management),
    SecureBoot(SecureBoot),
    Tpm(Tpm),
    BitLocker(BitLocker),
    Vbs(Vbs),
    WinRe(WinRe),
    Accounts(Accounts),
    RemoteAccess(RemoteAccess),
    Software(Software),
    BrowserExtensions(BrowserInventory),
    Storage(Storage),
    Ntfs(Ntfs),
    Backup(Backup),
    Adapters(Adapters),
    Dns(Dns),
    Proxy(Proxy),
    Vpn(Vpn),
    Permissions(Permissions),
    OsSupport(OsSupport),
    SecureBootCerts(SecureBootCerts),
    DefenderProtection(DefenderProtection),
    SmartScreen(SmartScreen),
    UpdatePolicy(UpdatePolicy),
    LegacyFeatures(LegacyFeatures),
    HostsFile(HostsFile),
    Persistence(Persistence),
    AccountHygiene(AccountHygiene),
    Sharing(Sharing),
    FirewallRules(FirewallRules),
    AccountSetup(AccountSetup),
    WindowsHello(WindowsHello),
    DnsEncryption(DnsEncryption),
    WifiSecurity(WifiSecurity),
    Autostart(Autostart),
    RunHistory(RunHistory),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub id: ProbeId,
    pub scope: Scope,
    pub observed_at_unix_seconds: Option<u64>,
    pub source: String,
    pub status: Status,
    pub evidence: Option<Evidence>,
    pub failure: Option<UnknownReason>,
    pub assessments: Vec<Assessment>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleReference {
    pub id: String,
    pub revision: u32,
    pub mapping_version: String,
    pub documentation: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    pub status: Status,
    pub detail: String,
    pub rule: RuleReference,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recommendation {
    pub rule: RuleReference,
    pub profile: Profile,
    pub reason: String,
    pub guidance: String,
    pub management: ManagementStatus,
    pub compatibility_notes: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coverage {
    pub total_probes: usize,
    pub probes_with_evidence: usize,
    pub probes_without_evidence: usize,
    pub assessments_unknown: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Omission {
    pub scope: Scope,
    pub area: String,
    pub reason: String,
}
impl Omission {
    pub(super) fn new(scope: Scope, area: &str, reason: &str) -> Self {
        Self {
            scope,
            area: area.into(),
            reason: reason.into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub rule_mapping_version: String,
    pub collected_at_unix_seconds: Option<u64>,
    pub scope: Scope,
    pub profile: Profile,
    pub compatibility: CompatibilityNeeds,
    pub management: ManagementStatus,
    pub status: Status,
    pub probes: Vec<Diagnostic>,
    pub recommendations: Vec<Recommendation>,
    pub coverage: Coverage,
    pub omissions: Vec<Omission>,
}
