//! The compiled table of hardening controls. Every entry is data; the rules that read it live in the parent module.

use super::*;

const NO_GATE: Gate = Gate {
    areas: &[],
    pattern: ".",
    tamper_exempt: false,
    secedit: false,
    own_policy_key: "",
    shared_values: &[],
    policy_values: &[],
};

/// Any policy for virtualization-based security, in the policy store or in
/// Mobile Device Management, means somebody else decides: assessment only.
const VBS_GATE: Gate = Gate {
    areas: &["DeviceGuard", "VirtualizationBasedTechnology"],
    own_policy_key: DEVICE_GUARD_POLICY,
    policy_values: &[
        (DEVICE_GUARD_POLICY, "EnableVirtualizationBasedSecurity"),
        (DEVICE_GUARD_POLICY, "HypervisorEnforcedCodeIntegrity"),
        (DEVICE_GUARD_POLICY, "RequirePlatformSecurityFeatures"),
        (DEVICE_GUARD_POLICY, "ConfigureKernelShadowStacksLaunch"),
    ],
    ..NO_GATE
};

pub(crate) const fn set(
    name: &'static str,
    path: &'static str,
    safe: &'static [u32],
    absent_safe: bool,
    fix: Option<u32>,
    max: u32,
) -> Key {
    Key {
        name,
        path,
        value: "",
        rule: Rule::Set {
            safe,
            absent_safe,
            fix,
        },
        max,
        allowed: &[],
    }
}

pub(crate) const fn text(
    name: &'static str,
    path: &'static str,
    safe: &'static [&'static str],
    absent_safe: bool,
    fix: Option<&'static str>,
) -> Key {
    Key {
        name,
        path,
        value: "",
        rule: Rule::Text {
            safe,
            absent_safe,
            fix,
        },
        max: 256,
        allowed: &[],
    }
}

pub(super) const LSA: &str = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
pub(super) const PNP: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
pub(super) const WU: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
pub(super) const WU_AU: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
pub(super) const SYSPOL: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
pub(super) const EXPLORER: &str =
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";

pub(super) const LSA_MSV1: &str = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
pub(super) const CI_CONFIG: &str = r"HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config";
pub(super) const PRINTERS_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
pub(super) const STORE_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore";
pub(super) const WU_UX: &str = r"HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
pub(super) const EXPLORER_MACHINE: &str =
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
pub(super) const WINDOWS_AI_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI";
const DSH_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Dsh";
const DEVICE_METADATA_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
const INPUT_PERSONALIZATION_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization";
const TEXT_INPUT_POLICY: &str =
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput";
const PAINT_POLICY: &str = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint";
const NOTEPAD_POLICY: &str = r"HKLM:\SOFTWARE\Policies\WindowsNotepad";
pub(super) const DATA_COLLECTION_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection";
pub(super) const DELIVERY_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
pub(super) const POWER_CONSOLELOCK_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51";
pub(super) const DEVICE_GUARD_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
pub(super) const HVCI_SCENARIO: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
pub(super) const STACK_SCENARIO: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks";
const MITIGATION_STATES: &[u32] = &[0, 1, 2];
/// Pause markers are minutes since 1970; the cap keeps them inside a PowerShell int.
const PAUSE_MAX: u32 = 2_000_000_000;

const ASR_ACTIONS: &[u32] = &[0, 1, 2, 6];
const fn asr(guid: &'static str, fix: u32) -> Key {
    Key {
        name: guid,
        path: "",
        value: "",
        rule: Rule::Set {
            safe: &[1, 6],
            absent_safe: false,
            fix: Some(fix),
        },
        max: 6,
        allowed: ASR_ACTIONS,
    }
}

const fn asr_block(guid: &'static str) -> Key {
    Key {
        name: guid,
        path: "",
        value: "",
        rule: Rule::Set {
            safe: &[1],
            absent_safe: false,
            fix: Some(1),
        },
        max: 6,
        allowed: ASR_ACTIONS,
    }
}

pub(super) const SSL3_CLIENT: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client";
pub(super) const SSL3_SERVER: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server";
pub(super) const TLS10_CLIENT: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client";
pub(super) const TLS10_SERVER: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server";
pub(super) const TLS11_CLIENT: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client";
pub(super) const TLS11_SERVER: &str =
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server";
const TLS_ENABLED_VALUES: &[u32] = &[0, 1, u32::MAX];
/// SCHANNEL `Enabled` is a DWORD where 0 is off and any other value (often
/// 0xFFFFFFFF) is on. Only 0 is safe; the exact original is journaled.
const fn tls_enabled(name: &'static str, path: &'static str) -> Key {
    Key {
        name,
        path,
        value: "Enabled",
        rule: Rule::Set {
            safe: &[0],
            absent_safe: false,
            fix: Some(0),
        },
        max: u32::MAX,
        allowed: TLS_ENABLED_VALUES,
    }
}
const fn tls_default_off(name: &'static str, path: &'static str) -> Key {
    Key {
        name,
        path,
        value: "DisabledByDefault",
        rule: Rule::Set {
            safe: &[1],
            absent_safe: false,
            fix: Some(1),
        },
        max: 1,
        allowed: &[],
    }
}
/// Cloud extended timeout in seconds (Defender accepts 0 to 50).
const CLOUD_TIMEOUT_SAFE: &[u32] = &[
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, 46, 47, 48, 49, 50,
];

pub(super) const WINLOGON: &str = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
pub(super) const TERMINAL_SERVER: &str = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server";
pub(super) const TERMINAL_SERVICES_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
pub(super) const EDGE_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Edge";
pub(super) const CHROME_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Google\Chrome";
const BRAVE_POLICY: &str = r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave";
const FIREFOX_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox";
const FIREFOX_TRACKING_POLICY: &str =
    r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection";
const FIREFOX_DOH_POLICY: &str = r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

const BROWSER_MANAGEMENT: &[(&str, &str)] = &[
    (CHROME_POLICY, "CloudManagementEnrollmentToken"),
    (EDGE_POLICY, "EdgeManagementEnrollmentToken"),
];

const ADDON_GATE: &[(&str, &str)] = &[
    (CHROME_POLICY, "CloudManagementEnrollmentToken"),
    (EDGE_POLICY, "EdgeManagementEnrollmentToken"),
    (CHROME_POLICY, "ExtensionSettings"),
    (EDGE_POLICY, "ExtensionSettings"),
];

const BROWSER_AREAS: &[&str] = &["Browser", "Edge", "ADMX_MicrosoftEdge"];

pub(super) const TCPIP: &str = r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
pub(super) const TCPIP6: &str = r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";

pub(super) static SPECS: &[Spec] = &[
    Spec {
        id: "defender.cloud_protection",
        title: "Defender cloud-assisted detection",
        description: "Turn on Defender cloud protection and block-at-first-sight. Sends information about suspicious files to Microsoft. Unmanaged devices only; the original values are restored on undo.",
        source: Source::DefenderPref,
        reboot: false,
        ask: true,
        keys: &[
            set("MAPSReporting", "", &[1, 2], false, Some(2), 2),
            set("DisableBlockAtFirstSeen", "", &[0], false, Some(0), 1),
        ],
        gate: NO_GATE,
    },
    Spec {
        id: "defender.pua",
        title: "Defender unwanted-app blocking",
        description: "Turn on blocking of potentially unwanted applications. Audit-only or disabled settings are repaired; the original value is restored on undo.",
        source: Source::DefenderPref,
        reboot: false,
        ask: false,
        keys: &[set("PUAProtection", "", &[1], false, Some(1), 2)],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.script_nis",
        title: "Defender script scanning and network inspection",
        description: "Repair only explicitly disabled script scanning or network traffic inspection. Absent values already mean on.",
        source: Source::DefenderPref,
        reboot: false,
        ask: false,
        keys: &[
            set("DisableScriptScanning", "", &[0], true, Some(0), 1),
            set("DisableIntrusionPreventionSystem", "", &[0], true, Some(0), 1),
        ],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.asr.standard",
        title: "Defender app and script protections",
        description: "Turn on Microsoft Defender protections that stop unsafe drivers from loading, keep other programs from reading your sign-in details, and stop programs from quietly setting themselves up to run in the background. Only rules that are off are set to Block; Block and Warn settings are preserved. Rules are added, never replaced as a list.",
        source: Source::DefenderAsr,
        reboot: false,
        ask: false,
        keys: &[
            asr("56a863a9-875e-4185-98a7-b882c64b5ce5", 1),
            asr("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", 1),
            asr("e6db77e5-3df2-4cf1-b95a-636979351e5b", 1),
        ],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.asr.web_script_email",
        title: "Defender script and email attachment rules",
        description: "Ask before scripts or email attachments launch programs (Warn mode, the person can allow each time). Rules already on are preserved.",
        source: Source::DefenderAsr,
        reboot: false,
        ask: true,
        keys: &[
            asr("d3e037e1-3eb8-44c8-a917-57927947596d", 6),
            asr("5beb7efe-fd9a-4556-801d-275e5ffc04cc", 6),
            asr("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", 6),
        ],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "lsa.run_as_ppl",
        title: "Run the sign-in service as a protected process",
        description: "Set RunAsPPL to 2 (protected, without a firmware lock) only when Secure Boot is on, no add-on would be blocked and no third-party sign-in packages exist. Value 1 (firmware lock) is never written. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1, 2],
            ..set("RunAsPPL", LSA, &[1, 2], false, Some(2), 2)
        }],
        gate: Gate {
            areas: &["LocalSecurityAuthority"],
            ..NO_GATE
        },
    },
    Spec {
        id: "net.public_sharing_exposure",
        title: "Turn off file sharing on public networks",
        description: "Remove the Public profile from enabled built-in file and printer sharing and network discovery rules (or disable a rule that is Public-only). Rules are never deleted and the network type is never changed.",
        source: Source::FirewallExposure,
        reboot: false,
        ask: false,
        keys: &[Key {
            name: "*",
            path: "",
            value: "",
            rule: Rule::Exposure,
            max: 15,
            allowed: &[],
        }],
        gate: NO_GATE,
    },
    Spec {
        id: "printer.point_and_print",
        title: "Printer driver install without permission",
        description: "Remove only insecure Point and Print policy values so Windows uses its protected default. Unrelated printer policy and the Print Spooler are untouched.",
        source: Source::Registry,
        reboot: false,
        ask: false,
        keys: &[
            set("RestrictDriverInstallationToAdministrators", PNP, &[1], true, None, 1),
            set("NoWarningNoElevationOnInstall", PNP, &[0], true, None, 1),
            set("UpdatePromptSettings", PNP, &[0, 1], true, None, 2),
        ],
        gate: Gate {
            areas: &["Printers", "ADMX_Printing"],
            own_policy_key: PNP,
            ..NO_GATE
        },
    },
    Spec {
        id: "net.llmnr",
        title: "Turn off LLMNR name lookups",
        description: "Set the DNS Client EnableMulticast policy to 0 so other devices on the network cannot answer name lookups. Undo removes the value again. Restart recommended.",
        source: Source::Registry,
        reboot: true,
        ask: false,
        keys: &[set(
            "EnableMulticast",
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            &[0],
            false,
            Some(0),
            1,
        )],
        gate: Gate {
            areas: &["ADMX_DnsClient"],
            own_policy_key: r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            ..NO_GATE
        },
    },
    Spec {
        id: "accounts.lockout_policy",
        title: "Lock an account after repeated wrong passwords",
        description: "Where local accounts never lock, set the lockout threshold to 10 failed sign-ins. Lockout duration and window are not changed.",
        source: Source::Lockout,
        reboot: false,
        ask: false,
        keys: &[set(
            "LockoutThreshold",
            "",
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            false,
            Some(10),
            999,
        )],
        gate: Gate {
            areas: &["DeviceLock"],
            secedit: true,
            ..NO_GATE
        },
    },
    Spec {
        id: "autorun.disabled",
        title: "Stop USB and disc auto-run",
        description: "Set NoDriveTypeAutoRun to 255 and NoAutorun to 1 so inserted drives never start anything on their own. Takes effect after sign-out or restart.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            set("NoDriveTypeAutoRun", EXPLORER, &[255], false, Some(255), 255),
            set("NoAutorun", EXPLORER, &[1], false, Some(1), 1),
        ],
        gate: Gate {
            areas: &["ADMX_AutoPlay", "Autoplay"],
            ..NO_GATE
        },
    },
    Spec {
        id: "wifi.risky_profiles",
        title: "Saved Wi-Fi networks that join by themselves",
        description: "Set saved open, WEP or WPA-TKIP Wi-Fi networks to connect manually. Networks are never deleted; passwords are never read.",
        source: Source::WifiProfiles,
        reboot: false,
        ask: true,
        keys: &[set("*", "", &[0], false, Some(0), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "lsa.restrict_anonymous",
        title: "Keep account and shared folder lists private",
        description: "Set RestrictAnonymous to 1 and keep Everyone from including anonymous users and null sessions off. Very old devices may no longer list shared folders. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            set("RestrictAnonymous", LSA, &[1, 2], false, Some(1), 2),
            set("EveryoneIncludesAnonymous", LSA, &[0], true, Some(0), 1),
            set(
                "RestrictNullSessAccess",
                r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                &[1],
                true,
                Some(1),
                1,
            ),
        ],
        gate: Gate {
            areas: &["LocalPoliciesSecurityOptions"],
            pattern: "^NetworkAccess_",
            secedit: true,
            ..NO_GATE
        },
    },
    Spec {
        id: "remote_assistance.disabled",
        title: "Block unsolicited Remote Assistance",
        description: "Set fAllowToGetHelp to 0 so nobody can be invited to control this computer through Remote Assistance. Quick Assist is separate and unaffected.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "fAllowToGetHelp",
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance",
            &[0],
            false,
            Some(0),
            1,
        )],
        gate: Gate {
            areas: &["RemoteAssistance", "ADMX_RemoteAssistance"],
            policy_values: &[(
                r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                "fAllowToGetHelp",
            )],
            ..NO_GATE
        },
    },
    Spec {
        id: "wsh.disabled",
        title: "Turn off Windows Script Host",
        description: "Set Windows Script Host Enabled to 0 so .vbs and .js files cannot be run by double-clicking. Undo removes the value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "Enabled",
            r"HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings",
            &[0],
            false,
            Some(0),
            1,
        )],
        gate: NO_GATE,
    },
    Spec {
        id: "update.auto_policy_disabled",
        title: "Windows automatic updates switched off by a setting",
        description: "Remove locally set update blockers (NoAutoUpdate=1, AUOptions=1, DisableWindowsUpdateAccess=1). Update servers or managed devices are left alone; undo restores the values.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            set("NoAutoUpdate", WU_AU, &[0], true, None, 1),
            Key {
                allowed: &[0, 1, 2, 3, 4, 5],
                ..set("AUOptions", WU_AU, &[0, 2, 3, 4, 5], true, None, 5)
            },
            set("DisableWindowsUpdateAccess", WU, &[0], true, None, 1),
        ],
        gate: Gate {
            areas: &["Update", "ADMX_WindowsUpdate"],
            policy_values: &[
                (WU, "WUServer"),
                (WU, "WUStatusServer"),
                (WU, "SetPolicyDrivenUpdateSourceForFeatureUpdates"),
                (WU, "SetPolicyDrivenUpdateSourceForQualityUpdates"),
                (WU_AU, "UseWUServer"),
            ],
            ..NO_GATE
        },
    },
    Spec {
        id: "ntlm.lm_compat_level",
        title: "Accept only modern NTLM sign-in",
        description: "Set LmCompatibilityLevel to 5 (NTLMv2 only). Old network drives or scanners may stop signing in. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[set("LmCompatibilityLevel", LSA, &[5], false, Some(5), 5)],
        gate: Gate {
            areas: &["LocalPoliciesSecurityOptions"],
            pattern: "^NetworkSecurity_LANManagerAuthenticationLevel",
            secedit: true,
            ..NO_GATE
        },
    },
    Spec {
        id: "accounts.builtin_administrator",
        title: "Unused built-in Administrator account",
        description: "Disable the built-in Administrator (RID 500) account when another enabled administrator exists. Never deletes it; undo enables it again.",
        source: Source::BuiltinAdmin,
        reboot: false,
        ask: true,
        keys: &[set("Enabled", "", &[0], false, Some(0), 1)],
        gate: Gate {
            areas: &["LocalPoliciesSecurityOptions"],
            pattern: "^Accounts_EnableAdministratorAccountStatus",
            secedit: true,
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.activity_history",
        title: "Windows activity history",
        description: "Stop Windows collecting and syncing an activity timeline (EnableActivityFeed, PublishUserActivities, UploadUserActivities = 0).",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            set("EnableActivityFeed", SYSPOL, &[0], false, Some(0), 1),
            set("PublishUserActivities", SYSPOL, &[0], false, Some(0), 1),
            set("UploadUserActivities", SYSPOL, &[0], false, Some(0), 1),
        ],
        gate: Gate {
            areas: &["Privacy"],
            pattern: "^(EnableActivityFeed|PublishUserActivities|UploadUserActivities)",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.advertising_id",
        title: "Advertising ID",
        description: "Set the DisabledByGroupPolicy advertising-ID policy to 1 so apps cannot track you across apps for ads.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "DisabledByGroupPolicy",
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            &[1],
            false,
            Some(1),
            1,
        )],
        gate: Gate {
            areas: &["Privacy"],
            pattern: "^AllowAdvertisingId",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.wifi_random_address",
        title: "Random hardware address on Wi-Fi",
        description: "Turn on random hardware addresses on each Wi-Fi adapter, so Wi-Fi networks cannot recognise this computer from one visit to the next. Applies from the next Wi-Fi connection. Not offered when the computer has no Wi-Fi adapter. Undo restores every adapter.",
        source: Source::WifiRandomAddress,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1],
            ..set("*", "", &[1], false, Some(1), 1)
        }],
        gate: NO_GATE,
    },
    Spec {
        id: "privacy.online_speech",
        title: "Online speech recognition",
        description: "Stop people on this computer from turning on cloud-based speech recognition (AllowInputPersonalization=0). Voice typing stops working. Not offered on Windows Home. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "AllowInputPersonalization",
            INPUT_PERSONALIZATION_POLICY,
            &[0],
            false,
            Some(0),
            1,
        )],
        gate: Gate {
            areas: &["Privacy"],
            pattern: "^AllowInputPersonalization",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.typing_inking",
        title: "Sending what you type and write by hand",
        description: "Stop Windows sending typing and handwriting samples to Microsoft to improve recognition (AllowLinguisticDataCollection=0). Not offered on Windows Home. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "AllowLinguisticDataCollection",
            TEXT_INPUT_POLICY,
            &[0],
            false,
            Some(0),
            1,
        )],
        gate: Gate {
            areas: &["TextInput"],
            pattern: "^AllowLinguisticDataCollection",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.lock_screen_notifications",
        title: "Messages on the lock screen",
        description: "Stop app notifications showing on the lock screen (DisableLockScreenAppNotifications=1). Not offered on Windows Home. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("DisableLockScreenAppNotifications", SYSPOL, &[1], false, Some(1), 1)],
        gate: Gate {
            areas: &["WindowsLogon"],
            pattern: "^DisableLockScreenAppNotifications",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.signin_email",
        title: "Your email address on the sign-in screen",
        description: "Stop people choosing to show account details such as an email address on the sign-in screen (BlockUserFromShowingAccountDetailsOnSignin=1). Not offered on Windows Home. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "BlockUserFromShowingAccountDetailsOnSignin",
            SYSPOL,
            &[1],
            false,
            Some(1),
            1,
        )],
        gate: Gate {
            areas: &["ADMX_Logon"],
            pattern: "^BlockUserFromShowingAccountDetailsOnSignin",
            ..NO_GATE
        },
    },
    Spec {
        id: "defender.asr.office",
        title: "Defender protections for Office files",
        description: "Turn on Microsoft Defender protections that stop Office from starting other programs, saving risky files or running code inside other programs. Only offered when Office is installed. Rules are added, never replaced as a list.",
        source: Source::DefenderAsr,
        reboot: false,
        ask: true,
        keys: &[
            asr_block("d4f940ab-401b-4efc-aadc-ad5f3c50688a"),
            asr_block("3b576869-a4ec-4529-8536-b80a7769e899"),
            asr_block("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"),
            asr_block("26190899-1602-49e8-8b27-eb1d0a1ce869"),
        ],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.asr.ransomware_usb",
        title: "Defender ransomware and USB rules",
        description: "Ask before unknown programs from USB drives run and use extra ransomware protection (Warn mode, the person can allow each time). Needs cloud protection. Rules are added, never replaced as a list.",
        source: Source::DefenderAsr,
        reboot: false,
        ask: true,
        keys: &[
            asr("c1db55ab-c21a-4637-bb3f-a12568109d35", 6),
            asr("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", 6),
        ],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.network_protection",
        title: "Defender network protection",
        description: "Turn on Defender network protection so programs cannot reach known harmful websites and servers. Windows Pro and Enterprise only; the original value is restored on undo.",
        source: Source::DefenderPref,
        reboot: false,
        ask: true,
        keys: &[set("EnableNetworkProtection", "", &[1], false, Some(1), 2)],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.cloud_block_level",
        title: "Defender stricter cloud blocking",
        description: "Set the Defender cloud block level to High and allow up to 20 extra seconds for a cloud verdict on unknown files. Zero tolerance is never set. Original values are restored on undo.",
        source: Source::DefenderPref,
        reboot: false,
        ask: true,
        keys: &[
            Key {
                allowed: &[0, 1, 2, 4, 6],
                ..set("CloudBlockLevel", "", &[2, 4, 6], false, Some(2), 6)
            },
            set("CloudExtendedTimeout", "", CLOUD_TIMEOUT_SAFE, false, Some(20), 50),
        ],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "net.stack_hardening",
        title: "Harden how this computer handles network traffic",
        description: "Ignore ICMP redirects, refuse source-routed packets (IPv4 and IPv6) and stop answering name-release requests. Undo restores the original values. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            set("EnableICMPRedirect", TCPIP, &[0], false, Some(0), 1),
            set("DisableIPSourceRouting", TCPIP, &[2], false, Some(2), 2),
            Key {
                value: "DisableIPSourceRouting",
                ..set("DisableIPSourceRouting6", TCPIP6, &[2], false, Some(2), 2)
            },
            set(
                "NoNameReleaseOnDemand",
                r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
                &[1],
                false,
                Some(1),
                1,
            ),
        ],
        gate: NO_GATE,
    },
    Spec {
        id: "net.netbios",
        title: "Turn off the old NetBIOS name service",
        description: "Set NetBIOS over TCP/IP to Disabled on each network adapter. Only offered when the old file-sharing version is off and no mapped drive or shared folder uses a bare computer name. Undo restores every adapter.",
        source: Source::NetbiosAdapters,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1, 2],
            ..set("*", "", &[2], false, Some(2), 2)
        }],
        gate: NO_GATE,
    },
    Spec {
        id: "net.mdns",
        title: "Turn off multicast name lookups (mDNS)",
        description: "Set EnableMDNS to 0 so this computer neither asks nor answers local-network name lookups. Casting, AirPrint and some smart-home devices may stop being found. Undo restores the original value. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[set(
            "EnableMDNS",
            r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            &[0],
            false,
            Some(0),
            1,
        )],
        gate: NO_GATE,
    },
    Spec {
        id: "net.wpad",
        title: "Stop automatic proxy discovery (WPAD)",
        description: "Set DisableWpad to 1 so Windows no longer searches the network for a proxy script. The proxy service itself is left running. Undo restores the original value. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[set(
            "DisableWpad",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
            &[1],
            false,
            Some(1),
            1,
        )],
        gate: NO_GATE,
    },
    Spec {
        id: "firewall.outbound_smb_internet",
        title: "Block file sharing to the internet",
        description: "Add one firewall rule, \"Secblitz: block outbound file sharing to the internet\", that blocks TCP ports 445 and 139 to internet addresses. Home-network file sharing is unaffected. Undo removes the rule.",
        source: Source::FirewallOutbound,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1],
            ..set("RulePresent", "", &[1], false, Some(1), 1)
        }],
        gate: NO_GATE,
    },
    Spec {
        id: "tls.legacy_protocols",
        title: "Turn off old secure-connection versions",
        description: "Turn off SSL 3.0, TLS 1.0 and TLS 1.1 (client and server) in Windows. Current browsers are unaffected; very old apps or devices may fail to connect. Undo restores the original values. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            tls_enabled("ssl3.client.enabled", SSL3_CLIENT),
            tls_default_off("ssl3.client.default_off", SSL3_CLIENT),
            tls_enabled("ssl3.server.enabled", SSL3_SERVER),
            tls_default_off("ssl3.server.default_off", SSL3_SERVER),
            tls_enabled("tls10.client.enabled", TLS10_CLIENT),
            tls_default_off("tls10.client.default_off", TLS10_CLIENT),
            tls_enabled("tls10.server.enabled", TLS10_SERVER),
            tls_default_off("tls10.server.default_off", TLS10_SERVER),
            tls_enabled("tls11.client.enabled", TLS11_CLIENT),
            tls_default_off("tls11.client.default_off", TLS11_CLIENT),
            tls_enabled("tls11.server.enabled", TLS11_SERVER),
            tls_default_off("tls11.server.default_off", TLS11_SERVER),
        ],
        gate: NO_GATE,
    },
    Spec {
        id: "ntlm.extras",
        title: "Stricter old sign-in settings",
        description: "Turn off two old Windows sign-in settings: keeping a weak old copy of passwords (NoLMHash=1) and letting the system account fall back to signing in without a name (allownullsessionfallback=0). Absent values already mean safe on current Windows. UseMachineId is deliberately not set because it can break network drives. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            set("NoLMHash", LSA, &[1], true, Some(1), 1),
            set("allownullsessionfallback", LSA_MSV1, &[0], true, Some(0), 1),
        ],
        gate: Gate {
            areas: &["LocalPoliciesSecurityOptions"],
            pattern: "^NetworkSecurity_(DoNotStoreLANManager|AllowLocalSystemNULL)",
            secedit: true,
            ..NO_GATE
        },
    },
    Spec {
        id: "driver.vulnerable_blocklist",
        title: "Block drivers Windows knows are unsafe",
        description: "Turn the Windows list of drivers that are known to be unsafe back on. A missing value already means on. Old hardware tools may stop loading a driver. Restart required.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[set("VulnerableDriverBlocklistEnable", CI_CONFIG, &[1], true, Some(1), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "system.exploit_mitigations",
        title: "Windows built-in memory protections",
        description: "Turn back on only the system-wide memory protections (DEP, SEHOP, bottom-up ASLR, high-entropy ASLR, Control Flow Guard) that were explicitly switched off. Protections that are on or left at the Windows default are never touched; forced image relocation is never changed. Restart required.",
        source: Source::ExploitMitigations,
        reboot: true,
        ask: false,
        keys: &[
            Key { allowed: MITIGATION_STATES, ..set("DEP", "", &[1, 2], false, Some(1), 2) },
            Key { allowed: MITIGATION_STATES, ..set("SEHOP", "", &[1, 2], false, Some(1), 2) },
            Key { allowed: MITIGATION_STATES, ..set("BottomUp", "", &[1, 2], false, Some(1), 2) },
            Key { allowed: MITIGATION_STATES, ..set("HighEntropy", "", &[1, 2], false, Some(1), 2) },
            Key { allowed: MITIGATION_STATES, ..set("CFG", "", &[1, 2], false, Some(1), 2) },
        ],
        gate: NO_GATE,
    },
    Spec {
        id: "ps.v2_engine",
        title: "Remove the old PowerShell 2.0 engine",
        description: "Turn off the Windows PowerShell 2.0 optional feature, which lacks modern malware scanning and logging. A feature that is missing already counts as removed. Removal can take a minute or more; undo turns the feature back on.",
        source: Source::PowerShellV2,
        reboot: false,
        ask: true,
        keys: &[set("Enabled", "", &[0], false, Some(0), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "printer.spooler_remote",
        title: "Print sharing on this computer",
        description: "Stop the Print Spooler accepting connections from other computers (RegisterSpoolerRemoteRpcEndPoint=2) when no printer on this computer is shared and nothing is waiting to print. The Spooler restarts once; local printing is unaffected.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[1, 2],
            ..set("RegisterSpoolerRemoteRpcEndPoint", PRINTERS_POLICY, &[2], false, Some(2), 2)
        }],
        gate: Gate {
            areas: &["Printers", "ADMX_Printing"],
            ..NO_GATE
        },
    },
    Spec {
        id: "services.legacy_remote",
        title: "Old remote tools that start by themselves",
        description: "Stop and disable Remote Registry, WinRM, OpenSSH server, Telnet, FTP, IIS web and SNMP services that are running or start automatically. Services that are not installed are ignored; undo restores each start type and running state.",
        source: Source::LegacyServices,
        reboot: false,
        ask: true,
        keys: &[Key {
            name: "*",
            path: "",
            value: "",
            rule: Rule::Set {
                safe: &[3, 4],
                absent_safe: false,
                fix: Some(4),
            },
            max: 13,
            allowed: &[2, 3, 4, 5, 10, 11, 12, 13],
        }],
        gate: Gate {
            areas: &["RemoteManagement", "ADMX_WinRM"],
            ..NO_GATE
        },
    },
    Spec {
        id: "session.lock_on_wake",
        title: "Ask for your password when the computer wakes",
        description: "Require sign-in when the computer wakes from sleep, on the active power plan (plugged in and on battery). Not offered when the signed-in account has no password.",
        source: Source::LockOnWake,
        reboot: false,
        ask: true,
        keys: &[
            set("Ac", "", &[1], false, Some(1), 1),
            set("Dc", "", &[1], false, Some(1), 1),
        ],
        gate: Gate {
            areas: &["Power"],
            pattern: "^RequirePasswordWhenComputerWakes",
            policy_values: &[
                (POWER_CONSOLELOCK_POLICY, "ACSettingIndex"),
                (POWER_CONSOLELOCK_POLICY, "DCSettingIndex"),
            ],
            ..NO_GATE
        },
    },
    Spec {
        id: "update.store_autoupdate_policy",
        title: "Store apps blocked from updating",
        description: "Remove a locally set Microsoft Store policy that stops apps updating by themselves (AutoDownload=2). Managed devices are left alone; undo restores the value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("AutoDownload", STORE_POLICY, &[0, 1, 3, 4], true, None, 4)],
        gate: Gate {
            areas: &["ApplicationManagement"],
            pattern: "^AllowAppStoreAutoUpdate",
            ..NO_GATE
        },
    },
    Spec {
        id: "update.paused",
        title: "Windows updates are paused",
        description: "Resume Windows Update by removing the pause markers (PauseUpdatesExpiryTime and the feature and quality pause start and end times) while a pause is still in force. Undo writes the saved times back, to the minute.",
        source: Source::UpdatePause,
        reboot: false,
        ask: true,
        keys: &[
            set("PauseUpdatesExpiryTime", WU_UX, &[0], false, Some(0), PAUSE_MAX),
            set("PauseFeatureUpdatesEndTime", WU_UX, &[0], false, Some(0), PAUSE_MAX),
            set("PauseQualityUpdatesEndTime", WU_UX, &[0], false, Some(0), PAUSE_MAX),
            set("PauseFeatureUpdatesStartTime", WU_UX, &[0], false, Some(0), PAUSE_MAX),
            set("PauseQualityUpdatesStartTime", WU_UX, &[0], false, Some(0), PAUSE_MAX),
        ],
        gate: Gate {
            areas: &["Update", "ADMX_WindowsUpdate"],
            policy_values: &[
                (WU, "WUServer"),
                (WU, "WUStatusServer"),
                (WU, "SetPolicyDrivenUpdateSourceForFeatureUpdates"),
                (WU, "SetPolicyDrivenUpdateSourceForQualityUpdates"),
                (WU_AU, "UseWUServer"),
            ],
            ..NO_GATE
        },
    },
    Spec {
        id: "smartscreen.apps",
        title: "Warn before running unknown downloads",
        description: "Set the SmartScreen app and file check to Warn when it is Off, and remove a locally set EnableSmartScreen=0 policy value. Managed devices and policy-controlled values are left alone; undo restores both.",
        source: Source::SmartScreen,
        reboot: false,
        ask: true,
        keys: &[
            Key {
                allowed: &[0, 1, 2, 3],
                ..set("SmartScreenEnabled", EXPLORER_MACHINE, &[1, 2, 3], true, Some(1), 3)
            },
            set("EnableSmartScreen", SYSPOL, &[1], true, None, 1),
        ],
        gate: Gate {
            areas: &["SmartScreen"],
            ..NO_GATE
        },
    },
    Spec {
        id: "vbs.memory_integrity",
        title: "Memory integrity",
        description: "Turn on Memory integrity (Core isolation in Windows Security) by setting Enabled=1, and WasEnabledBy=2 so Windows Security shows the switch as normal, under the HypervisorEnforcedCodeIntegrity scenario. Locked is never written, so there is no firmware lock. Offered only when the hardware supports it, nothing manages it, nothing is locked and every driver passes the static compatibility scan. Needs a restart; undo restores the exact earlier values.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            Key {
                allowed: &[0, 1],
                ..set("Enabled", HVCI_SCENARIO, &[1], false, Some(1), 1)
            },
            set("WasEnabledBy", HVCI_SCENARIO, &[2], false, Some(2), 255),
        ],
        gate: VBS_GATE,
    },
    Spec {
        id: "vbs.kernel_stack_protection",
        title: "Kernel-mode hardware-enforced stack protection",
        description: "Turn on Kernel-mode Hardware-enforced Stack Protection by setting Enabled=1 and WasEnabledBy=2 under the KernelShadowStacks scenario. Locked is never written. Offered only when Memory integrity is running and the processor supports shadow stacks. Needs a restart; undo restores the exact earlier values.",
        source: Source::Registry,
        reboot: true,
        ask: true,
        keys: &[
            Key {
                allowed: &[0, 1],
                ..set("Enabled", STACK_SCENARIO, &[1], false, Some(1), 1)
            },
            set("WasEnabledBy", STACK_SCENARIO, &[2], false, Some(2), 255),
        ],
        gate: VBS_GATE,
    },
    Spec {
        id: "privacy.recall",
        title: "Recall screenshots",
        description: "Stop Windows saving snapshots of your screen for Recall (DisableAIDataAnalysis=1) on computers that have the Recall feature. Existing snapshots are removed by Windows. Not offered where Recall does not exist; undo removes the setting.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("DisableAIDataAnalysis", WINDOWS_AI_POLICY, &[1], false, Some(1), 1)],
        gate: Gate {
            areas: &["WindowsAI"],
            own_policy_key: WINDOWS_AI_POLICY,
            shared_values: &["DisableClickToDo"],
            ..NO_GATE
        },
    },
    Spec {
        id: "ai.click_to_do",
        title: "Click to Do",
        description: "Stop Windows offering actions on what is on your screen with Click to Do (DisableClickToDo=1). Only offered on versions of Windows that have it; undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("DisableClickToDo", WINDOWS_AI_POLICY, &[1], false, Some(1), 1)],
        gate: Gate {
            areas: &["WindowsAI"],
            own_policy_key: WINDOWS_AI_POLICY,
            shared_values: &["DisableAIDataAnalysis"],
            ..NO_GATE
        },
    },
    Spec {
        id: "ai.paint",
        title: "AI tools in Paint",
        description: "Turn off the AI tools in Paint: Cocreator, Generative fill and Image Creator (DisableCocreator, DisableGenerativeFill, DisableImageCreator = 1). Only offered where Paint is installed; undo restores the earlier values.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            set("DisableCocreator", PAINT_POLICY, &[1], false, Some(1), 1),
            set("DisableGenerativeFill", PAINT_POLICY, &[1], false, Some(1), 1),
            set("DisableImageCreator", PAINT_POLICY, &[1], false, Some(1), 1),
        ],
        gate: Gate {
            own_policy_key: PAINT_POLICY,
            ..NO_GATE
        },
    },
    Spec {
        id: "ai.notepad",
        title: "AI tools in Notepad",
        description: "Turn off the AI writing tools in Notepad (DisableAIFeatures=1). Only offered where the Notepad app from the Microsoft Store is installed; undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("DisableAIFeatures", NOTEPAD_POLICY, &[1], false, Some(1), 1)],
        gate: Gate {
            own_policy_key: NOTEPAD_POLICY,
            ..NO_GATE
        },
    },
    Spec {
        id: "debloat.widgets_policy",
        title: "Widgets button and news board",
        description: "Turn off the Widgets button and its news board for everyone on this computer (AllowNewsAndInterests=0). Not offered on Windows Home, which ignores it, or while Windows protects the value from apps; undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("AllowNewsAndInterests", DSH_POLICY, &[0], false, Some(0), 1)],
        gate: Gate {
            areas: &["NewsAndInterests"],
            pattern: "^AllowNewsAndInterests",
            own_policy_key: DSH_POLICY,
            ..NO_GATE
        },
    },
    Spec {
        id: "debloat.device_companion_apps",
        title: "Extra apps for new devices",
        description: "Stop Windows downloading device pictures and details from the internet, which stops the extra apps it suggests for new mice, keyboards and monitors (PreventDeviceMetadataFromNetwork=1). Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set(
            "PreventDeviceMetadataFromNetwork",
            DEVICE_METADATA_POLICY,
            &[1],
            false,
            Some(1),
            1,
        )],
        gate: Gate {
            own_policy_key: DEVICE_METADATA_POLICY,
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.diagnostic_data_level",
        title: "Optional diagnostic data",
        description: "Limit diagnostic data sent to Microsoft to the required level (AllowTelemetry=1). It is never set to 0 and the diagnostics service is never switched off. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1, 2, 3],
            ..set("AllowTelemetry", DATA_COLLECTION_POLICY, &[0, 1], false, Some(1), 3)
        }],
        gate: Gate {
            areas: &["System"],
            pattern: "^AllowTelemetry",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.delivery_optimization",
        title: "Update sharing with other computers",
        description: "Stop this computer sharing Windows and app downloads with other computers (DODownloadMode=0). Updates still download from Microsoft. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1, 2, 3, 99, 100],
            ..set("DODownloadMode", DELIVERY_POLICY, &[0, 99, 100], false, Some(0), 100)
        }],
        gate: Gate {
            areas: &["DeliveryOptimization"],
            pattern: "^DODownloadMode",
            ..NO_GATE
        },
    },
    Spec {
        id: "privacy.clipboard_sync",
        title: "Clipboard shared between your devices",
        description: "Stop the clipboard being synced to your other devices (AllowCrossDeviceClipboard=0). Not offered on Windows Home. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("AllowCrossDeviceClipboard", SYSPOL, &[0], false, Some(0), 1)],
        gate: Gate {
            areas: &["Experience"],
            pattern: "^AllowCrossDeviceClipboard",
            ..NO_GATE
        },
    },
    Spec {
        id: "defender.exclusions_risky",
        title: "Risky antivirus exclusions",
        description: "Remove only the Defender exclusions that hide whole drives, Windows, user folders, program types such as exe or dll, or script engines. Every removed entry is recorded and undo adds it back. Other exclusions are never touched.",
        source: Source::DefenderExclusions,
        reboot: false,
        ask: true,
        keys: &[set("*", "", &[0], false, Some(0), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "accounts.autologon",
        title: "Automatic sign-in",
        description: "Turn off automatic sign-in by setting only the Winlogon AutoAdminLogon text value to 0. The saved sign-in name, any saved password and the sign-in count are never read or changed, so undo writes the earlier value back exactly. Managed devices are left alone.",
        source: Source::WinlogonAutoLogon,
        reboot: false,
        ask: true,
        keys: &[set("AutoAdminLogon", WINLOGON, &[0], true, Some(0), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "remote_desktop.disabled",
        title: "Remote Desktop connections",
        description: "Stop this computer accepting Remote Desktop connections by setting only fDenyTSConnections to 1. Firewall rules, network-level sign-in and services are not touched. Not offered while you are connected remotely or where Windows cannot host Remote Desktop; undo writes the earlier value back.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("fDenyTSConnections", TERMINAL_SERVER, &[1], true, Some(1), 1)],
        gate: Gate {
            areas: &["RemoteDesktopServices", "ADMX_TerminalServer"],
            policy_values: &[(TERMINAL_SERVICES_POLICY, "fDenyTSConnections")],
            ..NO_GATE
        },
    },
    Spec {
        id: "smb1.disabled",
        title: "Old file sharing (SMB1)",
        description: "Turn off the old SMB1 file-sharing Windows feature and its client and server parts without removing their files. Only parts that are on are turned off; undo turns exactly those parts back on. Needs a restart and can take a minute or more.",
        source: Source::SmbFeature,
        reboot: true,
        ask: true,
        keys: &[
            set("SMB1Protocol", "", &[0], false, Some(0), 1),
            set("SMB1Protocol-Client", "", &[0], false, Some(0), 1),
            set("SMB1Protocol-Server", "", &[0], false, Some(0), 1),
            set("SMB1Protocol-Deprecation", "", &[0], false, Some(0), 1),
        ],
        gate: NO_GATE,
    },
    Spec {
        id: "services.unquoted_paths",
        title: "Background programs with unquoted paths",
        description: "Put quotes around the program path of each background program that has spaces in an unquoted path a standard user could change. Only the path text changes, and only when the program file exists and nothing else in the path could be started first. The exact original is kept and put back on undo.",
        source: Source::UnquotedServices,
        reboot: false,
        ask: true,
        keys: &[set("*", "", HANDLED_SAFE, false, Some(0), 2)],
        gate: NO_GATE,
    },
    Spec {
        id: "firewall.user_dir_inbound_allow",
        title: "Firewall allowances for downloaded programs",
        description: "Switch off (never delete) the inbound allow rules of programs that sit in Downloads, Desktop or Temp folders. Undo switches exactly those rules back on.",
        source: Source::UserDirFirewall,
        reboot: false,
        ask: true,
        keys: &[set("*", "", HANDLED_SAFE, false, Some(0), 2)],
        gate: NO_GATE,
    },
    Spec {
        id: "net.hosts_file",
        title: "Redirected trusted websites",
        description: "Comment out only the lines of the hosts file that send a trusted website, bank or security product somewhere else or block its updates. Each line is marked with a note. The original file is kept and put back byte for byte on undo.",
        source: Source::HostsFile,
        reboot: false,
        ask: true,
        keys: &[set("*", "", HANDLED_SAFE, false, Some(0), 2)],
        gate: NO_GATE,
    },
    Spec {
        id: "persistence.run_and_tasks",
        title: "Risky programs that start by themselves",
        description: "Switch off, the way Task Manager does, start-up entries and scheduled tasks that start unsigned programs from Temp, Downloads or similar places. Nothing is deleted. Undo switches exactly those items back on.",
        source: Source::StartupItems,
        reboot: false,
        ask: true,
        keys: &[set("*", "", HANDLED_SAFE, false, Some(0), 2)],
        gate: NO_GATE,
    },
    Spec {
        id: "accounts.stale_enabled",
        title: "Old accounts that are still switched on",
        description: "Switch off (never delete) local accounts that are switched on but have not signed in for 180 days. Never your own account, an account signed in now, the last administrator or a built-in account. Every account is recorded and undo switches it back on.",
        source: Source::StaleAccounts,
        reboot: false,
        ask: true,
        keys: &[set("*", "", &[0], false, Some(0), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "smb.shares_exposed",
        title: "Who can open your shared folders",
        description: "Remove only the Everyone, Anonymous or Guests entry that gives Change or Full access from a shared folder's permission list. Every removed entry is recorded exactly and undo adds it back. Built-in shares (C$, ADMIN$, IPC$, print$) and all other entries are never touched.",
        source: Source::ShareGrants,
        reboot: false,
        ask: true,
        keys: &[set("*", "", &[0], false, Some(0), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "smartscreen.browser_policy",
        title: "Browser warnings about dangerous sites",
        description: "Remove a locally set policy value that switches off the Edge or Chrome warning about dangerous websites. Managed devices and Group Policy values are left alone. The removed value is recorded and undo puts it back exactly.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            set("SmartScreenEnabled", EDGE_POLICY, &[1], true, None, 1),
            Key {
                allowed: &[0, 1, 2],
                ..set("SafeBrowsingProtectionLevel", CHROME_POLICY, &[1, 2], true, None, 2)
            },
            set("SafeBrowsingEnabled", CHROME_POLICY, &[1], true, None, 1),
        ],
        gate: Gate {
            areas: &["Browser", "Edge", "ADMX_MicrosoftEdge"],
            pattern: "SmartScreen|SafeBrowsing",
            // A browser enrolled in cloud management is run by an organization.
            policy_values: &[
                (CHROME_POLICY, "CloudManagementEnrollmentToken"),
                (EDGE_POLICY, "EdgeManagementEnrollmentToken"),
            ],
            ..NO_GATE
        },
    },
    Spec {
        id: "browser.shopping_ai",
        title: "Shopping and AI sidebars in your browsers",
        description: "Set the Edge policies EdgeShoppingAssistantEnabled and HubsSidebarEnabled to 0 and the Chrome policies ShoppingListEnabled to 0 and GeminiSettings to 1. Browsers then show that a setting was made for the whole computer. Undo puts back every value exactly, or removes it if it was not there.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            set("EdgeShoppingAssistantEnabled", EDGE_POLICY, &[0], false, Some(0), 1),
            set("HubsSidebarEnabled", EDGE_POLICY, &[0], false, Some(0), 1),
            set("ShoppingListEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("GeminiSettings", CHROME_POLICY, &[1], false, Some(1), 1),
        ],
        gate: Gate {
            areas: BROWSER_AREAS,
            pattern: "Shopping|HubsSidebar|Gemini",
            policy_values: BROWSER_MANAGEMENT,
            ..NO_GATE
        },
    },
    Spec {
        id: "browser.data_collection",
        title: "Usage data your browsers send",
        description: "Turn off the browsers' own data collection with the Edge policies DiagnosticData and PersonalizationReportingEnabled, the Chrome policies MetricsReportingEnabled, UrlKeyedAnonymizedDataCollectionEnabled and the four PrivacySandbox ad policies, and the Firefox policies DisableTelemetry and DisableFirefoxStudies. Browsers then show that a setting was made for the whole computer. Undo puts back every value exactly, or removes it if it was not there.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            Key {
                allowed: &[0, 1, 2],
                ..set("DiagnosticData", EDGE_POLICY, &[0, 1], false, Some(0), 2)
            },
            set("PersonalizationReportingEnabled", EDGE_POLICY, &[0], false, Some(0), 1),
            set("MetricsReportingEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("UrlKeyedAnonymizedDataCollectionEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("PrivacySandboxAdTopicsEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("PrivacySandboxSiteEnabledAdsEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("PrivacySandboxAdMeasurementEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("PrivacySandboxPromptEnabled", CHROME_POLICY, &[0], false, Some(0), 1),
            set("DisableTelemetry", FIREFOX_POLICY, &[1], false, Some(1), 1),
            set("DisableFirefoxStudies", FIREFOX_POLICY, &[1], false, Some(1), 1),
        ],
        gate: Gate {
            areas: BROWSER_AREAS,
            pattern: "DiagnosticData|PersonalizationReporting|MetricsReporting|UrlKeyedAnonymized|PrivacySandbox|Telemetry",
            policy_values: BROWSER_MANAGEMENT,
            ..NO_GATE
        },
    },
    Spec {
        id: "browser.safety_mode",
        title: "Stronger protection in your browsers",
        description: "Set the Edge policy EnhanceSecurityMode to 1 (balanced) and the Firefox policy EnableTrackingProtection to on. Chrome's warnings are handled by the browser warnings control. Browsers then show that a setting was made for the whole computer. Undo puts back every value exactly, or removes it if it was not there.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            Key {
                allowed: &[0, 1, 2, 3],
                ..set("EnhanceSecurityMode", EDGE_POLICY, &[1, 2], false, Some(1), 3)
            },
            Key {
                value: "Value",
                ..set("FirefoxTrackingProtection", FIREFOX_TRACKING_POLICY, &[1], false, Some(1), 1)
            },
        ],
        gate: Gate {
            areas: BROWSER_AREAS,
            pattern: "EnhanceSecurityMode|TrackingProtection",
            policy_values: BROWSER_MANAGEMENT,
            ..NO_GATE
        },
    },
    Spec {
        id: "browser.dns_bypass",
        title: "Browsers use Web protection",
        description: "Set the Edge, Chrome and Brave policy DnsOverHttpsMode to off and the Firefox policy DNSOverHTTPS to disabled and locked, so the browsers use the computer's own lookups, which Web protection filters, instead of their own private lookups. Browsers then show that a setting was made for the whole computer. Undo puts back every value exactly, or removes it if it was not there.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[
            Key {
                value: "DnsOverHttpsMode",
                ..text("EdgeDnsOverHttpsMode", EDGE_POLICY, &["off"], false, Some("off"))
            },
            Key {
                value: "DnsOverHttpsMode",
                ..text("ChromeDnsOverHttpsMode", CHROME_POLICY, &["off"], false, Some("off"))
            },
            Key {
                value: "DnsOverHttpsMode",
                ..text("BraveDnsOverHttpsMode", BRAVE_POLICY, &["off"], false, Some("off"))
            },
            Key {
                value: "Enabled",
                ..set("FirefoxDnsOverHttpsEnabled", FIREFOX_DOH_POLICY, &[0], false, Some(0), 1)
            },
            Key {
                value: "Locked",
                ..set("FirefoxDnsOverHttpsLocked", FIREFOX_DOH_POLICY, &[1], false, Some(1), 1)
            },
        ],
        gate: Gate {
            areas: BROWSER_AREAS,
            pattern: "DnsOverHttps|DNSOverHTTPS",
            policy_values: BROWSER_MANAGEMENT,
            ..NO_GATE
        },
    },
    Spec {
        id: "browser.extensions_off",
        title: "Turn off a browser add-on",
        description: "Turn off the Chrome or Edge add-ons you pick, from those that can read every site you visit or talk to other programs, by adding each one to the browser's block list. Only the entry Secblitz adds is ever removed again, so undo turns the add-on back on with its data. Other entries, a block-everything rule and managed browsers are left alone. This applies to everyone who uses the browser on this computer.",
        source: Source::BrowserExtensions,
        reboot: false,
        ask: true,
        keys: &[set("*", "", HANDLED_SAFE, false, Some(0), 2)],
        gate: Gate {
            areas: BROWSER_AREAS,
            pattern: "ExtensionInstall|ExtensionSettings",
            policy_values: ADDON_GATE,
            ..NO_GATE
        },
    },
    Spec {
        id: "recovery.winre_enabled",
        title: "Windows recovery tools",
        description: "Turn the Windows recovery tools back on with the inbox ReAgentc.exe /enable, only when they are off and their image is still in Windows\\System32\\Recovery. Partitions, BitLocker and start-up settings are never edited by Secblitz. Undo runs ReAgentc.exe /disable, which puts the image back where it was.",
        source: Source::RecoveryTools,
        reboot: false,
        ask: false,
        keys: &[set("Enabled", "", &[1], false, Some(1), 1)],
        gate: NO_GATE,
    },
    Spec {
        id: "clickfix.run_box",
        title: "Turn off the Run box",
        description: "Turn off the Run box (Win+R and Run in the Start menu) for every account on this computer by setting NoRun=1. Task Manager, Command Prompt and everything else still work. Undo restores the earlier value.",
        source: Source::Registry,
        reboot: false,
        ask: true,
        keys: &[set("NoRun", EXPLORER, &[1], false, Some(1), 1)],
        gate: Gate {
            areas: &["ADMX_StartMenu"],
            ..NO_GATE
        },
    },
    Spec {
        id: "defender.cfa_watch",
        title: "Watch for apps changing your files",
        description: "Set Defender folder protection to watch only: it records which apps change files in folders like Documents and Pictures, and blocks nothing. Only offered while folder protection is off. The earlier mode is restored on undo.",
        source: Source::DefenderPref,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1, 2, 3, 4],
            ..set("EnableControlledFolderAccess", "", &[1, 2, 3, 4], false, Some(2), 4)
        }],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.cfa_block",
        title: "Protect your files from ransomware",
        description: "Turn on Defender folder protection so apps Windows does not trust cannot change files in folders like Documents and Pictures. Only offered after a week of watching. The earlier mode is restored on undo.",
        source: Source::DefenderPref,
        reboot: false,
        ask: true,
        keys: &[Key {
            allowed: &[0, 1, 2, 3, 4],
            ..set("EnableControlledFolderAccess", "", &[1, 3], false, Some(1), 4)
        }],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
    Spec {
        id: "defender.cfa_allowed_apps",
        title: "Apps allowed to change your files",
        description: "Add the apps that folder protection watched or blocked to its list of allowed apps. Only .exe files that exist are added, never script tools or wildcards. Each app Secblitz adds is recorded and undo removes exactly that one.",
        source: Source::CfaAllowedApps,
        reboot: false,
        ask: true,
        keys: &[set("*", "", &[1], false, Some(1), 1)],
        gate: Gate { tamper_exempt: true, ..NO_GATE },
    },
];
