//! PC health tips and the per-rule advice behind them.
use super::rules::{
    rule_advice, rule_fix, rule_fix_advice, rule_open, rule_remove_threats, rule_renewal_advice,
    rule_restart, rule_scan,
};
use secblitz::diagnostics as diag;
use secblitz::model::CheckStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipProfile {
    Everyday,
    Gaming,
    Work,
    Extra,
}

impl TipProfile {
    pub const ALL: [TipProfile; 4] = [Self::Everyday, Self::Gaming, Self::Work, Self::Extra];
    pub fn title(self) -> &'static str {
        match self {
            Self::Everyday => "Everyday use",
            Self::Gaming => "Gaming",
            Self::Work => "Work & development",
            Self::Extra => "Extra security",
        }
    }
    pub fn blurb(self) -> &'static str {
        match self {
            Self::Everyday => "Browsing, email and video calls",
            Self::Gaming => "Smooth play and a healthy computer",
            Self::Work => "Coding, remote work and shared files",
            Self::Extra => "The strongest protection Windows offers",
        }
    }
    pub fn profile(self) -> diag::Profile {
        match self {
            Self::Everyday => diag::Profile::Everyday,
            Self::Gaming => diag::Profile::Gaming,
            Self::Work => diag::Profile::Development,
            Self::Extra => diag::Profile::HigherSecurity,
        }
    }
    fn probes(self) -> &'static [diag::ProbeId] {
        use diag::ProbeId as P;
        match self {
            Self::Everyday => &[
                P::UpdateCache,
                P::DefenderHealth,
                P::SecurityProviders,
                P::BitLocker,
                P::Backup,
                P::Storage,
                P::Ntfs,
                P::Accounts,
                P::OsSupport,
                P::SecureBootCerts,
                P::DefenderProtection,
                P::SmartScreen,
                P::UpdatePolicy,
                P::HostsFile,
                P::Autostart,
                P::RunHistory,
                P::AccountSetup,
            ],
            Self::Gaming => &[
                P::UpdateCache,
                P::DefenderHealth,
                P::SecurityProviders,
                P::Storage,
                P::Ntfs,
                P::Adapters,
                P::Software,
                P::OsSupport,
                P::SecureBootCerts,
                P::DefenderProtection,
                P::UpdatePolicy,
                P::Autostart,
                P::RunHistory,
                P::WifiSecurity,
            ],
            Self::Work => &[
                P::UpdateCache,
                P::DefenderHealth,
                P::SecurityProviders,
                P::BitLocker,
                P::Backup,
                P::RemoteAccess,
                P::Accounts,
                P::Software,
                P::Vpn,
                P::OsSupport,
                P::SecureBootCerts,
                P::DefenderProtection,
                P::SmartScreen,
                P::UpdatePolicy,
                P::HostsFile,
                P::LegacyFeatures,
                P::Sharing,
                P::AccountHygiene,
                P::FirewallRules,
                P::Autostart,
                P::RunHistory,
                P::AccountSetup,
                P::WifiSecurity,
                P::DnsEncryption,
            ],
            Self::Extra => &[
                P::DefenderHealth,
                P::SecureBoot,
                P::Tpm,
                P::BitLocker,
                P::Vbs,
                P::WinRe,
                P::RemoteAccess,
                P::Accounts,
                P::Permissions,
                P::UpdateCache,
                P::OsSupport,
                P::SecureBootCerts,
                P::DefenderProtection,
                P::SmartScreen,
                P::UpdatePolicy,
                P::HostsFile,
                P::LegacyFeatures,
                P::Persistence,
                P::BrowserExtensions,
                P::AccountHygiene,
                P::Sharing,
                P::FirewallRules,
                P::Autostart,
                P::RunHistory,
                P::AccountSetup,
                P::WindowsHello,
                P::WifiSecurity,
                P::DnsEncryption,
            ],
        }
    }
}

pub fn tip_title(id: diag::ProbeId) -> &'static str {
    use diag::ProbeId as P;
    match id {
        P::UpdateCache => "Windows updates",
        P::UpdateHistory => "Recent updates",
        P::DefenderHealth => "Virus protection",
        P::DefenderPolicy => "Extra virus shields",
        P::SecurityProviders => "Security apps and firewall",
        P::Management => "Who manages this computer",
        P::SecureBoot => "Startup protection",
        P::Tpm => "Security chip",
        P::BitLocker => "Disk encryption",
        P::Vbs => "Core system protection",
        P::WinRe => "Recovery tools",
        P::Accounts => "Sign-in accounts",
        P::RemoteAccess => "Access from other computers",
        P::Software => "Old apps",
        P::BrowserExtensions => "Browser add-ons",
        P::Storage => "Drive health",
        P::Ntfs => "Disk space and errors",
        P::Backup => "Backups",
        P::Adapters => "Network connection",
        P::Dns => "Network settings",
        P::Proxy => "Internet route",
        P::Vpn => "VPN",
        P::Permissions => "Protected services",
        P::OsSupport => "Windows version support",
        P::SecureBootCerts => "Startup security renewal",
        P::DefenderProtection => "Virus protection safeguards",
        P::SmartScreen => "Download and website warnings",
        P::UpdatePolicy => "Automatic updates",
        P::LegacyFeatures => "Old Windows tools",
        P::HostsFile => "Website redirects",
        P::Persistence => "Hidden background tasks",
        P::AccountHygiene => "Old and hidden accounts",
        P::Sharing => "Shared folders",
        P::FirewallRules => "Apps allowed through the firewall",
        P::AccountSetup => "Your everyday account",
        P::WindowsHello => "PIN and Windows Hello",
        P::DnsEncryption => "Private internet lookups",
        P::WifiSecurity => "Wi-Fi protection",
        P::Autostart => "Programs that start by themselves",
        P::RunHistory => "Run box history",
    }
}

pub fn probe_page(id: diag::ProbeId) -> Option<crate::guide::Page> {
    use crate::guide::Page;
    use diag::ProbeId as P;
    Some(match id {
        P::UpdateCache | P::UpdateHistory | P::OsSupport | P::SecureBootCerts | P::UpdatePolicy => {
            Page::WindowsUpdate
        }
        P::DefenderHealth | P::DefenderPolicy | P::DefenderProtection => Page::ProtectionHistory,
        P::SecurityProviders => Page::WindowsSecurity,
        P::Management => Page::WorkAccounts,
        P::SecureBoot => Page::Recovery,
        P::Tpm => Page::DeviceSecurity,
        P::BitLocker => Page::Encryption,
        P::Vbs => Page::CoreIsolation,
        P::Accounts | P::AccountHygiene | P::AccountSetup => Page::OtherUsers,
        P::RemoteAccess => Page::RemoteDesktop,
        P::Software => Page::InstalledApps,
        P::Storage | P::Backup => Page::Backup,
        P::Ntfs => Page::Storage,
        P::Adapters | P::Dns | P::Proxy | P::Vpn | P::DnsEncryption => Page::Network,
        P::WifiSecurity => Page::Wifi,
        P::SmartScreen => Page::AppBrowser,
        P::RunHistory => Page::WindowsSecurity,
        P::LegacyFeatures => Page::OptionalFeatures,
        P::FirewallRules => Page::Firewall,
        P::WindowsHello => Page::SignIn,
        P::BrowserExtensions
        | P::WinRe
        | P::Permissions
        | P::HostsFile
        | P::Persistence
        | P::Sharing
        | P::Autostart => return None,
    })
}

pub fn probe_guide(id: diag::ProbeId) -> Option<&'static crate::guide::Guide> {
    use diag::ProbeId as P;
    crate::guide::guide(match id {
        P::UpdateCache | P::UpdateHistory => "Windows updates",
        P::OsSupport => "Windows lifecycle",
        P::BitLocker => "Device encryption",
        P::SecureBoot => "Secure Boot",
        P::Management => "Management and mutation eligibility",
        P::RunHistory => "clickfix.run_history",
        _ => return None,
    })
}

pub fn tip_advice(id: diag::ProbeId) -> &'static str {
    use diag::ProbeId as P;
    match id {
        P::UpdateCache | P::UpdateHistory => {
            "Your computer may be missing security updates. Open Windows Update to install them."
        }
        P::DefenderHealth | P::DefenderPolicy => "Turn on and update Windows virus protection.",
        P::SecurityProviders => "Make sure one virus protection and the firewall are on.",
        P::Management => "Your computer is managed by an organization. Ask them before changing it.",
        P::SecureBoot => "Turn on Secure Boot (startup protection) in your computer's start-up settings.",
        P::Tpm => "Your security chip is off or not ready. Check your computer's start-up settings.",
        P::BitLocker => "Turn on disk encryption so your files stay private if the computer is lost.",
        P::Vbs => "Core system protection (Memory integrity) is off. Protection shows whether this computer can turn it on safely.",
        P::WinRe => "Recovery tools are off. They help if Windows ever stops starting.",
        P::Accounts => "Use a normal account every day, and switch off the guest account.",
        P::RemoteAccess => "Switch off remote access if you don't use it.",
        P::Software => "Remove old apps that no longer get safety updates.",
        P::BrowserExtensions => "In your browser's menu, open Extensions or Add-ons and remove the ones you don't use.",
        P::Storage => "A drive is showing signs of wear. Back up your files soon.",
        P::Ntfs => "Free up disk space or check your drive for errors.",
        P::Backup => "No backup found. Set up a regular backup of your files.",
        P::Adapters | P::Dns | P::Proxy => "Check your internet connection settings.",
        P::Vpn => "Check your VPN settings.",
        P::Permissions => "Some protected services have loose settings. A fix may be available.",
        P::OsSupport => "Your Windows version is running out of safety updates. Install the newest version in Windows Update.",
        P::SecureBootCerts => "Your computer's startup security needs a renewal. Install all Windows updates and check your computer maker's website.",
        P::DefenderProtection => "Open Windows Security and check your virus protection settings.",
        P::SmartScreen => "Turn on warnings for risky downloads and websites in Windows Security.",
        P::UpdatePolicy => "Turn automatic Windows updates back on and restart your computer when asked.",
        P::LegacyFeatures => "Remove a very old Windows tool that is rarely needed.",
        P::HostsFile => "A hidden file may be sending trusted websites somewhere else. Ask someone you trust to check it.",
        P::Persistence => "Something is set up to run quietly in the background. Ask someone you trust to look at it.",
        P::AccountHygiene => "Turn off hidden or unused accounts on this computer.",
        P::Sharing => "Stop sharing folders you don't need.",
        P::FirewallRules => "Some apps in your personal folders are allowed through the firewall. Remove ones you don't know.",
        P::AccountSetup => "Use a normal account every day, and turn on Find my device on a laptop.",
        P::WindowsHello => "Add a PIN or Windows Hello in Sign-in options for faster, safer sign-in.",
        P::DnsEncryption => "Your internet lookups aren't private. Turn on encrypted lookups in your network settings.",
        P::WifiSecurity => "Your Wi-Fi has weak or no protection. Switch to the newest security option on your router.",
        P::Autostart => "A risky program starts by itself with Windows. Ask someone you trust to look at it.",
        P::RunHistory => "Something typed into the Run box looks like a fake check page trick. Run a full virus scan and change your passwords from another device.",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipFix<'r> {
    Offered(&'static str),
    NotOffered {
        control: &'static str,
        reason: &'r str,
    },
    Restart(&'static str),
    Unchecked,
    NoFix,
    Manual,
}

pub fn tip_fix<'r>(
    tip: &Tip,
    report: Option<&'r secblitz::engine::Report>,
    available: &[String],
) -> TipFix<'r> {
    let Some(control) = tip.fix else {
        return TipFix::Manual;
    };
    let Some(report) = report else {
        return TipFix::Unchecked;
    };
    let Some(row) = report.results.iter().find(|r| r.id == control) else {
        return if available.iter().any(|id| id == control) {
            TipFix::Unchecked
        } else {
            TipFix::NoFix
        };
    };
    if crate::app::flow::candidates(report, available)
        .iter()
        .any(|id| id == control)
    {
        return TipFix::Offered(control);
    }
    let a = secblitz::advice::for_outcome(row);
    if a.status == "Not offered" {
        TipFix::NotOffered {
            control,
            reason: &row.detail,
        }
    } else if a.step == secblitz::advice::NextStep::Restart {
        TipFix::Restart(a.next)
    } else if secblitz::vbs::is_vbs_check_id(control) && row.status == CheckStatus::Compliant {
        TipFix::Restart(core_restart_advice(control))
    } else {
        TipFix::Manual
    }
}

pub fn core_restart_advice(control: &str) -> &'static str {
    if control == secblitz::vbs::STACK_PROTECTION {
        "Extra core protection is on but is not running. Restart your computer (choose Restart, not Shut down)."
    } else {
        crate::app::score::RESTART_TO_START
    }
}

pub fn tip_words(
    tip: &Tip,
    fix: TipFix<'_>,
) -> (&'static str, Option<&'static crate::guide::Guide>) {
    let other = tip
        .guide
        .filter(|g| tip.fix.and_then(crate::guide::guide) != Some(*g));
    match fix {
        TipFix::Offered(_) => (tip.fix_advice, other),
        TipFix::NotOffered { control, reason } => (
            tip.advice,
            crate::guide::guide_not_offered(control, reason).or(other),
        ),
        TipFix::Restart(line) => (line, None),
        TipFix::Unchecked | TipFix::NoFix | TipFix::Manual => (tip.advice, tip.guide),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipAction {
    ReviewFix(&'static str),
    SeeWhy,
    CheckNow,
    RestartNow,
    RemoveThreats,
    StartRenewal { bitlocker: bool },
    Scan,
    Steps,
    Open(secblitz::actions::Action),
    None,
}

pub fn tip_action(tip: &Tip, fix: TipFix<'_>, can_open: bool) -> TipAction {
    let (_, guide) = tip_words(tip, fix);
    match (fix, tip.open) {
        _ if tip.state != TipState::Look => TipAction::None,
        (TipFix::Offered(id), _) => TipAction::ReviewFix(id),
        (TipFix::NotOffered { .. }, _) => TipAction::SeeWhy,
        (TipFix::Restart(_), _) => TipAction::None,
        _ if matches!(tip.renewal, Some(diag::Renewal::Offer { .. })) => match tip.renewal {
            Some(diag::Renewal::Offer { bitlocker }) => TipAction::StartRenewal { bitlocker },
            _ => TipAction::None,
        },
        _ if tip.restart => TipAction::RestartNow,
        _ if tip.remove_threats => TipAction::RemoveThreats,
        _ if tip.scan => TipAction::Scan,
        _ if guide.is_some() => TipAction::Steps,
        (_, Some(open)) if can_open => TipAction::Open(open),
        (TipFix::Unchecked, _) => TipAction::CheckNow,
        (TipFix::Manual, _) if tip.fix.is_some() => TipAction::SeeWhy,
        _ => TipAction::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipState {
    Good,
    Look,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Tip {
    pub title: &'static str,
    pub state: TipState,
    pub advice: &'static str,
    pub open: Option<secblitz::actions::Action>,
    pub scan: bool,
    pub guide: Option<&'static crate::guide::Guide>,
    pub fix: Option<&'static str>,
    pub fix_advice: &'static str,
    pub restart: bool,
    pub remove_threats: bool,
    pub renewal: Option<diag::Renewal>,
    pub explain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TipsReport {
    pub profile: TipProfile,
    pub tips: Vec<Tip>,
    #[allow(dead_code)] // raw evidence, never shown on screen
    pub technical: String,
}

impl TipsReport {
    pub fn count(&self, state: TipState) -> usize {
        self.tips.iter().filter(|t| t.state == state).count()
    }
}

fn tip_state(status: diag::Status) -> TipState {
    match status {
        diag::Status::Healthy | diag::Status::Informational => TipState::Good,
        diag::Status::Attention => TipState::Look,
        diag::Status::Unknown | diag::Status::Unsupported => TipState::Unknown,
    }
}

pub fn summarize_tips(profile: TipProfile, report: &diag::Report) -> TipsReport {
    let mut tips = Vec::new();
    let mut technical = String::new();
    for &id in profile.probes() {
        let Some(probe) = report.probes.iter().find(|p| p.id == id) else {
            continue;
        };
        let mut state = tip_state(probe.status);
        if id == diag::ProbeId::UpdateCache && probe.status != diag::Status::Attention {
            if let Some(h) = report
                .probes
                .iter()
                .find(|p| p.id == diag::ProbeId::UpdateHistory)
            {
                state = tip_state(h.status);
                for a in &h.assessments {
                    technical.push_str(&format!("  history {:?}: {}\n", a.status, a.detail));
                }
            }
        }
        technical.push_str(&format!("{id:?}: {:?} ({})\n", probe.status, probe.source));
        for a in &probe.assessments {
            technical.push_str(&format!("  {:?}: {}\n", a.status, a.detail));
        }
        let attention: Vec<&str> = probe
            .assessments
            .iter()
            .filter(|a| a.status == diag::Status::Attention)
            .map(|a| a.rule.id.as_str())
            .filter(|id| rule_advice(id).is_some())
            .collect();
        let lead = attention
            .iter()
            .copied()
            .find(|id| rule_fix(id).is_some())
            .or_else(|| attention.iter().copied().find(|id| rule_restart(id)))
            .or_else(|| attention.first().copied());
        let remove_threats = probe
            .assessments
            .iter()
            .any(|a| a.status == diag::Status::Attention && rule_remove_threats(&a.rule.id));
        let scan = probe
            .assessments
            .iter()
            .any(|a| a.status == diag::Status::Attention && rule_scan(&a.rule.id));
        let look = state == TipState::Look;
        let renewal = match &probe.evidence {
            Some(diag::Evidence::SecureBootCerts(facts)) if look => Some(diag::Renewal::of(facts)),
            _ => None,
        };
        let explain = lead
            .into_iter()
            .chain(
                probe
                    .assessments
                    .iter()
                    .filter(|a| a.status == diag::Status::Attention)
                    .chain(probe.assessments.iter())
                    .map(|a| a.rule.id.as_str()),
            )
            .find(|rule| secblitz::explain::for_check(rule).is_some())
            .map(str::to_owned);
        let lead = lead.filter(|_| look);
        let restart = lead.is_some_and(rule_restart) || renewal == Some(diag::Renewal::Started);
        tips.push(Tip {
            explain,
            title: tip_title(id),
            state,
            advice: match (
                look,
                renewal
                    .and_then(rule_renewal_advice)
                    .or_else(|| lead.and_then(rule_advice)),
            ) {
                (false, _) => "",
                (true, Some(text)) => text,
                (true, None) => tip_advice(id),
            },
            open: match (look, lead.and_then(rule_open)) {
                (false, _) => None,
                (true, _) if restart => None,
                (true, Some(open)) => Some(open),
                (true, None) => probe_page(id).map(crate::guide::Page::action),
            },
            scan: look && scan,
            // The lead's own steps, else the first check that needs a look
            // and has steps (a fix that is not offered must not hide them).
            guide: lead
                .filter(|_| !restart)
                .and_then(|lead| {
                    crate::guide::guide(lead)
                        .or_else(|| attention.iter().copied().find_map(crate::guide::guide))
                })
                .or_else(|| probe_guide(id).filter(|_| look && !restart)),
            fix: lead.and_then(rule_fix),
            fix_advice: lead.map_or("", rule_fix_advice),
            restart,
            remove_threats: look && remove_threats,
            renewal,
        });
    }
    let rank = |s: TipState| match s {
        TipState::Look => 0,
        TipState::Unknown => 1,
        TipState::Good => 2,
    };
    tips.sort_by_key(|t| rank(t.state));
    for r in report.recommendations.iter().take(24) {
        technical.push_str(&format!("{}: {}\n", r.rule.id, r.reason));
    }
    if technical.len() > 8000 {
        technical.truncate(technical.floor_char_boundary(8000));
    }
    TipsReport {
        profile,
        tips,
        technical,
    }
}

pub fn run_tips(profile: TipProfile) -> TipsReport {
    let report = diag::collect(profile.profile(), &diag::Context::default());
    summarize_tips(profile, &report)
}

#[cfg(test)]
mod tests {
    use super::super::errors::assert_no_dev_terms;
    use super::super::rules::{threats_result, ThreatsResult};
    use super::*;

    fn report_with(probe_id: diag::ProbeId, rules: &[&str]) -> diag::Report {
        let mut report = diag::collect(TipProfile::Extra.profile(), &diag::Context::default());
        let probe = report
            .probes
            .iter_mut()
            .find(|p| p.id == probe_id)
            .expect("probe is part of the profile");
        probe.status = diag::Status::Attention;
        probe.assessments = rules
            .iter()
            .map(|id| diag::Assessment {
                status: diag::Status::Attention,
                detail: String::new(),
                rule: diag::RuleReference {
                    id: (*id).into(),
                    revision: 1,
                    mapping_version: String::new(),
                    documentation: vec![],
                },
            })
            .collect();
        report
    }

    fn tip_in(report: &diag::Report, probe_id: diag::ProbeId) -> Tip {
        summarize_tips(TipProfile::Extra, report)
            .tips
            .into_iter()
            .find(|t| t.title == tip_title(probe_id))
            .expect("tip for the probe")
    }

    #[test]
    fn checks_with_a_protection_fix_point_to_it_instead_of_manual_steps() {
        for id in [
            "accounts.stale_enabled",
            "smb.shares_exposed",
            "smartscreen.browser_policy",
            "smartscreen.apps",
            "update.paused",
            "ps.v2_engine",
        ] {
            assert_eq!(rule_fix(id), Some(id), "{id}");
            assert_no_dev_terms(rule_fix_advice(id));
            assert!(rule_fix_advice(id).len() <= 130, "{id}: one short line");
        }
        for id in [
            "defender.threats",
            "defender.scan_age",
            "persistence.wmi_subscriptions",
            "unknown.rule",
        ] {
            assert_eq!(rule_fix(id), None, "{id}");
        }
        for (probe, rule) in [
            (diag::ProbeId::AccountHygiene, "accounts.stale_enabled"),
            (diag::ProbeId::Sharing, "smb.shares_exposed"),
        ] {
            let tip = tip_in(&report_with(probe, &[rule]), probe);
            assert_eq!(tip.state, TipState::Look, "{rule}");
            assert_eq!(tip.fix, Some(rule), "{rule}");
            assert_eq!(tip.fix_advice, rule_fix_advice(rule), "{rule}");
            assert_eq!(tip.advice, rule_advice(rule).unwrap(), "{rule}");
            assert_eq!(tip.open, rule_open(rule), "{rule}");
            assert!(!tip.scan && !tip.remove_threats, "{rule}");
        }
        let mut report = report_with(diag::ProbeId::AccountHygiene, &["accounts.stale_enabled"]);
        let probe = report
            .probes
            .iter_mut()
            .find(|p| p.id == diag::ProbeId::AccountHygiene)
            .unwrap();
        probe.status = diag::Status::Healthy;
        for a in &mut probe.assessments {
            a.status = diag::Status::Healthy;
        }
        let tip = tip_in(&report, diag::ProbeId::AccountHygiene);
        assert_eq!((tip.fix, tip.remove_threats, tip.open), (None, false, None));
        let tip = tip_for(
            diag::ProbeId::Persistence,
            &["persistence.wmi_subscriptions"],
        );
        assert_eq!(tip.fix, None);
        assert_eq!(
            tip.advice,
            rule_advice("persistence.wmi_subscriptions").unwrap()
        );
    }

    #[test]
    fn found_threats_offer_removal_and_a_scan_stays_for_the_scan_check() {
        assert!(rule_remove_threats("defender.threats"));
        assert!(!rule_remove_threats("defender.scan_age"));
        assert!(rule_scan("defender.scan_age") && !rule_scan("defender.threats"));
        let tip = tip_in(
            &report_with(diag::ProbeId::DefenderProtection, &["defender.threats"]),
            diag::ProbeId::DefenderProtection,
        );
        assert!(tip.remove_threats && !tip.scan && tip.fix.is_none());
        assert_eq!(tip.advice, rule_advice("defender.threats").unwrap());
        let tip = tip_in(
            &report_with(diag::ProbeId::DefenderProtection, &["defender.scan_age"]),
            diag::ProbeId::DefenderProtection,
        );
        assert!(tip.scan && !tip.remove_threats);
    }

    #[test]
    fn threat_removal_is_judged_only_by_what_defender_reports() {
        use secblitz::actions::ThreatRemoval as R;
        let judge = |found, removed, left| {
            threats_result(&R {
                found,
                removed,
                left,
            })
        };
        assert_eq!(judge(0, 0, 0), ThreatsResult::Nothing);
        assert_eq!(judge(2, 2, 0), ThreatsResult::Removed);
        assert_eq!(judge(3, 1, 2), ThreatsResult::Partly);
        assert_eq!(judge(2, 0, 2), ThreatsResult::Stuck);
        assert_eq!(judge(1, 0, 0), ThreatsResult::Stuck);
        assert_eq!(judge(0, 0, 1), ThreatsResult::Stuck);
    }

    #[test]
    fn a_tip_for_something_secblitz_can_fix_goes_to_the_fix() {
        let mut report = diag::collect(TipProfile::Extra.profile(), &diag::Context::default());
        // On Windows the probes read the real PC; only the planted finding may count.
        for p in &mut report.probes {
            p.status = diag::Status::Healthy;
            p.assessments.clear();
        }
        let probe = report
            .probes
            .iter_mut()
            .find(|p| p.id == diag::ProbeId::Vbs)
            .unwrap();
        probe.status = diag::Status::Attention;
        probe.assessments = vec![diag::Assessment {
            status: diag::Status::Attention,
            detail: String::new(),
            rule: diag::RuleReference {
                id: "vbs.memory_integrity".into(),
                revision: 1,
                mapping_version: String::new(),
                documentation: vec![],
            },
        }];
        let tips = summarize_tips(TipProfile::Extra, &report);
        let tip = tips
            .tips
            .iter()
            .find(|t| t.title == tip_title(diag::ProbeId::Vbs))
            .expect("the core protection tip is in the extra profile");
        assert_eq!(tip.state, TipState::Look);
        assert_eq!(tip.fix, Some("vbs.memory_integrity"));
        assert_eq!(tip.advice, rule_advice("vbs.memory_integrity").unwrap());
        assert_eq!(tip.guide, crate::guide::guide("vbs.memory_integrity"));
        assert!(!tip.fix_advice.is_empty());
        assert!(tips.tips.iter().filter(|t| t.fix.is_some()).count() == 1);
    }

    fn look_tip(rule: &str) -> Tip {
        Tip {
            title: "Test",
            state: TipState::Look,
            advice: rule_advice(rule).unwrap_or(""),
            open: rule_open(rule),
            scan: false,
            guide: crate::guide::guide(rule),
            fix: rule_fix(rule),
            fix_advice: rule_fix_advice(rule),
            restart: false,
            remove_threats: false,
            renewal: None,
            explain: None,
        }
    }

    fn protection(id: &str, status: &str, detail: &str) -> secblitz::engine::Report {
        secblitz::engine::Report {
            transaction: None,
            results: vec![secblitz::engine::Outcome {
                id: id.into(),
                status: status.into(),
                detail: detail.into(),
                ..secblitz::engine::Outcome::default()
            }],
            findings: vec![],
            readiness: None,
            undo_next: Vec::new(),
        }
    }

    #[test]
    fn a_tip_promises_a_fix_only_when_protection_offers_it() {
        let mi = "vbs.memory_integrity";
        let tip = look_tip(mi);
        let all = vec![mi.to_owned()];
        let r = protection(mi, "attention", "Eligible");
        assert_eq!(tip_fix(&tip, Some(&r), &all), TipFix::Offered(mi));
        assert_eq!(tip_fix(&tip, Some(&r), &[]), TipFix::Manual);
        let reason = format!("{}: a.sys", secblitz::vbs::DRIVER);
        let r = protection(mi, "skipped", &reason);
        assert_eq!(
            tip_fix(&tip, Some(&r), &all),
            TipFix::NotOffered {
                control: mi,
                reason: &reason
            }
        );
        assert!(crate::guide::guide_not_offered(mi, &reason).is_some());
        let r = protection(mi, "skipped", secblitz::vbs::NOT_SUPPORTED);
        assert!(matches!(
            tip_fix(&tip, Some(&r), &all),
            TipFix::NotOffered { .. }
        ));
        assert!(crate::guide::guide_not_offered(mi, secblitz::vbs::NOT_SUPPORTED).is_none());
        assert_eq!(tip_fix(&tip, None, &all), TipFix::Unchecked);
        let other = protection("uac.enabled", "attention", "");
        assert_eq!(tip_fix(&tip, Some(&other), &all), TipFix::Unchecked);
        assert_eq!(tip_fix(&tip, Some(&other), &[]), TipFix::NoFix);
        let r = protection(mi, "compliant", "");
        assert_eq!(
            tip_fix(&tip, Some(&r), &all),
            TipFix::Restart(crate::app::score::RESTART_TO_START)
        );
        let r = protection(mi, "applied", "Preference applied; restart required");
        assert!(matches!(tip_fix(&tip, Some(&r), &all), TipFix::Restart(_)));
        let stack = look_tip("vbs.kernel_stack_protection");
        let r = protection("vbs.kernel_stack_protection", "compliant", "");
        assert_eq!(
            tip_fix(
                &stack,
                Some(&r),
                &["vbs.kernel_stack_protection".to_owned()]
            ),
            TipFix::Restart(core_restart_advice("vbs.kernel_stack_protection"))
        );
        for (status, detail) in [
            ("skipped", "Relevant policy is configured: assessment only"),
            ("unknown", ""),
            ("skipped", secblitz::vbs::ALREADY_ON),
        ] {
            let r = protection(mi, status, detail);
            assert_eq!(
                tip_fix(&tip, Some(&r), &all),
                TipFix::Manual,
                "{status} {detail}"
            );
        }
        let manual = look_tip("defender.tamper_protection");
        assert_eq!(manual.fix, None);
        let r = protection("defender.tamper_protection", "attention", "");
        assert_eq!(tip_fix(&manual, Some(&r), &all), TipFix::Manual);
        assert_eq!(rule_fix("remote.rdp"), Some("remote_desktop.disabled"));
        assert_eq!(rule_fix("smb.v1"), Some("smb1.disabled"));
        let rdp = look_tip("remote.rdp");
        let r = protection("remote_desktop.disabled", "attention", "Eligible");
        assert_eq!(
            tip_fix(&rdp, Some(&r), &["remote_desktop.disabled".to_owned()]),
            TipFix::Offered("remote_desktop.disabled")
        );
        assert_eq!(rule_fix("winre.enabled"), Some("recovery.winre_enabled"));
        assert_eq!(
            rule_fix("browser.permissions"),
            Some("browser.extensions_off")
        );
        let add_ons = tip_for(diag::ProbeId::BrowserExtensions, &["browser.permissions"]);
        assert_eq!(add_ons.fix, Some("browser.extensions_off"));
        assert_eq!(add_ons.advice, rule_advice("browser.permissions").unwrap());
        assert_eq!(add_ons.fix_advice, rule_fix_advice("browser.permissions"));
        for line in [add_ons.advice, add_ons.fix_advice] {
            assert!(line.len() <= 130 && !line.contains('\u{2014}'), "{line}");
        }
        assert!(!add_ons.advice.contains("Secblitz can"));
        assert!(add_ons.fix_advice.contains("Secblitz can"));
        let winre = tip_for(diag::ProbeId::WinRe, &["winre.enabled"]);
        assert_eq!(winre.fix, Some("recovery.winre_enabled"));
        assert_eq!(winre.advice, rule_advice("winre.enabled").unwrap());
        assert_eq!(winre.fix_advice, rule_fix_advice("winre.enabled"));
        assert_eq!(winre.explain.as_deref(), Some("winre.enabled"));
        let fixes = ["recovery.winre_enabled".to_owned()];
        let r = protection("recovery.winre_enabled", "attention", "Eligible");
        assert_eq!(
            tip_fix(&winre, Some(&r), &fixes),
            TipFix::Offered("recovery.winre_enabled")
        );
        assert_eq!(
            tip_action(&winre, tip_fix(&winre, Some(&r), &fixes), true),
            TipAction::ReviewFix("recovery.winre_enabled")
        );
        assert_eq!(
            tip_words(&winre, TipFix::Offered("recovery.winre_enabled")).0,
            winre.fix_advice
        );
        let reason = "Not offered: the recovery tools are missing from this computer";
        let r = protection("recovery.winre_enabled", "skipped", reason);
        assert_eq!(
            tip_fix(&winre, Some(&r), &fixes),
            TipFix::NotOffered {
                control: "recovery.winre_enabled",
                reason
            }
        );
        assert_eq!(
            tip_action(&winre, tip_fix(&winre, Some(&r), &fixes), true),
            TipAction::SeeWhy
        );
        assert_eq!(tip_fix(&winre, None, &fixes), TipFix::Unchecked);
        let r = protection("recovery.winre_enabled", "compliant", "");
        assert_eq!(tip_fix(&winre, Some(&r), &fixes), TipFix::Manual);
        assert_eq!(tip_action(&winre, TipFix::Manual, true), TipAction::SeeWhy);
        assert!(!rule_advice("winre.enabled")
            .unwrap()
            .contains("Secblitz can"));
        for rule in ["remote.rdp", "smb.v1", mi, "vbs.kernel_stack_protection"] {
            let text = rule_advice(rule).unwrap();
            assert!(!text.contains("Secblitz can"), "{rule}: {text}");
            assert!(
                crate::guide::guide(rule).is_some(),
                "{rule}: steps for doing it by hand"
            );
        }
    }

    #[test]
    fn every_profile_lists_known_probes_with_unique_titles() {
        for p in TipProfile::ALL {
            let ids = p.probes();
            assert!(ids.len() >= 5);
            for (i, id) in ids.iter().enumerate() {
                assert!(!ids[..i].contains(id));
            }
        }
    }

    fn tip_for(probe_id: diag::ProbeId, rules: &[&str]) -> Tip {
        let profile = TipProfile::ALL
            .into_iter()
            .find(|p| p.probes().contains(&probe_id))
            .expect("a profile lists the probe");
        let mut report = diag::collect(profile.profile(), &diag::Context::default());
        let probe = report.probes.iter_mut().find(|p| p.id == probe_id).unwrap();
        probe.status = diag::Status::Attention;
        probe.assessments = rules
            .iter()
            .map(|id| diag::Assessment {
                status: diag::Status::Attention,
                detail: String::new(),
                rule: diag::RuleReference {
                    id: (*id).into(),
                    revision: 1,
                    mapping_version: String::new(),
                    documentation: vec![],
                },
            })
            .collect();
        summarize_tips(profile, &report)
            .tips
            .into_iter()
            .find(|t| t.title == tip_title(probe_id))
            .unwrap()
    }

    #[test]
    fn tips_for_checks_we_can_fix_point_to_the_fix_and_keep_the_manual_way() {
        for id in [
            "services.unquoted_paths",
            "firewall.user_dir_inbound_allow",
            "net.hosts_file",
            "persistence.run_and_tasks",
        ] {
            assert_eq!(
                rule_fix(id),
                Some(id),
                "{id} must be a real fix on the Protection page"
            );
            let fix = rule_fix_advice(id);
            assert!(fix.contains("We can"), "{id}: {fix}");
            let manual = rule_advice(id).unwrap();
            assert!(
                !manual.contains("We can") && !manual.contains("Secblitz can"),
                "{id}: {manual}"
            );
            assert!(!manual.contains('\u{2014}'), "{id}");
        }
        assert!(rule_advice("persistence.run_and_tasks")
            .unwrap()
            .contains("Task Manager"));
        let tip = tip_for(
            diag::ProbeId::Persistence,
            &["persistence.wmi_subscriptions", "services.unquoted_paths"],
        );
        assert_eq!(tip.fix, Some("services.unquoted_paths"));
        assert!(!tip.restart && !tip.scan);
        assert_eq!(tip.advice, rule_advice("services.unquoted_paths").unwrap());
        assert_eq!(tip.fix_advice, rule_fix_advice("services.unquoted_paths"));
        assert_eq!(tip.explain.as_deref(), Some("services.unquoted_paths"));
        let tip = tip_for(
            diag::ProbeId::Persistence,
            &["persistence.wmi_subscriptions"],
        );
        assert!(tip.fix.is_none() && !tip.restart);
        assert_eq!(
            tip.guide,
            crate::guide::guide("persistence.wmi_subscriptions")
        );
    }

    #[test]
    fn review_fix_is_only_said_when_the_protection_page_offers_it() {
        let id = "net.hosts_file";
        let tip = tip_for(diag::ProbeId::HostsFile, &[id]);
        let all = vec![id.to_owned()];
        assert_eq!(
            tip_fix(&tip, Some(&protection(id, "attention", "Eligible")), &all),
            TipFix::Offered(id)
        );
        for status in ["ok", "conflict", "compliant", "unknown"] {
            assert_eq!(
                tip_fix(&tip, Some(&protection(id, status, "")), &all),
                TipFix::Manual,
                "{status}"
            );
        }
        let managed = protection(id, "skipped", "Domain-managed machine: assessment only");
        assert_eq!(tip_fix(&tip, Some(&managed), &all), TipFix::Manual);
        assert_eq!(tip_fix(&tip, None, &all), TipFix::Unchecked);
        let reason = "Not offered: the hosts file uses a format we cannot keep exactly";
        assert_eq!(
            tip_fix(&tip, Some(&protection(id, "skipped", reason)), &all),
            TipFix::NotOffered {
                control: id,
                reason
            }
        );
        let mut pending = protection(id, "attention", "Eligible");
        pending.findings.push(secblitz::model::Finding {
            title: "x".into(),
            status: CheckStatus::Pending,
            detail: String::new(),
        });
        assert_eq!(tip_fix(&tip, Some(&pending), &all), TipFix::Manual);
        assert_eq!(
            tip_fix(
                &tip,
                Some(&protection("services.unquoted_paths", "attention", "")),
                &all
            ),
            TipFix::Unchecked
        );
    }

    #[test]
    fn overdue_restart_offers_restart_now_instead_of_opening_windows_update() {
        assert!(rule_restart("update.reboot_overdue") && !rule_restart("update.paused"));
        let tip = tip_for(diag::ProbeId::UpdatePolicy, &["update.reboot_overdue"]);
        assert!(tip.restart && tip.fix.is_none() && tip.open.is_none() && tip.guide.is_none());
        assert!(tip.advice.contains("Save your work"));
        let tip = tip_for(
            diag::ProbeId::UpdatePolicy,
            &["update.reboot_overdue", "update.paused"],
        );
        assert_eq!((tip.fix, tip.restart), (Some("update.paused"), false));
        let mut report = diag::collect(diag::Profile::Everyday, &diag::Context::default());
        for probe in &mut report.probes {
            probe.status = diag::Status::Healthy;
        }
        let tips = summarize_tips(TipProfile::Everyday, &report);
        assert!(tips.tips.iter().all(|t| t.fix.is_none() && !t.restart));
    }

    #[test]
    fn every_area_tip_without_its_own_check_opens_a_page_or_shows_steps() {
        use diag::ProbeId as P;
        let none = [
            P::BrowserExtensions,
            P::WinRe,
            P::Permissions,
            P::HostsFile,
            P::Persistence,
            P::Sharing,
            P::Autostart,
        ];
        for &id in P::ALL {
            let tip = Tip {
                title: tip_title(id),
                state: TipState::Look,
                advice: tip_advice(id),
                open: probe_page(id).map(crate::guide::Page::action),
                scan: false,
                guide: probe_guide(id),
                fix: None,
                fix_advice: "",
                restart: false,
                remove_threats: false,
                renewal: None,
                explain: None,
            };
            let action = tip_action(&tip, TipFix::Manual, true);
            assert_eq!(
                action == TipAction::None,
                none.contains(&id),
                "{id:?}: {action:?}"
            );
            if let (Some(g), Some(page)) = (probe_guide(id), probe_page(id)) {
                assert_eq!(g.page, page, "{id:?}");
            }
        }
    }

    #[test]
    fn every_tip_that_needs_the_person_has_a_fix_an_action_or_steps() {
        for rule in [
            "os.feature_release_support",
            "boot.secure_boot_certs",
            "defender.tamper_protection",
            "defender.threats",
            "defender.exclusions_risky",
            "defender.scan_age",
            "smartscreen.apps",
            "smartscreen.browser_policy",
            "update.paused",
            "update.reboot_overdue",
            "ps.v2_engine",
            "net.hosts_file",
            "persistence.wmi_subscriptions",
            "services.unquoted_paths",
            "accounts.stale_enabled",
            "smb.shares_exposed",
            "firewall.user_dir_inbound_allow",
            "accounts.daily_admin",
            "accounts.hello_configured",
            "accounts.find_my_device",
            "vbs.memory_integrity",
            "vbs.kernel_stack_protection",
            "net.dns_encryption",
            "net.wifi_security",
            "persistence.run_and_tasks",
            "clickfix.run_history",
            "remote.rdp",
            "smb.v1",
            "winre.enabled",
        ] {
            let mut tip = look_tip(rule);
            tip.scan = rule_scan(rule);
            tip.remove_threats = rule_remove_threats(rule);
            tip.restart = rule_restart(rule);
            let mut states = vec![TipFix::Manual];
            if let Some(control) = tip.fix {
                states.extend([
                    TipFix::Unchecked,
                    TipFix::Offered(control),
                    TipFix::NotOffered {
                        control,
                        reason: "Not offered: some reason",
                    },
                ]);
            }
            for fix in states {
                assert_ne!(
                    tip_action(&tip, fix, true),
                    TipAction::None,
                    "{rule} {fix:?}: needs a fix, an action, a page or steps"
                );
            }
        }
        let tip = look_tip("vbs.memory_integrity");
        let fix = TipFix::Restart(crate::app::score::RESTART_TO_START);
        assert_eq!(tip_action(&tip, fix, true), TipAction::None);
        assert_eq!(
            tip_words(&tip, fix),
            (crate::app::score::RESTART_TO_START, None)
        );
        let tip = look_tip("net.hosts_file");
        assert_eq!(
            tip_action(&tip, TipFix::Unchecked, true),
            TipAction::CheckNow
        );
        assert_eq!(tip_action(&tip, TipFix::Manual, true), TipAction::SeeWhy);
        assert_eq!(
            tip_action(&tip, TipFix::Offered("net.hosts_file"), true),
            TipAction::ReviewFix("net.hosts_file")
        );
        let tip = look_tip("firewall.user_dir_inbound_allow");
        assert_eq!(
            tip_action(&tip, TipFix::Unchecked, true),
            TipAction::Open(secblitz::actions::Action::OpenFirewall)
        );
        let wmi = "persistence.wmi_subscriptions";
        assert!(rule_fix(wmi).is_none());
        let guide = crate::guide::guide(wmi).expect("hidden tasks have steps");
        assert!(guide.steps[0].contains("Don't remove anything yourself"));
        let tip = tip_for(diag::ProbeId::Persistence, &[wmi]);
        assert_eq!(tip.guide, Some(guide));
        let tip = tip_for(
            diag::ProbeId::Persistence,
            &["services.unquoted_paths", wmi],
        );
        assert_eq!(tip.fix, Some("services.unquoted_paths"));
        assert_eq!(tip.guide, Some(guide));
        for fix in [
            TipFix::Manual,
            TipFix::Unchecked,
            TipFix::Offered("services.unquoted_paths"),
            TipFix::NotOffered {
                control: "services.unquoted_paths",
                reason: "Not offered: some reason",
            },
        ] {
            assert_eq!(tip_words(&tip, fix).1, Some(guide), "{fix:?}");
        }
        let rdp = look_tip("remote.rdp");
        assert_eq!(
            tip_words(&rdp, TipFix::Offered("remote_desktop.disabled")).1,
            None
        );
    }

    #[test]
    fn exact_check_advice_is_plain_and_picks_the_first_problem() {
        for rule in [
            "os.feature_release_support",
            "boot.secure_boot_certs",
            "defender.tamper_protection",
            "defender.threats",
            "defender.exclusions_risky",
            "defender.scan_age",
            "smartscreen.apps",
            "smartscreen.browser_policy",
            "update.paused",
            "update.reboot_overdue",
            "ps.v2_engine",
            "net.hosts_file",
            "persistence.wmi_subscriptions",
            "services.unquoted_paths",
            "accounts.stale_enabled",
            "smb.shares_exposed",
            "firewall.user_dir_inbound_allow",
            "accounts.daily_admin",
            "accounts.hello_configured",
            "accounts.find_my_device",
            "vbs.memory_integrity",
            "vbs.kernel_stack_protection",
            "net.dns_encryption",
            "net.wifi_security",
            "persistence.run_and_tasks",
            "winre.enabled",
        ] {
            let text = rule_advice(rule).expect(rule);
            assert_no_dev_terms(text);
            assert!(text.len() <= 130, "{rule}: keep it to one short line");
        }
        assert_eq!(rule_advice("update.freshness"), None);
        for id in ["vbs.memory_integrity", "vbs.kernel_stack_protection"] {
            assert_eq!(rule_fix(id), Some(id), "{id}");
            assert_eq!(
                rule_open(id),
                Some(secblitz::actions::Action::OpenCoreIsolation),
                "{id}"
            );
            assert!(rule_advice(id).unwrap().contains("Protection"), "{id}");
        }
        assert_eq!(
            rule_fix("defender.exclusions_risky"),
            Some("defender.exclusions_risky")
        );
        assert!(
            rule_fix("defender.tamper_protection").is_none()
                && rule_fix("update.freshness").is_none()
        );
        assert_eq!(
            rule_open("os.feature_release_support"),
            Some(secblitz::actions::Action::OpenWindowsUpdate)
        );
        assert_eq!(rule_open("net.hosts_file"), None);
        use secblitz::actions::Action as A;
        assert_eq!(
            rule_open("defender.tamper_protection"),
            Some(A::OpenTamperProtection)
        );
        assert_eq!(
            rule_open("defender.threats"),
            Some(A::OpenProtectionHistoryList)
        );
        assert_eq!(
            rule_open("defender.scan_age"),
            Some(A::OpenProtectionHistory)
        );
        assert_eq!(
            rule_open("smartscreen.apps"),
            Some(A::OpenAppBrowserControl)
        );
        assert_eq!(
            rule_open("smartscreen.browser_policy"),
            Some(A::OpenAppBrowserControl)
        );
        assert_eq!(rule_open("ps.v2_engine"), Some(A::OpenOptionalFeatures));
        assert_eq!(rule_open("accounts.stale_enabled"), Some(A::OpenAccounts));

        let mut report = diag::collect(diag::Profile::Everyday, &diag::Context::default());
        let probe = report
            .probes
            .iter_mut()
            .find(|p| p.id == diag::ProbeId::DefenderProtection)
            .unwrap();
        probe.status = diag::Status::Attention;
        probe.assessments = ["defender.tamper_protection", "defender.scan_age"]
            .iter()
            .map(|id| diag::Assessment {
                status: diag::Status::Attention,
                detail: String::new(),
                rule: diag::RuleReference {
                    id: (*id).into(),
                    revision: 1,
                    mapping_version: String::new(),
                    documentation: vec![],
                },
            })
            .collect();
        let tips = summarize_tips(TipProfile::Everyday, &report);
        let tip = tips
            .tips
            .iter()
            .find(|t| t.title == tip_title(diag::ProbeId::DefenderProtection))
            .unwrap();
        assert_eq!(tip.state, TipState::Look);
        assert_eq!(
            tip.advice,
            rule_advice("defender.tamper_protection").unwrap()
        );
        assert_eq!(
            tip.open,
            Some(secblitz::actions::Action::OpenTamperProtection)
        );
    }

    #[test]
    fn a_tip_for_something_only_the_person_can_do_carries_numbered_steps() {
        let mut report = diag::collect(diag::Profile::Everyday, &diag::Context::default());
        let probe = report
            .probes
            .iter_mut()
            .find(|p| p.id == diag::ProbeId::DefenderProtection)
            .unwrap();
        probe.status = diag::Status::Attention;
        probe.assessments = vec![diag::Assessment {
            status: diag::Status::Attention,
            detail: String::new(),
            rule: diag::RuleReference {
                id: "defender.tamper_protection".into(),
                revision: 1,
                mapping_version: String::new(),
                documentation: vec![],
            },
        }];
        let tips = summarize_tips(TipProfile::Everyday, &report);
        let tip = tips
            .tips
            .iter()
            .find(|t| t.title == tip_title(diag::ProbeId::DefenderProtection))
            .unwrap();
        let guide = tip.guide.expect("guide");
        assert_eq!(guide.page.action(), tip.open.unwrap());
        assert_eq!(tip.fix, None);
        for rule in [
            "accounts.find_my_device",
            "net.wifi_security",
            "vbs.kernel_stack_protection",
        ] {
            let g = crate::guide::guide(rule).expect(rule);
            assert_eq!(rule_open(rule), Some(g.page.action()), "{rule}");
        }
        assert_eq!(rule_fix("update.paused"), Some("update.paused"));
        assert_eq!(rule_fix("defender.tamper_protection"), None);
    }

    #[test]
    fn new_checks_are_in_the_expected_profiles() {
        use diag::ProbeId as P;
        for p in TipProfile::ALL {
            for id in [
                P::OsSupport,
                P::SecureBootCerts,
                P::DefenderProtection,
                P::UpdatePolicy,
            ] {
                assert!(p.probes().contains(&id), "{p:?} {id:?}");
            }
        }
        assert!(TipProfile::Extra.probes().contains(&P::Persistence));
        assert!(!TipProfile::Everyday.probes().contains(&P::Persistence));
    }

    #[test]
    fn tips_report_puts_problems_first() {
        let mut report = diag::collect(diag::Profile::Everyday, &diag::Context::default());
        let plain = summarize_tips(TipProfile::Everyday, &report);
        assert!(!plain.tips.is_empty());
        assert!(plain.tips.iter().all(|t| t.state == TipState::Unknown));
        let ids = TipProfile::Everyday.probes();
        for probe in &mut report.probes {
            if probe.id == ids[ids.len() - 1] {
                probe.status = diag::Status::Healthy;
            }
            if probe.id == ids[1] {
                probe.status = diag::Status::Attention;
            }
        }
        let tips = summarize_tips(TipProfile::Everyday, &report);
        assert_eq!(tips.tips[0].state, TipState::Look);
        assert_eq!(tips.tips[0].title, tip_title(ids[1]));
        assert_eq!(tips.tips[0].advice, tip_advice(ids[1]));
        assert_eq!(tips.tips.last().unwrap().state, TipState::Good);
        assert_eq!(tips.count(TipState::Look), 1);
        assert_eq!(tips.count(TipState::Good), 1);
        assert!(tips
            .tips
            .iter()
            .filter(|t| t.state == TipState::Good)
            .all(|t| t.advice.is_empty()));
    }

    fn renewal_tip(change: impl Fn(&mut diag::SecureBootCerts)) -> Tip {
        use diag::Reading::Known;
        let mut facts = diag::SecureBootCerts {
            update_completed_event: Known(false),
            update_staged_event: Known(true),
            update_error_event: Known(false),
            servicing_status: Known("NotStarted".into()),
            ca2023_in_db: Known(false),
            secure_boot_enabled: Known(true),
            maker_blocked_event: Known(false),
            available_updates: Known(0),
            servicing_error: Known(0),
            capable: Known(0),
            task_state: Known("Ready".into()),
            is_vm: Known(false),
            bitlocker_on: Known(true),
            other_os: Known(false),
        };
        change(&mut facts);
        let mut report = report_with(diag::ProbeId::SecureBootCerts, &["boot.secure_boot_certs"]);
        let probe = report
            .probes
            .iter_mut()
            .find(|p| p.id == diag::ProbeId::SecureBootCerts)
            .unwrap();
        probe.evidence = Some(diag::Evidence::SecureBootCerts(facts));
        tip_in(&report, diag::ProbeId::SecureBootCerts)
    }

    #[test]
    fn the_startup_security_tip_offers_the_renewal_only_when_it_can_be_done() {
        use diag::Reading::Known;
        let tip = renewal_tip(|_| {});
        assert_eq!(tip.renewal, Some(diag::Renewal::Offer { bitlocker: true }));
        assert_eq!(
            tip_action(&tip, TipFix::Manual, true),
            TipAction::StartRenewal { bitlocker: true }
        );
        assert!(tip.advice.contains("renewing"));
        let tip = renewal_tip(|f| f.bitlocker_on = Known(false));
        assert_eq!(
            tip_action(&tip, TipFix::Manual, true),
            TipAction::StartRenewal { bitlocker: false }
        );

        let started = renewal_tip(|f| f.available_updates = Known(0x5944));
        assert!(started.restart && started.open.is_none());
        assert_eq!(
            tip_action(&started, TipFix::Manual, true),
            TipAction::RestartNow
        );
        assert!(started.advice.starts_with("Renewal started."));

        for (name, change, words) in [
            (
                "maker",
                (|f: &mut diag::SecureBootCerts| f.maker_blocked_event = Known(true))
                    as fn(&mut diag::SecureBootCerts),
                "computer maker needs to update",
            ),
            (
                "task",
                |f| f.task_state = Known("Disabled".into()),
                "update job is switched off",
            ),
            (
                "other system",
                |f| f.other_os = Known(true),
                "another system",
            ),
        ] {
            let tip = renewal_tip(change);
            assert!(tip.advice.contains(words), "{name}: {}", tip.advice);
            assert!(!matches!(
                tip_action(&tip, TipFix::Manual, true),
                TipAction::StartRenewal { .. } | TipAction::RestartNow
            ));
            assert_no_dev_terms(tip.advice);
        }
    }
}
