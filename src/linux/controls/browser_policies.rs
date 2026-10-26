//! What each browser check asks for: the Firefox policies and the Chromium family policies it writes, and how to tell
//! from the policies a browser already has whether the setting is safe.

use serde_json::{json, Map, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ctl {
    Data,
    Https,
    Tracking,
    AdTopics,
    Sponsored,
    SafeBrowsing,
    PasswordLeaks,
    Background,
    Suggestions,
    EncryptedDns,
}

const SAFE_BROWSING_PREFS: [&str; 2] = [
    "browser.safebrowsing.malware.enabled",
    "browser.safebrowsing.phishing.enabled",
];

impl Ctl {
    pub const ALL: [Ctl; 10] = [
        Ctl::Data,
        Ctl::Https,
        Ctl::Tracking,
        Ctl::AdTopics,
        Ctl::Sponsored,
        Ctl::SafeBrowsing,
        Ctl::PasswordLeaks,
        Ctl::Background,
        Ctl::Suggestions,
        Ctl::EncryptedDns,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Ctl::Data => "linux.browser_data_collection",
            Ctl::Https => "linux.browser_https_only",
            Ctl::Tracking => "linux.browser_tracking",
            Ctl::AdTopics => "linux.browser_ad_topics",
            Ctl::Sponsored => "linux.browser_sponsored",
            Ctl::SafeBrowsing => "linux.browser_safe_browsing",
            Ctl::PasswordLeaks => "linux.browser_password_leaks",
            Ctl::Background => "linux.browser_background",
            Ctl::Suggestions => "linux.browser_search_suggestions",
            Ctl::EncryptedDns => "linux.browser_encrypted_dns",
        }
    }

    pub fn memo(self) -> &'static str {
        match self {
            Ctl::Data => "browser_firefox_data",
            Ctl::Https => "browser_firefox_https",
            Ctl::Tracking => "browser_firefox_tracking",
            Ctl::AdTopics => "browser_firefox_ad_topics",
            Ctl::Sponsored => "browser_firefox_sponsored",
            Ctl::SafeBrowsing => "browser_firefox_safe_browsing",
            Ctl::PasswordLeaks => "browser_firefox_password_leaks",
            Ctl::Background => "browser_firefox_background",
            Ctl::Suggestions => "browser_firefox_suggestions",
            Ctl::EncryptedDns => "browser_firefox_dns",
        }
    }

    pub fn firefox(self) -> bool {
        !matches!(self, Ctl::AdTopics | Ctl::PasswordLeaks | Ctl::Background)
    }

    pub fn chromium(self) -> bool {
        !matches!(self, Ctl::Https | Ctl::Sponsored)
    }

    /// Edge reads other names for these settings, so a policy written under the Chromium names would change nothing there.
    pub fn edge(self) -> bool {
        !matches!(self, Ctl::Data | Ctl::SafeBrowsing | Ctl::PasswordLeaks)
    }

    pub fn firefox_policies(self) -> Vec<(&'static str, Value)> {
        match self {
            Ctl::Data => vec![
                ("DisableTelemetry", json!(true)),
                ("DisableFirefoxStudies", json!(true)),
            ],
            Ctl::Https => vec![("HttpsOnlyMode", json!("enabled"))],
            Ctl::Tracking => vec![(
                "EnableTrackingProtection",
                json!({"Value": true, "Cryptomining": true, "Fingerprinting": true}),
            )],
            Ctl::Sponsored => vec![
                (
                    "FirefoxHome",
                    json!({"SponsoredTopSites": false, "SponsoredPocket": false}),
                ),
                ("FirefoxSuggest", json!({"SponsoredSuggestions": false})),
            ],
            Ctl::SafeBrowsing => {
                let prefs: Map<String, Value> = SAFE_BROWSING_PREFS
                    .iter()
                    .map(|k| ((*k).to_string(), json!({"Value": true, "Status": "locked"})))
                    .collect();
                vec![("Preferences", Value::Object(prefs))]
            }
            Ctl::Suggestions => vec![("SearchSuggestEnabled", json!(false))],
            Ctl::EncryptedDns => vec![("DNSOverHTTPS", json!({"Enabled": true, "Fallback": true}))],
            Ctl::AdTopics | Ctl::PasswordLeaks | Ctl::Background => Vec::new(),
        }
    }

    pub fn firefox_safe(self, policies: &Map<String, Value>) -> bool {
        match self {
            Ctl::Https => matches!(
                policies.get("HttpsOnlyMode").and_then(Value::as_str),
                Some("enabled" | "force_enabled")
            ),
            Ctl::SafeBrowsing => {
                let prefs = policies.get("Preferences").and_then(Value::as_object);
                !SAFE_BROWSING_PREFS.iter().any(|k| {
                    prefs.and_then(|p| p.get(*k)).and_then(|v| v.get("Value"))
                        == Some(&json!(false))
                })
            }
            Ctl::EncryptedDns => {
                policies.get("DNSOverHTTPS").and_then(|v| v.get("Enabled")) == Some(&json!(true))
            }
            _ => self
                .firefox_policies()
                .iter()
                .all(|(k, want)| policies.get(*k).is_some_and(|have| contains(have, want))),
        }
    }

    pub fn chromium_policies(self) -> Vec<(&'static str, Value)> {
        match self {
            Ctl::Data => vec![
                ("MetricsReportingEnabled", json!(false)),
                ("UrlKeyedAnonymizedDataCollectionEnabled", json!(false)),
            ],
            Ctl::Tracking => vec![("BlockThirdPartyCookies", json!(true))],
            Ctl::AdTopics => vec![
                ("PrivacySandboxAdTopicsEnabled", json!(false)),
                ("PrivacySandboxSiteEnabledAdsEnabled", json!(false)),
                ("PrivacySandboxAdMeasurementEnabled", json!(false)),
                ("PrivacySandboxPromptEnabled", json!(false)),
            ],
            Ctl::SafeBrowsing => vec![("SafeBrowsingProtectionLevel", json!(1))],
            Ctl::PasswordLeaks => vec![("PasswordLeakDetectionEnabled", json!(true))],
            Ctl::Background => vec![("BackgroundModeEnabled", json!(false))],
            Ctl::Suggestions => vec![("SearchSuggestEnabled", json!(false))],
            Ctl::EncryptedDns => vec![("DnsOverHttpsMode", json!("automatic"))],
            Ctl::Https | Ctl::Sponsored => Vec::new(),
        }
    }

    /// `seen` holds the value each setting ends up with across the policy folder.
    pub fn chromium_safe(self, seen: &Map<String, Value>) -> bool {
        match self {
            Ctl::SafeBrowsing => seen.get("SafeBrowsingProtectionLevel") != Some(&json!(0)),
            Ctl::EncryptedDns => matches!(
                seen.get("DnsOverHttpsMode").and_then(Value::as_str),
                Some("automatic" | "secure")
            ),
            _ => self
                .chromium_policies()
                .iter()
                .all(|(k, v)| seen.get(*k) == Some(v)),
        }
    }
}

/// Whether `have` already says everything `want` asks for, looking inside objects.
fn contains(have: &Value, want: &Value) -> bool {
    match (have, want) {
        (Value::Object(have), Value::Object(want)) => want
            .iter()
            .all(|(k, w)| have.get(k).is_some_and(|h| contains(h, w))),
        _ => have == want,
    }
}

/// Puts `src` into `dst`, keeping the keys of an object that `src` does not mention.
pub fn merge(dst: &mut Value, src: &Value) {
    match (dst, src) {
        (Value::Object(dst), Value::Object(src)) => {
            for (k, v) in src {
                match dst.get_mut(k) {
                    Some(existing) => merge(existing, v),
                    None => {
                        dst.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (dst, src) => *dst = src.clone(),
    }
}
