//! The fingerprint specification for tool-originated traffic (plan §6.2).
//!
//! A [`FingerprintSpec`] is *derived from and pinned to* the same
//! [`FingerprintProfile`] the browser uses, so the matched request engine and
//! the browser share one JA3/JA4/HTTP-2/header fingerprint and cannot drift
//! apart (plan §6.3). The spec is pure data — the TLS/H2 stack that realizes it
//! lives in the engine backend.
//!
//! **Honesty (plan §6.3):** this derivation *targets* parity with the browser;
//! it does not *prove* it. Real parity must be measured against JA3/JA4/HTTP-2
//! reflection endpoints (the Phase-0 parity suite). Treat the preset mapping as
//! a starting point to be verified, never as a guarantee.

use camio_core::FingerprintProfile;
use serde::Serialize;

/// Browser family being impersonated. Camoufox is a Firefox fork, so Camio's
/// matched engine impersonates Firefox; the other families are modelled for
/// completeness and future imported profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Firefox,
    Chrome,
    Safari,
}

impl BrowserFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserFamily::Firefox => "firefox",
            BrowserFamily::Chrome => "chrome",
            BrowserFamily::Safari => "safari",
        }
    }
}

/// The HTTP/2 fingerprint surface (Akamai-style, plan §6.1 item 2): SETTINGS
/// values and the pseudo-header order. Encoded as data so a backend can apply it
/// and a parity check can compare it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Http2Fingerprint {
    /// Order of the HTTP/2 pseudo-headers on the wire. Firefox sends
    /// `:method :path :authority :scheme`; Chrome `:method :authority :scheme :path`.
    pub pseudo_header_order: [&'static str; 4],
    /// SETTINGS_HEADER_TABLE_SIZE.
    pub header_table_size: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE.
    pub initial_window_size: u32,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (None = not advertised).
    pub max_concurrent_streams: Option<u32>,
    /// Connection-level WINDOW_UPDATE increment sent on connect.
    pub connection_window: u32,
}

impl Http2Fingerprint {
    /// Firefox's HTTP/2 fingerprint (approximate; verify against the pinned
    /// build in the parity suite).
    pub fn firefox() -> Self {
        Http2Fingerprint {
            pseudo_header_order: [":method", ":path", ":authority", ":scheme"],
            header_table_size: 65536,
            initial_window_size: 131072,
            max_concurrent_streams: None,
            connection_window: 12517377,
        }
    }

    /// Chrome's HTTP/2 fingerprint (approximate).
    pub fn chrome() -> Self {
        Http2Fingerprint {
            pseudo_header_order: [":method", ":authority", ":scheme", ":path"],
            header_table_size: 65536,
            initial_window_size: 6291456,
            max_concurrent_streams: Some(1000),
            connection_window: 15663105,
        }
    }
}

/// The complete fingerprint target for the matched request engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FingerprintSpec {
    pub family: BrowserFamily,
    pub major_version: u32,
    pub user_agent: String,
    pub accept_language: String,
    /// Canonical outbound header order (names in the browser's exact casing).
    /// The engine emits headers in this order and never alphabetizes
    /// (plan §6.1 item 3). Headers not listed keep their relative order after
    /// the known ones.
    pub header_order: Vec<String>,
    /// Whether to append a `DNT: 1` header (mirrors the profile's do-not-track).
    pub send_dnt: bool,
    pub http2: Http2Fingerprint,
    /// The profile and pinned Camoufox build this spec was derived from — stamped
    /// onto every exchange as `fingerprint_used` for attribution (plan §16).
    pub profile_name: String,
    pub camoufox_build: String,
}

impl FingerprintSpec {
    /// Derive the matched-engine spec from the browser's fingerprint profile.
    /// The two therefore share one identity by construction (plan §6.3).
    pub fn from_profile(profile: &FingerprintProfile) -> Self {
        let major = parse_firefox_major(&profile.persona.user_agent)
            .unwrap_or(camio_core::ALIGNED_FIREFOX_MAJOR);

        FingerprintSpec {
            family: BrowserFamily::Firefox,
            major_version: major,
            user_agent: profile.persona.user_agent.clone(),
            accept_language: profile.persona.accept_language.clone(),
            header_order: firefox_header_order(),
            send_dnt: profile.policy.do_not_track,
            http2: Http2Fingerprint::firefox(),
            profile_name: profile.name.clone(),
            camoufox_build: profile.camoufox_build.clone(),
        }
    }

    /// A short, stable label of the impersonation target for the status bar and
    /// audit log, e.g. `firefox/158`.
    pub fn target_label(&self) -> String {
        format!("{}/{}", self.family.as_str(), self.major_version)
    }
}

/// Firefox's characteristic request header order (lowercased canonical names;
/// casing applied by the backend). Verify against the pinned build.
fn firefox_header_order() -> Vec<String> {
    [
        "Host",
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Referer",
        "Content-Type",
        "Content-Length",
        "Origin",
        "Connection",
        "Cookie",
        "Upgrade-Insecure-Requests",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "Pragma",
        "Cache-Control",
        "TE",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Extract the Firefox major version from a UA string like
/// `...rv:158.0) Gecko/20100101 Firefox/158.0`.
fn parse_firefox_major(ua: &str) -> Option<u32> {
    let idx = ua.find("Firefox/")?;
    let rest = &ua[idx + "Firefox/".len()..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::FingerprintProfile;

    #[test]
    fn spec_is_derived_from_profile_identity() {
        let profile = FingerprintProfile::new("win-firefox-158-balanced", "158.0.1-beta.41");
        let spec = FingerprintSpec::from_profile(&profile);

        // The engine's UA/lang come from the same persona the browser uses.
        assert_eq!(spec.user_agent, profile.persona.user_agent);
        assert_eq!(spec.accept_language, profile.persona.accept_language);
        assert_eq!(spec.family, BrowserFamily::Firefox);
        assert_eq!(spec.major_version, 158);
        assert_eq!(spec.profile_name, "win-firefox-158-balanced");
        assert_eq!(spec.camoufox_build, "158.0.1-beta.41");
        assert_eq!(spec.target_label(), "firefox/158");
    }

    #[test]
    fn firefox_pseudo_header_order_matches_known_fingerprint() {
        let fp = Http2Fingerprint::firefox();
        assert_eq!(
            fp.pseudo_header_order,
            [":method", ":path", ":authority", ":scheme"]
        );
        // Distinct from Chrome's — the differentiating part of the H2 fingerprint.
        assert_ne!(
            fp.pseudo_header_order,
            Http2Fingerprint::chrome().pseudo_header_order
        );
    }

    #[test]
    fn major_version_parses_from_ua() {
        assert_eq!(
            parse_firefox_major(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"
            ),
            Some(135)
        );
        assert_eq!(parse_firefox_major("no firefox here"), None);
    }

    #[test]
    fn header_order_starts_with_host_and_user_agent() {
        let order = firefox_header_order();
        assert_eq!(order[0], "Host");
        assert_eq!(order[1], "User-Agent");
    }
}
