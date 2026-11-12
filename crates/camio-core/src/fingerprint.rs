//! Fingerprint profiles and anti-detection policy for the managed Camoufox browser.
//!
//! This module is the concrete implementation of Camio plan §6 ("Fingerprint
//! transparency") and the user's request to "make Camoufox harder to detect and
//! implement Chameleon anti-fingerprinting features".
//!
//! # Why this is more powerful than the Chameleon extension
//!
//! Chameleon (the Firefox WebExtension by sereneblue, a Random Agent Spoofer
//! port) is limited: a WebExtension **cannot modify `about:config`**, so several
//! of its protections are best-effort content scripts. Camio drives *Camoufox*,
//! a Firefox fork we launch ourselves, so we can:
//!   1. Write real `about:config` preferences into the profile's `user.js`, and
//!   2. Pass engine-level fingerprint overrides to Camoufox (navigator/screen/
//!      WebGL/timezone/fonts), which are injected below the JS layer.
//!
//! A [`FingerprintProfile`] is a *persona* (stable identity values) plus a
//! *policy* (the anti-detection toggles). Per plan §6, ONE profile is shared by
//! the browser and the fingerprint-matched request engine so that their
//! JA3/JA4, HTTP/2, header-order and `navigator.*` fingerprints cannot diverge.
//!
//! ## Reliability note
//!
//! The `user.js` preference layer uses standard, documented Firefox prefs and is
//! the reliable path. The Camoufox engine-config key names
//! ([`FingerprintProfile::to_camoufox_config`]) follow Camoufox's dotted-path
//! override schema but MUST be validated against the pinned Camoufox build in
//! the Phase-0 feasibility spike (plan §15) before being relied upon.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// The Camoufox release this crate's defaults are aligned to. The persona's
/// Firefox version is kept in lock-step with this so a site cannot catch a
/// navigator/UA mismatch. Bump together with the pinned engine build.
pub const ALIGNED_FIREFOX_MAJOR: u32 = 158;

/// Screen geometry presented to the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenSize {
    pub width: u32,
    pub height: u32,
    /// Usable area height (minus OS taskbar); width usually equals `width`.
    pub avail_height: u32,
    pub color_depth: u8,
}

impl ScreenSize {
    pub const FHD: ScreenSize = ScreenSize {
        width: 1920,
        height: 1080,
        avail_height: 1040,
        color_depth: 24,
    };
}

/// A stable identity ("persona"): the values that make up navigator/screen/
/// WebGL/intl fingerprints. Keep these internally consistent — a Windows UA with
/// a macOS platform string is itself a tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persona {
    pub user_agent: String,
    /// `navigator.platform`, e.g. `Win32`, `MacIntel`, `Linux x86_64`.
    pub platform: String,
    /// Value for the `Accept-Language` header and `navigator.language`.
    pub accept_language: String,
    /// BCP-47 primary locale, e.g. `en-US`.
    pub locale: String,
    /// IANA timezone, e.g. `America/New_York`.
    pub timezone: String,
    pub screen: ScreenSize,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub hardware_concurrency: u32,
    /// `navigator.deviceMemory` in GiB (browsers clamp/round to 0.25..8).
    pub device_memory: u32,
}

impl Default for Persona {
    /// A deliberately *common* Windows 10 + Firefox persona: blending into a
    /// large anonymity set beats a unique "stealth" identity. The Firefox
    /// version tracks [`ALIGNED_FIREFOX_MAJOR`].
    fn default() -> Self {
        let ua = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
            v = ALIGNED_FIREFOX_MAJOR
        );
        Persona {
            user_agent: ua,
            platform: "Win32".to_string(),
            accept_language: "en-US,en;q=0.5".to_string(),
            locale: "en-US".to_string(),
            timezone: "America/New_York".to_string(),
            screen: ScreenSize::FHD,
            // Generic desktop GPU strings that are common and non-unique.
            webgl_vendor: "Google Inc. (NVIDIA)".to_string(),
            webgl_renderer:
                "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0, D3D11)"
                    .to_string(),
            hardware_concurrency: 8,
            device_memory: 8,
        }
    }
}

/// How WebRTC should be handled. WebRTC can leak the real local/public IP even
/// behind a proxy, so it is a classic de-anonymisation vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcMode {
    /// Leave WebRTC fully enabled (default Firefox behaviour).
    Enabled,
    /// Keep WebRTC working but prevent host/local-IP candidates from leaking.
    LeakProtected,
    /// Disable WebRTC entirely.
    Disabled,
}

/// Camera/microphone enumeration exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDeviceMode {
    Allow,
    /// Disable the media-device API so `enumerateDevices()` reveals nothing.
    Block,
}

/// Referer header behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefererPolicy {
    /// Firefox default.
    Default,
    /// Send only scheme+host+port (drop path/query) — Chameleon's trim option.
    TrimToOrigin,
    /// Never send a Referer header.
    Disabled,
}

/// WebGL exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebglMode {
    /// Report the persona's spoofed vendor/renderer (engine-level override).
    Spoof,
    /// Disable WebGL entirely (strongest, but itself somewhat distinctive).
    Disabled,
}

/// The anti-detection toggles. Field names mirror Chameleon's options where they
/// map cleanly; see each field's doc for the underlying Firefox pref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintPolicy {
    /// `privacy.resistFingerprinting` — Mozilla's omnibus RFP (canvas noise,
    /// timezone→persona, reduced font/screen entropy, keyboard/pointer, etc.).
    pub resist_fingerprinting: bool,
    /// `privacy.resistFingerprinting.letterboxing` — round inner window size to
    /// a fixed grid so viewport size is not a unique signal.
    pub letterboxing: bool,
    /// `privacy.firstPartyIsolation` — key all caches/storage by first party.
    pub first_party_isolation: bool,
    pub webrtc: WebRtcMode,
    pub media_devices: MediaDeviceMode,
    pub webgl: WebglMode,
    /// `privacy.trackingprotection.*` — enhanced tracking protection incl.
    /// fingerprinting and cryptomining lists.
    pub tracking_protection: bool,
    /// `privacy.donottrackheader.enabled`.
    pub do_not_track: bool,
    pub referer: RefererPolicy,
    /// `network.cookie.cookieBehavior` value (5 = reject trackers + partition).
    pub cookie_behavior: u8,
    /// Hide the automation tell `navigator.webdriver`
    /// (`dom.webdriver.enabled = false`) WITHOUT disabling the Marionette/BiDi
    /// control channel Camio needs. This is the key "harder to detect" fix for
    /// a programmatically driven browser (plan §6.1 / §18 risk row).
    pub hide_automation: bool,
    /// Silence Mozilla telemetry / normandy / health-report phone-homes so the
    /// profile does not look like a freshly-spawned automated instance.
    pub disable_telemetry: bool,
    /// `browser.sessionhistory.max_entries` — Chameleon's "limit tab history".
    pub limit_tab_history: Option<u32>,
}

impl FingerprintPolicy {
    /// Maximum protection. Some options (disabling WebGL, FPI) can *reduce*
    /// blending-in or break sites; use when stealth outweighs compatibility.
    pub fn hardened() -> Self {
        FingerprintPolicy {
            resist_fingerprinting: true,
            letterboxing: true,
            first_party_isolation: true,
            webrtc: WebRtcMode::Disabled,
            media_devices: MediaDeviceMode::Block,
            webgl: WebglMode::Spoof,
            tracking_protection: true,
            do_not_track: true,
            referer: RefererPolicy::TrimToOrigin,
            cookie_behavior: 5,
            hide_automation: true,
            disable_telemetry: true,
            limit_tab_history: Some(2),
        }
    }

    /// Strong protection that stays close to a normal Firefox user (best for
    /// authorized testing where the app must still work). The default.
    pub fn balanced() -> Self {
        FingerprintPolicy {
            resist_fingerprinting: true,
            letterboxing: false,
            first_party_isolation: false,
            webrtc: WebRtcMode::LeakProtected,
            media_devices: MediaDeviceMode::Allow,
            webgl: WebglMode::Spoof,
            tracking_protection: true,
            do_not_track: true,
            referer: RefererPolicy::Default,
            cookie_behavior: 5,
            hide_automation: true,
            disable_telemetry: true,
            limit_tab_history: None,
        }
    }

    /// No spoofing — a plain Firefox baseline, useful for measuring the delta.
    pub fn off() -> Self {
        FingerprintPolicy {
            resist_fingerprinting: false,
            letterboxing: false,
            first_party_isolation: false,
            webrtc: WebRtcMode::Enabled,
            media_devices: MediaDeviceMode::Allow,
            webgl: WebglMode::Spoof,
            tracking_protection: false,
            do_not_track: false,
            referer: RefererPolicy::Default,
            cookie_behavior: 0,
            hide_automation: false,
            disable_telemetry: false,
            limit_tab_history: None,
        }
    }
}

impl Default for FingerprintPolicy {
    fn default() -> Self {
        Self::balanced()
    }
}

/// A single `about:config` preference value.
#[derive(Debug, Clone, PartialEq)]
pub enum PrefValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

impl PrefValue {
    fn render(&self) -> String {
        match self {
            PrefValue::Bool(b) => b.to_string(),
            PrefValue::Int(i) => i.to_string(),
            // Firefox prefs use JSON-style string escaping.
            PrefValue::Str(s) => serde_json::Value::String(s.clone()).to_string(),
        }
    }
}

/// A complete, pinnable fingerprint identity: persona + policy, aligned to a
/// Camoufox build. This is the `FingerprintProfile` object in plan §13.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintProfile {
    /// Human-readable label, e.g. "win-firefox-158-hardened".
    pub name: String,
    /// The Camoufox release this profile is pinned to (e.g. "158.0.1-beta.41").
    pub camoufox_build: String,
    pub persona: Persona,
    pub policy: FingerprintPolicy,
}

impl FingerprintProfile {
    pub fn new(name: impl Into<String>, camoufox_build: impl Into<String>) -> Self {
        FingerprintProfile {
            name: name.into(),
            camoufox_build: camoufox_build.into(),
            persona: Persona::default(),
            policy: FingerprintPolicy::balanced(),
        }
    }

    /// Render the policy+persona to an ordered list of `about:config` prefs.
    pub fn to_prefs(&self) -> Vec<(String, PrefValue)> {
        let p = &self.policy;
        let persona = &self.persona;
        let mut prefs: Vec<(String, PrefValue)> = Vec::new();
        let mut set = |k: &str, v: PrefValue| prefs.push((k.to_string(), v));

        // --- Identity ---------------------------------------------------------
        set(
            "general.useragent.override",
            PrefValue::Str(persona.user_agent.clone()),
        );
        set(
            "intl.accept_languages",
            PrefValue::Str(persona.accept_language.clone()),
        );

        // --- Resist Fingerprinting (omnibus) ---------------------------------
        set(
            "privacy.resistFingerprinting",
            PrefValue::Bool(p.resist_fingerprinting),
        );
        set(
            "privacy.resistFingerprinting.letterboxing",
            PrefValue::Bool(p.letterboxing),
        );
        // Still allow our own UA override to take effect under RFP.
        if p.resist_fingerprinting {
            set(
                "privacy.resistFingerprinting.block_mozAddonManager",
                PrefValue::Bool(true),
            );
            set("privacy.spoof_english", PrefValue::Int(2));
        }

        // --- First-party isolation -------------------------------------------
        set(
            "privacy.firstPartyIsolation",
            PrefValue::Bool(p.first_party_isolation),
        );

        // --- WebRTC leak control ---------------------------------------------
        match p.webrtc {
            WebRtcMode::Enabled => {
                set("media.peerconnection.enabled", PrefValue::Bool(true));
            }
            WebRtcMode::LeakProtected => {
                set("media.peerconnection.enabled", PrefValue::Bool(true));
                set(
                    "media.peerconnection.ice.default_address_only",
                    PrefValue::Bool(true),
                );
                set("media.peerconnection.ice.no_host", PrefValue::Bool(true));
                set(
                    "media.peerconnection.ice.proxy_only_if_behind_proxy",
                    PrefValue::Bool(true),
                );
            }
            WebRtcMode::Disabled => {
                set("media.peerconnection.enabled", PrefValue::Bool(false));
            }
        }

        // --- Media devices ----------------------------------------------------
        match p.media_devices {
            MediaDeviceMode::Allow => {}
            MediaDeviceMode::Block => {
                set("media.navigator.enabled", PrefValue::Bool(false));
                set("media.navigator.permission.disabled", PrefValue::Bool(true));
            }
        }

        // --- WebGL ------------------------------------------------------------
        match p.webgl {
            WebglMode::Spoof => {} // handled via engine-level config
            WebglMode::Disabled => set("webgl.disabled", PrefValue::Bool(true)),
        }

        // --- Tracking protection ---------------------------------------------
        set(
            "privacy.trackingprotection.enabled",
            PrefValue::Bool(p.tracking_protection),
        );
        set(
            "privacy.trackingprotection.fingerprinting.enabled",
            PrefValue::Bool(p.tracking_protection),
        );
        set(
            "privacy.trackingprotection.cryptomining.enabled",
            PrefValue::Bool(p.tracking_protection),
        );
        set(
            "privacy.trackingprotection.socialtracking.enabled",
            PrefValue::Bool(p.tracking_protection),
        );

        // --- Do Not Track -----------------------------------------------------
        set(
            "privacy.donottrackheader.enabled",
            PrefValue::Bool(p.do_not_track),
        );

        // --- Referer ----------------------------------------------------------
        match p.referer {
            RefererPolicy::Default => {}
            RefererPolicy::TrimToOrigin => {
                // 2 = send scheme+host+port only.
                set("network.http.referer.trimmingPolicy", PrefValue::Int(2));
                set(
                    "network.http.referer.XOriginTrimmingPolicy",
                    PrefValue::Int(2),
                );
            }
            RefererPolicy::Disabled => {
                set("network.http.sendRefererHeader", PrefValue::Int(0));
            }
        }

        // --- Cookies ----------------------------------------------------------
        set(
            "network.cookie.cookieBehavior",
            PrefValue::Int(p.cookie_behavior as i64),
        );

        // --- Hide automation tell (keep control channel working) -------------
        if p.hide_automation {
            set("dom.webdriver.enabled", PrefValue::Bool(false));
            set("useAutomationExtension", PrefValue::Bool(false));
        }

        // --- Telemetry / phone-home silence ----------------------------------
        if p.disable_telemetry {
            for k in [
                "toolkit.telemetry.enabled",
                "toolkit.telemetry.unified",
                "datareporting.healthreport.uploadEnabled",
                "datareporting.policy.dataSubmissionEnabled",
                "app.normandy.enabled",
                "app.shield.optoutstudies.enabled",
                "browser.discovery.enabled",
                "network.connectivity-service.enabled",
                "network.captive-portal-service.enabled",
            ] {
                set(k, PrefValue::Bool(false));
            }
        }

        // --- Tab history ------------------------------------------------------
        if let Some(n) = p.limit_tab_history {
            set(
                "browser.sessionhistory.max_entries",
                PrefValue::Int(n as i64),
            );
        }

        prefs
    }

    /// Render the profile to a Firefox `user.js` file body.
    pub fn to_user_js(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "// Generated by Camio — do not edit by hand.");
        let _ = writeln!(
            out,
            "// Profile: {} (Camoufox {})",
            self.name, self.camoufox_build
        );
        let _ = writeln!(
            out,
            "// Fingerprint policy rendered to about:config preferences.\n"
        );
        for (k, v) in self.to_prefs() {
            let _ = writeln!(
                out,
                "user_pref({}, {});",
                PrefValue::Str(k).render(),
                v.render()
            );
        }
        out
    }

    /// Render engine-level fingerprint overrides for Camoufox (navigator/screen/
    /// WebGL/timezone). Uses Camoufox's dotted-path override schema.
    ///
    /// NOTE: key names follow Camoufox's documented config format but must be
    /// verified against the pinned build in the Phase-0 spike (plan §15).
    pub fn to_camoufox_config(&self) -> serde_json::Value {
        let persona = &self.persona;
        let mut cfg = serde_json::Map::new();
        let mut put = |k: &str, v: serde_json::Value| {
            cfg.insert(k.to_string(), v);
        };

        put("navigator.userAgent", persona.user_agent.clone().into());
        put("navigator.platform", persona.platform.clone().into());
        put("navigator.language", persona.locale.clone().into());
        put(
            "navigator.languages",
            serde_json::json!([persona.locale, "en"]),
        );
        put(
            "navigator.hardwareConcurrency",
            persona.hardware_concurrency.into(),
        );
        put("navigator.deviceMemory", persona.device_memory.into());
        put("screen.width", persona.screen.width.into());
        put("screen.height", persona.screen.height.into());
        put("screen.availWidth", persona.screen.width.into());
        put("screen.availHeight", persona.screen.avail_height.into());
        put("screen.colorDepth", persona.screen.color_depth.into());
        put("timezone", persona.timezone.clone().into());
        put("locale:language", persona.locale.clone().into());

        if matches!(self.policy.webgl, WebglMode::Spoof) {
            put("webGl:vendor", persona.webgl_vendor.clone().into());
            put("webGl:renderer", persona.webgl_renderer.clone().into());
            put("webGl:unmaskedVendor", persona.webgl_vendor.clone().into());
            put(
                "webGl:unmaskedRenderer",
                persona.webgl_renderer.clone().into(),
            );
        }

        serde_json::Value::Object(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_version_tracks_aligned_firefox() {
        let p = Persona::default();
        assert!(p
            .user_agent
            .contains(&format!("Firefox/{}.0", ALIGNED_FIREFOX_MAJOR)));
        assert!(p
            .user_agent
            .contains(&format!("rv:{}.0", ALIGNED_FIREFOX_MAJOR)));
    }

    #[test]
    fn hardened_disables_webrtc_and_hides_webdriver() {
        let prof = FingerprintProfile {
            name: "t".into(),
            camoufox_build: "158.0.1-beta.41".into(),
            persona: Persona::default(),
            policy: FingerprintPolicy::hardened(),
        };
        let prefs = prof.to_prefs();
        let find = |k: &str| {
            prefs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };

        assert_eq!(
            find("media.peerconnection.enabled"),
            Some(PrefValue::Bool(false))
        );
        assert_eq!(find("dom.webdriver.enabled"), Some(PrefValue::Bool(false)));
        assert_eq!(
            find("privacy.resistFingerprinting"),
            Some(PrefValue::Bool(true))
        );
    }

    #[test]
    fn balanced_protects_webrtc_without_disabling() {
        let prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        let prefs = prof.to_prefs();
        let has = |k: &str| prefs.iter().any(|(key, _)| key == k);
        assert!(has("media.peerconnection.ice.default_address_only"));
        // Balanced keeps webdriver hidden (we drive it programmatically).
        assert!(has("dom.webdriver.enabled"));
    }

    #[test]
    fn user_js_is_wellformed_pref_lines() {
        let prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        let js = prof.to_user_js();
        for line in js.lines().filter(|l| l.starts_with("user_pref(")) {
            assert!(line.ends_with(");"), "bad pref line: {line}");
            assert!(line.contains(", "), "pref line missing value: {line}");
        }
    }

    #[test]
    fn camoufox_config_carries_persona() {
        let prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        let cfg = prof.to_camoufox_config();
        assert_eq!(cfg["navigator.platform"], serde_json::json!("Win32"));
        assert_eq!(cfg["timezone"], serde_json::json!("America/New_York"));
        assert!(cfg.get("webGl:renderer").is_some());
    }

    #[test]
    fn profile_roundtrips_json() {
        let prof = FingerprintProfile::new("win-firefox-158", "158.0.1-beta.41");
        let s = serde_json::to_string(&prof).unwrap();
        let back: FingerprintProfile = serde_json::from_str(&s).unwrap();
        assert_eq!(prof, back);
    }
}
