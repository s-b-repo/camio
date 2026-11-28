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
    /// 1366×768 — still one of the single most common laptop resolutions.
    pub const HD: ScreenSize = ScreenSize {
        width: 1366,
        height: 768,
        avail_height: 728,
        color_depth: 24,
    };
    /// 1536×864 — the common 125%-scaled FHD laptop panel.
    pub const HD_PLUS: ScreenSize = ScreenSize {
        width: 1536,
        height: 864,
        avail_height: 824,
        color_depth: 24,
    };
    /// 2560×1440 — common high-end desktop monitor.
    pub const QHD: ScreenSize = ScreenSize {
        width: 2560,
        height: 1440,
        avail_height: 1400,
        color_depth: 24,
    };
    /// 1440×900 — common macOS (default-scaled) logical resolution.
    pub const WXGA_PLUS: ScreenSize = ScreenSize {
        width: 1440,
        height: 900,
        avail_height: 875, // macOS menu bar, no taskbar
        color_depth: 24,
    };
    /// 1512×982 — the 14" MacBook Pro default logical resolution.
    pub const MBP14: ScreenSize = ScreenSize {
        width: 1512,
        height: 982,
        avail_height: 957,
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

/// The operating system a persona presents, mirroring Camoufox /
/// `camofox-browser`'s `CAMOFOX_OS`. The UA, `navigator.platform`, and WebGL
/// renderer must all agree — a Windows UA with a macOS platform is itself a tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserOs {
    Windows,
    Macos,
    Linux,
}

impl BrowserOs {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserOs::Windows => "windows",
            BrowserOs::Macos => "macos",
            BrowserOs::Linux => "linux",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" | "win32" | "win64" => Some(BrowserOs::Windows),
            "macos" | "mac" | "osx" | "darwin" | "macintel" => Some(BrowserOs::Macos),
            "linux" => Some(BrowserOs::Linux),
            _ => None,
        }
    }
}

impl Persona {
    /// A persona consistent with `os` (UA / `navigator.platform` / WebGL agree),
    /// keeping the common locale/timezone/screen defaults.
    pub fn for_os(os: BrowserOs) -> Self {
        match os {
            BrowserOs::Windows => Persona::windows(),
            BrowserOs::Macos => Persona::macos(),
            BrowserOs::Linux => Persona::linux(),
        }
    }

    /// The default common Windows 10 + Firefox persona.
    pub fn windows() -> Self {
        Persona::default()
    }

    /// A common macOS (Apple Silicon) + Firefox persona.
    pub fn macos() -> Self {
        let v = ALIGNED_FIREFOX_MAJOR;
        Persona {
            user_agent: format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
            ),
            platform: "MacIntel".to_string(),
            webgl_vendor: "Google Inc. (Apple)".to_string(),
            webgl_renderer:
                "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)".to_string(),
            ..Persona::default()
        }
    }

    /// A common Linux + Firefox persona (Mesa/Intel GPU strings).
    pub fn linux() -> Self {
        let v = ALIGNED_FIREFOX_MAJOR;
        Persona {
            user_agent: format!(
                "Mozilla/5.0 (X11; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
            ),
            platform: "Linux x86_64".to_string(),
            webgl_vendor: "Mesa".to_string(),
            webgl_renderer: "Mesa Intel(R) UHD Graphics (CML GT2)".to_string(),
            ..Persona::default()
        }
    }

    /// The OS this persona presents, inferred from `platform`.
    pub fn os(&self) -> BrowserOs {
        if self.platform.starts_with("Win") {
            BrowserOs::Windows
        } else if self.platform.starts_with("Mac") {
            BrowserOs::Macos
        } else {
            BrowserOs::Linux
        }
    }

    /// Build a **realistic, blend-in** Firefox persona, deterministic from
    /// `seed`.
    ///
    /// The anti-fingerprint philosophy here is "look like one of the many, not
    /// like a unique stealth build": every field is drawn from a curated
    /// [`DeviceProfile`] of real OS+GPU+hardware+screen combinations, so the
    /// result is a *plausible real machine* rather than an impossible mix of
    /// independently-random values (which is itself a detectable fingerprint).
    /// The Firefox version stays pinned to [`ALIGNED_FIREFOX_MAJOR`] so the UA
    /// cannot drift from the engine Camio actually drives — the variety is in
    /// the OS/device/screen/locale, exactly where real Firefox users vary.
    pub fn random(seed: u64) -> Self {
        let mut rng = crate::rng::SplitMix64::new(seed);
        Persona::random_with(&mut rng)
    }

    /// Like [`Persona::random`] but from a one-off, non-reproducible seed.
    pub fn random_from_entropy() -> Self {
        let mut rng = crate::rng::SplitMix64::from_entropy();
        Persona::random_with(&mut rng)
    }

    /// Generate `n` personas from consecutive sub-seeds of `seed`. Useful for a
    /// rotation pool where each session gets a distinct-but-reproducible
    /// identity.
    pub fn random_pool(seed: u64, n: usize) -> Vec<Self> {
        (0..n as u64).map(|i| Persona::random(seed ^ i.wrapping_mul(0x9E37_79B9))).collect()
    }

    fn random_with(rng: &mut crate::rng::SplitMix64) -> Self {
        let weights: Vec<u32> = DEVICE_PROFILES.iter().map(|d| d.weight).collect();
        let profile = &DEVICE_PROFILES[rng.weighted_index(&weights)];
        let screen = *rng.choose(profile.screens).unwrap_or(&ScreenSize::FHD);
        let cores = *rng.choose(profile.cores).unwrap_or(&8);
        let memory = *rng.choose(profile.memory).unwrap_or(&8);
        let (locale, accept_language, timezone) = {
            let l = rng.choose(LOCALE_POOL).copied().unwrap_or(LOCALE_POOL[0]);
            (l.0.to_string(), l.1.to_string(), l.2.to_string())
        };
        let v = ALIGNED_FIREFOX_MAJOR;
        let user_agent = match profile.os {
            BrowserOs::Windows => format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
            ),
            BrowserOs::Macos => format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
            ),
            BrowserOs::Linux => {
                format!("Mozilla/5.0 (X11; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0")
            }
        };
        Persona {
            user_agent,
            platform: profile.platform.to_string(),
            accept_language,
            locale,
            timezone,
            screen,
            webgl_vendor: profile.webgl_vendor.to_string(),
            webgl_renderer: profile.webgl_renderer.to_string(),
            hardware_concurrency: cores,
            device_memory: memory,
        }
    }
}

/// A curated real-device profile: a coherent OS + GPU + hardware + screen
/// bundle. Random personas are assembled only from these so every generated
/// identity is internally consistent (a Windows UA always pairs with a Windows
/// platform string and a GPU/driver combo that ships on Windows, etc.).
struct DeviceProfile {
    os: BrowserOs,
    platform: &'static str,
    webgl_vendor: &'static str,
    webgl_renderer: &'static str,
    /// Plausible `navigator.hardwareConcurrency` values for this class of
    /// machine. Correlated with the device so a low-end laptop doesn't claim 32
    /// cores.
    cores: &'static [u32],
    /// Plausible `navigator.deviceMemory` values (GiB; browsers clamp to powers
    /// of two in 0.25..=8).
    memory: &'static [u32],
    /// Screen resolutions this class of machine commonly ships with.
    screens: &'static [ScreenSize],
    /// Relative real-world frequency weight (Windows desktops dominate; Linux is
    /// rare on the general web but common among the technical users Camio runs
    /// alongside, so it is present but low-weighted).
    weight: u32,
}

/// Common (locale, Accept-Language, IANA timezone) triples, internally
/// consistent and weighted toward the largest anonymity set (en-US). A random
/// persona picks one whole triple so the three fields can never disagree.
static LOCALE_POOL: &[(&str, &str, &str)] = &[
    ("en-US", "en-US,en;q=0.5", "America/New_York"),
    ("en-US", "en-US,en;q=0.5", "America/Chicago"),
    ("en-US", "en-US,en;q=0.5", "America/Los_Angeles"),
    ("en-GB", "en-GB,en;q=0.5", "Europe/London"),
    ("en-CA", "en-CA,en;q=0.7,fr-CA;q=0.3", "America/Toronto"),
    ("en-AU", "en-AU,en;q=0.5", "Australia/Sydney"),
];

/// The curated device-profile table. GPU renderer strings are real ANGLE/Mesa
/// strings that ship on the matching OS; keep them current when the aligned
/// Firefox/Camoufox build moves.
static DEVICE_PROFILES: &[DeviceProfile] = &[
    // --- Windows desktops/laptops (the web-majority) --------------------------
    DeviceProfile {
        os: BrowserOs::Windows,
        platform: "Win32",
        webgl_vendor: "Google Inc. (NVIDIA)",
        webgl_renderer:
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        cores: &[8, 12, 16],
        memory: &[8],
        screens: &[ScreenSize::FHD, ScreenSize::QHD, ScreenSize::HD_PLUS],
        weight: 180,
    },
    DeviceProfile {
        os: BrowserOs::Windows,
        platform: "Win32",
        webgl_vendor: "Google Inc. (Intel)",
        webgl_renderer:
            "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        cores: &[4, 8],
        // deviceMemory is browser-clamped to ≤ 8; a budget Intel laptop commonly
        // reports 4 or 8. Never emit a value a real browser couldn't report.
        memory: &[4, 8],
        screens: &[ScreenSize::HD, ScreenSize::FHD, ScreenSize::HD_PLUS],
        weight: 140,
    },
    DeviceProfile {
        os: BrowserOs::Windows,
        platform: "Win32",
        webgl_vendor: "Google Inc. (AMD)",
        webgl_renderer:
            "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        cores: &[6, 8, 12],
        memory: &[8],
        screens: &[ScreenSize::FHD, ScreenSize::QHD],
        weight: 70,
    },
    // --- macOS (Apple Silicon + Intel) ---------------------------------------
    DeviceProfile {
        os: BrowserOs::Macos,
        platform: "MacIntel",
        webgl_vendor: "Google Inc. (Apple)",
        webgl_renderer: "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
        cores: &[8, 10],
        memory: &[8],
        screens: &[ScreenSize::MBP14, ScreenSize::WXGA_PLUS, ScreenSize::FHD],
        weight: 90,
    },
    DeviceProfile {
        os: BrowserOs::Macos,
        platform: "MacIntel",
        webgl_vendor: "Google Inc. (Apple)",
        webgl_renderer: "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
        cores: &[8],
        memory: &[8],
        screens: &[ScreenSize::WXGA_PLUS, ScreenSize::FHD],
        weight: 60,
    },
    // --- Linux (rarer on the general web, common among Camio's users) ---------
    DeviceProfile {
        os: BrowserOs::Linux,
        platform: "Linux x86_64",
        webgl_vendor: "Mesa",
        webgl_renderer: "Mesa Intel(R) UHD Graphics (CML GT2)",
        cores: &[4, 8, 12],
        memory: &[4, 8],
        screens: &[ScreenSize::FHD, ScreenSize::HD, ScreenSize::QHD],
        weight: 30,
    },
];

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

/// Canvas fingerprinting defense. A tracker reads a hidden `<canvas>` back
/// as pixels and hashes them — the hash becomes a stable device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanvasMode {
    /// Leave canvas readback untouched (plain Firefox).
    Allow,
    /// Prompt on every readback. Overt, breaks some sites — useful for audit,
    /// not for stealth.
    Prompt,
    /// Return a per-session, per-origin **randomized** readback (Camoufox
    /// patched behaviour under `privacy.resistFingerprinting`). Each site sees
    /// a stable-looking canvas that doesn't match any other operator's.
    Randomize,
    /// Block the readback API entirely by returning empty data.
    Block,
}

/// AudioContext fingerprinting defense. `OfflineAudioContext`'s DSP output is
/// device-specific; a sub-millisecond noise injection breaks the hash without
/// affecting audio playback itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioMode {
    /// Plain AudioContext.
    Allow,
    /// Add sub-perceptual noise to `AudioContext` output (Camoufox patch /
    /// RFP behaviour). The noise is seeded per session so a single tracker
    /// cannot average it out across page loads in that session.
    Noise,
    /// Disable WebAudio (`dom.webaudio.enabled = false`). Overt, but safe when
    /// the target site has no audio.
    Disabled,
}

/// Font enumeration exposure. The exact list of installed fonts is one of the
/// top-5 distinguishers in modern fingerprinting (EFF Panopticlick dataset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FontMode {
    /// Expose the real OS font list.
    System,
    /// Restrict the **system** fonts pages can see/probe to a common bundled
    /// set via `font.system.whitelist` (Camoufox / Tor Browser approach),
    /// collapsing font-enumeration entropy.
    BundledOnly,
}

/// HTTP `Sec-CH-UA` / `User-Agent Client Hints` behaviour. Chromium sites
/// increasingly pin fingerprints off these; a Firefox persona should NOT
/// advertise them (that's a tell in itself), and a Chrome persona must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientHintsMode {
    /// Do not send Sec-CH-UA headers (Firefox default). The right choice for
    /// a Firefox persona.
    Off,
    /// Send only the low-entropy hints a site asks for. Only useful for a
    /// Chrome persona; harmless for Firefox.
    LowEntropyOnly,
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

    // -- Extended stealth (plan §6.1 "match the matched engine, harder to
    // detect"). Each toggle emits a specific `about:config` pref below and is
    // independent of the omnibus RFP flag so an operator can opt into one
    // defense without taking the full RFP hit on compatibility. -------------
    /// Canvas readback fingerprinting defense.
    pub canvas: CanvasMode,
    /// AudioContext fingerprinting defense.
    pub audio: AudioMode,
    /// Font enumeration defense.
    pub fonts: FontMode,
    /// `Sec-CH-UA` client-hints behaviour.
    pub client_hints: ClientHintsMode,
    /// Disable `speechSynthesis`, which exposes the exact OS voice list — a
    /// near-unique fingerprint on macOS and some Linux distros.
    pub disable_speech_synthesis: bool,
    /// Disable the Battery Status API. Deprecated but still exposed by
    /// Firefox when not explicitly turned off; a straight fingerprint vector.
    pub disable_battery_api: bool,
    /// Disable the Keyboard Layout API (`navigator.keyboard`), which reveals
    /// the OS keyboard layout — a strong locale/OS tell.
    pub disable_keyboard_api: bool,
    /// Disable `navigator.getGamepads()` — silently probed by some trackers.
    pub disable_gamepad_api: bool,
    /// Add sub-millisecond jitter to `performance.now()` and `Date.now()` so
    /// a tracker cannot use timing resolution itself as an entropy source.
    /// Firefox's `privacy.reduceTimerPrecision` tamper-resistant default.
    pub reduce_timer_precision: bool,
    /// `network.http.referer.XOriginPolicy = 2` — only send the `Referer`
    /// header cross-origin when the full host matches, i.e. drop it on true
    /// cross-site requests even when the referrer policy would allow it.
    pub strip_cross_origin_referer: bool,
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
            canvas: CanvasMode::Randomize,
            audio: AudioMode::Noise,
            fonts: FontMode::BundledOnly,
            client_hints: ClientHintsMode::Off,
            disable_speech_synthesis: true,
            disable_battery_api: true,
            disable_keyboard_api: true,
            disable_gamepad_api: true,
            reduce_timer_precision: true,
            strip_cross_origin_referer: true,
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
            canvas: CanvasMode::Randomize,
            audio: AudioMode::Noise,
            fonts: FontMode::BundledOnly,
            client_hints: ClientHintsMode::Off,
            disable_speech_synthesis: true,
            disable_battery_api: true,
            // Off in balanced: disabling KeyboardEvent.code can break
            // keyboard-heavy web apps. `hardened` turns it on.
            disable_keyboard_api: false,
            disable_gamepad_api: true,
            reduce_timer_precision: true,
            strip_cross_origin_referer: false,
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
            canvas: CanvasMode::Allow,
            audio: AudioMode::Allow,
            fonts: FontMode::System,
            client_hints: ClientHintsMode::Off,
            disable_speech_synthesis: false,
            disable_battery_api: false,
            disable_keyboard_api: false,
            disable_gamepad_api: false,
            reduce_timer_precision: false,
            strip_cross_origin_referer: false,
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
        // Canvas and AudioContext defenses in Firefox only work with RFP on, so
        // the effective RFP state is the omnibus flag OR a selected canvas/audio
        // mode that needs it. Computing it once here (rather than re-setting the
        // pref inside the canvas arm) keeps `privacy.resistFingerprinting` to a
        // single, correct line instead of a `false` then `true` duplicate.
        let canvas_needs_rfp = !matches!(p.canvas, CanvasMode::Allow);
        let audio_needs_rfp = matches!(p.audio, AudioMode::Noise);
        let rfp_on = p.resist_fingerprinting || canvas_needs_rfp || audio_needs_rfp;
        set("privacy.resistFingerprinting", PrefValue::Bool(rfp_on));
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
            // `spoof_english = 2` forces navigator.language / Accept-Language to
            // en-US. That is right ONLY for an English persona; forcing it for a
            // non-English persona (e.g. `de-DE`) would contradict the persona's
            // own locale and be a tell. Emit it only when the persona is English.
            if persona.locale.to_ascii_lowercase().starts_with("en") {
                set("privacy.spoof_english", PrefValue::Int(2));
            }
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
        // `dom.webdriver.enabled = false` makes `navigator.webdriver` report
        // false even while Marionette is connected — the pref-level half of the
        // fix; Camoufox's C++ patch closes the rest. (The old second line here,
        // `useAutomationExtension`, was a Selenium/ChromeDriver capability, NOT
        // a Firefox pref: in a user.js it just created an orphan pref Firefox
        // ignores, so it is dropped rather than shipped as dead config.)
        if p.hide_automation {
            set("dom.webdriver.enabled", PrefValue::Bool(false));
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

        // --- Extra anti-fingerprinting surface (Camoufox-aligned) ------------
        // When fingerprint resistance is on, close vectors RFP does not fully
        // cover and that match what the Camoufox engine patches below: the
        // Battery, Geolocation, Network Information and Gamepad APIs, plus
        // speculative network activity that can deanonymize.
        if p.resist_fingerprinting {
            set("dom.battery.enabled", PrefValue::Bool(false));
            set("geo.enabled", PrefValue::Bool(false));
            set("geo.provider.network.url", PrefValue::Str(String::new()));
            set("dom.netinfo.enabled", PrefValue::Bool(false));
            set("dom.gamepad.enabled", PrefValue::Bool(false));
            set("beacon.enabled", PrefValue::Bool(false));
            set("network.dns.disablePrefetch", PrefValue::Bool(true));
            set("network.predictor.enabled", PrefValue::Bool(false));
            // Don't expose the real GPU via WEBGL_debug_renderer_info even when
            // WebGL itself stays enabled.
            set("webgl.enable-debug-renderer-info", PrefValue::Bool(false));
        }

        // --- Canvas readback --------------------------------------------------
        // RFP was forced on above when a non-Allow canvas mode is selected. With
        // RFP on, `toDataURL`/`getImageData` return either randomized pixels or,
        // for non-user-initiated reads, a declined (blank) result — governed by
        // `autoDeclineNoUserInputCanvasPrompts`. There is no separate pref that
        // "blocks" readback; the modes differ only in that toggle, and the
        // per-origin randomization is RFP's (and Camoufox's engine layer's)
        // behaviour, not a pref we can name.
        match p.canvas {
            CanvasMode::Allow => {}
            // Prompt and Randomize both allow the read and let RFP return
            // randomized pixels (do NOT auto-decline, or the script gets a blank
            // canvas instead of a plausible-but-unique one). They differ only in
            // intent: Prompt surfaces the permission UI in interactive use.
            CanvasMode::Prompt | CanvasMode::Randomize => {
                set(
                    "privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts",
                    PrefValue::Bool(false),
                );
            }
            CanvasMode::Block => {
                // Auto-decline non-user-initiated readback → the script gets a
                // blank canvas. This is the closest Firefox gets to a hard block.
                set(
                    "privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts",
                    PrefValue::Bool(true),
                );
            }
        }

        // --- AudioContext -----------------------------------------------------
        match p.audio {
            AudioMode::Allow => {}
            AudioMode::Noise => {
                // The actual AudioContext noise comes from RFP (forced on above)
                // and Camoufox's engine patch; this pref just keeps WebAudio
                // reachable so that noise path runs rather than the API being off.
                set("dom.webaudio.enabled", PrefValue::Bool(true));
            }
            AudioMode::Disabled => {
                set("dom.webaudio.enabled", PrefValue::Bool(false));
            }
        }

        // --- Fonts ------------------------------------------------------------
        match p.fonts {
            FontMode::System => {}
            FontMode::BundledOnly => {
                // The real restriction is `font.system.whitelist`: it limits
                // which *system* fonts pages can see/probe, collapsing font-
                // enumeration entropy. (`browser.display.use_document_fonts`
                // is deliberately NOT set — 1 is the permissive default and 0
                // would also block legit web/icon fonts, breaking rendering.)
                set(
                    "font.system.whitelist",
                    PrefValue::Str(String::from(
                        "Arial,Arial Black,Comic Sans MS,Courier New,Georgia,Impact,Palatino Linotype,Tahoma,Times New Roman,Trebuchet MS,Verdana",
                    )),
                );
            }
        }

        // --- Client Hints -----------------------------------------------------
        // Firefox does not implement UA Client Hints (`Sec-CH-UA*` request
        // headers / `navigator.userAgentData`) at all, so for a Firefox persona
        // there is nothing to disable — advertising them would itself be a tell.
        // `Off` is therefore a deliberate no-op rather than a pref that would be
        // orphaned (Firefox would just store an unknown pref with no effect).
        // The field is retained for a future Chrome persona, where
        // `LowEntropyOnly` would gate which hints are emitted.
        match p.client_hints {
            ClientHintsMode::Off => {}
            ClientHintsMode::LowEntropyOnly => {}
        }

        // --- Additional per-API opt-outs (independent of omnibus RFP) --------
        if p.disable_speech_synthesis {
            set("media.webspeech.synth.enabled", PrefValue::Bool(false));
        }
        if p.disable_battery_api {
            set("dom.battery.enabled", PrefValue::Bool(false));
        }
        if p.disable_keyboard_api {
            // Firefox does not implement the `navigator.keyboard` Keyboard-Map
            // API, so the real keyboard-layout fingerprint vector is
            // `KeyboardEvent.code` (physical key → layout). Turning it OFF hides
            // that (RFP also spoofs key events). This can affect keyboard-heavy
            // web apps, which is why only the `hardened` preset enables it.
            set("dom.keyboardevent.code.enabled", PrefValue::Bool(false));
        }
        if p.disable_gamepad_api {
            set("dom.gamepad.enabled", PrefValue::Bool(false));
        }
        if p.reduce_timer_precision {
            set("privacy.reduceTimerPrecision", PrefValue::Bool(true));
            set(
                "privacy.resistFingerprinting.reduceTimerPrecision.jitter",
                PrefValue::Bool(true),
            );
            // 2ms resolution + jitter: the Tor Browser default. Makes
            // high-resolution timing attacks (SharedArrayBuffer side channels,
            // GPU timing, hardware probing) materially harder.
            set(
                "privacy.resistFingerprinting.reduceTimerPrecision.microseconds",
                PrefValue::Int(2000),
            );
        }
        if p.strip_cross_origin_referer {
            set("network.http.referer.XOriginPolicy", PrefValue::Int(2));
        }

        prefs
    }

    /// Render the profile to a Firefox `user.js` file body.
    pub fn to_user_js(&self) -> String {
        // Written with `push_str`/`format!` rather than `writeln!`: appending to
        // a String cannot fail, and asserting otherwise per line only added a
        // place for a panic to live.
        let mut out = String::new();
        out.push_str("// Generated by Camio — do not edit by hand.\n");
        out.push_str(&format!(
            "// Profile: {} (Camoufox {})\n",
            self.name, self.camoufox_build
        ));
        out.push_str("// Fingerprint policy rendered to about:config preferences.\n\n");
        for (k, v) in self.to_prefs() {
            out.push_str(&format!(
                "user_pref({}, {});\n",
                PrefValue::Str(k).render(),
                v.render()
            ));
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
    fn os_personas_are_internally_consistent() {
        let mac = Persona::macos();
        assert_eq!(mac.platform, "MacIntel");
        assert!(mac.user_agent.contains("Mac OS X"));
        assert_eq!(mac.os(), BrowserOs::Macos);

        let lin = Persona::for_os(BrowserOs::Linux);
        assert_eq!(lin.platform, "Linux x86_64");
        assert!(lin.user_agent.contains("X11; Linux"));
        assert_eq!(lin.os(), BrowserOs::Linux);

        assert_eq!(Persona::windows().os(), BrowserOs::Windows);
        assert_eq!(BrowserOs::parse("mac"), Some(BrowserOs::Macos));
        assert_eq!(BrowserOs::parse("nope"), None);
    }

    #[test]
    fn random_persona_is_deterministic_and_consistent() {
        let a = Persona::random(12345);
        let b = Persona::random(12345);
        assert_eq!(a, b, "random(seed) must be reproducible");

        // Across many seeds, every generated persona must be internally
        // consistent: UA OS token ↔ platform ↔ WebGL vendor family all agree,
        // the Firefox version is the aligned one, and Accept-Language starts
        // with the locale.
        for seed in 0..200u64 {
            let p = Persona::random(seed);
            assert!(
                p.user_agent
                    .contains(&format!("Firefox/{ALIGNED_FIREFOX_MAJOR}.0")),
                "version drift: {}",
                p.user_agent
            );
            match p.os() {
                BrowserOs::Windows => {
                    assert_eq!(p.platform, "Win32");
                    assert!(p.user_agent.contains("Windows NT"));
                }
                BrowserOs::Macos => {
                    assert_eq!(p.platform, "MacIntel");
                    assert!(p.user_agent.contains("Mac OS X"));
                    assert!(p.webgl_renderer.contains("Apple"));
                }
                BrowserOs::Linux => {
                    assert_eq!(p.platform, "Linux x86_64");
                    assert!(p.user_agent.contains("X11; Linux"));
                }
            }
            assert!(
                p.accept_language.starts_with(&p.locale),
                "accept-language {} vs locale {}",
                p.accept_language,
                p.locale
            );
            // Hardware is from the plausible, correlated ranges — never absurd.
            // deviceMemory stays within the browser-clamped ceiling of 8 so a
            // real browser could actually report it.
            assert!(p.hardware_concurrency >= 4 && p.hardware_concurrency <= 16);
            assert!(p.device_memory >= 4 && p.device_memory <= 8);
            assert!(p.screen.width >= 1280 && p.screen.height >= 720);
            assert!(p.screen.avail_height <= p.screen.height);
        }
    }

    #[test]
    fn random_pool_returns_n_personas() {
        let pool = Persona::random_pool(999, 25);
        assert_eq!(pool.len(), 25);
        // The pool should contain more than one distinct OS over 25 draws
        // (otherwise the weighting/entropy is broken).
        let distinct_os: std::collections::HashSet<_> =
            pool.iter().map(|p| p.os()).collect();
        assert!(distinct_os.len() >= 2, "pool lacks OS variety");
    }

    #[test]
    fn hardened_prefs_close_extra_fingerprint_vectors() {
        let mut prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        prof.policy = FingerprintPolicy::hardened();
        let prefs = prof.to_prefs();
        let has = |k: &str| prefs.iter().any(|(key, _)| key == k);
        assert!(has("dom.battery.enabled"));
        assert!(has("geo.enabled"));
        assert!(has("dom.netinfo.enabled"));
        assert!(has("webgl.enable-debug-renderer-info"));
    }

    #[test]
    fn extended_stealth_prefs_land_on_hardened() {
        let mut prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        prof.policy = FingerprintPolicy::hardened();
        let prefs = prof.to_prefs();
        let find = |k: &str| prefs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        // Canvas / Audio / Fonts / timer / per-API blocks all land. Hardened
        // uses Randomize, so canvas readback is allowed-but-randomized
        // (auto-decline FALSE), not blanked — a blank canvas is itself a tell.
        assert_eq!(
            find("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts"),
            Some(PrefValue::Bool(false))
        );
        assert_eq!(
            find("privacy.resistFingerprinting"),
            Some(PrefValue::Bool(true))
        );
        assert_eq!(find("dom.webaudio.enabled"), Some(PrefValue::Bool(true)));
        assert!(find("font.system.whitelist").is_some());
        // use_document_fonts is deliberately NOT emitted (it's the permissive
        // default and would mislead).
        assert_eq!(find("browser.display.use_document_fonts"), None);
        assert_eq!(
            find("media.webspeech.synth.enabled"),
            Some(PrefValue::Bool(false))
        );
        // hardened disables the KeyboardEvent.code layout vector (the real one;
        // Firefox has no navigator.keyboard API to turn off).
        assert_eq!(
            find("dom.keyboardevent.code.enabled"),
            Some(PrefValue::Bool(false))
        );
        // The automation tell is hidden by a REAL pref; the old junk
        // `useAutomationExtension` capability is not emitted.
        assert_eq!(find("dom.webdriver.enabled"), Some(PrefValue::Bool(false)));
        assert_eq!(find("useAutomationExtension"), None);
        assert_eq!(
            find("privacy.reduceTimerPrecision"),
            Some(PrefValue::Bool(true))
        );
        assert_eq!(
            find("privacy.resistFingerprinting.reduceTimerPrecision.microseconds"),
            Some(PrefValue::Int(2000))
        );
        assert_eq!(
            find("network.http.referer.XOriginPolicy"),
            Some(PrefValue::Int(2))
        );
    }

    #[test]
    fn off_policy_omits_extended_stealth() {
        let mut prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        prof.policy = FingerprintPolicy::off();
        let prefs = prof.to_prefs();
        let find = |k: &str| prefs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(find("privacy.reduceTimerPrecision"), None);
        assert_eq!(find("media.webspeech.synth.enabled"), None);
        assert_eq!(find("font.system.whitelist"), None);
    }

    #[test]
    fn canvas_defense_forces_rfp_on_even_when_rfp_flag_is_off() {
        // A canvas defense selected while the omnibus RFP flag is off must still
        // turn RFP on (otherwise the canvas pref is a silent no-op), and must do
        // so exactly once — no duplicate pref lines.
        let mut prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        prof.policy = FingerprintPolicy::off(); // resist_fingerprinting = false
        prof.policy.canvas = CanvasMode::Randomize;
        let prefs = prof.to_prefs();
        let rfp: Vec<_> = prefs
            .iter()
            .filter(|(k, _)| k == "privacy.resistFingerprinting")
            .collect();
        // Exactly one line, and it is `true`.
        assert_eq!(rfp.len(), 1, "expected a single RFP pref, got {rfp:?}");
        assert_eq!(rfp[0].1, PrefValue::Bool(true));
        assert_eq!(
            prefs
                .iter()
                .find(|(k, _)| k == "privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts")
                .map(|(_, v)| v.clone()),
            Some(PrefValue::Bool(false))
        );
    }

    #[test]
    fn rfp_on_does_not_duplicate_the_rfp_pref_for_canvas() {
        // When resist_fingerprinting is already true, a canvas defense must not
        // emit a SECOND privacy.resistFingerprinting line.
        let mut prof = FingerprintProfile::new("t", "158.0.1-beta.41");
        prof.policy = FingerprintPolicy::hardened(); // RFP already on + canvas set
        let prefs = prof.to_prefs();
        let count = prefs
            .iter()
            .filter(|(k, _)| k == "privacy.resistFingerprinting")
            .count();
        assert_eq!(count, 1, "RFP pref must appear once, not duplicated");
    }

    #[test]
    fn spoof_english_only_for_english_personas() {
        // English persona → spoof_english emitted.
        let mut en = FingerprintProfile::new("en", "158.0.1-beta.41");
        en.policy = FingerprintPolicy::balanced();
        assert!(en
            .to_prefs()
            .iter()
            .any(|(k, _)| k == "privacy.spoof_english"));

        // German persona under the same policy → NOT emitted (it would
        // contradict the persona's own de-DE locale).
        let mut de = FingerprintProfile::new("de", "158.0.1-beta.41");
        de.policy = FingerprintPolicy::balanced();
        de.persona.locale = "de-DE".to_string();
        de.persona.accept_language = "de-DE,de;q=0.9".to_string();
        assert!(!de
            .to_prefs()
            .iter()
            .any(|(k, _)| k == "privacy.spoof_english"));
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
