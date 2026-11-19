# Camio — anti-fingerprinting / stealth reference

How Camio presents a non-detectable browser identity, which Camoufox features it
covers, and the honest gaps. This is a reference, not a promise of
undetectability — Camio **measures** parity and never claims invisibility
(plan §6.3).

## The engine, and what "stealth" means here

Camio is built on the **Camoufox** engine — a Firefox fork that spoofs
fingerprint surfaces (navigator, screen, WebGL, AudioContext, WebRTC, …) at the
**C++ level, before JavaScript ever sees them**. `jo-inc/camofox-browser` is a
REST API server that *wraps* that same engine for agents; it is not a separate
browser, and its `CAMOFOX_OS` / `CAMOFOX_LOCALE` / `CAMOFOX_TIMEZONE` knobs map
onto Camio's persona (see [OS personas](#os-personas)).

Camio's own contribution is **fingerprint transparency**: the managed browser and
the tool's request engine (`camio-request`, BoringSSL impersonation) carry the
*same* identity, so tool traffic doesn't add a second, mismatched fingerprint on
top of the browser's.

## Two configuration layers

A profile ([`camio_core::fingerprint`](../crates/camio-core/src/fingerprint.rs))
is rendered to two layers that the launcher applies together
([`camio-app/src/browser.rs`](../crates/camio-app/src/browser.rs)):

| Layer | Produced by | Applies to | Covers |
|---|---|---|---|
| **`user.js` prefs** | `FingerprintProfile::to_user_js()` | **any** Firefox-family binary (LibreWolf, Camoufox, Firefox) | `about:config`: RFP, UA/locale, WebRTC, WebGL, tracking/telemetry, and the extra API lockdowns below |
| **Engine config** | `to_camoufox_config()` | **Camoufox only** (ignored by plain LibreWolf) | C++-level `navigator`/screen/WebGL/timezone injection below the JS layer |

So **LibreWolf** gets strong *pref-level* stealth (RFP + Camio's lockdowns), and
**Camoufox** additionally gets the *C++-level* spoofing that pref-level config
can't reach. LibreWolf is the launcher's **preferred** binary
(`CANDIDATES = ["librewolf", "camoufox", "camoufox-bin", "firefox"]`).

## OS personas

`--os windows|macos|linux` (CLI `fingerprint show`, `launch`; `BrowserOs` in the
API) selects a persona whose **UA, `navigator.platform`, and WebGL renderer are
internally consistent** — a Windows UA with a macOS platform is itself a tell.
The persona flows into *both* layers, so the browser and the tool engine agree.
This is the equivalent of camofox-browser's `CAMOFOX_OS`.

## Feature coverage vs. Camoufox

| Surface | Camoufox | Camio coverage | How |
|---|---|---|---|
| navigator (UA, platform, language, hardwareConcurrency, deviceMemory) | ✓ | ✓ | persona → user.js + engine config |
| screen / window geometry | ✓ | ✓ | persona `ScreenSize` → both layers (RFP also reduces entropy) |
| WebGL vendor/renderer | ✓ | ✓ | persona → engine config; `WEBGL_debug_renderer_info` disabled in user.js |
| WebRTC IP leak | ✓ | ✓ | `WebRtcMode` (leak-protected / disabled) prefs |
| timezone / locale | ✓ | ✓ | persona → both layers; RFP ties timezone to persona |
| canvas noise | ✓ | ✓ (via RFP) | `privacy.resistFingerprinting` |
| Battery API | ✓ | ✓ | `dom.battery.enabled=false` under RFP |
| Geolocation | ✓ | ✓ | `geo.enabled=false`, empty provider URL under RFP |
| Network Information / Gamepad APIs | — | ✓ | disabled under RFP |
| media devices (enumerate) | ✓ | ✓ | `MediaDeviceMode::Block` |
| `navigator.webdriver` automation tell | ✓ | ✓ | `dom.webdriver.enabled=false` |
| fonts (bundled per-OS, metric jitter) | ✓ (C++) | partial | font *selection* follows the OS persona; bundled fonts + letter-spacing jitter need the Camoufox binary |
| AudioContext, speech voices, human cursor, JS-sandbox/frame-leak | ✓ (C++) | via Camoufox binary | these are engine-level and ride the Camoufox build; not reproducible at the LibreWolf pref layer |

## Honest limits

- **Pref-level ≠ C++-level.** On a plain **LibreWolf** binary, the surfaces marked
  "via Camoufox binary" above are **not** spoofed — only Camoufox's patched build
  provides them. Use the Camoufox binary when you need those; use LibreWolf for
  RFP-grade pref stealth.
- **Camio does not compile a browser.** "Merging Camoufox into LibreWolf" would
  mean rebuilding a patched Firefox fork; Camio instead *drives* an existing
  Camoufox or LibreWolf binary and applies the config above.
- **Parity is measured, not asserted.** The request engine surfaces a note when
  its emulation preset lags the browser version; measure JA3/JA4/H2 before
  relying on parity for a specific target.
