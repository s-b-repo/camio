// camio-user.js — baseline Firefox prefs baked into the camio-browser fork.
//
// This mirrors the stealth defaults that camio-core's `FingerprintProfile`
// writes at launch, so even a profile Camio hasn't touched (a human-started
// first run, a secondary profile) still comes up with the same hardened
// baseline the Camio launcher would apply. Camio's launcher still overwrites
// `user.js` at run-time with the operator's chosen persona, so this file is
// the "no app yet" baseline, not the source of truth.
//
// Shape: each line is `user_pref("<key>", <value>);` so Firefox's stock
// profile-startup pref loader (not just the autoconfig .cfg) picks them up.
// The camio.cfg file adds `lockPref` lines where locking is intentional.

// --- Identity (Firefox-158 Windows persona; aligns with ALIGNED_FIREFOX_MAJOR) -
user_pref("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0");
user_pref("intl.accept_languages", "en-US,en;q=0.5");

// --- Mozilla omnibus RFP + letterbox-less balanced defaults ------------------
user_pref("privacy.resistFingerprinting", true);
// false = randomized canvas readback (Randomize mode), not a blank one.
user_pref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", false);
user_pref("privacy.spoof_english", 2);

// --- WebRTC leak protection (keeps WebRTC working, blocks host candidates) ---
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);

// --- Automation-tell hidden; Marionette stays available via -marionette ------
// (dom.webdriver.enabled is the real pref; the ChromeDriver-only
// `useAutomationExtension` capability is NOT a Firefox pref, so it is omitted.)
user_pref("dom.webdriver.enabled", false);

// --- Extended stealth (matches FingerprintPolicy::balanced in camio-core) ----
user_pref("dom.battery.enabled", false);
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");
user_pref("dom.netinfo.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("media.webspeech.synth.enabled", false);
user_pref("beacon.enabled", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("webgl.enable-debug-renderer-info", false);

// --- Timer precision reduction (Tor-browser-grade: 2ms + jitter) -------------
user_pref("privacy.reduceTimerPrecision", true);
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.jitter", true);
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 2000);

// --- Tracking protection + cookie partitioning -------------------------------
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("network.cookie.cookieBehavior", 5);

// --- Phone-home / telemetry silence ------------------------------------------
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("network.captive-portal-service.enabled", false);

// --- Theme (enables Camio's userChrome.css shipped at the profile root) -----
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
user_pref("browser.theme.toolbar-theme", 0);  // dark toolbars

// --- About:newtab identity (hide Pocket/sponsored; keep the surface quiet) ---
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("extensions.pocket.enabled", false);
