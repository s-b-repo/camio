#!/usr/bin/env bash
# build.sh — assemble the camio-browser fork: LibreWolf base + Camoufox stealth
# patches + Camio black/blue branding, then build.
#
# This is an automated RUNBOOK, not a guarantee: LibreWolf and Camoufox patch the
# same Firefox tree, so a Firefox uplift may need you to reconcile a conflict.
# Building needs ~40 GB free disk, a Firefox build toolchain (`./mach bootstrap`),
# and hours of CPU. Nothing here runs unless you invoke it.
set -euo pipefail
cd "$(dirname "$0")"

LIBREWOLF_REF="${LIBREWOLF_REF:-main}"
CAMOUFOX_REF="${CAMOUFOX_REF:-main}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
WORK="build"
BRANDING_ONLY=0
FULL=0

usage() {
  cat <<USAGE
Usage: ./build.sh [options]
  --branding-only     Only inject Camio branding into an existing $WORK/ tree
  --full              Best-effort end-to-end build (LONG; for CI / a big disk)
  --jobs N            Parallel build jobs (default: $JOBS)
  --librewolf REF     LibreWolf git ref (default: $LIBREWOLF_REF)
  --camoufox REF      Camoufox git ref (default: $CAMOUFOX_REF)
  -h, --help          This help
Env: LIBREWOLF_REF, CAMOUFOX_REF, JOBS
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --branding-only) BRANDING_ONLY=1 ;;
    --full) FULL=1 ;;
    --jobs) JOBS="$2"; shift ;;
    --librewolf) LIBREWOLF_REF="$2"; shift ;;
    --camoufox) CAMOUFOX_REF="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing prerequisite: $1" >&2; exit 1; }; }
need git; need python3

check_disk() {
  local avail_kb
  avail_kb=$(df -Pk . | awk 'NR==2{print $4}')
  if [ "${avail_kb:-0}" -lt 42000000 ]; then
    echo "WARNING: <40 GB free here; a Firefox build will likely fail with ENOSPC." >&2
    echo "         Run this on a machine with more disk." >&2
  fi
}

inject_branding() {
  local tree="$1"
  echo "==> injecting Camio black/blue branding into $tree"
  # Ship the autoconfig + userChrome into the source tree's branding dir.
  install -D -m 0644 branding/camio.cfg "$tree/browser/app/camio.cfg"
  install -D -m 0644 branding/userChrome.css \
    "$tree/browser/branding/camio/profile/chrome/userChrome.css" 2>/dev/null || \
    install -D -m 0644 branding/userChrome.css "$tree/.camio/chrome/userChrome.css"
  # autoconfig loader so camio.cfg is read at startup.
  cat > "$tree/browser/app/profile/autoconfig.js.camio" <<'JS'
pref("general.config.filename", "camio.cfg");
pref("general.config.obscure_value", 0);
JS

  # --- Rebrand the COMPILED product name: overwrite the brand strings in the
  # LibreWolf branding dir so the binary reports "Camio Browser" natively (About
  # dialog, window title, menus), not just via a post-package application.ini
  # rename. A Firefox build resolves every -brand-*/brandShortName term from
  # these files, so this is the real rebrand. We overwrite in place (keeping the
  # `librewolf` branding dir name, which build config references) rather than
  # add a new branding dir, so no configure/mozconfig change is needed.
  for brand_dir in \
    "$tree/browser/branding/librewolf" \
    "$tree/browser/branding/nightly" ; do
    [ -d "$brand_dir" ] || continue
    for loc in "$brand_dir"/locales/*/ ; do
      [ -d "$loc" ] || continue
      [ -f branding/brand.ftl ] && install -m 0644 branding/brand.ftl "$loc/brand.ftl"
      [ -f branding/brand.properties ] && \
        install -m 0644 branding/brand.properties "$loc/brand.properties"
    done
    echo "    rebranded product strings in $(basename "$brand_dir")"
  done

  echo "    branding staged (reconcile paths to your Firefox version if needed)."
}

if [ "$BRANDING_ONLY" -eq 1 ]; then
  [ -d "$WORK" ] || { echo "no $WORK/ tree; run a full build first" >&2; exit 1; }
  inject_branding "$WORK"
  echo "done (branding only)."
  exit 0
fi

check_disk
mkdir -p "$WORK"

# Fail fast on an unreachable/private repo instead of prompting for a password.
export GIT_TERMINAL_PROMPT=0

echo "==> fetching LibreWolf ($LIBREWOLF_REF)"
[ -d "$WORK/librewolf" ] || git clone --depth 1 --branch "$LIBREWOLF_REF" \
  https://codeberg.org/librewolf/source.git "$WORK/librewolf"

# Camoufox source (the Firefox C++ patches): as of 2026-11 the upstream repo
# (github.com/daijro/camoufox) is UNAVAILABLE — the maintainers' accounts were
# suspended and only prebuilt binaries remain (jo-inc/camofox-browser/releases).
# So Camoufox patches are OPTIONAL here: set CAMOUFOX_REPO to a reachable source
# mirror to merge them; otherwise the fork is LibreWolf + Camio branding
# (pref-level stealth), and you get Camoufox's C++ stealth by pointing Camio at a
# prebuilt Camoufox binary instead.
CAMOUFOX_REPO="${CAMOUFOX_REPO:-}"
if [ -n "$CAMOUFOX_REPO" ]; then
  echo "==> fetching Camoufox patches from $CAMOUFOX_REPO ($CAMOUFOX_REF)"
  [ -d "$WORK/camoufox" ] || git clone --depth 1 --branch "$CAMOUFOX_REF" \
    "$CAMOUFOX_REPO" "$WORK/camoufox" \
    || echo "    WARNING: Camoufox clone failed; continuing with LibreWolf + branding only."
else
  echo "==> Camoufox source not configured (upstream suspended); building"
  echo "    LibreWolf + Camio branding only. Set CAMOUFOX_REPO=<mirror> to merge patches."
fi

if [ "$FULL" -eq 0 ]; then
  cat <<'NOTE'
==> scaffold prepared. For a full build, re-run with --full (LONG; best-effort),
    or step through manually:
    1. cd build/librewolf && make dir && make fetch   # fetch Firefox + LW patches
    2. apply Camoufox patches to the firefox-* source  # reconcile conflicts
    3. ../../build.sh --branding-only                  # stage Camio branding
    4. make build && make package                      # compile + package
NOTE
  inject_branding "$WORK/librewolf" || true
  echo "done: scaffold prepared under $WORK/. See README.md."
  exit 0
fi

# ---- --full: end-to-end build (hours; experimental) ------------------------
# LibreWolf's Makefile chains: download+verify the Firefox tarball -> extract ->
# copy + run scripts/patch.sh (creates the `librewolf-<version>` source dir) ->
# `./mach build` -> `./mach package-multi-locale` (drops librewolf-*.tar.xz in
# the repo dir). `make package` pulls in every prerequisite; `make bootstrap`
# installs the toolchain first. (There is no `dir`/`fetch` target.)
echo "==> FULL build (long, experimental)"
export MOZBUILD_STATE_PATH="${MOZBUILD_STATE_PATH:-$PWD/$WORK/.mozbuild}"
ROOT="$PWD"
CAMOUFOX_PATCHES="$ROOT/$WORK/camoufox/patches"
BRANDING_CSS="$ROOT/branding/userChrome.css"

cd "$WORK/librewolf"
echo "==> installing the Firefox build toolchain (mach bootstrap)"
make bootstrap </dev/null || echo "    bootstrap non-zero (continuing; may already be set up)"

# Create the patched LibreWolf source dir up front so branding / Camoufox
# patches land *before* the compile. The dir is librewolf-<version>.
lwver="$(make -s version 2>/dev/null | tr -cd '0-9.' || true)"
[ -n "$lwver" ] && make "librewolf-$lwver" </dev/null 2>/dev/null || true
lwsrc="$(find . -maxdepth 1 -type d -name 'librewolf-*' 2>/dev/null | head -1)"
echo "==> LibreWolf source dir: ${lwsrc:-<created during build>}"

if [ -n "$lwsrc" ] && ls "$CAMOUFOX_PATCHES"/*.patch >/dev/null 2>&1; then
  echo "==> applying Camoufox stealth patches (best-effort; failures logged)"
  for p in "$CAMOUFOX_PATCHES"/*.patch; do
    if ( cd "$lwsrc" && patch -p1 --forward --fuzz=3 --no-backup-if-mismatch < "$p" ) >/dev/null 2>&1; then
      echo "    applied $(basename "$p")"
    else
      echo "    SKIPPED $(basename "$p") — reconcile for this Firefox version"
    fi
  done
fi

# Bake the Camio black/blue chrome into the distribution so the fork is themed
# even before Camio's launcher re-applies it.
if [ -n "$lwsrc" ] && [ -f "$BRANDING_CSS" ]; then
  install -D -m 0644 "$BRANDING_CSS" \
    "$lwsrc/browser/branding/librewolf/camio-userChrome.css" 2>/dev/null \
    && echo "    staged Camio userChrome.css into the branding dir"
fi

# Rebrand the compiled product name: overwrite the LibreWolf brand strings in
# the REAL source tree ($lwsrc) that `make build` compiles, so the binary says
# "Camio Browser" natively. inject_branding also stages camio.cfg/userChrome.
if [ -n "$lwsrc" ]; then
  inject_branding "$lwsrc" || echo "    WARNING: brand-string injection failed; continuing"
fi

# Trim peak RAM so the heaviest TUs (dom/bindings, dom/canvas) don't OOM a
# memory-constrained runner: drop separate debug symbols (the big RAM/disk/time
# hog) and cap parallel jobs. $JOBS defaults to nproc; the CI caps it lower.
if [ -n "$lwsrc" ]; then
  {
    echo ''
    echo '# --- Camio build tuning (reduce peak memory) ---'
    echo 'ac_add_options --disable-debug-symbols'
    echo "mk_add_options MOZ_MAKE_FLAGS=\"-j$JOBS\""
    echo "mk_add_options \"export RUSTC_WRAPPER=\""
  } >> "$lwsrc/mozconfig" 2>/dev/null \
    && echo "    appended memory-trimming options to $lwsrc/mozconfig"
fi

echo "==> compiling + packaging (this is the multi-hour part)"
make build   </dev/null || { echo "build failed — see logs"; exit 1; }
make package </dev/null || echo "    package step non-zero"

# ---- Camio rebrand: bake the black/blue theme + hardening into the package ---
# LibreWolf ships an autoconfig (librewolf.cfg) whose sandbox allows only pref
# functions. We disable that sandbox via defaults/pref so the .cfg can also copy
# our userChrome.css into each profile, append Camio prefs + that copy to the
# .cfg, ship the stylesheet at the app root, and rebrand the dir + tarball.
pkg="$(ls librewolf-*.en-US.*.tar.xz 2>/dev/null | head -1)"
if [ -n "$pkg" ] && [ -f "$BRANDING_CSS" ]; then
  echo "==> baking Camio branding into $pkg"
  rm -rf camio-pkg && mkdir camio-pkg
  tar -xf "$pkg" -C camio-pkg
  app="camio-pkg/librewolf"
  if [ -d "$app" ]; then
    install -m 0644 "$BRANDING_CSS" "$app/camio-userChrome.css"
    # Branded user.js baseline + new-tab page.
    [ -f "$ROOT/branding/camio-user.js" ] && \
      install -m 0644 "$ROOT/branding/camio-user.js" "$app/camio-user.js"
    [ -f "$ROOT/branding/newtab.html" ] && \
      install -m 0644 "$ROOT/branding/newtab.html" "$app/newtab.html"
    # Self-hosted Cyber Sec webfonts next to newtab.html (its @font-face uses fonts/).
    if [ -d "$ROOT/branding/fonts" ]; then
      mkdir -p "$app/fonts"
      install -m 0644 "$ROOT/branding/fonts/"*.woff2 "$app/fonts/" 2>/dev/null || true
    fi
    mkdir -p "$app/defaults/pref"
    cat > "$app/defaults/pref/camio-autoconfig.js" <<'CAMIOPREF'
// Camio: allow the autoconfig (.cfg) full power so it can install the theme.
pref("general.config.sandbox_enabled", false);
CAMIOPREF
    cat >> "$app/librewolf.cfg" <<'CAMIOCFG'

// ===== Camio fork: black/blue theme + extra hardening =====
lockPref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
lockPref("dom.webdriver.enabled", false);
defaultPref("privacy.resistFingerprinting", true);
defaultPref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", false);
defaultPref("privacy.reduceTimerPrecision", true);
defaultPref("privacy.resistFingerprinting.reduceTimerPrecision.jitter", true);
defaultPref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 2000);
defaultPref("dom.battery.enabled", false);
defaultPref("dom.netinfo.enabled", false);
defaultPref("dom.gamepad.enabled", false);
defaultPref("media.webspeech.synth.enabled", false);
defaultPref("beacon.enabled", false);
defaultPref("network.dns.disablePrefetch", true);
defaultPref("network.predictor.enabled", false);
defaultPref("webgl.enable-debug-renderer-info", false);
defaultPref("geo.enabled", false);
defaultPref("media.peerconnection.ice.default_address_only", true);
defaultPref("media.peerconnection.ice.no_host", true);
try {
  // Copy userChrome.css + camio-user.js from the app dir into every profile
  // at startup, so a freshly-created profile gets Camio defaults even without
  // Camio's own launcher touching it first.
  var _profD = Services.dirsvc.get("ProfD", Components.interfaces.nsIFile);
  var _appD  = Services.dirsvc.get("GreD",  Components.interfaces.nsIFile);
  var _chromeDir = _profD.clone(); _chromeDir.append("chrome");
  if (!_chromeDir.exists())
    _chromeDir.create(Components.interfaces.nsIFile.DIRECTORY_TYPE, 0o755);
  function _copy(name, intoDir, asName) {
    var _src = _appD.clone(); _src.append(name);
    var _dst = intoDir.clone(); _dst.append(asName || name);
    if (_src.exists()) {
      if (_dst.exists()) _dst.remove(false);
      _src.copyTo(intoDir, asName || name);
    }
  }
  _copy("camio-userChrome.css", _chromeDir, "userChrome.css");
  _copy("camio-user.js", _profD, "user.js");
} catch (e) { try { Components.utils.reportError(e); } catch (_e) {} }
CAMIOCFG
    # Rebrand pass: rename application.ini product strings so about:support
    # reads "Camio Browser" instead of "LibreWolf". Idempotent; safe on reruns.
    "$ROOT/rebrand.sh" "$app" 2>/dev/null || true
    mv "$app" "camio-pkg/camio-browser"
    camio_tar="${pkg/librewolf-/camio-browser-}"
    ( cd camio-pkg && tar -cJf "../$camio_tar" camio-browser )
    echo "    wrote $camio_tar — themed + stealth-preconfigured Camio browser"
  fi
  rm -rf camio-pkg
fi

# ---- Build a Debian package (needs dpkg-deb) --------------------------------
# Installs the fork to /opt/camio-browser, a /usr/bin/camio-browser launcher,
# the .desktop entry, and icons — so `camio-browser` lands on PATH (which the
# Camio app's launcher now prefers) and shows up in the applications menu.
if [ -n "${camio_tar:-}" ] && [ -f "$camio_tar" ] && command -v dpkg-deb >/dev/null 2>&1; then
  debver="$(printf '%s' "$pkg" | sed -E 's/^librewolf-([0-9][^.]*\.[^.]*\.[^-]*-[0-9]+)\..*/\1/')"
  [ -n "$debver" ] || debver="$(date +%Y%m%d)"
  deb="camio-browser_${debver}_amd64"
  echo "==> building $deb.deb"
  rm -rf "$deb"
  mkdir -p "$deb/DEBIAN" "$deb/opt" "$deb/usr/bin" \
    "$deb/usr/share/applications" \
    "$deb/usr/share/icons/hicolor/scalable/apps" \
    "$deb/usr/share/icons/hicolor/128x128/apps"
  tar -xf "$camio_tar" -C "$deb/opt"   # -> opt/camio-browser/
  printf '#!/bin/sh\nexec /opt/camio-browser/librewolf "$@"\n' > "$deb/usr/bin/camio-browser"
  chmod 0755 "$deb/usr/bin/camio-browser"
  install -m 0644 "$ROOT/branding/camio-browser.desktop" \
    "$deb/usr/share/applications/camio-browser.desktop"
  install -m 0644 "$ROOT/branding/camio-browser.svg" \
    "$deb/usr/share/icons/hicolor/scalable/apps/camio-browser.svg"
  cp "$deb/opt/camio-browser/browser/chrome/icons/default/default128.png" \
     "$deb/usr/share/icons/hicolor/128x128/apps/camio-browser.png" 2>/dev/null || true
  isize="$(du -sk "$deb/opt" | cut -f1)"
  cat > "$deb/DEBIAN/control" <<CTRL
Package: camio-browser
Version: ${debver}
Architecture: amd64
Maintainer: Camio Project <noreply@users.noreply.github.com>
Installed-Size: ${isize}
Depends: libgtk-3-0, libdbus-glib-1-2, libx11-6, libxcb1
Section: web
Priority: optional
Description: Camio Browser - fingerprint-hardened LibreWolf fork
 A black/blue themed, stealth-preconfigured Firefox-family browser used by the
 Camio security workbench. Built from LibreWolf with Camio branding and extra
 hardening baked in. Camoufox's C++ patches are not included while upstream is
 suspended; point Camio at a prebuilt Camoufox binary for the C++ stealth layer.
CTRL
  cat > "$deb/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -f /usr/share/icons/hicolor || true
exit 0
POST
  chmod 0755 "$deb/DEBIAN/postinst"
  dpkg-deb --root-owner-group --build "$deb" "${deb}.deb" \
    && echo "    wrote ${deb}.deb"
  rm -rf "$deb"
fi

echo "==> done. Look in $PWD for camio-browser-*.tar.xz, camio-browser_*_amd64.deb (and librewolf-*.tar.xz)."
