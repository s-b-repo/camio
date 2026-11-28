#!/usr/bin/env bash
# rebrand.sh — swap LibreWolf product strings for Camio in an unpacked fork tree.
#
# build.sh does the heavy lifting (fetch LibreWolf, apply Camoufox patches when
# a mirror is set, compile, package, bake userChrome + .cfg + .deb). This
# script covers the string-swap layer the main build doesn't touch: the few
# user-visible places where "LibreWolf" still appears after a vanilla package
# is extracted — about:support's "Application Basics > Name", the default
# window title on first run, and the application.ini / platform.ini stamps
# that `--help` / `--version` print.
#
# It operates on an already-unpacked "camio-browser" app directory (the one
# build.sh renames from "librewolf" to "camio-browser"), is idempotent, and
# does NOT touch files outside that directory.
#
# Usage: ./rebrand.sh <camio-browser-dir>

set -euo pipefail

APP="${1:-}"
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
  echo "usage: $0 <camio-browser-dir>" >&2
  exit 2
fi

echo "==> rebranding product strings in $APP"

# application.ini / platform.ini set the Name shown in about:support and in
# some crash-report UI. We flip Name=LibreWolf to Name=Camio Browser, keeping
# the Vendor/CodeName untouched (those affect the on-disk profile path and
# changing them silently orphans existing profiles).
for ini in "$APP/application.ini" "$APP/platform.ini" "$APP/browser/application.ini"; do
  [ -f "$ini" ] || continue
  # Only replace an EXACT "Name=LibreWolf" line (avoid stray substring matches).
  if grep -qE '^Name=LibreWolf$' "$ini"; then
    sed -i -E 's/^Name=LibreWolf$/Name=Camio Browser/' "$ini"
    echo "    renamed in $(basename "$ini")"
  fi
done

# omni.ja holds the compiled-in brand strings (brand.ftl / brand.properties)
# that the About dialog, window title and menus read. For a FROM-SOURCE build
# these are already "Camio Browser" (build.sh injects branding/brand.* before
# compile). For a PREBUILT LibreWolf tarball there is no compile step, so swap
# the brand-term *values* inside each omni.ja here. omni.ja is a zip stored
# with no compression and no extra fields (`zip -X -0`); we preserve that so
# Firefox still maps it. Best-effort: needs unzip+zip, and clears startupCache
# so the edited strings take effect.
rebrand_omni() {
  local jar="$1"
  command -v unzip >/dev/null 2>&1 && command -v zip >/dev/null 2>&1 || {
    echo "    skipped $(basename "$jar") (need unzip+zip to rebrand a prebuilt jar)"
    return 0
  }
  local work; work="$(mktemp -d)"
  if ! unzip -q "$jar" -d "$work" 2>/dev/null; then
    echo "    skipped $(basename "$jar") (not an unzippable omni.ja)"; rm -rf "$work"; return 0
  fi
  # Rewrite brand-term VALUES wherever a brand.ftl / brand.properties lives.
  # Match the term, keep the key, replace only the human-readable value.
  local changed=0
  while IFS= read -r bf; do
    sed -i -E \
      -e 's/(-brand-shorter-name =).*/\1 Camio/' \
      -e 's/(-brand-short-name =).*/\1 Camio Browser/' \
      -e 's/(-brand-full-name =).*/\1 Camio Browser/' \
      -e 's/(-brand-product-name =).*/\1 Camio Browser/' \
      -e 's/(-vendor-short-name =).*/\1 Camio/' "$bf" && changed=1
  done < <(find "$work" -name brand.ftl 2>/dev/null)
  while IFS= read -r bp; do
    sed -i -E \
      -e 's/^(brandShorterName=).*/\1Camio/' \
      -e 's/^(brandShortName=).*/\1Camio Browser/' \
      -e 's/^(brandFullName=).*/\1Camio Browser/' \
      -e 's/^(vendorShortName=).*/\1Camio/' "$bp" && changed=1
  done < <(find "$work" -name brand.properties 2>/dev/null)
  if [ "$changed" -eq 1 ]; then
    ( cd "$work" && zip -q -r -X -0 "../omni.rebuilt" . ) && mv "$work/../omni.rebuilt" "$jar" \
      && echo "    rebranded brand strings in $(basename "$jar")"
  else
    echo "    no brand.* files found in $(basename "$jar") (skipped)"
  fi
  rm -rf "$work"
}
for f in "$APP/browser/omni.ja" "$APP/omni.ja"; do
  [ -f "$f" ] || continue
  rebrand_omni "$f"
done
# Clear the startup cache so edited omni.ja strings are re-read, not served
# from a stale precompiled cache.
rm -rf "$APP/browser/startupCache" "$APP/startupCache" 2>/dev/null || true

# Launcher: build.sh writes /usr/bin/camio-browser already. For a bare
# tarball install we also drop a shim inside the app dir so people running
# the extracted tree directly get the right argv0, which some fingerprinting
# sites read via process name.
if [ -f "$APP/librewolf" ] && [ ! -f "$APP/camio-browser" ]; then
  ( cd "$APP" && ln -sf librewolf camio-browser )
  echo "    added 'camio-browser' launcher symlink next to 'librewolf'"
fi

# Drop the newtab page next to the app so the branded start page is one file
# away. The browser doesn't load it automatically — that needs a dedicated
# about: protocol handler in the compiled binary — but it ships so an
# operator can point about:home at `file://$APP/newtab.html`.
BRANDING_DIR="$(cd "$(dirname "$0")" && pwd)/branding"
if [ -f "$BRANDING_DIR/newtab.html" ]; then
  install -m 0644 "$BRANDING_DIR/newtab.html" "$APP/newtab.html"
  # Self-hosted Cyber Sec webfonts next to newtab.html (its @font-face uses fonts/).
  if [ -d "$BRANDING_DIR/fonts" ]; then
    mkdir -p "$APP/fonts"
    install -m 0644 "$BRANDING_DIR/fonts/"*.woff2 "$APP/fonts/" 2>/dev/null || true
  fi
  echo "    staged newtab.html (+ fonts) at $APP/newtab.html"
fi

# Bake the user.js baseline at the app root. Firefox doesn't auto-load this,
# but build.sh's post-package .cfg copies it into every new profile at startup
# (see the Services.dirsvc block in build.sh), so the result is the same.
if [ -f "$BRANDING_DIR/camio-user.js" ]; then
  install -m 0644 "$BRANDING_DIR/camio-user.js" "$APP/camio-user.js"
  echo "    staged camio-user.js at $APP/camio-user.js"
fi

echo "==> rebrand pass complete."
