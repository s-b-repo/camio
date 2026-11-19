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

usage() {
  cat <<USAGE
Usage: ./build.sh [options]
  --branding-only     Only inject Camio branding into an existing $WORK/ tree
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

echo "==> fetching LibreWolf ($LIBREWOLF_REF)"
[ -d "$WORK/librewolf" ] || git clone --depth 1 --branch "$LIBREWOLF_REF" \
  https://codeberg.org/librewolf/source.git "$WORK/librewolf"

echo "==> fetching Camoufox ($CAMOUFOX_REF) for its stealth patches"
[ -d "$WORK/camoufox" ] || git clone --depth 1 --branch "$CAMOUFOX_REF" \
  https://github.com/daijro/camoufox.git "$WORK/camoufox"

cat <<'NOTE'
==> NEXT (manual-ish, version-specific):
    1. Build the LibreWolf source tree per its README (it fetches the matching
       Firefox source: `make dir && make fetch`).
    2. Apply Camoufox's patches on top (see camoufox's Makefile / patches/).
       Conflicts here are expected across Firefox uplifts — reconcile them.
    3. Re-run `./build.sh --branding-only` to stage the Camio branding.
    4. Build with `./mach build -j'"$JOBS"'` and package with `./mach package`.
NOTE
inject_branding "$WORK/librewolf" || true
echo "done: scaffold prepared under $WORK/. See README.md for the build steps."
