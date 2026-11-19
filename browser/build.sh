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
echo "==> done. Look for librewolf-*.tar.xz in $PWD."
