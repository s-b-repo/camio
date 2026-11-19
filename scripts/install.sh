#!/bin/sh
# Camio quick installer — downloads the latest prebuilt release and installs the
# `camio` CLI (and the `camio-app` GUI, when present) to a bin directory on PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/s-b-repo/camio/main/scripts/install.sh | sh
#
# Environment overrides:
#   CAMIO_VERSION=vX.Y.Z   install a specific release          (default: latest)
#   CAMIO_BIN_DIR=/path     install location (default: ~/.local/bin, or
#                           /usr/local/bin when writable)
#
# Targets published by the release workflow: linux-x86_64, linux-aarch64,
# macos-x86_64, macos-aarch64. For the themed camio-browser fork, install the
# .deb from the matching browser-v* release instead (see docs/INDEX.md).
set -eu

REPO="s-b-repo/camio"
VERSION="${CAMIO_VERSION:-}"

say() { printf '==> %s\n' "$*"; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

have tar || die "tar is required"
if have curl; then
  dl() { curl -fsSL "$1"; }
  dlo() { curl -fsSL -o "$1" "$2"; }
  probe() { curl -fsIL -o /dev/null "$1"; }
elif have wget; then
  dl() { wget -qO- "$1"; }
  dlo() { wget -qO "$1" "$2"; }
  probe() { wget -q --spider "$1"; }
else
  die "need curl or wget"
fi

# ---- detect the release target ----------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux) os_t="linux" ;;
  Darwin) os_t="macos" ;;
  *) die "unsupported OS '$os' — build from source (see the README)" ;;
esac
case "$arch" in
  x86_64 | amd64) arch_t="x86_64" ;;
  aarch64 | arm64) arch_t="aarch64" ;;
  *) die "unsupported architecture '$arch'" ;;
esac
TARGET="${os_t}-${arch_t}"

# ---- resolve the version ----------------------------------------------------
# Honour CAMIO_VERSION; otherwise pick the newest release that actually publishes
# a build for this target — a version-bump bot can create releases faster than
# the binaries are attached, so "latest" may not have assets yet.
if [ -z "$VERSION" ]; then
  say "finding the newest release with a $TARGET build"
  tags="$(dl "https://api.github.com/repos/$REPO/releases?per_page=30" \
    | grep '"tag_name":' | sed -E 's/.*"tag_name"[^"]*"([^"]+)".*/\1/')"
  for t in $tags; do
    if probe "https://github.com/$REPO/releases/download/$t/camio-${t}-${TARGET}.tar.gz"; then
      VERSION="$t"
      break
    fi
  done
  [ -n "$VERSION" ] || die "no published $TARGET build yet — build from source (see the README)"
fi
say "installing Camio $VERSION ($TARGET)"

NAME="camio-${VERSION}-${TARGET}"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $NAME.tar.gz"
dlo "$TMP/$NAME.tar.gz" "$BASE/$NAME.tar.gz" \
  || die "no $TARGET build for $VERSION — check the release page for available targets"

# ---- verify the checksum when published -------------------------------------
if dlo "$TMP/$NAME.tar.gz.sha256" "$BASE/$NAME.tar.gz.sha256" 2>/dev/null; then
  say "verifying SHA-256"
  want="$(awk '{print $1}' "$TMP/$NAME.tar.gz.sha256")"
  if have sha256sum; then
    got="$(sha256sum "$TMP/$NAME.tar.gz" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "$TMP/$NAME.tar.gz" | awk '{print $1}')"
  fi
  [ "$want" = "$got" ] || die "checksum mismatch (expected $want, got $got)"
fi

tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
SRC="$TMP/$NAME"

# ---- choose a bin directory -------------------------------------------------
BIN="${CAMIO_BIN_DIR:-}"
if [ -z "$BIN" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    BIN="/usr/local/bin"
  else
    BIN="$HOME/.local/bin"
  fi
fi
mkdir -p "$BIN"

installed=""
for b in camio camio-app; do
  if [ -f "$SRC/$b" ]; then
    cp "$SRC/$b" "$BIN/$b"
    chmod 0755 "$BIN/$b"
    installed="$installed $b"
  fi
done
[ -n "$installed" ] || die "no binaries found inside the archive"
say "installed:$installed -> $BIN"

case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) printf '\n  NOTE: %s is not on your PATH. Add it:\n    export PATH="%s:$PATH"\n' "$BIN" "$BIN" ;;
esac

cat <<EOF

Next steps:
  camio --help                 # command-line interface
  camio fingerprint show       # inspect the anti-detection profile
  camio app                    # native desktop workbench (if camio-app installed)

Docs: https://github.com/$REPO/blob/main/docs/INDEX.md
Only test targets you are authorized to assess.
EOF
