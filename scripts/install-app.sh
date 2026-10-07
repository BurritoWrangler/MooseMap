#!/usr/bin/env bash
#
# install-app.sh — build and install the MooseMap desktop app on Kali/Debian.
#
# One command from a fresh checkout to an installed, menu-launchable app:
#   1. ensures the build toolchain is present (offers to run setup)
#   2. regenerates the app icons from the SVG
#   3. builds the Tauri bundle (frontend + release binary + .deb)
#   4. installs the .deb so "MooseMap" appears in the applications menu
#
# Usage:
#   ./scripts/install-app.sh              # build + install (.deb via sudo dpkg)
#   ./scripts/install-app.sh --no-install # build only; print the artifact path
#   ./scripts/install-app.sh --setup      # run setup-kali.sh --desktop first
#   ./scripts/install-app.sh --uninstall  # remove an installed MooseMap
#
# Authorized use only. MooseMap performs active scanning — only run it against
# assets you are explicitly authorized to test.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DO_INSTALL=1
DO_SETUP=0
ACTION="build"
PKG_NAME="moosemap"   # dpkg package name (from the bundle identifier/productName)

for arg in "$@"; do
  case "$arg" in
    --no-install) DO_INSTALL=0 ;;
    --setup)      DO_SETUP=1 ;;
    --uninstall)  ACTION="uninstall" ;;
    -h|--help)    sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n'  "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n'  "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  have sudo && SUDO="sudo" || warn "not root and no sudo; install step may fail"
fi

# Resolve the installed dpkg package name. Tauri derives the Debian package name
# from productName lowercased ("MooseMap" -> "moosemap"), but discover it so this
# keeps working if that convention changes.
resolve_pkg() {
  have dpkg || return 1
  if dpkg -s "$PKG_NAME" >/dev/null 2>&1; then
    echo "$PKG_NAME"; return 0
  fi
  # Fall back to any installed package whose name contains "moosemap".
  dpkg-query -W -f='${Package}\n' 2>/dev/null \
    | grep -i moosemap | head -n1
}

# --- uninstall ---------------------------------------------------------------
if [ "$ACTION" = "uninstall" ]; then
  say "removing installed MooseMap package"
  pkg="$(resolve_pkg || true)"
  if [ -n "${pkg:-}" ]; then
    $SUDO apt-get remove -y "$pkg" || $SUDO dpkg -r "$pkg" \
      || die "failed to remove package '$pkg'"
    say "removed '$pkg'."
  else
    warn "no installed MooseMap package found (nothing to do)."
  fi
  exit 0
fi

# --- optional setup ----------------------------------------------------------
if [ "$DO_SETUP" -eq 1 ]; then
  say "running setup-kali.sh --desktop"
  ./scripts/setup-kali.sh --desktop
fi

# --- preflight: build toolchain ---------------------------------------------
have cargo || die "cargo not found. Run: ./scripts/install-app.sh --setup  (or make setup)"
have npm   || die "npm not found. Run: ./scripts/install-app.sh --setup  (or make setup)"
if ! cargo tauri --version >/dev/null 2>&1; then
  die "tauri-cli not found. Run: ./scripts/install-app.sh --setup  (installs it)"
fi

# --- icons -------------------------------------------------------------------
say "generating app icons from assets/moosemap.svg"
cargo tauri icon assets/moosemap.svg --output src-tauri/icons \
  || warn "icon generation failed; continuing with existing icons"

# --- build the bundle --------------------------------------------------------
say "building the MooseMap desktop bundle (this can take a few minutes)…"
cargo tauri build

BUNDLE_DIR="src-tauri/target/release/bundle"

# Locate the produced .deb (name includes version + arch).
DEB="$(find "$BUNDLE_DIR/deb" -maxdepth 1 -name '*.deb' -print 2>/dev/null | head -n1 || true)"
APPIMAGE="$(find "$BUNDLE_DIR/appimage" -maxdepth 1 -name '*.AppImage' -print 2>/dev/null | head -n1 || true)"

if [ -z "$DEB" ] && [ -z "$APPIMAGE" ]; then
  die "build finished but no .deb/.AppImage found under $BUNDLE_DIR"
fi

say "built:"
[ -n "$DEB" ]      && echo "    deb:      $REPO/$DEB"
[ -n "$APPIMAGE" ] && echo "    appimage: $REPO/$APPIMAGE"

# --- install -----------------------------------------------------------------
if [ "$DO_INSTALL" -eq 0 ]; then
  say "build-only mode (--no-install). Install the .deb yourself with:"
  echo "    sudo dpkg -i \"$REPO/$DEB\" && sudo apt-get -f install -y"
  exit 0
fi

if [ -z "$DEB" ]; then
  warn "no .deb produced; cannot auto-install. The AppImage is runnable directly:"
  echo "    \"$REPO/$APPIMAGE\""
  exit 0
fi

if ! have dpkg; then
  warn "dpkg not available (not a Debian system?). Run the AppImage or install manually."
  exit 0
fi

say "installing $DEB"
# dpkg may report missing runtime deps; apt-get -f install resolves them.
if ! $SUDO dpkg -i "$DEB"; then
  warn "dpkg reported missing dependencies; resolving with apt-get -f install"
  $SUDO apt-get -f install -y || die "failed to resolve package dependencies"
fi

say "done. Launch \"MooseMap\" from your applications menu (Utility/Security),"
say "or run 'moosemap-desktop' from a terminal."
warn "reminder: only scan assets you are explicitly authorized to test."
