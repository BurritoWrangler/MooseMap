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
#   ./scripts/install-app.sh              # build + install the .deb (sudo dpkg)
#   ./scripts/install-app.sh --appimage   # install the portable AppImage (no sudo)
#   ./scripts/install-app.sh --no-install # build only; print the artifact path
#   ./scripts/install-app.sh --setup      # run setup-kali.sh --desktop first
#   ./scripts/install-app.sh --uninstall  # remove MooseMap (deb and/or AppImage)
#
# The .deb is the default on Debian/Kali. --appimage installs a single portable
# binary into ~/.local/bin plus a menu entry (user-level, no package manager) —
# handy on non-Debian hosts.
#
# Authorized use only. MooseMap performs active scanning — only run it against
# assets you are explicitly authorized to test.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DO_INSTALL=1
DO_SETUP=0
ACTION="build"
MODE="deb"            # install mode: "deb" (default) or "appimage"
PKG_NAME="moosemap"   # dpkg package name (from the bundle identifier/productName)

for arg in "$@"; do
  case "$arg" in
    --no-install) DO_INSTALL=0 ;;
    --setup)      DO_SETUP=1 ;;
    --appimage)   MODE="appimage" ;;
    --uninstall)  ACTION="uninstall" ;;
    -h|--help)    sed -n '3,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# User-level XDG locations for the AppImage install.
XDG_BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
XDG_APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
XDG_ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
APPIMAGE_DEST="$XDG_BIN/MooseMap.AppImage"
DESKTOP_DEST="$XDG_APPS/moosemap-appimage.desktop"
ICON_DEST="$XDG_ICONS/moosemap.svg"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n'  "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n'  "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Refresh the desktop menu + icon caches (best-effort; harmless if tools absent).
refresh_menu_caches() {
  have update-desktop-database && update-desktop-database "$XDG_APPS" 2>/dev/null || true
  have gtk-update-icon-cache \
    && gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null \
    || true
}

# Install the given AppImage into ~/.local/bin with a menu entry + icon.
install_appimage() {
  local src="$1"
  [ -n "$src" ] || die "no AppImage to install"
  say "installing AppImage (user-level, no sudo)"
  mkdir -p "$XDG_BIN" "$XDG_APPS" "$XDG_ICONS"

  install -m 0755 "$src" "$APPIMAGE_DEST"
  install -m 0644 "$REPO/assets/moosemap.svg" "$ICON_DEST"

  # The app opens its own window, so Terminal=false (unlike the old browser
  # launcher). Exec points straight at the installed AppImage.
  cat > "$DESKTOP_DEST" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=MooseMap
GenericName=External Pentest Orchestrator
Comment=Authorized external penetration testing with real-time tracking
Exec=$APPIMAGE_DEST
Icon=moosemap
Terminal=false
Categories=Security;Network;System;
Keywords=pentest;security;recon;scan;nmap;nuclei;httpx;subfinder;vulnerability;
StartupNotify=true
EOF
  chmod 0644 "$DESKTOP_DEST"

  have desktop-file-validate && desktop-file-validate "$DESKTOP_DEST" \
    && say "desktop entry validated" || true
  refresh_menu_caches

  say "installed to $APPIMAGE_DEST"
  case ":$PATH:" in
    *":$XDG_BIN:"*) : ;;
    *) warn "$XDG_BIN is not on your PATH; the menu entry still works via its absolute path." ;;
  esac
}

# Remove an AppImage install (binary + menu entry + icon).
uninstall_appimage() {
  local removed=0
  for f in "$APPIMAGE_DEST" "$DESKTOP_DEST" "$ICON_DEST"; do
    if [ -e "$f" ]; then rm -f "$f" && removed=1; fi
  done
  if [ "$removed" -eq 1 ]; then
    refresh_menu_caches
    say "removed AppImage install"
  fi
}

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

# --- uninstall (handles both .deb package and AppImage install) --------------
if [ "$ACTION" = "uninstall" ]; then
  say "removing MooseMap (deb package and/or AppImage install)"
  found=0

  pkg="$(resolve_pkg || true)"
  if [ -n "${pkg:-}" ]; then
    $SUDO apt-get remove -y "$pkg" || $SUDO dpkg -r "$pkg" \
      || die "failed to remove package '$pkg'"
    say "removed dpkg package '$pkg'."
    found=1
  fi

  if [ -e "$APPIMAGE_DEST" ] || [ -e "$DESKTOP_DEST" ]; then
    uninstall_appimage
    found=1
  fi

  [ "$found" -eq 1 ] || warn "no installed MooseMap found (nothing to do)."
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
  say "build-only mode (--no-install). Artifacts:"
  [ -n "$DEB" ]      && echo "    deb:      $REPO/$DEB"
  [ -n "$APPIMAGE" ] && echo "    appimage: $REPO/$APPIMAGE"
  exit 0
fi

# Auto-select AppImage if that's all we have, even without --appimage.
if [ "$MODE" = "deb" ] && { [ -z "$DEB" ] || ! have dpkg; }; then
  if [ -n "$APPIMAGE" ]; then
    warn "no installable .deb (or dpkg missing) — falling back to AppImage install"
    MODE="appimage"
  fi
fi

if [ "$MODE" = "appimage" ]; then
  [ -n "$APPIMAGE" ] || die "AppImage install requested but no .AppImage was built"
  install_appimage "$APPIMAGE"
else
  [ -n "$DEB" ] || die "no .deb produced; try --appimage"
  have dpkg || die "dpkg not available; use --appimage on non-Debian systems"
  say "installing $DEB"
  # dpkg may report missing runtime deps; apt-get -f install resolves them.
  if ! $SUDO dpkg -i "$DEB"; then
    warn "dpkg reported missing dependencies; resolving with apt-get -f install"
    $SUDO apt-get -f install -y || die "failed to resolve package dependencies"
  fi
fi

say "done. Launch \"MooseMap\" from your applications menu (Security/Network),"
say "or run it from a terminal (moosemap-desktop, or the AppImage path above)."
warn "reminder: only scan assets you are explicitly authorized to test."
