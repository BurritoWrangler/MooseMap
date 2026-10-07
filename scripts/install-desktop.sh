#!/usr/bin/env bash
#
# install-desktop.sh — add MooseMap to the applications menu with an icon.
#
# Installs the launcher, icon, and a .desktop entry into XDG directories so
# MooseMap shows up in the main menu (Kali: Applications, usually under the
# security/network groups). User-level by default (no sudo).
#
# Usage:
#   ./scripts/install-desktop.sh            # install for the current user
#   ./scripts/install-desktop.sh --system   # install for all users (needs sudo)
#   ./scripts/install-desktop.sh --uninstall # remove the entry
#
# Assumes the release binary is built (`make build`). The launcher falls back to
# a repo-relative build or `cargo run` if the binary isn't on PATH.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="user"
ACTION="install"

for arg in "$@"; do
  case "$arg" in
    --system)    MODE="system" ;;
    --user)      MODE="user" ;;
    --uninstall) ACTION="uninstall" ;;
    -h|--help)   sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }

# Resolve target directories by mode.
if [ "$MODE" = "system" ]; then
  SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
  BIN_DIR="/usr/local/bin"
  APP_DIR="/usr/share/applications"
  ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
else
  SUDO=""
  BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
  APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
  ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
fi

LAUNCHER="$BIN_DIR/moosemap-launch"
ICON_PATH="$ICON_DIR/moosemap.svg"
DESKTOP_PATH="$APP_DIR/moosemap.desktop"

refresh_caches() {
  command -v update-desktop-database >/dev/null 2>&1 \
    && $SUDO update-desktop-database "$APP_DIR" 2>/dev/null || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && $SUDO gtk-update-icon-cache -f -t "$(dirname "$(dirname "$(dirname "$ICON_DIR")")")" 2>/dev/null || true
}

if [ "$ACTION" = "uninstall" ]; then
  say "removing MooseMap desktop entry ($MODE)"
  $SUDO rm -f "$DESKTOP_PATH" "$ICON_PATH" "$LAUNCHER"
  refresh_caches
  say "done."
  exit 0
fi

say "installing MooseMap desktop entry ($MODE)"
$SUDO mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR"

# 1. Launcher script.
$SUDO install -m 0755 "$REPO/scripts/moosemap-launch.sh" "$LAUNCHER"

# 2. If a release binary exists, install it to BIN_DIR so the launcher finds it
#    on PATH; otherwise the launcher falls back to the repo build / cargo run.
if [ -x "$REPO/target/release/moosemap" ]; then
  $SUDO install -m 0755 "$REPO/target/release/moosemap" "$BIN_DIR/moosemap"
  say "installed moosemap binary to $BIN_DIR/moosemap"
else
  warn "no release binary at target/release/moosemap — run 'make build' first."
  warn "the menu entry will still work by building from the repo on first launch."
fi

# 3. Icon.
$SUDO install -m 0644 "$REPO/assets/moosemap.svg" "$ICON_PATH"

# 4. .desktop entry with absolute Exec/Icon paths substituted in.
tmp="$(mktemp)"
sed -e "s|__EXEC__|$LAUNCHER|g" \
    -e "s|__ICON__|$ICON_PATH|g" \
    "$REPO/desktop/moosemap.desktop" > "$tmp"
$SUDO install -m 0644 "$tmp" "$DESKTOP_PATH"
rm -f "$tmp"

# Validate if the tool is available (non-fatal).
if command -v desktop-file-validate >/dev/null 2>&1; then
  desktop-file-validate "$DESKTOP_PATH" && say "desktop entry validated" \
    || warn "desktop-file-validate reported issues (entry still installed)"
fi

refresh_caches

say "done. Look for \"MooseMap\" in your applications menu."
if [ "$MODE" = "user" ]; then
  case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) warn "$BIN_DIR is not on your PATH; the menu entry still works via its absolute path." ;;
  esac
fi
