#!/usr/bin/env bash
#
# setup-kali.sh — provision a Kali/Debian VM to build and run MooseMap.
#
# Installs: the external scanning tools (nmap, masscan, subfinder, httpx,
# nuclei), the Rust toolchain, and Node.js for the GUI. Idempotent: safe to
# re-run. After it finishes, verify with `cargo run -p moosemap-cli -- tools`.
#
# Authorized use only. MooseMap performs active scanning — only run it against
# assets you are explicitly authorized to test.
#
# Usage:
#   ./scripts/setup-kali.sh            # install everything
#   ./scripts/setup-kali.sh --tools    # external scanning tools only
#   ./scripts/setup-kali.sh --no-node  # skip Node.js (API/CLI only, no GUI)
#   ./scripts/setup-kali.sh --desktop  # also install Tauri desktop-app deps
#                                       # (WebKitGTK, build tools, tauri-cli)

set -euo pipefail

WITH_NODE=1
TOOLS_ONLY=0
WITH_DESKTOP=0
for arg in "$@"; do
  case "$arg" in
    --no-node) WITH_NODE=0 ;;
    --tools)   TOOLS_ONLY=1 ;;
    --desktop) WITH_DESKTOP=1 ;;
    -h|--help) sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Prefix privileged commands with sudo only if we aren't already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then SUDO="sudo"; else
    warn "not root and sudo not found; apt installs may fail"
  fi
fi

apt_install() {
  say "apt install: $*"
  $SUDO apt-get update -y
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

# ---------------------------------------------------------------------------
# External scanning tools
# ---------------------------------------------------------------------------
install_scanning_tools() {
  # nmap + masscan are in the Kali/Debian repos.
  have nmap    || apt_install nmap    || warn "could not install nmap"
  have masscan || apt_install masscan || warn "could not install masscan"

  # ProjectDiscovery tools: try apt first (Kali packages them), then go install.
  install_pd_tool subfinder \
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_pd_tool nuclei \
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  install_pd_httpx

  # Pull nuclei templates (first run otherwise does this mid-scan).
  if have nuclei; then
    say "updating nuclei templates"
    nuclei -update-templates -silent || warn "nuclei template update failed (network?)"
  fi
}

# Install a ProjectDiscovery tool: apt package of the same name, else go install.
install_pd_tool() {
  local name="$1" gopkg="$2"
  if have "$name"; then say "$name already present"; return; fi
  if apt_install "$name"; then return; fi
  warn "$name not available via apt; trying 'go install'"
  ensure_go
  go install "$gopkg" && warn "ensure \$(go env GOPATH)/bin is on your PATH"
}

# httpx needs special care: on Kali the apt package 'httpx-toolkit' installs the
# ProjectDiscovery binary AS `httpx-toolkit` (the plain `httpx` is the unrelated
# Python client). MooseMap auto-detects `httpx-toolkit`, so no env var is needed.
pd_httpx_present() {
  # True if either `httpx` or `httpx-toolkit` is ProjectDiscovery's.
  { have httpx         && httpx         -version 2>&1 | grep -qi projectdiscovery; } ||
  { have httpx-toolkit && httpx-toolkit -version 2>&1 | grep -qi projectdiscovery; }
}

install_pd_httpx() {
  if pd_httpx_present; then
    say "ProjectDiscovery httpx already present"; return
  fi
  if apt_install httpx-toolkit; then
    say "installed httpx-toolkit (ProjectDiscovery httpx; invoked as 'httpx-toolkit' on Kali)"
  else
    warn "httpx-toolkit not available via apt; trying 'go install'"
    ensure_go
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
      && warn "ensure \$(go env GOPATH)/bin precedes any Python httpx on PATH"
  fi
  if pd_httpx_present; then
    say "ProjectDiscovery httpx ready (MooseMap auto-detects 'httpx-toolkit')"
  else
    warn "could not verify a ProjectDiscovery httpx; set MOOSEMAP_HTTPX to its path"
  fi
}

ensure_go() {
  have go && return
  apt_install golang-go || warn "could not install Go; PD tool install may fail"
}

# ---------------------------------------------------------------------------
# Rust toolchain
# ---------------------------------------------------------------------------
install_rust() {
  if have cargo; then say "cargo already present ($(cargo --version))"; return; fi
  say "installing Rust via rustup"
  if have curl; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
  else
    apt_install rustc cargo || warn "could not install Rust"
  fi
}

# ---------------------------------------------------------------------------
# Node.js (for the web GUI)
# ---------------------------------------------------------------------------
install_node() {
  if have npm; then say "npm already present ($(npm --version))"; return; fi
  apt_install nodejs npm || warn "could not install Node.js/npm"
}

# ---------------------------------------------------------------------------
# Desktop app (Tauri) build dependencies.
#
# Tauri on Linux needs WebKitGTK + GTK dev headers and a few build tools, plus
# the Tauri CLI for bundling and icon generation. librsvg2-bin provides
# rsvg-convert for turning the SVG into PNG/ICO/ICNS icon sets.
# ---------------------------------------------------------------------------
install_desktop_deps() {
  say "installing Tauri desktop build dependencies"
  apt_install \
    libwebkit2gtk-4.1-dev \
    build-essential \
    curl wget file \
    libxdo-dev \
    libssl-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev librsvg2-bin \
    || warn "some Tauri system deps failed to install"

  # Tauri CLI (provides `cargo tauri dev|build|icon`).
  if cargo tauri --version >/dev/null 2>&1; then
    say "tauri-cli already present"
  else
    say "installing tauri-cli (cargo install tauri-cli)"
    cargo install tauri-cli --version '^2' --locked \
      || warn "could not install tauri-cli; 'cargo tauri' commands will be unavailable"
  fi
}

# ---------------------------------------------------------------------------
main() {
  install_scanning_tools
  if [ "$TOOLS_ONLY" -eq 0 ]; then
    install_rust
    [ "$WITH_NODE" -eq 1 ] && install_node
    [ "$WITH_DESKTOP" -eq 1 ] && install_desktop_deps
  fi

  say "done. verify with:"
  echo "    cargo run -p moosemap-cli -- tools"
  if [ "$WITH_DESKTOP" -eq 1 ]; then
    echo "    make app-build   # build the desktop app (.deb/AppImage)"
  fi
  echo
  warn "reminder: only scan assets you are explicitly authorized to test."
}

main
