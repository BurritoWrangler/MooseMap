#!/usr/bin/env bash
#
# moosemap-launch.sh — launcher used by the desktop/menu entry.
#
# Starts the MooseMap server (which serves the GUI and opens the browser) and
# keeps it attached to this terminal so you can see logs and press Ctrl-C to
# stop. Closing the terminal stops MooseMap — deliberate for a scanning tool you
# don't want running unattended.
#
# Resolution order for the binary:
#   1. $MOOSEMAP_BIN if set
#   2. `moosemap` on PATH (installed)
#   3. target/release/moosemap relative to the repo (source checkout)
#   4. `cargo run` as a last resort (dev)

set -euo pipefail

ADDR="${MOOSEMAP_ADDR:-127.0.0.1:8080}"

find_bin() {
  if [ -n "${MOOSEMAP_BIN:-}" ] && [ -x "${MOOSEMAP_BIN}" ]; then
    echo "${MOOSEMAP_BIN}"; return 0
  fi
  if command -v moosemap >/dev/null 2>&1; then
    command -v moosemap; return 0
  fi
  # Repo-relative release build (this script lives in <repo>/scripts).
  local here repo
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  repo="$(dirname "$here")"
  if [ -x "$repo/target/release/moosemap" ]; then
    echo "$repo/target/release/moosemap"; return 0
  fi
  return 1
}

echo "Starting MooseMap on http://${ADDR} …"
echo "(Close this window or press Ctrl-C to stop the server.)"
echo

if BIN="$(find_bin)"; then
  exec "$BIN" serve --addr "$ADDR"
else
  # Dev fallback: run from source if a built binary isn't available.
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  repo="$(dirname "$here")"
  cd "$repo"
  exec cargo run -p moosemap-cli -- serve --addr "$ADDR"
fi
