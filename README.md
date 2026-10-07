# MooseMap

MooseMap is a Rust-based orchestrator that automates an **authorized** external
penetration test / attack-surface assessment. You give it a scope (IP addresses,
CIDR blocks, or FQDNs), and it drives a suite of recon and scanning tools through
a staged pipeline, tracks progress in real time, and produces a prioritized report
of exploitable findings.

It ships with a modern, accessible web GUI (React + TypeScript) backed by an
async Rust engine (Tokio + axum) with live WebSocket status updates.

> ## ⚠️ Authorized use only
>
> MooseMap performs active scanning that can be intrusive. **Only run it against
> assets you own or are explicitly authorized in writing to test.** Unauthorized
> scanning may be illegal. MooseMap enforces a declared scope and refuses to act
> on any target outside it, but *you* are responsible for having authorization.

## Architecture

A Cargo workspace of focused crates:

| Crate                | Responsibility |
|----------------------|----------------|
| `crates/core`        | Domain models, scope parsing, scope guard, pipeline engine, task tracking |
| `crates/scanners`    | `StageExecutor` trait + tool adapters (nmap, subfinder, httpx, nuclei + version heuristics real; masscan stubbed) |
| `crates/report`      | Prioritization scoring + JSON/Markdown report generation |
| `crates/server`      | axum REST API + WebSocket live updates + SQLite persistence; serves the frontend |
| `crates/cli`         | `clap` CLI to launch the server or run headless scans |
| `frontend/`          | Vite + React + TypeScript accessible GUI |

### Pipeline stages

```
discovery -> port scan -> service enum -> web recon -> vuln scan -> prioritize -> report
```

Each (target, stage) is a tracked task with a status (queued / running / done /
failed / skipped). Status changes are broadcast over WebSocket for live tracking.

## Prerequisites

- **Rust** 1.80+ (`rustc`, `cargo`)
- **Node.js** 18+ and npm (only to build/develop the frontend)
- External recon tools on `PATH` (optional but recommended; adapters degrade
  gracefully and report when a tool is missing):
  - [`nmap`](https://nmap.org/) — **implemented** (discovery, port scan, service/version enum)
  - [`subfinder`](https://github.com/projectdiscovery/subfinder) — **implemented** (passive subdomain enumeration)
  - [`httpx`](https://github.com/projectdiscovery/httpx) — **implemented** (web recon)
  - [`nuclei`](https://github.com/projectdiscovery/nuclei) — **implemented** (vulnerability scanning)
  - `masscan` — stubbed, planned

Version-based vulnerability heuristics run with **no external tool required**,
so you still get actionable vuln signal from service banners even without nuclei.

On macOS: `brew install nmap httpx nuclei subfinder`

`subfinder` only enumerates subdomains that fall within your declared scope —
add a wildcard entry like `*.example.com` to include discovered subdomains, or
they are dropped as out of scope.

## Kali Quick Start

Kali Linux is the recommended host. A helper script installs the scanning tools,
Rust, and Node:

```bash
./scripts/setup-kali.sh          # tools + Rust + Node (GUI)
./scripts/setup-kali.sh --tools  # scanning tools only
```

Then confirm everything resolves correctly:

```bash
cargo run -p moosemap-cli -- tools   # the "doctor": shows each tool's path + status
```

Kali-specific notes the doctor and adapters account for:

- **`httpx` shadowing.** Kali may have a Python `httpx` HTTP-client CLI on
  `PATH` that is **not** ProjectDiscovery's `httpx`. MooseMap verifies the binary
  (`httpx -version`) and *skips with a clear message* rather than misparsing the
  wrong tool. Install ProjectDiscovery's (`apt install httpx-toolkit`) or point
  MooseMap at it explicitly:

  ```bash
  export MOOSEMAP_HTTPX="$(go env GOPATH)/bin/httpx"
  ```

  Any tool's binary can be overridden with `MOOSEMAP_<TOOL>` (e.g.
  `MOOSEMAP_NUCLEI`, `MOOSEMAP_SUBFINDER`).

- **Privileges.** `nmap`'s SYN scan and `masscan` need root/`CAP_NET_RAW`. Run
  MooseMap with `sudo` for best results; unprivileged, nmap falls back to a TCP
  connect scan (slower, still works).

- **nuclei templates.** The first run downloads templates. `setup-kali.sh` runs
  `nuclei -update-templates` for you; otherwise it happens mid-scan.

- **Binding.** The server binds `127.0.0.1:8080` by default (localhost only). To
  reach the GUI from your host machine, bind the VM's interface explicitly and
  understand you are exposing the API:
  `cargo run -p moosemap-cli -- serve --addr 0.0.0.0:8080`.

### How findings become "actionable"

The vuln-scan stage produces [`Finding`]s with a severity and an inferred
*exploitability*:

- **nuclei** maps template severity directly and infers exploitability from
  template metadata: a `kev`/`known-exploited` tag ⇒ *active*, a referenced CVE ⇒
  *proof-of-concept*, otherwise *theoretical*.
- **version heuristics** flag end-of-life / commonly-exploited software (e.g. the
  vsftpd 2.3.4 backdoor, exposed Redis, SMBv1) from `nmap -sV` banners.

The prioritizer scores each finding as
`severity × exploitability × confirmation_boost × cve_boost` and sorts the
report so the most practically exploitable items come first. The executive
summary counts "actionable" items (Medium+ severity, or anything with a known
exploit or referenced CVE).

## Build & run

The GUI is the primary interface. The whole flow is three `make` targets:

```bash
make setup    # install scanning tools, Rust, and Node (Kali/Debian)
make build    # build the web GUI + the release binary
make run      # launch the server and open the GUI in your browser
```

`make run` serves the built GUI, prints a clickable URL, and opens your default
browser. Set `MOOSEMAP_NO_OPEN=1` to skip auto-opening (headless/SSH/CI). Run
`make help` to see all targets, and `make doctor` to check tool readiness from
the terminal.

### The workflow, in the GUI

1. **Check readiness** — the sidebar's *Scanner readiness* panel shows which
   tools are installed and resolve correctly (and flags the Kali `httpx`
   shadowing problem) before you scan.
2. **Define scope & start** — enter authorized IPs/CIDRs/domains and launch.
3. **Track live** — stages and findings stream in over WebSocket.
4. **Export the report** — on a finished run, download the prioritized report
   as **Markdown** or **JSON** from the run header.

### Running without Make

```bash
cd frontend && npm install && npm run build && cd ..   # build GUI (Node 18+)
cargo run -p moosemap-cli -- serve                     # serve + open browser

# Flags / env vars:
#   --addr 127.0.0.1:8080                 (MOOSEMAP_ADDR)
#   --database-url sqlite://moosemap.db   (MOOSEMAP_DB)
#   --frontend-dir frontend/dist          (MOOSEMAP_FRONTEND)
#   MOOSEMAP_NO_OPEN=1                    (don't auto-open the browser)
```

During frontend development, run the Vite dev server (which proxies `/api`
and the WebSocket to the backend on `:8080`):

```bash
cargo run -p moosemap-cli -- serve           # terminal 1 (backend)
cd frontend && npm run dev                    # terminal 2 (http://localhost:5173)
```

### Headless CLI scan

```bash
# Active scanning requires an explicit authorization acknowledgement.
cargo run -p moosemap-cli -- scan \
  --name "acme-ext" \
  --scope "192.0.2.0/24, example.com, *.staging.example.com" \
  --i-am-authorized \
  --json-out report.json \
  --md-out report.md

# Check which external tools are installed
cargo run -p moosemap-cli -- tools
```

Without `--json-out`/`--md-out`, the Markdown report is printed to stdout.
Missing external tools cause their stages to be **skipped**, not fail, so the
pipeline always runs end to end.

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/health`               | Liveness/version |
| GET  | `/api/tools`                | Tool doctor: per-tool path, state, role, install hint |
| GET  | `/api/runs`                 | List assessments |
| POST | `/api/runs`                 | Create (`{name, scope, start}`) |
| GET  | `/api/runs/:id`             | Get a run |
| POST | `/api/runs/:id/start`       | Start scanning |
| GET  | `/api/runs/:id/tasks`       | Per-stage task status |
| GET  | `/api/runs/:id/report`      | Full prioritized report (JSON for the UI) |
| GET  | `/api/runs/:id/report.json` | Download report as a JSON attachment |
| GET  | `/api/runs/:id/report.md`   | Download report as a Markdown attachment |
| GET  | `/api/events`               | WebSocket live event stream |

## Accessibility

The GUI is built for WCAG-minded use: semantic landmarks and a skip link,
keyboard-reachable controls with visible `:focus-visible` outlines, status
conveyed by text + shape (not color alone), an ARIA live region announcing
real-time status changes, and support for `prefers-reduced-motion` and
`prefers-color-scheme`. Full conformance still requires manual testing with
assistive technologies and expert review.

## License

MIT
