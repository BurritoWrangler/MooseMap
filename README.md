# MooseMap

MooseMap is a Rust-based orchestrator that automates an **authorized** external
penetration test / attack-surface assessment. You give it a scope (IP addresses,
CIDR blocks, or FQDNs), and it drives a suite of recon and scanning tools through
a staged pipeline, tracks progress in real time, and produces a prioritized report
of exploitable findings.

MooseMap runs as a **native desktop application** (Tauri): a modern, accessible
GUI (React + TypeScript) in its own window, backed by an async Rust engine
(Tokio + axum) that runs in-process with live status updates. A headless
server/CLI mode is also available for remote and automation use.

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
| `crates/server`      | axum REST API + WebSocket live updates + SQLite persistence; serves the frontend (runs in-process inside the desktop app) |
| `crates/cli`         | `clap` CLI for headless scans and the optional server mode |
| `src-tauri/`         | **The desktop app** (Tauri): native window hosting the GUI + in-process server |
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

## Kali notes

Kali Linux is the recommended host. `make setup` (which runs
`./scripts/setup-kali.sh --desktop`) installs the scanning tools, Rust, Node,
and the Tauri desktop-build dependencies. Confirm tooling resolves with
`make doctor` (or `cargo run -p moosemap-cli -- tools`).

Kali-specific details the doctor and adapters handle for you:

- **`httpx` naming.** On Kali, ProjectDiscovery's httpx is packaged as
  `httpx-toolkit` (the plain `httpx` is the unrelated Python client). MooseMap
  **auto-detects `httpx-toolkit`** — no configuration needed. You can still pin a
  specific binary with `MOOSEMAP_HTTPX`, and any tool with `MOOSEMAP_<TOOL>`
  (e.g. `MOOSEMAP_NUCLEI`, `MOOSEMAP_SUBFINDER`).

- **Privileges.** `nmap`'s SYN scan and `masscan` need root/`CAP_NET_RAW`. Launch
  MooseMap with `sudo` for best results; unprivileged, nmap falls back to a TCP
  connect scan (slower, still works).

- **nuclei templates.** The first run downloads templates. `make setup` runs
  `nuclei -update-templates` for you; otherwise it happens mid-scan.

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

## Install & run (desktop app)

MooseMap is a **native desktop application**. It runs the whole engine in-process
and shows its GUI in its own window — no browser, no terminal. Three `make`
targets take you from a fresh Kali VM to an installed app:

```bash
make setup    # scanning tools + Rust + Node + desktop (Tauri) build deps
make build    # build the standalone app bundle (.deb / AppImage)
make run      # launch MooseMap in a native window
```

`make build` produces an installable package under
`src-tauri/target/release/bundle/`. Installing it (e.g. `sudo dpkg -i
src-tauri/target/release/bundle/deb/*.deb`) drops **MooseMap** into your
applications menu with its icon, like any other app — launch it from there and
it opens in its own window. Closing the window stops everything (intentional for
a scanning tool you don't want running unattended).

While developing the UI, `make dev` runs the app with a hot-reloading GUI.

### The workflow, in the app

1. **Check readiness** — the *Scanner readiness* panel shows which tools are
   installed and resolve correctly (and flags the Kali `httpx` shadowing
   problem) before you scan.
2. **Define scope & start** — enter authorized IPs/CIDRs/domains and launch.
3. **Track live** — stages and findings stream in in real time.
4. **Export the report** — on a finished run, download the prioritized report
   as **Markdown** or **JSON** from the run header.

Run `make help` for all targets, and `make doctor` to check tool readiness from
the terminal.

## Advanced: headless / remote mode

The same engine and GUI can run as a plain server with **no window** — useful on
a headless VM you reach over SSH, where you'd forward a port and use a browser on
your own machine:

```bash
make headless                       # builds the web GUI, then serves it
# or directly:
cargo run -p moosemap-cli -- serve --addr 0.0.0.0:8080 --open

# Flags / env vars:
#   --addr 127.0.0.1:8080                 (MOOSEMAP_ADDR)
#   --database-url sqlite://moosemap.db   (MOOSEMAP_DB)
#   --frontend-dir frontend/dist          (MOOSEMAP_FRONTEND)
#   --open                                launch a local browser (off by default)
```

`serve` does not open a browser unless you pass `--open`; it just prints the URL.
The desktop app is the normal way to use MooseMap — this mode is for remote/VM
and automation use.

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
