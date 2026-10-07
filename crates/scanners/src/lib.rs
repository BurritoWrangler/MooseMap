//! # moosemap-scanners
//!
//! Concrete [`moosemap_core::StageExecutor`] implementations that drive external
//! recon/scanning tools, plus helpers for locating and running those tools.
//!
//! ## Implemented (real adapters)
//! - [`nmap`] — host discovery, port scan, service/version enumeration.
//! - [`subfinder`] — passive subdomain enumeration for in-scope domains.
//! - [`httpx`] — web recon: confirms live HTTP(S) endpoints from open services.
//! - [`nuclei`] — template-based vulnerability scanning of web endpoints.
//! - [`heuristics`] — version-based vuln heuristics (no external tool required).
//!
//! ## Planned (stubbed, skip gracefully)
//! - [`stubs::MasscanPortScan`] (high-rate port sweeping).
//!
//! Use [`default_executors`] to get the standard pipeline wiring.

use std::sync::Arc;

use moosemap_core::StageExecutor;

pub mod heuristics;
pub mod httpx;
pub mod nmap;
pub mod nuclei;
pub mod stubs;
pub mod subfinder;
pub mod tool;

/// The default set of stage executors for a standard external assessment.
///
/// Order matters within a stage: executors run in registration order, and later
/// stages read what earlier ones produced. The web-recon stage (httpx) confirms
/// HTTP endpoints that the vuln-scan stage (nuclei) then targets; the version
/// heuristics run alongside nuclei so there is vuln signal even without it.
pub fn default_executors() -> Vec<Arc<dyn StageExecutor>> {
    vec![
        // Discovery: subfinder expands domains into subdomains, nmap confirms
        // which hosts are live. subfinder runs first so its subdomains are
        // available as targets for subsequent stages.
        Arc::new(subfinder::SubfinderDiscovery),
        Arc::new(nmap::NmapDiscovery),
        // Port scan
        Arc::new(nmap::NmapPortScan::default()),
        Arc::new(stubs::MasscanPortScan),
        // Service enumeration
        Arc::new(nmap::NmapServiceEnum),
        // Web recon
        Arc::new(httpx::HttpxWebRecon),
        // Vulnerability scanning: real scanner first, then always-on heuristics.
        Arc::new(nuclei::NucleiVulnScan),
        Arc::new(heuristics::VersionHeuristics),
        // Prioritize + Report stages are provided by the orchestrator layer
        // (see moosemap-report), not by scanners.
    ]
}

/// Report which known external tools are available on this host.
pub fn tool_availability() -> Vec<(&'static str, bool)> {
    ["nmap", "masscan", "subfinder", "httpx", "nuclei"]
        .into_iter()
        .map(|t| (t, tool::is_installed(t)))
        .collect()
}

/// Per-tool diagnostic status for the `tools` doctor command.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolStatus {
    /// Canonical tool name, e.g. "httpx".
    pub name: &'static str,
    /// Binary MooseMap would actually invoke (after env override), if resolvable.
    pub resolved_path: Option<String>,
    /// Overall health: "ok", "missing", or "wrong".
    pub state: &'static str,
    /// Human-readable detail (e.g. the Python-httpx warning, or an install hint).
    pub detail: String,
    /// What this tool contributes to the pipeline.
    pub role: &'static str,
    /// How to install it on Kali/Debian.
    pub install_hint: &'static str,
}

/// Produce a full, Kali-aware diagnostic for every known tool.
///
/// For the ProjectDiscovery tools this runs the same resolve+verify path the
/// adapters use, so the operator sees exactly what each stage will do — including
/// catching the Python `httpx` that shadows ProjectDiscovery's on Kali.
pub async fn tool_report() -> Vec<ToolStatus> {
    async fn pd(
        name: &'static str,
        role: &'static str,
        hint: &'static str,
    ) -> ToolStatus {
        let bin = tool::resolve_binary(name);
        let resolved_path = tool::which(&bin).map(|p| p.display().to_string());
        let (state, detail) = match tool::verify_projectdiscovery(&bin, name).await {
            tool::ToolCheck::Ok => ("ok", format!("verified ProjectDiscovery {name}")),
            tool::ToolCheck::Missing => ("missing", format!("{name} not found on PATH")),
            tool::ToolCheck::Wrong(reason) => ("wrong", reason),
        };
        ToolStatus { name, resolved_path, state, detail, role, install_hint: hint }
    }

    fn plain(
        name: &'static str,
        role: &'static str,
        hint: &'static str,
        extra: &str,
    ) -> ToolStatus {
        let bin = tool::resolve_binary(name);
        let resolved_path = tool::which(&bin).map(|p| p.display().to_string());
        let (state, detail) = if resolved_path.is_some() {
            ("ok", format!("found{extra}"))
        } else {
            ("missing", format!("{name} not found on PATH"))
        };
        ToolStatus { name, resolved_path, state, detail, role, install_hint: hint }
    }

    vec![
        plain(
            "nmap",
            "discovery, port scan, service/version enum",
            "sudo apt install -y nmap",
            " (run MooseMap with sudo for SYN scans; unprivileged falls back to TCP connect)",
        ),
        plain(
            "masscan",
            "high-rate port sweeping (planned)",
            "sudo apt install -y masscan",
            " (requires root/CAP_NET_RAW)",
        ),
        pd(
            "subfinder",
            "passive subdomain enumeration",
            "sudo apt install -y subfinder  # or: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        )
        .await,
        pd(
            "httpx",
            "web recon (HTTP probing, tech/title)",
            "sudo apt install -y httpx-toolkit  # PD httpx; avoid the Python 'httpx' CLI",
        )
        .await,
        pd(
            "nuclei",
            "template-based vulnerability scanning",
            "sudo apt install -y nuclei && nuclei -update-templates",
        )
        .await,
    ]
}
