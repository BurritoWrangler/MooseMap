//! Core domain models shared across the engine, scanners, and reporting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// A single resolved thing we can scan: either an IP address or a hostname.
///
/// CIDR blocks and hostnames in the declared scope expand into `Target`s during
/// discovery; a `Target` is the unit a scanner actually acts upon.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    /// A concrete IP address (v4 or v6).
    Ip(std::net::IpAddr),
    /// A fully-qualified domain name.
    Host(String),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Host(h) => write!(f, "{h}"),
        }
    }
}

/// Parse a tool-reported authority (`host[:port]`, optionally scheme/path-wrapped)
/// into a [`Target`] plus an optional port.
///
/// Handles the shapes external tools (nmap/httpx/nuclei) emit:
/// - `https://[2001:db8::1]:8443/path` → `(Ip(2001:db8::1), Some(8443))`
/// - `[2001:db8::1]:443`               → `(Ip(2001:db8::1), Some(443))`
/// - `2001:db8::1`                      → `(Ip(2001:db8::1), None)`
/// - `192.0.2.10:8080`                  → `(Ip(192.0.2.10), Some(8080))`
/// - `http://example.com/x`             → `(Host(example.com), Some(80))` via scheme
/// - `example.com`                      → `(Host(example.com), None)`
///
/// IPv6 is parsed correctly: a *bracketed* host carries an optional `:port`
/// suffix, while a bare colon-bearing string with no brackets is treated as a
/// whole IPv6 address (never split on its internal colons). Ports outside
/// `1..=65535` are rejected (returned as `None`) rather than silently wrapping.
///
/// Returns `None` only if no usable host remains after parsing.
pub fn parse_host_port(input: &str) -> Option<(Target, Option<u16>)> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }

    // Derive a default port from the scheme, then strip scheme + any path.
    let scheme_port = if s.starts_with("https://") {
        Some(443u16)
    } else if s.starts_with("http://") {
        Some(80u16)
    } else {
        None
    };
    let authority = s
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return None;
    }

    // Helper: validate and parse a port string into 1..=65535.
    fn parse_port(p: &str) -> Option<u16> {
        p.parse::<u16>().ok().filter(|&n| n != 0)
    }

    let (host_str, port): (&str, Option<u16>) = if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6: "[addr]" or "[addr]:port".
        match rest.split_once(']') {
            Some((addr, after)) => {
                let port = after
                    .strip_prefix(':')
                    .and_then(parse_port);
                (addr, port)
            }
            None => (authority, None), // malformed; treat whole thing as host
        }
    } else if authority.matches(':').count() >= 2 {
        // Multiple colons, no brackets → a bare IPv6 address (no port).
        (authority, None)
    } else {
        // host:port or bare host (IPv4 / hostname).
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, parse_port(p)),
            None => (authority, None),
        }
    };

    if host_str.is_empty() {
        return None;
    }

    let target = match host_str.parse::<std::net::IpAddr>() {
        Ok(ip) => Target::Ip(ip),
        Err(_) => Target::Host(host_str.to_ascii_lowercase()),
    };

    Some((target, port.or(scheme_port)))
}

/// Transport protocol for a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// The observed state of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// A discovered service on an open port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub target: Target,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    /// e.g. "http", "ssh", "https".
    pub service_name: Option<String>,
    /// Product/version banner, e.g. "nginx 1.24.0".
    pub product: Option<String>,
    pub version: Option<String>,
}

impl Service {
    pub fn endpoint(&self) -> String {
        format!("{}:{}/{}", self.target, self.port, self.protocol)
    }
}

/// A confirmed HTTP(S) endpoint discovered during web recon.
///
/// Produced by the web-recon stage (e.g. httpx) from the open services, and
/// consumed by the vulnerability-scan stage (e.g. nuclei) as its target list.
/// Keeping endpoints separate from raw services lets the vuln scanner focus on
/// things that actually speak HTTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebEndpoint {
    pub target: Target,
    pub port: u16,
    /// "http" or "https".
    pub scheme: String,
    /// Fully-qualified URL, e.g. "https://example.com:8443".
    pub url: String,
    /// HTTP status code from the probe, if obtained.
    pub status_code: Option<u16>,
    /// Page <title>, if any.
    pub title: Option<String>,
    /// Detected technologies / fingerprints.
    pub tech: Vec<String>,
    /// `Server` header, if present.
    pub server: Option<String>,
}

impl WebEndpoint {
    pub fn new(target: Target, port: u16, scheme: impl Into<String>, url: impl Into<String>) -> Self {
        WebEndpoint {
            target,
            port,
            scheme: scheme.into(),
            url: url.into(),
            status_code: None,
            title: None,
            tech: Vec::new(),
            server: None,
        }
    }
}

/// Severity of a finding, ordered so comparisons work (Info < .. < Critical).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// A coarse numeric weight used by the prioritization model.
    pub fn weight(self) -> f32 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 2.5,
            Severity::Medium => 5.0,
            Severity::High => 8.0,
            Severity::Critical => 10.0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

/// How practically exploitable a finding is believed to be. Feeds priority.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Exploitability {
    /// No known practical exploit / informational.
    None,
    /// Theoretical or requires significant preconditions.
    Theoretical,
    /// Public PoC exists.
    ProofOfConcept,
    /// Weaponized/known-exploited; trivially exploitable.
    Active,
}

impl Exploitability {
    pub fn multiplier(self) -> f32 {
        match self {
            Exploitability::None => 0.5,
            Exploitability::Theoretical => 0.8,
            Exploitability::ProofOfConcept => 1.2,
            Exploitability::Active => 1.6,
        }
    }
}

/// A security-relevant observation produced by a scanner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    /// Which target this concerns.
    pub target: Target,
    /// Optional port the finding is tied to.
    pub port: Option<u16>,
    /// Short title, e.g. "Outdated OpenSSH with known CVEs".
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub exploitability: Exploitability,
    /// Which scanner/tool produced it, e.g. "nmap", "nuclei".
    pub source: String,
    /// Related identifiers (CVEs, template IDs, etc.).
    pub references: Vec<String>,
    /// Computed priority score; higher = address sooner. Set by the prioritizer.
    pub priority: f32,
    pub discovered_at: DateTime<Utc>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: Target,
        port: Option<u16>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        exploitability: Exploitability,
        source: impl Into<String>,
    ) -> Self {
        Finding {
            id: Uuid::new_v4(),
            target,
            port,
            title: title.into(),
            description: description.into(),
            severity,
            exploitability,
            source: source.into(),
            references: Vec::new(),
            priority: 0.0,
            discovered_at: Utc::now(),
        }
    }

    pub fn with_references(mut self, refs: Vec<String>) -> Self {
        self.references = refs;
        self
    }
}

/// The ordered stages of the assessment pipeline.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Resolve/expand scope, host discovery.
    Discovery,
    /// Find open ports.
    PortScan,
    /// Identify services/versions on open ports.
    ServiceEnum,
    /// Web-specific recon (HTTP probing, tech fingerprint, content discovery).
    WebRecon,
    /// Vulnerability scanning.
    VulnScan,
    /// Score and prioritize findings.
    Prioritize,
    /// Produce the report.
    Report,
}

impl Stage {
    /// Canonical execution order.
    pub fn ordered() -> &'static [Stage] {
        &[
            Stage::Discovery,
            Stage::PortScan,
            Stage::ServiceEnum,
            Stage::WebRecon,
            Stage::VulnScan,
            Stage::Prioritize,
            Stage::Report,
        ]
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Stage::Discovery => "discovery",
            Stage::PortScan => "port_scan",
            Stage::ServiceEnum => "service_enum",
            Stage::WebRecon => "web_recon",
            Stage::VulnScan => "vuln_scan",
            Stage::Prioritize => "prioritize",
            Stage::Report => "report",
        };
        write!(f, "{s}")
    }
}

/// Lifecycle status of a tracked task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    Done,
    Failed,
    /// Skipped because preconditions weren't met (e.g. tool missing, no targets).
    Skipped,
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Running => "running",
            TaskStatus::Done => "done",
            TaskStatus::Failed => "failed",
            TaskStatus::Skipped => "skipped",
        };
        write!(f, "{s}")
    }
}

/// A tracked unit of work: one stage of the pipeline for a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub run_id: Uuid,
    pub stage: Stage,
    pub status: TaskStatus,
    /// Human-readable detail about current progress.
    pub message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl Task {
    pub fn new(run_id: Uuid, stage: Stage) -> Self {
        Task {
            id: Uuid::new_v4(),
            run_id,
            stage,
            status: TaskStatus::Queued,
            message: None,
            started_at: None,
            finished_at: None,
        }
    }
}

/// Overall status of a scan run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl fmt::Display for RunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RunStatus::Pending => "pending",
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Failed => "failed",
            RunStatus::Cancelled => "cancelled",
        };
        write!(f, "{s}")
    }
}

/// A full assessment run against a declared scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: Uuid,
    pub name: String,
    /// The raw scope entries as the user declared them.
    pub scope: Vec<String>,
    pub status: RunStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Run {
    pub fn new(name: impl Into<String>, scope: Vec<String>) -> Self {
        let now = Utc::now();
        Run {
            id: Uuid::new_v4(),
            name: name.into(),
            scope,
            status: RunStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Target {
        Target::Ip(s.parse().unwrap())
    }

    #[test]
    fn parses_ipv4_with_and_without_port() {
        assert_eq!(parse_host_port("192.0.2.10:8080"), Some((ip("192.0.2.10"), Some(8080))));
        assert_eq!(parse_host_port("192.0.2.10"), Some((ip("192.0.2.10"), None)));
    }

    #[test]
    fn parses_scheme_and_path() {
        assert_eq!(
            parse_host_port("https://example.com/admin"),
            Some((Target::Host("example.com".into()), Some(443)))
        );
        assert_eq!(
            parse_host_port("http://192.0.2.5"),
            Some((ip("192.0.2.5"), Some(80)))
        );
        // Explicit port beats the scheme default.
        assert_eq!(
            parse_host_port("https://example.com:8443/x"),
            Some((Target::Host("example.com".into()), Some(8443)))
        );
    }

    #[test]
    fn parses_bare_ipv6() {
        assert_eq!(parse_host_port("2001:db8::1"), Some((ip("2001:db8::1"), None)));
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        assert_eq!(
            parse_host_port("[2001:db8::1]:8443"),
            Some((ip("2001:db8::1"), Some(8443)))
        );
        assert_eq!(
            parse_host_port("https://[2001:db8::1]:8443/path"),
            Some((ip("2001:db8::1"), Some(8443)))
        );
        // Bracketed with no port.
        assert_eq!(
            parse_host_port("[fe80::1]"),
            Some((ip("fe80::1"), None))
        );
    }

    #[test]
    fn rejects_out_of_range_and_zero_ports() {
        // 70000 must NOT wrap to 4464 — it's rejected (port None), host kept.
        assert_eq!(parse_host_port("192.0.2.10:70000"), Some((ip("192.0.2.10"), None)));
        assert_eq!(parse_host_port("192.0.2.10:0"), Some((ip("192.0.2.10"), None)));
    }

    #[test]
    fn hostname_lowercased() {
        assert_eq!(
            parse_host_port("API.Example.COM:443"),
            Some((Target::Host("api.example.com".into()), Some(443)))
        );
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(parse_host_port(""), None);
        assert_eq!(parse_host_port("   "), None);
        assert_eq!(parse_host_port("http://"), None);
    }
}
