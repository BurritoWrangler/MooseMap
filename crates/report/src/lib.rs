//! # moosemap-report
//!
//! Prioritization scoring and report generation (JSON + Markdown) for a run's
//! services and findings.
//!
//! Typical use after an engine run:
//!
//! ```no_run
//! use moosemap_report::{Report, prioritize};
//! # use moosemap_core::{Run, Service, Finding};
//! # fn demo(run: Run, services: Vec<Service>, mut findings: Vec<Finding>) {
//! prioritize::prioritize(&mut findings);
//! let report = Report::build(&run, services, findings);
//! let json = report.to_json().unwrap();
//! let md = report.to_markdown();
//! # }
//! ```

pub mod prioritize;

use chrono::{DateTime, Utc};
use moosemap_core::model::{Finding, Run, Service, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A complete, serializable assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub run_id: uuid::Uuid,
    pub name: String,
    pub scope: Vec<String>,
    pub generated_at: DateTime<Utc>,
    pub summary: Summary,
    pub services: Vec<Service>,
    /// Findings, already prioritized (highest first).
    pub findings: Vec<Finding>,
}

/// Executive summary counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_targets: usize,
    pub total_open_ports: usize,
    pub total_findings: usize,
    /// Count of findings at each severity, keyed by severity name.
    pub by_severity: BTreeMap<String, usize>,
    /// Findings considered actionable (>= Medium).
    pub actionable: usize,
    /// The highest-priority finding titles (up to 5), for an at-a-glance view.
    pub top_priorities: Vec<String>,
}

impl Report {
    /// Build a report from a run plus its collected services and (already
    /// prioritized) findings. If findings aren't yet prioritized, call
    /// [`prioritize::prioritize`] first.
    pub fn build(run: &Run, services: Vec<Service>, findings: Vec<Finding>) -> Self {
        let total_open_ports = services.len();
        let targets: std::collections::BTreeSet<String> =
            services.iter().map(|s| s.target.to_string()).collect();

        let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            by_severity.insert(sev.to_string(), 0);
        }
        for f in &findings {
            *by_severity.entry(f.severity.to_string()).or_insert(0) += 1;
        }

        let actionable = findings.iter().filter(|f| prioritize::is_actionable(f)).count();
        let top_priorities = findings
            .iter()
            .filter(|f| prioritize::is_actionable(f))
            .take(5)
            .map(|f| f.title.clone())
            .collect();

        let summary = Summary {
            total_targets: targets.len(),
            total_open_ports,
            total_findings: findings.len(),
            by_severity,
            actionable,
            top_priorities,
        };

        Report {
            run_id: run.id,
            name: run.name.clone(),
            scope: run.scope.clone(),
            generated_at: Utc::now(),
            summary,
            services,
            findings,
        }
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Render a human-readable Markdown report.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# MooseMap Assessment Report: {}\n\n", self.name));
        md.push_str("> ⚠️ Authorized testing only. This report documents findings from an authorized external assessment.\n\n");
        md.push_str(&format!(
            "- **Run ID:** `{}`\n- **Generated:** {}\n- **Scope:** {}\n\n",
            self.run_id,
            self.generated_at.to_rfc3339(),
            if self.scope.is_empty() {
                "(none)".to_string()
            } else {
                self.scope.join(", ")
            }
        ));

        // Summary
        md.push_str("## Executive summary\n\n");
        md.push_str(&format!(
            "- Targets with open ports: **{}**\n- Open ports: **{}**\n- Findings: **{}** ({} actionable)\n\n",
            self.summary.total_targets,
            self.summary.total_open_ports,
            self.summary.total_findings,
            self.summary.actionable,
        ));

        md.push_str("| Severity | Count |\n|---|---|\n");
        for sev in ["critical", "high", "medium", "low", "info"] {
            let n = self.summary.by_severity.get(sev).copied().unwrap_or(0);
            md.push_str(&format!("| {sev} | {n} |\n"));
        }
        md.push('\n');

        if !self.summary.top_priorities.is_empty() {
            md.push_str("### Top priorities\n\n");
            for (i, t) in self.summary.top_priorities.iter().enumerate() {
                md.push_str(&format!("{}. {t}\n", i + 1));
            }
            md.push('\n');
        }

        // Prioritized findings
        md.push_str("## Prioritized findings\n\n");
        if self.findings.is_empty() {
            md.push_str("_No findings recorded._\n\n");
        } else {
            for (i, f) in self.findings.iter().enumerate() {
                let loc = match f.port {
                    Some(p) => format!("{}:{}", f.target, p),
                    None => f.target.to_string(),
                };
                md.push_str(&format!(
                    "### {}. {} ({})\n\n",
                    i + 1,
                    f.title,
                    f.severity
                ));
                md.push_str(&format!(
                    "- **Target:** `{loc}`\n- **Severity:** {}\n- **Exploitability:** {:?}\n- **Priority score:** {:.2}\n- **Source:** {}\n",
                    f.severity, f.exploitability, f.priority, f.source
                ));
                if !f.references.is_empty() {
                    md.push_str(&format!("- **References:** {}\n", f.references.join(", ")));
                }
                md.push_str(&format!("\n{}\n\n", f.description));
            }
        }

        // Service inventory
        md.push_str("## Service inventory\n\n");
        if self.services.is_empty() {
            md.push_str("_No open services discovered._\n");
        } else {
            md.push_str("| Target | Port | Proto | Service | Product/Version |\n");
            md.push_str("|---|---|---|---|---|\n");
            for s in &self.services {
                let banner = [s.product.clone(), s.version.clone()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    s.target,
                    s.port,
                    s.protocol,
                    s.service_name.clone().unwrap_or_default(),
                    banner
                ));
            }
        }
        md.push('\n');

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::model::{Exploitability, PortState, Protocol, Severity, Target};

    fn sample_run() -> Run {
        Run::new("acme-ext", vec!["192.0.2.0/24".into(), "example.com".into()])
    }

    fn sample_services() -> Vec<Service> {
        vec![Service {
            target: Target::Ip("192.0.2.10".parse().unwrap()),
            port: 443,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: Some("https".into()),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
        }]
    }

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding::new(
                Target::Ip("192.0.2.10".parse().unwrap()),
                Some(443),
                "Critical RCE in web stack",
                "desc",
                Severity::Critical,
                Exploitability::Active,
                "nuclei",
            ),
            Finding::new(
                Target::Ip("192.0.2.10".parse().unwrap()),
                Some(443),
                "Exposed service: https",
                "desc",
                Severity::Info,
                Exploitability::None,
                "nmap",
            ),
        ]
    }

    #[test]
    fn builds_summary_counts() {
        let run = sample_run();
        let mut findings = sample_findings();
        prioritize::prioritize(&mut findings);
        let report = Report::build(&run, sample_services(), findings);

        assert_eq!(report.summary.total_open_ports, 1);
        assert_eq!(report.summary.total_targets, 1);
        assert_eq!(report.summary.total_findings, 2);
        assert_eq!(report.summary.actionable, 1);
        assert_eq!(report.summary.by_severity.get("critical"), Some(&1));
        assert_eq!(report.summary.by_severity.get("info"), Some(&1));
        // Highest priority finding comes first.
        assert_eq!(report.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn json_roundtrips() {
        let run = sample_run();
        let report = Report::build(&run, sample_services(), sample_findings());
        let json = report.to_json().unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back.run_id, report.run_id);
        assert_eq!(back.findings.len(), 2);
    }

    #[test]
    fn markdown_contains_key_sections() {
        let run = sample_run();
        let mut findings = sample_findings();
        prioritize::prioritize(&mut findings);
        let md = Report::build(&run, sample_services(), findings).to_markdown();
        assert!(md.contains("# MooseMap Assessment Report"));
        assert!(md.contains("## Executive summary"));
        assert!(md.contains("## Prioritized findings"));
        assert!(md.contains("## Service inventory"));
        assert!(md.contains("Critical RCE in web stack"));
        assert!(md.contains("nginx 1.24.0"));
    }
}
