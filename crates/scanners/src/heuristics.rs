//! Version-based vulnerability heuristics.
//!
//! A [`StageExecutor`] for the vuln-scan stage that needs **no external tools**.
//! It inspects the product/version banners captured by nmap `-sV` and flags
//! software that is end-of-life, commonly misconfigured, or carries well-known
//! classes of issues. This guarantees some actionable vuln signal even when
//! nuclei isn't installed.
//!
//! The ruleset here is intentionally small and conservative — it is a starting
//! point, not a CVE database. Each rule explains *why* it fires and points at a
//! reference so the operator can verify. nuclei remains the authoritative
//! scanner when available.

use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{Exploitability, Finding, Service, Severity, Stage};

/// A single heuristic rule over a discovered service.
struct Rule {
    /// Matches against the lowercased "product version service_name" banner.
    keywords: &'static [&'static str],
    title: &'static str,
    description: &'static str,
    severity: Severity,
    exploitability: Exploitability,
    references: &'static [&'static str],
}

/// The built-in ruleset. Kept small and explainable on purpose.
const RULES: &[Rule] = &[
    Rule {
        keywords: &["telnet"],
        title: "Cleartext Telnet service exposed",
        description:
            "Telnet transmits credentials and session data in cleartext and is \
             trivially sniffable or hijackable on the network path. It should be \
             replaced with SSH.",
        severity: Severity::High,
        exploitability: Exploitability::ProofOfConcept,
        references: &["https://attack.mitre.org/techniques/T1040/"],
    },
    Rule {
        keywords: &["ftp"],
        title: "FTP service exposed",
        description:
            "FTP authenticates and transfers data in cleartext. Where anonymous \
             access or weak credentials are allowed it frequently leads to data \
             exposure. Prefer SFTP/FTPS.",
        severity: Severity::Medium,
        exploitability: Exploitability::Theoretical,
        references: &["https://owasp.org/www-community/vulnerabilities/"],
    },
    Rule {
        keywords: &["vsftpd 2.3.4"],
        title: "vsftpd 2.3.4 backdoor",
        description:
            "vsftpd 2.3.4 shipped with a well-known backdoor that grants a root \
             shell on connection. This is actively exploited and must be patched \
             immediately.",
        severity: Severity::Critical,
        exploitability: Exploitability::Active,
        references: &["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    Rule {
        keywords: &["openssh 7.", "openssh 6.", "openssh 5."],
        title: "Outdated OpenSSH version",
        description:
            "This OpenSSH release is end-of-life and carries multiple published \
             CVEs (e.g. user enumeration, auth issues). Upgrade to a current \
             release.",
        severity: Severity::Medium,
        exploitability: Exploitability::ProofOfConcept,
        references: &["https://www.openssh.com/security.html"],
    },
    Rule {
        keywords: &["smbv1", "microsoft-ds", "netbios-ssn"],
        title: "SMB service exposed to the perimeter",
        description:
            "SMB/NetBIOS exposed externally is a high-value target (e.g. \
             EternalBlue-class issues on SMBv1). It should not be reachable from \
             untrusted networks.",
        severity: Severity::High,
        exploitability: Exploitability::Active,
        references: &["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    Rule {
        keywords: &["apache httpd 2.2", "apache httpd 2.0"],
        title: "End-of-life Apache httpd",
        description:
            "Apache httpd 2.0/2.2 are end-of-life and unpatched against numerous \
             CVEs. Upgrade to a supported 2.4.x release.",
        severity: Severity::High,
        exploitability: Exploitability::ProofOfConcept,
        references: &["https://httpd.apache.org/security/vulnerabilities_24.html"],
    },
    Rule {
        keywords: &["nginx 1.1", "nginx 1.0", "nginx 0."],
        title: "Outdated nginx version",
        description:
            "This nginx release is old and likely unpatched. Review for known \
             CVEs and upgrade to a current stable release.",
        severity: Severity::Medium,
        exploitability: Exploitability::Theoretical,
        references: &["https://nginx.org/en/security_advisories.html"],
    },
    Rule {
        keywords: &["mysql 5.0", "mysql 5.1", "mysql 5.5"],
        title: "End-of-life MySQL exposed",
        description:
            "An end-of-life MySQL version is reachable. Besides missing security \
             patches, database services should rarely be exposed externally.",
        severity: Severity::High,
        exploitability: Exploitability::Theoretical,
        references: &["https://www.oracle.com/security-alerts/"],
    },
    Rule {
        keywords: &["redis"],
        title: "Redis service exposed",
        description:
            "Redis exposed without authentication allows arbitrary data access \
             and, in many configurations, remote code execution via module/\
             config abuse. It must not be internet-facing.",
        severity: Severity::High,
        exploitability: Exploitability::Active,
        references: &["https://redis.io/docs/management/security/"],
    },
];

/// Build the lowercased banner string a rule matches against.
fn banner_of(svc: &Service) -> String {
    [
        svc.product.clone(),
        svc.version.clone(),
        svc.service_name.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase()
}

/// Evaluate the ruleset against one service, returning any matched findings.
fn evaluate(svc: &Service) -> Vec<Finding> {
    let banner = banner_of(svc);
    if banner.trim().is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for rule in RULES {
        if rule.keywords.iter().any(|kw| banner.contains(kw)) {
            let finding = Finding::new(
                svc.target.clone(),
                Some(svc.port),
                rule.title,
                format!("{} (observed: {})", rule.description, banner.trim()),
                rule.severity,
                rule.exploitability,
                "version-heuristics",
            )
            .with_references(rule.references.iter().map(|s| s.to_string()).collect());
            out.push(finding);
        }
    }
    out
}

/// Flags risky/outdated software from service banners. Always runs.
pub struct VersionHeuristics;

#[async_trait]
impl StageExecutor for VersionHeuristics {
    fn stage(&self) -> Stage {
        Stage::VulnScan
    }
    fn name(&self) -> &str {
        "version-heuristics"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let services: Vec<Service> = {
            let state = ctx.state.lock().await;
            state.services.clone()
        };
        if services.is_empty() {
            return Ok(StageOutcome::Skipped("no services to evaluate".into()));
        }

        let mut count = 0usize;
        for svc in &services {
            for finding in evaluate(svc) {
                ctx.add_finding(finding).await;
                count += 1;
            }
        }
        ctx.info(format!("version heuristics produced {count} finding(s)"));
        Ok(StageOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::model::{PortState, Protocol, Target};

    fn svc(product: &str, version: &str, name: &str, port: u16) -> Service {
        Service {
            target: Target::Ip("192.0.2.1".parse().unwrap()),
            port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: Some(name.to_string()),
            product: Some(product.to_string()),
            version: Some(version.to_string()),
        }
    }

    #[test]
    fn flags_vsftpd_backdoor_as_critical_active() {
        let f = evaluate(&svc("vsftpd", "2.3.4", "ftp", 21));
        // Both the generic ftp rule and the vsftpd backdoor rule fire.
        assert!(f.iter().any(|x| x.severity == Severity::Critical
            && x.exploitability == Exploitability::Active));
    }

    #[test]
    fn flags_outdated_openssh() {
        let f = evaluate(&svc("OpenSSH", "7.4", "ssh", 22));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(!f[0].references.is_empty());
    }

    #[test]
    fn clean_modern_service_has_no_findings() {
        let f = evaluate(&svc("OpenSSH", "9.6", "ssh", 22));
        assert!(f.is_empty());
    }

    #[test]
    fn empty_banner_no_findings() {
        let mut s = svc("", "", "", 1234);
        s.product = None;
        s.version = None;
        s.service_name = None;
        assert!(evaluate(&s).is_empty());
    }
}
