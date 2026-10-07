//! CVE correlation from service version banners (curated offline ruleset).
//!
//! After service/version enumeration, this stage matches each discovered
//! `product + version` against a small, curated set of high-signal CVEs that
//! show up on external perimeters, and emits a [`Finding`] per match.
//!
//! ## Accuracy stance
//!
//! This is a **version-based heuristic, not confirmation**. A banner says
//! "OpenSSH 8.2" — but a distro may have back-ported the fix, so a version
//! match can be a false positive. We therefore:
//!
//! - cap exploitability conservatively: KEV-listed CVEs are [`Exploitability::Active`],
//!   others are [`Exploitability::ProofOfConcept`] at most, never silently "Active";
//! - say so plainly in the finding description;
//! - dedup against findings that already reference the same CVE on the same
//!   target (e.g. nuclei confirmed it), so we never double-count.
//!
//! The matcher is backed by [`crate::version::VersionRange`] (correct numeric +
//! suffix comparison), so the ruleset can later be swapped for a full NVD feed
//! without changing the engine wiring.

use crate::version::VersionRange;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{Exploitability, Finding, Service, Severity, Stage};

/// A single curated CVE rule: a product + affected version range, with scoring
/// metadata. Kept data-only so the ruleset reads like a table.
struct CveRule {
    /// Normalized product key this rule applies to (see [`product_key`]).
    product: &'static str,
    /// Affected version range (NVD-style bounds).
    range: fn() -> VersionRange,
    cve: &'static str,
    cvss: f32,
    /// EPSS exploit-probability (0.0..1.0) if known; informational.
    epss: Option<f32>,
    severity: Severity,
    /// On CISA KEV / known actively exploited.
    kev: bool,
    /// Short human description of the issue.
    title: &'static str,
    reference: &'static str,
}

/// The curated ruleset. Intentionally small and high-precision: entries are
/// things that genuinely appear on external perimeters and matter. Extend as
/// needed; each row is independently testable via [`match_service`].
///
/// Version ranges use real numeric comparison, so e.g. "affected < 1.1.1g"
/// correctly excludes 1.1.1g and later.
fn ruleset() -> Vec<CveRule> {
    vec![
        CveRule {
            product: "openssl",
            range: || VersionRange::from_until("1.0.1", "1.0.1g"),
            cve: "CVE-2014-0160",
            cvss: 7.5,
            epss: Some(0.97),
            severity: Severity::High,
            kev: true,
            title: "OpenSSL Heartbleed memory disclosure",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        },
        CveRule {
            product: "vsftpd",
            range: || VersionRange::exact("2.3.4"),
            cve: "CVE-2011-2523",
            cvss: 9.8,
            epss: Some(0.95),
            severity: Severity::Critical,
            kev: true,
            title: "vsftpd 2.3.4 backdoor (root shell on connect)",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        },
        CveRule {
            product: "openssh",
            // User-enumeration via timing, fixed in 7.7.
            range: || VersionRange::below("7.7"),
            cve: "CVE-2018-15473",
            cvss: 5.3,
            epss: Some(0.80),
            severity: Severity::Medium,
            kev: false,
            title: "OpenSSH username enumeration",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        },
        CveRule {
            product: "apache httpd",
            // Path traversal / RCE, fixed in 2.4.51 (2.4.49 and 2.4.50 affected).
            range: || VersionRange::from_until("2.4.49", "2.4.51"),
            cve: "CVE-2021-41773",
            cvss: 9.8,
            epss: Some(0.97),
            severity: Severity::Critical,
            kev: true,
            title: "Apache httpd path traversal & RCE",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
        CveRule {
            product: "nginx",
            // Example: DNS resolver off-by-one range affecting < 1.21.0 line.
            range: || VersionRange::below("1.21.0"),
            cve: "CVE-2021-23017",
            cvss: 7.7,
            epss: Some(0.30),
            severity: Severity::High,
            kev: false,
            title: "nginx resolver off-by-one heap write",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        },
        CveRule {
            product: "proftpd",
            range: || VersionRange::from_until("1.3.5", "1.3.5a"),
            cve: "CVE-2015-3306",
            cvss: 9.8,
            epss: Some(0.94),
            severity: Severity::Critical,
            kev: false,
            title: "ProFTPD mod_copy unauthenticated file copy/RCE",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
        },
        CveRule {
            product: "exim",
            range: || VersionRange::below("4.92"),
            cve: "CVE-2019-10149",
            cvss: 9.8,
            epss: Some(0.90),
            severity: Severity::Critical,
            kev: true,
            title: "Exim RCE (The Return of the WIZard)",
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
        },
    ]
}

/// Normalize a service's product string to a match key.
///
/// nmap `-sV` product strings vary ("OpenSSH", "Apache httpd", "nginx",
/// "ProFTPD", "Exim smtpd"). We lowercase and collapse to a stable key, mapping
/// a few known aliases. Returns `None` if there's no usable product.
fn product_key(service_name: Option<&str>, product: Option<&str>) -> Option<String> {
    let raw = product
        .filter(|s| !s.trim().is_empty())
        .or(service_name)?
        .to_ascii_lowercase();

    // Map common nmap product spellings to our ruleset keys.
    let key = if raw.contains("openssh") {
        "openssh"
    } else if raw.contains("apache") && raw.contains("httpd") {
        "apache httpd"
    } else if raw.contains("nginx") {
        "nginx"
    } else if raw.contains("openssl") {
        "openssl"
    } else if raw.contains("vsftpd") {
        "vsftpd"
    } else if raw.contains("proftpd") {
        "proftpd"
    } else if raw.contains("exim") {
        "exim"
    } else {
        // Fall back to the raw lowercased product; still comparable to keys.
        return Some(raw);
    };
    Some(key.to_string())
}

/// Match a single service against the ruleset, returning the CVEs that apply.
/// Pure function, exposed for testing.
fn match_service(service_name: Option<&str>, product: Option<&str>, version: Option<&str>) -> Vec<&'static CveRule> {
    let (Some(key), Some(ver)) = (product_key(service_name, product), version) else {
        return Vec::new();
    };
    // Hold the ruleset in a process-wide static so we can return &'static
    // references (std OnceLock — no extra dependency).
    use std::sync::OnceLock;
    static RULES: OnceLock<Vec<CveRule>> = OnceLock::new();
    RULES
        .get_or_init(ruleset)
        .iter()
        .filter(|r| r.product == key && (r.range)().matches_str(ver))
        .collect()
}

/// Map a rule to a conservative exploitability rating.
fn exploitability_of(rule: &CveRule) -> Exploitability {
    if rule.kev {
        Exploitability::Active
    } else {
        // Version-based match of a published CVE: public PoC is likely, but we
        // never assert "Active" without KEV corroboration.
        Exploitability::ProofOfConcept
    }
}

/// CVE correlation executor — runs in the vuln-scan stage, no external tool.
pub struct CveCorrelation;

#[async_trait]
impl StageExecutor for CveCorrelation {
    fn stage(&self) -> Stage {
        Stage::VulnScan
    }
    fn name(&self) -> &str {
        "cve-correlation"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        // Snapshot services and the CVEs already referenced by existing findings
        // (e.g. nuclei) per target, so we can dedup.
        let (services, existing): (Vec<Service>, Vec<(String, String)>) = {
            let state = ctx.state.lock().await;
            let services = state.services.clone();
            let existing = state
                .findings
                .iter()
                .flat_map(|f| {
                    let target = f.target.to_string();
                    f.references
                        .iter()
                        .filter(|r| r.to_ascii_uppercase().contains("CVE-"))
                        .map(move |r| (target.clone(), r.to_ascii_uppercase()))
                })
                .collect();
            (services, existing)
        };

        if services.is_empty() {
            return Ok(StageOutcome::Skipped("no services to correlate".into()));
        }

        let mut count = 0usize;
        for svc in &services {
            let matches = match_service(
                svc.service_name.as_deref(),
                svc.product.as_deref(),
                svc.version.as_deref(),
            );
            for rule in matches {
                // Dedup: skip if a finding on this target already cites this CVE.
                let target = svc.target.to_string();
                let already = existing
                    .iter()
                    .any(|(t, c)| t == &target && c == rule.cve);
                if already {
                    continue;
                }

                let banner = [svc.product.clone(), svc.version.clone()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                let epss = rule
                    .epss
                    .map(|e| format!(" EPSS {:.2}.", e))
                    .unwrap_or_default();
                let desc = format!(
                    "{} ({}). Matched from the service banner \"{}\" against known \
                     affected versions. CVSS {:.1}.{}{}\n\nNote: this is a \
                     version-based correlation and may be a false positive if the \
                     vendor/distro back-ported a fix. Verify before relying on it.",
                    rule.title,
                    rule.cve,
                    banner,
                    rule.cvss,
                    epss,
                    if rule.kev { " On CISA KEV (known exploited)." } else { "" },
                );

                let mut refs = vec![
                    rule.cve.to_string(),
                    rule.reference.to_string(),
                ];
                if let Some(e) = rule.epss {
                    refs.push(format!("EPSS:{e:.2}"));
                }

                let finding = Finding::new(
                    svc.target.clone(),
                    Some(svc.port),
                    format!("{} — {}", rule.cve, rule.title),
                    desc,
                    rule.severity,
                    exploitability_of(rule),
                    "cve-correlation",
                )
                .with_references(refs);

                ctx.add_finding(finding).await;
                count += 1;
            }
        }

        ctx.info(format!("CVE correlation produced {count} finding(s)"));
        Ok(StageOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_heartbleed_openssl() {
        let m = match_service(Some("https"), Some("OpenSSL"), Some("1.0.1f"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].cve, "CVE-2014-0160");
        assert!(m[0].kev);
    }

    #[test]
    fn heartbleed_excludes_patched() {
        // 1.0.1g is the fixed version — must NOT match (end-exclusive).
        let m = match_service(Some("https"), Some("OpenSSL"), Some("1.0.1g"));
        assert!(m.is_empty());
    }

    #[test]
    fn matches_vsftpd_backdoor_exact() {
        assert_eq!(match_service(Some("ftp"), Some("vsftpd"), Some("2.3.4")).len(), 1);
        // Neighbors don't match.
        assert!(match_service(Some("ftp"), Some("vsftpd"), Some("2.3.5")).is_empty());
        assert!(match_service(Some("ftp"), Some("vsftpd"), Some("2.3.3")).is_empty());
    }

    #[test]
    fn apache_traversal_range() {
        // 2.4.49 and 2.4.50 affected; 2.4.51 fixed.
        assert_eq!(match_service(None, Some("Apache httpd"), Some("2.4.49")).len(), 1);
        assert_eq!(match_service(None, Some("Apache httpd"), Some("2.4.50")).len(), 1);
        assert!(match_service(None, Some("Apache httpd"), Some("2.4.51")).is_empty());
        assert!(match_service(None, Some("Apache httpd"), Some("2.4.48")).is_empty());
    }

    #[test]
    fn openssh_below_boundary_numeric() {
        // 7.6 affected, 7.7 fixed — numeric (not lexical) comparison.
        assert_eq!(match_service(None, Some("OpenSSH"), Some("7.6")).len(), 1);
        assert_eq!(match_service(None, Some("OpenSSH"), Some("6.9")).len(), 1);
        assert!(match_service(None, Some("OpenSSH"), Some("7.7")).is_empty());
        assert!(match_service(None, Some("OpenSSH"), Some("8.9p1")).is_empty());
    }

    #[test]
    fn product_alias_mapping() {
        // nmap-style product strings normalize to the ruleset key.
        assert_eq!(product_key(None, Some("OpenSSH")).as_deref(), Some("openssh"));
        assert_eq!(product_key(None, Some("Apache httpd")).as_deref(), Some("apache httpd"));
        assert_eq!(product_key(Some("http"), Some("nginx")).as_deref(), Some("nginx"));
    }

    #[test]
    fn no_version_no_match() {
        assert!(match_service(None, Some("OpenSSH"), None).is_empty());
    }

    #[test]
    fn unknown_product_no_match() {
        assert!(match_service(Some("ssh"), Some("Dropbear sshd"), Some("2019.78")).is_empty());
    }

    #[test]
    fn exploitability_is_conservative() {
        let kev = &ruleset()[1]; // vsftpd, kev=true
        assert_eq!(exploitability_of(kev), Exploitability::Active);
        let non_kev = ruleset().into_iter().find(|r| !r.kev).unwrap();
        assert_eq!(exploitability_of(&non_kev), Exploitability::ProofOfConcept);
    }
}
