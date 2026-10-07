//! Prioritization model.
//!
//! Each finding gets a `priority` score so the report can surface the most
//! important, practically-exploitable issues first. The model is intentionally
//! simple and transparent (no opaque ML): operators can reason about why a
//! finding ranks where it does.
//!
//! ```text
//! priority = severity_weight (0..10)
//!          * exploitability_multiplier (0.5..1.6)
//!          * confirmation_boost (1.0 or 1.15)
//!          * cve_boost          (1.0 or 1.2)
//! ```
//!
//! - `confirmation_boost` nudges up findings tied to a concrete port/service,
//!   since those are confirmed reachable rather than inferred.
//! - `cve_boost` rewards findings that carry a concrete CVE identifier in their
//!   references — a verifiable, publicly-tracked exploitability signal — so real
//!   CVE hits (e.g. from nuclei) surface above generic observations of the same
//!   nominal severity.

use moosemap_core::model::{Exploitability, Finding, Severity};

/// Does this finding reference a concrete CVE identifier?
fn has_cve(f: &Finding) -> bool {
    f.references
        .iter()
        .any(|r| r.to_ascii_uppercase().contains("CVE-"))
}

/// Compute and assign `priority` to every finding in place, then sort them
/// highest-priority first (ties broken by severity, then title for stability).
pub fn prioritize(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        f.priority = score(f);
    }
    findings.sort_by(|a, b| {
        b.priority
            .partial_cmp(&a.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.severity.cmp(&a.severity))
            .then(a.title.cmp(&b.title))
    });
}

/// Score a single finding. Pure function; exposed for testing/explanation.
pub fn score(f: &Finding) -> f32 {
    let confirmation_boost = if f.port.is_some() { 1.15 } else { 1.0 };
    let cve_boost = if has_cve(f) { 1.2 } else { 1.0 };
    (f.severity.weight()
        * f.exploitability.multiplier()
        * confirmation_boost
        * cve_boost)
        // round to 2 decimals for stable display
        .mul_add(100.0, 0.5)
        .floor()
        / 100.0
}

/// A finding is "actionable/exploitable" for the executive summary when it is
/// either at least Medium severity, or lower severity but carrying a concrete
/// exploitability signal (a known exploit, or a referenced CVE). This captures
/// cases like an exposed service that is Low/Medium by nominal severity but
/// actively exploitable in practice.
pub fn is_actionable(f: &Finding) -> bool {
    if f.severity == Severity::Info {
        return false;
    }
    f.severity >= Severity::Medium
        || f.exploitability >= Exploitability::ProofOfConcept
        || has_cve(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::model::{Exploitability, Target};

    fn finding(sev: Severity, exp: Exploitability, port: Option<u16>) -> Finding {
        Finding::new(
            Target::Ip("192.0.2.1".parse().unwrap()),
            port,
            "t",
            "d",
            sev,
            exp,
            "test",
        )
    }

    #[test]
    fn critical_active_outranks_low_theoretical() {
        let hi = finding(Severity::Critical, Exploitability::Active, Some(443));
        let lo = finding(Severity::Low, Exploitability::Theoretical, None);
        assert!(score(&hi) > score(&lo));
    }

    #[test]
    fn info_scores_zero() {
        let f = finding(Severity::Info, Exploitability::None, Some(80));
        assert_eq!(score(&f), 0.0);
    }

    #[test]
    fn port_boost_applies() {
        let with_port = finding(Severity::High, Exploitability::Active, Some(22));
        let without = finding(Severity::High, Exploitability::Active, None);
        assert!(score(&with_port) > score(&without));
    }

    #[test]
    fn prioritize_sorts_desc_and_assigns() {
        let mut fs = vec![
            finding(Severity::Low, Exploitability::Theoretical, None),
            finding(Severity::Critical, Exploitability::Active, Some(443)),
            finding(Severity::Medium, Exploitability::ProofOfConcept, Some(80)),
        ];
        prioritize(&mut fs);
        assert_eq!(fs[0].severity, Severity::Critical);
        assert!(fs[0].priority >= fs[1].priority);
        assert!(fs[1].priority >= fs[2].priority);
        assert!(fs.iter().all(|f| f.priority > 0.0 || f.severity == Severity::Info));
    }

    #[test]
    fn actionable_threshold() {
        // Medium+ is actionable regardless of exploitability.
        assert!(is_actionable(&finding(Severity::Medium, Exploitability::None, None)));
        // Low severity but actively exploitable IS actionable now.
        assert!(is_actionable(&finding(Severity::Low, Exploitability::Active, None)));
        // Low + no exploit signal is not actionable.
        assert!(!is_actionable(&finding(Severity::Low, Exploitability::None, None)));
        // Info is never actionable.
        assert!(!is_actionable(&finding(Severity::Info, Exploitability::Active, Some(80))));
    }

    fn finding_with_cve(sev: Severity, exp: Exploitability) -> Finding {
        finding(sev, exp, Some(443)).with_references(vec!["CVE-2021-44228".into()])
    }

    #[test]
    fn cve_reference_boosts_score() {
        let with_cve = finding_with_cve(Severity::High, Exploitability::ProofOfConcept);
        let without = finding(Severity::High, Exploitability::ProofOfConcept, Some(443));
        assert!(score(&with_cve) > score(&without));
    }

    #[test]
    fn cve_reference_makes_low_actionable() {
        let f = finding(Severity::Low, Exploitability::None, Some(80))
            .with_references(vec!["CVE-2019-0001".into()]);
        assert!(is_actionable(&f));
    }

    #[test]
    fn kev_critical_tops_everything() {
        // A KEV-grade critical with a CVE should be the single highest score.
        let mut fs = vec![
            finding(Severity::High, Exploitability::ProofOfConcept, Some(443)),
            finding_with_cve(Severity::Critical, Exploitability::Active),
            finding(Severity::Medium, Exploitability::Active, Some(80)),
        ];
        prioritize(&mut fs);
        assert_eq!(fs[0].severity, Severity::Critical);
        assert_eq!(fs[0].exploitability, Exploitability::Active);
    }
}
