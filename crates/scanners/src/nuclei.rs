//! nuclei adapter — vulnerability scanning.
//!
//! Runs [nuclei](https://github.com/projectdiscovery/nuclei) against the web
//! endpoints confirmed during web recon (falling back to open `host:port`
//! services if no endpoints were confirmed) and turns each match into a
//! prioritized [`Finding`].
//!
//! nuclei is driven with `-jsonl` (one JSON object per match on stdout). Targets
//! are supplied on stdin. Severity maps 1:1 onto [`Severity`]; exploitability is
//! inferred from template tags/classification:
//!
//! - tag `kev` / `known-exploited`           -> [`Exploitability::Active`]
//! - a CVE id present (classification/tags)  -> [`Exploitability::ProofOfConcept`]
//! - otherwise                               -> [`Exploitability::Theoretical`]
//!
//! Informational matches stay [`Exploitability::None`].

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{Exploitability, Finding, Severity, Stage, Target};
use std::collections::BTreeSet;

const NUCLEI: &str = "nuclei";

/// A parsed nuclei result.
#[derive(Debug, Clone)]
pub struct NucleiMatch {
    pub template_id: String,
    pub name: String,
    pub severity: Severity,
    pub description: Option<String>,
    pub host: String,
    pub matched_at: Option<String>,
    pub tags: Vec<String>,
    pub cves: Vec<String>,
    pub reference_urls: Vec<String>,
}

fn severity_from_str(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Infer exploitability from a match's tags + CVE classification.
pub fn exploitability_of(m: &NucleiMatch) -> Exploitability {
    if m.severity == Severity::Info {
        return Exploitability::None;
    }
    let tags_lower: Vec<String> = m.tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    let is_kev = tags_lower
        .iter()
        .any(|t| t == "kev" || t == "known-exploited" || t.contains("exploited"));
    if is_kev {
        return Exploitability::Active;
    }
    if !m.cves.is_empty() || tags_lower.iter().any(|t| t.starts_with("cve")) {
        return Exploitability::ProofOfConcept;
    }
    Exploitability::Theoretical
}

/// Parse one nuclei `-jsonl` line into a [`NucleiMatch`].
///
/// nuclei's JSON is stable at the top level (`template-id`, `info`, `host`,
/// `matched-at`); nested shapes vary by version, so we read defensively.
pub fn parse_nuclei_line(line: &str) -> Option<NucleiMatch> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let template_id = v
        .get("template-id")
        .or_else(|| v.get("templateID"))
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();

    let info = v.get("info").cloned().unwrap_or(serde_json::Value::Null);
    let name = info
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or(&template_id)
        .to_string();
    let severity = severity_from_str(
        info.get("severity").and_then(|x| x.as_str()).unwrap_or("info"),
    );
    let description = info
        .get("description")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // host may be a URL or host:port; keep as reported.
    let host = v
        .get("host")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("ip").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    let matched_at = v
        .get("matched-at")
        .or_else(|| v.get("matched_at"))
        .and_then(|x| x.as_str())
        .map(str::to_string);

    // Tags: info.tags can be a comma string or an array depending on version.
    let tags = match info.get("tags") {
        Some(serde_json::Value::String(s)) => {
            s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
        }
        Some(serde_json::Value::Array(a)) => {
            a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    };

    // CVEs: info.classification.cve-id (string or array) and any cve-ish tags.
    let mut cves: Vec<String> = Vec::new();
    if let Some(cls) = info.get("classification") {
        match cls.get("cve-id") {
            Some(serde_json::Value::String(s)) if !s.is_empty() => {
                cves.push(s.to_uppercase())
            }
            Some(serde_json::Value::Array(a)) => {
                for c in a {
                    if let Some(s) = c.as_str() {
                        if !s.is_empty() {
                            cves.push(s.to_uppercase());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for t in &tags {
        let up = t.to_uppercase();
        if up.starts_with("CVE-") && !cves.contains(&up) {
            cves.push(up);
        }
    }

    // Reference URLs from info.reference (string or array).
    let reference_urls = match info.get("reference") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.to_string()],
        Some(serde_json::Value::Array(a)) => {
            a.iter().filter_map(|r| r.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    };

    Some(NucleiMatch {
        template_id,
        name,
        severity,
        description,
        host,
        matched_at,
        tags,
        cves,
        reference_urls,
    })
}

/// Map a nuclei match's host back to a core [`Target`] (prefer IP) plus the
/// port if one can be derived from the host string or its scheme.
fn match_target(host: &str) -> Option<(Target, Option<u16>)> {
    // host can be "https://1.2.3.4:443", "1.2.3.4:443", "example.com", etc.
    let scheme_default_port = if host.starts_with("https://") {
        Some(443u16)
    } else if host.starts_with("http://") {
        Some(80u16)
    } else {
        None
    };
    let stripped = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let hostpart = stripped.split('/').next().unwrap_or(stripped);
    // Split host:port, being careful not to misread an IPv6 literal.
    let (bare, port) = match hostpart.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>().ok()),
        _ => (hostpart, None),
    };
    if bare.is_empty() {
        return None;
    }
    let port = port.or(scheme_default_port);
    let target = match bare.parse() {
        Ok(ip) => Target::Ip(ip),
        Err(_) => Target::Host(bare.to_string()),
    };
    Some((target, port))
}

/// Vulnerability scanning via nuclei.
pub struct NucleiVulnScan;

#[async_trait]
impl StageExecutor for NucleiVulnScan {
    fn stage(&self) -> Stage {
        Stage::VulnScan
    }
    fn name(&self) -> &str {
        "nuclei-vulnscan"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let nuclei_bin = tool::resolve_binary(NUCLEI);
        match tool::verify_projectdiscovery(&nuclei_bin, "nuclei").await {
            tool::ToolCheck::Ok => {}
            tool::ToolCheck::Missing => {
                return Ok(StageOutcome::Skipped("nuclei not installed".into()))
            }
            tool::ToolCheck::Wrong(reason) => {
                return Ok(StageOutcome::Skipped(reason))
            }
        }

        // Prefer confirmed web endpoints; fall back to open services as host:port.
        let targets: Vec<String> = {
            let state = ctx.state.lock().await;
            if !state.web_endpoints.is_empty() {
                state.web_endpoints.iter().map(|e| e.url.clone()).collect()
            } else {
                let mut set: BTreeSet<String> = BTreeSet::new();
                for svc in &state.services {
                    set.insert(format!("{}:{}", svc.target, svc.port));
                }
                set.into_iter().collect()
            }
        };

        if targets.is_empty() {
            return Ok(StageOutcome::Skipped("no targets to scan".into()));
        }

        ctx.info(format!("running nuclei against {} target(s)", targets.len()));

        // -jsonl: JSON lines; -silent: only results; -no-color; disable update.
        let args = vec![
            "-jsonl".to_string(),
            "-silent".to_string(),
            "-no-color".to_string(),
            "-disable-update-check".to_string(),
        ];
        let stdin = targets.join("\n");
        let out = tool::run_with_stdin(&nuclei_bin, &args, &stdin).await?;
        if !out.success() && out.stdout.trim().is_empty() && !out.stderr.trim().is_empty() {
            anyhow::bail!("nuclei failed: {}", out.stderr.trim());
        }

        let mut count = 0usize;
        for line in out.stdout.lines() {
            let Some(m) = parse_nuclei_line(line) else { continue };
            let Some((target, port)) = match_target(&m.host) else { continue };
            // Re-enforce scope on every result.
            if !ctx.scope.allows(&target) {
                ctx.warn(format!("dropping out-of-scope nuclei result for {}", m.host));
                continue;
            }

            let exploit = exploitability_of(&m);
            let mut refs = m.cves.clone();
            refs.extend(m.reference_urls.clone());
            refs.push(format!("nuclei-template:{}", m.template_id));

            let where_ = m.matched_at.clone().unwrap_or_else(|| m.host.clone());
            let desc = m
                .description
                .clone()
                .unwrap_or_else(|| format!("nuclei template {} matched", m.template_id));

            let finding = Finding::new(
                target,
                port,
                m.name.clone(),
                format!("{desc}\n\nMatched at: {where_}"),
                m.severity,
                exploit,
                "nuclei",
            )
            .with_references(refs);

            ctx.add_finding(finding).await;
            count += 1;
        }

        ctx.info(format!("nuclei produced {count} finding(s)"));
        Ok(StageOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRIT: &str = r#"{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Log4Shell remote code execution","tags":["cve","cve2021","rce","kev"],"classification":{"cve-id":"CVE-2021-44228"},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},"host":"https://192.0.2.10:8080","matched-at":"https://192.0.2.10:8080/api"}"#;

    const MED: &str = r#"{"template-id":"tech-detect","info":{"name":"Exposed Panel","severity":"medium","tags":"panel,exposure"},"host":"example.com:443"}"#;

    #[test]
    fn parses_critical_with_cve_and_kev() {
        let m = parse_nuclei_line(CRIT).unwrap();
        assert_eq!(m.template_id, "CVE-2021-44228");
        assert_eq!(m.severity, Severity::Critical);
        assert_eq!(m.cves, vec!["CVE-2021-44228"]);
        assert!(m.tags.iter().any(|t| t == "kev"));
        // KEV => Active exploitability.
        assert_eq!(exploitability_of(&m), Exploitability::Active);
    }

    #[test]
    fn parses_medium_string_tags() {
        let m = parse_nuclei_line(MED).unwrap();
        assert_eq!(m.severity, Severity::Medium);
        assert_eq!(m.tags, vec!["panel", "exposure"]);
        assert!(m.cves.is_empty());
        // Medium, no CVE/KEV => Theoretical.
        assert_eq!(exploitability_of(&m), Exploitability::Theoretical);
    }

    #[test]
    fn cve_without_kev_is_poc() {
        let line = r#"{"template-id":"CVE-2019-0001","info":{"name":"X","severity":"high","tags":["cve"],"classification":{"cve-id":"CVE-2019-0001"}},"host":"1.2.3.4:80"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(exploitability_of(&m), Exploitability::ProofOfConcept);
    }

    #[test]
    fn match_target_handles_urls_and_hostports() {
        assert_eq!(
            match_target("https://192.0.2.10:8080"),
            Some((Target::Ip("192.0.2.10".parse().unwrap()), Some(8080)))
        );
        assert_eq!(
            match_target("example.com:443"),
            Some((Target::Host("example.com".into()), Some(443)))
        );
        // Scheme implies the default port when none is explicit.
        assert_eq!(
            match_target("http://example.com/path"),
            Some((Target::Host("example.com".into()), Some(80)))
        );
        // Bare host with no scheme and no port -> no port.
        assert_eq!(
            match_target("example.com"),
            Some((Target::Host("example.com".into()), None))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_nuclei_line("nope").is_none());
        assert!(parse_nuclei_line("").is_none());
    }

    // ---- real-world schema-variation fixtures ----
    //
    // nuclei's JSONL carries many optional/nested fields that vary by version
    // and template. These lock in that we read the ones we care about and
    // ignore the rest without failing.

    #[test]
    fn full_modern_record_array_classification_and_metadata() {
        // Representative of a current nuclei match: cve-id as an array,
        // cwe-id present, reference as array, plus metadata / extracted-results
        // / matcher-name / type / curl-command that we must ignore.
        let line = r#"{"template-id":"CVE-2023-1234","template-path":"http/cves/2023/CVE-2023-1234.yaml","info":{"name":"Example Product RCE","author":["pdteam"],"tags":["cve","cve2023","rce","intrusive"],"description":"Remote code execution in Example Product.","reference":["https://nvd.nist.gov/vuln/detail/CVE-2023-1234","https://example.com/advisory"],"severity":"critical","classification":{"cve-id":["CVE-2023-1234"],"cwe-id":["CWE-78"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L","cvss-score":9.8},"metadata":{"max-request":2},"remediation":"Upgrade."},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/cgi-bin/exec","extracted-results":["uid=0(root)"],"matcher-name":"rce","curl-command":"curl -X POST ...","timestamp":"2024-05-01T12:00:00Z"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(m.template_id, "CVE-2023-1234");
        assert_eq!(m.severity, Severity::Critical);
        assert_eq!(m.cves, vec!["CVE-2023-1234"]);
        assert_eq!(m.reference_urls.len(), 2);
        assert!(m.description.is_some());
        // cve + rce + intrusive tags, no kev -> proof-of-concept.
        assert_eq!(exploitability_of(&m), Exploitability::ProofOfConcept);
    }

    #[test]
    fn reference_as_single_string() {
        let line = r#"{"template-id":"exposure","info":{"name":"Config Exposure","severity":"low","tags":["exposure","config"],"reference":"https://example.com/doc"},"host":"http://192.0.2.30:8080"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(m.reference_urls, vec!["https://example.com/doc"]);
        assert!(m.cves.is_empty());
    }

    #[test]
    fn reference_null_and_no_classification() {
        // Many templates have no CVE and `reference: null`.
        let line = r#"{"template-id":"ssl-dns-names","info":{"name":"SSL DNS Names","severity":"info","tags":["ssl"],"reference":null},"host":"example.com:443","type":"ssl"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(m.severity, Severity::Info);
        assert!(m.reference_urls.is_empty());
        assert!(m.cves.is_empty());
        // Info is always None exploitability.
        assert_eq!(exploitability_of(&m), Exploitability::None);
    }

    #[test]
    fn templateid_camelcase_fallback() {
        // Some older output used `templateID`.
        let line = r#"{"templateID":"legacy-check","info":{"name":"Legacy","severity":"high","tags":["misc"]},"host":"1.2.3.4:80"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(m.template_id, "legacy-check");
        assert_eq!(m.severity, Severity::High);
    }

    #[test]
    fn cve_discovered_only_via_tag() {
        // No classification block, but a CVE id appears in tags.
        let line = r#"{"template-id":"generic","info":{"name":"Thing","severity":"high","tags":["cve-2020-5902","f5"]},"host":"1.2.3.4:443"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(m.cves, vec!["CVE-2020-5902"]);
        assert_eq!(exploitability_of(&m), Exploitability::ProofOfConcept);
    }

    #[test]
    fn ip_field_used_when_host_absent() {
        let line = r#"{"template-id":"t","info":{"name":"n","severity":"medium","tags":[]},"ip":"198.51.100.7","matched-at":"198.51.100.7:3306"}"#;
        let m = parse_nuclei_line(line).unwrap();
        let (target, _port) = match_target(&m.host).unwrap();
        assert_eq!(target, Target::Ip("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn kev_via_known_exploited_tag_variant() {
        // Some templates tag `known-exploited` rather than `kev`.
        let line = r#"{"template-id":"CVE-2021-26855","info":{"name":"Exchange SSRF","severity":"critical","tags":["cve","known-exploited","exchange"],"classification":{"cve-id":["CVE-2021-26855"]}},"host":"https://mail.example.com"}"#;
        let m = parse_nuclei_line(line).unwrap();
        assert_eq!(exploitability_of(&m), Exploitability::Active);
    }
}
