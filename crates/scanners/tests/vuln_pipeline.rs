//! End-to-end integration test for the recon -> vuln -> actionable-report flow.
//!
//! External scanners (nmap/httpx/nuclei) aren't available in CI, so this test
//! injects synthetic services via a tiny in-test executor, then runs the *real*
//! [`VersionHeuristics`] vuln executor through the engine and feeds the result
//! into the *real* report prioritizer. It proves the whole chain — services ->
//! findings -> prioritized, actionable report — works, independent of tools.

use std::sync::Arc;

use moosemap_core::engine::{
    async_trait, Engine, StageContext, StageExecutor, StageOutcome,
};
use moosemap_core::model::{PortState, Protocol, Service, Severity, Stage, Target};
use moosemap_core::{Run, ScopeGuard};
use moosemap_report::{prioritize, Report};
use moosemap_scanners::heuristics::VersionHeuristics;

/// Seeds the run state with synthetic services, as if a real scanner had run.
struct FakeServices;

#[async_trait]
impl StageExecutor for FakeServices {
    fn stage(&self) -> Stage {
        Stage::ServiceEnum
    }
    fn name(&self) -> &str {
        "fake-services"
    }
    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let t = Target::Ip("192.0.2.10".parse().unwrap());
        let mk = |port, name: &str, product: &str, version: &str| Service {
            target: t.clone(),
            port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: Some(name.into()),
            product: Some(product.into()),
            version: Some(version.into()),
        };
        let mut st = ctx.state.lock().await;
        st.services.push(mk(21, "ftp", "vsftpd", "2.3.4")); // critical backdoor
        st.services.push(mk(6379, "redis", "Redis", "6.2")); // high, exposed
        st.services.push(mk(22, "ssh", "OpenSSH", "9.6")); // clean, modern
        Ok(StageOutcome::Completed)
    }
}

#[tokio::test]
async fn vuln_findings_flow_into_prioritized_actionable_report() {
    let engine = Engine::new(
        vec![Arc::new(FakeServices), Arc::new(VersionHeuristics)],
        256,
    );
    let run = Run::new("integration", vec!["192.0.2.0/24".into()]);
    let scope = Arc::new(ScopeGuard::from_input("192.0.2.0/24").unwrap());

    let result = engine.run(&run, scope).await;
    assert_eq!(result.status, moosemap_core::RunStatus::Completed);

    // Heuristics should have flagged the vsftpd backdoor and exposed Redis.
    assert!(
        result.findings.iter().any(|f| f.severity == Severity::Critical),
        "expected a critical finding from the vsftpd 2.3.4 backdoor"
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("redis")),
        "expected a finding for the exposed Redis service"
    );

    // Build the report exactly as the orchestrator does.
    let mut findings = result.findings;
    prioritize::prioritize(&mut findings);
    let report = Report::build(&run, result.services, findings);

    // The top-priority finding must be the critical, actively-exploited one.
    assert_eq!(report.findings[0].severity, Severity::Critical);
    assert_eq!(
        report.findings[0].exploitability,
        moosemap_core::Exploitability::Active
    );

    // Priorities are monotonically non-increasing.
    for pair in report.findings.windows(2) {
        assert!(pair[0].priority >= pair[1].priority);
    }

    // The executive summary surfaces actionable items and top priorities.
    assert!(report.summary.actionable >= 2);
    assert!(!report.summary.top_priorities.is_empty());
    assert_eq!(
        report.summary.top_priorities[0],
        report.findings[0].title,
        "top priority in summary should match the highest-scored finding"
    );
}

// ---------------------------------------------------------------------------
// Discovery -> (web) -> vuln flow for a Host target, with scope enforcement.
// ---------------------------------------------------------------------------

use moosemap_core::WebEndpoint;

/// Mimics subfinder: adds one in-scope subdomain and one out-of-scope host.
/// Both are pushed to `targets` without a guard check on purpose, so the test
/// can prove that *downstream* stages still refuse to act on the out-of-scope
/// one (defense in depth — every stage re-checks the guard).
struct FakeDiscovery;

#[async_trait]
impl StageExecutor for FakeDiscovery {
    fn stage(&self) -> Stage {
        Stage::Discovery
    }
    fn name(&self) -> &str {
        "fake-discovery"
    }
    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let mut st = ctx.state.lock().await;
        st.targets.push(Target::Host("api.example.com".into())); // in scope
        st.targets.push(Target::Host("evil.attacker.test".into())); // NOT in scope
        Ok(StageOutcome::Completed)
    }
}

/// Mimics a web-recon stage: for each in-scope Host target, record a web
/// endpoint and a web service. Out-of-scope targets are skipped via the guard.
struct FakeWebRecon;

#[async_trait]
impl StageExecutor for FakeWebRecon {
    fn stage(&self) -> Stage {
        Stage::WebRecon
    }
    fn name(&self) -> &str {
        "fake-webrecon"
    }
    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let targets = {
            let st = ctx.state.lock().await;
            st.targets.clone()
        };
        let mut st = ctx.state.lock().await;
        for t in targets {
            if !ctx.scope.allows(&t) {
                continue; // scope guard: never touch out-of-scope hosts
            }
            if let Target::Host(h) = &t {
                st.web_endpoints.push(WebEndpoint::new(
                    t.clone(),
                    443,
                    "https",
                    format!("https://{h}"),
                ));
                // An exposed, outdated service to trip a heuristic rule.
                st.services.push(Service {
                    target: t.clone(),
                    port: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service_name: Some("http".into()),
                    product: Some("Apache httpd".into()),
                    version: Some("2.2.15".into()),
                });
            }
        }
        Ok(StageOutcome::Completed)
    }
}

#[tokio::test]
async fn host_target_flows_discovery_to_vuln_and_scope_is_enforced() {
    // Scope authorizes example.com + subdomains, but NOT attacker.test.
    let scope = Arc::new(ScopeGuard::from_input("*.example.com, example.com").unwrap());
    let engine = Engine::new(
        vec![
            Arc::new(FakeDiscovery),
            Arc::new(FakeWebRecon),
            Arc::new(VersionHeuristics),
        ],
        256,
    );
    let run = Run::new("discovery-flow", vec!["*.example.com".into()]);

    let result = engine.run(&run, scope).await;
    assert_eq!(result.status, moosemap_core::RunStatus::Completed);

    // The in-scope subdomain produced a web endpoint and a finding.
    assert!(result
        .web_endpoints
        .iter()
        .any(|e| e.url == "https://api.example.com"));
    assert!(
        result
            .findings
            .iter()
            .any(|f| matches!(&f.target, Target::Host(h) if h == "api.example.com")),
        "expected a finding for the in-scope subdomain"
    );

    // The out-of-scope host must never appear in endpoints OR findings.
    assert!(
        !result.web_endpoints.iter().any(|e| e.url.contains("attacker.test")),
        "out-of-scope host leaked into web endpoints"
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| matches!(&f.target, Target::Host(h) if h.contains("attacker.test"))),
        "out-of-scope host leaked into findings"
    );

    // The Apache 2.2 heuristic should have fired (High severity).
    let mut findings = result.findings;
    prioritize::prioritize(&mut findings);
    let report = Report::build(&run, result.services, findings);
    assert!(report.findings.iter().any(|f| f.severity == Severity::High));
    assert!(report.summary.actionable >= 1);
}

// ---------------------------------------------------------------------------
// CVE correlation: a known-vulnerable banner yields a prioritized CVE finding.
// ---------------------------------------------------------------------------

use moosemap_scanners::cve::CveCorrelation;

/// Seeds a vsftpd 2.3.4 service (the backdoored release, CVE-2011-2523, KEV).
struct FakeVulnService;

#[async_trait]
impl StageExecutor for FakeVulnService {
    fn stage(&self) -> Stage {
        Stage::ServiceEnum
    }
    fn name(&self) -> &str {
        "fake-vuln-service"
    }
    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let mut st = ctx.state.lock().await;
        st.services.push(Service {
            target: Target::Ip("192.0.2.50".parse().unwrap()),
            port: 21,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: Some("ftp".into()),
            product: Some("vsftpd".into()),
            version: Some("2.3.4".into()),
        });
        Ok(StageOutcome::Completed)
    }
}

#[tokio::test]
async fn cve_correlation_emits_prioritized_cve_finding() {
    let engine = Engine::new(
        vec![Arc::new(FakeVulnService), Arc::new(CveCorrelation)],
        256,
    );
    let run = Run::new("cve", vec!["192.0.2.0/24".into()]);
    let scope = Arc::new(ScopeGuard::from_input("192.0.2.0/24").unwrap());

    let result = engine.run(&run, scope).await;
    assert_eq!(result.status, moosemap_core::RunStatus::Completed);

    // A CVE-2011-2523 finding should exist, Critical + Active (KEV), from the
    // cve-correlation source, carrying the CVE and an EPSS reference.
    let cve = result
        .findings
        .iter()
        .find(|f| f.title.contains("CVE-2011-2523"))
        .expect("expected a CVE-2011-2523 finding");
    assert_eq!(cve.severity, Severity::Critical);
    assert_eq!(cve.exploitability, moosemap_core::Exploitability::Active);
    assert_eq!(cve.source, "cve-correlation");
    assert!(cve.references.iter().any(|r| r == "CVE-2011-2523"));
    assert!(cve.references.iter().any(|r| r.starts_with("EPSS:")));

    // After prioritization it should outrank a plain informational finding.
    let mut findings = result.findings;
    prioritize::prioritize(&mut findings);
    assert!(findings[0].title.contains("CVE-2011-2523"));
}

// ---------------------------------------------------------------------------
// TLS + content-discovery adapters skip gracefully when their tools are absent
// (sslscan/feroxbuster aren't installed in CI), and the pipeline still completes.
// ---------------------------------------------------------------------------

use moosemap_scanners::content::ContentDiscovery;
use moosemap_scanners::tls::SslscanTls;

/// Seeds an HTTPS service so the TLS adapter has something to consider.
struct FakeTlsService;

#[async_trait]
impl StageExecutor for FakeTlsService {
    fn stage(&self) -> Stage {
        Stage::ServiceEnum
    }
    fn name(&self) -> &str {
        "fake-tls-service"
    }
    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let mut st = ctx.state.lock().await;
        st.services.push(Service {
            target: Target::Ip("192.0.2.60".parse().unwrap()),
            port: 443,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: Some("https".into()),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
        });
        Ok(StageOutcome::Completed)
    }
}

#[tokio::test]
async fn tls_and_content_adapters_integrate_without_tools() {
    // Neither sslscan nor feroxbuster is installed in CI; both adapters must
    // skip gracefully and the run must still complete.
    let engine = Engine::new(
        vec![
            Arc::new(FakeTlsService),
            Arc::new(SslscanTls),
            Arc::new(ContentDiscovery),
        ],
        128,
    );
    let run = Run::new("tls", vec!["192.0.2.0/24".into()]);
    let scope = Arc::new(ScopeGuard::from_input("192.0.2.0/24").unwrap());
    let result = engine.run(&run, scope).await;
    assert_eq!(result.status, moosemap_core::RunStatus::Completed);
}
