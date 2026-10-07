//! httpx adapter — web recon.
//!
//! Takes the open services discovered by the port-scan / service-enum stages,
//! probes which of them actually speak HTTP(S) using
//! [httpx](https://github.com/projectdiscovery/httpx), and records confirmed
//! [`WebEndpoint`]s on the run state. The vuln-scan stage (nuclei) consumes
//! those endpoints as its target list.
//!
//! httpx is driven with `-json` (JSON Lines on stdout). We feed it one
//! `host:port` per line on stdin so it only probes in-scope, already-open
//! services rather than guessing.

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{
    Exploitability, Finding, Service, Severity, Stage, Target, WebEndpoint,
};
use std::collections::BTreeSet;

const HTTPX: &str = "httpx";

use moosemap_core::engine::StageOutcome as Outcome;

/// Resolve + verify the httpx binary, returning either the usable binary name or
/// a `Skipped` outcome explaining why we won't run (missing, or the Python httpx
/// shadowing ProjectDiscovery's on Kali). Centralizes the Kali gotcha.
async fn resolve_httpx() -> Result<String, Outcome> {
    let bin = tool::resolve_binary(HTTPX);
    match tool::verify_projectdiscovery(&bin, "httpx").await {
        tool::ToolCheck::Ok => Ok(bin),
        tool::ToolCheck::Missing => {
            Err(Outcome::Skipped("httpx not installed".into()))
        }
        tool::ToolCheck::Wrong(reason) => Err(Outcome::Skipped(reason)),
    }
}

/// Ports we always treat as HTTP(S) candidates even if the service name was not
/// resolved, plus any port whose service name looks web-ish.
const COMMON_WEB_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 7001, 9000, 9443,
];

/// Decide whether a discovered service is worth probing for HTTP.
fn is_web_candidate(svc: &Service) -> bool {
    if COMMON_WEB_PORTS.contains(&svc.port) {
        return true;
    }
    match svc.service_name.as_deref() {
        Some(name) => {
            let n = name.to_ascii_lowercase();
            n.contains("http") || n.contains("ssl") || n.contains("web")
        }
        None => false,
    }
}

/// Parse one httpx JSONL line into a [`WebEndpoint`].
///
/// httpx field names vary slightly across versions; we read the common/stable
/// ones (`url`, `scheme`, `host`/`input`, `port`, `status_code`, `title`,
/// `tech`, `webserver`) and tolerate anything missing.
pub fn parse_httpx_line(line: &str) -> Option<WebEndpoint> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let url = v.get("url").and_then(|x| x.as_str())?.to_string();

    // Scheme: prefer explicit field, else derive from URL.
    let scheme = v
        .get("scheme")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if url.starts_with("https") {
                "https".into()
            } else {
                "http".into()
            }
        });

    // Host: httpx reports `host` (resolved) and/or `input`; prefer input which
    // mirrors what we fed in, so the target matches our scope entries.
    let host = v
        .get("input")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("host").and_then(|x| x.as_str()))
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    let port = v
        .get("port")
        .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
        .map(|p| p as u16)
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });

    let target = match host.parse() {
        Ok(ip) => Target::Ip(ip),
        Err(_) if !host.is_empty() => Target::Host(host),
        Err(_) => return None,
    };

    let mut ep = WebEndpoint::new(target, port, scheme, url);
    ep.status_code = v
        .get("status_code")
        .and_then(|x| x.as_u64())
        .map(|c| c as u16);
    ep.title = v
        .get("title")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    ep.server = v
        .get("webserver")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    ep.tech = v
        .get("tech")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Some(ep)
}

/// Web recon via httpx.
pub struct HttpxWebRecon;

#[async_trait]
impl StageExecutor for HttpxWebRecon {
    fn stage(&self) -> Stage {
        Stage::WebRecon
    }
    fn name(&self) -> &str {
        "httpx-webrecon"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let httpx_bin = match resolve_httpx().await {
            Ok(bin) => bin,
            Err(skip) => return Ok(skip),
        };

        // Gather candidate host:port pairs from discovered web-ish services.
        let candidates: Vec<String> = {
            let state = ctx.state.lock().await;
            let mut set: BTreeSet<String> = BTreeSet::new();
            for svc in &state.services {
                if is_web_candidate(svc) {
                    set.insert(format!("{}:{}", svc.target, svc.port));
                }
            }
            set.into_iter().collect()
        };

        if candidates.is_empty() {
            return Ok(StageOutcome::Skipped(
                "no web-candidate services to probe".into(),
            ));
        }

        ctx.info(format!("probing {} candidate endpoint(s) with httpx", candidates.len()));

        // -json: JSONL output; -silent: suppress banner; -nc: no color.
        // We pass targets via stdin (one per line).
        let args = vec![
            "-json".to_string(),
            "-silent".to_string(),
            "-no-color".to_string(),
            "-title".to_string(),
            "-tech-detect".to_string(),
            "-web-server".to_string(),
            "-status-code".to_string(),
        ];
        let stdin = candidates.join("\n");
        let out = tool::run_with_stdin(&httpx_bin, &args, &stdin).await?;
        if !out.success() && out.stdout.trim().is_empty() {
            anyhow::bail!("httpx failed: {}", out.stderr.trim());
        }

        let mut added = 0usize;
        let mut state = ctx.state.lock().await;
        for line in out.stdout.lines() {
            if let Some(ep) = parse_httpx_line(line) {
                // Re-enforce scope on every endpoint httpx reports.
                if !ctx.scope.allows(&ep.target) {
                    continue;
                }
                if !state.web_endpoints.iter().any(|e| e.url == ep.url) {
                    state.web_endpoints.push(ep);
                    added += 1;
                }
            }
        }
        // Snapshot endpoints to emit findings without holding the lock.
        let endpoints = state.web_endpoints.clone();
        drop(state);

        // Emit informational findings so the web surface is visible in reports.
        for ep in &endpoints {
            let techs = if ep.tech.is_empty() {
                String::new()
            } else {
                format!(" — tech: {}", ep.tech.join(", "))
            };
            let title = ep
                .title
                .as_deref()
                .map(|t| format!(" \"{t}\""))
                .unwrap_or_default();
            ctx.add_finding(Finding::new(
                ep.target.clone(),
                Some(ep.port),
                format!("Web endpoint: {}", ep.url),
                format!(
                    "HTTP(S) endpoint responding{}{}{}",
                    ep.status_code
                        .map(|c| format!(" ({c})"))
                        .unwrap_or_default(),
                    title,
                    techs
                ),
                Severity::Info,
                Exploitability::None,
                "httpx-webrecon",
            ))
            .await;
        }

        ctx.info(format!("confirmed {added} live web endpoint(s)"));
        Ok(StageOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::model::{PortState, Protocol};

    #[test]
    fn parses_httpx_line() {
        let line = r#"{"url":"https://example.com:8443","scheme":"https","input":"example.com:8443","port":"8443","status_code":200,"title":"Admin Panel","webserver":"nginx","tech":["Nginx","PHP"]}"#;
        let ep = parse_httpx_line(line).unwrap();
        assert_eq!(ep.url, "https://example.com:8443");
        assert_eq!(ep.scheme, "https");
        assert_eq!(ep.port, 8443);
        assert_eq!(ep.target, Target::Host("example.com".into()));
        assert_eq!(ep.status_code, Some(200));
        assert_eq!(ep.title.as_deref(), Some("Admin Panel"));
        assert_eq!(ep.server.as_deref(), Some("nginx"));
        assert_eq!(ep.tech, vec!["Nginx", "PHP"]);
    }

    #[test]
    fn parses_ip_host() {
        let line = r#"{"url":"http://192.0.2.10","host":"192.0.2.10","port":80,"status_code":403}"#;
        let ep = parse_httpx_line(line).unwrap();
        assert_eq!(ep.target, Target::Ip("192.0.2.10".parse().unwrap()));
        assert_eq!(ep.port, 80);
        assert_eq!(ep.scheme, "http");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_httpx_line("not json").is_none());
        assert!(parse_httpx_line("").is_none());
        assert!(parse_httpx_line(r#"{"no":"url"}"#).is_none());
    }

    #[test]
    fn web_candidate_detection() {
        let mk = |port, name: Option<&str>| Service {
            target: Target::Ip("192.0.2.1".parse().unwrap()),
            port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: name.map(str::to_string),
            product: None,
            version: None,
        };
        assert!(is_web_candidate(&mk(80, None)));
        assert!(is_web_candidate(&mk(8443, None)));
        assert!(is_web_candidate(&mk(12345, Some("http-alt"))));
        assert!(is_web_candidate(&mk(993, Some("imaps-ssl"))));
        assert!(!is_web_candidate(&mk(22, Some("ssh"))));
    }

    // ---- real-world schema-variation fixtures ----
    //
    // httpx output varies across versions and flags. These exercise the shapes
    // seen in practice so the parser degrades gracefully rather than dropping
    // results or panicking.

    #[test]
    fn full_recent_httpx_record_with_extra_fields() {
        // A representative line from a recent httpx with many flags enabled.
        // Extra fields we don't model (a, cnames, time, words, lines, cdn,
        // failed, ...) must be ignored, not cause a parse failure.
        let line = r#"{"timestamp":"2024-01-02T00:00:00Z","port":"443","url":"https://api.example.com","input":"api.example.com","title":"API Gateway","scheme":"https","webserver":"Apache/2.4.52","content_type":"text/html","method":"GET","host":"203.0.113.5","status_code":200,"content_length":1024,"tech":["Apache HTTP Server","OpenSSL"],"words":120,"lines":30,"cdn":false,"failed":false,"a":["203.0.113.5"]}"#;
        let ep = parse_httpx_line(line).unwrap();
        // `input` is preferred over `host` so the target matches our scope seed,
        // not the resolved IP.
        assert_eq!(ep.target, Target::Host("api.example.com".into()));
        assert_eq!(ep.scheme, "https");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.status_code, Some(200));
        assert_eq!(ep.server.as_deref(), Some("Apache/2.4.52"));
        assert!(ep.tech.contains(&"OpenSSL".to_string()));
    }

    #[test]
    fn port_absent_derived_from_scheme() {
        // Some invocations omit `port`; it must fall back to the scheme default.
        let https = r#"{"url":"https://secure.example.com","input":"secure.example.com","scheme":"https"}"#;
        assert_eq!(parse_httpx_line(https).unwrap().port, 443);
        let http = r#"{"url":"http://plain.example.com","input":"plain.example.com"}"#;
        let ep = parse_httpx_line(http).unwrap();
        assert_eq!(ep.port, 80);
        assert_eq!(ep.scheme, "http"); // derived from url when scheme absent
    }

    #[test]
    fn input_may_carry_host_and_port() {
        // When input is "host:port", we take the host portion for the target.
        let line = r#"{"url":"https://example.com:8443","input":"example.com:8443","port":8443,"scheme":"https"}"#;
        let ep = parse_httpx_line(line).unwrap();
        assert_eq!(ep.target, Target::Host("example.com".into()));
        assert_eq!(ep.port, 8443);
    }

    #[test]
    fn missing_optional_fields_are_none_not_empty() {
        // No title/webserver/tech -> optionals None/empty, still a valid endpoint.
        let line = r#"{"url":"http://192.0.2.20","input":"192.0.2.20","port":80,"status_code":401}"#;
        let ep = parse_httpx_line(line).unwrap();
        assert_eq!(ep.target, Target::Ip("192.0.2.20".parse().unwrap()));
        assert!(ep.title.is_none());
        assert!(ep.server.is_none());
        assert!(ep.tech.is_empty());
        assert_eq!(ep.status_code, Some(401));
    }

    #[test]
    fn empty_string_title_treated_as_absent() {
        let line = r#"{"url":"http://192.0.2.21","input":"192.0.2.21","title":"","webserver":""}"#;
        let ep = parse_httpx_line(line).unwrap();
        assert!(ep.title.is_none());
        assert!(ep.server.is_none());
    }

    #[test]
    fn only_host_no_input_still_resolves_target() {
        // Older httpx may emit `host` without `input`.
        let line = r#"{"url":"http://legacy.example.com","host":"legacy.example.com","port":80}"#;
        let ep = parse_httpx_line(line).unwrap();
        assert_eq!(ep.target, Target::Host("legacy.example.com".into()));
    }
}
