//! subfinder adapter — passive subdomain enumeration (discovery).
//!
//! For each hostname in the declared scope,
//! [subfinder](https://github.com/projectdiscovery/subfinder) passively
//! enumerates subdomains. Every discovered name is re-checked against the
//! [`ScopeGuard`](moosemap_core::ScopeGuard) before being added as a `Host`
//! target, so enumeration can only ever surface things the operator already
//! authorized (e.g. via a `*.example.com` scope entry). Discovered hosts flow
//! into web recon (httpx) and vuln scanning (nuclei).
//!
//! subfinder is driven with `-json` (JSON Lines on stdout) and fed domains on
//! stdin via `-dL -` (one domain per line).

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{Stage, Target};
use moosemap_core::scope::ScopeEntry;
use std::collections::BTreeSet;

const SUBFINDER: &str = "subfinder";

/// Extract the apex/registered domains to enumerate from the scope entries.
///
/// Both exact-host and wildcard scope entries are used as seeds. IPs and CIDRs
/// are ignored (subdomain enumeration is meaningless for them).
fn seed_domains(ctx: &StageContext) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for e in ctx.scope.entries() {
        if let ScopeEntry::Host { name, .. } = e {
            set.insert(name.clone());
        }
    }
    set.into_iter().collect()
}

/// Parse one subfinder `-json` line, returning the discovered hostname.
///
/// subfinder reports `{"host":"sub.example.com","input":"example.com",...}`.
/// Older/plain output is a bare hostname per line; we accept that too.
pub fn parse_subfinder_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // JSON object form.
    if line.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        return v
            .get("host")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty());
    }
    // Plain hostname form (no JSON): accept if it looks like a hostname.
    let host = line.trim_end_matches('.').to_ascii_lowercase();
    if host.contains(' ') || !host.contains('.') {
        return None;
    }
    Some(host)
}

/// Passive subdomain enumeration via subfinder.
pub struct SubfinderDiscovery;

#[async_trait]
impl StageExecutor for SubfinderDiscovery {
    fn stage(&self) -> Stage {
        Stage::Discovery
    }
    fn name(&self) -> &str {
        "subfinder-discovery"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        let subfinder_bin = tool::resolve_binary(SUBFINDER);
        match tool::verify_projectdiscovery(&subfinder_bin, "subfinder").await {
            tool::ToolCheck::Ok => {}
            tool::ToolCheck::Missing => {
                return Ok(StageOutcome::Skipped("subfinder not installed".into()))
            }
            tool::ToolCheck::Wrong(reason) => {
                return Ok(StageOutcome::Skipped(reason))
            }
        }
        let domains = seed_domains(ctx);
        if domains.is_empty() {
            return Ok(StageOutcome::Skipped(
                "no domain scope entries to enumerate".into(),
            ));
        }

        ctx.info(format!(
            "enumerating subdomains for {} domain(s) with subfinder",
            domains.len()
        ));

        // -json: JSONL; -silent: results only; -dL -: read domains from stdin.
        let args = vec![
            "-json".to_string(),
            "-silent".to_string(),
            "-dL".to_string(),
            "-".to_string(),
        ];
        let stdin = domains.join("\n");
        let out = tool::run_with_stdin(&subfinder_bin, &args, &stdin).await?;
        if !out.success() && out.stdout.trim().is_empty() && !out.stderr.trim().is_empty() {
            anyhow::bail!("subfinder failed: {}", out.stderr.trim());
        }

        let mut added = 0usize;
        let mut out_of_scope = 0usize;
        let mut state = ctx.state.lock().await;
        for line in out.stdout.lines() {
            let Some(host) = parse_subfinder_line(line) else { continue };
            let target = Target::Host(host);
            // Enforce scope: only keep subdomains the operator authorized.
            if !ctx.scope.allows(&target) {
                out_of_scope += 1;
                continue;
            }
            if !state.targets.contains(&target) {
                state.targets.push(target);
                added += 1;
            }
        }
        drop(state);

        if out_of_scope > 0 {
            ctx.warn(format!(
                "{out_of_scope} discovered subdomain(s) were out of scope and dropped \
                 (add a wildcard scope entry like *.domain to include them)"
            ));
        }
        ctx.info(format!("added {added} in-scope subdomain target(s)"));
        Ok(StageOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_line() {
        let line = r#"{"host":"api.example.com","input":"example.com","source":"crtsh"}"#;
        assert_eq!(parse_subfinder_line(line).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let line = r#"{"host":"API.Example.com."}"#;
        assert_eq!(parse_subfinder_line(line).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn parses_plain_hostname_line() {
        assert_eq!(
            parse_subfinder_line("mail.example.com").as_deref(),
            Some("mail.example.com")
        );
    }

    #[test]
    fn rejects_non_hostname_plain_lines() {
        assert!(parse_subfinder_line("localhost").is_none()); // no dot
        assert!(parse_subfinder_line("some log line here").is_none());
        assert!(parse_subfinder_line("").is_none());
    }

    #[test]
    fn json_without_host_is_none() {
        assert!(parse_subfinder_line(r#"{"input":"example.com"}"#).is_none());
    }
}
