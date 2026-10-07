//! Scope parsing, validation, and the scope guard.
//!
//! The scope is the set of assets the operator is authorized to test. Every
//! target a scanner is asked to act on is checked against the [`ScopeGuard`];
//! anything not covered by the declared scope is refused. This is the central
//! safety mechanism that keeps MooseMap from touching assets it shouldn't.

use crate::model::Target;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("empty scope entry")]
    Empty,
    #[error("invalid scope entry: {0:?}")]
    Invalid(String),
    #[error("hostname too long: {0:?}")]
    HostTooLong(String),
}

/// A single parsed, authorized scope entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    /// A single IP address.
    Ip(IpAddr),
    /// A CIDR network (also used to represent a single IP as a /32 or /128).
    Cidr(IpNet),
    /// A hostname (and, implicitly, its subdomains if `include_subdomains`).
    Host {
        name: String,
        include_subdomains: bool,
    },
}

impl ScopeEntry {
    /// Does this entry authorize the given target?
    pub fn contains(&self, target: &Target) -> bool {
        match (self, target) {
            (ScopeEntry::Ip(a), Target::Ip(b)) => a == b,
            (ScopeEntry::Cidr(net), Target::Ip(ip)) => net.contains(ip),
            (ScopeEntry::Host { name, include_subdomains }, Target::Host(h)) => {
                let h = h.trim_end_matches('.').to_ascii_lowercase();
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                if h == name {
                    true
                } else if *include_subdomains {
                    h.ends_with(&format!(".{name}"))
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

/// Parse one raw scope token into a [`ScopeEntry`].
///
/// Accepted forms:
/// - `192.0.2.10`                -> single IP
/// - `2001:db8::1`               -> single IPv6
/// - `192.0.2.0/24`              -> CIDR
/// - `example.com`               -> host (exact)
/// - `*.example.com`             -> host + subdomains
/// - `.example.com`              -> host + subdomains (leading-dot form)
pub fn parse_entry(raw: &str) -> Result<ScopeEntry, ScopeError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(ScopeError::Empty);
    }

    // CIDR?
    if s.contains('/') {
        return IpNet::from_str(s)
            .map(ScopeEntry::Cidr)
            .map_err(|_| ScopeError::Invalid(s.to_string()));
    }

    // Bare IP?
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(ScopeEntry::Ip(ip));
    }

    // Wildcard / leading-dot host forms imply subdomains.
    let (name, include_subdomains) = if let Some(rest) = s.strip_prefix("*.") {
        (rest, true)
    } else if let Some(rest) = s.strip_prefix('.') {
        (rest, true)
    } else {
        (s, false)
    };

    let name = name.trim_end_matches('.');
    if !is_valid_hostname(name) {
        return Err(ScopeError::Invalid(s.to_string()));
    }
    if name.len() > 253 {
        return Err(ScopeError::HostTooLong(s.to_string()));
    }

    Ok(ScopeEntry::Host {
        name: name.to_ascii_lowercase(),
        include_subdomains,
    })
}

/// Minimal, conservative hostname validation (RFC 1123-ish labels).
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    // Must contain at least one dot to be an FQDN-ish entry, but allow
    // single-label hosts too (e.g. intranet names). Reject obvious junk.
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Parse a comma/whitespace/newline-separated list of scope tokens.
///
/// Collects all parse errors rather than failing on the first, so the operator
/// can fix the whole list at once.
pub fn parse_scope(input: &str) -> Result<Vec<ScopeEntry>, Vec<(String, ScopeError)>> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();

    for token in input.split([',', '\n', '\r', ' ', '\t']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match parse_entry(token) {
            Ok(e) => entries.push(e),
            Err(err) => errors.push((token.to_string(), err)),
        }
    }

    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

/// Enforces that targets fall within the authorized scope.
///
/// Construct once per run from the parsed scope, then call [`ScopeGuard::allows`]
/// before acting on any target. [`ScopeGuard::check`] returns a descriptive error
/// suitable for logging/aborting.
#[derive(Debug, Clone, Default)]
pub struct ScopeGuard {
    entries: Vec<ScopeEntry>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("target {target} is outside the authorized scope and will not be scanned")]
pub struct OutOfScope {
    pub target: String,
}

impl ScopeGuard {
    pub fn new(entries: Vec<ScopeEntry>) -> Self {
        ScopeGuard { entries }
    }

    /// Build a guard directly from raw scope input.
    pub fn from_input(input: &str) -> Result<Self, Vec<(String, ScopeError)>> {
        parse_scope(input).map(ScopeGuard::new)
    }

    pub fn entries(&self) -> &[ScopeEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True if any scope entry authorizes this target.
    pub fn allows(&self, target: &Target) -> bool {
        self.entries.iter().any(|e| e.contains(target))
    }

    /// Returns `Err(OutOfScope)` if the target is not authorized.
    pub fn check(&self, target: &Target) -> Result<(), OutOfScope> {
        if self.allows(target) {
            Ok(())
        } else {
            Err(OutOfScope {
                target: target.to_string(),
            })
        }
    }

    /// Filter an iterator of targets down to only the in-scope ones.
    pub fn retain_in_scope<I>(&self, targets: I) -> Vec<Target>
    where
        I: IntoIterator<Item = Target>,
    {
        targets.into_iter().filter(|t| self.allows(t)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Target {
        Target::Ip(s.parse().unwrap())
    }
    fn host(s: &str) -> Target {
        Target::Host(s.to_string())
    }

    #[test]
    fn parses_single_ip() {
        assert_eq!(
            parse_entry("192.0.2.10").unwrap(),
            ScopeEntry::Ip("192.0.2.10".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipv6() {
        assert_eq!(
            parse_entry("2001:db8::1").unwrap(),
            ScopeEntry::Ip("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn parses_cidr() {
        let e = parse_entry("192.0.2.0/24").unwrap();
        assert!(matches!(e, ScopeEntry::Cidr(_)));
    }

    #[test]
    fn parses_host_exact() {
        assert_eq!(
            parse_entry("example.com").unwrap(),
            ScopeEntry::Host {
                name: "example.com".into(),
                include_subdomains: false
            }
        );
    }

    #[test]
    fn parses_wildcard_host() {
        assert_eq!(
            parse_entry("*.example.com").unwrap(),
            ScopeEntry::Host {
                name: "example.com".into(),
                include_subdomains: true
            }
        );
    }

    #[test]
    fn rejects_junk() {
        assert!(parse_entry("not a host!").is_err());
        assert!(parse_entry("").is_err());
        assert!(parse_entry("-bad.example.com").is_err());
    }

    #[test]
    fn cidr_contains_ip() {
        let g = ScopeGuard::from_input("192.0.2.0/24").unwrap();
        assert!(g.allows(&ip("192.0.2.55")));
        assert!(!g.allows(&ip("192.0.3.1")));
    }

    #[test]
    fn exact_host_does_not_match_subdomain() {
        let g = ScopeGuard::from_input("example.com").unwrap();
        assert!(g.allows(&host("example.com")));
        assert!(!g.allows(&host("api.example.com")));
    }

    #[test]
    fn wildcard_host_matches_subdomain_but_not_sibling() {
        let g = ScopeGuard::from_input("*.example.com").unwrap();
        assert!(g.allows(&host("api.example.com")));
        assert!(g.allows(&host("example.com")));
        assert!(!g.allows(&host("example.org")));
        assert!(!g.allows(&host("notexample.com")));
    }

    #[test]
    fn host_match_is_case_and_trailing_dot_insensitive() {
        let g = ScopeGuard::from_input("Example.COM").unwrap();
        assert!(g.allows(&host("example.com.")));
    }

    #[test]
    fn check_reports_out_of_scope() {
        let g = ScopeGuard::from_input("10.0.0.0/8").unwrap();
        let err = g.check(&ip("192.0.2.1")).unwrap_err();
        assert_eq!(err.target, "192.0.2.1");
    }

    #[test]
    fn parse_scope_collects_all_errors() {
        // Two tokens contain characters invalid in hostnames ('!' and '_').
        let err = parse_scope("example.com, bad!, 1.2.3.4, under_score").unwrap_err();
        assert_eq!(err.len(), 2);
    }

    #[test]
    fn parse_scope_mixed_ok() {
        let entries =
            parse_scope("192.0.2.0/24, example.com, *.test.local 10.0.0.1").unwrap();
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn retain_filters_out_of_scope() {
        let g = ScopeGuard::from_input("192.0.2.0/24").unwrap();
        let kept = g.retain_in_scope(vec![
            ip("192.0.2.1"),
            ip("8.8.8.8"),
            ip("192.0.2.254"),
        ]);
        assert_eq!(kept.len(), 2);
    }
}
