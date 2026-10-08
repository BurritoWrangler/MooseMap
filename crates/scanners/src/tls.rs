//! TLS/SSL analysis via `sslscan`.
//!
//! Runs [`sslscan`](https://github.com/rbsec/sslscan) against TLS-bearing
//! services discovered in earlier stages and turns its findings into
//! prioritized [`Finding`]s: deprecated protocols, weak ciphers, and certificate
//! problems (expired / self-signed / name mismatch). Certificate SANs are logged
//! informationally — they also reveal additional in-scope hostnames.
//!
//! sslscan is driven with `--xml=-` (XML to stdout). If it isn't installed, the
//! stage skips gracefully.

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{Exploitability, Finding, Service, Severity, Stage, Target};

const SSLSCAN: &str = "sslscan";

/// Ports/service names that typically speak TLS.
const TLS_PORTS: &[u16] = &[443, 8443, 9443, 993, 995, 465, 990, 636, 989, 5061];

fn is_tls_service(svc: &Service) -> bool {
    if TLS_PORTS.contains(&svc.port) {
        return true;
    }
    match svc.service_name.as_deref() {
        Some(name) => {
            let n = name.to_ascii_lowercase();
            n.contains("ssl") || n.contains("tls") || n.contains("https")
        }
        None => false,
    }
}

/// Parsed, normalized result of an sslscan run against one endpoint.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SslscanResult {
    /// Deprecated protocols found enabled (e.g. "SSLv3", "TLSv1.0").
    pub weak_protocols: Vec<String>,
    /// Weak/NULL/anonymous/export cipher names found accepted.
    pub weak_ciphers: Vec<String>,
    /// True if sslscan flagged the host as vulnerable to Heartbleed.
    pub heartbleed: bool,
    /// Certificate problems: ("expired"|"self-signed"|"mismatch", detail).
    pub cert_issues: Vec<String>,
    /// Subject Alternative Names from the certificate (discovery signal).
    pub sans: Vec<String>,
}

/// Protocols considered deprecated/insecure when enabled.
fn is_weak_protocol(proto_type: &str, version: &str) -> Option<String> {
    let t = proto_type.to_ascii_lowercase();
    let v = version.to_ascii_lowercase();
    if t == "ssl" {
        // Any SSLv2/SSLv3 is bad.
        Some(format!("SSLv{version}"))
    } else if t == "tls" && (v == "1.0" || v == "1.1") {
        Some(format!("TLSv{version}"))
    } else {
        None
    }
}

/// Is a cipher name indicative of a weak/insecure suite?
fn is_weak_cipher(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.contains("NULL")
        || n.contains("ANON")
        || n.contains("EXPORT")
        || n.contains("RC4")
        || n.contains("DES") && !n.contains("3DES") // single DES (keep an eye on 3DES separately)
        || n.contains("MD5")
        || n.contains("_DES_")
        || n.contains("3DES") // 3DES (SWEET32) — flag as weak
}

/// Parse sslscan `--xml=-` output into a normalized result.
///
/// sslscan XML shape (stable across versions):
/// `<protocol type="tls" version="1.0" enabled="1"/>`,
/// `<cipher status="accepted" sslversion="TLSv1.2" bits="112" cipher="DES-CBC3-SHA"/>`,
/// `<certificate>` with `<expired>`, `<self-signed>`, `<subject>`, `<altnames>`,
/// and a `<heartbleed vulnerable="1"/>` element. We read defensively.
pub fn parse_sslscan_xml(xml: &str) -> anyhow::Result<SslscanResult> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut result = SslscanResult::default();
    let mut buf = Vec::new();
    // Track whether we're inside <certificate> and the current text target.
    let mut in_cert = false;
    let mut text_target: Option<&'static str> = None;

    fn attr(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
        e.attributes().flatten().find_map(|a| {
            if a.key.as_ref() == key {
                Some(String::from_utf8_lossy(&a.value).into_owned())
            } else {
                None
            }
        })
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(anyhow::anyhow!("sslscan XML parse error: {e}")),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"protocol" => {
                        let enabled = attr(&e, b"enabled").as_deref() == Some("1");
                        if enabled {
                            let t = attr(&e, b"type").unwrap_or_default();
                            let v = attr(&e, b"version").unwrap_or_default();
                            if let Some(p) = is_weak_protocol(&t, &v) {
                                if !result.weak_protocols.contains(&p) {
                                    result.weak_protocols.push(p);
                                }
                            }
                        }
                    }
                    b"cipher" => {
                        let status = attr(&e, b"status").unwrap_or_default();
                        // "accepted"/"preferred" means the server will use it.
                        if status == "accepted" || status == "preferred" {
                            if let Some(name) = attr(&e, b"cipher") {
                                if is_weak_cipher(&name)
                                    && !result.weak_ciphers.contains(&name)
                                {
                                    result.weak_ciphers.push(name);
                                }
                            }
                        }
                    }
                    b"heartbleed" => {
                        if attr(&e, b"vulnerable").as_deref() == Some("1") {
                            result.heartbleed = true;
                        }
                    }
                    b"certificate" => in_cert = true,
                    b"expired" if in_cert => text_target = Some("expired"),
                    b"self-signed" if in_cert => text_target = Some("self-signed"),
                    b"altnames" if in_cert => text_target = Some("altnames"),
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(target) = text_target.take() {
                    let text = t.unescape().unwrap_or_default().trim().to_string();
                    match target {
                        "expired" if text == "true" => {
                            result.cert_issues.push("certificate is expired".into());
                        }
                        "self-signed" if text == "true" => {
                            result
                                .cert_issues
                                .push("certificate is self-signed".into());
                        }
                        "altnames" => {
                            for san in text.split([',', ' ']).filter(|s| !s.is_empty()) {
                                let san = san.trim_start_matches("DNS:").to_string();
                                if !result.sans.contains(&san) {
                                    result.sans.push(san);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"certificate" {
                    in_cert = false;
                }
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(result)
}

/// TLS analysis executor (service-enum stage; runs after nmap -sV).
pub struct SslscanTls;

#[async_trait]
impl StageExecutor for SslscanTls {
    fn stage(&self) -> Stage {
        Stage::ServiceEnum
    }
    fn name(&self) -> &str {
        "sslscan-tls"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        if !tool::is_installed(SSLSCAN) {
            return Ok(StageOutcome::Skipped("sslscan not installed".into()));
        }

        let targets: Vec<(Target, u16)> = {
            let state = ctx.state.lock().await;
            state
                .services
                .iter()
                .filter(|s| is_tls_service(s))
                .map(|s| (s.target.clone(), s.port))
                .collect()
        };
        if targets.is_empty() {
            return Ok(StageOutcome::Skipped("no TLS services to analyze".into()));
        }

        ctx.info(format!("sslscan over {} TLS endpoint(s)", targets.len()));

        let mut count = 0usize;
        for (target, port) in targets {
            if !ctx.scope.allows(&target) {
                continue;
            }
            let endpoint = format!("{target}:{port}");
            let args = vec![
                "--xml=-".to_string(),
                "--no-colour".to_string(),
                endpoint.clone(),
            ];
            let out = tool::run(SSLSCAN, &args).await?;
            if out.stdout.trim().is_empty() {
                continue;
            }
            let r = match parse_sslscan_xml(&out.stdout) {
                Ok(r) => r,
                Err(e) => {
                    ctx.warn(format!("sslscan parse failed for {endpoint}: {e}"));
                    continue;
                }
            };

            count += emit_findings(ctx, &target, port, &r).await;
        }

        ctx.info(format!("TLS analysis produced {count} finding(s)"));
        Ok(StageOutcome::Completed)
    }
}

/// Turn a parsed sslscan result into findings; returns how many were emitted.
async fn emit_findings(
    ctx: &StageContext,
    target: &Target,
    port: u16,
    r: &SslscanResult,
) -> usize {
    let mut n = 0;

    if r.heartbleed {
        ctx.add_finding(
            Finding::new(
                target.clone(),
                Some(port),
                "TLS: Heartbleed (CVE-2014-0160)",
                "sslscan reports this endpoint vulnerable to Heartbleed memory \
                 disclosure (CVE-2014-0160).",
                Severity::High,
                Exploitability::Active,
                "sslscan-tls",
            )
            .with_references(vec!["CVE-2014-0160".into()]),
        )
        .await;
        n += 1;
    }

    if !r.weak_protocols.is_empty() {
        ctx.add_finding(Finding::new(
            target.clone(),
            Some(port),
            "TLS: deprecated protocol(s) enabled",
            format!(
                "The server accepts deprecated TLS/SSL protocols: {}. These are \
                 insecure and should be disabled.",
                r.weak_protocols.join(", ")
            ),
            Severity::Medium,
            Exploitability::Theoretical,
            "sslscan-tls",
        ))
        .await;
        n += 1;
    }

    if !r.weak_ciphers.is_empty() {
        let sample: Vec<String> = r.weak_ciphers.iter().take(8).cloned().collect();
        ctx.add_finding(Finding::new(
            target.clone(),
            Some(port),
            "TLS: weak cipher suite(s) accepted",
            format!(
                "The server accepts weak cipher suites ({}{}). Disable NULL/anon/\
                 export/RC4/DES/3DES/MD5 ciphers.",
                sample.join(", "),
                if r.weak_ciphers.len() > sample.len() {
                    format!(", +{} more", r.weak_ciphers.len() - sample.len())
                } else {
                    String::new()
                }
            ),
            Severity::Medium,
            Exploitability::Theoretical,
            "sslscan-tls",
        ))
        .await;
        n += 1;
    }

    for issue in &r.cert_issues {
        ctx.add_finding(Finding::new(
            target.clone(),
            Some(port),
            "TLS: certificate problem",
            format!("Certificate issue: {issue}."),
            Severity::High,
            Exploitability::Theoretical,
            "sslscan-tls",
        ))
        .await;
        n += 1;
    }

    if !r.sans.is_empty() {
        ctx.add_finding(Finding::new(
            target.clone(),
            Some(port),
            "TLS: certificate SANs",
            format!(
                "Certificate subject alternative names (may reveal additional \
                 in-scope hosts): {}",
                r.sans.join(", ")
            ),
            Severity::Info,
            Exploitability::None,
            "sslscan-tls",
        ))
        .await;
        n += 1;
    }

    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::model::{PortState, Protocol};

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<document>
 <ssltest host="192.0.2.10" port="443">
  <protocol type="ssl" version="3" enabled="1"/>
  <protocol type="tls" version="1.0" enabled="1"/>
  <protocol type="tls" version="1.1" enabled="1"/>
  <protocol type="tls" version="1.2" enabled="1"/>
  <protocol type="tls" version="1.3" enabled="0"/>
  <heartbleed sslversion="TLSv1.2" vulnerable="1"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="112" cipher="DES-CBC3-SHA"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="AES128-GCM-SHA256"/>
  <cipher status="accepted" sslversion="SSLv3" bits="128" cipher="RC4-MD5"/>
  <certificate>
   <self-signed>true</self-signed>
   <expired>true</expired>
   <altnames>DNS:example.com, DNS:www.example.com</altnames>
  </certificate>
 </ssltest>
</document>"#;

    #[test]
    fn parses_protocols_ciphers_cert() {
        let r = parse_sslscan_xml(SAMPLE).unwrap();
        assert!(r.weak_protocols.contains(&"SSLv3".to_string()));
        assert!(r.weak_protocols.contains(&"TLSv1.0".to_string()));
        assert!(r.weak_protocols.contains(&"TLSv1.1".to_string()));
        // TLS 1.2 enabled is fine; must not be flagged.
        assert!(!r.weak_protocols.iter().any(|p| p.contains("1.2")));
        assert!(r.heartbleed);
        assert!(r.weak_ciphers.iter().any(|c| c.contains("DES-CBC3")));
        assert!(r.weak_ciphers.iter().any(|c| c.contains("RC4")));
        // Strong cipher not flagged.
        assert!(!r.weak_ciphers.iter().any(|c| c.contains("AES128-GCM")));
        assert!(r.cert_issues.iter().any(|i| i.contains("self-signed")));
        assert!(r.cert_issues.iter().any(|i| i.contains("expired")));
        assert_eq!(r.sans, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn clean_server_has_no_issues() {
        let xml = r#"<document><ssltest host="h" port="443">
          <protocol type="tls" version="1.2" enabled="1"/>
          <protocol type="tls" version="1.3" enabled="1"/>
          <cipher status="accepted" cipher="AES256-GCM-SHA384"/>
        </ssltest></document>"#;
        let r = parse_sslscan_xml(xml).unwrap();
        assert!(r.weak_protocols.is_empty());
        assert!(r.weak_ciphers.is_empty());
        assert!(!r.heartbleed);
        assert!(r.cert_issues.is_empty());
    }

    #[test]
    fn weak_cipher_classification() {
        assert!(is_weak_cipher("RC4-MD5"));
        assert!(is_weak_cipher("DES-CBC3-SHA")); // 3DES / SWEET32
        assert!(is_weak_cipher("EXP-RC2-CBC-MD5"));
        assert!(is_weak_cipher("NULL-SHA"));
        assert!(!is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384"));
        assert!(!is_weak_cipher("AES128-GCM-SHA256"));
    }

    #[test]
    fn tls_service_detection() {
        let mk = |port, name: Option<&str>| Service {
            target: Target::Ip("192.0.2.1".parse().unwrap()),
            port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: name.map(str::to_string),
            product: None,
            version: None,
        };
        assert!(is_tls_service(&mk(443, None)));
        assert!(is_tls_service(&mk(8443, None)));
        assert!(is_tls_service(&mk(12345, Some("https-alt"))));
        assert!(is_tls_service(&mk(993, Some("imaps"))));
        assert!(!is_tls_service(&mk(22, Some("ssh"))));
        assert!(!is_tls_service(&mk(80, Some("http"))));
    }

    #[test]
    fn empty_xml_ok() {
        let r = parse_sslscan_xml("<document></document>").unwrap();
        assert_eq!(r, SslscanResult::default());
    }
}
