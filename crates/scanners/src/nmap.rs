//! nmap adapter.
//!
//! nmap is the first real integration. It covers three pipeline stages:
//!
//! - [`NmapDiscovery`]  — expands the in-scope IP/CIDR entries into live hosts
//!   (ping/host discovery) plus any explicit hostnames, populating `targets`.
//! - [`NmapPortScan`]   — scans discovered targets for open ports.
//! - [`NmapServiceEnum`]— service/version detection on the open ports, and emits
//!   informational findings for notable/outdated services.
//!
//! All three parse nmap's XML output (`-oX -`). If nmap isn't installed, each
//! executor returns [`StageOutcome::Skipped`] rather than failing the run.

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::{
    Exploitability, Finding, PortState, Protocol, Service, Severity, Stage, Target,
};

const NMAP: &str = "nmap";

/// Parsed representation of a host from nmap XML.
#[derive(Debug, Default, Clone)]
pub struct NmapHost {
    pub address: Option<String>,
    pub hostnames: Vec<String>,
    pub up: bool,
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Clone)]
pub struct NmapPort {
    pub portid: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// Parse nmap XML (`-oX -`) into a list of hosts.
///
/// This is a tolerant, hand-rolled parse over the event stream from `quick-xml`.
/// nmap's schema is stable and shallow, so we avoid full serde deserialization.
pub fn parse_nmap_xml(xml: &str) -> anyhow::Result<Vec<NmapHost>> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut hosts: Vec<NmapHost> = Vec::new();
    let mut cur: Option<NmapHost> = None;
    let mut buf = Vec::new();

    // Helper to read an attribute as String.
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
            Err(e) => return Err(anyhow::anyhow!("nmap XML parse error: {e}")),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"host" => {
                        cur = Some(NmapHost::default());
                    }
                    b"status" => {
                        if let Some(h) = cur.as_mut() {
                            if let Some(state) = attr(&e, b"state") {
                                h.up = state == "up";
                            }
                        }
                    }
                    b"address" => {
                        if let Some(h) = cur.as_mut() {
                            let addr = attr(&e, b"addr");
                            let kind = attr(&e, b"addrtype").unwrap_or_default();
                            // Prefer IP addresses; ignore MAC addresses.
                            if kind.starts_with("ipv") {
                                h.address = addr;
                            }
                        }
                    }
                    b"hostname" => {
                        if let Some(h) = cur.as_mut() {
                            if let Some(name) = attr(&e, b"name") {
                                h.hostnames.push(name);
                            }
                        }
                    }
                    b"port" => {
                        if let Some(h) = cur.as_mut() {
                            let protocol = match attr(&e, b"protocol").as_deref() {
                                Some("udp") => Protocol::Udp,
                                _ => Protocol::Tcp,
                            };
                            // Skip ports with a missing/invalid portid rather
                            // than recording a bogus port 0.
                            if let Some(portid) = attr(&e, b"portid")
                                .and_then(|s| s.parse::<u16>().ok())
                                .filter(|&p| p != 0)
                            {
                                h.ports.push(NmapPort {
                                    portid,
                                    protocol,
                                    state: PortState::Filtered,
                                    service_name: None,
                                    product: None,
                                    version: None,
                                });
                            }
                        }
                    }
                    b"state" => {
                        // <state state="open" .../> inside the current <port>
                        if let Some(h) = cur.as_mut() {
                            if let Some(p) = h.ports.last_mut() {
                                p.state = match attr(&e, b"state").as_deref() {
                                    Some("open") => PortState::Open,
                                    Some("closed") => PortState::Closed,
                                    _ => PortState::Filtered,
                                };
                            }
                        }
                    }
                    b"service" => {
                        if let Some(h) = cur.as_mut() {
                            if let Some(p) = h.ports.last_mut() {
                                p.service_name = attr(&e, b"name");
                                p.product = attr(&e, b"product");
                                p.version = attr(&e, b"version");
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"host" {
                    if let Some(h) = cur.take() {
                        hosts.push(h);
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(hosts)
}

/// Turn the in-scope entries into concrete nmap target arguments.
///
/// We feed nmap the raw scope tokens (IPs, CIDRs, hostnames). nmap expands CIDRs
/// itself. Every host nmap reports back is re-checked against the scope guard
/// before we accept it, so expansion can never escape scope.
fn scope_targets(ctx: &StageContext) -> Vec<String> {
    use moosemap_core::scope::ScopeEntry;
    ctx.scope
        .entries()
        .iter()
        .map(|e| match e {
            ScopeEntry::Ip(ip) => ip.to_string(),
            ScopeEntry::Cidr(net) => net.to_string(),
            ScopeEntry::Host { name, .. } => name.clone(),
        })
        .collect()
}

/// Convert an nmap host's address into a core `Target`, preferring IP.
fn host_to_target(h: &NmapHost) -> Option<Target> {
    if let Some(addr) = &h.address {
        if let Ok(ip) = addr.parse() {
            return Some(Target::Ip(ip));
        }
    }
    h.hostnames.first().map(|n| Target::Host(n.clone()))
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Host discovery with nmap (`-sn`), scope-enforced.
pub struct NmapDiscovery;

#[async_trait]
impl StageExecutor for NmapDiscovery {
    fn stage(&self) -> Stage {
        Stage::Discovery
    }
    fn name(&self) -> &str {
        "nmap-discovery"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        if !tool::is_installed(NMAP) {
            return Ok(StageOutcome::Skipped("nmap not installed".into()));
        }
        let targets = scope_targets(ctx);
        if targets.is_empty() {
            return Ok(StageOutcome::Skipped("empty scope".into()));
        }

        let mut args = vec![
            "-sn".to_string(),       // ping scan, no port scan
            "-n".to_string(),        // no DNS (faster, avoids surprises)
            "-oX".to_string(),
            "-".to_string(),         // XML to stdout
        ];
        args.extend(targets.clone());

        ctx.info(format!("nmap host discovery over {} scope entr{}",
            targets.len(), if targets.len() == 1 { "y" } else { "ies" }));

        let out = tool::run(NMAP, &args).await?;
        if !out.success() && out.stdout.trim().is_empty() {
            anyhow::bail!("nmap discovery failed: {}", out.stderr.trim());
        }

        let hosts = parse_nmap_xml(&out.stdout)?;
        let mut added = 0usize;
        let mut state = ctx.state.lock().await;
        for h in hosts.iter().filter(|h| h.up) {
            if let Some(target) = host_to_target(h) {
                // Re-enforce scope on every discovered host.
                if !ctx.scope.allows(&target) {
                    ctx.warn(format!("skipping out-of-scope host {target}"));
                    continue;
                }
                if !state.targets.contains(&target) {
                    state.targets.push(target);
                    added += 1;
                }
            }
        }
        drop(state);
        ctx.info(format!("discovered {added} live host(s) in scope"));
        Ok(StageOutcome::Completed)
    }
}

// ---------------------------------------------------------------------------
// Port scan
// ---------------------------------------------------------------------------

/// Port scan with nmap over the discovered targets.
pub struct NmapPortScan {
    /// nmap `-p` spec, e.g. "1-1000" or "--top-ports 1000" handled separately.
    pub ports: String,
}

impl Default for NmapPortScan {
    fn default() -> Self {
        NmapPortScan {
            ports: "--top-ports 1000".to_string(),
        }
    }
}

#[async_trait]
impl StageExecutor for NmapPortScan {
    fn stage(&self) -> Stage {
        Stage::PortScan
    }
    fn name(&self) -> &str {
        "nmap-portscan"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        if !tool::is_installed(NMAP) {
            return Ok(StageOutcome::Skipped("nmap not installed".into()));
        }
        let targets: Vec<String> = {
            let state = ctx.state.lock().await;
            state.targets.iter().map(|t| t.to_string()).collect()
        };
        if targets.is_empty() {
            return Ok(StageOutcome::Skipped("no live targets to scan".into()));
        }

        let mut args = vec!["-n".to_string(), "-Pn".to_string()];
        // ports spec may be "--top-ports N" (two tokens) or "-p RANGE".
        if let Some(rest) = self.ports.strip_prefix("--top-ports ") {
            args.push("--top-ports".into());
            args.push(rest.trim().into());
        } else {
            args.push("-p".into());
            args.push(self.ports.clone());
        }
        args.push("-oX".into());
        args.push("-".into());
        args.extend(targets.clone());

        ctx.info(format!("nmap port scan over {} target(s)", targets.len()));
        let out = tool::run(NMAP, &args).await?;
        if !out.success() && out.stdout.trim().is_empty() {
            anyhow::bail!("nmap port scan failed: {}", out.stderr.trim());
        }

        let hosts = parse_nmap_xml(&out.stdout)?;
        let mut open = 0usize;
        let mut state = ctx.state.lock().await;
        for h in &hosts {
            let Some(target) = host_to_target(h) else { continue };
            if !ctx.scope.allows(&target) {
                continue;
            }
            for p in &h.ports {
                if p.state == PortState::Open {
                    // Dedup on (target, port, protocol) so a re-scan or a host
                    // reported twice doesn't create duplicate service rows.
                    let dup = state.services.iter().any(|s| {
                        s.target == target && s.port == p.portid && s.protocol == p.protocol
                    });
                    if dup {
                        continue;
                    }
                    open += 1;
                    state.services.push(Service {
                        target: target.clone(),
                        port: p.portid,
                        protocol: p.protocol,
                        state: p.state,
                        service_name: p.service_name.clone(),
                        product: p.product.clone(),
                        version: p.version.clone(),
                    });
                }
            }
        }
        drop(state);
        ctx.info(format!("found {open} open port(s)"));
        Ok(StageOutcome::Completed)
    }
}

// ---------------------------------------------------------------------------
// Service / version enumeration
// ---------------------------------------------------------------------------

/// Service & version detection (`-sV`) on the open ports found so far.
///
/// Updates service banners and emits informational findings so the operator can
/// see the attack surface even before the dedicated vuln scanners run.
pub struct NmapServiceEnum;

#[async_trait]
impl StageExecutor for NmapServiceEnum {
    fn stage(&self) -> Stage {
        Stage::ServiceEnum
    }
    fn name(&self) -> &str {
        "nmap-service-enum"
    }

    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
        if !tool::is_installed(NMAP) {
            return Ok(StageOutcome::Skipped("nmap not installed".into()));
        }

        // Group ports per target for a focused -sV scan, built directly from the
        // locked state (no full Vec<Service> clone — just the target->ports map).
        use std::collections::BTreeMap;
        let by_target: BTreeMap<String, Vec<u16>> = {
            let state = ctx.state.lock().await;
            let mut map: BTreeMap<String, Vec<u16>> = BTreeMap::new();
            for s in &state.services {
                map.entry(s.target.to_string()).or_default().push(s.port);
            }
            map
        };
        if by_target.is_empty() {
            return Ok(StageOutcome::Skipped("no open ports to enumerate".into()));
        }

        let mut updated = 0usize;
        for (target_str, ports) in by_target {
            let port_list = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let args = vec![
                "-n".into(),
                "-Pn".into(),
                "-sV".into(),
                "-p".into(),
                port_list,
                "-oX".into(),
                "-".into(),
                target_str.clone(),
            ];
            ctx.info(format!("nmap -sV on {target_str}"));
            let out = tool::run(NMAP, &args).await?;
            if out.stdout.trim().is_empty() {
                continue;
            }
            let hosts = parse_nmap_xml(&out.stdout)?;
            let mut state = ctx.state.lock().await;
            for h in &hosts {
                let Some(target) = host_to_target(h) else { continue };
                if !ctx.scope.allows(&target) {
                    continue;
                }
                for p in &h.ports {
                    if let Some(svc) = state.services.iter_mut().find(|s| {
                        s.target == target && s.port == p.portid && s.protocol == p.protocol
                    }) {
                        if p.service_name.is_some() {
                            svc.service_name = p.service_name.clone();
                        }
                        if p.product.is_some() {
                            svc.product = p.product.clone();
                        }
                        if p.version.is_some() {
                            svc.version = p.version.clone();
                        }
                        updated += 1;
                    }
                }
            }
        }

        // Emit informational findings describing the identified attack surface.
        let services: Vec<Service> = {
            let state = ctx.state.lock().await;
            state.services.clone()
        };
        for svc in &services {
            let banner = [svc.product.clone(), svc.version.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            let svc_name = svc.service_name.clone().unwrap_or_else(|| "unknown".into());
            let desc = if banner.is_empty() {
                format!("Open {} service on port {}", svc_name, svc.port)
            } else {
                format!("Open {} service on port {} ({})", svc_name, svc.port, banner)
            };
            ctx.add_finding(Finding::new(
                svc.target.clone(),
                Some(svc.port),
                format!("Exposed service: {svc_name}"),
                desc,
                Severity::Info,
                Exploitability::None,
                "nmap-service-enum",
            ))
            .await;
        }

        ctx.info(format!("enumerated {updated} service(s)"));
        Ok(StageOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="web.example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.0.2.11" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

    #[test]
    fn parses_hosts_ports_and_services() {
        let hosts = parse_nmap_xml(SAMPLE).unwrap();
        assert_eq!(hosts.len(), 2);

        let up = &hosts[0];
        assert!(up.up);
        assert_eq!(up.address.as_deref(), Some("192.0.2.10"));
        assert_eq!(up.hostnames, vec!["web.example.com"]);
        assert_eq!(up.ports.len(), 3);

        let ssh = &up.ports[0];
        assert_eq!(ssh.portid, 22);
        assert_eq!(ssh.state, PortState::Open);
        assert_eq!(ssh.service_name.as_deref(), Some("ssh"));
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("8.9p1"));

        let https = &up.ports[2];
        assert_eq!(https.portid, 443);
        assert_eq!(https.state, PortState::Closed);

        assert!(!hosts[1].up);
    }

    #[test]
    fn host_to_target_prefers_ip() {
        let hosts = parse_nmap_xml(SAMPLE).unwrap();
        let t = host_to_target(&hosts[0]).unwrap();
        assert_eq!(t, Target::Ip("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn empty_xml_yields_no_hosts() {
        let hosts = parse_nmap_xml("<nmaprun></nmaprun>").unwrap();
        assert!(hosts.is_empty());
    }
}
