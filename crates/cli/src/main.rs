//! MooseMap CLI.
//!
//! Two entry points:
//! - `moosemap serve`  — launch the HTTP + WebSocket server (and GUI).
//! - `moosemap scan`   — run a headless assessment, stream progress to the
//!   terminal, and write JSON/Markdown reports.
//!
//! Authorized use only: `scan` enforces the declared scope just like the server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use moosemap_core::engine::Engine;
use moosemap_core::event::{EngineEvent, LogLevel};
use moosemap_core::model::{Run, RunStatus};
use moosemap_core::scope::ScopeGuard;
use moosemap_report::{prioritize, Report};
use moosemap_server::{serve, ServerConfig};

#[derive(Parser)]
#[command(
    name = "moosemap",
    version,
    about = "Orchestrated, authorized external penetration testing with real-time tracking",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Launch the API + WebSocket server (serves the web GUI).
    Serve(ServeArgs),
    /// Run a headless assessment and write a report.
    Scan(ScanArgs),
    /// Report which external scanning tools are installed.
    Tools,
}

#[derive(Parser)]
struct ServeArgs {
    /// Address to bind, e.g. 127.0.0.1:8080.
    #[arg(long, env = "MOOSEMAP_ADDR", default_value = "127.0.0.1:8080")]
    addr: SocketAddr,
    /// SQLite database URL.
    #[arg(
        long,
        env = "MOOSEMAP_DB",
        default_value = "sqlite://moosemap.db"
    )]
    database_url: String,
    /// Directory of built frontend assets to serve.
    #[arg(long, env = "MOOSEMAP_FRONTEND", default_value = "frontend/dist")]
    frontend_dir: PathBuf,
}

#[derive(Parser)]
struct ScanArgs {
    /// Scope: comma/space/newline separated IPs, CIDRs, FQDNs.
    #[arg(long)]
    scope: String,
    /// A name for this assessment.
    #[arg(long, default_value = "cli-scan")]
    name: String,
    /// Write the JSON report to this path.
    #[arg(long)]
    json_out: Option<PathBuf>,
    /// Write the Markdown report to this path.
    #[arg(long)]
    md_out: Option<PathBuf>,
    /// Confirm you are authorized to test every target in scope.
    #[arg(long, default_value_t = false)]
    i_am_authorized: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => run_serve(args).await,
        Command::Scan(args) => run_scan(args).await,
        Command::Tools => {
            print_tools().await;
            Ok(())
        }
    }
}

async fn run_serve(args: ServeArgs) -> anyhow::Result<()> {
    let frontend_dir = Some(args.frontend_dir).filter(|p| p.exists());
    if frontend_dir.is_none() {
        eprintln!(
            "note: frontend assets not found; serving API + placeholder page only.\n\
             build the GUI with: (cd frontend && npm install && npm run build)"
        );
    }
    let config = ServerConfig {
        addr: args.addr,
        database_url: args.database_url,
        frontend_dir,
    };
    // serve() prints the clickable URL and opens the browser (unless
    // MOOSEMAP_NO_OPEN is set).
    serve(config).await
}

async fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    // Validate scope up front and give actionable feedback.
    let guard = match ScopeGuard::from_input(&args.scope) {
        Ok(g) if !g.is_empty() => g,
        Ok(_) => {
            anyhow::bail!("scope is empty");
        }
        Err(errs) => {
            eprintln!("Invalid scope entries:");
            for (tok, e) in errs {
                eprintln!("  - {tok}: {e}");
            }
            anyhow::bail!("refusing to scan: fix the scope and retry");
        }
    };

    // Require an explicit authorization acknowledgement for active scanning.
    if !args.i_am_authorized {
        eprintln!(
            "Refusing to scan without authorization confirmation.\n\
             MooseMap performs active scanning. Only scan assets you are\n\
             explicitly authorized to test. Re-run with --i-am-authorized to confirm."
        );
        anyhow::bail!("authorization not confirmed");
    }

    let scope_tokens: Vec<String> = args
        .scope
        .split([',', '\n', '\r', ' ', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let run = Run::new(args.name.clone(), scope_tokens);
    let run_id = run.id;
    let scope = Arc::new(guard);

    // Build the engine with the default scanner set and stream events live.
    let engine = Engine::new(moosemap_scanners::default_executors(), 1024);
    let mut rx = engine.subscribe();

    let printer = tokio::spawn(async move {
        while let Ok(ev) = rx.recv().await {
            print_event(&ev);
        }
    });

    println!("Starting assessment \"{}\" ({run_id})", args.name);
    let result = engine.run(&run, scope).await;

    // Give the printer a moment to flush, then stop it.
    drop(engine);
    let _ = printer.await;

    // Prioritize + build the report.
    let mut findings = result.findings;
    prioritize::prioritize(&mut findings);
    let report = Report::build(&run, result.services, findings);

    print_summary(&report, result.status);

    if let Some(path) = &args.json_out {
        std::fs::write(path, report.to_json()?)?;
        println!("Wrote JSON report to {}", path.display());
    }
    if let Some(path) = &args.md_out {
        std::fs::write(path, report.to_markdown())?;
        println!("Wrote Markdown report to {}", path.display());
    }
    if args.json_out.is_none() && args.md_out.is_none() {
        // Default: print Markdown to stdout.
        println!("\n{}", report.to_markdown());
    }

    if result.status == RunStatus::Failed {
        anyhow::bail!("assessment finished with failures");
    }
    Ok(())
}

fn print_event(ev: &EngineEvent) {
    match ev {
        EngineEvent::RunStatusChanged { status, .. } => {
            println!("  run status: {status}");
        }
        EngineEvent::TaskStatusChanged { stage, status, message, .. } => {
            let msg = message.as_deref().map(|m| format!(" — {m}")).unwrap_or_default();
            println!("  [{stage}] {status}{msg}");
        }
        EngineEvent::Log { stage, level, message, .. } => {
            let tag = match level {
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
            };
            println!("    ({tag}) [{stage}] {message}");
        }
        EngineEvent::FindingAdded { finding, .. } => {
            println!(
                "    + finding: [{}] {} ({})",
                finding.severity, finding.title, finding.target
            );
        }
    }
}

fn print_summary(report: &Report, status: RunStatus) {
    let s = &report.summary;
    println!("\n=== Summary ({status}) ===");
    println!("  targets with open ports: {}", s.total_targets);
    println!("  open ports:              {}", s.total_open_ports);
    println!("  findings:                {} ({} actionable)", s.total_findings, s.actionable);
    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(n) = s.by_severity.get(sev) {
            if *n > 0 {
                println!("    {sev}: {n}");
            }
        }
    }
}

async fn print_tools() {
    println!("MooseMap tool doctor\n");
    let report = moosemap_scanners::tool_report().await;
    for t in &report {
        let mark = match t.state {
            "ok" => "✓ ok     ",
            "wrong" => "⚠ wrong  ",
            _ => "✗ missing",
        };
        println!("  {mark} {:<10} {}", t.name, t.role);
        if let Some(path) = &t.resolved_path {
            println!("              path:    {path}");
        }
        println!("              {}", t.detail);
        if t.state != "ok" {
            println!("              install: {}", t.install_hint);
        }
        println!();
    }
    println!(
        "Missing tools cause their pipeline stages to be skipped (not fail).\n\
         Override a tool's binary with MOOSEMAP_<TOOL>, e.g. MOOSEMAP_HTTPX=/opt/pd/httpx.\n\
         On Kali, make sure `httpx` is ProjectDiscovery's, not the Python HTTP client.\n\
         See the Kali Quick Start in README.md and scripts/setup-kali.sh."
    );
}
