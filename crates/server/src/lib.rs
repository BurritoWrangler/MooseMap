//! # moosemap-server
//!
//! The application service layer and HTTP/WebSocket API for MooseMap.
//!
//! - [`store`] — SQLite persistence (runs, tasks, findings, services).
//! - [`orchestrator`] — wires the engine to persistence + a live event bus.
//! - [`api`] — axum REST + WebSocket router, serving the built frontend.
//!
//! [`serve`] is the one-call entry point used by the CLI.

pub mod api;
pub mod orchestrator;
pub mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

pub use orchestrator::Orchestrator;
pub use store::Store;

/// Configuration for the running server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    /// SQLite URL, e.g. `sqlite://moosemap.db`.
    pub database_url: String,
    /// Directory of built frontend assets to serve, if any.
    pub frontend_dir: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            addr: "127.0.0.1:8080".parse().unwrap(),
            database_url: "sqlite://moosemap.db".to_string(),
            frontend_dir: Some(PathBuf::from("frontend/dist")),
        }
    }
}

/// Build an [`Orchestrator`] backed by SQLite and the default scanner set.
pub async fn build_orchestrator(database_url: &str) -> anyhow::Result<Orchestrator> {
    let store = Store::connect(database_url).await?;
    let executors: Vec<Arc<dyn moosemap_core::StageExecutor>> =
        moosemap_scanners::default_executors();
    Ok(Orchestrator::new(store, executors))
}

/// Start the HTTP + WebSocket server and run until shutdown (Ctrl-C).
pub async fn serve(config: ServerConfig) -> anyhow::Result<()> {
    let orch = build_orchestrator(&config.database_url).await?;
    let app = api::router(orch, config.frontend_dir.clone());

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(addr = %config.addr, "MooseMap server listening");

    // A URL the user can click. For 0.0.0.0 we point at localhost, which is
    // what a browser on the same host should use.
    let host = match config.addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    let url = format!("http://{host}:{}", config.addr.port());
    println!("\n  MooseMap is running — open {url}\n");

    // Best-effort: open the GUI in the default browser unless disabled. Never
    // fails the server if the opener is missing (headless/SSH/CI).
    if std::env::var_os("MOOSEMAP_NO_OPEN").is_none() {
        open_browser(&url);
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Open `url` in the OS default browser, best-effort. Silent on failure.
fn open_browser(url: &str) {
    // Platform-appropriate opener; spawn detached and ignore the result.
    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("open", &[])];
    #[cfg(target_os = "windows")]
    let candidates: &[(&str, &[&str])] = &[("cmd", &["/C", "start", ""])];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[(&str, &[&str])] = &[("xdg-open", &[]), ("sensible-browser", &[])];

    for (bin, prefix) in candidates {
        let mut cmd = std::process::Command::new(bin);
        cmd.args(prefix.iter().copied());
        cmd.arg(url);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if cmd.spawn().is_ok() {
            return;
        }
    }
    // No opener available (common on headless VMs). The printed URL is enough.
    tracing::debug!("could not auto-open a browser; open the printed URL manually");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builds_orchestrator_in_memory() {
        let orch = build_orchestrator("sqlite::memory:").await.unwrap();
        // Smoke test: create a run through the orchestrator.
        let run = orch.create_run("t".into(), "192.0.2.0/24").await.unwrap();
        assert_eq!(run.scope, vec!["192.0.2.0/24".to_string()]);
    }

    #[test]
    fn default_config_is_localhost() {
        let c = ServerConfig::default();
        assert_eq!(c.addr.ip().to_string(), "127.0.0.1");
        assert_eq!(c.addr.port(), 8080);
    }
}
