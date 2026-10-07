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

/// Browser-facing URL for a bound address (maps `0.0.0.0`/`::` to localhost).
pub fn browser_url(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    format!("http://{host}:{}", addr.port())
}

/// Bind the server socket, returning the listener, built app, and the *actual*
/// bound address. Shared by `serve()` (CLI) and `serve_in_process()` (desktop).
async fn bind(
    config: &ServerConfig,
) -> anyhow::Result<(tokio::net::TcpListener, axum::Router, SocketAddr)> {
    let orch = build_orchestrator(&config.database_url).await?;
    let app = api::router(orch, config.frontend_dir.clone());
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    let local_addr = listener.local_addr()?;
    Ok((listener, app, local_addr))
}

/// Start the HTTP + WebSocket server and run until shutdown (Ctrl-C).
///
/// Used by the CLI. Prints the URL and opens the browser (unless
/// `MOOSEMAP_NO_OPEN` is set).
pub async fn serve(config: ServerConfig) -> anyhow::Result<()> {
    let (listener, app, local_addr) = bind(&config).await?;
    tracing::info!(addr = %local_addr, "MooseMap server listening");

    let url = browser_url(local_addr);
    println!("\n  MooseMap is running — open {url}\n");

    if std::env::var_os("MOOSEMAP_NO_OPEN").is_none() {
        open_browser(&url);
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Start the server in-process for the desktop (Tauri) app.
///
/// Binds `config.addr`; if that port is already taken, retries on an
/// OS-assigned free port (`127.0.0.1:0`) so the desktop app never fails to
/// launch just because 8080 is busy. Spawns the server on the current Tokio
/// runtime and returns the browser URL to point the webview at. Does **not**
/// open a browser or install a Ctrl-C handler — the app window owns the
/// lifecycle (closing the window exits the process).
pub async fn serve_in_process(config: ServerConfig) -> anyhow::Result<String> {
    let (listener, app, local_addr) = match bind(&config).await {
        Ok(bound) => bound,
        Err(_) => {
            // Port busy (or similar) — fall back to an ephemeral localhost port.
            let mut fallback = config.clone();
            fallback.addr = "127.0.0.1:0".parse().unwrap();
            bind(&fallback).await?
        }
    };
    let url = browser_url(local_addr);
    tracing::info!(addr = %local_addr, "MooseMap in-process server listening");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "in-process server exited");
        }
    });

    Ok(url)
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

    #[test]
    fn browser_url_maps_unspecified_to_localhost() {
        let any: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(browser_url(any), "http://127.0.0.1:8080");
        let loopback: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(browser_url(loopback), "http://127.0.0.1:9000");
    }

    #[tokio::test]
    async fn serve_in_process_binds_and_returns_url() {
        // Bind an ephemeral port so the test never collides.
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            database_url: "sqlite::memory:".into(),
            frontend_dir: None,
        };
        let url = serve_in_process(config).await.unwrap();
        assert!(url.starts_with("http://127.0.0.1:"));

        // The server is live: /api/health responds.
        let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
        // Give the spawned task a moment to start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let body = reqwest_get(&format!("http://127.0.0.1:{port}/api/health")).await;
        assert!(body.contains("\"status\":\"ok\""), "unexpected health body: {body}");
    }

    /// Minimal GET using a raw TCP request to avoid adding an HTTP client dep.
    async fn reqwest_get(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.strip_prefix("http://").unwrap();
        let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap();
        let mut stream = tokio::net::TcpStream::connect(hostport).await.unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }
}
