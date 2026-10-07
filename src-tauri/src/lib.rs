//! MooseMap desktop app.
//!
//! Wraps the existing MooseMap stack in a native window: it starts the axum
//! API + WebSocket server **in-process** on a localhost port, then points a
//! Tauri webview window at it. The React GUI, API, and live event stream are
//! reused unchanged — the only difference from "run the server + open a
//! browser" is that everything lives in one window with no terminal.
//!
//! ## Lifecycle
//! - A dedicated Tokio runtime hosts the server; it is kept alive for the whole
//!   app via managed state, so the server runs as long as the window is open.
//! - Closing the window exits the process, which stops the server.

use std::sync::Arc;

use tauri::{WebviewUrl, WebviewWindowBuilder};

/// Keeps the server's Tokio runtime alive for the lifetime of the app.
/// Dropping this shuts the runtime (and the server) down.
struct ServerRuntime {
    _rt: Arc<tokio::runtime::Runtime>,
}

/// The default address the in-process server tries first. If it's busy,
/// `serve_in_process` falls back to an OS-assigned port automatically.
fn default_config() -> moosemap_server::ServerConfig {
    let mut cfg = moosemap_server::ServerConfig::default();
    // Allow overriding the DB location / bind addr via the same env vars the
    // CLI honors, so the desktop app and CLI can share a database if desired.
    if let Ok(db) = std::env::var("MOOSEMAP_DB") {
        cfg.database_url = db;
    }
    if let Ok(addr) = std::env::var("MOOSEMAP_ADDR") {
        if let Ok(parsed) = addr.parse() {
            cfg.addr = parsed;
        }
    }
    // The desktop app serves its own frontend via the embedded server; use the
    // repo/bundle frontend dist. When bundled, this is resolved relative to the
    // working directory; for a dev run it's ../frontend/dist.
    cfg
}

/// Start the in-process server and return (runtime guard, server URL).
///
/// Blocks until the server socket is bound so we have a real URL to navigate
/// the window to. The server itself runs on a background task on this runtime.
fn start_server() -> anyhow::Result<(ServerRuntime, String)> {
    let rt = Arc::new(tokio::runtime::Runtime::new()?);
    let cfg = default_config();
    let url = rt.block_on(moosemap_server::serve_in_process(cfg))?;
    Ok((ServerRuntime { _rt: rt }, url))
}

/// Build and run the desktop application. Returns when the window is closed.
pub fn run() -> anyhow::Result<()> {
    // Start the embedded server first so we can point the window at it.
    let (server_rt, url) = start_server()?;
    tracing::info!(%url, "embedded server ready; opening window");

    let parsed_url = url
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid server url {url}: {e}"))?;

    tauri::Builder::default()
        // Keep the runtime alive for the whole app lifetime.
        .manage(server_rt)
        .setup(move |app| {
            // Create the main window pointing at the embedded server URL. We
            // build it here (rather than from config) because the port is only
            // known at runtime.
            let win = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External(parsed_url),
            )
            .title("MooseMap")
            .inner_size(1280.0, 860.0)
            .min_inner_size(900.0, 600.0)
            .center()
            .resizable(true)
            .build()?;
            win.show()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("error running MooseMap desktop app: {e}"))?;

    Ok(())
}
