//! HTTP + WebSocket API.
//!
//! REST endpoints create/list/inspect runs and fetch reports; the WebSocket
//! endpoint streams live [`EngineEvent`]s for real-time status tracking in the
//! GUI. Built frontend assets (if present) are served as a SPA fallback.

use std::path::PathBuf;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::orchestrator::{CreateRunError, Orchestrator, StartRunError};

/// Build the axum router. `frontend_dir`, when provided and present, is served
/// as static files with SPA fallback to `index.html`.
pub fn router(orch: Orchestrator, frontend_dir: Option<PathBuf>) -> Router {
    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/tools", get(tools))
        .route("/api/runs", get(list_runs).post(create_run))
        .route("/api/runs/:id", get(get_run))
        .route("/api/runs/:id/start", post(start_run))
        .route("/api/runs/:id/tasks", get(get_tasks))
        .route("/api/runs/:id/report", get(get_report))
        .route("/api/runs/:id/report.json", get(download_report_json))
        .route("/api/runs/:id/report.md", get(download_report_md))
        .route("/api/events", get(ws_handler))
        .with_state(orch)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    match frontend_dir {
        Some(dir) if dir.join("index.html").exists() => {
            let index = dir.join("index.html");
            let serve = ServeDir::new(dir).not_found_service(ServeFile::new(index));
            api.fallback_service(serve)
        }
        _ => api.fallback(spa_placeholder),
    }
}

async fn spa_placeholder() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        include_str!("placeholder.html"),
    )
}

// ---- DTOs ----

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Deserialize)]
struct CreateRunRequest {
    name: String,
    /// Raw scope text: comma/space/newline separated IPs, CIDRs, FQDNs.
    scope: String,
    /// Start scanning immediately after creation.
    #[serde(default)]
    start: bool,
}

/// A uniform JSON error body.
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    details: Vec<String>,
}

impl ApiError {
    fn new(msg: impl Into<String>) -> Self {
        ApiError { error: msg.into(), details: Vec::new() }
    }
    fn with_details(msg: impl Into<String>, details: Vec<String>) -> Self {
        ApiError { error: msg.into(), details }
    }
}

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

// ---- handlers ----

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        name: "moosemap",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Tool "doctor": per-tool resolved path, health (ok/wrong/missing), role, and
/// install hint. Runs the same resolve+verify path the scan adapters use, so the
/// GUI's readiness panel reflects exactly what a scan will do (incl. catching the
/// Python `httpx` that shadows ProjectDiscovery's on Kali).
async fn tools() -> Json<Vec<moosemap_scanners::ToolStatus>> {
    Json(moosemap_scanners::tool_report().await)
}

async fn list_runs(State(orch): State<Orchestrator>) -> ApiResult<Response> {
    let runs = orch
        .store()
        .list_runs()
        .await
        .map_err(internal)?;
    Ok(Json(runs).into_response())
}

async fn create_run(
    State(orch): State<Orchestrator>,
    Json(req): Json<CreateRunRequest>,
) -> ApiResult<Response> {
    if req.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("run name is required")),
        ));
    }
    let run = orch.create_run(req.name, &req.scope).await.map_err(|e| match e {
        CreateRunError::InvalidScope(details) => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::with_details("invalid scope", details)),
        ),
        CreateRunError::EmptyScope => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("scope is empty")),
        ),
        CreateRunError::Storage(s) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new(s)),
        ),
    })?;

    if req.start {
        orch.start_run(run.id).await.map_err(start_err)?;
    }

    Ok((StatusCode::CREATED, Json(run)).into_response())
}

async fn get_run(
    State(orch): State<Orchestrator>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    match orch.store().get_run(id).await.map_err(internal)? {
        Some(run) => Ok(Json(run).into_response()),
        None => Err(not_found()),
    }
}

async fn start_run(
    State(orch): State<Orchestrator>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    orch.start_run(id).await.map_err(start_err)?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({"started": id}))).into_response())
}

async fn get_tasks(
    State(orch): State<Orchestrator>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    let tasks = orch.store().list_tasks(id).await.map_err(internal)?;
    Ok(Json(tasks).into_response())
}

async fn get_report(
    State(orch): State<Orchestrator>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    match orch.build_report(id).await.map_err(internal)? {
        Some(report) => Ok(Json(report).into_response()),
        None => Err(not_found()),
    }
}

/// A filesystem-safe slug from the run name, for the download filename.
fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_ascii_lowercase();
    if s.is_empty() { "moosemap-report".into() } else { s }
}

/// Download the report as a pretty-printed JSON attachment.
async fn download_report_json(
    State(orch): State<Orchestrator>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    let Some(report) = orch.build_report(id).await.map_err(internal)? else {
        return Err(not_found());
    };
    let body = report.to_json().map_err(internal)?;
    let filename = format!("{}-report.json", slug(&report.name));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response())
}

/// Download the report as a Markdown attachment.
async fn download_report_md(
    State(orch): State<Orchestrator>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    let Some(report) = orch.build_report(id).await.map_err(internal)? else {
        return Err(not_found());
    };
    let body = report.to_markdown();
    let filename = format!("{}-report.md", slug(&report.name));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response())
}

/// WebSocket endpoint streaming live engine events as JSON text frames.
async fn ws_handler(
    State(orch): State<Orchestrator>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| ws_stream(socket, orch))
}

async fn ws_stream(mut socket: WebSocket, orch: Orchestrator) {
    let mut rx = orch.subscribe();
    // Greet so clients can confirm the stream is live.
    let _ = socket
        .send(Message::Text(
            serde_json::json!({"type": "connected"}).to_string(),
        ))
        .await;

    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Ok(ev) => {
                    if let Ok(text) = serde_json::to_string(&ev) {
                        if socket.send(Message::Text(text)).await.is_err() {
                            break; // client gone
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Dropped some events; tell the client to refetch state.
                    let _ = socket.send(Message::Text(
                        serde_json::json!({"type": "lagged"}).to_string(),
                    )).await;
                }
                Err(_) => break, // sender dropped
            },
            // Drain/observe inbound frames so pings/closes are handled.
            inbound = socket.recv() => match inbound {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
}

// ---- error helpers ----

fn internal(e: impl std::fmt::Display) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError::new(e.to_string())),
    )
}

fn not_found() -> (StatusCode, Json<ApiError>) {
    (StatusCode::NOT_FOUND, Json(ApiError::new("not found")))
}

fn start_err(e: StartRunError) -> (StatusCode, Json<ApiError>) {
    match e {
        StartRunError::NotFound => not_found(),
        StartRunError::AlreadyRunning => (
            StatusCode::CONFLICT,
            Json(ApiError::new("run is already running")),
        ),
        StartRunError::Storage(s) => internal(s),
    }
}
