//! HTTP-level tests for the new tool-doctor and report-download endpoints.
//!
//! Drives the real axum router with an in-memory SQLite store, so routing,
//! handlers, serialization, and headers are all exercised end to end without a
//! live socket or any external scanning tools installed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use moosemap_server::{api, Orchestrator, Store};
use tower::ServiceExt; // for `oneshot`

async fn test_router() -> axum::Router {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let orch = Orchestrator::new(store, moosemap_scanners::default_executors());
    api::router(orch, None)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn tools_endpoint_returns_doctor_shape() {
    let app = test_router().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/tools")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let arr = json.as_array().expect("tools returns an array");
    assert!(!arr.is_empty());
    // Each entry has the rich doctor fields (not the old {name,installed}).
    let first = &arr[0];
    for key in ["name", "resolved_path", "state", "detail", "role", "install_hint"] {
        assert!(first.get(key).is_some(), "missing field: {key}");
    }
    // nmap is one of the known tools.
    assert!(arr.iter().any(|t| t.get("name").and_then(|n| n.as_str()) == Some("nmap")));
}

/// Create a run via the API and return its id.
async fn create_run(app: &axum::Router, name: &str, scope: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/runs")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"name": name, "scope": scope}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    json["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn report_json_download_has_attachment_headers() {
    let app = test_router().await;
    let id = create_run(&app, "Acme Ext", "192.0.2.0/30").await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/runs/{id}/report.json"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ctype = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ctype.contains("application/json"));
    let cd = resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cd.contains("attachment"));
    assert!(cd.contains("acme-ext-report.json"), "unexpected filename: {cd}");

    // Body is valid JSON carrying the run name.
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(json["name"].as_str(), Some("Acme Ext"));
}

#[tokio::test]
async fn report_markdown_download_has_attachment_headers() {
    let app = test_router().await;
    let id = create_run(&app, "Acme Ext", "192.0.2.0/30").await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/runs/{id}/report.md"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ctype = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ctype.contains("text/markdown"));
    let cd = resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cd.contains("acme-ext-report.md"), "unexpected filename: {cd}");

    let body = body_string(resp).await;
    assert!(body.starts_with("# MooseMap Assessment Report: Acme Ext"));
}

#[tokio::test]
async fn report_download_unknown_run_is_404() {
    let app = test_router().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/runs/{}/report.json", uuid::Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
