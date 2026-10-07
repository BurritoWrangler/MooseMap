//! Orchestrates runs: wires the engine to persistence and a live event bus.
//!
//! The orchestrator is the application service layer. The API calls it to create
//! and launch runs; it spawns the engine on a background task, mirrors engine
//! events into SQLite (so state survives restarts) and re-broadcasts them to any
//! connected WebSocket clients, and persists the final prioritized report.

use std::sync::Arc;

use chrono::Utc;
use moosemap_core::engine::Engine;
use moosemap_core::event::EngineEvent;
use moosemap_core::model::{Run, RunStatus, Stage, Task, TaskStatus};
use moosemap_core::scope::ScopeGuard;
use moosemap_report::{prioritize, Report};
use tokio::sync::broadcast;
use tracing::{error, info};
use uuid::Uuid;

use crate::store::Store;

/// Shared application state handed to axum handlers.
#[derive(Clone)]
pub struct Orchestrator {
    store: Store,
    /// Executors used to build an engine per run.
    executors: Arc<Vec<Arc<dyn moosemap_core::StageExecutor>>>,
    /// Server-wide event bus; WebSocket clients subscribe here.
    events: broadcast::Sender<EngineEvent>,
}

impl Orchestrator {
    pub fn new(
        store: Store,
        executors: Vec<Arc<dyn moosemap_core::StageExecutor>>,
    ) -> Self {
        let (events, _) = broadcast::channel(1024);
        Orchestrator {
            store,
            executors: Arc::new(executors),
            events,
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Subscribe to the live event stream (all runs).
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.events.subscribe()
    }

    /// Validate scope and create a run record. Does **not** start scanning.
    ///
    /// Returns an error listing invalid scope tokens if parsing fails, so the
    /// API can surface a 400 with actionable detail.
    pub async fn create_run(
        &self,
        name: String,
        scope_input: &str,
    ) -> Result<Run, CreateRunError> {
        let guard = ScopeGuard::from_input(scope_input).map_err(|errs| {
            CreateRunError::InvalidScope(
                errs.into_iter()
                    .map(|(tok, e)| format!("{tok}: {e}"))
                    .collect(),
            )
        })?;
        if guard.is_empty() {
            return Err(CreateRunError::EmptyScope);
        }

        // Keep the normalized scope tokens as declared.
        let scope: Vec<String> = scope_input
            .split([',', '\n', '\r', ' ', '\t'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let run = Run::new(name, scope);
        self.store
            .insert_run(&run)
            .await
            .map_err(|e| CreateRunError::Storage(e.to_string()))?;
        info!(run_id = %run.id, "created run");
        Ok(run)
    }

    /// Launch a previously-created run on a background task. Returns immediately.
    pub async fn start_run(&self, run_id: Uuid) -> Result<(), StartRunError> {
        let run = self
            .store
            .get_run(run_id)
            .await
            .map_err(|e| StartRunError::Storage(e.to_string()))?
            .ok_or(StartRunError::NotFound)?;

        if run.status == RunStatus::Running {
            return Err(StartRunError::AlreadyRunning);
        }

        let scope = ScopeGuard::from_input(&run.scope.join(","))
            .map_err(|_| StartRunError::Storage("stored scope no longer parses".into()))?;
        let scope = Arc::new(scope);

        let store = self.store.clone();
        let events = self.events.clone();
        let executors = (*self.executors).clone();

        tokio::spawn(async move {
            if let Err(e) = run_pipeline(store, events, executors, run, scope).await {
                error!(%run_id, error = %e, "run pipeline errored");
            }
        });

        Ok(())
    }

    /// Build the full report for a finished (or in-progress) run from storage.
    pub async fn build_report(&self, run_id: Uuid) -> anyhow::Result<Option<Report>> {
        let Some(run) = self.store.get_run(run_id).await? else {
            return Ok(None);
        };
        let services = self.store.list_services(run_id).await?;
        let findings = self.store.list_findings(run_id).await?;
        Ok(Some(Report::build(&run, services, findings)))
    }
}

/// Emit a stage task event for a post-engine stage (Prioritize/Report): persist
/// it to the store and broadcast it to WebSocket clients, so both the live GUI
/// and a later REST fetch show the stage with the given status. These stages are
/// handled here rather than by the engine (see [`Stage::engine_stages`]).
#[allow(clippy::too_many_arguments)]
async fn emit_stage_task(
    store: &Store,
    bus: &broadcast::Sender<EngineEvent>,
    run_id: Uuid,
    task_id: Uuid,
    stage: Stage,
    status: TaskStatus,
    message: Option<String>,
) {
    let now = Utc::now();
    // Reuse a stable task_id across the running->done transition so upsert_task
    // updates one row rather than creating duplicates.
    let task = Task {
        id: task_id,
        run_id,
        stage,
        status,
        message: message.clone(),
        started_at: Some(now),
        finished_at: if matches!(status, TaskStatus::Done | TaskStatus::Failed) {
            Some(now)
        } else {
            None
        },
    };
    let _ = store.upsert_task(&task).await;
    let _ = bus.send(EngineEvent::TaskStatusChanged {
        run_id,
        task_id,
        stage,
        status,
        message,
        at: now,
    });
}

/// Drives one run: subscribes to engine events, mirrors them to the store and
/// the server bus, runs the engine, then persists prioritized results.
async fn run_pipeline(
    store: Store,
    bus: broadcast::Sender<EngineEvent>,
    executors: Vec<Arc<dyn moosemap_core::StageExecutor>>,
    run: Run,
    scope: Arc<ScopeGuard>,
) -> anyhow::Result<()> {
    let run_id = run.id;
    let engine = Engine::new(executors, 1024);
    let mut rx = engine.subscribe();

    // Keep a sender clone for the post-engine (Prioritize/Report) stage events;
    // the relay task below takes ownership of `bus`.
    let post_bus = bus.clone();

    // Relay task: forward engine events to the server bus + persist them.
    let store_relay = store.clone();
    let relay = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            // Re-broadcast to WebSocket subscribers (ignore if none).
            let _ = bus.send(event.clone());

            // Mirror relevant events into storage.
            match &event {
                EngineEvent::RunStatusChanged { run_id, status, .. } => {
                    let _ = store_relay.update_run_status(*run_id, *status).await;
                }
                EngineEvent::TaskStatusChanged {
                    run_id,
                    task_id,
                    stage,
                    status,
                    message,
                    ..
                } => {
                    let task = moosemap_core::model::Task {
                        id: *task_id,
                        run_id: *run_id,
                        stage: *stage,
                        status: *status,
                        message: message.clone(),
                        started_at: None,
                        finished_at: None,
                    };
                    let _ = store_relay.upsert_task(&task).await;
                }
                EngineEvent::FindingAdded { run_id, finding, .. } => {
                    let _ = store_relay.insert_finding(*run_id, finding).await;
                }
                EngineEvent::Log { .. } => {}
            }
        }
    });

    // Run the engine (scanning stages) to completion.
    let result = engine.run(&run, scope).await;

    // --- Prioritize stage (post-engine; emits its own task events) -----------
    let prioritize_task = Uuid::new_v4();
    emit_stage_task(&store, &post_bus, run_id, prioritize_task, Stage::Prioritize,
        TaskStatus::Running, None).await;

    let mut findings = result.findings;
    prioritize::prioritize(&mut findings);
    let prioritize_result = async {
        store.replace_services(run_id, &result.services).await?;
        for f in &findings {
            store.insert_finding(run_id, f).await?;
        }
        anyhow::Ok(())
    }
    .await;

    if let Err(e) = &prioritize_result {
        emit_stage_task(&store, &post_bus, run_id, prioritize_task, Stage::Prioritize,
            TaskStatus::Failed, Some(e.to_string())).await;
        store.update_run_status(run_id, RunStatus::Failed).await?;
        drop(engine);
        let _ = relay.await;
        return Err(anyhow::anyhow!("prioritize/persist failed: {e}"));
    }
    let actionable = findings.iter().filter(|f| prioritize::is_actionable(f)).count();
    emit_stage_task(&store, &post_bus, run_id, prioritize_task, Stage::Prioritize,
        TaskStatus::Done,
        Some(format!("{} finding(s), {actionable} actionable", findings.len()))).await;

    // --- Report stage (post-engine) ------------------------------------------
    let report_task = Uuid::new_v4();
    emit_stage_task(&store, &post_bus, run_id, report_task, Stage::Report,
        TaskStatus::Running, None).await;
    // The report is built on demand from persisted data; confirm it builds so
    // the stage reflects a genuinely available report.
    let report_ok = Report::build(&run, result.services.clone(), findings.clone());
    emit_stage_task(&store, &post_bus, run_id, report_task, Stage::Report,
        TaskStatus::Done,
        Some(format!("report ready ({} services)", report_ok.services.len()))).await;

    store.update_run_status(run_id, result.status).await?;

    // Ensure the relay drains remaining buffered events, then finish.
    drop(engine);
    let _ = relay.await;

    info!(%run_id, status = %result.status, findings = findings.len(), "pipeline persisted");
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CreateRunError {
    #[error("invalid scope entries: {0:?}")]
    InvalidScope(Vec<String>),
    #[error("scope is empty")]
    EmptyScope,
    #[error("storage error: {0}")]
    Storage(String),
}

#[derive(Debug, thiserror::Error)]
pub enum StartRunError {
    #[error("run not found")]
    NotFound,
    #[error("run is already running")]
    AlreadyRunning,
    #[error("storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_scanners::default_executors;

    async fn orch() -> Orchestrator {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        Orchestrator::new(store, default_executors())
    }

    #[tokio::test]
    async fn create_run_rejects_invalid_scope() {
        let o = orch().await;
        let err = o.create_run("bad".into(), "not a host!, @@@").await.unwrap_err();
        assert!(matches!(err, CreateRunError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn create_run_rejects_empty_scope() {
        let o = orch().await;
        let err = o.create_run("empty".into(), "   ").await.unwrap_err();
        assert!(matches!(err, CreateRunError::EmptyScope));
    }

    #[tokio::test]
    async fn create_and_fetch_run() {
        let o = orch().await;
        let run = o.create_run("acme".into(), "192.0.2.0/24, example.com").await.unwrap();
        let fetched = o.store().get_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "acme");
        assert_eq!(fetched.scope.len(), 2);
    }

    #[tokio::test]
    async fn full_run_completes_and_builds_report() {
        // No external tools installed in CI -> every stage skips, run completes.
        let o = orch().await;
        let run = o.create_run("acme".into(), "192.0.2.0/24").await.unwrap();
        o.start_run(run.id).await.unwrap();

        // Poll until the run reaches a terminal state.
        let mut status = RunStatus::Pending;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            status = o.store().get_run(run.id).await.unwrap().unwrap().status;
            if matches!(status, RunStatus::Completed | RunStatus::Failed) {
                break;
            }
        }
        assert_eq!(status, RunStatus::Completed);

        let report = o.build_report(run.id).await.unwrap().unwrap();
        assert_eq!(report.name, "acme");

        let tasks = o.store().list_tasks(run.id).await.unwrap();
        assert_eq!(tasks.len(), moosemap_core::model::Stage::ordered().len());
    }

    #[tokio::test]
    async fn start_run_not_found() {
        let o = orch().await;
        let err = o.start_run(Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, StartRunError::NotFound));
    }
}
