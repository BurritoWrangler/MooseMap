//! The pipeline engine: drives a run through its stages, tracks task state,
//! and broadcasts live events.
//!
//! The engine itself knows nothing about specific tools. It is handed a set of
//! [`StageExecutor`]s (one or more per [`Stage`]) which do the real work. This
//! keeps the engine testable and lets the `scanners` crate own tool integration.

use crate::event::{EngineEvent, LogLevel};
use crate::model::{Finding, Run, RunStatus, Service, Stage, Task, TaskStatus};
use crate::scope::ScopeGuard;
use chrono::Utc;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

/// Shared, mutable state accumulated as a run progresses.
///
/// Stage executors read what previous stages produced (e.g. the port scan reads
/// discovered targets; service enum reads open ports) and write their own output.
#[derive(Debug, Default)]
pub struct RunState {
    /// Concrete targets discovered/expanded from scope.
    pub targets: Vec<crate::model::Target>,
    /// Services discovered across all targets.
    pub services: Vec<Service>,
    /// Confirmed HTTP(S) endpoints from web recon (feeds the vuln scanner).
    pub web_endpoints: Vec<crate::model::WebEndpoint>,
    /// Findings accumulated so far.
    pub findings: Vec<Finding>,
}

/// Context passed to each stage executor.
pub struct StageContext {
    pub run_id: Uuid,
    pub scope: Arc<ScopeGuard>,
    pub state: Arc<Mutex<RunState>>,
    events: broadcast::Sender<EngineEvent>,
    stage: Stage,
}

impl StageContext {
    /// Emit a log line for this stage.
    pub fn log(&self, level: LogLevel, message: impl Into<String>) {
        let _ = self.events.send(EngineEvent::Log {
            run_id: self.run_id,
            stage: self.stage,
            level,
            message: message.into(),
            at: Utc::now(),
        });
    }

    pub fn info(&self, message: impl Into<String>) {
        self.log(LogLevel::Info, message);
    }

    pub fn warn(&self, message: impl Into<String>) {
        self.log(LogLevel::Warn, message);
    }

    /// Record a finding and broadcast it.
    pub async fn add_finding(&self, finding: Finding) {
        let _ = self.events.send(EngineEvent::FindingAdded {
            run_id: self.run_id,
            finding: Box::new(finding.clone()),
            at: Utc::now(),
        });
        self.state.lock().await.findings.push(finding);
    }
}

/// The outcome of running a stage.
pub enum StageOutcome {
    /// Stage completed normally.
    Completed,
    /// Stage had nothing to do (e.g. no targets, tool not installed).
    Skipped(String),
}

/// Something that performs the work of a single pipeline stage.
///
/// Implemented in the `scanners` crate. Multiple executors may be registered for
/// the same stage (e.g. several vuln scanners); they run in sequence.
#[async_trait::async_trait]
pub trait StageExecutor: Send + Sync {
    /// Which stage this executor belongs to.
    fn stage(&self) -> Stage;

    /// Short name for logging, e.g. "nmap".
    fn name(&self) -> &str;

    /// Do the work. Mutate shared state via `ctx.state`, emit findings via
    /// `ctx.add_finding`, and log via `ctx.info`/`ctx.warn`.
    async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome>;
}

// Re-export the async_trait macro users of this crate need.
pub use async_trait::async_trait;

/// Drives runs through the pipeline.
pub struct Engine {
    events: broadcast::Sender<EngineEvent>,
    executors: Vec<Arc<dyn StageExecutor>>,
}

impl Engine {
    /// Create an engine with the given stage executors and an event channel
    /// capacity (number of buffered events before lagging receivers drop).
    pub fn new(executors: Vec<Arc<dyn StageExecutor>>, event_capacity: usize) -> Self {
        let (events, _) = broadcast::channel(event_capacity.max(16));
        Engine { events, executors }
    }

    /// Subscribe to live events. Call before `run` to avoid missing early events.
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.events.subscribe()
    }

    /// Executors registered for a given stage, in registration order.
    fn executors_for(&self, stage: Stage) -> Vec<Arc<dyn StageExecutor>> {
        self.executors
            .iter()
            .filter(|e| e.stage() == stage)
            .cloned()
            .collect()
    }

    fn send_run_status(&self, run_id: Uuid, status: RunStatus) {
        let _ = self.events.send(EngineEvent::RunStatusChanged {
            run_id,
            status,
            at: Utc::now(),
        });
    }

    fn send_task_status(&self, task: &Task) {
        let _ = self.events.send(EngineEvent::TaskStatusChanged {
            run_id: task.run_id,
            task_id: task.id,
            stage: task.stage,
            status: task.status,
            message: task.message.clone(),
            at: Utc::now(),
        });
    }

    /// Execute a run end-to-end. Returns the final run state (findings/services)
    /// and the task records. Emits events throughout for live tracking.
    pub async fn run(
        &self,
        run: &Run,
        scope: Arc<ScopeGuard>,
    ) -> RunResult {
        let run_id = run.id;
        info!(%run_id, name = %run.name, "starting run");
        self.send_run_status(run_id, RunStatus::Running);

        let state = Arc::new(Mutex::new(RunState::default()));
        let mut tasks: BTreeMap<Stage, Task> = BTreeMap::new();
        let mut run_failed = false;

        for &stage in Stage::engine_stages() {
            let mut task = Task::new(run_id, stage);
            task.status = TaskStatus::Running;
            task.started_at = Some(Utc::now());
            self.send_task_status(&task);

            let ctx = StageContext {
                run_id,
                scope: scope.clone(),
                state: state.clone(),
                events: self.events.clone(),
                stage,
            };

            let executors = self.executors_for(stage);
            let mut any_ran = false;
            let mut skip_reasons: Vec<String> = Vec::new();
            let mut stage_error: Option<String> = None;

            if executors.is_empty() {
                skip_reasons.push("no executor registered".into());
            }

            for exec in executors {
                ctx.info(format!("running {}", exec.name()));
                match exec.execute(&ctx).await {
                    Ok(StageOutcome::Completed) => {
                        any_ran = true;
                    }
                    Ok(StageOutcome::Skipped(reason)) => {
                        ctx.warn(format!("{} skipped: {reason}", exec.name()));
                        skip_reasons.push(format!("{}: {reason}", exec.name()));
                    }
                    Err(e) => {
                        warn!(%run_id, stage = %stage, executor = exec.name(), error = %e, "stage executor failed");
                        ctx.log(LogLevel::Error, format!("{} failed: {e}", exec.name()));
                        stage_error = Some(format!("{}: {e}", exec.name()));
                    }
                }
            }

            task.finished_at = Some(Utc::now());
            if let Some(err) = stage_error {
                task.status = TaskStatus::Failed;
                task.message = Some(err);
                run_failed = true;
                self.send_task_status(&task);
                tasks.insert(stage, task);
                // A failed stage stops the pipeline; later stages depend on it.
                break;
            } else if any_ran {
                task.status = TaskStatus::Done;
                self.send_task_status(&task);
            } else {
                task.status = TaskStatus::Skipped;
                task.message = Some(skip_reasons.join("; "));
                self.send_task_status(&task);
            }
            tasks.insert(stage, task);
        }

        let final_status = if run_failed {
            RunStatus::Failed
        } else {
            RunStatus::Completed
        };
        self.send_run_status(run_id, final_status);
        info!(%run_id, status = %final_status, "run finished");

        let state = Arc::try_unwrap(state)
            .map(Mutex::into_inner)
            .unwrap_or_default();

        RunResult {
            run_id,
            status: final_status,
            tasks: tasks.into_values().collect(),
            services: state.services,
            web_endpoints: state.web_endpoints,
            findings: state.findings,
        }
    }
}

/// The result of a completed engine run.
#[derive(Debug)]
pub struct RunResult {
    pub run_id: Uuid,
    pub status: RunStatus,
    pub tasks: Vec<Task>,
    pub services: Vec<Service>,
    pub web_endpoints: Vec<crate::model::WebEndpoint>,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Severity, Exploitability, Target};

    struct DiscoveryStub;

    #[async_trait::async_trait]
    impl StageExecutor for DiscoveryStub {
        fn stage(&self) -> Stage {
            Stage::Discovery
        }
        fn name(&self) -> &str {
            "stub-discovery"
        }
        async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
            let mut st = ctx.state.lock().await;
            st.targets.push(Target::Ip("192.0.2.1".parse().unwrap()));
            Ok(StageOutcome::Completed)
        }
    }

    struct VulnStub;

    #[async_trait::async_trait]
    impl StageExecutor for VulnStub {
        fn stage(&self) -> Stage {
            Stage::VulnScan
        }
        fn name(&self) -> &str {
            "stub-vuln"
        }
        async fn execute(&self, ctx: &StageContext) -> anyhow::Result<StageOutcome> {
            let target = Target::Ip("192.0.2.1".parse().unwrap());
            ctx.add_finding(Finding::new(
                target,
                Some(443),
                "Test finding",
                "A synthetic finding for tests",
                Severity::High,
                Exploitability::ProofOfConcept,
                "stub-vuln",
            ))
            .await;
            Ok(StageOutcome::Completed)
        }
    }

    #[tokio::test]
    async fn runs_pipeline_and_collects_findings() {
        let engine = Engine::new(
            vec![Arc::new(DiscoveryStub), Arc::new(VulnStub)],
            64,
        );
        let mut rx = engine.subscribe();
        let run = Run::new("test", vec!["192.0.2.0/24".into()]);
        let scope = Arc::new(ScopeGuard::from_input("192.0.2.0/24").unwrap());

        let result = engine.run(&run, scope).await;

        assert_eq!(result.status, RunStatus::Completed);
        assert_eq!(result.findings.len(), 1);
        // The engine produces a task per engine-owned stage (prioritize/report
        // are handled post-engine by the orchestrator, not here).
        assert_eq!(result.tasks.len(), Stage::engine_stages().len());

        // We should have received a RunStatusChanged(Running) first.
        let first = rx.try_recv().unwrap();
        matches!(first, EngineEvent::RunStatusChanged { status: RunStatus::Running, .. });
    }

    #[tokio::test]
    async fn stages_without_executors_are_skipped_not_failed() {
        let engine = Engine::new(vec![Arc::new(DiscoveryStub)], 64);
        let run = Run::new("test", vec!["192.0.2.0/24".into()]);
        let scope = Arc::new(ScopeGuard::from_input("192.0.2.0/24").unwrap());
        let result = engine.run(&run, scope).await;
        assert_eq!(result.status, RunStatus::Completed);
        let skipped = result
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Skipped)
            .count();
        // Every engine-owned stage except Discovery has no executor -> skipped.
        assert_eq!(skipped, Stage::engine_stages().len() - 1);
    }
}
