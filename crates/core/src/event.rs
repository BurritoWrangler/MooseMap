//! Live events emitted by the engine for real-time status tracking.
//!
//! The engine publishes [`EngineEvent`]s over a Tokio broadcast channel. The
//! server relays them to WebSocket clients; the CLI can print them. Events are
//! cheap clones and serializable so they can go straight onto the wire.

use crate::model::{Finding, RunStatus, Stage, TaskStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A real-time event about the progress of a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEvent {
    /// A run changed overall status.
    RunStatusChanged {
        run_id: Uuid,
        status: RunStatus,
        at: DateTime<Utc>,
    },
    /// A stage task changed status.
    TaskStatusChanged {
        run_id: Uuid,
        task_id: Uuid,
        stage: Stage,
        status: TaskStatus,
        message: Option<String>,
        at: DateTime<Utc>,
    },
    /// Free-form progress log line tied to a stage.
    Log {
        run_id: Uuid,
        stage: Stage,
        level: LogLevel,
        message: String,
        at: DateTime<Utc>,
    },
    /// A new finding was produced.
    FindingAdded {
        run_id: Uuid,
        finding: Box<Finding>,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl EngineEvent {
    pub fn run_id(&self) -> Uuid {
        match self {
            EngineEvent::RunStatusChanged { run_id, .. }
            | EngineEvent::TaskStatusChanged { run_id, .. }
            | EngineEvent::Log { run_id, .. }
            | EngineEvent::FindingAdded { run_id, .. } => *run_id,
        }
    }
}
