//! # moosemap-core
//!
//! Core domain models, scope parsing/enforcement, and the pipeline engine for
//! MooseMap — an orchestrator for **authorized** external penetration tests.
//!
//! The crate is deliberately tool-agnostic: it defines *what* a run is and *how*
//! stages are sequenced and tracked, while the `scanners` crate provides the
//! concrete [`engine::StageExecutor`] implementations that drive real tools.
//!
//! ## Safety model
//!
//! [`scope::ScopeGuard`] is the central guard rail. Every target must be checked
//! against it before any scanner acts, ensuring MooseMap only touches assets the
//! operator declared in scope.

pub mod engine;
pub mod event;
pub mod model;
pub mod scope;

pub use engine::{Engine, RunResult, RunState, StageContext, StageExecutor, StageOutcome};
pub use event::{EngineEvent, LogLevel};
pub use model::{
    Exploitability, Finding, PortState, Protocol, Run, RunStatus, Service, Severity,
    Stage, Target, Task, TaskStatus, WebEndpoint,
};
pub use scope::{OutOfScope, ScopeEntry, ScopeError, ScopeGuard};
