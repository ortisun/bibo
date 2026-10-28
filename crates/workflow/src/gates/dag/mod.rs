//! The deterministic task plan validator and the traceability matrix.
//!
//! Work package `s1-stage-architecture-and-planning`. These are pure functions of a typed
//! [`TaskDag`](factory_domain::contracts::TaskDag), the frozen specification and a set of limits:
//! no port, no clock, no agent. The planning stage runs them on the plan the planner returned and
//! turns the result into a gate report. A language model never decides that a plan is sound.
//!
//! | Module | What it holds |
//! |---|---|
//! | `graph` | Unique ids, dangling edges, cycles, the run order, parallel pairs, the critical path |
//! | `glob` | Whether two file patterns could name the same file |
//! | `validate` | Coverage, ownership, sizing and the rest of the checks, and their findings |
//! | `matrix` | The requirement, design, task, test and documentation traceability matrix |
//!
//! # Decisions that the specification leaves open
//!
//! * **The critical path is computed, not trusted.** The plan may declare one. The validator
//!   computes the longest chain by expected seconds and records both. A declared path that names a
//!   task the plan does not hold is a finding. A declared path that differs from the computed one is
//!   not, because the example plan in `schemas/examples` declares a path through two tasks that do
//!   not depend on each other, and that example must be accepted.
//! * **Parallelism is allowed only when it is proven harmless.** Two tasks that nothing orders are
//!   a finding when they may write the same file or own the same interface. The file test is
//!   conservative: patterns it cannot tell apart count as overlapping.

pub mod glob;
pub mod graph;
pub mod matrix;
pub mod validate;

pub use graph::{CriticalPath, Graph, Node, ShapeProblem};
pub use matrix::{DesignLink, Gap, Matrix, MatrixInput, Severity};
pub use validate::{Analysis, Check, Finding, Limits, Report, SpecFacts, validate};

/// The gate that holds the result of the validator.
pub const GATE_ID: &str = "task-plan-validator";
