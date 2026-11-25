//! The `TASK_PLANNING` stage: a task graph for the frozen specification and the approved design,
//! checked by rules and not by the word of the planner.
//!
//! Work package `s1-stage-architecture-and-planning`. The stage gives the `planner` agent the
//! frozen specification, the design, the repository map and the identifiers the factory assigned to
//! the plan, in a read-only sandbox, and takes back an envelope: a plan, or one question for a
//! person. It then checks the plan with the validator of `crate::gates::dag`, compares the plan's
//! metadata with its own copy of the values it assigned, builds the traceability matrix, computes the
//! critical path itself, and checks that every task is written in plain English.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `envelope` | The planner's envelope read strictly: a plan, or a question |
//! | `metadata` | The values the factory assigns to a plan, and the comparison with the plan's copy |
//! | `replan` | Which tasks of a plan that was sent back can be kept |
//! | `handler` | `PlanningHandler`, its configuration, its contract and its deliverable names |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//!
//! The checks themselves are in `crate::gates::dag`, which is pure and has no port.
//!
//! # Rules this stage keeps
//!
//! * **The metadata is the factory's.** The plan id, the version, the job, the mode, the
//!   specification and architecture references and the time are assigned before the planner runs.
//!   The planner copies them, the stage compares every field, and a plan that differs in one is
//!   sent back.
//! * **The plan is validated by rule.** A cycle, a dangling dependency, a duplicate identifier, an
//!   uncovered scenario or requirement, a task that serves nothing, two tasks that nothing orders
//!   and that may write the same file or own the same interface, a protected path, a specialist
//!   the factory does not run, and a plan or a task over its size limit each fail the gate.
//! * **The critical path is computed.** The planner may declare one. The stage computes the longest
//!   chain from the dependencies and the estimates, and records both.
//! * **A question is not a plan.** When the planner asks a person, the stage stores the question
//!   in its record and no plan, and the decision is a human gate.
//! * **A plan that was sent back is replanned in part.** The stage validates the earlier plan again,
//!   tells the planner which tasks passed every check, and the new plan is validated whole.
//! * **The plan is never repaired.** It is stored as the planner wrote it, even when it fails.
//!
//! # Decisions that the specification leaves open
//!
//! * **The plan's version comes from the round before it.** A first run is version 1. A run that
//!   replaces another is the version of the plan it replaces plus one. The `RoundSource` seam says
//!   which that is.
//! * **A stage run that waits for a person has no plan.** A person who approves it instead of
//!   answering leaves the implementation stage without a plan, and that stage blocks on the
//!   missing input.
//! * **Risk-first sequencing is the planner's job and is not checked.** No deterministic rule
//!   says which of two tasks is riskier.

pub mod envelope;
mod gates;
pub mod handler;
pub mod metadata;
pub mod replan;
mod run;

pub use gates::task_body;
pub use handler::{
    GRANTED_TOOLS, MATRIX, METADATA_GATE, PlanningConfig, PlanningDeps, PlanningHandler, RECORD,
    TASK_PLAN, TRACEABILITY_GATE,
};
