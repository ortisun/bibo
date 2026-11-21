//! The `IMPLEMENTATION` stage: a builder changes the code in a sandbox, and the factory ingests,
//! audits and commits the change on the host.
//!
//! Work package `s1-stage-implementation-and-review`. The stage runs the single builder agent over
//! the task graph in topological order. Each task has its own workspace, made over the commit of
//! the task before it, and its own `agent` sandbox. When the builder has finished and the sandbox
//! is gone, the host audits the tree (`Workspace::ingest`), makes the commit itself
//! (`Workspace::commit`) and records it in the task ledger. Then it names the first and the last
//! commit in the deliverable `implementation-result`, which the validation stage and the review
//! stage read.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `plan` | The task plan read, put in order and rendered for the builder |
//! | `report` | The builder's report, read strictly; its summary is dropped |
//! | `feedback` | What a rework round tells the builder |
//! | `evidence` | `implementation-result` and the evidence manifest |
//! | `scope` | The owned-files check |
//! | `seams` | The small traits the stage needs and no port offers, and the spec and posture checks |
//! | `input` | The names of the deliverables the stage takes from the runs before it |
//! | `contract` | The stage contract |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//! | `handler` | `ImplementationHandler`, the `StageHandler` |
//!
//! # Rules this stage keeps
//!
//! * The builder runs in the `agent` profile, over the workspace the stage made, or it does not
//!   run. The stage checks the spec it is given and the posture of the sandbox that was made.
//! * Nothing is read from the sandbox's tree until the sandbox is gone, and nothing is committed
//!   that `Workspace::ingest` did not return. The builder has no git directory, so no hook it
//!   writes ever runs on the host.
//! * A change the audit refuses is recorded with its paths and the rule, never dropped and never
//!   committed. `evaluate` turns it into a policy violation that blocks the stage run.
//! * What the builder says about its work (its summary, the commands it lists) is recorded as a
//!   statement and counted as nothing. The commits, the changed paths and the statistics are the
//!   host's own measurements.
//! * Every write to the task ledger carries the attempt and the epoch of its lease, so the store
//!   refuses a worker that lost the lease, and the stage stops before the audit and before the
//!   commit when the engine has cancelled the attempt (NT-LSE-01).
//!
//! # Decisions that the specification leaves open
//!
//! * **A rework run is one task.** The builder agent works on one planned task at a time, and a
//!   round that was sent back does not say which task is at fault. The run therefore builds one
//!   task, `rework-round-<n>`, on top of the commit the replaced run ended with. It receives the
//!   failed gate reports and the deduplicated findings as its only feedback, and its owned files
//!   are those of the whole plan.
//! * **The builder's `BLOCKED` and `NEEDS_HUMAN` ask a person.** They return a structured request
//!   (`builder-blocked`, `builder-needs-human`, `dependency-requested`) and the engine escalates.
//! * **A `DONE` with no change is invalid output.** The tree is measured, and the report that
//!   contradicts it is not believed.

pub mod contract;
pub mod evidence;
pub mod feedback;
mod gates;
pub mod handler;
pub mod input;
pub mod plan;
pub mod report;
pub(crate) mod run;
pub mod scope;
pub mod seams;

pub use contract::{COMMITS_GATE, GRANTED_TOOLS, PROTECTED_GATE, SCOPE_GATE};
pub use evidence::{EVIDENCE, ImplementationEvidence, RESULT};
pub use handler::{
    CommitIdentity, ImplementationConfig, ImplementationDeps, ImplementationHandler, StageBudget,
};
pub use input::{
    ARCHITECTURE, IMPLEMENTATION_RESULT, REPOSITORY_MAP, SPECIFICATION_CONTRACT, TASK_PLAN,
    VALIDATION_EVIDENCE,
};
pub use seams::{
    AgentOutputCheck, AnswerHistory, CapabilityProbes, Hold, LedgerError, PlannedTask,
    ReworkContext, ReworkSource, SeamError, TaskLedger, TaskRecord, WorkspaceAccess,
    WorkspaceAgentSpecs,
};
