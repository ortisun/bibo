//! The `DOCUMENTING` stage: the smallest set of documents a change needs, written in a sandbox,
//! audited and committed on the host.
//!
//! Work package `s1-stage-documentation`. Documentation is a stage of its own, after the change was
//! built, validated and reviewed and before it is delivered (master prompt section 10). The stage
//! does not ask a model what to document. The impact policy of
//! [`crate::gates::docs::plan`] derives the plan from the diff, and the plan is stored as the
//! deliverable `documentation-plan` whatever follows. When the policy says nothing needs
//! documenting, the plan carries the rule, no writer runs, and the stage still proves that its
//! sandbox can be made.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `input` | The names of the deliverables of this stage and of the stage after it |
//! | `repo` | What the stages read from the job's object store on the host |
//! | `writer` | The writer's report, read strictly; its summary is dropped |
//! | `handler` | `DocumentingHandler`, its configuration and its stage contract |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//!
//! # Rules this stage keeps
//!
//! * The writer runs in the `agent` profile, over a checkout the stage made, or it does not run.
//!   Its manifest lets it write the README, the changelog and Markdown under `docs`, and the host
//!   checks every changed path against that list again, because a sandbox tool grant is not a
//!   control the host can see.
//! * Nothing is read from the sandbox's tree until the sandbox is gone, and nothing is committed
//!   that `Workspace::ingest` did not return. A refused change, or a path outside the writer's
//!   scope, is recorded with its paths and never committed. `evaluate` turns it into a policy
//!   violation that blocks the stage run.
//! * What the writer says about its work is recorded as a statement and counted as nothing. Its
//!   summary is dropped. Its claims count only when the file each one cites exists in the tree the
//!   host read.
//! * The documentation commit is made over the head of the code on the same job branch, so the
//!   evidence manifest of the delivery stage covers both.
//!
//! # Decisions that the specification leaves open
//!
//! * **The release note is the changelog entry.** The policy asks for a release-note line when a
//!   change ships in a release. Nothing in a job says it does, so the changelog entry carries it.
//! * **A bug fix with no mark in the diff is not detected.** See [`crate::gates::docs::plan`].
//! * **A rework round builds on the head the replaced run ended with.** A rework after a code
//!   change is a new run over the new code head: the composition root must not hand it the old
//!   head.

mod gates;
pub mod handler;
pub mod input;
pub mod repo;
pub(crate) mod run;
pub mod writer;

pub use handler::{
    DocumentingConfig, DocumentingDeps, DocumentingHandler, GRANTED_TOOLS, PLAN_GATE,
    PROTECTED_GATE, SCOPE_GATE, TRACE_GATE,
};
pub use input::{
    DOCUMENTATION_GATE_REPORT, DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, DOCUMENTATION_REVIEW,
    DOCUMENTATION_REVIEW_RECORD, DOMAIN_PROFILE, writer_model_of, writer_selection,
};
