//! The `SPECIFICATION` stage: the request becomes a typed, frozen specification.
//!
//! Work package `s1-spec-adapter-and-stage`. The stage runs the three skills of the writer that
//! the policy allows besides the constitution (specify, clarify, checklist), each in its own
//! sandbox over the commit of the one before. The host audits the tree, commits it, reads the files
//! back and hands the exact bytes to the specification provider, which builds the typed contract.
//! A deterministic gate of the factory's own, an independent reviewer and, unless the policy says
//! otherwise, a person decide. Only then is the specification frozen.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `seams` | The small traits the stage needs and no port offers: approvals, drafts, history |
//! | `input` | The names of the deliverables and of the files the skills read |
//! | `evidence` | The host's measurements, as the document `evaluate` reads |
//! | `judge` | Every rule of the gate, run over the contract and the evidence |
//! | `contract` | The stage contract |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//! | `handler` | `SpecificationHandler`, the `StageHandler` |
//!
//! The gate rules themselves are in `crate::gates::spec`.
//!
//! # Rules this stage keeps
//!
//! * The request travels in a file. The skills run with a fixed instruction, and issue text never
//!   reaches their arguments.
//! * Nothing is read from a sandbox's tree until the sandbox is gone, and nothing is committed that
//!   `Workspace::ingest` did not return.
//! * A forbidden skill after the run, a forbidden file, a denied call in the event stream or a
//!   write outside the four skills' files makes `stage_profile_check` fail. The stage run is
//!   blocked, nobody is asked to override it, and the output does not count.
//! * Spec Kit's own ticks count as nothing. A checklist item counts when the independent reviewer
//!   verified it or a person waived it with a reason.
//! * Authorization is a structured record written by the engine when a person decides. The text
//!   of the specification, the request and the answers is never read for it.
//! * A frozen specification is never edited. A revision is a new feature directory, seeded from the
//!   old one, linked to it and numbered one higher.
//!
//! # Decisions that the specification leaves open
//!
//! * **The constitution is not written here.** It belongs to the repository and is approved apart
//!   from any feature request, and no agent manifest grants the constitution skill. A run that finds
//!   no filled constitution asks a person (`constitution-required`).
//! * **Questions come from the files and from the output.** The provider notes the questions it
//!   hears and the markers it finds. The stage puts them to a person with their text unchanged, and
//!   stops after the configured number of rounds.
//! * **Approval comes after the gate.** The first attempt that passes every rule keeps its draft
//!   and asks (`specification-approval-needed`). The next attempt reads the approval the engine
//!   recorded for that draft and freezes exactly that draft.

pub mod contract;
pub mod evidence;
mod gates;
pub mod handler;
pub mod input;
pub mod judge;
pub(crate) mod run;
pub mod seams;

pub use contract::{GRANTED_TOOLS, gates as gate_ids};
pub use evidence::{Evidence, Failure, Refusal, ReviewRecord, Revision};
pub use handler::{
    CommitIdentity, SpecificationConfig, SpecificationDeps, SpecificationHandler, StageBudget,
};
pub use input::{
    ANSWERS_FILE, EVIDENCE, NORMALIZED_REQUEST, REPOSITORY_MAP, REQUEST_FILE, REVIEWER,
    SPECIFICATION_CONTRACT, WRITER,
};
pub use judge::REVIEW;
pub use seams::{
    AgentOutputCheck, ApprovalRecord, CapabilityProbes, DraftRecord, PreviousSpec, ReworkContext,
    ReworkSource, SeamError, SpecApprovals, SpecDrafts, SpecHistory, WorkspaceAccess,
    WorkspaceAgentSpecs,
};
