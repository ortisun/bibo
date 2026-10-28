//! The `INTAKE` stage: who asked, what was asked, and whether to go on.
//!
//! Work package `s1-stage-intake-and-repository`. The stage turns a request that anyone could have
//! edited into a short plain-English request that later stages can read, and it does so in this
//! order: it checks that the person who applied the label is on the named allowlist (by numeric
//! id), stores the original text unchanged and apart, asks the intake classifier through the
//! runtime port with the text as untrusted data, checks the answer against the agent's own output
//! schema, and maps it to one of four outcomes: accept, clarify, decline, split.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `authorize` | Who may ask, found by numeric id, and the one refusal notice |
//! | `classify` | The classifier's answer read into a typed value, and the outcome rules |
//! | `normalize` | The title and description, and the documents the stage returns |
//! | `seams` | The small traits the stage needs and no port offers |
//! | `handler` | `IntakeHandler`, the `StageHandler` |
//! | `common` | The contract and the gate report builders that both stages of the package use |
//!
//! # Rules this stage keeps
//!
//! * An unauthorized request, and a request edited since the last person confirmed it, never reach
//!   an agent. The refusal is the same text for every reason, so it tells an attacker nothing about
//!   the allowlist.
//! * The original text is stored once, byte for byte, under its hash. The normalized request holds
//!   none of it.
//! * Nothing the issue says changes what the stage grants: the tools of the run are those of the
//!   agent manifest, read before the text, and the contract is resolved without the text.
//! * The classifier's answer is checked twice (its schema, then a typed read), and never repaired.
//!
//! # Decisions that the specification leaves open
//!
//! The classifier's schema has no field for "decline" or "split". The rules in
//! [`classify::IntakeRules`] map a kind of request (`question` by default) to a decline and a
//! number of domain tags to a split, and both are data a policy can change. A decline or a split
//! blocks the stage run, which an operator can override and the override is audited.

pub mod authorize;
pub mod classify;
pub mod common;
pub mod handler;
pub mod normalize;
pub mod seams;

pub use authorize::{Authorization, DenialReason, NOTICE, authorize};
pub use classify::{Classification, IntakeRules, Outcome, RequestKind};
pub use handler::{IntakeConfig, IntakeDeps, IntakeHandler, ORIGINAL_GATE, OUTCOME_GATE};
pub use seams::{
    AgentOutputCheck, AgentSandboxSpecs, AllowlistSource, CapabilityProbes, RecordedRequest,
    RequestSnapshot, RequestSource, SeamError,
};
