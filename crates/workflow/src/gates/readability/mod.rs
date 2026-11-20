//! The readability gate: the deterministic part of the human-readable artifact quality gate.
//!
//! `docs/reference/documentation-policy.md` says what the gate is for and which rules block and
//! which only warn. `fixtures/readability/rules.json` is the catalog of rules and word lists, and
//! `fixtures/readability/cases/` is the corpus that decides the boundary cases. This module is
//! the code side:
//!
//! * [`catalog`] embeds the catalog at compile time and checks it against the functions here.
//! * [`check`] is the pure function: artifacts and options in, findings out. It reads only the
//!   text it is given, never edits it, and does an amount of work proportional to its size.
//! * [`options`] holds what a repository may switch off (only `title-type-tag`).
//!
//! The policy's last word on the reviewer rules is that they are not run here: they need a model.
//! The gate says in its report that the advisory review did not run, or reports `BLOCKED` when
//! the stage contract requires it.

mod artifact;
mod catalog;
mod engine;
mod finding;
mod gate;
mod lang;
mod options;
mod rules;
mod text;

pub use artifact::{Artifact, ArtifactKind, DocumentType};
pub use catalog::{
    Catalog, CatalogError, Language, Lists, RULES_JSON, ReviewerRule, RuleId, RuleSpec, Severity,
};
pub use engine::{CheckError, MAX_TOTAL_BYTES, check};
pub use finding::{Finding, Part};
pub use gate::{
    GATE_ID, GATE_VERSION, GateError, ReadabilityGate, ReportContext, ReportError, ReviewerPolicy,
    TOOL_NAME,
};
pub use options::{Options, OptionsError};
