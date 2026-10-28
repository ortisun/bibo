//! The typed policy documents, and (in later modules of this directory) the pure rules that
//! decide what a path, a command, a tool call, a dependency or an action may do.
//!
//! # Why the documents live here
//!
//! `policies/security.yaml` and `policies/approval.yaml` are read by `factory-contracts`, which is
//! a ring 2 adapter and depends on this crate. The evaluators in this module are ring 0 and must
//! name the document types, so the types are here and `factory-contracts` re-exports them. The
//! types use `serde`, `regex` and `globset` only, all three on the `domain` allow list in
//! `docs/architecture/crate-dependency-rules.json`. Reading a file, parsing YAML, checking that
//! names used in one place are defined in another, and the policy hash stay in `factory-contracts`.
//!
//! No policy type implements `Default`: a missing policy is an error, never an empty allow.

pub mod approval;
pub mod common;
pub mod security;

pub use approval::ApprovalPolicy;
pub use common::{ConfigSource, GlobText, PolicyStatus, RegexText, ThreatId};
pub use security::SecurityPolicy;
