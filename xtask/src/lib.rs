//! Architecture checks for the factory workspace.
//!
//! `cargo xtask check-architecture` reads `docs/architecture/crate-dependency-rules.json`, asks
//! Cargo for the real dependency graph, and fails when the workspace breaks a rule in that file.
//! xtask is repository tooling and not part of the product. The rules file allows it std and
//! serde_json only.

pub mod cli;
pub mod clippy_bans;
pub mod finding;
pub mod generated;
pub mod invariants;
pub mod links;
pub mod lints;
pub mod metadata;
pub mod rules;
pub mod scan;
pub mod source_scans;
pub mod st07;
pub mod static_checks;
pub mod syntax;
pub mod topology;
