//! Embeds the JSON schemas, validates agent output, and loads agent manifests, domain capability
//! profiles and policy files. This is a ring 2 adapter crate (ADR 0002). It depends on
//! `factory-domain` and `factory-ports` only, and it implements two ports: `OutputValidator` and
//! `AgentRegistry`.
//!
//! Work package: `s0-contracts-and-registry`.
//!
//! # Map
//!
//! | Module | What it holds | Port or contract |
//! |---|---|---|
//! | [`schemas`] | The eleven schemas of `schemas/`, embedded at compile time | |
//! | [`schema_engine`] | A closed JSON Schema (draft 2020-12) engine for exactly the keywords those schemas use | |
//! | [`validator`] | `SchemaOutputValidator`, the hard limits, the strict JSON parse, the path-safety rule | `OutputValidator` |
//! | [`agent_schema`] | `AgentSchema` and `AgentSchemaLoader`: an agent's output checked against ITS OWN schema in `agents/schemas/`, with the same limits and strict parse | |
//! | [`yaml`] | The restricted YAML reader, and the record of the YAML parser decision | parser contract in `policies/security.yaml` |
//! | [`loader`] | Agent manifests, capability profiles and project manifests into typed values, with file and field in every error | |
//! | [`registry`] | `FileAgentRegistry`: manifests, prompts with checked hashes, profiles by tag | `AgentRegistry` |
//! | [`policy`] | `policies/security.yaml` and `policies/approval.yaml` into typed values, with the policy hash | |
//!
//! # What is not here
//!
//! * **`ModelRouter`.** `policies/model_routing.yaml` exists, and [`policy::routing`] reads it into
//!   typed values. The router that applies it, `PolicyModelRouter`, is not in this crate: it is in
//!   `factory_composition::routing`. Every number in the file still waits for the project owner. The
//!   in-memory `StaticModelRouter` in `testkit` covers tests.
//! * **Policy evaluation.** Which tool is granted, which path is protected and who may approve what
//!   is `s1-policy-evaluation`. This crate only reads and validates the documents.
//!
//! # Decisions
//!
//! 1. **The `jsonschema` crate is not used.** See [`schema_engine`]. It fails `cargo deny` on two
//!    licences, and `deny.toml` may not be edited by this work package.
//! 2. **The YAML parser is `saphyr-parser`, used for events only.** See [`yaml`] for the comparison
//!    and the evidence.
//! 3. **The typed policy documents live in `factory-domain`, and this crate re-exports them.**
//!    `domain::policy` is ring 0 and cannot depend on this crate, and the evaluators of
//!    `s1-policy-evaluation` must name the types. So `policy::{common, security, approval}` moved
//!    into `factory-domain` (`crates/domain/src/policy/`). They use only `serde`, `regex` and
//!    `globset`, which the domain allow list names. [`policy`] keeps the loader, the cross-reference
//!    checks, the hash and the error type, and exposes the documents under their old paths.
//! 4. **Untrusted bytes go through [`validator::SchemaOutputValidator::parse_and_validate`].** The
//!    port method takes a value that was parsed already, so it can re-check the limits but cannot
//!    stop a parse that has happened.

pub mod agent_schema;
pub mod loader;
pub mod policy;
pub mod registry;
pub mod schema_engine;
pub mod schemas;
pub mod validator;
pub mod yaml;
