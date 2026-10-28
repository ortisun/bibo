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
//! | [`yaml`] | The restricted YAML reader, and the record of the YAML parser decision | parser contract in `policies/security.yaml` |
//! | [`loader`] | Agent manifests, capability profiles and project manifests into typed values, with file and field in every error | |
//! | [`registry`] | `FileAgentRegistry`: manifests, prompts with checked hashes, profiles by tag | `AgentRegistry` |
//! | [`policy`] | `policies/security.yaml` and `policies/approval.yaml` into typed values, with the policy hash | |
//!
//! # What is not here
//!
//! * **`ModelRouter`.** The slice plan lists `PolicyModelRouter` for this crate, and the port says
//!   it reads `policies/model_routing.yaml`. That file does not exist, and no schema or parser
//!   contract describes it, so a router would have to invent the file format. The work package that
//!   owns `policies/` has to write the file first. The in-memory `StaticModelRouter` in `testkit`
//!   covers tests until then.
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

pub mod loader;
pub mod policy;
pub mod registry;
pub mod schema_engine;
pub mod schemas;
pub mod validator;
pub mod yaml;
