//! The domain model: identifiers, value objects, the Job, StageRun, Attempt and TaskNode state
//! machines, guards, contract types, and pure policy evaluation. Ring 0 of the workspace: it makes
//! no I/O, clock or random call and uses no async runtime.
//!
//! Time and identifiers come in as parameters: a [`Timestamp`](values::Timestamp) is built from a
//! value the `Clock` port produced or from a document, and an identifier is wrapped from a UUID
//! the `IdGenerator` port produced. Nothing here reads the environment or the file system.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | [`ids`] | One type for each kind of identifier, so a job id cannot stand in for a tenant id |
//! | [`scope`] | [`TenantScope`](scope::TenantScope), which every repository call will take |
//! | [`values`] | Checked wrappers: slugs, titles, prose, hashes, timestamps, versions, ranged numbers, counted lists |
//! | [`vocabulary`] | Closed sets shared by the contracts: execution mode, fidelity, risk tier, gate outcome, review verdict, stage kind, assurance level |
//! | [`state`] | The four state machines, their guards and actors, with the exact names and moves of `state-machine.json` |
//! | [`contracts`] | One type for each schema in `schemas/` |
//! | [`ledger`] | The evidence ledger hash chain |
//! | [`patterns`] | The regular expressions the schemas declare, which the types compile |
//! | [`policy`] | The typed policy documents and the pure rules that apply them |
//!
//! # How the code is kept equal to the documents
//!
//! * `docs/architecture/state-machine.json` is embedded by a test that compares it with the
//!   state tables in both directions.
//! * `schemas/` and `schemas/examples/` are embedded by tests that read every valid example into
//!   its type and back, refuse every invalid one for the stated reason, and compare patterns,
//!   closed sets, required fields and unknown fields with the schema files.
//! * The ledger chain hash is compared with an independent script.
//!
//! # Rules that apply to every type
//!
//! * A value read from a document is valid. Fields of the contract structs are public so code
//!   can build and change them, and [`Contract::validate`](contracts::Contract::validate) checks
//!   such a value.
//! * Error messages are plain English and name the rule that was broken.
//! * Where a type is stricter than its schema, its documentation says so.

pub mod contracts;
pub mod error;
pub mod ids;
pub mod ledger;
pub mod machines;
pub mod patterns;
pub mod policy;
pub mod redaction;
pub mod scope;
pub mod state;
pub mod values;
pub mod vocabulary;

mod macros;
