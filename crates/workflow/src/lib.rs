//! The durable workflow engine and every stage handler: admission, scheduling, leases, retries,
//! gate evaluation and rework routing. An application crate: it depends on `factory-domain` and
//! `factory-ports` and never on an adapter.
//!
//! # What the engine is
//!
//! A narrow PostgreSQL-backed durable state machine (ADR 0001), driven through the `Store` port.
//! Rows hold the state. The transition tables and guards live in `factory-domain`. This crate
//! decides *when* a move is justified, builds the facts the guards read, asks the guard, plans the
//! move through `AppliedTransition::plan` (which asks the transition table) and writes the status
//! change, its evidence and its outbox event in **one transaction** (invariants INV-02 and
//! INV-03). A language model never decides that a stage advanced: an agent returns data, a gate
//! reads recorded evidence, and the engine applies the result.
//!
//! This crate makes no I/O call of its own (rule DEP-05). Time comes from the `Clock` port and
//! from `Tx::database_time`, identifiers from `IdGenerator`, and everything else through the
//! ports. `crates/workflow/clippy.toml` bans the calls that would break the rule.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | [`engine`] | [`Engine`](engine::Engine), its configuration, the single place that writes a decision, and the use cases: admission, attempt results, failure handling, gating, rework, supersession |
//! | [`scheduler`] | The claim loop, the lease heartbeat, the sweeper and the retry back-off |
//! | [`commands`] | What a person or an operator can ask for, and the [`Authority`](commands::Authority) seam that says who may |
//! | [`handlers`] | The [`StageHandler`](handlers::StageHandler) trait that each stage package implements, and the registry |
//! | [`gates`] | The gate framework: how stored evidence becomes a gate outcome. The stage packages add gates under it |
//! | [`prompts`] | The prompt assembler: where text that other people or programs wrote enters a model prompt, inside delimited, quoted blocks, with secrets removed and a record of what the model saw |
//! | [`audit`] | The audit stream with actor, policy hash and correlation id, and the verifier that re-reads a job |
//! | [`stages`] | The module lines of every stage directory. Each stage package fills its own directory |
//!
//! # Where the engine keeps what it knows about a job
//!
//! In the store, and nowhere else. The engine rebuilds its view of a job from the rows that the
//! listing operations of the `Store` port return: the stage runs, the attempts of each one, and the
//! artifacts each one consumed and produced. A restart needs no memory of the old process. The
//! outbox is a notification record, and the engine reads it only for the few facts that the store
//! has no row for yet. `engine::timeline` names each of them and says what is missing.

pub mod audit;
pub mod commands;
pub mod conventions;
pub mod engine;
pub mod gates;
pub mod handlers;
pub mod prompts;
pub mod scheduler;
pub mod stages;
