//! Scenario tests of the engine, over the in-memory store and the scripted stage handlers.
//!
//! Each test drives the engine through the public API only: it receives a job, admits it, claims
//! work, moves the fake clock, sweeps, and then reads the job back. The scenarios use the `Store`
//! trait and no detail of the in-memory store, so the same suite can run on another store.

//!
//! The scenarios are written against the `Store` port and the [`support::Backend`] levers, and
//! they live in `engine_scenarios/body.rs`. This file runs them on the in-memory store. The same
//! file is included by `apps/worker/tests/engine_scenarios_on_postgres_all.rs`, which runs them on
//! `PgStore`. `engine_scenarios/in_memory_only.rs` holds the scenarios that need a deliberately
//! broken store, which PostgreSQL cannot be made to be.

mod support;

include!("engine_scenarios/body.rs");
include!("engine_scenarios/in_memory_only.rs");
