//! Independent security review of the supply chain gates (work package `s1-supply-chain-gates`).
//!
//! The builder wrote `tests/supply_chain/`. These tests were written afterwards by the reviewer,
//! who did not build the gates, and they try to break them. Each module says what it attacks.
//!
//! * A test marked `#[ignore = "confirmed defect SC-n: ..."]` **fails on the current code by
//!   design**. It states what the gate must do. Run all of them with
//!   `cargo test -p factory-workflow --test supply_chain_review -- --ignored`.
//!   The review document `docs/reviews/supply-chain-and-delivery-security-review.md` has the
//!   table of defects and the command that shows each one.
//! * A test without `#[ignore]` passes today and pins something that held under attack, so a
//!   later change cannot loosen it unnoticed.
//!
//! The harness of the builder (`files`, `people`, `world`) is included by path and is not edited.
//! Nothing here reaches a network, runs a hostile fixture, or uses a real credential.

// The included harness has helpers that these tests do not call.
#![allow(dead_code)]

#[path = "../supply_chain/files.rs"]
mod files;
#[path = "../supply_chain/people.rs"]
mod people;
#[path = "../readability/schema_check.rs"]
mod schema_check;
#[path = "../supply_chain/world.rs"]
mod world;

mod audit_config;
mod build_code;
mod dos;
mod evidence;
mod freshness;
mod held;
mod identity;
mod lookalike;
mod reader;
mod registry_input;
mod requirements;
