//! Independent security review of the HTTP API (`docs/reviews/api-security-review.md`).
//!
//! Every test in this target is `#[ignore]`, so the default run and CI stay green. There are two
//! kinds:
//!
//! * **Confirmed defects** (`defects.rs`, `api_10` in `cli.rs`). The reason string starts with
//!   `confirmed defect API-n`. Each asserts the behaviour the design requires and FAILS today. When
//!   a defect is fixed its test passes and the `#[ignore]` is removed.
//! * **Held probes** (`held.rs`, the `held_` test in `cli.rs`). The reason string starts with
//!   `held probe`. Each is an attack that was tried and did not work; it PASSES today, and is kept
//!   so that the claim "this held" can be re-run.
//!
//! Run the defects with
//! `cargo test -p factory-api --test security_review -- --ignored api_ --test-threads=1`
//! and the probes with
//! `cargo test -p factory-api --test security_review -- --ignored held_ --test-threads=1`.
//! A single test: `... -- --ignored defects::api_1_a_designation_narrowed_to_one_repository_does_not_reach_another --exact`.
//!
//! A PostgreSQL server is needed (`docs/database/running.md`); a test that cannot get one panics
//! with `BLOCKED:`. No secret-shaped literal is written here: every token and password is built
//! at run time.

#[path = "../support/mod.rs"]
mod support;

mod cli;
mod defects;
mod held;
mod util;
