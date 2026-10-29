//! Independent re-review of the fixes for the HTTP API and the command line (API-1 to API-11) and of
//! what the API's database login can still do after the grant narrowing (API-3). 2026-10-29.
//!
//! Tests named `rr_` show a confirmed defect and are `#[ignore]`d, so the normal run stays green.
//! Tests named `held_` pin an attack that was tried and did not work. Everything that needs a
//! database is `#[ignore]`d too and says so.
//!
//! One defect:  `cargo test -p factory-api --test security_rereview --locked -- --ignored <name> --exact`
//! All defects: `cargo test -p factory-api --test security_rereview --locked -- --ignored rr_ --test-threads=1`
//! All probes:  `cargo test -p factory-api --test security_rereview --locked -- --include-ignored held_ --test-threads=1`
//!
//! A PostgreSQL server is needed for the database tests (`docs/database/running.md`); one that cannot
//! get it panics with `BLOCKED:`. No secret-shaped literal is written here.

#[path = "../support/mod.rs"]
mod support;

mod cli;
mod privileges;
mod sources;
