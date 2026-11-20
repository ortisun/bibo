//! Independent re-review of the fixes for the decision signing (AUT-12), the redaction patterns
//! (API-4, API-5) and the profile check of the assembled pipeline (AUT-13). 2026-10-29.
//!
//! Tests named `rr_` show a confirmed defect and are `#[ignore]`d, so the normal run stays green.
//! Tests named `held_` pin an attack that was tried and did not work; they run normally unless they
//! need PostgreSQL, in which case they are `#[ignore]`d too and say so.
//!
//! One defect:  `cargo test -p factory-composition --test security_rereview --locked -- --ignored <name> --exact`
//! All defects: `cargo test -p factory-composition --test security_rereview --locked -- --ignored rr_`
//! All probes:  `cargo test -p factory-composition --test security_rereview --locked held_`
//!
//! No secret-shaped literal is written here: every password, token and key is built when a test runs.

#[path = "../support/mod.rs"]
mod support;

mod hook;
mod narrowing;
mod redaction;
mod registry;
mod signing;

use std::path::PathBuf;

pub(crate) fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}
