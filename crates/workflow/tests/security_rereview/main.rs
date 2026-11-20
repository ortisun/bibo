//! Independent re-review of the fixes for the authority, approval, delivery and gate findings
//! (AUT-1 to AUT-13) and for the supply chain gates and their policy follow-ups. 2026-10-29.
//!
//! Tests named `rr_` show a confirmed defect and are `#[ignore]`d, so the normal run stays green.
//! Tests named `held_` pin an attack that was tried and did not work; they run normally.
//!
//! One defect:  `cargo test -p factory-workflow --test security_rereview --locked -- --ignored <name> --exact`
//! All defects: `cargo test -p factory-workflow --test security_rereview --locked -- --ignored rr_`
//! All probes:  `cargo test -p factory-workflow --test security_rereview --locked held_`

#[path = "../support/mod.rs"]
mod support;

mod commands;
mod lint;
mod lint_property;
mod overrides;
mod risk;
