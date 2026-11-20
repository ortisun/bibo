//! Shared support for the database tests of `factory-worker`: the one in `factory-composition`,
//! included as it is, so that there is one provisioning code, one scripted validator and one
//! engine-over-PostgreSQL world for both crates.
#![allow(dead_code, unused_imports)]

#[path = "../../../../crates/composition/tests/support/mod.rs"]
mod shared;

pub use shared::*;

pub mod deployment;
pub mod loopback;
