//! The validation stage and the trusted gates, against the in-memory ports.
//!
//! The ports are the fakes of `factory-testkit`, the policy is the real security policy (as the
//! JSON fixture that `factory-contracts` keeps equal to `policies/security.yaml`), and the
//! output of `cargo test` is the output recorded from the pinned verify image. Real Docker is
//! out of reach of this crate: it may not depend on the sandbox adapter (rule DEP-01), so the
//! run of this stage in the pinned image belongs to the end-to-end harness.
//!
//! Every negative test of `docs/security/negative-test-catalog.md` that this package owns has a
//! function whose name starts `negative_nt_...`.

#[path = "../readability/schema_check.rs"]
mod schema_check;

mod cargo;
mod world;

mod gates;
mod negative_gate;
mod negative_secret;
mod schema;
