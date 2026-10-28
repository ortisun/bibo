//! The delivery and approval stages, against the in-memory ports.
//!
//! The ports are the fakes of `factory-testkit`. The code host is the in-memory `FakeChangeHost`
//! behind a recording wrapper (`spy`), so a test can read what reached the host. The policy is the
//! real approval and security policy (as the JSON fixtures that `factory-contracts` keeps equal to
//! `policies/*.yaml`). Real GitHub is out of reach of this crate (rule DEP-01): what is checked
//! here is the stage against the contract of the port, and the behaviour of the real adapter is
//! unverified by these tests.
//!
//! Every negative test of `docs/security/negative-test-catalog.md` that this package owns has a
//! function whose name starts `negative_nt_...`.

#[path = "../readability/schema_check.rs"]
#[allow(dead_code)]
mod schema_check;

#[path = "../support/mod.rs"]
mod support;

mod spy;
mod world;

mod approval;
mod approval_stage;
mod happy;
mod judging;
mod negative;
