//! Tests of the pure policy evaluators in `factory_domain::policy`, built from the real
//! `policies/security.yaml` and `policies/approval.yaml` (through the fixtures that
//! `factory-contracts` keeps equal to them).
//!
//! Every negative test of `docs/security/negative-test-catalog.md` that the work package
//! `s1-policy-evaluation` owns has a function here whose name starts `negative_nt_...`. The
//! tests that guard a control also run against a weakened input or rule where that is possible
//! from the outside; the deliberate breaks of the implementation itself are recorded in the
//! hand-off, with the failures they cause.

#[path = "policy/support.rs"]
mod support;

#[path = "policy/paths.rs"]
mod paths;
