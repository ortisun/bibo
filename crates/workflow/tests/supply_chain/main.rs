//! The dependency and supply chain gates, against the in-memory ports.
//!
//! The ports are the fakes of `factory-testkit`, the policy is the real security policy (as the
//! JSON fixture that `factory-contracts` keeps equal to `policies/security.yaml`), and the
//! registry, the audit tool and the SBOM tool are scripted programs of the fake sandbox. No
//! registry is reached, no real `cargo audit` runs, and no Docker is used: this crate may not
//! depend on the sandbox adapter (rule DEP-01), so the run in the pinned images belongs to the
//! end-to-end harness. The hostile fixtures of `fixtures/repos/security/` are read as text and
//! never written to a disk and never run.
//!
//! Every negative test of `docs/security/negative-test-catalog.md` that this package owns has a
//! function whose name starts `negative_nt_sup_...`.

mod files;
mod integrity;
