//! The cross-cutting negative tests of `s1-security-review-and-tests`.
//!
//! The tests of this target do not belong to one stage. They run the injection corpus through the
//! engine with a runtime that obeys every instruction it is given (NT-INJ-01, NT-INJ-03,
//! NT-INJ-04), plant a canary of every secret class and sweep every sink a job writes to
//! (NT-SEC-01), and show that every audit event type the policy requires appears with its actor,
//! policy hash and correlation id and has an owner (NT-AUD-03).
//!
//! The rig is the one of the implementation stage tests, included by path, so these tests run the
//! real implementation handler through the real engine over the labelled fakes. Real Docker is out
//! of reach of this crate (rule DEP-01): what a real container adds is named in the matrix
//! `docs/security/p0-coverage.md`, where the tests that need it are BLOCKED and never passed.
//!
//! Every test name starts with `negative_` and the catalog id, so the filter of the work package
//! (`negative_nt_inj_01`, `negative_nt_inj_03`, `negative_nt_inj_04`, `negative_nt_sec_01`,
//! `negative_nt_aud_03`) selects it.

#[path = "../support/mod.rs"]
mod support;

#[path = "../implementation/rig.rs"]
mod rig;
#[path = "../implementation/standin.rs"]
mod standin;

/// The implementation target registers its review handler through this module. These tests run
/// without a reviewer in the pipeline, so the registration does nothing.
mod review {
    use std::sync::Arc;

    use factory_workflow::handlers::HandlerRegistry;

    use crate::rig::{RigSpecs, StandInCheck};

    pub fn register(_: &mut HandlerRegistry, _: &Arc<StandInCheck>, _: &Arc<RigSpecs>) {}
}

#[path = "../prompts/support.rs"]
mod prompts_support;

mod audit_matrix;
mod corpus;
mod negative;
mod negative_aud;
mod negative_sec;
mod obey;
mod sweep;
