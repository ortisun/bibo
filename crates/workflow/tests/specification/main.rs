//! The specification stage (`s1-spec-adapter-and-stage`).
//!
//! The gate rules are pure and are tested directly in `gate`. The stage is tested through the real
//! engine over the labelled fakes, with the scripted adversarial runtime (FX-ADV) and a scripted
//! specification provider, in the other modules. The real Spec Kit adapter cannot be a dependency
//! of this crate (rule DEP-01), so its parser, integrity checks and post-conditions are proved in
//! `factory-spec_adapter`, on the recorded real output. The two meet at the typed contract.
//!
//! Every test name says what it proves. The done criteria of the work package are found by these
//! names: `self_ticked_checklist_is_not_evidence`, `stage_profile_check_blocks_forbidden_artifacts`
//! and `new_spec_revision_supersedes_downstream`. The negative tests of the catalog that this
//! package owns have a function whose name starts `negative_nt_`.

#[path = "../support/mod.rs"]
mod support;

mod gate;
mod invocation;
mod negative;
mod rig;
mod stage;
