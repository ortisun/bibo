//! The implementation and review stages (`s1-stage-implementation-and-review`).
//!
//! The tests drive the two real handlers through the real engine over the labelled fakes of
//! `factory-testkit`, with the scripted adversarial runtime (FX-ADV) as the builder and as the
//! reviewer. The stages before them are stand-ins that store the deliverables the real ones
//! would, and the validation stage is a stand-in that writes the evidence the real one writes
//! (the real validation stage has its own tests in `tests/validation`).
//!
//! Every test name says what it proves. The done criteria of the work package are found by these
//! names: `commits_happen_on_the_host`, `reviewer_never_sees_the_builder_summary`,
//! `negative_nt_inj_06`, `rework_is_capped_at_two`, `resume_after_crash` and
//! `agent_runs_only_in_the_sandbox`. The negative tests of the catalog that this package owns
//! have a function whose name starts `negative_nt_`.
//!
//! The fakes are labelled `fake`, and so is every handler built over them, so these tests run in
//! test mode. Real Docker and real git are out of reach of this crate (rule DEP-01): what they
//! add is listed in the final report of the work package, and the end-to-end harness proves it.

#[path = "../support/mod.rs"]
mod support;

mod rig;
mod standin;

mod build;
mod loops;
mod negative;
mod review;
