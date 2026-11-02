//! The intake and repository intelligence stages (`s1-stage-intake-and-repository`).
//!
//! The tests drive the two real handlers through the real engine over the labelled fakes of
//! `factory-testkit`, with the scripted adversarial runtime (FX-ADV) as the classifier. Every
//! test name says what it proves. The done criteria of the work package are found by these names:
//! `negative_nt_authz_01`, `negative_nt_authz_05`, `original_and_normalized_are_separate`,
//! `issue_text_cannot_change_grants`, `negative_nt_sec_07`, `repository_map_for_the_fixture` and
//! `baseline_in_sandbox`.
//!
//! The fakes are labelled `fake`, and so is every handler built over them, so these tests run in
//! test mode. The one test that needs a real container (`baseline_in_sandbox`) reports BLOCKED
//! when it is not asked for with `FACTORY_LIVE=1`, and when Docker or the image is missing.

#[path = "../support/mod.rs"]
mod support;

mod design;
mod harness;
mod intake;
mod pair;
mod repo_intel;
mod repo_rig;
mod webhook;
