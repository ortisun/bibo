//! The architecture and task planning stages (`s1-stage-architecture-and-planning`).
//!
//! The tests drive the two real handlers through the real engine over the labelled fakes of
//! `factory-testkit`, with the scripted adversarial runtime (FX-ADV) as the architect, the planner
//! and the critic. The stages before them (intake, repository intelligence, specification and
//! domain discovery) are stand-ins that store the deliverables the real ones would, and the
//! implementation stage is a stand-in that reads what planning produced by the names the real one
//! uses. Each of those stages has its own tests in its own package.
//!
//! Every test name says what it proves. The done criteria of the work package are found by these
//! names: `traceability_gate`, `dag_validator`, `critic_runs_only_when_policy_requires` and
//! `task_text_is_readable`. The package has no negative test of the catalog assigned to it. The
//! tests named `injection_` and `negative_` are the package's own cases for the same attacks as
//! NT-INJ-02, NT-INJ-03 and NT-INJ-06, applied to the text these two stages read and write.
//!
//! The fakes are labelled `fake`, and so is every handler built over them, so these tests run in
//! test mode. What real Docker, a real model and a real repository add is listed in the report of
//! the work package.

#[path = "../support/mod.rs"]
mod support;

mod dag;
mod flow;
mod rig;
