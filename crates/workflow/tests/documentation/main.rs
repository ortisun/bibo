//! The documentation stages and the Documentation Quality Gate (`s1-stage-documentation`).
//!
//! The pure checks are tested directly. The two stages are driven through the real engine over the
//! labelled fakes of `factory-testkit`, with the scripted adversarial runtime (FX-ADV) as the
//! documentation writer and as the documentation reviewer. The stages before them are the real
//! implementation stage and stand-ins for the others, as in `tests/implementation`, whose rig this
//! one is a copy of: the rig builds its handlers inside, so a second test crate cannot add two
//! handlers to it without a copy.
//!
//! Every test name says what it proves. The done criteria of the work package are found by these
//! names: `impact_policy`, `plan_matches_schema`, `gate_checks`, `absence_is_never_a_pass`,
//! `reviewer_independence`, `defects_route_by_class` and `external_links_are_not_reported_valid`.
//! The negative tests of the catalog that this package owns have a function whose name starts
//! `negative_nt_`. The deliberate breaks of the review are in `breaks`.
//!
//! The fakes are labelled `fake`, and so is every handler built over them, so these tests run in
//! test mode. Real Docker and real git are out of reach of this crate (rule DEP-01): what they add
//! is listed in the final report of the work package, and the end-to-end harness proves it.

#[path = "../support/mod.rs"]
mod support;

mod rig;
mod standin;

mod flow;
mod negative;
mod pure;
