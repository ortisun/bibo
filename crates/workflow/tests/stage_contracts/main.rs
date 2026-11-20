//! The cross-stage contract suite.
//!
//! # Why this exists
//!
//! Each stage of the pipeline was tested against documents that its own author wrote. That never
//! asks the question that breaks a pipeline: does the stage after this one read what this stage
//! really stores? Three defects of that class were found by running the stages together: a
//! deliverable name that one stage assumed and another did not produce, a delivery that pushed the
//! code head so that the documentation commit never reached the pull request, and an approval
//! stage that read `documentation-gate-report` as one gate report while the documentation review
//! stage stores a document with a binding and ten typed reports.
//!
//! This suite makes that class fail in CI. For each pair of a stage and the stage that reads its
//! output, the output is built by **the producer's own code** and handed to **the consumer's own
//! reader**. No document in these tests is written by hand.
//!
//! # Where the real output comes from
//!
//! | Producer | Built by | Fidelity |
//! |---|---|---|
//! | `INTAKE`, `REPOSITORY_INTELLIGENCE` | the real handlers through the real engine (`harness`) | real |
//! | `ARCHITECTURE`, `TASK_PLANNING` | the real handlers through the real engine (`planning_rig`) | real |
//! | `IMPLEMENTATION`, `REVIEW`, `DOCUMENTING`, `DOCUMENTATION_REVIEW` | the real handlers through the real engine (`rig`) | real |
//! | `VALIDATION` | the validation stage's own `evidence_document`, called by the rig's stand-in; the real handler's contract is resolved on the real job | serializer |
//! | `DELIVERY`, `APPROVAL` | the real handlers, over the repository and the code host of the rig (`deliver`) | real |
//! | `SPECIFICATION` | the real handler through the real engine, fed the request the real intake stage stored (`spec_rig`); the typed contract comes from the scripted provider of the stage's own tests, because the Spec Kit adapter cannot be a dependency of this crate (rule DEP-01) | real, over a scripted provider |
//! | `DOMAIN_DISCOVERY` | **pending**: the module is a placeholder in this checkout | none |
//!
//! The stand-ins the rigs register for the stages that are not under test store documents their
//! author chose. [`chain::Universe::real`] refuses to hand one out as a producer's output.
//!
//! # What is checked
//!
//! * `pairs`: each producer to consumer pair, by parsing and by the fields the consumer relies on.
//! * `heads`: the commits, base to code head to documentation head to pushed head, across the stages.
//! * `names` and `registry`: the deliverable names agree, and every deliverable that any stage
//!   reads is produced by exactly one stage that runs before it in `docs/architecture/state-machine.json`;
//!   every deliverable nobody reads is listed as terminal.
//! * `breaks`: drift in the producers' documents, applied to the real output, is refused by the
//!   consumers' readers. The mutation runs that show the suite fails on a changed source are in the
//!   report of the work that added it.
//!
//! The rigs are the ones of the stage test targets, included by path, so the suite runs the same
//! handlers over the same fakes. Real Docker, git and GitHub are out of reach of this crate
//! (rule DEP-01): the fakes are the contract of the ports, and what the real adapters add is
//! checked by their own tests and by the end-to-end harness.

#[path = "../support/mod.rs"]
mod support;

// The job through the documentation stages: the real implementation, review, documenting and
// documentation review handlers (stand-ins around them).
#[path = "../documentation/rig.rs"]
mod rig;
#[path = "../documentation/standin.rs"]
mod standin;

// The job through intake and repository intelligence: both real handlers.
#[path = "../intake_repo/harness.rs"]
#[allow(dead_code)]
mod harness;
#[path = "../intake_repo/repo_rig.rs"]
#[allow(dead_code)]
mod repo_rig;

// The job through the specification stage: the real handler, over the seams its own tests use.
#[path = "../specification/rig.rs"]
mod spec_rig;

// The job through architecture and task planning: both real handlers.
#[path = "../planning/rig.rs"]
mod planning_rig;

// The stand-ins the delivery stage reads to check the design again before it opens the pull request.
#[path = "../delivery/design_fakes.rs"]
#[allow(dead_code)]
mod design_fakes;

mod chain;
mod deliver;

mod boundary;
mod breaks;
mod heads;
mod names;
mod pairs;
mod registry;
