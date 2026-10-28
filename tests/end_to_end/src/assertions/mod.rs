//! The assertions A1 to A14 of the Slice 1 acceptance section.
//!
//! Each is a pure function from the evidence of a run to a verdict. They read stored records, not
//! log text. The ids and the wording follow `docs/architecture/slice-plan.md`, section 10.

pub mod contracts;
pub mod delivery;
pub mod language;
pub mod stages;
pub mod support;
pub mod telemetry;

use crate::check::{Check, Env, Verdict};
use crate::evidence::RunEvidence;

/// All fourteen assertions, in order.
#[must_use]
pub fn all() -> Vec<Check> {
    vec![
        Check {
            id: "A1",
            title: "The job is COMPLETED. Every stage kind in scope has exactly one PASSED run that is not superseded, and the order respects requires.",
            run: stages::a1,
        },
        Check {
            id: "A2",
            title: "DOCUMENTING and DOCUMENTATION_REVIEW both completed after REVIEW passed and before DELIVERY, shown by ledger sequence.",
            run: stages::a2,
        },
        Check {
            id: "A3",
            title: "The pull request exists on GitHub, is a draft, links the issue, and its head branch holds the code and the documentation commits.",
            run: delivery::a3,
        },
        Check {
            id: "A4",
            title: "The evidence manifest validates, limitations is not empty, every adapter is real, the ledger chain verifies, and the head hash in the pull request body equals the stored head.",
            run: contracts::a4,
        },
        Check {
            id: "A5",
            title: "The specification contract validates, its artifact hashes match the files on the branch, and skills_invoked is a subset of the four allowed.",
            run: contracts::a5,
        },
        Check {
            id: "A6",
            title: "The task graph validates and passes the planner checks, every acceptance scenario is covered, and the changed paths are inside the union of owned files.",
            run: contracts::a6,
        },
        Check {
            id: "A7",
            title: "Every gate report validates, every PASSED report has exit code 0 for all commands, images are pinned by digest, and fidelity is real.",
            run: contracts::a7,
        },
        Check {
            id: "A8",
            title: "Every human-facing artifact passes the readability gate. For a request in another language the specification, plan, pull request and documentation are English.",
            run: language::a8,
        },
        Check {
            id: "A9",
            title: "The job waited in WAITING_FOR_HUMAN until an authorized approval, then completed. The pull request was not merged and the base branch is unchanged.",
            run: delivery::a9,
        },
        Check {
            id: "A10",
            title: "No code path called merge or deploy, and the token used had no merge permission.",
            run: delivery::a10,
        },
        Check {
            id: "A11",
            title: "Every attempt has a span whose parent is its stage run span, and the correlation id appears on every event and log line.",
            run: telemetry::a11,
        },
        Check {
            id: "A12",
            title: "The documentation gate report is PASSED with the link check and snippet execution actually run. NOT_APPLICABLE only with a recorded rule.",
            run: contracts::a12,
        },
        Check {
            id: "A13",
            title: "With a failing check, DELIVERY never starts.",
            run: stages::a13,
        },
        Check {
            id: "A14",
            title: "The ledger holds no entry with fidelity fake in a production-mode job, and no fake adapter appears in the manifest.",
            run: contracts::a14,
        },
    ]
}

/// Runs the fourteen assertions on the evidence.
#[must_use]
pub fn run_all(evidence: &RunEvidence, env: &Env) -> Vec<Verdict> {
    all()
        .iter()
        .map(|check| check.apply(evidence, env))
        .collect()
}

/// The assertion with this id.
#[must_use]
pub fn by_id(id: &str) -> Option<Check> {
    all().into_iter().find(|check| check.id == id)
}
