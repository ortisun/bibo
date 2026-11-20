//! Names: the strings that two stages must spell the same way.
//!
//! A deliverable is found by its name. A stage that writes `documentation-gate-report` and a stage
//! that asks for `documentation-gate-reports` agree on nothing, and the second one is blocked with
//! no document to read. Several stages keep their own constant for the same deliverable, so the
//! first test compares the constants. The second asks the real stages what they stored.

use factory_domain::vocabulary::StageKind;
use factory_workflow::stages::{
    approval, architecture, delivery, documenting, implementation, planning, review, specification,
    validation,
};

use crate::chain::{Pipeline, Specified};
use crate::registry::PENDING;

/// The constants of different stages that name one deliverable, grouped by the deliverable. Every
/// constant of a group has the same value, and the group is named by the producer's constant.
#[test]
fn the_constants_that_name_one_deliverable_are_equal_in_every_stage_that_has_one() {
    use delivery::input as d;
    let groups: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            implementation::RESULT,
            vec![
                (
                    "delivery::input::IMPLEMENTATION_RESULT",
                    d::IMPLEMENTATION_RESULT,
                ),
                (
                    "validation::IMPLEMENTATION_RESULT",
                    validation::IMPLEMENTATION_RESULT,
                ),
                (
                    "implementation::input::IMPLEMENTATION_RESULT",
                    implementation::input::IMPLEMENTATION_RESULT,
                ),
                (
                    "documenting::IMPLEMENTATION_RESULT",
                    documenting::input::IMPLEMENTATION_RESULT,
                ),
            ],
        ),
        (
            validation::EVIDENCE,
            vec![
                (
                    "delivery::input::VALIDATION_EVIDENCE",
                    d::VALIDATION_EVIDENCE,
                ),
                (
                    "implementation::input::VALIDATION_EVIDENCE",
                    implementation::input::VALIDATION_EVIDENCE,
                ),
            ],
        ),
        (
            review::VERDICT,
            vec![("delivery::input::REVIEW_VERDICT", d::REVIEW_VERDICT)],
        ),
        (
            planning::TASK_PLAN,
            vec![
                ("delivery::input::TASK_PLAN", d::TASK_PLAN),
                (
                    "implementation::input::TASK_PLAN",
                    implementation::input::TASK_PLAN,
                ),
            ],
        ),
        (
            architecture::handler::DESIGN,
            vec![
                ("delivery::input::ARCHITECTURE", d::ARCHITECTURE),
                (
                    "implementation::input::ARCHITECTURE",
                    implementation::input::ARCHITECTURE,
                ),
            ],
        ),
        (
            documenting::DOCUMENTATION_PLAN,
            vec![("delivery::input::DOCUMENTATION_PLAN", d::DOCUMENTATION_PLAN)],
        ),
        (
            documenting::DOCUMENTATION_RESULT,
            vec![(
                "delivery::input::DOCUMENTATION_RESULT",
                d::DOCUMENTATION_RESULT,
            )],
        ),
        (
            documenting::DOCUMENTATION_GATE_REPORT,
            vec![("delivery::input::DOCUMENTATION_GATE", d::DOCUMENTATION_GATE)],
        ),
        (
            documenting::DOCUMENTATION_REVIEW,
            vec![(
                "delivery::input::DOCUMENTATION_REVIEW",
                d::DOCUMENTATION_REVIEW,
            )],
        ),
        (
            specification::SPECIFICATION_CONTRACT,
            vec![
                (
                    "implementation::input::SPECIFICATION_CONTRACT",
                    implementation::input::SPECIFICATION_CONTRACT,
                ),
                (
                    "delivery::input::SPECIFICATION_CONTRACT",
                    d::SPECIFICATION_CONTRACT,
                ),
                (
                    "validation::SPECIFICATION_CONTRACT",
                    validation::SPECIFICATION_CONTRACT,
                ),
                (
                    "documenting::SPECIFICATION_CONTRACT",
                    documenting::input::SPECIFICATION_CONTRACT,
                ),
            ],
        ),
        (
            validation::POLICY_INPUT,
            vec![("delivery::input::POLICY_INPUT", d::POLICY_INPUT)],
        ),
        (
            delivery::RESULT,
            vec![(
                "approval::contract reads delivery::RESULT",
                delivery::RESULT,
            )],
        ),
        (
            approval::REQUEST,
            vec![("approval::REQUEST", "approval-request")],
        ),
    ];
    let mut differing = Vec::new();
    for (producer, readers) in groups {
        for (label, value) in readers {
            if value != producer {
                differing.push(format!(
                    "{label} is {value:?}, the producer stores {producer:?}"
                ));
            }
        }
    }
    assert!(differing.is_empty(), "{differing:#?}");
}

/// A stage that is a real handler in the job stores every deliverable that the delivery and the
/// approval stage read from it, under the name they ask for.
#[tokio::test]
async fn the_real_stages_store_what_delivery_and_approval_ask_them_for() {
    let pipeline = Pipeline::documented().await;
    let asked = delivery::input::SOURCES
        .iter()
        .chain(approval::contract::SOURCES.iter());
    let mut missing = Vec::new();
    let mut not_verified = Vec::new();
    for &(kind, name) in asked {
        if pipeline.real.contains(&kind) {
            if !pipeline.names_of(kind).contains(name) {
                missing.push(format!("{kind} does not store {name}"));
            }
        } else {
            not_verified.push((kind, name));
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
    // The specification stage is real in its own job, and stores what everything after it asks for.
    let specified = Specified::run().await.universe;
    for &(kind, name) in delivery::input::SOURCES
        .iter()
        .chain(approval::contract::SOURCES.iter())
        .filter(|(kind, _)| *kind == StageKind::Specification)
    {
        assert!(
            specified.names_of(kind).contains(name),
            "{kind} does not store {name}"
        );
    }
    // The deliverables asked of a stage that is a stand-in in this job are checked in
    // `pairs::pair_*` through the stage that really produces them, or they are pending.
    for (kind, name) in not_verified {
        let covered = matches!(
            kind,
            StageKind::Validation
                | StageKind::Specification
                | StageKind::TaskPlanning
                | StageKind::Architecture
                | StageKind::Delivery
        ) || PENDING.contains(&(kind, name));
        assert!(covered, "{kind} {name} is verified nowhere");
    }
}
