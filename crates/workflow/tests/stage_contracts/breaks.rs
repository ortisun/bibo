//! Deliberate breaks, applied to what the real stages stored.
//!
//! Each test makes the producer's document drift in one of the four ways that this class of defect
//! takes, and asserts that the stage after it refuses the drift with a typed error. A consumer that
//! shrugged off the drift would be a consumer that reads something other than what the producer
//! stores, which is the defect these tests exist to catch.
//!
//! | Drift | Test |
//! |---|---|
//! | A deliverable renamed on one side | `break_a_renamed_deliverable_blocks_every_stage_that_reads_it` |
//! | The shape of a stored document changed on the producer side | `break_a_changed_shape_is_refused_by_the_reader` |
//! | A field a consumer relies on dropped | `break_a_dropped_field_is_refused_by_the_consumer` |
//! | A consumer reads one report where the producer stores a list | `break_one_report_where_the_producer_stores_a_list` |
//!
//! The same four breaks were also made in the source of a stage, one at a time, to show that this
//! target fails by name and the stage's own tests do not always: see the report of the change that
//! added the suite.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, GateReport};
use factory_domain::vocabulary::StageKind;
use factory_workflow::handlers::StageError;
use factory_workflow::stages::approval;
use factory_workflow::stages::delivery::documentation_gate::{DocumentationGate, GateProblem};
use factory_workflow::stages::delivery::input as delivery_input;
use factory_workflow::stages::implementation::input as implementation_input;
use factory_workflow::stages::review::evidence::Evidence;
use serde_json::{Value, json};

use crate::deliver::Delivery;
use crate::pairs::Whole;

const BLOCKED: StageError = StageError::Blocked(BlockedCode::DependencyUnavailable);

/// A deliverable stored under another name than the one the stages after it ask for blocks them
/// before anything runs, and the contract of each of them says what is missing.
#[tokio::test]
async fn break_a_renamed_deliverable_blocks_every_stage_that_reads_it() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;
    let handler = delivery.delivery_handler();

    // The delivery stage asks for each of ten deliverables. Rename each, in turn, as a producer
    // that changed its constant would have, and the stage is blocked.
    for &(kind, name) in &delivery_input::SOURCES {
        let mut upstream = delivery.upstream_of_delivery();
        Delivery::rename(&mut upstream, kind, name, &format!("{name}-renamed"));
        assert_eq!(
            delivery
                .contract(&handler, StageKind::Delivery, &upstream)
                .err(),
            Some(BLOCKED),
            "{kind} {name}"
        );
    }

    // The same for the approval stage and the five it asks for.
    let approval = delivery.approval_handler();
    for &(kind, name) in &approval::contract::SOURCES {
        let mut upstream = delivery.upstream_of_approval(&whole.delivered);
        Delivery::rename(&mut upstream, kind, name, &format!("{name}-renamed"));
        assert_eq!(
            delivery
                .contract(&approval, StageKind::Approval, &upstream)
                .err(),
            Some(BLOCKED),
            "{kind} {name}"
        );
    }

    // And nothing is blocked when nothing is renamed.
    assert!(
        delivery
            .contract(
                &handler,
                StageKind::Delivery,
                &delivery.upstream_of_delivery()
            )
            .is_ok()
    );
}

/// A document whose shape the producer changed is not read by the stage that asks for the old
/// shape, and that stage says so instead of reading something else.
#[tokio::test]
async fn break_a_changed_shape_is_refused_by_the_reader() {
    let whole = Whole::run().await;
    let pipeline = &whole.pipeline;
    let renamed = |value: &Value, from: &str, to: &str| {
        let mut changed = value.clone();
        let object = changed.as_object_mut().expect("an object");
        let moved = object.remove(from).unwrap_or_else(|| panic!("no {from}"));
        object.insert(to.to_owned(), moved);
        changed
    };
    let bytes = |value: &Value| serde_json::to_vec(value).expect("JSON");

    // implementation-result, read by the implementation, delivery and review readers.
    let result = pipeline
        .real(StageKind::Implementation, "implementation-result")
        .json();
    let changed = bytes(&renamed(&result, "head_commit", "head"));
    assert!(implementation_input::parse_candidate(&changed).is_none());
    assert!(delivery_input::parse_candidate(&changed).is_none());

    // validation-evidence, read by the review stage.
    let evidence = pipeline
        .find(StageKind::Validation, "validation-evidence")
        .json();
    assert!(Evidence::read(&bytes(&evidence)).is_ok());
    for (from, to) in [("reports", "gate_reports"), ("binding", "bound_to")] {
        assert!(
            Evidence::read(&bytes(&renamed(&evidence, from, to))).is_err(),
            "{from} renamed to {to}"
        );
    }

    // documentation-gate-report, read by the delivery and approval stages.
    let gate = pipeline
        .real(StageKind::DocumentationReview, "documentation-gate-report")
        .json();
    assert!(DocumentationGate::from_json(&gate).is_ok());
    for (from, to) in [("reports", "gate_reports"), ("binding", "bound_to")] {
        assert_eq!(
            DocumentationGate::from_json(&renamed(&gate, from, to)).unwrap_err(),
            GateProblem::Invalid,
            "{from} renamed to {to}"
        );
    }
    let binding = &gate["binding"];
    let mut moved = gate.clone();
    moved["binding"] = renamed(binding, "documentation_head", "docs_head");
    assert_eq!(
        DocumentationGate::from_json(&moved).unwrap_err(),
        GateProblem::Invalid
    );

    // delivery-result, read by the approval stage: a renamed field is a field it cannot find.
    let delivery = Delivery::over(pipeline).await;
    let approval = delivery.approval_handler();
    let mut upstream = delivery.upstream_of_approval(&whole.delivered);
    delivery
        .edit(
            &mut upstream,
            StageKind::Delivery,
            "delivery-result",
            |value| {
                *value = renamed(value, "head_commit", "head");
            },
        )
        .await;
    assert_eq!(
        delivery
            .run(&approval, StageKind::Approval, &upstream)
            .await
            .err(),
        Some(StageError::InvalidOutput)
    );
}

/// A field that a consumer relies on is a field the consumer refuses to go on without. The fields
/// are the ones the approval stage reads from the delivery result and the documentation gate
/// report, and the delivery stage reads from the gate report.
#[tokio::test]
async fn break_a_dropped_field_is_refused_by_the_consumer() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;
    let approval = delivery.approval_handler();

    // Every field of the delivery result that the approval stage reads.
    for field in [
        "delivered",
        "repository",
        "pull_request",
        "head_commit",
        "code_head",
        "base_commit",
        "tree",
        "head_branch",
        "base_branch",
        "manifest_sha256",
        "spec_version",
    ] {
        let mut upstream = delivery.upstream_of_approval(&whole.delivered);
        delivery
            .edit(
                &mut upstream,
                StageKind::Delivery,
                "delivery-result",
                |value| {
                    value.as_object_mut().expect("an object").remove(field);
                },
            )
            .await;
        let error = delivery
            .run(&approval, StageKind::Approval, &upstream)
            .await
            .err();
        assert!(
            matches!(
                error,
                Some(StageError::InvalidOutput | StageError::PolicyDenied)
            ),
            "{field}: {error:?}"
        );
    }

    // Every field of the binding of the documentation gate report, for both stages.
    for field in [
        "base_commit",
        "code_head",
        "documentation_head",
        "plan_sha256",
        "specification_sha256",
    ] {
        let drop = |value: &mut Value| {
            value["binding"]
                .as_object_mut()
                .expect("a binding")
                .remove(field);
        };
        let mut upstream = delivery.upstream_of_approval(&whole.delivered);
        delivery
            .edit(
                &mut upstream,
                StageKind::DocumentationReview,
                "documentation-gate-report",
                drop,
            )
            .await;
        assert_eq!(
            delivery
                .run(&approval, StageKind::Approval, &upstream)
                .await
                .err(),
            Some(StageError::InvalidOutput),
            "approval, {field}"
        );
        let mut upstream = delivery.upstream_of_delivery();
        delivery
            .edit(
                &mut upstream,
                StageKind::DocumentationReview,
                "documentation-gate-report",
                drop,
            )
            .await;
        assert_eq!(
            delivery
                .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
                .await
                .err(),
            Some(StageError::InvalidOutput),
            "delivery, {field}"
        );
    }
}

/// The documentation review stage stores a list of reports. A stage that reads one report cannot
/// read it, and a stage that is handed one report where the list is stored refuses it. This is the
/// defect of the approval stage, in both directions.
#[tokio::test]
async fn break_one_report_where_the_producer_stores_a_list() {
    let whole = Whole::run().await;
    let gate = whole
        .pipeline
        .real(StageKind::DocumentationReview, "documentation-gate-report")
        .json();

    // The producer stores a document with a list: it is not a gate report, so a reader of a single
    // gate report cannot read it.
    assert!(
        gate["reports"]
            .as_array()
            .is_some_and(|list| list.len() > 1)
    );
    assert!(GateReport::from_json_value(gate.clone()).is_err());

    // The other way round: one gate report where the list is stored is refused by both readers.
    let one = gate["reports"][0].clone();
    assert!(GateReport::from_json_value(one.clone()).is_ok());
    assert_eq!(
        DocumentationGate::from_json(&one).unwrap_err(),
        GateProblem::Invalid
    );
    let delivery = Delivery::over(&whole.pipeline).await;
    let approval = delivery.approval_handler();
    let mut upstream = delivery.upstream_of_approval(&whole.delivered);
    delivery
        .edit(
            &mut upstream,
            StageKind::DocumentationReview,
            "documentation-gate-report",
            |value| *value = one.clone(),
        )
        .await;
    assert_eq!(
        delivery
            .run(&approval, StageKind::Approval, &upstream)
            .await
            .err(),
        Some(StageError::InvalidOutput)
    );
    let mut upstream = delivery.upstream_of_delivery();
    delivery
        .edit(
            &mut upstream,
            StageKind::DocumentationReview,
            "documentation-gate-report",
            |value| *value = one.clone(),
        )
        .await;
    assert_eq!(
        delivery
            .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
            .await
            .err(),
        Some(StageError::InvalidOutput)
    );

    // A list of one is a list: the shape is what matters, not the count.
    let mut listed = gate.clone();
    listed["reports"] = json!([gate["reports"][0].clone()]);
    assert!(DocumentationGate::from_json(&listed).is_ok());
}

/// The specification the real stage froze is read by the delivery stage as a typed contract. A
/// specification with a part missing, or that is not the contract any more, is refused with a
/// typed error.
#[tokio::test]
async fn break_a_dropped_part_of_the_specification_is_refused_by_the_consumers() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;
    let handler = delivery.delivery_handler();

    // The parts of the specification the consumers read: its metadata (the version, the status),
    // its requirements and the scenarios that cover them, and its title.
    for part in ["metadata", "requirements", "title", "provenance"] {
        let mut upstream = delivery.upstream_of_delivery();
        delivery
            .edit(
                &mut upstream,
                StageKind::Specification,
                "specification-contract",
                |value| {
                    value
                        .as_object_mut()
                        .expect("an object")
                        .remove(part)
                        .unwrap_or_else(|| panic!("the specification has no {part}"));
                },
            )
            .await;
        assert_eq!(
            delivery
                .run(&handler, StageKind::Delivery, &upstream)
                .await
                .err(),
            Some(StageError::InvalidOutput),
            "{part}"
        );
    }

    // A requirement that names a scenario the specification does not have breaks the contract.
    let mut upstream = delivery.upstream_of_delivery();
    delivery
        .edit(
            &mut upstream,
            StageKind::Specification,
            "specification-contract",
            |value| value["requirements"][0]["acceptance_scenario_ids"] = json!(["SC-999"]),
        )
        .await;
    assert_eq!(
        delivery
            .run(&handler, StageKind::Delivery, &upstream)
            .await
            .err(),
        Some(StageError::InvalidOutput)
    );
}
