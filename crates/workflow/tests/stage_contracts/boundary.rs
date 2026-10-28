//! The delivery boundary, with the producer's bytes tampered.
//!
//! Conditions C-a, C-b and C-c of `docs/reviews/supply-chain-and-delivery-security-review.md`.
//! The real stages ran and stored their documents. Each test changes one stored document of an
//! earlier stage the way a producer that drifted, or an attacker who could write the artifact
//! store, would, and asserts that the delivery and the approval stage both refuse it with a typed
//! error. A stage that read these documents by hash only would have taken the tampered bytes,
//! because the contract is resolved over whatever is stored.

use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::StageKind;
use factory_workflow::handlers::StageError;
use serde_json::json;

use crate::deliver::Delivery;
use crate::pairs::Whole;

const SPECIFICATION: &str = "specification-contract";
const REVIEW: &str = "documentation-review";

/// A specification that a person did not approve is not delivered and not put in front of a
/// person, whatever the stage before it said.
#[tokio::test]
async fn break_a_specification_that_is_not_approved_is_refused_by_delivery_and_approval() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;
    for status in ["draft", "superseded"] {
        let mut upstream = delivery.upstream_of_delivery();
        delivery
            .edit(
                &mut upstream,
                StageKind::Specification,
                SPECIFICATION,
                |v| {
                    v["metadata"]["status"] = json!(status);
                },
            )
            .await;
        let error = delivery
            .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
            .await
            .err();
        assert!(
            matches!(
                error,
                Some(StageError::PolicyDenied | StageError::InvalidOutput)
            ),
            "delivery, {status}: {error:?}"
        );

        let mut upstream = delivery.upstream_of_approval(&whole.delivered);
        delivery
            .edit(
                &mut upstream,
                StageKind::Specification,
                SPECIFICATION,
                |v| {
                    v["metadata"]["status"] = json!(status);
                },
            )
            .await;
        let error = delivery
            .run(&delivery.approval_handler(), StageKind::Approval, &upstream)
            .await
            .err();
        assert!(
            matches!(
                error,
                Some(StageError::PolicyDenied | StageError::InvalidOutput)
            ),
            "approval, {status}: {error:?}"
        );
    }
}

/// A documentation review whose bytes were tampered with is refused by both stages: a verdict
/// that names other reports, a verdict over another specification, and a verdict that is no
/// longer a pass.
#[tokio::test]
async fn break_a_tampered_documentation_review_is_refused_by_delivery_and_approval() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;

    type Tamper = fn(&mut serde_json::Value);
    let tampers: [(&str, Tamper); 3] = [
        ("other reports", |v| {
            v["inputs_reviewed"]["gate_reports"][0]["sha256"] =
                json!(Sha256Digest::of(b"a report that was never stored"));
        }),
        ("another specification", |v| {
            v["inputs_reviewed"]["frozen_spec_sha256"] =
                json!(Sha256Digest::of(b"another specification"));
        }),
        ("a reviewer who did not pass it", |v| {
            v["verdict"] = json!("NEEDS_HUMAN");
            v["human_question"] = json!("Is the documentation a fair account of the change?");
        }),
    ];
    for (what, tamper) in tampers {
        let mut upstream = delivery.upstream_of_delivery();
        delivery
            .edit(
                &mut upstream,
                StageKind::DocumentationReview,
                REVIEW,
                tamper,
            )
            .await;
        let error = delivery
            .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
            .await
            .err();
        assert_eq!(error, Some(StageError::PolicyDenied), "delivery, {what}");

        let mut upstream = delivery.upstream_of_approval(&whole.delivered);
        delivery
            .edit(
                &mut upstream,
                StageKind::DocumentationReview,
                REVIEW,
                tamper,
            )
            .await;
        let error = delivery
            .run(&delivery.approval_handler(), StageKind::Approval, &upstream)
            .await
            .err();
        assert_eq!(error, Some(StageError::PolicyDenied), "approval, {what}");
    }
}

/// The untouched documents are accepted by both, so the refusals above are about the tampering.
#[tokio::test]
async fn the_untouched_documents_are_accepted_by_delivery_and_approval() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;
    assert!(
        delivery
            .run(
                &delivery.delivery_handler(),
                StageKind::Delivery,
                &delivery.upstream_of_delivery()
            )
            .await
            .is_ok()
    );
    assert!(
        delivery
            .run(
                &delivery.approval_handler(),
                StageKind::Approval,
                &delivery.upstream_of_approval(&whole.delivered)
            )
            .await
            .is_ok()
    );
}
