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
use factory_workflow::handlers::{StageError, UpstreamRun};
use serde_json::json;

use crate::deliver::Delivery;
use crate::pairs::Whole;

const SPECIFICATION: &str = "specification-contract";
const REVIEW: &str = "documentation-review";

/// Gives the specification this status and nothing else: it is still a valid document, and the
/// documentation reviewer's verdict is re-bound to its new hash, so that the only thing left for
/// a stage to refuse is the status.
async fn with_status(delivery: &Delivery<'_>, upstream: &mut [UpstreamRun], status: &str) {
    delivery
        .edit(upstream, StageKind::Specification, SPECIFICATION, |v| {
            v["metadata"]["status"] = json!(status);
        })
        .await;
    let hash = upstream
        .iter()
        .rev()
        .filter(|run| run.kind == StageKind::Specification)
        .find_map(|run| {
            run.outputs
                .iter()
                .find(|o| o.name.as_str() == SPECIFICATION)
        })
        .map(|output| output.artifact.sha256.clone())
        .expect("the specification");
    delivery
        .edit(upstream, StageKind::DocumentationReview, REVIEW, |v| {
            v["inputs_reviewed"]["frozen_spec_sha256"] = json!(hash);
        })
        .await;
}

/// A specification that a person did not approve is not delivered and not put in front of a
/// person, whatever the stage before it said.
#[tokio::test]
async fn break_a_specification_that_is_not_approved_is_refused_by_delivery_and_approval() {
    let whole = Whole::run().await;
    let delivery = Delivery::over(&whole.pipeline).await;
    for status in ["draft", "superseded"] {
        let mut upstream = delivery.upstream_of_delivery();
        with_status(&delivery, &mut upstream, status).await;
        let error = delivery
            .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
            .await
            .err();
        assert_eq!(error, Some(StageError::PolicyDenied), "delivery, {status}");

        let mut upstream = delivery.upstream_of_approval(&whole.delivered);
        with_status(&delivery, &mut upstream, status).await;
        let error = delivery
            .run(&delivery.approval_handler(), StageKind::Approval, &upstream)
            .await
            .err();
        assert_eq!(error, Some(StageError::PolicyDenied), "approval, {status}");
    }

    // The same edit with the status left as it was is accepted, so the refusal is the status.
    let mut upstream = delivery.upstream_of_delivery();
    with_status(&delivery, &mut upstream, "approved").await;
    assert!(
        delivery
            .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
            .await
            .is_ok()
    );
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
