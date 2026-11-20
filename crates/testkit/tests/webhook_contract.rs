//! The fake webhook verifier against the shared contract suite, and against each deliberate
//! defect. The table of defects lives with the fake (`webhook::DEFECTS`), so that
//! `contract_register` reads the same one.

use factory_testkit::contracts::webhook;
use factory_testkit::webhook::{DEFECTS, FakeWebhookSubject};

#[tokio::test]
async fn the_fake_verifier_passes_the_webhook_contract() {
    let report = webhook::run(|| async { FakeWebhookSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), webhook::checks().len());
}

#[tokio::test]
async fn the_webhook_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report = webhook::run(|| async move { FakeWebhookSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a fake with the defect {defect:?}"
        );
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
