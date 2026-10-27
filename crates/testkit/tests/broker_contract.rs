//! The fake model broker against the shared broker contract suite, and against each deliberate
//! defect.

use factory_testkit::broker::{BrokerDefect, FakeBrokerSubject};
use factory_testkit::contracts::broker;

#[tokio::test]
async fn the_fake_broker_passes_the_broker_contract() {
    let report = broker::run(|| async { FakeBrokerSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), broker::checks().len());
}

const DEFECTS: [(BrokerDefect, &[&str]); 7] = [
    (
        BrokerDefect::IssuesWithoutValidation,
        &["an_invalid_request_is_refused"],
    ),
    (
        BrokerDefect::NeverRevokesAtCeiling,
        &["a_token_that_reaches_its_ceiling_is_revoked_and_refuses_more"],
    ),
    (
        BrokerDefect::RevokeKeepsSpending,
        &["revoking_stops_spending_and_keeps_the_usage_readable"],
    ),
    (
        BrokerDefect::RevokeFailsTwice,
        &["revoking_twice_or_revoking_an_unknown_token_succeeds"],
    ),
    (BrokerDefect::ForgetsExpiry, &["a_token_expires_with_time"]),
    (BrokerDefect::SharedMeter, &["tokens_are_independent"]),
    (BrokerDefect::RevokesEveryone, &["tokens_are_independent"]),
];

#[tokio::test]
async fn the_broker_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let report = broker::run(|| async move { FakeBrokerSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a broker with the defect {defect:?}"
        );
        for name in must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
