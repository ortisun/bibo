//! The in-memory broker against the shared broker contract suite, and against each deliberate
//! defect. The table of defects lives with the fake (`broker::DEFECTS`).

use factory_testkit::broker::{DEFECTS, FakeBrokerSubject};
use factory_testkit::contracts::broker;

#[tokio::test]
async fn the_in_memory_broker_passes_the_broker_contract() {
    let report = broker::run(|| async { FakeBrokerSubject::new() }).await;
    report.assert_ok();
    assert_eq!(report.passed.len(), broker::checks().len());
}

#[tokio::test]
async fn the_broker_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report = broker::run(|| async move { FakeBrokerSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a broker with the defect {defect:?}"
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
