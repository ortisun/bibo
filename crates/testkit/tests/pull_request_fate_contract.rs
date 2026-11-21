//! The fake fate source against its contract suite, and against each deliberate defect. The table
//! of defects lives with the fake (`pull_request_fate::PULL_REQUEST_FATE_DEFECTS`).

use factory_testkit::contracts::pull_request_fate;
use factory_testkit::pull_request_fate::{FakePullRequestFates, PULL_REQUEST_FATE_DEFECTS};

#[tokio::test]
async fn the_fake_fate_source_passes_its_contract() {
    let report = pull_request_fate::run_pull_request_fate(|| async {
        FakePullRequestFates::with_suite_repository()
    })
    .await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(
        report.passed.len(),
        pull_request_fate::pull_request_fate_checks().len()
    );
}

#[tokio::test]
async fn the_fate_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in PULL_REQUEST_FATE_DEFECTS {
        let defect = *defect;
        let report = pull_request_fate::run_pull_request_fate(|| async move {
            FakePullRequestFates::with_suite_repository_and_defect(defect)
        })
        .await;
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}

#[test]
fn the_fake_reports_that_it_is_a_fake() {
    use factory_domain::vocabulary::Fidelity;
    use factory_ports::pull_request_fate::PullRequestFateSource;
    assert_eq!(
        FakePullRequestFates::with_suite_repository().fidelity(),
        Fidelity::Fake
    );
}
