//! The fake change host and the fake issue source against their shared contract suites, and
//! against each deliberate defect. The tables of defects live with the fakes
//! (`githost::CHANGE_HOST_DEFECTS`, `githost::ISSUE_SOURCE_DEFECTS`).

use factory_testkit::contracts::githost;
use factory_testkit::githost::{
    CHANGE_HOST_DEFECTS, FakeChangeHost, FakeIssueSource, ISSUE_SOURCE_DEFECTS,
};

#[tokio::test]
async fn the_fake_change_host_passes_the_change_host_contract() {
    let report = githost::run_change_host(|| async { FakeChangeHost::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), githost::change_host_checks().len());
}

#[tokio::test]
async fn the_fake_issue_source_passes_the_issue_source_contract() {
    let report = githost::run_issue_source(|| async { FakeIssueSource::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), githost::issue_source_checks().len());
}

#[tokio::test]
async fn the_change_host_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in CHANGE_HOST_DEFECTS {
        let defect = *defect;
        let report =
            githost::run_change_host(|| async move { FakeChangeHost::with_defect(defect) }).await;
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}

#[tokio::test]
async fn the_issue_source_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in ISSUE_SOURCE_DEFECTS {
        let defect = *defect;
        let report =
            githost::run_issue_source(|| async move { FakeIssueSource::with_defect(defect) }).await;
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
