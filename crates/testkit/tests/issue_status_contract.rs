//! The fake status writer against its contract suite, and against each deliberate defect. The
//! table of defects lives with the fake (`issue_status::ISSUE_STATUS_DEFECTS`).

use factory_domain::state::JobStatus;
use factory_testkit::contracts::issue_status;
use factory_testkit::issue_status::{FakeIssueStatusWriter, ISSUE_STATUS_DEFECTS, status_labels};

#[tokio::test]
async fn the_fake_status_writer_passes_the_status_writer_contract() {
    let report = issue_status::run_issue_status(|| async { FakeIssueStatusWriter::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(
        report.passed.len(),
        issue_status::issue_status_checks().len()
    );
}

#[tokio::test]
async fn the_status_writer_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in ISSUE_STATUS_DEFECTS {
        let defect = *defect;
        let report =
            issue_status::run_issue_status(
                || async move { FakeIssueStatusWriter::with_defect(defect) },
            )
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
fn the_labels_of_the_fake_come_from_the_rendered_policy_and_cover_every_job_state() {
    let labels = status_labels();
    assert_eq!(labels.iter().count(), JobStatus::ALL.len());
    assert_eq!(
        labels.label_for(JobStatus::WaitingForHuman).as_str(),
        "factory: waiting for a person"
    );
    assert_eq!(
        labels.label_for(JobStatus::Completed).as_str(),
        "factory: done"
    );
}

#[test]
fn the_fake_reports_that_it_is_a_fake() {
    use factory_domain::vocabulary::Fidelity;
    use factory_ports::issue_status::IssueStatusWriter;
    assert_eq!(FakeIssueStatusWriter::new().fidelity(), Fidelity::Fake);
}
