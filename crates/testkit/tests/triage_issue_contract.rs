//! The fake triage issue writer against its contract suite, and against each deliberate defect.
//! The table of defects lives with the fake (`triage_issue::TRIAGE_ISSUE_DEFECTS`).

use factory_domain::vocabulary::Fidelity;
use factory_ports::triage_issue::TriageIssueWriter;
use factory_testkit::contracts::triage_issue;
use factory_testkit::triage_issue::{FakeTriageIssues, TRIAGE_ISSUE_DEFECTS, triage_labels};

#[tokio::test]
async fn the_fake_triage_issue_writer_passes_its_contract() {
    let report = triage_issue::run_triage_issue(|| async { FakeTriageIssues::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(
        report.passed.len(),
        triage_issue::triage_issue_checks().len()
    );
}

#[tokio::test]
async fn the_triage_issue_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in TRIAGE_ISSUE_DEFECTS {
        let defect = *defect;
        let report =
            triage_issue::run_triage_issue(|| async move { FakeTriageIssues::with_defect(defect) })
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
fn the_labels_of_the_fake_are_the_troubleshooter_labels_and_nothing_of_the_factory() {
    let labels = triage_labels();
    assert_eq!(labels.names(), ["troubleshooter", "troubleshooter: triage"]);
    assert!(
        labels
            .names()
            .iter()
            .all(|l| !l.starts_with("factory") && !l.starts_with("design:"))
    );
}

#[test]
fn the_fake_reports_that_it_is_a_fake() {
    assert_eq!(FakeTriageIssues::new().fidelity(), Fidelity::Fake);
}
