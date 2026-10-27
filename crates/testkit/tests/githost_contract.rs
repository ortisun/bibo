//! The fake change host and the fake issue source against their shared contract suites, and
//! against each deliberate defect.

use factory_testkit::contracts::githost;
use factory_testkit::githost::{
    ChangeHostDefect, FakeChangeHost, FakeIssueSource, IssueSourceDefect,
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

const CHANGE_HOST_DEFECTS: [(ChangeHostDefect, &[&str]); 8] = [
    (
        ChangeHostDefect::AcceptsAnyBranch,
        &[
            "push_targets_are_for_factory_branches_only",
            "a_pull_request_from_a_head_outside_factory_is_refused",
        ],
    ),
    (
        ChangeHostDefect::DuplicatePullRequests,
        &["opening_for_the_same_head_twice_returns_the_same_pull_request"],
    ),
    (
        ChangeHostDefect::OpensReadyForReview,
        &["a_pull_request_is_opened_as_a_draft_and_stays_open"],
    ),
    (
        ChangeHostDefect::IgnoresBodyTag,
        &["the_body_is_updated_only_if_its_tag_is_current"],
    ),
    (
        ChangeHostDefect::DuplicateComments,
        &["a_comment_is_posted_once_per_key"],
    ),
    (
        ChangeHostDefect::SkipsSecretCheck,
        &["text_with_a_secret_is_not_posted"],
    ),
    (
        ChangeHostDefect::RevokeDoesNothing,
        &["after_a_job_ends_its_calls_are_refused"],
    ),
    (
        ChangeHostDefect::SharesAcrossTenants,
        &["another_tenant_cannot_reach_a_pull_request"],
    ),
];

#[tokio::test]
async fn the_change_host_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in CHANGE_HOST_DEFECTS {
        let report =
            githost::run_change_host(|| async move { FakeChangeHost::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a change host with the defect {defect:?}"
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

const ISSUE_SOURCE_DEFECTS: [(IssueSourceDefect, &str); 4] = [
    (IssueSourceDefect::CachesIssues, "an_issue_is_fetched_live"),
    (
        IssueSourceDefect::GuessesLabelActor,
        "the_label_actor_is_the_person_who_applied_it",
    ),
    (
        IssueSourceDefect::AlwaysProtected,
        "protection_is_reported_as_the_repository_has_it",
    ),
    (
        IssueSourceDefect::IgnoresRepositoryScope,
        "a_scope_for_another_repository_cannot_read_an_issue",
    ),
];

#[tokio::test]
async fn the_issue_source_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in ISSUE_SOURCE_DEFECTS {
        let report =
            githost::run_issue_source(|| async move { FakeIssueSource::with_defect(defect) }).await;
        assert!(
            report.failed_check(must_fail),
            "the defect {defect:?} should fail {must_fail}, but the failed checks were {:?}",
            report.failed_names()
        );
    }
}
