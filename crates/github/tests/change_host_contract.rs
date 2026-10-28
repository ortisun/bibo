//! The shared contract suite for `ChangeHost`, run against the GitHub adapter talking to the fake
//! GitHub server over the loopback interface.

mod common;

use common::subjects::ChangeHostWorld;
use factory_testkit::contracts::githost;

#[tokio::test]
async fn the_github_change_host_passes_the_whole_change_host_contract() {
    let report = githost::run_change_host(|| async { ChangeHostWorld::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), githost::change_host_checks().len());
}

/// The three checks that the done criteria name, one by one, so a failure says which.
#[tokio::test]
async fn check_runs_and_markers() {
    let report = githost::run_change_host(|| async { ChangeHostWorld::new() }).await;
    for name in [
        "a_check_run_is_updated_not_duplicated",
        "a_pull_request_needs_a_pushed_head",
        "a_comment_is_found_by_its_marker_before_posting",
        "a_check_run_carries_the_apps_identity",
        "opening_for_the_same_head_twice_returns_the_same_pull_request",
    ] {
        assert!(
            report.passed.contains(&name),
            "{name} did not pass: failed = {:?}",
            report.failed_names()
        );
    }
}
