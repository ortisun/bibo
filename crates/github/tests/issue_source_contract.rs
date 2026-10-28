//! The shared contract suite for `IssueSource`, run against the GitHub adapter talking to the fake
//! GitHub server over the loopback interface.

mod common;

use common::subjects::IssueSourceWorld;
use factory_testkit::contracts::githost;

#[tokio::test]
async fn the_github_issue_source_passes_the_whole_issue_source_contract() {
    let report = githost::run_issue_source(|| async { IssueSourceWorld::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), githost::issue_source_checks().len());
}
