//! The real broker against the shared `ModelBroker` contract suite, the same suite the in-memory
//! fake passes. The subject spends through `MeteringOps`, the seam the port describes; the HTTP
//! listener is checked against the same suite in `http_contract.rs`.

mod support;

use factory_testkit::contracts::broker;
use support::CoreSubject;

#[tokio::test]
async fn the_real_broker_passes_the_broker_contract() {
    let report = broker::run(|| async { CoreSubject::new() }).await;
    report.assert_ok();
    assert_eq!(report.passed.len(), broker::checks().len());
}

/// `revoke_for_job` revokes every token of the job, and spend recorded through `MeteringOps`
/// that reaches the ceiling revokes the token in the same step. Both are contract checks; this
/// test runs the suite and looks at just those two, so the done criterion of the work package
/// has a test of its own name.
#[tokio::test]
async fn revoke_for_job_and_metering_through_the_core() {
    let report = broker::run(|| async { CoreSubject::new() }).await;
    for name in [
        "revoke_for_job_revokes_every_token_of_the_job",
        "metering_to_the_ceiling_revokes_the_token",
    ] {
        assert!(
            report.passed.contains(&name),
            "{name} did not pass: {:?}",
            report.failed_names()
        );
    }
}
