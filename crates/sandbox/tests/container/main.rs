//! The Docker adapter against a real daemon (work package `s1-sandbox-adapter`).
//!
//! Every test here needs Docker and the three images of `infra/sandbox-images/images.json`. When
//! either is missing the test panics with a message that starts `BLOCKED:` (the convention of the
//! security harness). It never skips quietly and it never passes without a daemon.
//!
//! Every container, network and volume a test makes carries the run's label
//! (`factory.test_run=<id>`), and the lab removes what is labelled when the test ends.

#[path = "../support/mod.rs"]
mod support;

mod behavior;
mod breaks;
mod contract;
mod harness;

use factory_testkit::contracts::sandbox;

#[tokio::test(flavor = "multi_thread")]
async fn the_docker_adapter_passes_the_sandbox_contract() {
    let report = sandbox::run(|| async { contract::DockerSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), sandbox::checks().len());
}
