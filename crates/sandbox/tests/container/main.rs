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
mod hand_made;
mod harness;
mod isolation;
mod retry;

use factory_testkit::contracts::sandbox;

#[tokio::test(flavor = "multi_thread")]
async fn the_docker_adapter_passes_the_sandbox_contract() {
    let report = sandbox::run(|| async { contract::DockerSubject::new() }).await;
    report.assert_ok();
    // One check may be skipped, for one reason only: a daemon that has AppArmor (a Linux host)
    // cannot be made to lack it, so the check of a daemon without AppArmor has nothing to run
    // on. Docker Desktop lacks AppArmor and runs it; the scripted suite runs it on both hosts.
    let allowed = (
        "apparmor_not_available_is_accepted_only_by_policy",
        "skipped: this subject cannot make the daemon lack AppArmor",
    );
    assert!(
        report
            .skipped
            .iter()
            .all(|(name, why)| (*name, why.as_str()) == allowed),
        "skipped: {:?}",
        report.skipped
    );
    assert_eq!(
        report.passed.len() + report.skipped.len(),
        sandbox::checks().len()
    );
}
