//! The fake sandbox provider against the shared contract suite, and against each deliberate defect. The table of
//! defects lives with the fake (`sandbox::DEFECTS`), so that `contract_register` reads the same one.

use factory_testkit::contracts::sandbox;
use factory_testkit::sandbox::{DEFECTS, FakeSandboxSubject};

#[tokio::test(start_paused = true)]
async fn the_fake_sandbox_passes_the_sandbox_contract() {
    let report = sandbox::run(|| async { FakeSandboxSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), sandbox::checks().len());
}

#[tokio::test(start_paused = true)]
async fn the_sandbox_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report = sandbox::run(|| async move { FakeSandboxSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a fake with the defect {defect:?}"
        );
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
