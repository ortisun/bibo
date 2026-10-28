//! The scripted process runner against the shared contract suite, and against each deliberate
//! defect. The table of defects lives with the fake (`process::DEFECTS`), so that
//! `contract_register` reads the same one.

use factory_testkit::contracts::process;
use factory_testkit::process::{DEFECTS, ScriptedProcessSubject};

#[tokio::test(start_paused = true)]
async fn the_scripted_runner_passes_the_process_contract() {
    let report = process::run(|| async { ScriptedProcessSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), process::checks().len());
}

#[tokio::test(start_paused = true)]
async fn the_process_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report =
            process::run(|| async move { ScriptedProcessSubject::with_defect(defect) }).await;
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
