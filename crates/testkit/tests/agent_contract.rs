//! The scripted runtime against the shared agent runtime contract suite, and against each
//! deliberate defect. Time is paused so the cancellation checks run without waiting. The table of
//! defects lives with the fake (`agent::DEFECTS`).

use factory_testkit::agent::{DEFECTS, FakeAgentRuntimeSubject};
use factory_testkit::contracts::agent;

#[tokio::test(start_paused = true)]
async fn the_scripted_runtime_passes_the_agent_runtime_contract() {
    let report = agent::run(|| async { FakeAgentRuntimeSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), agent::checks().len());
}

#[tokio::test(start_paused = true)]
async fn the_agent_runtime_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report =
            agent::run(|| async move { FakeAgentRuntimeSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a runtime with the defect {defect:?}"
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
