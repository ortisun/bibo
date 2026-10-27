//! The fake workspace provider against the shared contract suite, and against each deliberate defect. The table of
//! defects lives with the fake (`workspace::DEFECTS`), so that `contract_register` reads the same one.

use factory_testkit::contracts::workspace;
use factory_testkit::workspace::{DEFECTS, FakeWorkspaceSubject};

#[tokio::test]
async fn the_fake_workspace_passes_the_workspace_contract() {
    let report = workspace::run(|| async { FakeWorkspaceSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), workspace::checks().len());
}

#[tokio::test]
async fn the_workspace_contract_catches_every_deliberate_defect() {
    let mut problems = Vec::new();
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report =
            workspace::run(|| async move { FakeWorkspaceSubject::with_defect(defect) }).await;
        if report.is_ok() {
            problems.push(format!(
                "the suite passed a fake with the defect {defect:?}"
            ));
        }
        for name in *must_fail {
            if !report.failed_check(name) {
                problems.push(format!(
                    "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                    report.failed_names()
                ));
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
