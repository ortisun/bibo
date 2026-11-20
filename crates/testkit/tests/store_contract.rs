//! The in-memory store against the shared contract suite, and against each deliberate defect. The table of
//! defects lives with the fake (`store::DEFECTS`), so that `contract_register` reads the same one.

use factory_testkit::contracts::store;
use factory_testkit::store::{DEFECTS, InMemoryStoreSubject};

#[tokio::test]
async fn the_in_memory_store_passes_the_store_contract() {
    let report = store::run(|| async { InMemoryStoreSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), store::checks().len());
}

#[tokio::test]
async fn the_store_contract_catches_every_deliberate_defect() {
    let mut problems = Vec::new();
    for (defect, must_fail) in DEFECTS {
        let defect = *defect;
        let report = store::run(|| async move { InMemoryStoreSubject::with_defect(defect) }).await;
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
