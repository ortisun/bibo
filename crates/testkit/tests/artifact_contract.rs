//! The in-memory artifact store against the shared artifact store contract suite, and against
//! each deliberate defect. The table of defects lives with the fake (`artifact::DEFECTS`) so that
//! `contract_register` reads the same one.

use factory_testkit::artifact::{ArtifactDefect, DEFECTS, InMemoryArtifactSubject};
use factory_testkit::contracts::artifact;

#[tokio::test]
async fn the_in_memory_artifact_store_passes_the_artifact_store_contract() {
    let report = artifact::run(|| async { InMemoryArtifactSubject::new() }).await;
    report.assert_ok();
    assert_eq!(report.passed.len(), artifact::checks().len());
}

#[tokio::test]
async fn the_artifact_store_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let defect: ArtifactDefect = *defect;
        let report =
            artifact::run(|| async move { InMemoryArtifactSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a store with the defect {defect:?}"
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
