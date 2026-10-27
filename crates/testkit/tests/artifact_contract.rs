//! The in-memory artifact store against the shared artifact store contract suite, and against
//! each deliberate defect.

use factory_testkit::artifact::{ArtifactDefect, InMemoryArtifactSubject};
use factory_testkit::contracts::artifact;

#[tokio::test]
async fn the_in_memory_artifact_store_passes_the_artifact_store_contract() {
    let report = artifact::run(|| async { InMemoryArtifactSubject::new() }).await;
    report.assert_ok();
    assert_eq!(report.passed.len(), artifact::checks().len());
}

const DEFECTS: [(ArtifactDefect, &[&str]); 4] = [
    (
        ArtifactDefect::NotContentAddressed,
        &[
            "stored_bytes_come_back_unchanged_with_a_reference_that_describes_them",
            "the_same_bytes_give_the_same_reference",
        ],
    ),
    (
        ArtifactDefect::SkipsRehashOnGet,
        &["a_damaged_blob_is_never_returned"],
    ),
    (
        ArtifactDefect::IgnoresSizeLimit,
        &["an_object_over_the_limit_is_refused"],
    ),
    (
        ArtifactDefect::KeepsFirstMediaType,
        &["the_same_bytes_with_another_media_type_share_one_hash"],
    ),
];

#[tokio::test]
async fn the_artifact_store_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let report =
            artifact::run(|| async move { InMemoryArtifactSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a store with the defect {defect:?}"
        );
        for name in must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
