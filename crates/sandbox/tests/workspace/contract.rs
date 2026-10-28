//! The workspace contract suite against the git adapter, the same suite the fake passes.

use factory_testkit::contracts::workspace;

use crate::harness::{CaseSensitiveVolume, GitSubject};

#[tokio::test(flavor = "multi_thread")]
async fn the_git_adapter_passes_the_workspace_contract() {
    // `.GitHub` next to `.github` is only a different name on a case-sensitive file system.
    let volume = CaseSensitiveVolume::mount();
    let report = workspace::run(|| async { GitSubject::new_in(volume.dir()).await }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), workspace::checks().len());
}
