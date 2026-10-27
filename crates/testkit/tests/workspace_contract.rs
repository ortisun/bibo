//! The fake workspace against the shared workspace contract suite, and against each deliberate
//! defect.

use factory_testkit::contracts::workspace;
use factory_testkit::workspace::{FakeWorkspaceSubject, WorkspaceDefect};

#[tokio::test]
async fn the_fake_workspace_passes_the_workspace_contract() {
    let report = workspace::run(|| async { FakeWorkspaceSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), workspace::checks().len());
}

const DEFECTS: [(WorkspaceDefect, &[&str]); 9] = [
    (
        WorkspaceDefect::ReadsFromSandboxTree,
        &["the_sandbox_cannot_change_what_the_host_reads_from_the_base"],
    ),
    (
        WorkspaceDefect::ShowsHiddenPaths,
        &[
            "base_files_are_read_from_the_trusted_store_and_hidden_paths_are_not_found",
            "listing_matches_a_glob_in_order_and_never_shows_hidden_paths",
        ],
    ),
    (
        WorkspaceDefect::SkipsHiddenPathCheck,
        &["a_hidden_path_in_the_tree_is_refused"],
    ),
    (
        WorkspaceDefect::SkipsProtectedPathCheck,
        &["a_change_to_a_protected_path_is_refused_with_every_changed_path"],
    ),
    (
        WorkspaceDefect::FollowsEscapingSymlinks,
        &["a_symlink_that_leaves_the_workspace_is_refused"],
    ),
    (
        WorkspaceDefect::SkipsSecretScan,
        &["a_secret_in_a_changed_file_is_refused_without_repeating_it"],
    ),
    (
        WorkspaceDefect::PushesAnyBranch,
        &["a_push_outside_factory_branches_is_refused"],
    ),
    (
        WorkspaceDefect::CommitsUnauditedChanges,
        &["a_change_the_workspace_never_ingested_is_not_committed"],
    ),
    (
        WorkspaceDefect::SharesOneTree,
        &["two_workspaces_do_not_share_a_tree"],
    ),
];

#[tokio::test]
async fn the_workspace_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let report =
            workspace::run(|| async move { FakeWorkspaceSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a workspace with the defect {defect:?}"
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
