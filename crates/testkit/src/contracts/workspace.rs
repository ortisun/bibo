//! The contract suite for `WorkspaceProvider` and `Workspace`: the trusted read path, the audit at
//! ingestion, committing only what was audited, and pushing only to `factory/`.
//!
//! The suite works on a small fixture repository. A subject must seed its repository with exactly
//! [`FIXTURE_FILES`] at the base commit it reports, and must build requests with
//! [`HIDDEN_GLOB`] hidden and [`PROTECTED_GLOB`] protected.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_ports::clock::Uuid;
use factory_ports::paths::{BranchName, CommitSha, RepoGlob, RepoPath, RepoRef};
use factory_ports::workspace::{
    ChangeKind, ChangedPath, CommitRequest, IngestedChange, PushCredential, PushTarget, Workspace,
    WorkspaceError, WorkspaceMounts, WorkspaceProvider, WorkspaceRequest,
};

use super::{Check, Context, Report, check_list, ensure, ensure_eq, ensure_err, run_checks};

/// The files of the base commit: path and text.
pub const FIXTURE_FILES: [(&str, &str); 6] = [
    ("README.md", "# Fixture\n"),
    ("src/lib.rs", "pub fn answer() -> u32 { 42 }\n"),
    ("src/main.rs", "fn main() {}\n"),
    ("docs/guide.md", "A guide to the fixture.\n"),
    (
        "tests/holdout/secret_case.rs",
        "// held out from the sandbox\n",
    ),
    (".github/workflows/ci.yml", "name: ci\n"),
];

/// The pattern of the hidden paths: they never exist in the checkout.
pub const HIDDEN_GLOB: &str = "tests/holdout/**";

/// The pattern of the protected paths: the sandbox may read them but a change is refused.
pub const PROTECTED_GLOB: &str = ".github/**";

/// One change the sandbox makes to its writable tree.
#[derive(Debug, Clone)]
pub enum TreeEdit {
    /// Creates or overwrites a file.
    Write(RepoPath, Vec<u8>),
    /// Removes a file.
    Delete(RepoPath),
    /// Creates a symbolic link at `path` pointing at `target`.
    Symlink {
        /// Where the link is.
        path: RepoPath,
        /// What it points at, as text.
        target: String,
    },
    /// Creates a gitlink (a submodule entry) at the path.
    Gitlink(RepoPath),
    /// Creates a git directory inside the directory at the path.
    NestedGit(RepoPath),
}

/// What the suite needs beyond the two workspace ports.
#[async_trait]
pub trait WorkspaceSubject: Send + Sync {
    /// The provider under test.
    fn provider(&self) -> &dyn WorkspaceProvider;

    /// The repository the provider can check out.
    fn repo(&self) -> RepoRef;

    /// The base commit, which holds [`FIXTURE_FILES`].
    fn base(&self) -> CommitSha;

    /// Changes the sandbox-writable tree of the workspace, as the sandbox would. A fake edits its
    /// map. A real adapter writes into `mounts().workspace` on disk.
    async fn edit_sandbox_tree(
        &self,
        workspace: &dyn Workspace,
        edit: TreeEdit,
    ) -> Result<(), String>;

    /// The commit the remote branch points at, or `None` when nothing was pushed there.
    async fn pushed_commit(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha>;

    /// True when the workspace's host directories still exist.
    async fn directories_exist(&self, mounts: &WorkspaceMounts) -> bool;
}

/// A check of the workspace contract.
pub type WorkspaceCheck = Check<dyn WorkspaceSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: WorkspaceSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn WorkspaceSubject>
    })
    .await
}

/// Every check of the workspace contract.
#[must_use]
pub fn checks() -> Vec<WorkspaceCheck> {
    check_list![dyn WorkspaceSubject;
        a_new_workspace_masks_git_and_overlays_the_protected_paths,
        base_files_are_read_from_the_trusted_store_and_hidden_paths_are_not_found,
        the_sandbox_cannot_change_what_the_host_reads_from_the_base,
        listing_matches_a_glob_in_order_and_never_shows_hidden_paths,
        an_untouched_tree_ingests_as_no_change,
        additions_modifications_and_deletions_are_reported,
        a_rename_is_a_deletion_and_an_addition,
        a_change_to_a_protected_path_is_refused_with_every_changed_path,
        a_hidden_path_in_the_tree_is_refused,
        a_symlink_that_leaves_the_workspace_is_refused,
        a_gitlink_is_refused,
        a_nested_git_directory_is_refused,
        a_secret_in_a_changed_file_is_refused_without_repeating_it,
        an_audited_change_can_be_committed_and_pushed,
        a_change_the_workspace_never_ingested_is_not_committed,
        a_push_outside_factory_branches_is_refused,
        a_commit_the_workspace_did_not_make_is_not_pushed,
        disposing_removes_the_host_directories,
        two_workspaces_do_not_share_a_tree,
    ]
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn path(text: &str) -> Result<RepoPath, String> {
    RepoPath::new(text).ctx(&format!("path {text}"))
}

fn glob(text: &str) -> Result<RepoGlob, String> {
    RepoGlob::new(text).ctx(&format!("glob {text}"))
}

fn job(n: u128) -> JobId {
    JobId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

async fn open(subject: &dyn WorkspaceSubject, n: u128) -> Result<Box<dyn Workspace>, String> {
    let request = WorkspaceRequest {
        job: job(n),
        repo: subject.repo(),
        base: subject.base(),
        hidden: vec![glob(HIDDEN_GLOB)?],
        protected: vec![glob(PROTECTED_GLOB)?],
    };
    subject
        .provider()
        .create(request)
        .await
        .ctx("create a workspace")
}

async fn write(
    subject: &dyn WorkspaceSubject,
    workspace: &dyn Workspace,
    at: &str,
    text: &str,
) -> Result<(), String> {
    subject
        .edit_sandbox_tree(
            workspace,
            TreeEdit::Write(path(at)?, text.as_bytes().to_vec()),
        )
        .await
}

fn change(at: &str, kind: ChangeKind) -> Result<ChangedPath, String> {
    Ok(ChangedPath {
        path: path(at)?,
        kind,
    })
}

fn sorted(mut changes: Vec<ChangedPath>) -> Vec<ChangedPath> {
    changes.sort();
    changes
}

fn commit_request() -> CommitRequest {
    CommitRequest {
        message: "Add the change the factory made".to_owned(),
        author_name: "Software Factory".to_owned(),
        author_email: "factory@example.invalid".to_owned(),
    }
}

// ---------------------------------------------------------------------------------------------
// Checks

async fn a_new_workspace_masks_git_and_overlays_the_protected_paths(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let mounts = workspace.mounts();
    ensure!(
        mounts.git_masked,
        "the version-control directory must be masked from the sandbox"
    );
    ensure!(
        mounts.workspace != mounts.out,
        "the workspace and the output directory must be different places"
    );
    let protected = glob(PROTECTED_GLOB)?;
    ensure!(
        mounts
            .protected_overlays
            .iter()
            .all(|overlay| protected.matches(overlay)),
        "every overlay must lie in a protected path, but they are {:?}",
        mounts.protected_overlays
    );
    let workflow = path(".github/workflows/ci.yml")?;
    ensure!(
        mounts
            .protected_overlays
            .iter()
            .any(|overlay| workflow.is_within(overlay)),
        "the protected file {workflow} must be covered by a read-only overlay, but the overlays are {:?}",
        mounts.protected_overlays
    );
    ensure!(
        subject.directories_exist(&mounts).await,
        "the workspace directories must exist after create"
    );
    Ok(())
}

async fn base_files_are_read_from_the_trusted_store_and_hidden_paths_are_not_found(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let read = workspace
        .read_base_file(&path("src/lib.rs")?, 1024)
        .await
        .ctx("read src/lib.rs")?;
    ensure_eq!(
        read,
        b"pub fn answer() -> u32 { 42 }\n".to_vec(),
        "the bytes of src/lib.rs"
    );
    ensure_err!(
        workspace
            .read_base_file(&path("src/absent.rs")?, 1024)
            .await,
        WorkspaceError::PathNotFound(_),
        "a path that is not in the base commit"
    );
    ensure_err!(
        workspace
            .read_base_file(&path("tests/holdout/secret_case.rs")?, 1024)
            .await,
        WorkspaceError::PathNotFound(_),
        "a hidden path"
    );
    ensure_err!(
        workspace.read_base_file(&path("src/lib.rs")?, 5).await,
        WorkspaceError::TooLarge,
        "a file larger than max_bytes"
    );
    Ok(())
}

async fn the_sandbox_cannot_change_what_the_host_reads_from_the_base(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    write(
        subject,
        workspace.as_ref(),
        "README.md",
        "# Rewritten by the sandbox\n",
    )
    .await?;
    let read = workspace
        .read_base_file(&path("README.md")?, 1024)
        .await
        .ctx("read")?;
    ensure_eq!(
        read,
        b"# Fixture\n".to_vec(),
        "the host's read of README.md after the sandbox rewrote it"
    );
    Ok(())
}

async fn listing_matches_a_glob_in_order_and_never_shows_hidden_paths(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let rust = workspace
        .list_base(&glob("**/*.rs")?, 100)
        .await
        .ctx("list rust")?;
    ensure_eq!(
        rust,
        vec![path("src/lib.rs")?, path("src/main.rs")?],
        "Rust files (the hidden holdout file must not appear)"
    );
    let first = workspace
        .list_base(&glob("**/*.rs")?, 1)
        .await
        .ctx("list with a limit")?;
    ensure_eq!(
        first,
        vec![path("src/lib.rs")?],
        "the first match under a limit of one"
    );
    let docs = workspace
        .list_base(&glob("docs/**")?, 100)
        .await
        .ctx("list docs")?;
    ensure_eq!(docs, vec![path("docs/guide.md")?], "files under docs");
    let hidden = workspace
        .list_base(&glob(HIDDEN_GLOB)?, 100)
        .await
        .ctx("list hidden")?;
    ensure_eq!(hidden.len(), 0, "hidden paths");
    Ok(())
}

async fn an_untouched_tree_ingests_as_no_change(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let ingested = workspace.ingest(&subject.base()).await.ctx("ingest")?;
    ensure!(
        ingested.is_empty(),
        "a tree nobody touched has changes: {:?}",
        ingested.changes()
    );
    ensure_eq!(
        ingested.base().clone(),
        subject.base(),
        "the base of the change"
    );
    Ok(())
}

async fn additions_modifications_and_deletions_are_reported(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    write(subject, workspace.as_ref(), "docs/new.md", "A new page.\n").await?;
    write(
        subject,
        workspace.as_ref(),
        "README.md",
        "# Fixture, edited\n",
    )
    .await?;
    subject
        .edit_sandbox_tree(workspace.as_ref(), TreeEdit::Delete(path("src/main.rs")?))
        .await?;
    let ingested = workspace.ingest(&subject.base()).await.ctx("ingest")?;
    ensure_eq!(
        ingested.changes().to_vec(),
        sorted(vec![
            change("docs/new.md", ChangeKind::Added)?,
            change("README.md", ChangeKind::Modified)?,
            change("src/main.rs", ChangeKind::Deleted)?,
        ]),
        "the reported changes"
    );
    Ok(())
}

async fn a_rename_is_a_deletion_and_an_addition(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    subject
        .edit_sandbox_tree(workspace.as_ref(), TreeEdit::Delete(path("docs/guide.md")?))
        .await?;
    write(
        subject,
        workspace.as_ref(),
        "docs/handbook.md",
        "A guide to the fixture.\n",
    )
    .await?;
    let ingested = workspace.ingest(&subject.base()).await.ctx("ingest")?;
    ensure_eq!(
        ingested.changes().to_vec(),
        sorted(vec![
            change("docs/guide.md", ChangeKind::Deleted)?,
            change("docs/handbook.md", ChangeKind::Added)?,
        ]),
        "a rename must show both ends, so a protected-path rule sees both"
    );
    Ok(())
}

async fn a_change_to_a_protected_path_is_refused_with_every_changed_path(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    write(
        subject,
        workspace.as_ref(),
        ".github/workflows/ci.yml",
        "name: skip tests\n",
    )
    .await?;
    write(
        subject,
        workspace.as_ref(),
        ".github/workflows/extra.yml",
        "name: extra\n",
    )
    .await?;
    write(
        subject,
        workspace.as_ref(),
        "docs/ok.md",
        "An allowed change.\n",
    )
    .await?;
    match workspace.ingest(&subject.base()).await {
        Err(WorkspaceError::ProtectedPathChanged(paths)) => {
            let mut expected = vec![
                path(".github/workflows/ci.yml")?,
                path(".github/workflows/extra.yml")?,
            ];
            expected.sort();
            let mut found = paths;
            found.sort();
            ensure_eq!(found, expected, "the protected paths reported");
            Ok(())
        }
        Err(other) => Err(format!(
            "a protected change: expected ProtectedPathChanged but found {other:?}"
        )),
        Ok(_) => Err("a protected change was ingested".to_owned()),
    }
}

async fn a_hidden_path_in_the_tree_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    write(
        subject,
        workspace.as_ref(),
        "tests/holdout/planted.rs",
        "// planted\n",
    )
    .await?;
    ensure_err!(
        workspace.ingest(&subject.base()).await,
        WorkspaceError::HiddenPathPresent(_),
        "a file under a hidden path"
    );
    Ok(())
}

async fn a_symlink_that_leaves_the_workspace_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    for target in ["/etc/passwd", "../../outside", "../../../x"] {
        let workspace = open(subject, 1).await?;
        subject
            .edit_sandbox_tree(
                workspace.as_ref(),
                TreeEdit::Symlink {
                    path: path("docs/link")?,
                    target: target.to_owned(),
                },
            )
            .await?;
        match workspace.ingest(&subject.base()).await {
            Err(WorkspaceError::EscapingSymlink(at)) => {
                ensure_eq!(
                    at,
                    path("docs/link")?,
                    "the link reported for target {target}"
                );
            }
            Err(other) => {
                return Err(format!(
                    "a link to {target}: expected EscapingSymlink but found {other:?}"
                ));
            }
            Ok(_) => return Err(format!("a link to {target} was ingested")),
        }
    }
    // A link that stays inside the workspace is ordinary content.
    let workspace = open(subject, 1).await?;
    subject
        .edit_sandbox_tree(
            workspace.as_ref(),
            TreeEdit::Symlink {
                path: path("docs/readme-link")?,
                target: "../README.md".to_owned(),
            },
        )
        .await?;
    let ingested = workspace
        .ingest(&subject.base())
        .await
        .ctx("a link inside the workspace")?;
    ensure_eq!(
        ingested.changes().to_vec(),
        vec![change("docs/readme-link", ChangeKind::Added)?],
        "an internal link is an addition"
    );
    Ok(())
}

async fn a_gitlink_is_refused(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    subject
        .edit_sandbox_tree(workspace.as_ref(), TreeEdit::Gitlink(path("vendor/lib")?))
        .await?;
    ensure_err!(
        workspace.ingest(&subject.base()).await,
        WorkspaceError::Gitlink(_),
        "a gitlink"
    );
    Ok(())
}

async fn a_nested_git_directory_is_refused(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    subject
        .edit_sandbox_tree(workspace.as_ref(), TreeEdit::NestedGit(path("vendor/lib")?))
        .await?;
    ensure_err!(
        workspace.ingest(&subject.base()).await,
        WorkspaceError::NestedGit(_),
        "a nested git directory"
    );
    Ok(())
}

async fn a_secret_in_a_changed_file_is_refused_without_repeating_it(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    // A GitHub installation token: `ghs_` and 36 letters and digits (FX-CANARY).
    let canary = "ghs_a1B2c3D4e5a1B2c3D4e5a1B2c3D4e5a1B2c3";
    let notes = path("docs/notes.md")?;
    write(
        subject,
        workspace.as_ref(),
        "docs/notes.md",
        &format!("Remember the token {canary} for later.\n"),
    )
    .await?;
    let error = match workspace.ingest(&subject.base()).await {
        Err(error) => error,
        Ok(_) => return Err("a file with a token was ingested".to_owned()),
    };
    let WorkspaceError::SecretFound(findings) = &error else {
        return Err(format!(
            "a file with a token: expected SecretFound but found {error:?}"
        ));
    };
    ensure!(
        !findings.is_empty(),
        "a secret was found but no finding was reported"
    );
    ensure!(
        findings
            .iter()
            .any(|finding| finding.path.as_ref() == Some(&notes)),
        "a finding must name the file, but they are {findings:?}"
    );
    ensure!(
        !format!("{error} {error:?}").contains(canary),
        "the error must not repeat the secret"
    );
    Ok(())
}

async fn an_audited_change_can_be_committed_and_pushed(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    write(
        subject,
        workspace.as_ref(),
        "README.md",
        "# Fixture, improved\n",
    )
    .await?;
    let ingested = workspace.ingest(&subject.base()).await.ctx("ingest")?;
    let commit = workspace
        .commit(&ingested, commit_request())
        .await
        .ctx("commit")?;
    ensure!(
        commit != subject.base(),
        "a commit of a change must differ from the base commit"
    );

    let branch = BranchName::new("factory/job-1").ctx("branch")?;
    let target = PushTarget {
        repo: subject.repo(),
        branch: branch.clone(),
        credential: PushCredential::new("test-credential".to_owned()),
    };
    ensure_eq!(
        subject.pushed_commit(&subject.repo(), &branch).await,
        None,
        "the branch before the push"
    );
    workspace.push(&target, &commit).await.ctx("push")?;
    ensure_eq!(
        subject.pushed_commit(&subject.repo(), &branch).await,
        Some(commit.clone()),
        "the branch after the push"
    );
    workspace
        .push(&target, &commit)
        .await
        .ctx("a second push of the same commit")?;
    Ok(())
}

async fn a_change_the_workspace_never_ingested_is_not_committed(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let fabricated = IngestedChange::new(
        subject.base(),
        vec![change("README.md", ChangeKind::Modified)?],
        factory_domain::values::Sha256Digest::of(b"a tree nobody audited"),
    );
    ensure_err!(
        workspace.commit(&fabricated, commit_request()).await,
        WorkspaceError::Git(_),
        "a change that was not produced by ingest"
    );
    Ok(())
}

async fn a_push_outside_factory_branches_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    write(
        subject,
        workspace.as_ref(),
        "README.md",
        "# Fixture, improved\n",
    )
    .await?;
    let ingested = workspace.ingest(&subject.base()).await.ctx("ingest")?;
    let commit = workspace
        .commit(&ingested, commit_request())
        .await
        .ctx("commit")?;
    for name in ["main", "release/1.0", "factory-evil/x"] {
        let branch = BranchName::new(name).ctx("branch")?;
        let target = PushTarget {
            repo: subject.repo(),
            branch: branch.clone(),
            credential: PushCredential::new("test-credential".to_owned()),
        };
        ensure_err!(
            workspace.push(&target, &commit).await,
            WorkspaceError::BranchNotAllowed,
            "a push to {name}"
        );
        ensure_eq!(
            subject.pushed_commit(&subject.repo(), &branch).await,
            None,
            "the branch {name} after the refused push"
        );
    }
    Ok(())
}

async fn a_commit_the_workspace_did_not_make_is_not_pushed(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let foreign = CommitSha::parse(&"ab".repeat(20)).ctx("sha")?;
    let target = PushTarget {
        repo: subject.repo(),
        branch: BranchName::new("factory/job-1").ctx("branch")?,
        credential: PushCredential::new("test-credential".to_owned()),
    };
    ensure_err!(
        workspace.push(&target, &foreign).await,
        WorkspaceError::Git(_),
        "a push of a commit this workspace did not make"
    );
    Ok(())
}

async fn disposing_removes_the_host_directories(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let workspace = open(subject, 1).await?;
    let mounts = workspace.mounts();
    ensure!(
        subject.directories_exist(&mounts).await,
        "the directories must exist before dispose"
    );
    workspace.dispose().await.ctx("dispose")?;
    ensure!(
        !subject.directories_exist(&mounts).await,
        "the directories must be gone after dispose"
    );
    Ok(())
}

async fn two_workspaces_do_not_share_a_tree(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let one = open(subject, 1).await?;
    let two = open(subject, 2).await?;
    ensure!(
        one.mounts().workspace != two.mounts().workspace,
        "two workspaces must have different directories"
    );
    write(subject, one.as_ref(), "docs/only-in-one.md", "Only here.\n").await?;
    let untouched = two
        .ingest(&subject.base())
        .await
        .ctx("ingest the second workspace")?;
    ensure!(
        untouched.is_empty(),
        "an edit in one workspace showed up in another: {:?}",
        untouched.changes()
    );
    Ok(())
}
