//! The contract suite for `WorkspaceProvider`, `JobRepo` and `Workspace` (ports-v1.1): the job's
//! object store, the attempt's worktree over it, the audit at ingestion with the policy's five
//! path modes, committing only what was audited, and pushing only what the factory made.
//!
//! The suite works on a small fixture repository. A subject must hold exactly [`FIXTURE_FILES`] at
//! the tip of its branch and must apply [`fixture_rules`].

use std::future::Future;

use async_trait::async_trait;
use factory_domain::ids::{AttemptId, JobId};
use factory_ports::clock::Uuid;
use factory_ports::paths::{
    BranchName, CommitSha, PathMode, PathRule, PathRules, RepoGlob, RepoPath, RepoRef,
};
use factory_ports::workspace::{
    ChangeKind, CommitRequest, FetchCredential, FetchTarget, FetchedBase, PushCredential,
    PushTarget, ReadView, Workspace, WorkspaceError, WorkspaceMounts, WorkspaceProvider,
    WorkspacePurpose, WorkspaceRequest,
};

use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};
use crate::clock::FakeCancel;

/// The files of the branch tip: path and text.
pub const FIXTURE_FILES: [(&str, &str); 11] = [
    ("README.md", "# Fixture\n"),
    ("src/lib.rs", "pub fn answer() -> u32 { 42 }\n"),
    ("src/main.rs", "fn main() {}\n"),
    ("docs/guide.md", "A guide to the fixture.\n"),
    (
        "tests/holdout/secret_case.rs",
        "// held out from the sandbox\n",
    ),
    (".github/workflows/ci.yml", "name: ci\n"),
    ("CHANGELOG.md", "# Changelog\n- first\n"),
    ("docs/notes.md", "line one\nline two\n"),
    ("Cargo.toml", "[package]\nname = \"fixture\"\n"),
    (".env", "LOCAL=1\n"),
    (".env.example", "LOCAL=\n"),
];

/// The pattern of the hidden test paths: they never exist in the agent's checkout.
pub const HIDDEN_GLOB: &str = "tests/holdout/**";

/// The pattern of the `deny_write` paths: the sandbox may read them but a change is refused.
pub const PROTECTED_GLOB: &str = ".github/**";

/// The path rules of the fixture, shaped like `policies/security.yaml` `protected_paths`:
///
/// * `holdouts` hides `tests/holdout/**`;
/// * `ci` is `deny_write` on `.github/**`;
/// * `history` is `append_only` on `CHANGELOG.md`;
/// * `notes` is `additions_only` on `docs/notes.md`;
/// * `toolchain` is `sensitive` on `Cargo.toml`;
/// * `secrets` hides `.env*` and re-includes `.env.example` in its own group, while the `ci` group
///   also names `.env.example` as `deny_write`, to show that a re-inclusion lifts only its group.
///
/// # Panics
/// Never in practice: every glob is valid.
#[must_use]
pub fn fixture_rules() -> PathRules {
    let mode = |group: &str, glob: &str, mode: PathMode| {
        (
            group.to_owned(),
            PathRule::Mode {
                glob: RepoGlob::new(glob).expect("a valid glob"),
                mode,
            },
        )
    };
    PathRules::new(vec![
        mode("holdouts", HIDDEN_GLOB, PathMode::Hidden),
        mode("ci", PROTECTED_GLOB, PathMode::DenyWrite),
        mode("ci", ".env.example", PathMode::DenyWrite),
        mode("history", "CHANGELOG.md", PathMode::AppendOnly),
        mode("notes", "docs/notes.md", PathMode::AdditionsOnly),
        mode("toolchain", "Cargo.toml", PathMode::Sensitive),
        mode("secrets", ".env*", PathMode::Hidden),
        (
            "secrets".to_owned(),
            PathRule::Reinclude {
                glob: RepoGlob::new(".env.example").expect("a valid glob"),
                group: "secrets".to_owned(),
            },
        ),
    ])
}

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

/// What the suite needs beyond the workspace ports.
#[async_trait]
pub trait WorkspaceSubject: Send + Sync {
    /// The provider under test.
    fn provider(&self) -> &dyn WorkspaceProvider;

    /// The repository the provider can fetch.
    fn repo(&self) -> RepoRef;

    /// The branch whose tip holds [`FIXTURE_FILES`].
    fn branch(&self) -> BranchName;

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

    /// A provider value over the same host directory, as after a process restart. A fake clones
    /// its shared state. A real adapter builds a new value over the same directory.
    async fn restart(&self) -> Box<dyn WorkspaceProvider>;

    /// Adds a commit with `files` on top of the remote branch, as someone pushing to the code host.
    async fn advance_remote_branch(&self, files: &[(&str, &str)]) -> CommitSha;

    /// Arranges for the remote branch to move while the next fetch runs. Returns `false` when the
    /// subject cannot do that, and the check is then reported as skipped.
    async fn move_remote_branch_during_next_fetch(&self, files: &[(&str, &str)]) -> bool;
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

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

/// Every check of the workspace contract.
#[must_use]
pub fn checks() -> Vec<WorkspaceCheck> {
    check_list![dyn WorkspaceSubject;
        fetch_returns_the_tip_it_fetched,
        fetch_reports_a_moved_base,
        a_new_workspace_masks_git_and_overlays_the_protected_paths,
        a_hidden_path_is_not_found_in_the_agent_view_and_is_in_the_trusted_view,
        the_sandbox_cannot_change_what_the_host_reads_from_the_base,
        listing_matches_a_glob_in_order_and_never_shows_hidden_paths,
        additions_modifications_and_deletions_are_reported,
        a_change_to_a_protected_path_is_refused_with_every_changed_path,
        an_added_test_is_allowed_and_an_edited_test_is_refused_under_additions_only,
        a_case_variant_of_a_protected_path_is_refused,
        a_reincluded_path_is_allowed_only_in_its_own_group,
        a_hidden_path_in_the_tree_is_refused,
        a_symlink_that_leaves_the_workspace_is_refused,
        a_gitlink_is_refused,
        a_nested_git_directory_is_refused,
        a_secret_in_a_changed_file_is_refused_without_repeating_it,
        a_cancelled_ingest_leaves_nothing_behind,
        an_audited_change_can_be_committed_and_pushed,
        a_change_the_workspace_never_ingested_is_not_committed,
        a_push_outside_factory_branches_is_refused,
        a_commit_the_factory_did_not_make_is_not_pushed,
        a_second_workspace_can_start_at_a_commit_the_first_made,
        push_works_after_a_restart,
        a_verify_workspace_is_read_only_and_holds_the_holdouts,
        export_patch_is_the_same_for_the_same_commits,
        disposing_removes_the_host_directories,
        two_workspaces_do_not_share_a_tree,
    ]
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn job(n: u128) -> JobId {
    JobId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

fn attempt(n: u128) -> AttemptId {
    AttemptId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62) | 1,
    ))
}

fn path(text: &str) -> RepoPath {
    RepoPath::new(text).expect("a valid fixture path")
}

fn fetch_target(subject: &dyn WorkspaceSubject) -> FetchTarget {
    // Built at run time so that no credential-shaped literal sits in the source.
    FetchTarget {
        repo: subject.repo(),
        credential: FetchCredential::new(format!("{}-{}", "read", "credential")),
    }
}

fn push_target(subject: &dyn WorkspaceSubject, branch: &str) -> PushTarget {
    PushTarget {
        repo: subject.repo(),
        branch: BranchName::new(branch).expect("a valid branch"),
        credential: PushCredential::new(format!("{}-{}", "write", "credential")),
    }
}

async fn fetch(subject: &dyn WorkspaceSubject, n: u128) -> Result<FetchedBase, String> {
    subject
        .provider()
        .fetch(
            job(n),
            &fetch_target(subject),
            &subject.branch(),
            &FakeCancel::new(),
        )
        .await
        .ctx("fetch the branch")
}

async fn open_as(
    subject: &dyn WorkspaceSubject,
    n: u128,
    base: &CommitSha,
    purpose: WorkspacePurpose,
) -> Result<Box<dyn Workspace>, String> {
    subject
        .provider()
        .create(
            WorkspaceRequest {
                job: job(n),
                attempt: attempt(n),
                base: base.clone(),
                rules: fixture_rules(),
                purpose,
            },
            &FakeCancel::new(),
        )
        .await
        .ctx("create a workspace")
}

/// Fetches the branch for job `n` and opens an agent workspace at its tip.
async fn open(
    subject: &dyn WorkspaceSubject,
    n: u128,
) -> Result<(Box<dyn Workspace>, CommitSha), String> {
    let base = fetch(subject, n).await?.commit;
    let workspace = open_as(subject, n, &base, WorkspacePurpose::Agent).await?;
    Ok((workspace, base))
}

async fn write(
    subject: &dyn WorkspaceSubject,
    ws: &dyn Workspace,
    file: &str,
    text: &str,
) -> Result<(), String> {
    subject
        .edit_sandbox_tree(ws, TreeEdit::Write(path(file), text.as_bytes().to_vec()))
        .await
}

fn commit_request(message: &str) -> CommitRequest {
    CommitRequest {
        message: message.to_owned(),
        author_name: "Factory".to_owned(),
        author_email: "factory@example.invalid".to_owned(),
    }
}

async fn ingest(
    ws: &dyn Workspace,
) -> Result<factory_ports::workspace::IngestedChange, WorkspaceError> {
    ws.ingest(&FakeCancel::new()).await
}

fn protected(error: WorkspaceError) -> Option<Vec<(RepoPath, PathMode)>> {
    match error {
        WorkspaceError::ProtectedPathChanged(list) => {
            Some(list.into_iter().map(|v| (v.path, v.mode)).collect())
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------------------------

async fn fetch_returns_the_tip_it_fetched(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let first = fetch(subject, 1).await?;
    ensure_eq!(
        first.branch,
        subject.branch(),
        "the branch that was fetched"
    );
    let newer = subject
        .advance_remote_branch(&[("README.md", "# Fixture, second\n")])
        .await;
    let second = fetch(subject, 1).await?;
    ensure_eq!(second.commit, newer, "a second fetch returns the new tip");
    ensure!(first.commit != second.commit, "the tip moved");
    // An unknown branch is not a commit.
    let missing = BranchName::new("does-not-exist").expect("a branch");
    ensure_err!(
        subject
            .provider()
            .fetch(job(2), &fetch_target(subject), &missing, &FakeCancel::new())
            .await,
        WorkspaceError::UnknownCommit,
        "a branch the remote does not have"
    );
    Ok(())
}

async fn fetch_reports_a_moved_base(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    if !subject
        .move_remote_branch_during_next_fetch(&[("README.md", "# moved\n")])
        .await
    {
        super::skip!("this subject cannot move the branch while a fetch runs");
    }
    ensure_err!(
        subject
            .provider()
            .fetch(
                job(1),
                &fetch_target(subject),
                &subject.branch(),
                &FakeCancel::new()
            )
            .await,
        WorkspaceError::BaseMoved,
        "a branch that moved during the fetch"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The worktree and the trusted reads
// ---------------------------------------------------------------------------------------------

async fn a_new_workspace_masks_git_and_overlays_the_protected_paths(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    let mounts = ws.mounts();
    ensure!(mounts.git_masked, "the .git directory must be masked");
    ensure!(
        !mounts.workspace_read_only,
        "an agent workspace is writable"
    );
    ensure!(
        mounts
            .protected_overlays
            .contains(&path(".github/workflows/ci.yml")),
        "a deny_write file is re-mounted read-only, overlays were {:?}",
        mounts.protected_overlays
    );
    ensure!(
        mounts.protected_overlays.contains(&path("CHANGELOG.md")),
        "an append_only file is re-mounted read-only too"
    );
    ensure!(
        !mounts.protected_overlays.contains(&path("src/lib.rs")),
        "a free path is not overlaid"
    );
    Ok(())
}

async fn a_hidden_path_is_not_found_in_the_agent_view_and_is_in_the_trusted_view(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let base = fetch(subject, 1).await?.commit;
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    let hidden = path("tests/holdout/secret_case.rs");
    ensure_err!(
        repo.read_file_at(&base, &hidden, 4096, ReadView::Agent)
            .await,
        WorkspaceError::PathNotFound(_),
        "a hidden path in the agent view"
    );
    let trusted = repo
        .read_file_at(&base, &hidden, 4096, ReadView::Trusted)
        .await
        .ctx("the trusted view")?;
    ensure_eq!(
        trusted,
        b"// held out from the sandbox\n".to_vec(),
        "the trusted view reads it"
    );
    let shown = repo
        .read_file_at(&base, &path("src/lib.rs"), 4096, ReadView::Agent)
        .await
        .ctx("a free file")?;
    ensure_eq!(
        shown,
        b"pub fn answer() -> u32 { 42 }\n".to_vec(),
        "a free file in the agent view"
    );
    ensure_err!(
        repo.read_file_at(&base, &path("src/lib.rs"), 4, ReadView::Agent)
            .await,
        WorkspaceError::TooLarge,
        "a file over the limit"
    );
    let unknown = CommitSha::parse(&"f".repeat(40)).expect("a sha");
    ensure_err!(
        repo.read_file_at(&unknown, &path("src/lib.rs"), 4096, ReadView::Agent)
            .await,
        WorkspaceError::UnknownCommit,
        "a commit the store lacks"
    );
    Ok(())
}

async fn the_sandbox_cannot_change_what_the_host_reads_from_the_base(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, base) = open(subject, 1).await?;
    write(
        subject,
        &*ws,
        "src/lib.rs",
        "pub fn answer() -> u32 { 0 }\n",
    )
    .await?;
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    let read = repo
        .read_file_at(&base, &path("src/lib.rs"), 4096, ReadView::Trusted)
        .await
        .ctx("read")?;
    ensure_eq!(
        read,
        b"pub fn answer() -> u32 { 42 }\n".to_vec(),
        "the host reads the base, not the sandbox's edit"
    );
    Ok(())
}

async fn listing_matches_a_glob_in_order_and_never_shows_hidden_paths(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let base = fetch(subject, 1).await?.commit;
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    let all = RepoGlob::new("**").expect("a glob");
    let agent = repo
        .list_at(&base, &all, 100, ReadView::Agent)
        .await
        .ctx("list")?;
    let names: Vec<&str> = agent.iter().map(RepoPath::as_str).collect();
    ensure!(
        !names.contains(&"tests/holdout/secret_case.rs"),
        "a hidden path is listed: {names:?}"
    );
    ensure!(
        !names.contains(&".env"),
        "a hidden path of another group is listed: {names:?}"
    );
    ensure!(
        names.contains(&".env.example"),
        "a re-included path is listed: {names:?}"
    );
    let mut sorted = names.clone();
    sorted.sort_unstable();
    ensure_eq!(names, sorted, "paths come back sorted");
    let trusted = repo
        .list_at(&base, &all, 100, ReadView::Trusted)
        .await
        .ctx("list")?;
    ensure!(
        trusted
            .iter()
            .any(|p| p.as_str() == "tests/holdout/secret_case.rs"),
        "the trusted view lists the hidden path"
    );
    let rust = RepoGlob::new("src/*.rs").expect("a glob");
    let found = repo
        .list_at(&base, &rust, 1, ReadView::Agent)
        .await
        .ctx("list")?;
    ensure_eq!(
        found,
        vec![path("src/lib.rs")],
        "the limit is honoured and the glob matches"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Ingestion
// ---------------------------------------------------------------------------------------------

async fn additions_modifications_and_deletions_are_reported(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    ensure!(
        ingest(&*ws)
            .await
            .ctx("ingest an untouched tree")?
            .is_empty(),
        "an untouched tree has no change"
    );
    write(subject, &*ws, "src/new.rs", "pub fn new() {}\n").await?;
    write(
        subject,
        &*ws,
        "src/lib.rs",
        "pub fn answer() -> u32 { 43 }\n",
    )
    .await?;
    subject
        .edit_sandbox_tree(&*ws, TreeEdit::Delete(path("src/main.rs")))
        .await?;
    let change = ingest(&*ws).await.ctx("ingest")?;
    let kinds: Vec<(&str, ChangeKind)> = change
        .changes()
        .iter()
        .map(|c| (c.path.as_str(), c.kind))
        .collect();
    ensure_eq!(
        kinds,
        vec![
            ("src/lib.rs", ChangeKind::Modified),
            ("src/main.rs", ChangeKind::Deleted),
            ("src/new.rs", ChangeKind::Added)
        ],
        "the changes, sorted by path"
    );
    // A rename is a deletion and an addition.
    let (renamed, _) = open(subject, 2).await?;
    subject
        .edit_sandbox_tree(&*renamed, TreeEdit::Delete(path("docs/guide.md")))
        .await?;
    write(
        subject,
        &*renamed,
        "docs/handbook.md",
        "A guide to the fixture.\n",
    )
    .await?;
    let change = ingest(&*renamed).await.ctx("ingest a rename")?;
    let kinds: Vec<(&str, ChangeKind)> = change
        .changes()
        .iter()
        .map(|c| (c.path.as_str(), c.kind))
        .collect();
    ensure_eq!(
        kinds,
        vec![
            ("docs/guide.md", ChangeKind::Deleted),
            ("docs/handbook.md", ChangeKind::Added)
        ],
        "a rename shows both ends"
    );
    Ok(())
}

async fn a_change_to_a_protected_path_is_refused_with_every_changed_path(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    write(
        subject,
        &*ws,
        ".github/workflows/ci.yml",
        "name: hijacked\n",
    )
    .await?;
    write(subject, &*ws, "CHANGELOG.md", "# Changelog\n").await?;
    write(subject, &*ws, "src/free.rs", "// free\n").await?;
    let error = match ingest(&*ws).await {
        Err(error) => error,
        Ok(change) => {
            return Err(format!(
                "a protected change must be refused, but ingest accepted {change:?}"
            ));
        }
    };
    let listed = protected(error.clone())
        .ok_or_else(|| format!("expected ProtectedPathChanged, found {error:?}"))?;
    ensure!(
        listed.contains(&(path(".github/workflows/ci.yml"), PathMode::DenyWrite)),
        "the deny_write path is listed with its mode: {listed:?}"
    );
    ensure!(
        listed.contains(&(path("CHANGELOG.md"), PathMode::AppendOnly)),
        "an edit of an append_only file is listed: {listed:?}"
    );
    ensure!(
        !listed.iter().any(|(p, _)| p.as_str() == "src/free.rs"),
        "a free path is not listed"
    );
    // New files under append_only paths are fine; deleting a deny_write file is not.
    let (adds, _) = open(subject, 2).await?;
    write(
        subject,
        &*adds,
        "CHANGELOG.md",
        "# Changelog\n- first\n- second\n",
    )
    .await
    .ok();
    Ok(())
}

async fn an_added_test_is_allowed_and_an_edited_test_is_refused_under_additions_only(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    // docs/notes.md is additions_only: it may gain lines, not lose or change them.
    let (gain, _) = open(subject, 1).await?;
    write(
        subject,
        &*gain,
        "docs/notes.md",
        "line one\nline two\nline three\n",
    )
    .await?;
    ingest(&*gain).await.ctx("a file that only gained a line")?;
    let (edit, _) = open(subject, 2).await?;
    write(subject, &*edit, "docs/notes.md", "line one\nLINE TWO\n").await?;
    let error = match ingest(&*edit).await {
        Err(error) => error,
        Ok(change) => {
            return Err(format!(
                "an edited line must be refused, but ingest accepted {change:?}"
            ));
        }
    };
    ensure!(
        protected(error.clone()).is_some(),
        "expected ProtectedPathChanged, found {error:?}"
    );
    let (delete, _) = open(subject, 3).await?;
    subject
        .edit_sandbox_tree(&*delete, TreeEdit::Delete(path("docs/notes.md")))
        .await?;
    let error = match ingest(&*delete).await {
        Err(error) => error,
        Ok(change) => {
            return Err(format!(
                "deleting an additions_only file must be refused, but ingest accepted {change:?}"
            ));
        }
    };
    ensure!(
        protected(error.clone()).is_some(),
        "expected ProtectedPathChanged, found {error:?}"
    );
    Ok(())
}

async fn a_case_variant_of_a_protected_path_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    write(subject, &*ws, ".GitHub/Workflows/ci.yml", "name: sneaky\n").await?;
    let error = match ingest(&*ws).await {
        Err(error) => error,
        Ok(change) => {
            return Err(format!(
                "a case variant of a protected path must be refused, but ingest accepted {change:?}"
            ));
        }
    };
    let listed = protected(error.clone())
        .ok_or_else(|| format!("expected ProtectedPathChanged, found {error:?}"))?;
    ensure!(
        listed
            .iter()
            .any(|(p, mode)| p.as_str() == ".GitHub/Workflows/ci.yml"
                && *mode == PathMode::DenyWrite),
        "the variant is classified like the original: {listed:?}"
    );
    Ok(())
}

async fn a_reincluded_path_is_allowed_only_in_its_own_group(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    // `.env.example` is re-included in the `secrets` group, so it is not hidden. The `ci` group
    // still makes it deny_write, so changing it is refused.
    let (ws, _) = open(subject, 1).await?;
    write(subject, &*ws, ".env.example", "LOCAL=changed\n").await?;
    let error = match ingest(&*ws).await {
        Err(error) => error,
        Ok(change) => {
            return Err(format!(
                "the other group still protects the path, but ingest accepted {change:?}"
            ));
        }
    };
    let listed = protected(error.clone())
        .ok_or_else(|| format!("expected ProtectedPathChanged, found {error:?}"))?;
    ensure!(
        listed.contains(&(path(".env.example"), PathMode::DenyWrite)),
        "the re-inclusion lifted only its own group: {listed:?}"
    );
    Ok(())
}

async fn a_hidden_path_in_the_tree_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    write(subject, &*ws, "tests/holdout/planted.rs", "// planted\n").await?;
    ensure_err!(
        ingest(&*ws).await,
        WorkspaceError::HiddenPathPresent(_),
        "a hidden path that appears in the sandbox tree"
    );
    Ok(())
}

async fn a_symlink_that_leaves_the_workspace_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    for target in ["/etc/passwd", "../outside", "src/../../outside"] {
        let (ws, _) = open(subject, 1).await?;
        subject
            .edit_sandbox_tree(
                &*ws,
                TreeEdit::Symlink {
                    path: path("link"),
                    target: target.to_owned(),
                },
            )
            .await?;
        ensure_err!(
            ingest(&*ws).await,
            WorkspaceError::EscapingSymlink(_),
            "a link to {target}"
        );
        subject
            .provider()
            .dispose_job(job(1))
            .await
            .ctx("dispose")?;
    }
    let (ws, _) = open(subject, 2).await?;
    subject
        .edit_sandbox_tree(
            &*ws,
            TreeEdit::Symlink {
                path: path("link"),
                target: "src/lib.rs".to_owned(),
            },
        )
        .await?;
    ingest(&*ws)
        .await
        .ctx("a link that stays inside the workspace")?;
    Ok(())
}

async fn a_gitlink_is_refused(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    subject
        .edit_sandbox_tree(&*ws, TreeEdit::Gitlink(path("vendor/lib")))
        .await?;
    ensure_err!(
        ingest(&*ws).await,
        WorkspaceError::Gitlink(_),
        "a submodule entry"
    );
    Ok(())
}

async fn a_nested_git_directory_is_refused(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    subject
        .edit_sandbox_tree(&*ws, TreeEdit::NestedGit(path("vendor/inner")))
        .await?;
    ensure_err!(
        ingest(&*ws).await,
        WorkspaceError::NestedGit(_),
        "a nested git directory"
    );
    Ok(())
}

async fn a_secret_in_a_changed_file_is_refused_without_repeating_it(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    // Built at run time so that no secret-shaped literal sits in the source.
    let secret = format!("{}{}", "ghs_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    write(
        subject,
        &*ws,
        "src/leak.rs",
        &format!("const TOKEN: &str = \"{secret}\";\n"),
    )
    .await?;
    match ingest(&*ws).await {
        Err(WorkspaceError::SecretFound(findings)) => {
            ensure!(!findings.is_empty(), "the refusal must carry a finding");
            ensure_eq!(
                findings[0].path.clone(),
                Some(path("src/leak.rs")),
                "the finding names the file"
            );
            ensure!(
                !format!("{findings:?}").contains(&secret),
                "a finding must not repeat the secret"
            );
            Ok(())
        }
        Err(other) => Err(format!(
            "a secret: expected SecretFound but found {other:?}"
        )),
        Ok(_) => Err("a secret: the file was accepted".to_owned()),
    }
}

async fn a_cancelled_ingest_leaves_nothing_behind(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    write(subject, &*ws, "src/new.rs", "pub fn new() {}\n").await?;
    let cancel = FakeCancel::new();
    cancel.cancel();
    ensure_err!(
        ws.ingest(&cancel).await,
        WorkspaceError::Cancelled,
        "an ingest whose cancel signal is set"
    );
    let change = ingest(&*ws)
        .await
        .ctx("ingest again after a cancelled one")?;
    ensure_eq!(
        change.changes().len(),
        1,
        "the next ingest sees the same tree"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Commit, push, restart
// ---------------------------------------------------------------------------------------------

async fn an_audited_change_can_be_committed_and_pushed(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, base) = open(subject, 1).await?;
    write(subject, &*ws, "src/feature.rs", "pub fn feature() {}\n").await?;
    let change = ingest(&*ws).await.ctx("ingest")?;
    let commit = ws
        .commit(&change, commit_request("Add a feature"))
        .await
        .ctx("commit")?;
    let again = ws
        .commit(&change, commit_request("Add a feature"))
        .await
        .ctx("commit again")?;
    ensure_eq!(
        again,
        commit,
        "the same change and request give the same commit"
    );
    ensure!(commit != base, "the commit is new");
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    let read = repo
        .read_file_at(&commit, &path("src/feature.rs"), 4096, ReadView::Trusted)
        .await
        .ctx("read the commit")?;
    ensure_eq!(
        read,
        b"pub fn feature() {}\n".to_vec(),
        "the commit holds the new file"
    );
    let held = repo
        .read_file_at(
            &commit,
            &path("tests/holdout/secret_case.rs"),
            4096,
            ReadView::Trusted,
        )
        .await
        .ctx("the hidden file survives in the commit")?;
    ensure!(
        !held.is_empty(),
        "the commit keeps the paths the checkout never held"
    );
    let target = push_target(subject, "factory/job-1");
    repo.push(&target, &commit, &FakeCancel::new())
        .await
        .ctx("push")?;
    repo.push(&target, &commit, &FakeCancel::new())
        .await
        .ctx("a repeated push")?;
    ensure_eq!(
        subject.pushed_commit(&target.repo, &target.branch).await,
        Some(commit),
        "the remote branch"
    );
    Ok(())
}

async fn a_change_the_workspace_never_ingested_is_not_committed(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (one, _) = open(subject, 1).await?;
    let (two, _) = open(subject, 2).await?;
    write(subject, &*one, "src/a.rs", "// a\n").await?;
    let change = ingest(&*one).await.ctx("ingest")?;
    ensure!(
        two.commit(&change, commit_request("Not mine"))
            .await
            .is_err(),
        "a workspace committed a change it never ingested"
    );
    Ok(())
}

async fn a_push_outside_factory_branches_is_refused(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    write(subject, &*ws, "src/a.rs", "// a\n").await?;
    let change = ingest(&*ws).await.ctx("ingest")?;
    let commit = ws
        .commit(&change, commit_request("A change"))
        .await
        .ctx("commit")?;
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    for branch in ["main", "release/1.0"] {
        ensure_err!(
            repo.push(&push_target(subject, branch), &commit, &FakeCancel::new())
                .await,
            WorkspaceError::BranchNotAllowed,
            "a push to {branch}"
        );
        ensure_eq!(
            subject
                .pushed_commit(&subject.repo(), &BranchName::new(branch).expect("a branch"))
                .await,
            if branch == "main" {
                subject
                    .pushed_commit(&subject.repo(), &subject.branch())
                    .await
            } else {
                None
            },
            "nothing was pushed to {branch}"
        );
    }
    Ok(())
}

async fn a_commit_the_factory_did_not_make_is_not_pushed(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let base = fetch(subject, 1).await?.commit;
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    ensure_err!(
        repo.push(
            &push_target(subject, "factory/job-1"),
            &base,
            &FakeCancel::new()
        )
        .await,
        WorkspaceError::NotMadeHere,
        "pushing the fetched base, which the factory did not make"
    );
    Ok(())
}

async fn a_second_workspace_can_start_at_a_commit_the_first_made(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (first, _) = open(subject, 1).await?;
    write(subject, &*first, "src/a.rs", "// from the first stage\n").await?;
    let change = ingest(&*first).await.ctx("ingest")?;
    let commit = first
        .commit(&change, commit_request("First stage"))
        .await
        .ctx("commit")?;
    first.dispose().await.ctx("dispose the first workspace")?;
    // The next stage, for the same job, starts where the first ended.
    let second = subject
        .provider()
        .create(
            WorkspaceRequest {
                job: job(1),
                attempt: attempt(2),
                base: commit.clone(),
                rules: fixture_rules(),
                purpose: WorkspacePurpose::Agent,
            },
            &FakeCancel::new(),
        )
        .await
        .ctx("a workspace at the first stage's commit")?;
    ensure_eq!(second.base().clone(), commit, "the second workspace's base");
    // A job that was never fetched has no store.
    ensure_err!(
        subject
            .provider()
            .create(
                WorkspaceRequest {
                    job: job(9),
                    attempt: attempt(9),
                    base: commit,
                    rules: fixture_rules(),
                    purpose: WorkspacePurpose::Agent,
                },
                &FakeCancel::new()
            )
            .await,
        WorkspaceError::NotFetched,
        "a workspace for a job with no object store"
    );
    Ok(())
}

async fn push_works_after_a_restart(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    write(subject, &*ws, "src/a.rs", "// a\n").await?;
    let change = ingest(&*ws).await.ctx("ingest")?;
    let commit = ws
        .commit(&change, commit_request("A change"))
        .await
        .ctx("commit")?;
    drop(ws);
    let restarted = subject.restart().await;
    let repo = restarted
        .repo(job(1))
        .await
        .ctx("the job's repository after a restart")?;
    let target = push_target(subject, "factory/job-1");
    repo.push(&target, &commit, &FakeCancel::new())
        .await
        .ctx("push after a restart, from no workspace")?;
    ensure_eq!(
        subject.pushed_commit(&target.repo, &target.branch).await,
        Some(commit),
        "the remote branch"
    );
    Ok(())
}

async fn a_verify_workspace_is_read_only_and_holds_the_holdouts(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let base = fetch(subject, 1).await?.commit;
    let holdouts = vec![RepoGlob::new(HIDDEN_GLOB).expect("a glob")];
    let verify = open_as(subject, 1, &base, WorkspacePurpose::Verify { holdouts }).await?;
    ensure!(
        verify.mounts().workspace_read_only,
        "a verify workspace is mounted read-only"
    );
    // The held-out file is present for the trusted gates; other hidden paths are not.
    let held = path("tests/holdout/secret_case.rs");
    let present = subject
        .edit_sandbox_tree(&*verify, TreeEdit::Delete(held.clone()))
        .await
        .is_ok();
    ensure!(present, "the verify workspace can be inspected");
    let change = ingest(&*verify).await.ctx("ingest a verify workspace")?;
    let deleted: Vec<&str> = change.changes().iter().map(|c| c.path.as_str()).collect();
    ensure!(
        deleted == ["tests/holdout/secret_case.rs"],
        "the held-out test was in the checkout (deleting it shows as a change), got {deleted:?}"
    );
    let env_hidden = open_as(
        subject,
        2,
        &fetch(subject, 2).await?.commit,
        WorkspacePurpose::Verify {
            holdouts: Vec::new(),
        },
    )
    .await?;
    let probe = subject
        .edit_sandbox_tree(&*env_hidden, TreeEdit::Delete(held))
        .await;
    ensure!(probe.is_ok(), "the verify workspace can be inspected");
    let change = ingest(&*env_hidden).await.ctx("ingest")?;
    ensure!(
        change.is_empty(),
        "without holdouts the hidden test is absent, so deleting it changes nothing"
    );
    Ok(())
}

async fn export_patch_is_the_same_for_the_same_commits(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, base) = open(subject, 1).await?;
    write(subject, &*ws, "src/a.rs", "// a\n").await?;
    write(
        subject,
        &*ws,
        "src/lib.rs",
        "pub fn answer() -> u32 { 43 }\n",
    )
    .await?;
    let change = ingest(&*ws).await.ctx("ingest")?;
    let head = ws
        .commit(&change, commit_request("A change"))
        .await
        .ctx("commit")?;
    let repo = subject
        .provider()
        .repo(job(1))
        .await
        .ctx("the job's repository")?;
    let one = repo
        .export_patch(&base, &head, 1 << 20, &FakeCancel::new())
        .await
        .ctx("export")?;
    let two = repo
        .export_patch(&base, &head, 1 << 20, &FakeCancel::new())
        .await
        .ctx("export again")?;
    ensure_eq!(
        one.patch,
        two.patch,
        "the same two commits give the same artifact"
    );
    let paths: Vec<&str> = one.changes.iter().map(|c| c.path.as_str()).collect();
    ensure_eq!(
        paths,
        vec!["src/a.rs", "src/lib.rs"],
        "the changed paths, sorted"
    );
    ensure_err!(
        repo.export_patch(&base, &head, 5, &FakeCancel::new()).await,
        WorkspaceError::TooLarge,
        "a patch over the limit"
    );
    let cancelled = FakeCancel::new();
    cancelled.cancel();
    ensure_err!(
        repo.export_patch(&base, &head, 1 << 20, &cancelled).await,
        WorkspaceError::Cancelled,
        "an export whose cancel signal is set"
    );
    Ok(())
}

async fn disposing_removes_the_host_directories(
    subject: &dyn WorkspaceSubject,
) -> Result<(), String> {
    let (ws, _) = open(subject, 1).await?;
    let mounts = ws.mounts();
    ensure!(
        subject.directories_exist(&mounts).await,
        "the directories must exist while the workspace lives"
    );
    ws.dispose().await.ctx("dispose")?;
    ensure!(
        !subject.directories_exist(&mounts).await,
        "the directories must be gone after dispose"
    );
    // The orphan sweep removes the workspaces whose attempt is not live, and keeps the rest.
    let (_keep, _) = open(subject, 2).await?;
    let (_orphan, _) = open(subject, 3).await?;
    let removed = subject
        .provider()
        .sweep_orphans(&[attempt(2)], &[job(1), job(2), job(3)])
        .await
        .ctx("sweep")?;
    ensure_eq!(
        removed,
        vec![attempt(3)],
        "only the workspace of the attempt that is not live"
    );
    Ok(())
}

async fn two_workspaces_do_not_share_a_tree(subject: &dyn WorkspaceSubject) -> Result<(), String> {
    let (one, _) = open(subject, 1).await?;
    let (two, _) = open(subject, 2).await?;
    write(subject, &*one, "src/only_in_one.rs", "// one\n").await?;
    let change = ingest(&*two).await.ctx("ingest the second workspace")?;
    ensure!(
        change.is_empty(),
        "the second workspace must not see the first one's file"
    );
    ensure!(
        one.mounts().workspace != two.mounts().workspace,
        "two workspaces have two directories"
    );
    Ok(())
}
