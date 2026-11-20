//! Behaviour of the adapter that the contract suite does not name: restart, the protected-path
//! evaluation of renames and type changes, the path rules, the patch, and the views.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;

use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::TenantId;
use factory_domain::scope::TenantScope;
use factory_ports::artifact::ArtifactStore;
use factory_ports::paths::{PathMode, RepoGlob, RepoPath};
use factory_ports::workspace::{
    ChangeKind, ReadView, Workspace, WorkspaceError, WorkspaceProvider, WorkspacePurpose,
    WorkspaceRequest,
};
use factory_sandbox::SystemProcessRunner;
use factory_testkit::clock::FakeCancel;
use factory_testkit::contracts::workspace::{HIDDEN_GLOB, fixture_rules};

use crate::harness::{provider_over, settings};
use crate::support;
use crate::world::{World, commit_request};

fn path(text: &str) -> RepoPath {
    RepoPath::new(text).expect("a valid path")
}

/// What `ingest` refused with, as `(path, mode)` pairs. Fails the test for any other outcome.
async fn violations(ws: &dyn Workspace) -> Vec<(String, PathMode)> {
    match ws.ingest(&FakeCancel::new()).await {
        Err(WorkspaceError::ProtectedPathChanged(list)) => list
            .into_iter()
            .map(|v| (v.path.as_str().to_owned(), v.mode))
            .collect(),
        other => panic!("expected ProtectedPathChanged, got {other:?}"),
    }
}

async fn stored_bytes(world: &World, reference: &ArtifactRef) -> Vec<u8> {
    let tenant = TenantScope::new(
        TenantId::parse("00000000-0000-7000-8000-00000000000a").expect("a tenant id"),
    );
    world.artifacts.grant(tenant.tenant_id(), &reference.sha256);
    world
        .artifacts
        .get(&tenant, reference)
        .await
        .expect("the stored patch")
}

// ---- restart ------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn restart_keeps_commits_and_a_new_provider_can_push_and_start_at_them() {
    let world = World::new().await;
    let (ws, base) = world.open(1).await;
    fs::write(
        ws.mounts().workspace.join("src/new.rs"),
        "pub fn new() {}\n",
    )
    .expect("a file");
    let change = ws.ingest(&FakeCancel::new()).await.expect("ingest");
    let commit = ws
        .commit(&change, commit_request("A change"))
        .await
        .expect("commit");
    drop(ws);

    // A new provider value over the same host directory: what a process restart leaves.
    let restarted = provider_over(
        settings(&world.root, &world.remote),
        Arc::new(SystemProcessRunner::new()),
        Arc::clone(&world.artifacts),
        fixture_rules(),
    );
    let repo = restarted.repo(support::job(1)).await.expect("the store");
    let target = world.push_target("factory/job-1");
    repo.push(&target, &commit, &FakeCancel::new())
        .await
        .expect("push after a restart, from no workspace");
    assert_eq!(
        world.remote.branch_tip("factory/job-1").await,
        Some(commit.clone())
    );

    // A second workspace, from the new provider, starts at the commit the first one made.
    let second = restarted
        .create(
            WorkspaceRequest {
                job: support::job(1),
                attempt: support::attempt(2),
                base: commit.clone(),
                protected_base: None,
                rules: fixture_rules(),
                purpose: WorkspacePurpose::Agent,
            },
            &FakeCancel::new(),
        )
        .await
        .expect("a workspace at the first one's commit");
    assert_eq!(second.base(), &commit);
    assert!(second.mounts().workspace.join("src/new.rs").exists());

    // A commit the factory did not make is refused, whoever asks.
    let refused = repo.push(&target, &base, &FakeCancel::new()).await;
    assert_eq!(refused, Err(WorkspaceError::NotMadeHere));
}

// ---- the evaluation of renames, mode changes and type changes --------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rename_counts_as_two_paths_and_a_mode_or_type_change_is_a_modification() {
    let world = World::new().await;

    // The old end of a rename meets the rule: a protected file moved away.
    let (ws, _) = world.open(1).await;
    let dir = ws.mounts().workspace;
    fs::rename(
        dir.join(".github/workflows/ci.yml"),
        dir.join("ci-moved.yml"),
    )
    .expect("rename");
    let found = violations(&ws).await;
    assert_eq!(
        found,
        vec![(".github/workflows/ci.yml".to_owned(), PathMode::DenyWrite)],
        "the deletion end is refused; the free new name is not"
    );

    // The new end of a rename meets the rule: a free file moved into a protected directory.
    let (ws, _) = world.open(2).await;
    let dir = ws.mounts().workspace;
    fs::rename(dir.join("docs/guide.md"), dir.join(".github/guide.md")).expect("rename");
    assert_eq!(
        violations(&ws).await,
        vec![(".github/guide.md".to_owned(), PathMode::DenyWrite)]
    );

    // A mode change of an append-only file is a modification.
    let (ws, _) = world.open(3).await;
    let file = ws.mounts().workspace.join("CHANGELOG.md");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(
        violations(&ws).await,
        vec![("CHANGELOG.md".to_owned(), PathMode::AppendOnly)]
    );

    // A type change of an additions-only file (a file that becomes a link) is a modification,
    // although its lines are unchanged.
    let (ws, _) = world.open(4).await;
    let file = ws.mounts().workspace.join("docs/notes.md");
    fs::remove_file(&file).expect("remove");
    symlink("../README.md", &file).expect("link");
    assert_eq!(
        violations(&ws).await,
        vec![("docs/notes.md".to_owned(), PathMode::AdditionsOnly)]
    );

    // A rename of a free file is fine and shows both ends.
    let (ws, _) = world.open(5).await;
    let dir = ws.mounts().workspace;
    fs::rename(dir.join("docs/guide.md"), dir.join("docs/handbook.md")).expect("rename");
    let change = ws.ingest(&FakeCancel::new()).await.expect("ingest");
    let listed: Vec<(&str, ChangeKind)> = change
        .changes()
        .iter()
        .map(|c| (c.path.as_str(), c.kind))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("docs/guide.md", ChangeKind::Deleted),
            ("docs/handbook.md", ChangeKind::Added)
        ]
    );
}

// ---- the path rules ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn path_rules_follow_the_policy() {
    let rules = fixture_rules();
    // A case variant is the same protected path.
    assert_eq!(
        rules.classify(&path(".GitHub/Workflows/ci.yml")),
        Some(PathMode::DenyWrite)
    );
    // A composed and a decomposed spelling are the same name.
    let rules_with_accent = factory_ports::paths::PathRules::new(vec![(
        "g".to_owned(),
        factory_ports::paths::PathRule::Mode {
            glob: RepoGlob::new("caf\u{e9}/**").expect("glob"),
            mode: PathMode::DenyWrite,
        },
    )]);
    assert_eq!(
        rules_with_accent.classify(&path("cafe\u{301}/menu.txt")),
        Some(PathMode::DenyWrite)
    );
    // The names of the git directory are not paths at all: a Unicode-ignorable character, a
    // trailing dot or space, and the 8.3 short name all fold to it.
    for alias in [
        ".git",
        ".GIT",
        ".g\u{200c}it",
        ".git\u{200d}/config",
        ".git. /config",
        "GIT~1/config",
        "sub/.Git/hooks/pre-commit",
    ] {
        assert!(RepoPath::new(alias).is_err(), "{alias:?} must be refused");
    }
    assert!(RepoPath::new(".gitignore").is_ok());
    assert!(RepoPath::new(".github/workflows/ci.yml").is_ok());

    // The adapter refuses the same aliases when a sandbox writes them.
    let world = World::new().await;
    for (n, alias) in [(1u128, ".git\u{200d}"), (2, "GIT~1"), (3, ".GIT")] {
        let (ws, _) = world.open(n).await;
        let nested = ws.mounts().workspace.join("vendor").join(alias);
        fs::create_dir_all(&nested).expect("a nested directory");
        fs::write(nested.join("config"), "[core]\n").expect("a file");
        assert!(
            matches!(
                ws.ingest(&FakeCancel::new()).await,
                Err(WorkspaceError::NestedGit(_))
            ),
            "{alias:?}"
        );
    }

    // Additions only: an added line is allowed, an edited line is refused, and a new file in the
    // same directory is free.
    let (ws, _) = world.open(4).await;
    let dir = ws.mounts().workspace;
    fs::write(
        dir.join("docs/notes.md"),
        "line one\nline two\nline three\n",
    )
    .expect("gain");
    fs::write(dir.join("docs/new-page.md"), "new\n").expect("a new page");
    ws.ingest(&FakeCancel::new()).await.expect("allowed");
    fs::write(dir.join("docs/notes.md"), "line one\nLINE TWO\n").expect("edit");
    assert_eq!(
        violations(&ws).await,
        vec![("docs/notes.md".to_owned(), PathMode::AdditionsOnly)]
    );

    // A re-inclusion lifts only its own group: `.env.example` is visible, and the group that
    // protects it still refuses an edit. `.env` stays hidden and is not in the checkout.
    let (ws, _) = world.open(5).await;
    let dir = ws.mounts().workspace;
    assert!(dir.join(".env.example").exists());
    assert!(!dir.join(".env").exists());
    fs::write(dir.join(".env.example"), "LOCAL=changed\n").expect("edit");
    assert_eq!(
        violations(&ws).await,
        vec![(".env.example".to_owned(), PathMode::DenyWrite)]
    );
}

// ---- protected overlays and hidden paths (NT-SBX-11, NT-GATE-08), the host side ------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_11_the_mount_points_exist_and_a_hidden_write_fails_the_job() {
    let world = World::new().await;
    let (ws, _) = world.open(1).await;
    let mounts = ws.mounts();
    // Every overlay is an existing regular file in the checkout, so the runtime can mount over it.
    assert!(!mounts.protected_overlays.is_empty());
    for overlay in &mounts.protected_overlays {
        let meta = fs::symlink_metadata(mounts.workspace.join(overlay.as_str())).expect("exists");
        assert!(meta.file_type().is_file(), "{overlay}");
    }
    // The `.git` mask has its mount point: an empty regular file.
    let mask = fs::symlink_metadata(mounts.workspace.join(".git")).expect("the mask file");
    assert!(mask.file_type().is_file() && mask.len() == 0);
    assert!(mounts.git_masked);
    // The hidden paths are not in the checkout.
    assert!(!mounts.workspace.join("tests/holdout").exists());
    assert!(!mounts.workspace.join(".env").exists());

    // A file created at a hidden path fails the job and is named.
    fs::create_dir_all(mounts.workspace.join("tests/holdout")).expect("dir");
    fs::write(mounts.workspace.join("tests/holdout/planted.rs"), "// x\n").expect("file");
    match ws.ingest(&FakeCancel::new()).await {
        Err(WorkspaceError::HiddenPathPresent(found)) => {
            assert_eq!(found.as_str(), "tests/holdout/planted.rs");
        }
        other => panic!("expected HiddenPathPresent, got {other:?}"),
    }
    let report = ws.last_audit_report().expect("a report");
    assert_eq!(
        report.reasons.len(),
        1,
        "the reason is kept: {:?}",
        report.reasons
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_gate_08_the_holdout_is_invisible_to_the_agent_and_present_in_verify() {
    let world = World::new().await;
    let base = world.fetch(1).await;
    let agent = world
        .open_at(1, 1, &base, WorkspacePurpose::Agent)
        .await
        .mounts();
    let verify = world
        .open_at(
            1,
            2,
            &base,
            WorkspacePurpose::Verify {
                holdouts: vec![RepoGlob::new(HIDDEN_GLOB).expect("a glob")],
            },
        )
        .await
        .mounts();
    let held = "tests/holdout/secret_case.rs";
    assert!(!agent.workspace.join(held).exists(), "absent for the agent");
    assert!(
        fs::read_to_string(verify.workspace.join(held))
            .expect("present in verify")
            .contains("held out"),
    );
    assert!(verify.workspace_read_only && !agent.workspace_read_only);
    // Not found through the agent view of the store, and no listing shows it.
    let repo = world.provider.repo(support::job(1)).await.expect("repo");
    assert_eq!(
        repo.read_file_at(&base, &path(held), 4096, ReadView::Agent)
            .await,
        Err(WorkspaceError::PathNotFound(path(held)))
    );
    let listed = repo
        .list_at(
            &base,
            &RepoGlob::new("**").expect("glob"),
            100,
            ReadView::Agent,
        )
        .await
        .expect("list");
    assert!(listed.iter().all(|p| p.as_str() != held));
    // Nothing in the agent checkout holds the text, anywhere.
    let mut stack = vec![agent.workspace.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir").flatten() {
            let kind = entry.file_type().expect("type");
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                let text = fs::read(entry.path()).expect("read");
                assert!(
                    !String::from_utf8_lossy(&text).contains("held out from the sandbox"),
                    "{}",
                    entry.path().display()
                );
            }
        }
    }
}

// ---- the patch and the views ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn patch_and_views() {
    let world = World::new().await;
    let (ws, base) = world.open(1).await;
    let dir = ws.mounts().workspace;
    // A binary file with a NUL byte and a byte that is not UTF-8, a text edit, and a rename.
    fs::write(dir.join("logo.bin"), [0u8, 159, 146, 150, 0, 255, b'\n']).expect("binary");
    fs::write(dir.join("src/lib.rs"), "pub fn answer() -> u32 { 43 }\n").expect("edit");
    fs::rename(dir.join("docs/guide.md"), dir.join("docs/handbook.md")).expect("rename");
    let change = ws.ingest(&FakeCancel::new()).await.expect("ingest");
    let head = ws
        .commit(&change, commit_request("A mixed change"))
        .await
        .expect("commit");

    let repo = world.provider.repo(support::job(1)).await.expect("repo");
    let one = repo
        .export_patch(&base, &head, 1 << 20, &FakeCancel::new())
        .await
        .expect("export");
    let two = repo
        .export_patch(&base, &head, 1 << 20, &FakeCancel::new())
        .await
        .expect("export again");
    assert_eq!(one.patch, two.patch, "the same artifact");
    let first = stored_bytes(&world, &one.patch).await;
    let second = stored_bytes(&world, &two.patch).await;
    assert_eq!(first, second, "byte for byte the same");
    let text = String::from_utf8_lossy(&first);
    assert!(text.contains("GIT binary patch"), "binary safe: {text}");
    assert!(text.contains("+pub fn answer() -> u32 { 43 }"));
    assert!(!text.contains('\u{1b}'), "no color codes");
    let paths: Vec<(&str, ChangeKind)> = one
        .changes
        .iter()
        .map(|c| (c.path.as_str(), c.kind))
        .collect();
    assert_eq!(
        paths,
        vec![
            ("docs/guide.md", ChangeKind::Deleted),
            ("docs/handbook.md", ChangeKind::Added),
            ("logo.bin", ChangeKind::Added),
            ("src/lib.rs", ChangeKind::Modified)
        ],
        "a rename is two paths, sorted"
    );
    // The patch applies: the commit read back holds the binary bytes exactly.
    let read = repo
        .read_file_at(&head, &path("logo.bin"), 1024, ReadView::Trusted)
        .await
        .expect("read");
    assert_eq!(read, vec![0u8, 159, 146, 150, 0, 255, b'\n']);

    // The views: a verify workspace is read-only and holds the holdouts; the agent view of a
    // hidden path is not found.
    let verify = world
        .open_at(
            1,
            9,
            &head,
            WorkspacePurpose::Verify {
                holdouts: vec![RepoGlob::new(HIDDEN_GLOB).expect("glob")],
            },
        )
        .await;
    assert!(verify.mounts().workspace_read_only);
    assert!(
        verify
            .mounts()
            .workspace
            .join("tests/holdout/secret_case.rs")
            .exists()
    );
    assert!(verify.mounts().protected_overlays.is_empty());
    assert_eq!(
        repo.read_file_at(
            &head,
            &path("tests/holdout/secret_case.rs"),
            4096,
            ReadView::Agent
        )
        .await,
        Err(WorkspaceError::PathNotFound(path(
            "tests/holdout/secret_case.rs"
        )))
    );
    // Reads are bounded and a commit the store lacks is unknown.
    assert_eq!(
        repo.read_file_at(&head, &path("src/lib.rs"), 3, ReadView::Agent)
            .await,
        Err(WorkspaceError::TooLarge)
    );
}
