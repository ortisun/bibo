//! The workspace with a real sandbox (NT-SBX-09, NT-SBX-10, NT-SBX-11, NT-GATE-08). A container
//! built from the adapter's own mounts does the attacking, the container is removed, and the
//! adapter audits what it left.
//!
//! Every test here needs Docker and the images of `infra/sandbox-images/images.json`. When either
//! is missing the test panics with a message that starts `BLOCKED:`.
//!
//! What this host's file sharing lets a container plant depends on the platform. A command that
//! fails because the platform refuses it (a FIFO on a shared directory, for example) is printed
//! with the word `PLATFORM` and the test then requires the audit for the entries that were
//! planted. The host-side tests plant every kind of entry directly, so no kind goes untested.

use std::fs;
use std::time::Duration;

use factory_ports::sandbox::{SandboxProfile, SandboxSession, TeardownReason};
use factory_ports::workspace::{Workspace, WorkspaceError, WorkspacePurpose};
use factory_sandbox::workspace::{AuditKind, GitWorkspace};
use factory_testkit::clock::FakeCancel;
use factory_testkit::contracts::workspace::HIDDEN_GLOB;
use factory_testkit::fx::canary::{CanaryKind, CanarySet, Sweeper};

use crate::lab::Lab;
use crate::support;
use crate::world::{Options, World};

const WALL: Duration = Duration::from_secs(120);

/// Docker hands out the addresses of per-job networks from a small pool. The container tests lock
/// a file for it across processes; within one process (`cargo test` runs the tests of a target as
/// threads) these tests take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Runs one command in the sandbox and returns the exit code and the text it printed.
async fn run(lab: &Lab, session: &mut dyn SandboxSession, words: &[&str]) -> (Option<i32>, String) {
    let result = lab.run(session, words).await;
    let (out, err) = lab.text(&result).await;
    (result.exit_code, format!("{out}{err}"))
}

fn kinds(ws: &GitWorkspace) -> Vec<(AuditKind, String)> {
    ws.last_audit_report()
        .expect("an audit report")
        .reasons
        .into_iter()
        .map(|r| (r.kind, r.path.as_str().to_owned()))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_09_a_real_sandbox_plants_hostile_entries_and_the_audit_rejects_them() {
    let _one_at_a_time = SERIAL.lock().await;
    let lab = Lab::new(true);
    let world = World::with(Options::default()).await;
    let (ws, _) = world.open(1).await;
    let mounts = ws.mounts();
    let canaries = CanarySet::generate();
    let canary = canaries
        .get(CanaryKind::SecondTenantString)
        .value()
        .to_owned();
    let host_file = world.scratch.path().join("host-canary.txt");
    fs::write(&host_file, format!("host only: {canary}\n")).expect("a host file");

    let spec = support::spec(
        SandboxProfile::Agent,
        &lab.catalog(),
        &mounts,
        support::attempt(1),
        WALL,
    );
    let mut session = lab.create(spec).await.expect("an agent sandbox");

    // NT-SBX-09: what a hostile builder leaves behind.
    let host_path = host_file.display().to_string();
    let attacks: Vec<(&str, Vec<&str>)> = vec![
        (
            "a link to a host file",
            vec!["ln", "-s", &host_path, "/workspace/link-to-host"],
        ),
        (
            "a link that climbs out",
            vec!["ln", "-s", "../../../../etc/hostname", "/workspace/climb"],
        ),
        ("a FIFO", vec!["mkfifo", "/workspace/pipe"]),
        (
            "a hard link",
            vec!["ln", "/workspace/src/lib.rs", "/workspace/hard"],
        ),
        ("a setuid file", vec!["touch", "/workspace/setuid-file"]),
        (
            "a name with a line break",
            vec!["touch", "/workspace/line\nbreak.txt"],
        ),
        (
            "a nested repository",
            vec!["mkdir", "-p", "/workspace/aaa/x/.git"],
        ),
        (
            "its configuration",
            vec!["touch", "/workspace/aaa/x/.git/config"],
        ),
        (
            "a file at a hidden path",
            vec!["mkdir", "-p", "/workspace/tests/holdout"],
        ),
        (
            "the file",
            vec!["touch", "/workspace/tests/holdout/planted.rs"],
        ),
    ];
    let mut planted = Vec::new();
    for (what, words) in &attacks {
        let (code, text) = run(&lab, &mut *session, words).await;
        if code == Some(0) {
            planted.push(*what);
        } else {
            eprintln!(
                "PLATFORM: the sandbox could not plant {what}: {}",
                text.trim()
            );
        }
    }
    let (code, _) = run(
        &lab,
        &mut *session,
        &["chmod", "4755", "/workspace/setuid-file"],
    )
    .await;
    if code != Some(0) {
        eprintln!("PLATFORM: the sandbox could not set the setuid bit");
    }
    assert!(
        planted.contains(&"a link to a host file") && planted.contains(&"a nested repository"),
        "the basic attacks must be possible: {planted:?}"
    );

    // NT-SBX-10: the mask cannot be removed or replaced, and it reads as empty.
    for words in [
        &["rm", "-f", "/workspace/.git"][..],
        &["mv", "/workspace/.git", "/workspace/.git-moved"][..],
    ] {
        let (code, text) = run(&lab, &mut *session, words).await;
        assert_ne!(code, Some(0), "{words:?}: {text}");
        assert!(
            text.to_ascii_lowercase().contains("busy"),
            "{words:?}: {text}"
        );
    }
    let (code, text) = run(&lab, &mut *session, &["cat", "/workspace/.git"]).await;
    assert_eq!(code, Some(0));
    assert!(text.is_empty(), "the mask shows nothing: {text:?}");

    // NT-SBX-11: protected files cannot be changed from inside.
    for words in [
        &["cp", "/etc/hostname", "/workspace/.github/workflows/ci.yml"][..],
        &["rm", "-f", "/workspace/.github/workflows/ci.yml"][..],
        &["rm", "-f", "/workspace/CHANGELOG.md"][..],
    ] {
        let (code, text) = run(&lab, &mut *session, words).await;
        assert_ne!(code, Some(0), "{words:?}: {text}");
        let text = text.to_ascii_lowercase();
        assert!(
            text.contains("read-only") || text.contains("busy"),
            "{words:?}: {text}"
        );
    }
    // The hidden holdout does not exist for the sandbox, by name or by content.
    let (_, text) = run(
        &lab,
        &mut *session,
        &["find", "/workspace", "-name", "*secret_case*"],
    )
    .await;
    assert!(
        text.trim().is_empty(),
        "the holdout file is absent: {text:?}"
    );
    let (code, text) = run(
        &lab,
        &mut *session,
        &["grep", "-rl", "held out from the sandbox", "/workspace"],
    )
    .await;
    assert_eq!(code, Some(1), "no file holds the holdout text: {text:?}");

    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());

    // The audit, after the container is gone.
    let error = ws
        .ingest(&FakeCancel::new())
        .await
        .expect_err("the hostile tree is refused");
    assert!(matches!(error, WorkspaceError::NestedGit(_)), "{error:?}");
    let found = kinds(&ws);
    let has = |kind: AuditKind, path: &str| found.contains(&(kind, path.to_owned()));
    assert!(has(AuditKind::NestedGit, "aaa/x"), "{found:?}");
    assert!(has(AuditKind::EscapingSymlink, "link-to-host"), "{found:?}");
    assert!(has(AuditKind::EscapingSymlink, "climb"), "{found:?}");
    assert!(
        has(AuditKind::HiddenPath, "tests/holdout/planted.rs"),
        "{found:?}"
    );
    if planted.contains(&"a FIFO") {
        assert!(has(AuditKind::SpecialFile, "pipe"), "{found:?}");
    }
    if planted.contains(&"a hard link") {
        assert!(has(AuditKind::HardLink, "hard"), "{found:?}");
    }
    if planted.contains(&"a name with a line break") {
        assert!(
            found.iter().any(|(k, _)| *k == AuditKind::UnsafeName),
            "{found:?}"
        );
    }

    // The protected files and the mask are untouched on the host, and no sink holds the canary.
    let fixture = |path: &str| {
        factory_testkit::contracts::workspace::FIXTURE_FILES
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, text)| (*text).to_owned())
            .expect("a fixture file")
    };
    for path in [".github/workflows/ci.yml", "CHANGELOG.md", ".env.example"] {
        assert_eq!(
            fs::read_to_string(mounts.workspace.join(path)).expect("a protected file"),
            fixture(path),
            "{path} is byte-identical on the host"
        );
    }
    let mask = fs::symlink_metadata(mounts.workspace.join(".git")).expect("the mask file");
    assert!(mask.file_type().is_file() && mask.len() == 0);
    let sweeper = Sweeper::new(&canaries);
    assert!(
        sweeper
            .scan("error", format!("{error:?}").as_bytes())
            .is_empty()
    );
    assert!(
        sweeper
            .scan("report", format!("{:?}", ws.last_audit_report()).as_bytes())
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_gate_08_the_holdout_is_read_only_in_verify_and_a_clean_run_ingests() {
    let _one_at_a_time = SERIAL.lock().await;
    let lab = Lab::new(true);
    let world = World::with(Options::default()).await;
    let base = world.fetch(1).await;
    let agent = world.open_at(1, 1, &base, WorkspacePurpose::Agent).await;
    let verify = world
        .open_at(
            1,
            2,
            &base,
            WorkspacePurpose::Verify {
                holdouts: vec![factory_ports::paths::RepoGlob::new(HIDDEN_GLOB).expect("glob")],
            },
        )
        .await;

    // The agent sandbox writes an honest file, which the adapter ingests and commits.
    let spec = support::spec(
        SandboxProfile::Agent,
        &lab.catalog(),
        &agent.mounts(),
        support::attempt(1),
        WALL,
    );
    let mut session = lab.create(spec).await.expect("an agent sandbox");
    let (code, text) = run(
        &lab,
        &mut *session,
        &["touch", "/workspace/src/from_sandbox.rs"],
    )
    .await;
    assert_eq!(code, Some(0), "{text}");
    let (code, text) = run(&lab, &mut *session, &["touch", "/workspace/src/lib.rs"]).await;
    assert_eq!(
        code,
        Some(0),
        "the sandbox can write a checked-out file: {text}"
    );
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    let change = agent
        .ingest(&FakeCancel::new())
        .await
        .expect("an honest tree");
    let listed: Vec<&str> = change.changes().iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        listed,
        vec!["src/from_sandbox.rs"],
        "touching changed no bytes"
    );

    // The verify sandbox sees the holdout and cannot change it.
    let spec = support::spec(
        SandboxProfile::Verify,
        &lab.catalog(),
        &verify.mounts(),
        support::attempt(2),
        WALL,
    );
    let mut session = lab.create(spec).await.expect("a verify sandbox");
    let (code, text) = run(
        &lab,
        &mut *session,
        &["cat", "/workspace/tests/holdout/secret_case.rs"],
    )
    .await;
    assert_eq!(code, Some(0));
    assert!(text.contains("held out from the sandbox"), "{text}");
    let (code, text) = run(
        &lab,
        &mut *session,
        &["touch", "/workspace/tests/holdout/secret_case.rs"],
    )
    .await;
    assert_ne!(code, Some(0));
    assert!(text.to_ascii_lowercase().contains("read-only"), "{text}");
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_11_moving_a_protected_directory_is_not_stopped_inside_and_is_blocked_at_ingestion()
 {
    // The overlays are single files, so the directory that holds them can be renamed inside the
    // sandbox (a directory overlay would make that fail with "busy"). The overlay is defense in
    // depth; the host-side difference is the control, and it counts the old path of a rename.
    let _one_at_a_time = SERIAL.lock().await;
    let lab = Lab::new(true);
    let world = World::with(Options::default()).await;
    let (ws, _) = world.open(1).await;
    let spec = support::spec(
        SandboxProfile::Agent,
        &lab.catalog(),
        &ws.mounts(),
        support::attempt(1),
        WALL,
    );
    let mut session = lab.create(spec).await.expect("an agent sandbox");
    let (code, text) = run(
        &lab,
        &mut *session,
        &["mv", "/workspace/.github", "/workspace/moved-github"],
    )
    .await;
    eprintln!("PLATFORM: renaming the directory of an overlaid file: exit {code:?} {text}");
    let (code, text) = run(
        &lab,
        &mut *session,
        &["mkdir", "-p", "/workspace/.github/workflows"],
    )
    .await;
    assert!(code == Some(0) || code.is_some(), "{text}");
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    match ws.ingest(&FakeCancel::new()).await {
        Err(WorkspaceError::ProtectedPathChanged(list)) => {
            assert!(
                list.iter()
                    .any(|v| v.path.as_str() == ".github/workflows/ci.yml"),
                "the old path of the rename is refused: {list:?}"
            );
        }
        Ok(change) => {
            // The platform refused the rename, so the tree is unchanged.
            assert!(change.is_empty(), "{change:?}");
            assert!(
                ws.mounts()
                    .workspace
                    .join(".github/workflows/ci.yml")
                    .exists(),
                "the protected file is still where it was"
            );
        }
        Err(other) => panic!("unexpected {other:?}"),
    }
}
