//! The workflow files of the default branch, read through the real adapter and the fake GitHub
//! server (threat T-48). The preflight judges what these reads return.
//!
//! Nothing here ran against the real GitHub: the shape of the contents API is written from its
//! documentation (see `workflows.rs`), and the fake serves that shape. These tests show that the
//! adapter reads it, asks for `contents: read` and nothing more, and fails closed.

mod common;

use common::harness::{FIXTURE, World};
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{GitHostError, GitScope, IssueSource, WorkflowFile};
use factory_testkit::contracts::githost::scope;

const CONTENTS: &str = "GET /repos/{owner}/{repo}/contents/{path}";

/// The scope the preflight uses: the intake stage, whose own token reads issues only.
fn preflight_scope() -> GitScope {
    GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    }
}

async fn read(world: &World) -> Result<Vec<WorkflowFile>, GitHostError> {
    world
        .adapter
        .issue_source()
        .workflow_files(&preflight_scope())
        .await
}

fn file(path: &str, text: Option<&str>) -> WorkflowFile {
    WorkflowFile {
        path: path.to_owned(),
        text: text.map(str::to_owned),
    }
}

#[tokio::test]
async fn a_repository_without_the_directory_has_no_workflow_files() {
    let world = World::new();
    world.fake.add_file(FIXTURE, "README.md", Some("hello\n"));
    assert_eq!(read(&world).await, Ok(Vec::new()));
}

#[tokio::test]
async fn every_workflow_file_comes_back_with_its_text_and_nothing_else_does() {
    let world = World::new();
    let ci = "on:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  ci:\n    runs-on: ubuntu-latest\n";
    let long = format!("# {}\non: push\n", "é".repeat(400));
    world
        .fake
        .add_file(FIXTURE, ".github/workflows/ci.yml", Some(ci))
        .add_file(FIXTURE, ".github/workflows/release.yaml", Some(&long))
        .add_file(FIXTURE, ".github/workflows/README.md", Some("notes\n"))
        .add_file(FIXTURE, ".github/workflows/templates/inner.yml", Some("x"))
        .add_file(FIXTURE, ".github/dependabot.yml", Some("version: 2\n"))
        .add_file(FIXTURE, "docs/ci.yml", Some("not a workflow\n"));

    assert_eq!(
        read(&world).await,
        Ok(vec![
            file(".github/workflows/ci.yml", Some(ci)),
            file(".github/workflows/release.yaml", Some(&long)),
        ])
    );
    // The list and the two files, and no other file of the repository.
    let asked: Vec<String> = world
        .fake
        .requests_to(CONTENTS)
        .iter()
        .map(|request| request.path.clone())
        .collect();
    assert_eq!(asked.len(), 3, "{asked:?}");
    assert!(
        asked.iter().all(|path| path.contains("/contents/.github/workflows")),
        "{asked:?}"
    );
}

#[tokio::test]
async fn the_files_are_read_at_the_commit_of_the_default_branch() {
    let world = World::new();
    world
        .fake
        .add_file(FIXTURE, ".github/workflows/ci.yml", Some("on: push\n"));
    let tip = world.fake.branch_sha(FIXTURE, "main").expect("the tip");
    read(&world).await.expect("the files");
    for request in world.fake.requests_to(CONTENTS) {
        assert_eq!(
            request.query,
            Some(format!("ref={tip}")),
            "every read names the same commit"
        );
    }
}

#[tokio::test]
async fn a_file_the_host_gives_no_text_for_comes_back_without_text() {
    let world = World::new();
    world
        .fake
        .add_file(FIXTURE, ".github/workflows/huge.yml", None)
        .add_file(FIXTURE, ".github/workflows/ok.yml", Some("on: push\n"));
    assert_eq!(
        read(&world).await,
        Ok(vec![
            file(".github/workflows/huge.yml", None),
            file(".github/workflows/ok.yml", Some("on: push\n")),
        ])
    );
}

#[tokio::test]
async fn the_reads_carry_a_token_that_can_read_contents_and_nothing_more() {
    let world = World::new();
    world
        .fake
        .add_file(FIXTURE, ".github/workflows/ci.yml", Some("on: push\n"));
    read(&world).await.expect("the files");
    let mints = world.fake.mints();
    assert_eq!(mints.len(), 1, "one token for the whole read");
    let asked: Vec<(String, String)> = mints[0]
        .requested_permissions
        .clone()
        .expect("the token is narrowed")
        .into_iter()
        .collect();
    assert_eq!(
        asked,
        [
            ("contents".to_owned(), "read".to_owned()),
            ("metadata".to_owned(), "read".to_owned()),
        ]
    );
    assert_eq!(
        mints[0].requested_repositories.as_deref().map(<[String]>::len),
        Some(1),
        "the token is for one repository"
    );
}

#[tokio::test]
async fn a_read_that_fails_is_an_error_and_never_an_empty_list() {
    // The list fails.
    let world = World::new();
    world
        .fake
        .add_file(FIXTURE, ".github/workflows/ci.yml", Some("on: push\n"));
    world.fake.fail_always(CONTENTS, 500, "Server Error");
    assert!(read(&world).await.is_err());

    // The branch cannot be read: nothing is known about the directory.
    let world = World::new();
    world.fake.fail_always(
        "GET /repos/{owner}/{repo}/branches/{branch}",
        404,
        "Not Found",
    );
    assert!(read(&world).await.is_err());

    // The App may not read contents at all.
    let world = World::with(common::harness::Options {
        app: Some(
            factory_testkit::fx::github::AppConfig::factory_default().without_permission("contents"),
        ),
        ..common::harness::Options::default()
    });
    world
        .fake
        .add_file(FIXTURE, ".github/workflows/ci.yml", Some("on: push\n"));
    assert!(read(&world).await.is_err());
}
