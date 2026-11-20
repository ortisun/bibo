//! The repository intelligence stage reads the project's git conventions
//! (`.factory/repository.json`) at the protected default branch, and the job works from the
//! integration branch of the project's gitflow: `develop`, or the one open `release/` branch.

use factory_domain::machines::failure::FailureClass;
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::BranchName;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::stages::repo_intel::map;
use serde_json::{Value, json};

use crate::harness::{Options, Rig, USUAL_REQUEST, usual};
use crate::repo_rig::word_count;

fn settings(mode: &str) -> String {
    json!({
        "schema": "factory-repository-settings/1",
        "repository": {"owner": "example-org", "name": "fixture"},
        "project_board": null,
        "commits": {
            "convention": "conventional-commits",
            "types": ["build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test"],
            "scopes": [], "require_scope": false, "header_max_length": 100
        },
        "gitflow": {
            "closing_mode": mode, "main_branch": "main", "develop_branch": "develop",
            "prefixes": {"feature": ["feature/", "factory/"], "bugfix": ["bugfix/"], "release": ["release/"],
                         "hotfix": ["hotfix/"], "support": ["support/"]},
            "additional_flows": []
        }
    })
    .to_string()
}

fn files_with(settings: &str) -> Vec<(String, String)> {
    let mut files = word_count();
    files.push((".factory/repository.json".to_owned(), settings.to_owned()));
    files
}

async fn rig_with(settings: &str) -> Rig {
    Rig::build(Options {
        real_repo: true,
        repo_files: Some(files_with(settings)),
        ..Options::default()
    })
    .await
}

/// A branch on the remote: the default branch's files, plus one of its own.
fn put_branch(rig: &Rig, name: &str, settings: &str) -> String {
    let mut files = files_with(settings);
    files.push((
        format!("src/{}.rs", name.replace(['/', '.'], "_")),
        "pub fn on_branch() {}\n".to_owned(),
    ));
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    rig.remote
        .commit_on_branch(
            &rig.repo,
            &BranchName::new(name).expect("a branch"),
            &borrowed,
        )
        .as_str()
        .to_owned()
}

async fn run_stage(rig: &Rig) -> (factory_domain::ids::JobId, AttemptOutcome) {
    let job = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(usual());
    let (_, intake) = rig.run_next().await;
    assert_eq!(intake, AttemptOutcome::Succeeded, "intake passes");
    let (_, outcome) = rig.run_next().await;
    (job, outcome)
}

async fn the_map(rig: &Rig, job: factory_domain::ids::JobId) -> Value {
    rig.documents_with(job, StageKind::RepositoryIntelligence, "commit_sha")
        .await
        .into_iter()
        .next()
        .expect("a repository map")
}

fn blocked(outcome: &AttemptOutcome) -> bool {
    matches!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::PolicyDenied,
            ..
        }
    )
}

#[tokio::test]
async fn without_settings_the_job_works_from_the_default_branch() {
    let rig = Rig::build(Options {
        real_repo: true,
        ..Options::default()
    })
    .await;
    let (job, outcome) = run_stage(&rig).await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let map = the_map(&rig, job).await;
    assert_eq!(map["base_branch"], "main");
    assert_eq!(map["commit_sha"], rig.commit.as_str());
    assert!(map.get("git_settings").is_none());
}

#[tokio::test]
async fn develop_mode_works_from_develop() {
    let text = settings("develop");
    let rig = rig_with(&text).await;
    let tip = put_branch(&rig, "develop", &text);
    let (job, outcome) = run_stage(&rig).await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let map = the_map(&rig, job).await;
    map::validate(&map).expect("the map follows its schema");
    assert_eq!(map["base_branch"], "develop");
    assert_eq!(
        map["commit_sha"],
        tip.as_str(),
        "the base is the tip of develop, not of main"
    );
    assert_eq!(map["git_settings"]["path"], ".factory/repository.json");
    assert_eq!(map["git_settings"]["evidence"]["commit_sha"], tip.as_str());
}

#[tokio::test]
async fn settings_that_differ_on_the_base_are_not_cited_there() {
    let text = settings("develop");
    let rig = rig_with(&text).await;
    // develop holds an older copy of the file: the default branch decided, and the map does not
    // claim that the base holds what the default branch holds.
    put_branch(&rig, "develop", &text.replace("100", "90"));
    let (job, outcome) = run_stage(&rig).await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let map = the_map(&rig, job).await;
    assert_eq!(map["base_branch"], "develop");
    assert!(map.get("git_settings").is_none());
}

#[tokio::test]
async fn release_mode_works_from_the_one_open_release_branch() {
    let text = settings("release");
    let rig = rig_with(&text).await;
    put_branch(&rig, "develop", &text);
    let tip = put_branch(&rig, "release/1.2.0", &text);
    let (job, outcome) = run_stage(&rig).await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let map = the_map(&rig, job).await;
    assert_eq!(map["base_branch"], "release/1.2.0");
    assert_eq!(map["commit_sha"], tip.as_str());
}

#[tokio::test]
async fn release_mode_with_no_open_release_branch_blocks() {
    let text = settings("release");
    let rig = rig_with(&text).await;
    put_branch(&rig, "develop", &text);
    let (job, outcome) = run_stage(&rig).await;
    assert!(blocked(&outcome), "{outcome:?}");
    let run = rig
        .world
        .view(job)
        .await
        .newest(StageKind::RepositoryIntelligence)
        .expect("a run")
        .status;
    assert_ne!(run, StageRunStatus::Passed);
}

#[tokio::test]
async fn release_mode_never_guesses_between_two_release_branches() {
    let text = settings("release");
    let rig = rig_with(&text).await;
    put_branch(&rig, "release/1.2.0", &text);
    put_branch(&rig, "release/1.3.0", &text);
    let (_, outcome) = run_stage(&rig).await;
    assert!(blocked(&outcome), "{outcome:?}");
}

#[tokio::test]
async fn a_develop_branch_the_remote_does_not_have_blocks() {
    let rig = rig_with(&settings("develop")).await;
    let (_, outcome) = run_stage(&rig).await;
    assert!(blocked(&outcome), "{outcome:?}");
}

#[tokio::test]
async fn settings_that_are_not_valid_block_and_are_never_ignored() {
    let rig = rig_with(&settings("trunk")).await;
    let (_, outcome) = run_stage(&rig).await;
    assert!(blocked(&outcome), "{outcome:?}");
    let rig = rig_with("{ not json").await;
    let (_, outcome) = run_stage(&rig).await;
    assert!(blocked(&outcome), "{outcome:?}");
}
