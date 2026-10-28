//! Live smoke test: open a draft pull request on the protected fixture repository with a
//! registered App, read it back, publish a check run, comment, and close the pull request.
//!
//! Run it with `FACTORY_LIVE=1 cargo nextest run -p factory-github --test live_smoke`.
//!
//! * Without `FACTORY_LIVE=1` it does nothing and says so on the standard error stream. That is
//!   not a pass of the live check: it only keeps the default suite from reaching out.
//! * With `FACTORY_LIVE=1` and missing credentials it stops with a message that starts `BLOCKED:`
//!   and lists what a person must provide.
//! * With them, it runs for real. THIS PART HAS NEVER RUN: no App is registered yet.
//!
//! What a person provides:
//!
//! | Variable | What |
//! |---|---|
//! | `FACTORY_GITHUB_APP_ID` | the numeric id of the registered App |
//! | `FACTORY_GITHUB_PRIVATE_KEY_PATH` | a file with the App's private key (PEM) |
//! | `FACTORY_GITHUB_INSTALLATION_ID` | the installation that covers the fixture repository |
//! | `FACTORY_GITHUB_FIXTURE_REPO` | `owner/name` of the protected fixture repository |
//! | `FACTORY_GITHUB_FIXTURE_BRANCH` | a pushed branch `factory/...` that differs from the default branch |

mod common;

use common::live::{LiveApp, live_requested, require};
use factory_domain::values::Slug;
use factory_domain::vocabulary::StageKind;
use factory_github::Method;
use factory_ports::githost::{
    ChangeHost, CheckConclusion, CheckRequest, CheckStatus, CommentTarget, DraftPrRequest,
    IssueSource, PullRequestLifecycle,
};
use factory_ports::paths::BranchName;
use serde_json::json;

#[tokio::test]
async fn a_draft_pull_request_is_opened_read_checked_commented_and_closed_on_the_fixture_repository()
 {
    if !live_requested() {
        eprintln!("NOT RUN: set FACTORY_LIVE=1 to run the live smoke test (this is not a pass)");
        return;
    }
    let app = LiveApp::from_env("the live smoke test", "FACTORY_GITHUB");
    let head = require("the live smoke test", &["FACTORY_GITHUB_FIXTURE_BRANCH"]).remove(0);
    let adapter = app.adapter();
    let host = adapter.change_host();
    let scope = app.scope(StageKind::Delivery, 1);

    // The App holds what the policy asks and nothing it forbids.
    assert_eq!(
        adapter.audit_app().await.expect("the App can be read"),
        factory_github::AppAudit::Pass
    );

    let head = BranchName::new(&head).expect("a branch name");
    let pr = host
        .open_draft_pull_request(
            &scope,
            DraftPrRequest {
                head: head.clone(),
                base: BranchName::new("main").expect("a branch name"),
                title: "Live smoke test of the factory GitHub adapter".to_owned(),
                body: "This pull request is opened and closed by the live smoke test.".to_owned(),
            },
        )
        .await
        .expect("a draft pull request is opened");
    let state = host
        .pull_request_state(&scope, &pr)
        .await
        .expect("it can be read");
    assert!(state.draft && state.lifecycle == PullRequestLifecycle::Open);
    assert_eq!(state.head, head);

    // A second call for the same head returns the same pull request.
    let again = host
        .open_draft_pull_request(
            &scope,
            DraftPrRequest {
                head: head.clone(),
                base: BranchName::new("main").expect("a branch name"),
                title: "Live smoke test of the factory GitHub adapter".to_owned(),
                body: "This pull request is opened and closed by the live smoke test.".to_owned(),
            },
        )
        .await
        .expect("the same pull request");
    assert_eq!(again, pr);

    host.post_comment(
        &scope,
        &CommentTarget::PullRequest(pr.clone()),
        "Smoke test comment.",
        "live-smoke-1",
    )
    .await
    .expect("a comment");
    let check = |status| CheckRequest {
        commit: state.head_sha.clone(),
        name: Slug::parse("factory-live-smoke").expect("a name"),
        external_id: Slug::parse("live-smoke-1").expect("an id"),
        status,
        title: "Live smoke".to_owned(),
        summary: "The live smoke test ran.".to_owned(),
        details_url: None,
    };
    let running = host
        .publish_check(&scope, check(CheckStatus::InProgress))
        .await
        .expect("a check run");
    let done = host
        .publish_check(
            &scope,
            check(CheckStatus::Completed(CheckConclusion::Neutral)),
        )
        .await
        .expect("the check run is updated");
    assert_eq!(running, done, "one check run, updated");

    // The adapter never closes a pull request. The test does, with a token of its own.
    let token = app
        .token_for_test(&json!({"pull_requests": "write", "metadata": "read"}))
        .await;
    let target = format!(
        "/repos/{}/{}/pulls/{}",
        app.repo.owner(),
        app.repo.name(),
        pr.number
    );
    let (status, _) = app
        .call(
            &token,
            Method::Patch,
            &target,
            Some(&json!({"state": "closed"})),
        )
        .await;
    assert_eq!(status, 200, "the pull request was closed");

    host.revoke_job_tokens(scope.job)
        .await
        .expect("tokens are revoked");
    // And the issue source can read the fixture repository's rules with the Metadata permission.
    let report = adapter
        .issue_source()
        .repository_protection(&app.scope(StageKind::Intake, 2))
        .await;
    eprintln!("protection report of the fixture repository: {report:?}");
}
