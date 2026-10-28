//! Live check of ADR 0014 decision 7: a required check pinned to the factory App's id is not
//! satisfied by a check run of the same name from another App.
//!
//! Run it with `FACTORY_LIVE=1 cargo nextest run -p factory-github --test live_pinning`.
//!
//! If the claim holds, decision 7 stands. If another App's check satisfies the pinned
//! requirement, this test fails and the decision is reopened (ports-v1.1, section 13).
//!
//! * Without `FACTORY_LIVE=1` it does nothing and says so (this is not a pass).
//! * With `FACTORY_LIVE=1` and missing credentials it stops with `BLOCKED:` and the list.
//! * THIS PART HAS NEVER RUN: no App is registered, and it also needs a second App.
//!
//! What a person provides, besides what `live_smoke` needs: a second registered App installed on
//! the fixture repository (`FACTORY_GITHUB_OTHER_APP_ID`, `FACTORY_GITHUB_OTHER_PRIVATE_KEY_PATH`,
//! `FACTORY_GITHUB_OTHER_INSTALLATION_ID`), the pushed branch of an open draft or ready pull
//! request (`FACTORY_GITHUB_FIXTURE_PR`, its number), and a ruleset on the default branch that
//! requires the check `factory-live-pinning` with `integration_id` set to the factory App's id and
//! requires nothing else that is unmet (no review, no other check).

mod common;

use common::live::{LiveApp, live_requested, require};
use factory_domain::values::Slug;
use factory_domain::vocabulary::StageKind;
use factory_github::Method;
use factory_ports::githost::{ChangeHost, CheckConclusion, CheckRequest, CheckStatus};
use factory_ports::paths::CommitSha;
use serde_json::json;

const CHECK: &str = "factory-live-pinning";

fn success(commit: &CommitSha) -> CheckRequest {
    CheckRequest {
        commit: commit.clone(),
        name: Slug::parse(CHECK).expect("a name"),
        external_id: Slug::parse("live-pinning-1").expect("an id"),
        status: CheckStatus::Completed(CheckConclusion::Success),
        title: "Pinning".to_owned(),
        summary: "A successful check run.".to_owned(),
        details_url: None,
    }
}

#[tokio::test]
async fn a_check_run_of_the_same_name_from_another_app_does_not_satisfy_a_check_pinned_to_the_factory_app()
 {
    if !live_requested() {
        eprintln!("NOT RUN: set FACTORY_LIVE=1 to run the live pinning check (this is not a pass)");
        return;
    }
    let factory = LiveApp::from_env("the live pinning check", "FACTORY_GITHUB");
    let other = LiveApp::from_env("the live pinning check", "FACTORY_GITHUB_OTHER");
    let number: u64 = require("the live pinning check", &["FACTORY_GITHUB_FIXTURE_PR"])[0]
        .parse()
        .expect("the pull request number");

    let reader = factory
        .token_for_test(&serde_json::json!({"pull_requests": "read", "metadata": "read"}))
        .await;
    let target = format!(
        "/repos/{}/{}/pulls/{number}",
        factory.repo.owner(),
        factory.repo.name()
    );
    let (status, pull) = factory.call(&reader, Method::Get, &target, None).await;
    assert_eq!(status, 200, "the fixture pull request can be read");
    let commit =
        CommitSha::parse(pull["head"]["sha"].as_str().expect("a head commit")).expect("a commit");

    // The other App makes a successful check run of the pinned name. The merge state must still
    // say that a required check is missing.
    let other_host = other.adapter().change_host();
    other_host
        .publish_check(&other.scope(StageKind::Delivery, 5), success(&commit))
        .await
        .expect("the other App publishes its check");
    let (_, after_other) = factory.call(&reader, Method::Get, &target, None).await;
    assert_eq!(
        after_other["mergeable_state"],
        json!("blocked"),
        "a check of the same name from another App must not satisfy the pinned requirement: {}",
        after_other["mergeable_state"]
    );

    // The factory App makes the same check run. Now the requirement is met.
    let factory_host = factory.adapter().change_host();
    factory_host
        .publish_check(&factory.scope(StageKind::Delivery, 6), success(&commit))
        .await
        .expect("the factory App publishes its check");
    let (_, after_factory) = factory.call(&reader, Method::Get, &target, None).await;
    assert_ne!(
        after_factory["mergeable_state"],
        json!("blocked"),
        "the pinned requirement is met by the factory App's own check run"
    );
}
