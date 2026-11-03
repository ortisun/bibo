//! What the contract suites do not reach: the head commit in the body tag, check run conclusions,
//! no merge and no ready-for-review, rate limits, pagination with caps and the conditional reads.

mod common;

use std::time::Duration;

use common::harness::{FIXTURE, Options, World};
use common::transports::{Overrides, answer};
use factory_domain::values::{Slug, Uri};
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_github::{Method, conclusion_for_gate};
use factory_ports::githost::{
    ChangeHost, CheckConclusion, CheckRequest, CheckStatus, CommentTarget, DraftPrRequest,
    GitHostError, GitScope, IssueRef, IssueSource, PullRequestLifecycle, PullRequestRef, Rejection,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_testkit::contracts::githost::scope;
use serde_json::{Value, json};

fn delivery() -> GitScope {
    GitScope {
        stage: StageKind::Delivery,
        ..scope(1, 1)
    }
}

fn intake() -> GitScope {
    GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    }
}

fn branch(name: &str) -> BranchName {
    BranchName::new(name).unwrap()
}

fn draft() -> DraftPrRequest {
    DraftPrRequest {
        head: branch("factory/job-1"),
        base: branch("main"),
        title: "Add a word count command".to_owned(),
        body: "Evidence follows.".to_owned(),
    }
}

fn repo() -> RepoRef {
    RepoRef::parse(FIXTURE).unwrap()
}

// ---- the head commit ---------------------------------------------------------------------------

#[tokio::test]
async fn the_body_tag_covers_the_head_commit_so_a_push_makes_a_stale_manifest_conflict() {
    let world = World::new();
    let host = world.adapter.change_host();
    let pr = host
        .open_draft_pull_request(&delivery(), draft())
        .await
        .unwrap();
    let read = host.pull_request_state(&delivery(), &pr).await.unwrap();
    assert_eq!(
        read.head_sha.as_str(),
        world.fake.branch_sha(FIXTURE, "factory/job-1").unwrap(),
        "the head is read live"
    );

    // Someone pushes to the branch after the evidence was written for `read.head_sha`.
    let moved = world.fake.push_commit(FIXTURE, "factory/job-1");
    assert_ne!(moved, read.head_sha.as_str());
    assert_eq!(
        host.update_pull_request_body(
            &delivery(),
            &pr,
            "Evidence for the old commit.",
            Some(&read.body_etag)
        )
        .await,
        Err(GitHostError::Conflict),
        "the body is the same text, and the head moved"
    );
    let fresh = host.pull_request_state(&delivery(), &pr).await.unwrap();
    assert_eq!(
        fresh.head_sha.as_str(),
        moved,
        "the new head is read live too"
    );
    host.update_pull_request_body(
        &delivery(),
        &pr,
        "Evidence for the new commit.",
        Some(&fresh.body_etag),
    )
    .await
    .unwrap();
}

// ---- no merge, no ready for review ---------------------------------------------------------------

#[tokio::test]
async fn nothing_the_adapter_does_merges_marks_ready_or_touches_a_branch_it_may_not() {
    let world = World::new();
    let host = world.adapter.change_host();
    let pr = host
        .open_draft_pull_request(&delivery(), draft())
        .await
        .unwrap();
    host.update_pull_request_body(&delivery(), &pr, "A new body.", None)
        .await
        .unwrap();
    host.post_comment(
        &delivery(),
        &CommentTarget::PullRequest(pr.clone()),
        "Note.",
        "k",
    )
    .await
    .unwrap();
    host.pull_request_state(&delivery(), &pr).await.unwrap();
    host.revoke_job_tokens(delivery().job).await.unwrap();

    assert!(
        world.fake.merge_attempts().is_empty(),
        "no call to the merge endpoint"
    );
    assert_eq!(
        world.fake.pull_json(FIXTURE, pr.number).unwrap()["draft"],
        true,
        "still a draft"
    );
    for request in world.fake.requests() {
        if request.method == "PATCH" {
            let body = request.body_json().unwrap_or(Value::Null);
            assert!(
                body.get("draft").is_none(),
                "a PATCH named the draft state: {body}"
            );
        }
        assert!(!request.path.contains("graphql"), "{}", request.path);
    }
    assert!(
        world.fake.pushes().iter().all(|p| p.token_id.is_none()),
        "the adapter wrote no branch, so it deleted none"
    );
}

#[test]
fn the_source_has_no_merge_no_ready_call_no_workflow_write_and_one_delete() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut deletes = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let code: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        for needle in [
            "\"/merge",
            "/merge\"",
            "graphql",
            "ReadyForReview",
            "ready_for_review",
            "\"draft\": false",
            ".github/workflows",
            "/git/refs",
            "pulls/{number}/merge",
        ] {
            assert!(
                !code.iter().any(|l| l.contains(needle)),
                "{} holds {needle}",
                path.display()
            );
        }
        if code.iter().any(|l| l.contains("Method::Delete")) {
            deletes.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    deletes.sort();
    // The method exists in the wire module and in the transport's mapping. It is used to revoke an
    // installation token (`token.rs`) and, since ports v1.2, by the status writer (`status.rs`)
    // for two things only: taking a `factory: ` label off an issue and deleting the duplicate of
    // the status comment. The name of this test says "one delete" because that was true when it
    // was written; it is kept so that the records that cite it stay valid.
    assert_eq!(
        deletes,
        vec!["status.rs", "token.rs", "ureq_transport.rs", "wire.rs"]
    );
    let status = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/status.rs"),
    )
    .unwrap();
    let uses = status
        .lines()
        .filter(|l| !l.trim_start().starts_with("//") && l.contains("Method::Delete"))
        .count();
    assert_eq!(uses, 2, "a label and a duplicate comment, nothing else");
    for forbidden in ["/refs", "/branches", "/pulls", "/contents"] {
        assert!(
            !status.contains(forbidden),
            "the status writer touches no {forbidden}"
        );
    }
}

#[tokio::test]
async fn a_repository_that_cannot_hold_drafts_gets_its_ready_pull_request_closed_at_once() {
    let ready = answer(201, &[], &json!({"number": 7, "draft": false}));
    let world = World::with(Options {
        wrap: Some(Box::new(move |inner| {
            Overrides::new(inner, vec![(Method::Post, "/pulls", ready)])
        })),
        ..Options::default()
    });
    let host = world.adapter.change_host();
    // The scripted answer stands for a real pull request that exists on the host; make it.
    let outcome = host.open_draft_pull_request(&delivery(), draft()).await;
    assert_eq!(outcome, Err(GitHostError::Rejected(Rejection::Other)));
    let patches = world
        .fake
        .requests_to("PATCH /repos/{owner}/{repo}/pulls/{number}");
    assert_eq!(patches.len(), 1, "the close was asked for");
    assert_eq!(patches[0].body_json().unwrap(), json!({"state": "closed"}));
}

// ---- check runs ------------------------------------------------------------------------------

fn check_request(world: &World, external: &str, status: CheckStatus) -> CheckRequest {
    CheckRequest {
        commit: CommitSha::parse(&world.fake.branch_sha(FIXTURE, "factory/job-1").unwrap())
            .unwrap(),
        name: Slug::parse("factory-validation").unwrap(),
        external_id: Slug::parse(external).unwrap(),
        status,
        title: "Validation".to_owned(),
        summary: "Every gate ran.".to_owned(),
        details_url: None,
    }
}

#[tokio::test]
async fn gate_outcomes_reach_the_code_host_as_check_conclusions_and_blocked_is_never_success() {
    let world = World::new();
    let host = world.adapter.change_host();
    let cases = [
        (GateOutcome::Passed, "success"),
        (GateOutcome::Failed, "failure"),
        (GateOutcome::Blocked, "action_required"),
        (GateOutcome::NotApplicable, "neutral"),
    ];
    for (index, (outcome, expected)) in cases.into_iter().enumerate() {
        let request = check_request(
            &world,
            &format!("run-{index}"),
            CheckStatus::Completed(conclusion_for_gate(outcome)),
        );
        host.publish_check(&delivery(), request).await.unwrap();
        let recorded = world.extras.checks.lock().unwrap().last().cloned().unwrap();
        assert_eq!(
            recorded.conclusion.as_deref(),
            Some(expected),
            "{outcome:?}"
        );
        assert_eq!(recorded.status, "completed");
    }
    assert_eq!(
        conclusion_for_gate(GateOutcome::Blocked),
        CheckConclusion::ActionRequired
    );
}

#[tokio::test]
async fn a_check_run_goes_from_running_to_done_in_place_and_another_apps_run_is_never_touched() {
    let world = World::new();
    let host = world.adapter.change_host();
    let request = check_request(&world, "run-1", CheckStatus::InProgress);
    // Another App has a run with the same name and external id on the same commit.
    world
        .extras
        .checks
        .lock()
        .unwrap()
        .push(common::harness::CheckRecord {
            id: 999_001,
            repo: FIXTURE.to_owned(),
            name: "factory-validation".to_owned(),
            head_sha: request.commit.as_str().to_owned(),
            external_id: "run-1".to_owned(),
            status: "completed".to_owned(),
            conclusion: Some("success".to_owned()),
            app_id: world.fake.app().id + 1,
            title: "Another App".to_owned(),
            summary: "Not ours.".to_owned(),
        });
    let running = host
        .publish_check(&delivery(), request.clone())
        .await
        .unwrap();
    assert_ne!(
        running.id, 999_001,
        "a run of another App is not ours to update"
    );
    let done = host
        .publish_check(
            &delivery(),
            CheckRequest {
                status: CheckStatus::Completed(CheckConclusion::Failure),
                ..request
            },
        )
        .await
        .unwrap();
    assert_eq!(done, running);
    let checks = world.extras.checks.lock().unwrap().clone();
    let other = checks.iter().find(|c| c.id == 999_001).unwrap();
    assert_eq!(
        other.conclusion.as_deref(),
        Some("success"),
        "the other App's run is as it was"
    );
    let ours = checks.iter().find(|c| c.id == running.id).unwrap();
    assert_eq!(
        (ours.status.as_str(), ours.conclusion.as_deref()),
        ("completed", Some("failure"))
    );
}

#[tokio::test]
async fn check_text_has_bounds_and_the_link_must_be_on_the_allowed_list() {
    let world = World::new();
    let host = world.adapter.change_host();
    let base = check_request(&world, "run-1", CheckStatus::InProgress);
    let bad = |title: &str, summary: &str| CheckRequest {
        title: title.to_owned(),
        summary: summary.to_owned(),
        ..base.clone()
    };
    for request in [
        bad(&"t".repeat(101), "ok"),
        bad("ok", &"s".repeat(4001)),
        bad("", "ok"),
        bad("ok", "   "),
    ] {
        assert_eq!(
            host.publish_check(&delivery(), request).await,
            Err(GitHostError::Rejected(Rejection::TextBounds))
        );
    }
    let foreign = CheckRequest {
        details_url: Some(Uri::parse("https://attacker.test/e?d=1").unwrap()),
        ..base.clone()
    };
    assert_eq!(
        host.publish_check(&delivery(), foreign).await,
        Err(GitHostError::Rejected(Rejection::Other))
    );
    let own = CheckRequest {
        details_url: Some(
            Uri::parse("https://github.com/example-org/fixture/actions/runs/1").unwrap(),
        ),
        ..base
    };
    host.publish_check(&delivery(), own).await.unwrap();
}

// ---- rate limits ---------------------------------------------------------------------------------

fn seeded_issue(world: &World) -> IssueRef {
    let number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "octocat",
        &["factory"],
    );
    IssueRef {
        repo: repo(),
        number,
    }
}

const ISSUE_ROUTE: &str = "GET /repos/{owner}/{repo}/issues/{number}";

#[tokio::test]
async fn a_short_rate_limit_is_waited_out_from_the_headers_and_the_call_goes_through() {
    let world = World::new();
    let issue = seeded_issue(&world);
    world.fake.rate_limit_next(ISSUE_ROUTE, 3);
    world
        .adapter
        .issue_source()
        .fetch_issue(&intake(), &issue)
        .await
        .unwrap();
    assert_eq!(world.sleeper.waits(), vec![Duration::from_secs(3)]);
}

#[tokio::test]
async fn a_long_rate_limit_is_reported_with_its_wait_and_not_slept_through() {
    let world = World::new();
    let issue = seeded_issue(&world);
    world.fake.rate_limit_next(ISSUE_ROUTE, 120);
    assert_eq!(
        world
            .adapter
            .issue_source()
            .fetch_issue(&intake(), &issue)
            .await,
        Err(GitHostError::RateLimited {
            retry_after: Some(Duration::from_secs(120))
        })
    );
    assert!(world.sleeper.waits().is_empty());

    // A limit that does not lift stops after the retries.
    for _ in 0..6 {
        world.fake.rate_limit_next(ISSUE_ROUTE, 2);
    }
    assert!(matches!(
        world
            .adapter
            .issue_source()
            .fetch_issue(&intake(), &issue)
            .await,
        Err(GitHostError::RateLimited {
            retry_after: Some(_)
        })
    ));
    assert_eq!(world.sleeper.waits(), vec![Duration::from_secs(2); 3]);
}

#[tokio::test]
async fn a_secondary_limit_without_a_time_is_reported_as_a_minute() {
    let world = World::new();
    let issue = seeded_issue(&world);
    world.fake.fail_next(
        ISSUE_ROUTE,
        403,
        "You have exceeded a secondary rate limit.",
    );
    assert_eq!(
        world
            .adapter
            .issue_source()
            .fetch_issue(&intake(), &issue)
            .await,
        Err(GitHostError::RateLimited {
            retry_after: Some(Duration::from_secs(60))
        })
    );
    // A 403 that is a refusal is not a rate limit.
    world
        .fake
        .fail_next(ISSUE_ROUTE, 403, "Resource not accessible by integration");
    assert_eq!(
        world
            .adapter
            .issue_source()
            .fetch_issue(&intake(), &issue)
            .await,
        Err(GitHostError::Forbidden)
    );
}

#[tokio::test]
async fn a_server_error_on_a_read_is_retried_with_a_doubling_pause_and_a_write_is_not_retried() {
    let world = World::new();
    let issue = seeded_issue(&world);
    world.fake.fail_next(ISSUE_ROUTE, 502, "bad gateway");
    world.fake.fail_next(ISSUE_ROUTE, 503, "unavailable");
    world
        .adapter
        .issue_source()
        .fetch_issue(&intake(), &issue)
        .await
        .unwrap();
    assert_eq!(
        world.sleeper.waits(),
        vec![Duration::from_millis(250), Duration::from_millis(500)]
    );

    let host = world.adapter.change_host();
    world
        .fake
        .fail_next("POST /repos/{owner}/{repo}/pulls", 502, "bad gateway");
    assert_eq!(
        host.open_draft_pull_request(&delivery(), draft()).await,
        Err(GitHostError::Unavailable)
    );
    assert_eq!(
        world
            .fake
            .requests_to("POST /repos/{owner}/{repo}/pulls")
            .len(),
        1,
        "one try"
    );
}

// ---- pagination --------------------------------------------------------------------------------------

fn event(kind: &str, label: &str, actor_id: u64, login: &str) -> Value {
    json!({"id": actor_id, "event": kind, "label": {"name": label}, "actor": {"id": actor_id, "login": login}, "created_at": "2026-10-28T10:00:00Z"})
}

fn paged_world(
    link: Option<String>,
    max_pages: Option<u32>,
) -> (World, IssueRef, std::sync::Arc<Overrides>) {
    let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let handed = std::sync::Arc::clone(&slot);
    let world = World::with(Options {
        wrap: Some(Box::new(move |inner| {
            let overrides = Overrides::new(inner, Vec::new());
            *handed.lock().unwrap() = Some(std::sync::Arc::clone(&overrides));
            overrides
        })),
        configure: Some(Box::new(move |config| {
            if let Some(max) = max_pages {
                config.pages.max_pages = max;
                // The events of an issue have a cap of their own, larger by default.
                config.pages.event_pages = max;
            }
        })),
        ..Options::default()
    });
    let overrides = slot.lock().unwrap().take().unwrap();
    let number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "octocat",
        &["factory"],
    );
    // The first page of events carries a link to the next one.
    let base = world.server.base_url();
    let next = link.unwrap_or_else(|| {
        format!("<{base}/repos/{FIXTURE}/issues/{number}/events?per_page=100&page=2>; rel=\"next\"")
    });
    overrides.script(
        Method::Get,
        "events?per_page=100",
        answer(
            200,
            &[("link", next.as_str())],
            &json!([
                event("labeled", "other", 5, "someone"),
                event("labeled", "factory", 1, "octocat")
            ]),
        ),
    );
    (
        world,
        IssueRef {
            repo: repo(),
            number,
        },
        overrides,
    )
}

#[tokio::test]
async fn the_event_list_is_read_across_pages_and_the_latest_labeled_event_names_the_person() {
    let (world, issue, overrides) = paged_world(None, None);
    overrides.script(
        Method::Get,
        "page=2",
        answer(
            200,
            &[],
            &json!([
                event("unlabeled", "factory", 1, "octocat"),
                event("labeled", "factory", 77, "maintainer")
            ]),
        ),
    );
    let who = world
        .adapter
        .issue_source()
        .label_actor(&intake(), &issue, "factory")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(who.id, 77, "the later event, from the second page");
    assert_eq!(overrides.targets_with("events").len(), 2);
}

#[tokio::test]
async fn a_listing_that_is_longer_than_the_cap_is_an_error_and_not_a_guess() {
    let (world, issue, overrides) = paged_world(None, Some(1));
    let outcome = world
        .adapter
        .issue_source()
        .label_actor(&intake(), &issue, "other-label-not-there")
        .await;
    // The label is not on the issue, so nothing is read at all.
    assert_eq!(outcome, Ok(None));
    // The label is on the issue, the first page does not hold its event and the cap stops the read.
    world
        .fake
        .label_issue(FIXTURE, issue.number, "late", "octocat");
    let capped = world
        .adapter
        .issue_source()
        .label_actor(&intake(), &issue, "late")
        .await;
    assert_eq!(capped, Err(GitHostError::Unavailable));
    assert_eq!(
        overrides.targets_with("events").len(),
        1,
        "the second page was not requested"
    );
}

#[tokio::test]
async fn a_link_to_another_host_is_never_followed() {
    let hostile = "<https://attacker.test/steal?page=2>; rel=\"next\"".to_owned();
    let (world, issue, overrides) = paged_world(Some(hostile), None);
    world
        .fake
        .label_issue(FIXTURE, issue.number, "late", "octocat");
    let outcome = world
        .adapter
        .issue_source()
        .label_actor(&intake(), &issue, "late")
        .await;
    assert_eq!(outcome, Err(GitHostError::Unavailable));
    assert!(
        overrides.targets_with("attacker").is_empty() && overrides.targets_with("steal").is_empty(),
        "no request went to or toward the foreign link"
    );
}

// ---- conditional reads and original text -----------------------------------------------------------

#[tokio::test]
async fn a_second_read_sends_the_validator_and_a_changed_issue_is_read_in_full() {
    let world = World::new();
    let issue = seeded_issue(&world);
    let source = world.adapter.issue_source();
    let first = source.fetch_issue(&intake(), &issue).await.unwrap();
    world.clock.advance(Duration::from_secs(30));
    let second = source.fetch_issue(&intake(), &issue).await.unwrap();
    assert_eq!(first.title, second.title);
    let statuses: Vec<u16> = world
        .fake
        .requests_to(ISSUE_ROUTE)
        .iter()
        .map(|r| r.status)
        .collect();
    assert_eq!(
        statuses,
        vec![200, 304],
        "the second read was a conditional one"
    );
    assert!(
        second.fetched_at > first.fetched_at,
        "and it is stamped with the time it was made"
    );
    world.clock.advance(Duration::from_secs(30));
    world
        .fake
        .edit_issue_body(FIXTURE, issue.number, "A new body.");
    let third = source.fetch_issue(&intake(), &issue).await.unwrap();
    assert_eq!(third.body, "A new body.");
}

#[tokio::test]
async fn the_original_issue_text_is_kept_apart_from_the_normalized_text() {
    let world = World::new();
    let hidden = "Add\u{200b} word\u{202e} count\r\nplease";
    let number = world
        .fake
        .add_issue(FIXTURE, hidden, hidden, "octocat", &[]);
    let issue = world
        .adapter
        .issue_source()
        .fetch_issue(
            &intake(),
            &IssueRef {
                repo: repo(),
                number,
            },
        )
        .await
        .unwrap();
    assert_eq!(issue.title, hidden, "the title is exactly as written");
    assert_eq!(issue.body, hidden, "the body is exactly as written");
    let normalized = factory_github::normalize_untrusted_text(&issue.body);
    assert_eq!(normalized.original, hidden);
    assert_eq!(normalized.normalized, "Add word count\nplease");
}

#[tokio::test]
async fn an_issue_number_that_is_a_pull_request_is_not_an_issue() {
    let world = World::new();
    let host = world.adapter.change_host();
    let pr: PullRequestRef = host
        .open_draft_pull_request(&delivery(), draft())
        .await
        .unwrap();
    let as_issue = IssueRef {
        repo: repo(),
        number: pr.number,
    };
    assert_eq!(
        world
            .adapter
            .issue_source()
            .fetch_issue(&delivery(), &as_issue)
            .await,
        Err(GitHostError::NotFound)
    );
    let state = host.pull_request_state(&delivery(), &pr).await.unwrap();
    assert_eq!(
        (state.lifecycle, state.draft),
        (PullRequestLifecycle::Open, true)
    );
}
