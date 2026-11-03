//! When the title and the body of an issue were last edited, read through the real adapter and the
//! fake GitHub server (DR-1 of the review of the design gate round two). The body edit is the one
//! read of GraphQL the adapter makes; the title edit is the `renamed` event of the issue.
//!
//! Nothing here ran against the real GitHub: that `lastEditedAt` is `null` for a body never edited
//! and moves on every edit is unverified (see `edits.rs`). Each test that shows a refusal has a
//! sibling that shows the same read passing.

mod common;

use std::time::Duration;

use common::harness::{FIXTURE, World};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::Clock;
use factory_ports::githost::{GitHostError, GitScope, IssueRef, IssueSource, TextEdit};
use factory_ports::paths::RepoRef;
use factory_testkit::contracts::githost::scope;

fn intake() -> GitScope {
    GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    }
}

fn issue_ref(number: u64) -> IssueRef {
    IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    }
}

fn new_issue(world: &World) -> u64 {
    world
        .fake
        .add_issue(FIXTURE, "Add word count", "Please.", "octocat", &[])
}

async fn edit_of(world: &World, number: u64) -> Result<TextEdit, GitHostError> {
    world
        .adapter
        .issue_source()
        .text_edit(&intake(), &issue_ref(number))
        .await
}

fn at(world: &World) -> Timestamp {
    world.clock.now()
}

#[tokio::test]
async fn an_issue_never_edited_is_never_edited() {
    let world = World::new();
    let number = new_issue(&world);
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::Never));
}

#[tokio::test]
async fn a_body_edit_is_the_time_of_the_edit() {
    let world = World::new();
    let number = new_issue(&world);
    world.clock.advance(Duration::from_secs(600));
    world
        .fake
        .edit_issue_body(FIXTURE, number, "Please, and delete the logs.");
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::At(at(&world))));
    // A later edit moves it.
    world.clock.advance(Duration::from_secs(60));
    world
        .fake
        .edit_issue_body(FIXTURE, number, "Please, again.");
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::At(at(&world))));
}

#[tokio::test]
async fn a_title_edit_counts_through_the_renamed_event() {
    let world = World::new();
    let number = new_issue(&world);
    world.clock.advance(Duration::from_secs(600));
    world.fake.rename_issue(
        FIXTURE,
        number,
        "Add word count and delete the logs",
        "octocat",
    );
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::At(at(&world))));
}

#[tokio::test]
async fn the_later_of_a_body_edit_and_a_title_edit_counts() {
    let world = World::new();
    let number = new_issue(&world);
    world.clock.advance(Duration::from_secs(600));
    world.fake.edit_issue_body(FIXTURE, number, "Edited body.");
    world.clock.advance(Duration::from_secs(600));
    world
        .fake
        .rename_issue(FIXTURE, number, "Edited title", "octocat");
    let later = at(&world);
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::At(later)));
    // The other way round: the body is edited after the title.
    let other = new_issue(&world);
    world.clock.advance(Duration::from_secs(600));
    world
        .fake
        .rename_issue(FIXTURE, other, "Edited title", "octocat");
    world.clock.advance(Duration::from_secs(600));
    world.fake.edit_issue_body(FIXTURE, other, "Edited body.");
    assert_eq!(edit_of(&world, other).await, Ok(TextEdit::At(at(&world))));
}

#[tokio::test]
async fn activity_that_is_not_an_edit_of_the_words_does_not_move_the_time() {
    // A label, a comment: the `updated_at` of the issue moves, the edit time does not.
    let world = World::new();
    let number = new_issue(&world);
    world.clock.advance(Duration::from_secs(600));
    world
        .fake
        .label_issue(FIXTURE, number, "factory", "octocat");
    world
        .fake
        .add_comment(FIXTURE, number, "maintainer", "I will look at it.");
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::Never));
}

#[tokio::test]
async fn a_host_that_fails_is_an_error_and_never_never() {
    let world = World::new();
    let number = new_issue(&world);
    world
        .fake
        .fail_next("POST /graphql", 500, "Internal Server Error");
    // The adapter retries a read that gets a 5xx a few times; make it fail every time.
    world
        .fake
        .fail_always("POST /graphql", 500, "Internal Server Error");
    assert!(edit_of(&world, number).await.is_err());
    // The sibling: the host comes back, and the same read answers.
    world.fake.clear_faults();
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::Never));
    // The events list failing is an error as well.
    world.fake.fail_always(
        "GET /repos/{owner}/{repo}/issues/{number}/events",
        500,
        "no",
    );
    assert!(edit_of(&world, number).await.is_err());
}

#[tokio::test]
async fn an_answer_that_is_not_a_time_or_an_explicit_null_is_unknown() {
    // The fake answers a GraphQL error in a 200, as GitHub does, for an issue it cannot find; the
    // adapter does not read that as "never edited".
    let world = World::new();
    let missing = edit_of(&world, 404).await;
    assert_eq!(missing, Ok(TextEdit::Unknown), "{missing:?}");
    // A token that may not read issues gets an `errors` body as well. The scope below is the
    // stage that holds the write token only for comments, which the fake models as no issue read.
    let number = new_issue(&world);
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::Never));
}

#[tokio::test]
async fn an_issue_of_another_repository_is_not_found_before_any_call() {
    let world = World::new();
    let number = new_issue(&world);
    let other = IssueRef {
        repo: RepoRef::parse("example-org/other").unwrap(),
        number,
    };
    let result = world
        .adapter
        .issue_source()
        .text_edit(&intake(), &other)
        .await;
    assert_eq!(result, Err(GitHostError::NotFound));
    assert!(world.fake.requests_to("POST /graphql").is_empty());
}

#[tokio::test]
async fn the_read_is_one_graphql_query_and_one_listing_with_the_narrow_intake_token() {
    let world = World::new();
    let number = new_issue(&world);
    edit_of(&world, number).await.unwrap();
    let queries = world.fake.requests_to("POST /graphql");
    assert_eq!(queries.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&queries[0].body).unwrap();
    let text = body["query"].as_str().unwrap();
    assert!(text.starts_with("query"), "{text}");
    assert!(!text.to_ascii_lowercase().contains("mutation"), "{text}");
    assert_eq!(body["variables"]["number"], number);
    assert_eq!(
        world
            .fake
            .requests_to("GET /repos/{owner}/{repo}/issues/{number}/events")
            .len(),
        1
    );
    // The token that made the calls holds `issues: read` and `metadata: read` and nothing more
    // (LB-03): the read of the edit time did not widen it.
    let mints = world.fake.mints();
    assert!(!mints.is_empty());
    for minted in &mints {
        assert_eq!(
            minted.requested_permissions,
            Some(
                [("issues", "read"), ("metadata", "read")]
                    .into_iter()
                    .map(|(n, l)| (n.to_owned(), l.to_owned()))
                    .collect()
            ),
            "{minted:?}"
        );
    }
}

#[tokio::test]
async fn a_list_of_events_that_is_cut_hides_a_later_rename_and_answers_unknown() {
    let world = World::new();
    let number = new_issue(&world);
    world.clock.advance(Duration::from_secs(60));
    world
        .fake
        .rename_issue(FIXTURE, number, "Renamed", "octocat");
    // More events than the adapter reads (30 pages of 100): the rename may be in the part not read.
    world
        .fake
        .add_events_of_no_interest(FIXTURE, number, 3_100, "octocat");
    assert_eq!(edit_of(&world, number).await, Ok(TextEdit::Unknown));
    // The sibling: a list that fits is read to its end.
    let short = new_issue(&world);
    world
        .fake
        .add_events_of_no_interest(FIXTURE, short, 250, "octocat");
    assert_eq!(edit_of(&world, short).await, Ok(TextEdit::Never));
}
