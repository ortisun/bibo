//! What the design gate reads from the code host, through the real adapter and the fake GitHub
//! server on the loopback interface (security review of the design gate, findings DG-1, DG-2, DG-5
//! and DG-6). Nothing here ran against the real GitHub. Where the order or the paging of the
//! events matters, the fake can run either way, because the real order has not been observed.
//!
//! Each test that shows a refusal has a sibling that shows the same read passing.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::harness::{FIXTURE, Options, World};
use common::transports::{Overrides, answer};
use factory_domain::vocabulary::StageKind;
use factory_github::Method;
use factory_ports::githost::{AccountType, GitHostError, GitScope, IssueRef, IssueSource};
use factory_ports::paths::RepoRef;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::github::User;
use serde_json::json;

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

/// `octocat` has id 1, `maintainer` id 77: neither is special to the adapter.
const FIRST: &str = "octocat";
const LAST: &str = "maintainer";
const APPROVED: &str = "design: approved";

/// An issue with the approving label applied by `octocat` as the first event, then `noise` other
/// events, then applied again by `maintainer` as the last event. The events are listed in the
/// order `newest_first` says.
fn long_thread(world: &World, noise: usize, newest_first: bool) -> u64 {
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[]);
    world.fake.label_issue(FIXTURE, number, APPROVED, FIRST);
    world
        .fake
        .add_events_of_no_interest(FIXTURE, number, noise, FIRST);
    world.clock.advance(Duration::from_secs(3600));
    world.fake.unlabel_issue(FIXTURE, number, APPROVED, FIRST);
    world.fake.label_issue(FIXTURE, number, APPROVED, LAST);
    world
        .fake
        .list_events_newest_first(FIXTURE, number, newest_first);
    number
}

// ---- DG-1: the end of the list ------------------------------------------------------------------

#[tokio::test]
async fn the_latest_application_is_named_after_more_than_a_thousand_events_in_either_order() {
    // The old reader stopped at 1000 events and named `octocat`, whose application was event 2.
    // The list is now read to the end, and the person who applied the label last is named.
    for newest_first in [false, true] {
        for noise in [998, 999, 1000, 1100, 2500] {
            let world = World::new();
            let number = long_thread(&world, noise, newest_first);
            let found = world
                .adapter
                .issue_source()
                .label_application(&intake(), &issue_ref(number), APPROVED)
                .await
                .unwrap()
                .expect("the label is on the issue");
            assert_eq!(
                found.actor.id, 77,
                "{noise} events, newest first {newest_first}"
            );
            assert_eq!(found.actor_type, AccountType::User);
        }
    }
}

#[tokio::test]
async fn the_answer_is_the_same_whichever_way_the_list_runs() {
    let mut answers = Vec::new();
    for newest_first in [false, true] {
        let world = World::new();
        let number = long_thread(&world, 5, newest_first);
        answers.push(
            world
                .adapter
                .issue_source()
                .label_application(&intake(), &issue_ref(number), APPROVED)
                .await,
        );
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0].as_ref().unwrap().as_ref().unwrap().actor.id, 77);
}

#[tokio::test]
async fn a_list_that_is_still_cut_after_the_larger_cap_is_unavailable_in_both_arms() {
    // 3000 events are read. With more than that, a cut list answers nothing, whatever it holds:
    //  * the early application by `octocat` is in the part that was read (the arm that found one),
    //  * and with the order reversed the part that was read holds only the late one.
    for newest_first in [false, true] {
        let world = World::new();
        let number = long_thread(&world, 3100, newest_first);
        let source = world.adapter.issue_source();
        assert_eq!(
            source
                .label_application(&intake(), &issue_ref(number), APPROVED)
                .await,
            Err(GitHostError::Unavailable),
            "newest first {newest_first}"
        );
        assert_eq!(
            source
                .labels_ever_applied(&intake(), &issue_ref(number))
                .await,
            Err(GitHostError::Unavailable)
        );
        assert_eq!(
            source
                .label_actor(&intake(), &issue_ref(number), APPROVED)
                .await,
            Err(GitHostError::Unavailable)
        );
    }
    // The arm that found nothing: the label is on the issue and its only event is past the cut.
    let world = World::new();
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[]);
    world
        .fake
        .add_events_of_no_interest(FIXTURE, number, 3100, FIRST);
    world.fake.label_issue(FIXTURE, number, APPROVED, LAST);
    assert_eq!(
        world
            .adapter
            .issue_source()
            .label_application(&intake(), &issue_ref(number), APPROVED)
            .await,
        Err(GitHostError::Unavailable)
    );
}

#[tokio::test]
async fn an_honest_approval_after_event_one_thousand_is_named_and_a_label_not_there_is_none() {
    let world = World::new();
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[]);
    world
        .fake
        .add_events_of_no_interest(FIXTURE, number, 1100, FIRST);
    world.fake.label_issue(FIXTURE, number, APPROVED, LAST);
    let source = world.adapter.issue_source();
    let found = source
        .label_application(&intake(), &issue_ref(number), APPROVED)
        .await
        .unwrap()
        .expect("the label is on the issue");
    assert_eq!(found.actor.id, 77);
    assert_eq!(
        source
            .label_application(&intake(), &issue_ref(number), "not there")
            .await,
        Ok(None)
    );
}

#[tokio::test]
async fn a_label_that_was_taken_off_has_no_applier() {
    let world = World::new();
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[]);
    world.fake.label_issue(FIXTURE, number, APPROVED, FIRST);
    world.fake.unlabel_issue(FIXTURE, number, APPROVED, LAST);
    assert_eq!(
        world
            .adapter
            .issue_source()
            .label_application(&intake(), &issue_ref(number), APPROVED)
            .await,
        Ok(None)
    );
}

// ---- DG-2: the labels an issue ever had ----------------------------------------------------------

#[tokio::test]
async fn a_label_that_was_applied_and_taken_off_is_in_the_labels_ever_applied() {
    for newest_first in [false, true] {
        let world = World::new();
        let number = world.fake.add_issue(
            FIXTURE,
            "A new solution",
            "Words.",
            FIRST,
            &["design: proposed"],
        );
        world.fake.label_issue(FIXTURE, number, "bug", LAST);
        world
            .fake
            .unlabel_issue(FIXTURE, number, "design: proposed", LAST);
        world
            .fake
            .list_events_newest_first(FIXTURE, number, newest_first);
        assert_eq!(
            world.fake.labels_of(FIXTURE, number),
            vec!["bug".to_owned()]
        );
        assert_eq!(
            world
                .adapter
                .issue_source()
                .labels_ever_applied(&intake(), &issue_ref(number))
                .await,
            Ok(vec!["bug".to_owned(), "design: proposed".to_owned()])
        );
    }
}

#[tokio::test]
async fn an_issue_that_never_had_a_label_has_an_empty_history() {
    let world = World::new();
    let number = world
        .fake
        .add_issue(FIXTURE, "A small change", "Words.", FIRST, &[]);
    assert_eq!(
        world
            .adapter
            .issue_source()
            .labels_ever_applied(&intake(), &issue_ref(number))
            .await,
        Ok(Vec::new())
    );
}

// ---- DG-5: the kind of account --------------------------------------------------------------------

#[tokio::test]
async fn the_kind_of_account_that_applied_a_label_is_carried_through() {
    let world = World::new();
    let mut machine = User::person("ci-account", 5001, "write", "MEMBER");
    machine.is_bot = true;
    world.fake.add_user(machine);
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[]);
    world
        .fake
        .label_issue(FIXTURE, number, "factory", "ci-account");
    world.fake.label_issue(FIXTURE, number, APPROVED, LAST);
    let source = world.adapter.issue_source();
    let bot = source
        .label_application(&intake(), &issue_ref(number), "factory")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bot.actor.id, 5001);
    assert_eq!(bot.actor_type, AccountType::Bot);
    let person = source
        .label_application(&intake(), &issue_ref(number), APPROVED)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(person.actor_type, AccountType::User);
}

// ---- DG-6: an answer that is not whole -------------------------------------------------------------

/// The fake host's own answer for the issue, with `labels` replaced by `labels` (or removed).
fn issue_body(labels: Option<serde_json::Value>) -> serde_json::Value {
    let mut body = json!({
        "title": "A new solution",
        "body": "Words.",
        "user": {"id": 1, "login": "octocat", "type": "User"},
        "updated_at": "2026-10-28T10:00:00Z",
        "created_at": "2026-10-28T10:00:00Z",
    });
    if let Some(labels) = labels {
        body["labels"] = labels;
    }
    body
}

fn world_that_answers_the_issue_with(body: &serde_json::Value) -> (World, u64) {
    let rules = vec![(Method::Get, "/issues/", answer(200, &[], body))];
    let world = World::with(Options {
        wrap: Some(Box::new(move |inner| Overrides::new(inner, rules))),
        ..Options::default()
    });
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[APPROVED]);
    (world, number)
}

#[tokio::test]
async fn an_answer_with_no_whole_list_of_labels_is_unavailable_and_never_no_labels() {
    for odd in [
        None,
        Some(json!(null)),
        Some(json!("design: approved")),
        Some(json!({"name": "design: approved"})),
        Some(json!([1])),
        Some(json!([{"id": 3}])),
        Some(json!([{"name": 7}])),
        Some(json!([null])),
    ] {
        let (world, number) = world_that_answers_the_issue_with(&issue_body(odd.clone()));
        assert_eq!(
            world
                .adapter
                .issue_source()
                .fetch_issue(&intake(), &issue_ref(number))
                .await
                .map(|issue| issue.labels),
            Err(GitHostError::Unavailable),
            "{odd:?}"
        );
        // `label_application` reads the same member and says the same: it is not "label gone".
        let (world, number) = world_that_answers_the_issue_with(&issue_body(odd.clone()));
        assert_eq!(
            world
                .adapter
                .issue_source()
                .label_application(&intake(), &issue_ref(number), APPROVED)
                .await,
            Err(GitHostError::Unavailable),
            "{odd:?}"
        );
    }
}

#[tokio::test]
async fn a_whole_list_of_labels_is_read_as_it_is() {
    // The sibling: objects with a name, strings, and an empty list are all answers.
    for (labels, expected) in [
        (
            json!([{"name": "bug"}, {"name": "design: proposed"}]),
            vec!["bug", "design: proposed"],
        ),
        (json!(["bug"]), vec!["bug"]),
        (json!([]), Vec::new()),
    ] {
        let (world, number) = world_that_answers_the_issue_with(&issue_body(Some(labels.clone())));
        let read = world
            .adapter
            .issue_source()
            .fetch_issue(&intake(), &issue_ref(number))
            .await
            .unwrap()
            .labels;
        assert_eq!(read, expected, "{labels}");
    }
}

#[tokio::test]
async fn an_event_list_with_an_entry_that_is_not_whole_is_unavailable() {
    for odd in [
        json!([1]),
        json!([{"id": 1}]),
        json!([{"event": 4}]),
        json!([{"event": "labeled", "id": 1, "created_at": "2026-10-28T10:00:00Z", "label": {}}]),
        json!([{"event": "labeled", "id": 1, "label": {"name": "x"}, "actor": null}]),
        json!({"event": "labeled"}),
    ] {
        let rules = vec![(Method::Get, "/events", answer(200, &[], &odd))];
        let world = World::with(Options {
            wrap: Some(Box::new(move |inner| Overrides::new(inner, rules))),
            ..Options::default()
        });
        let number = world
            .fake
            .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[APPROVED]);
        let source = world.adapter.issue_source();
        assert_eq!(
            source
                .labels_ever_applied(&intake(), &issue_ref(number))
                .await,
            Err(GitHostError::Unavailable),
            "{odd}"
        );
    }
    // The sibling: a list of other kinds of events is a whole list.
    let rules = vec![(
        Method::Get,
        "/events",
        answer(
            200,
            &[],
            &json!([{"event": "closed"}, {"event": "subscribed"}]),
        ),
    )];
    let world = World::with(Options {
        wrap: Some(Box::new(move |inner| {
            let overrides: Arc<Overrides> = Overrides::new(inner, rules);
            overrides
        })),
        ..Options::default()
    });
    let number = world
        .fake
        .add_issue(FIXTURE, "A new solution", "Words.", FIRST, &[]);
    assert_eq!(
        world
            .adapter
            .issue_source()
            .labels_ever_applied(&intake(), &issue_ref(number))
            .await,
        Ok(Vec::new())
    );
}
