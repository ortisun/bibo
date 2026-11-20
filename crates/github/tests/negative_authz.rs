//! Negative tests for authority, as far as the GitHub adapter is concerned: NT-AUTHZ-01 to
//! NT-AUTHZ-04. The adapter does not authorize anyone. What it owes the decision is the numeric
//! id of the person, from the right place, with no GitHub role in the way.
//!
//! The decision here is the reference decision of the test kit (FX-AUTH), which has no parameter
//! for a role, an `author_association` or a login.

mod common;

use common::harness::{FIXTURE, World};
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{CommentRef, CommentTarget, GitScope, IssueRef, IssueSource};
use factory_ports::paths::RepoRef;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::auth::{Allowlist, AllowlistEntry, Decision, DenyReason, Designation};
use factory_testkit::fx::github::User;
use serde_json::json;

fn intake() -> GitScope {
    GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    }
}

fn list(version: u32, with_maintainer: bool) -> Allowlist {
    let mut list = Allowlist::new(version);
    if with_maintainer {
        list = list.with(AllowlistEntry::new(
            77,
            "maintainer",
            &[Designation::Requester, Designation::Approver],
        ));
    }
    list.with(AllowlistEntry::new(1, "octocat", &[Designation::Requester]))
}

fn issue_ref(number: u64) -> IssueRef {
    IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    }
}

#[tokio::test]
async fn negative_nt_authz_01_the_actor_is_the_numeric_id_and_a_lookalike_login_is_a_different_person()
 {
    let world = World::new();
    // The person on the allowlist (id 77) has renamed their account, and someone else (id 91)
    // has taken the old login. The allowlist entry still says "maintainer".
    world
        .fake
        .add_user(User::person("maintainer-renamed", 77, "write", "MEMBER"));
    world
        .fake
        .add_user(User::person("maintainer", 91, "admin", "OWNER"));
    let number = world
        .fake
        .add_issue(FIXTURE, "Add word count", "Please.", "octocat", &[]);
    let source = world.adapter.issue_source();
    let allowlist = list(1, true);

    world
        .fake
        .label_issue(FIXTURE, number, "factory", "maintainer");
    let who = source
        .label_actor(&intake(), &issue_ref(number), "factory")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((who.id, who.login.as_str()), (91, "maintainer"));
    let decision = allowlist.decide(who.id, Designation::Requester, 0);
    assert!(
        matches!(
            decision,
            Decision::Denied {
                reason: DenyReason::NotOnAllowlist,
                ..
            }
        ),
        "the login matches an entry and the id does not: {decision:?}"
    );

    let second = world
        .fake
        .add_issue(FIXTURE, "Add word count again", "Please.", "octocat", &[]);
    world
        .fake
        .label_issue(FIXTURE, second, "factory", "maintainer-renamed");
    let who = source
        .label_actor(&intake(), &issue_ref(second), "factory")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((who.id, who.login.as_str()), (77, "maintainer-renamed"));
    assert!(
        allowlist
            .decide(who.id, Designation::Requester, 0)
            .is_allowed(),
        "the id is on the list"
    );

    // A role grants nothing, and the adapter never asked GitHub what a role was.
    assert!(world.fake.permission_lookups().is_empty());
}

#[tokio::test]
async fn negative_nt_authz_01_a_label_that_came_with_issue_creation_names_its_author() {
    let world = World::new();
    // The author is not on the list and creates the issue with the label already on it.
    let number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "outsider",
        &["factory"],
    );
    let who = world
        .adapter
        .issue_source()
        .label_actor(&intake(), &issue_ref(number), "factory")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(who.id, 90);
    assert!(matches!(
        list(1, true).decide(who.id, Designation::Requester, 0),
        Decision::Denied {
            reason: DenyReason::NotOnAllowlist,
            ..
        }
    ));
}

#[tokio::test]
async fn negative_nt_authz_02_a_command_comment_arrives_with_its_authors_numeric_id() {
    let world = World::new();
    let source = world.adapter.issue_source();
    let seed = |id: u64, user_id: u64, login: &str, body: &str, edited: bool| {
        world.extras.comments.lock().unwrap().insert(
            (FIXTURE.to_owned(), id),
            json!({"id": id, "body": body,
                   "user": {"id": user_id, "login": login, "type": if login.ends_with("[bot]") {"Bot"} else {"User"}},
                   "created_at": "2026-10-28T10:00:00Z",
                   "updated_at": if edited { "2026-10-28T10:05:00Z" } else { "2026-10-28T10:00:00Z" },
                   "issue_url": format!("https://api.github.test/repos/{FIXTURE}/issues/12")}),
        );
    };
    seed(501, 77, "maintainer", "/factory approve", false);
    seed(502, 90, "outsider", "/factory approve", false);
    seed(
        503,
        424_242 + 1_000_000,
        "factory-test-app[bot]",
        "/factory approve",
        false,
    );
    seed(504, 77, "maintainer", "/factory approve", true);
    seed(505, 77, "maintainer", "```\n/factory approve\n```", false);
    let reference = |id: u64| CommentRef {
        target: CommentTarget::Issue(issue_ref(12)),
        id,
    };

    let allowlist = list(1, true);
    let approver = |id: u64| allowlist.decide(id, Designation::Approver, 0).is_allowed();

    let ok = source
        .fetch_comment(&intake(), &reference(501))
        .await
        .unwrap();
    assert!(approver(ok.author.id) && ok.edited_at.is_none());
    let stranger = source
        .fetch_comment(&intake(), &reference(502))
        .await
        .unwrap();
    assert!(
        !approver(stranger.author.id),
        "an outsider, whatever their role"
    );
    let bot = source
        .fetch_comment(&intake(), &reference(503))
        .await
        .unwrap();
    assert!(!approver(bot.author.id), "the factory's own bot");
    assert_eq!(
        bot.author.login.as_str(),
        "factory-test-app",
        "a bot login is shown without the suffix"
    );

    // An edited comment says so, so the engine can refuse to run it (NT-AUTHZ-03).
    let edited = source
        .fetch_comment(&intake(), &reference(504))
        .await
        .unwrap();
    assert!(edited.edited_at.is_some());
    // The text is returned exactly as written, so the engine sees the code fence.
    let fenced = source
        .fetch_comment(&intake(), &reference(505))
        .await
        .unwrap();
    assert_eq!(fenced.body, "```\n/factory approve\n```");

    // A comment of another issue cannot be passed off as this one's.
    let wrong_issue = CommentRef {
        target: CommentTarget::Issue(issue_ref(13)),
        id: 501,
    };
    assert_eq!(
        source.fetch_comment(&intake(), &wrong_issue).await,
        Err(factory_ports::githost::GitHostError::NotFound)
    );
    assert!(world.fake.permission_lookups().is_empty());
}

#[tokio::test]
async fn negative_nt_authz_04_removing_the_entry_removes_the_authority_and_the_decision_names_the_list()
 {
    let world = World::new();
    let number = world
        .fake
        .add_issue(FIXTURE, "Add word count", "Please.", "octocat", &[]);
    world
        .fake
        .label_issue(FIXTURE, number, "factory", "maintainer");
    let who = world
        .adapter
        .issue_source()
        .label_actor(&intake(), &issue_ref(number), "factory")
        .await
        .unwrap()
        .unwrap();
    // The GitHub role of the person does not change; the list does.
    let before = list(1, true);
    let after = list(2, false);
    assert!(before.decide(who.id, Designation::Approver, 0).is_allowed());
    let denied = after.decide(who.id, Designation::Approver, 0);
    match denied {
        Decision::Denied {
            reason: DenyReason::NotOnAllowlist,
            ref list_hash,
        } => {
            assert_ne!(
                list_hash.as_str(),
                before.hash(),
                "the decision records the new list"
            );
            assert_eq!(list_hash.as_str(), after.hash());
        }
        other => panic!("expected a denial, got {other:?}"),
    }
    assert!(world.fake.permission_lookups().is_empty());
}
