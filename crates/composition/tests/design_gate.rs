//! What the composition root gives the design gate of the intake stage (ADR 0016): the rule, read
//! from `policies/issue-workflow.yaml` at every attempt, and the comment that answers a person.
//!
//! The rule is a control. Every file that cannot be used gives **no rule**, and the health line says
//! so; each case sits beside the sound file that loads, so a failure is about the damage and not the
//! setup. The comment is posted through the fake change host of the test kit, labelled as a fake.

#![allow(dead_code)]

#[path = "../../github/tests/common/mod.rs"]
mod gh;

use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::design_gate::{FileDesignGatePolicy, IssueRefusalReplies};
use factory_composition::health::CheckStatus;
use factory_domain::ids::TenantId;
use factory_domain::policy::decision::Designation;
use factory_domain::policy::issue_workflow::{ReplyCap, ReplyKind};
use factory_ports::githost::{CommentTarget, IssueRef};
use factory_ports::paths::RepoRef;
use factory_testkit::githost::FakeChangeHost;
use factory_workflow::stages::intake::seams::{
    DesignGatePolicy, RefusalReplies, ReplyError, SeamError,
};
use gh::harness::{FIXTURE, World};

/// Five refusals in a day (the real policy says three; five makes the tests below longer than
/// they need to be).
fn the_cap() -> ReplyCap {
    ReplyCap::new(ReplyKind::Refusal, 5, 24).expect("a cap")
}

const FILE: &str = "policies/issue-workflow.yaml";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn real() -> String {
    std::fs::read_to_string(repo_root().join(FILE)).expect("the policy file")
}

fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert!(
        text.contains(from),
        "the policy file no longer contains `{from}`; update this test to the new text"
    );
    text.replacen(from, to, 1)
}

/// A protected checkout whose policy file has this text, or none.
fn checkout(name: &str, text: Option<&str>) -> PathBuf {
    let root = std::env::temp_dir().join(format!("design-gate-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policies")).expect("a directory");
    if let Some(text) = text {
        std::fs::write(root.join(FILE), text).expect("a file");
    }
    root
}

#[test]
fn the_real_policy_file_gives_the_rule_and_a_passing_health_line() {
    let source = FileDesignGatePolicy::new(repo_root());
    let gate = source.load().expect("the real policy gives a rule");
    assert_eq!(gate.approved_label(), "design: approved");
    assert_eq!(gate.approved_by(), Designation::Approver);
    let health = source.health_check();
    assert_eq!(health.status, CheckStatus::Pass, "{health:?}");
    assert!(health.detail.contains("design: approved"));
}

#[tokio::test]
async fn every_file_that_cannot_be_used_gives_no_rule_and_a_failing_health_line() {
    // The sibling: the sound file, copied into a checkout, gives the rule.
    let sound = checkout("sound", Some(&real()));
    let source = FileDesignGatePolicy::new(sound);
    assert!(source.load().is_ok());
    assert!(source.current().await.is_ok());

    let damaged: Vec<(&str, Option<String>)> = vec![
        ("no file", None),
        ("empty", Some(String::new())),
        ("not a policy", Some("this is not a policy\n".to_owned())),
        (
            "a schema version that is not 1",
            Some(replace_once(
                &real(),
                "schema_version: 1",
                "schema_version: 2",
            )),
        ),
        (
            "a key nobody knows",
            Some(replace_once(
                &real(),
                "intake_requirements:\n",
                "intake_requirements:\n  extra: true\n",
            )),
        ),
        (
            "no designation for the approver",
            Some(replace_once(
                &real(),
                "  design_approved_by: approver\n",
                "",
            )),
        ),
        (
            "the requester as the approver",
            Some(replace_once(
                &real(),
                "design_approved_by: approver",
                "design_approved_by: requester",
            )),
        ),
        (
            "a designation nobody holds",
            Some(replace_once(
                &real(),
                "design_approved_by: approver",
                "design_approved_by: everyone",
            )),
        ),
        (
            "a required state that is not a design state",
            Some(replace_once(
                &real(),
                "design_track_requires: approved",
                "design_track_requires: vanished",
            )),
        ),
        (
            "another policy",
            Some(replace_once(&real(), "id: issue-workflow", "id: approval")),
        ),
        (
            "a job state without a label",
            Some(replace_once(
                &real(),
                "    - { job_state: BLOCKED,           name: blocked,              color: \"b60205\", description: \"A check could not run, or something is missing. See the comment.\" }\n",
                "",
            )),
        ),
    ];
    for (name, text) in damaged {
        let source = FileDesignGatePolicy::new(checkout(&name.replace(' ', "-"), text.as_deref()));
        let reason = source.load().expect_err(name);
        assert!(
            reason.contains("policies/issue-workflow.yaml"),
            "{name}: {reason}"
        );
        assert!(
            !reason.contains("this is not a policy"),
            "{name}: the text of the file is not in the reason"
        );
        assert_eq!(
            source.current().await.expect_err(name),
            SeamError::Unavailable,
            "{name}"
        );
        let health = source.health_check();
        assert_eq!(health.status, CheckStatus::Fail, "{name}: {health:?}");
        assert!(
            health.detail.contains("Intake refuses every issue"),
            "{name}: {health:?}"
        );
    }
}

#[tokio::test]
async fn the_file_is_read_again_for_every_call_so_a_repair_and_a_breakage_both_take_effect() {
    let root = checkout("again", Some(&real()));
    let source = FileDesignGatePolicy::new(root.clone());
    assert!(source.current().await.is_ok());
    // Broken after the worker started: the next attempt has no rule.
    std::fs::write(root.join(FILE), "broken: [\n").expect("a file");
    assert_eq!(
        source.current().await.expect_err("broken"),
        SeamError::Unavailable
    );
    // Repaired: the next attempt has the rule again, with no restart.
    std::fs::write(root.join(FILE), real()).expect("a file");
    assert!(source.current().await.is_ok());
}

#[tokio::test]
async fn a_reply_is_one_comment_on_the_issue_for_each_key() {
    let host = Arc::new(FakeChangeHost::new());
    let replies = IssueRefusalReplies::new(
        host.clone(),
        Arc::new(factory_composition::system::RandomIds::new().expect("random")),
    );
    let issue = IssueRef {
        repo: RepoRef::parse("org/repo-0").expect("a repository"),
        number: 12,
    };
    let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(7));
    let target = CommentTarget::Issue(issue.clone());
    replies
        .post(
            tenant,
            &issue,
            "design-gate-run-1",
            "The design is not approved yet.",
            &the_cap(),
        )
        .await
        .expect("posted");
    // The same key again (a retry of the same stage run): still one comment.
    replies
        .post(
            tenant,
            &issue,
            "design-gate-run-1",
            "The design is not approved yet.",
            &the_cap(),
        )
        .await
        .expect("posted");
    assert_eq!(host.comments_on(&target).len(), 1);
    // Another stage run is another key and gets its own comment.
    replies
        .post(
            tenant,
            &issue,
            "design-gate-run-2",
            "The design is not approved yet.",
            &the_cap(),
        )
        .await
        .expect("posted");
    assert_eq!(host.comments_on(&target).len(), 2);
}

// ---- DG-9: the cap, the bounded look, and the token of the reply ----------------------------------

/// The replies of the worker over the real adapter and the fake GitHub server, for the tenant and
/// the repository the harness binds. Returns the world, the replies and the issue.
fn over_the_adapter() -> (World, IssueRefusalReplies, TenantId, IssueRef) {
    let world = World::new();
    let number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "octocat",
        &["factory"],
    );
    let replies = IssueRefusalReplies::new(
        Arc::new(world.adapter.change_host()),
        Arc::new(factory_composition::system::RandomIds::new().expect("random")),
    );
    let tenant = factory_testkit::contracts::githost::scope(1, 1).tenant;
    let issue = IssueRef {
        repo: RepoRef::parse(FIXTURE).expect("a repository"),
        number,
    };
    (world, replies, tenant, issue)
}

fn every_token_is_revoked(world: &World) {
    let tokens = world.fake.tokens();
    assert!(!tokens.is_empty(), "the reply minted a token");
    assert!(
        tokens.iter().all(|token| token.revoked_at.is_some()),
        "a token of a reply was left live: {tokens:?}"
    );
}

#[tokio::test]
async fn the_sixth_reply_of_a_day_on_one_issue_is_not_posted() {
    let (world, replies, tenant, issue) = over_the_adapter();
    for n in 1..=5 {
        replies
            .post(
                tenant,
                &issue,
                &format!("design-gate-{n}"),
                "Not yet.",
                &the_cap(),
            )
            .await
            .unwrap_or_else(|error| panic!("{n}: {error:?}"));
    }
    assert_eq!(
        replies
            .post(tenant, &issue, "design-gate-6", "Not yet.", &the_cap())
            .await,
        Err(ReplyError::CapReached)
    );
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 5);
    // The same stage run again is the same reply, found and not posted.
    assert_eq!(
        replies
            .post(tenant, &issue, "design-gate-3", "Not yet.", &the_cap())
            .await,
        Ok(())
    );
    every_token_is_revoked(&world);
}

#[tokio::test]
async fn a_thread_too_long_to_check_gets_no_reply() {
    let (world, replies, tenant, issue) = over_the_adapter();
    for n in 0..350 {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &format!("comment {n}"));
    }
    assert_eq!(
        replies
            .post(tenant, &issue, "design-gate-1", "Not yet.", &the_cap())
            .await,
        Err(ReplyError::NotChecked)
    );
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 350);
    every_token_is_revoked(&world);
}

#[tokio::test]
async fn a_hundred_and_thirty_comments_of_strangers_no_longer_silence_the_reply() {
    // DR-4. One page of 100 was enough to make the factory post nothing on an issue. The look is
    // three pages now, so the same thread gets its reply.
    let (world, replies, tenant, issue) = over_the_adapter();
    for n in 0..130 {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &format!("comment {n}"));
    }
    replies
        .post(tenant, &issue, "design-gate-1", "Not yet.", &the_cap())
        .await
        .expect("posted");
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 131);
}

#[tokio::test]
async fn each_kind_of_reply_has_its_own_cap_through_the_poster() {
    // DR-4. The poster marks a reply with the family of its kind, so the refusals, the withdrawal
    // and the notice about the environment are counted apart: a refusal cap that is used up does
    // not stop the other two.
    let (world, replies, tenant, issue) = over_the_adapter();
    let cap = |kind| ReplyCap::new(kind, 1, 24).expect("a cap");
    let (refusal, withdrawal, environment) = (
        cap(ReplyKind::Refusal),
        cap(ReplyKind::Withdrawal),
        cap(ReplyKind::Environment),
    );
    replies
        .post(tenant, &issue, "design-gate-1", "Not yet.", &refusal)
        .await
        .expect("a refusal");
    assert_eq!(
        replies
            .post(tenant, &issue, "design-gate-2", "Not yet, again.", &refusal)
            .await,
        Err(ReplyError::CapReached)
    );
    replies
        .post(tenant, &issue, "design-recheck-1", "Stopped.", &withdrawal)
        .await
        .expect("the withdrawal has its own room");
    replies
        .post(
            tenant,
            &issue,
            "environment-1",
            "Not available.",
            &environment,
        )
        .await
        .expect("so does the notice about the environment");
    assert_eq!(
        replies
            .post(tenant, &issue, "design-recheck-2", "Stopped.", &withdrawal)
            .await,
        Err(ReplyError::CapReached)
    );
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 3);
}

#[tokio::test]
async fn the_token_of_a_reply_is_revoked_whether_it_was_posted_capped_cut_or_will_be_retried() {
    // DG-9 (c). A comment endpoint that is down leaves the reply to be retried (`Later`), and the
    // token was kept for the retry until now. Every outcome ends it.
    let (world, replies, tenant, issue) = over_the_adapter();
    // Posted.
    replies
        .post(tenant, &issue, "design-gate-1", "Not yet.", &the_cap())
        .await
        .expect("posted");
    every_token_is_revoked(&world);
    // The comment endpoint is down: the listing fails, and the reply is for later.
    world.fake.fail_always(
        "GET /repos/{owner}/{repo}/issues/{number}/comments",
        503,
        "down",
    );
    let before = world.fake.tokens().len();
    assert_eq!(
        replies
            .post(tenant, &issue, "design-gate-2", "Not yet.", &the_cap())
            .await,
        Err(ReplyError::Later)
    );
    assert!(world.fake.tokens().len() > before, "a token was minted");
    every_token_is_revoked(&world);
    // The endpoint takes the listing and fails the post.
    world.fake.clear_faults();
    world.fake.fail_always(
        "POST /repos/{owner}/{repo}/issues/{number}/comments",
        503,
        "down",
    );
    assert_eq!(
        replies
            .post(tenant, &issue, "design-gate-3", "Not yet.", &the_cap())
            .await,
        Err(ReplyError::Later)
    );
    every_token_is_revoked(&world);
    // The host refuses (the issue is gone): final, and revoked.
    world.fake.clear_faults();
    let gone = IssueRef {
        repo: issue.repo.clone(),
        number: 9_999,
    };
    assert_eq!(
        replies
            .post(tenant, &gone, "design-gate-4", "Not yet.", &the_cap())
            .await,
        Err(ReplyError::NotSent)
    );
    every_token_is_revoked(&world);
}

#[tokio::test]
async fn a_cap_of_zero_cannot_be_made_and_so_cannot_be_asked_for() {
    // DG-9 (a). The type that carries the cap is built only from a number that is in range.
    for kind in ReplyKind::ALL {
        assert!(ReplyCap::new(kind, 0, 24).is_none());
        assert!(ReplyCap::new(kind, 5, 0).is_none());
        assert!(ReplyCap::new(kind, 101, 24).is_none());
        assert!(ReplyCap::new(kind, 5, 169).is_none());
        assert!(ReplyCap::new(kind, 5, 24).is_some());
        // And the closed value for a rule that cannot be read is one a day, of the same kind.
        let closed = ReplyCap::when_the_policy_cannot_be_read(kind);
        assert_eq!(closed.max(), 1);
        assert_eq!(closed.kind(), kind);
    }
}
