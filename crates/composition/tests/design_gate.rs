//! What the composition root gives the design gate of the intake stage (ADR 0016): the rule, read
//! from `policies/issue-workflow.yaml` at every attempt, and the comment that answers a person.
//!
//! The rule is a control. Every file that cannot be used gives **no rule**, and the health line says
//! so; each case sits beside the sound file that loads, so a failure is about the damage and not the
//! setup. The comment is posted through the fake change host of the test kit, labelled as a fake.

use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::design_gate::{FileDesignGatePolicy, IssueRefusalReplies};
use factory_composition::health::CheckStatus;
use factory_domain::ids::TenantId;
use factory_domain::policy::decision::Designation;
use factory_ports::githost::{CommentTarget, IssueRef};
use factory_ports::paths::RepoRef;
use factory_testkit::githost::FakeChangeHost;
use factory_workflow::stages::intake::seams::{DesignGatePolicy, RefusalReplies, SeamError};

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
        )
        .await
        .expect("posted");
    assert_eq!(host.comments_on(&target).len(), 2);
}
