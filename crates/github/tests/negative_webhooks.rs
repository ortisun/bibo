//! Negative tests owned by the GitHub adapter, webhook part: NT-WH-02, NT-WH-03, NT-WH-06 and
//! NT-WH-09 (`docs/security/negative-test-catalog.md`).

mod common;

use common::harness::{FIXTURE, World};
use factory_domain::vocabulary::StageKind;
use factory_github::{GithubWebhookVerifier, WebhookSecret};
use factory_ports::githost::{
    ChangeHost, CommentTarget, GitScope, IssueRef, IssueSource, WebhookHeaders, WebhookHint,
    WebhookRejection, WebhookVerifier,
};
use factory_ports::paths::RepoRef;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::auth::{Allowlist, AllowlistEntry, Decision, DenyReason, Designation};
use factory_testkit::fx::github::{Delivery, Expect, FakeGithub, Reason, User};

fn headers_of(delivery: &Delivery) -> WebhookHeaders {
    // A server that sees a header twice hands the application one value, joined with a comma.
    let joined = |name: &str| {
        let all: Vec<&str> = delivery
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        (!all.is_empty()).then(|| all.join(", "))
    };
    WebhookHeaders {
        event: joined("X-GitHub-Event"),
        delivery: joined("X-GitHub-Delivery"),
        signature_256: joined("X-Hub-Signature-256"),
        content_type: joined("Content-Type"),
        has_legacy_signature: delivery.header("X-Hub-Signature").is_some(),
    }
}

fn verifier_for(fake: &FakeGithub) -> GithubWebhookVerifier {
    GithubWebhookVerifier::new(vec![
        WebhookSecret::new(fake.webhook_secret().as_bytes()).expect("a long secret"),
    ])
    .expect("a verifier")
}

fn labeled_issue_world() -> (World, u64) {
    let world = World::new();
    let number = world
        .fake
        .add_issue(FIXTURE, "Add word count", "Please.", "octocat", &[]);
    (world, number)
}

/// NT-WH-02: wrong secret, truncated, non-hex, uppercase prefix, only the SHA-1 header, extra
/// white space, a body changed by one byte, two signature headers.
#[test]
fn negative_nt_wh_02_every_forged_signature_is_refused_for_the_right_reason() {
    let (world, number) = labeled_issue_world();
    let verifier = verifier_for(&world.fake);
    let delivery = world
        .fake
        .issues_labeled(FIXTURE, number, "factory", "octocat");
    let secret = world.fake.webhook_secret();
    let attacks = delivery.attack_variants(&secret);
    assert!(
        attacks.len() >= 15,
        "the table of attacks: {}",
        attacks.len()
    );
    for attack in attacks {
        let outcome = verifier.verify(&attack.delivery.body, &headers_of(&attack.delivery));
        match attack.expect {
            Expect::Valid if attack.name == "duplicate_keys_validly_signed" => {
                // The signature is good; the body is ambiguous. Refused before anything reads it.
                assert_eq!(outcome, Err(WebhookRejection::Malformed), "{}", attack.name);
            }
            Expect::Valid => assert!(outcome.is_ok(), "{}: {outcome:?}", attack.name),
            Expect::Invalid(Reason::MissingHeader) => assert_eq!(
                outcome,
                Err(WebhookRejection::MissingHeader("X-Hub-Signature-256")),
                "{}",
                attack.name
            ),
            Expect::Invalid(Reason::LegacyHeaderOnly) => assert_eq!(
                outcome,
                Err(WebhookRejection::LegacySignatureOnly),
                "{}",
                attack.name
            ),
            Expect::Invalid(_) => {
                assert_eq!(
                    outcome,
                    Err(WebhookRejection::BadSignature),
                    "{}",
                    attack.name
                );
            }
        }
    }
}

/// NT-WH-02, the static half: the comparison is a constant-time primitive and there is no `==`
/// on a digest. The architecture check ST-02 also scans for it; this reads the source itself.
#[test]
fn negative_nt_wh_02_the_signature_is_compared_with_a_constant_time_primitive() {
    let source = include_str!("../src/webhook.rs");
    assert!(source.contains("ct_eq"), "the constant-time comparison");
    for line in source.lines().filter(|l| !l.trim_start().starts_with("//")) {
        let names_a_digest = ["expected", "provided", "digest", "presented", "mac"]
            .iter()
            .any(|word| line.contains(word));
        assert!(
            !(names_a_digest && (line.contains(" == ") || line.contains(" != "))),
            "a digest compared with an operator: {line}"
        );
    }
}

/// NT-WH-03: the raw bytes are what is checked. The same JSON written differently is refused with
/// the signature of the original; a body with a repeated key is refused; a forged request is
/// refused without its body being read.
#[test]
fn negative_nt_wh_03_the_raw_body_decides_and_the_body_is_read_only_after_it() {
    let (world, number) = labeled_issue_world();
    let verifier = verifier_for(&world.fake);
    let delivery = world
        .fake
        .issues_labeled(FIXTURE, number, "factory", "octocat");
    assert!(
        verifier
            .verify(&delivery.body, &headers_of(&delivery))
            .is_ok()
    );

    // The same document, written with other white space, under the original's signature.
    let value: serde_json::Value = serde_json::from_slice(&delivery.body).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert_ne!(pretty, delivery.body);
    assert_eq!(
        verifier.verify(&pretty, &headers_of(&delivery)),
        Err(WebhookRejection::BadSignature)
    );

    // A forged signature on a body that cannot be read at all is a signature problem, not a
    // problem with the body: the body was not looked at.
    let mut garbage = headers_of(&delivery);
    garbage.signature_256 = Some(format!("sha256={}", "0".repeat(64)));
    assert_eq!(
        verifier.verify(b"\xff\xfe not json at all {{{", &garbage),
        Err(WebhookRejection::BadSignature)
    );
    let deep = vec![b'['; 100_000];
    assert_eq!(
        verifier.verify(&deep, &garbage),
        Err(WebhookRejection::BadSignature),
        "a hundred thousand levels of nesting, forged"
    );
}

/// NT-WH-06: the payload is a hint. `closed` before `labeled`, a payload that claims an owner
/// labelled it and a label that is gone by the time the factory looks.
#[tokio::test]
async fn negative_nt_wh_06_the_payload_is_a_hint_and_the_live_state_decides() {
    let (world, number) = labeled_issue_world();
    let verifier = verifier_for(&world.fake);
    // An organisation owner who is not on the allowlist applies the label.
    world
        .fake
        .add_user(User::person("boss", 5, "admin", "OWNER"));
    world.fake.label_issue(FIXTURE, number, "factory", "boss");
    let closed = world
        .fake
        .issues_event("closed", FIXTURE, number, "octocat");
    let labeled = world
        .fake
        .issues_labeled(FIXTURE, number, "factory", "boss");
    // Out of order: `closed` is read before `labeled`. Both verify, as separate deliveries.
    let first = verifier
        .verify(&closed.body, &headers_of(&closed))
        .expect("closed verifies");
    let second = verifier
        .verify(&labeled.body, &headers_of(&labeled))
        .expect("labeled verifies");
    assert_ne!(first.semantic_key, second.semantic_key);
    assert!(matches!(second.hint, WebhookHint::IssueLabeled { .. }));
    // The payload carried the sender's role; nothing of it reached the hint.
    let payload = labeled.payload();
    assert_eq!(payload["issue"]["author_association"], "MEMBER");
    assert_eq!(payload["sender"]["id"], 5);

    // The label is taken off before the factory looks. The live API says so.
    world
        .fake
        .unlabel_issue(FIXTURE, number, "factory", "octocat");
    let scope = GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    };
    let issue_ref = IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    };
    let source = world.adapter.issue_source();
    let live = source.fetch_issue(&scope, &issue_ref).await.unwrap();
    assert!(
        !live.labels.iter().any(|l| l == "factory"),
        "the live labels: {:?}",
        live.labels
    );
    assert_eq!(
        source
            .label_actor(&scope, &issue_ref, "factory")
            .await
            .unwrap(),
        None
    );
    assert!(
        !world
            .fake
            .requests_to("GET /repos/{owner}/{repo}/issues/{number}")
            .is_empty(),
        "the state was fetched from the API"
    );

    // Applied again, the numeric id of the person comes from the event list, and the allowlist
    // alone decides: an owner who is not on it is a stranger.
    world.fake.label_issue(FIXTURE, number, "factory", "boss");
    let actor = source
        .label_actor(&scope, &issue_ref, "factory")
        .await
        .unwrap()
        .expect("applied");
    assert_eq!(actor.id, 5);
    let list = Allowlist::new(1).with(AllowlistEntry::new(
        77,
        "maintainer",
        &[Designation::Requester],
    ));
    let decision = list.decide(actor.id, Designation::Requester, 0);
    assert!(matches!(
        decision,
        Decision::Denied {
            reason: DenyReason::NotOnAllowlist,
            ..
        }
    ));
    assert!(
        world.fake.permission_lookups().is_empty(),
        "no collaborator permission lookup decided anything"
    );
}

/// NT-WH-09: the factory's own events and other bots' events are recorded and ignored.
#[tokio::test]
async fn negative_nt_wh_09_the_factorys_own_events_and_other_bots_events_are_ignored() {
    let (world, number) = labeled_issue_world();
    let verifier = verifier_for(&world.fake);
    let bot_login = world.fake.app().bot_login();
    let mut other = User::person("dependabot[bot]", 49_699_333, "none", "NONE");
    other.is_bot = true;
    world.fake.add_user(other);

    // The factory comments on the issue through the adapter, and GitHub reports it.
    let host = world.adapter.change_host();
    let scope = GitScope {
        stage: StageKind::Delivery,
        ..scope(1, 1)
    };
    let target = CommentTarget::Issue(IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    });
    host.post_comment(&scope, &target, "Validation passed.", "validation-1")
        .await
        .unwrap();
    let own = world
        .fake
        .issue_comment_created(FIXTURE, number, "Validation passed.", &bot_login);
    let theirs =
        world
            .fake
            .issue_comment_created(FIXTURE, number, "Bump the version", "dependabot[bot]");
    let person = world
        .fake
        .issue_comment_created(FIXTURE, number, "factory approve", "octocat");
    let own_label = world
        .fake
        .issues_labeled(FIXTURE, number, "factory", &bot_login);
    for (what, delivery) in [
        ("the factory's comment", &own),
        ("another bot's comment", &theirs),
        ("the factory's label", &own_label),
    ] {
        let verified = verifier
            .verify(&delivery.body, &headers_of(delivery))
            .expect("it verifies");
        assert_eq!(
            verified.hint,
            WebhookHint::Other,
            "{what} must not start anything"
        );
    }
    let verified = verifier
        .verify(&person.body, &headers_of(&person))
        .expect("it verifies");
    assert!(
        matches!(verified.hint, WebhookHint::CommentCreated { .. }),
        "a person's comment is acted on"
    );
}
