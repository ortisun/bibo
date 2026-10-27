use std::sync::{Arc, Mutex};

use super::webhook::{MAX_BODY_BYTES, verdict_matches};
use super::*;
use crate::fx::http::HttpServer;

fn world() -> FakeGithub {
    let github = FakeGithub::new();
    github
        .add_repo("acme/widgets", "main")
        .add_installation(77, "acme", &["acme/widgets"])
        .add_user(User::person("alice", 1001, "write", "MEMBER"))
        .add_user(User::person("mallory", 1002, "admin", "OWNER"));
    github
}

#[test]
fn signatures_match_the_example_in_githubs_own_documentation() {
    // The secret, payload and signature that GitHub publishes in its webhook validation page.
    // The SHA-1 value comes from Python's hmac module.
    let secret = "It's a Secret to Everybody";
    assert_eq!(
        sign_sha256(secret, b"Hello, World!"),
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    );
    assert_eq!(
        sign_sha1(secret, b"Hello, World!"),
        "sha1=01dc10d0c83e72ed246219cdd91669667fe2ca59"
    );
}

#[test]
fn a_delivery_carries_the_headers_github_sends_and_is_labelled_fake() {
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");

    assert_eq!(delivery.event, "issues");
    assert_eq!(delivery.header("X-GitHub-Event"), Some("issues"));
    assert_eq!(
        delivery.header("X-GitHub-Delivery"),
        Some(delivery.id.as_str())
    );
    assert_eq!(delivery.header("Content-Type"), Some("application/json"));
    assert_eq!(delivery.header("X-Factory-Fidelity"), Some("fake"));
    assert!(
        delivery
            .header("User-Agent")
            .unwrap()
            .starts_with("GitHub-Hookshot/")
    );
    // A version 4 identifier in the 8-4-4-4-12 layout.
    let parts: Vec<&str> = delivery.id.split('-').collect();
    assert_eq!(
        parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12]
    );
    assert!(parts[2].starts_with('4'));

    // Both signatures are over the raw body and under the fake's secret.
    let secret = github.webhook_secret();
    assert_eq!(
        delivery.header("X-Hub-Signature-256"),
        Some(sign_sha256(&secret, &delivery.body).as_str())
    );
    assert_eq!(
        delivery.header("X-Hub-Signature"),
        Some(sign_sha1(&secret, &delivery.body).as_str())
    );
    // Two deliveries never share an id.
    assert_ne!(
        delivery.id,
        github
            .issues_labeled("acme/widgets", number, "factory:go", "alice")
            .id
    );
}

#[test]
fn event_payloads_carry_what_githubs_do_and_nothing_the_allowlist_should_believe() {
    let github = world();
    // A stranger who is an organisation owner and has the admin role on the repository.
    let number = github.add_issue("acme/widgets", "Take over", "Do it.", "mallory", &[]);
    let payload = github
        .issues_labeled("acme/widgets", number, "factory:go", "mallory")
        .payload();
    assert_eq!(payload["action"], "labeled");
    assert_eq!(payload["label"]["name"], "factory:go");
    assert_eq!(payload["sender"]["id"], 1002);
    assert_eq!(payload["sender"]["login"], "mallory");
    assert_eq!(payload["issue"]["author_association"], "OWNER");
    assert_eq!(payload["issue"]["number"], number);
    assert_eq!(payload["installation"]["id"], 77);
    assert_eq!(payload["repository"]["full_name"], "acme/widgets");

    let comment = github
        .issue_comment_created("acme/widgets", number, "/factory approve", "mallory")
        .payload();
    assert_eq!(comment["comment"]["body"], "/factory approve");
    assert_eq!(comment["comment"]["author_association"], "OWNER");

    assert_eq!(github.ping().event, "ping");
    assert_eq!(
        github.installation_event("created", 77).payload()["installation"]["id"],
        77
    );
    assert_eq!(
        github
            .issues_event("edited", "acme/widgets", number, "mallory")
            .payload()["action"],
        "edited"
    );
}

#[test]
fn every_forged_variant_gets_the_verdict_the_table_says() {
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let secret = github.webhook_secret();
    let verifier = ReferenceVerifier::new(vec![secret.clone()]);

    let attacks = delivery.attack_variants(&secret);
    let names: Vec<&str> = attacks.iter().map(|a| a.name).collect();
    for needed in [
        "baseline",
        "missing_signature",
        "empty_signature",
        "wrong_secret",
        "truncated",
        "non_hex",
        "no_prefix",
        "uppercase_prefix",
        "space_inside_value",
        "sha1_header_only",
        "two_signature_headers_valid_first",
        "two_signature_headers_invalid_first",
        "body_changed_by_one_byte",
        "reserialized_pretty",
        "reserialized_key_order",
        "duplicate_keys_validly_signed",
    ] {
        assert!(names.contains(&needed), "the attack table lacks {needed}");
    }
    for attack in &attacks {
        let verdict = verifier.verify(&attack.delivery.headers, &attack.delivery.body);
        assert!(
            verdict_matches(verdict, attack.expect),
            "{}: the reference verifier said {verdict:?}, the table expects {:?}",
            attack.name,
            attack.expect
        );
    }
    // Exactly two entries are valid: the baseline and the validly signed duplicate-key body.
    let valid: Vec<&str> = attacks
        .iter()
        .filter(|a| a.expect == Expect::Valid)
        .map(|a| a.name)
        .collect();
    assert_eq!(valid, ["baseline", "duplicate_keys_validly_signed"]);
}

#[test]
fn the_one_byte_and_reserialised_variants_are_still_json() {
    // Otherwise a receiver could refuse them for the wrong reason: the body, not the signature.
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let secret = github.webhook_secret();
    for attack in delivery.attack_variants(&secret) {
        if matches!(
            attack.name,
            "body_changed_by_one_byte" | "reserialized_pretty" | "reserialized_key_order"
        ) {
            assert!(
                serde_json::from_slice::<Value>(&attack.delivery.body).is_ok(),
                "{} is not JSON",
                attack.name
            );
            assert_ne!(
                attack.delivery.body, delivery.body,
                "{} changed nothing",
                attack.name
            );
        }
    }
    let changed = delivery
        .attack_variants(&secret)
        .into_iter()
        .find(|a| a.name == "body_changed_by_one_byte")
        .unwrap();
    let differing = changed
        .delivery
        .body
        .iter()
        .zip(&delivery.body)
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(differing, 1, "exactly one byte must differ");
}

#[test]
fn a_verifier_that_ignores_the_signature_is_caught_by_the_table() {
    // Deliberate break: a verifier that accepts anything with a signature header present passes
    // the baseline and fails the table. If the table could not tell, it would prove nothing.
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let secret = github.webhook_secret();
    let lazy = |headers: &[(String, String)]| {
        if headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("X-Hub-Signature-256"))
        {
            Verdict::Valid { secret_index: 0 }
        } else {
            Verdict::Invalid(Reason::MissingHeader)
        }
    };
    let disagreements: Vec<&str> = delivery
        .attack_variants(&secret)
        .iter()
        .filter(|a| !verdict_matches(lazy(&a.delivery.headers), a.expect))
        .map(|a| a.name)
        .collect();
    assert!(
        disagreements.contains(&"wrong_secret")
            && disagreements.contains(&"body_changed_by_one_byte")
            && disagreements.len() >= 5,
        "the table must expose a lazy verifier: {disagreements:?}"
    );
}

#[test]
fn a_comparison_that_is_not_constant_time_is_not_what_the_reference_uses() {
    // The reference compares with constant_time_eq. A wrong value that shares a long prefix with
    // the right one is refused the same way as a totally wrong one.
    let secret = "s3cret";
    let body = b"{}";
    let good = sign_sha256(secret, body);
    let mut nearly = good.clone();
    nearly.pop();
    nearly.push(if good.ends_with('0') { '1' } else { '0' });
    let verifier = ReferenceVerifier::new(vec![secret.to_owned()]);
    let headers = |value: &str| vec![("X-Hub-Signature-256".to_owned(), value.to_owned())];
    assert_eq!(
        verifier.verify(&headers(&nearly), body),
        Verdict::Invalid(Reason::Mismatch)
    );
    assert_eq!(
        verifier.verify(&headers(&good), body),
        Verdict::Valid { secret_index: 0 }
    );
}

#[test]
fn a_replayed_delivery_id_is_acknowledged_once_and_ignored_after() {
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let mut receiver = ReferenceReceiver::new(github.accepted_webhook_secrets());

    let first = receiver.receive(&delivery.headers, &delivery.body);
    assert!(
        matches!(first, ReceiveOutcome::Accepted { ref delivery_id, .. } if delivery_id == &delivery.id)
    );
    // Fifty more of the same delivery: every one is a duplicate, none is processed again.
    let duplicates = (0..50)
        .filter(|_| {
            matches!(
                receiver.receive(&delivery.headers, &delivery.body),
                ReceiveOutcome::Duplicate { .. }
            )
        })
        .count();
    assert_eq!(duplicates, 50);
    assert_eq!(
        receiver.json_parses(),
        1,
        "a replay must not be parsed again"
    );
}

#[test]
fn a_forged_delivery_cannot_use_up_a_real_delivery_id() {
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let mut receiver = ReferenceReceiver::new(github.accepted_webhook_secrets());

    // The attacker sends the same id first, with a wrong signature. It is rejected, so the real
    // delivery that follows is still accepted.
    let forged = delivery.clone().with_header(
        "X-Hub-Signature-256",
        &sign_sha256("not-the-secret", &delivery.body),
    );
    assert_eq!(
        receiver.receive(&forged.headers, &forged.body),
        ReceiveOutcome::Rejected(Rejection::Signature(Reason::Mismatch))
    );
    assert!(matches!(
        receiver.receive(&delivery.headers, &delivery.body),
        ReceiveOutcome::Accepted { .. }
    ));
}

#[test]
fn nothing_is_parsed_before_the_signature_passes() {
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let secret = github.webhook_secret();
    let mut receiver = ReferenceReceiver::new(github.accepted_webhook_secrets());
    for attack in delivery.attack_variants(&secret) {
        if matches!(attack.expect, Expect::Invalid(_)) {
            let outcome = receiver.receive(&attack.delivery.headers, &attack.delivery.body);
            assert!(
                matches!(outcome, ReceiveOutcome::Rejected(Rejection::Signature(_))),
                "{}: {outcome:?}",
                attack.name
            );
        }
    }
    assert_eq!(receiver.json_parses(), 0, "a forged body was parsed");
}

#[test]
fn the_receiver_checks_headers_content_type_size_and_json() {
    let github = world();
    let secret = github.webhook_secret();
    let mut receiver = ReferenceReceiver::new(vec![secret.clone()]);
    let good = github.ping();

    for (header, expected) in [
        ("X-GitHub-Event", Rejection::MissingHeader("X-GitHub-Event")),
        (
            "X-GitHub-Delivery",
            Rejection::MissingHeader("X-GitHub-Delivery"),
        ),
    ] {
        let stripped = good.clone().without_header(header);
        assert_eq!(
            receiver.receive(&stripped.headers, &stripped.body),
            ReceiveOutcome::Rejected(expected)
        );
    }
    let wrong_type = good.clone().with_header("Content-Type", "text/plain");
    assert_eq!(
        receiver.receive(&wrong_type.headers, &wrong_type.body),
        ReceiveOutcome::Rejected(Rejection::WrongContentType)
    );
    // `application/json; charset=utf-8` is fine.
    let with_charset = good
        .clone()
        .with_header("Content-Type", "application/json; charset=utf-8");
    assert!(matches!(
        receiver.receive(&with_charset.headers, &with_charset.body),
        ReceiveOutcome::Accepted { .. }
    ));

    // Too large, even with a valid signature.
    let big_body = vec![b' '; MAX_BODY_BYTES + 1];
    let big = github
        .deliver_signed_with("ping", &json!({}), &secret)
        .with_body(big_body.clone())
        .with_header("X-Hub-Signature-256", &sign_sha256(&secret, &big_body));
    assert_eq!(
        receiver.receive(&big.headers, &big.body),
        ReceiveOutcome::Rejected(Rejection::BodyTooLarge)
    );

    // A valid signature on a body that is not JSON.
    let not_json = b"not json at all";
    let broken = github
        .deliver_signed_with("ping", &json!({}), &secret)
        .with_body(not_json.to_vec())
        .with_header("X-Hub-Signature-256", &sign_sha256(&secret, not_json));
    assert_eq!(
        receiver.receive(&broken.headers, &broken.body),
        ReceiveOutcome::Rejected(Rejection::InvalidJson)
    );
}

#[test]
fn during_a_rotation_both_secrets_work_and_after_it_only_the_new_one() {
    let github = world();
    let old_secret = github.webhook_secret();
    let old_delivery = github.ping();
    let new_secret = github.rotate_webhook_secret();
    assert_ne!(old_secret, new_secret);
    let new_delivery = github.ping();

    let overlap = ReferenceVerifier::new(github.accepted_webhook_secrets());
    assert_eq!(
        overlap.verify(&old_delivery.headers, &old_delivery.body),
        Verdict::Valid { secret_index: 1 }
    );
    assert_eq!(
        overlap.verify(&new_delivery.headers, &new_delivery.body),
        Verdict::Valid { secret_index: 0 }
    );

    github.retire_old_webhook_secrets();
    let after = ReferenceVerifier::new(github.accepted_webhook_secrets());
    assert_eq!(
        after.verify(&old_delivery.headers, &old_delivery.body),
        Verdict::Invalid(Reason::Mismatch)
    );
    assert!(
        after
            .verify(&new_delivery.headers, &new_delivery.body)
            .is_valid()
    );
}

#[test]
fn a_delivery_posted_to_a_server_arrives_byte_for_byte_and_still_verifies() {
    let github = world();
    let number = github.add_issue("acme/widgets", "Add a thing", "Please.", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");

    let captured = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    let server = HttpServer::start("webhook-under-test", move |request| {
        *sink.lock().unwrap() = Some(request.clone());
        crate::fx::http::HttpResponse::empty(202)
    })
    .unwrap();

    let response = delivery.post_to(server.addr(), "/webhook").unwrap();
    assert_eq!(response.status, 202);
    let received = captured.lock().unwrap().clone().unwrap();
    assert_eq!(received.method, "POST");
    assert_eq!(received.path(), "/webhook");
    assert_eq!(
        received.body, delivery.body,
        "the raw bytes must arrive unchanged"
    );
    assert_eq!(received.header("x-github-event"), Some("issues"));
    // The receiving side can verify what it got with the reference verifier.
    let verdict = ReferenceVerifier::new(github.accepted_webhook_secrets())
        .verify(&received.headers, &received.body);
    assert!(verdict.is_valid());
}
