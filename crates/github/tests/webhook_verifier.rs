//! The webhook verifier: the shared contract suite, known answers from an independent script,
//! the size and depth limits, secret rotation and the replay filter against the store contract.

mod common;

use async_trait::async_trait;
use factory_domain::ids::{TenantId, WebhookDeliveryId};
use factory_domain::values::Sha256Digest;
use factory_github::{
    BadSecret, GithubWebhookVerifier, MAX_BODY_BYTES, MIN_SECRET_BYTES, NoSecrets, Replay,
    WebhookSecret, accept_delivery,
};
use factory_ports::clock::Uuid;
use factory_ports::githost::{WebhookHeaders, WebhookHint, WebhookRejection, WebhookVerifier};
use factory_ports::store::{DuplicateOf, Store};
use factory_testkit::clock::FakeClock;
use factory_testkit::contracts::webhook::{self, WebhookSubject};
use factory_testkit::fx::github::sign_sha256;
use factory_testkit::fx::rng::{ALPHANUMERIC, FxRng};
use factory_testkit::store::InMemoryStore;
use serde_json::Value;
use std::sync::Arc;

fn secret_text(rng: &mut FxRng) -> String {
    rng.string_from(ALPHANUMERIC, 48)
}

fn secret(text: &str) -> WebhookSecret {
    WebhookSecret::new(text.as_bytes()).expect("a long enough secret")
}

struct Secrets {
    current: String,
    previous: String,
    retired: String,
    unrelated: String,
}

impl Secrets {
    fn new() -> Self {
        let mut rng = FxRng::from_entropy();
        Self {
            current: secret_text(&mut rng),
            previous: secret_text(&mut rng),
            retired: secret_text(&mut rng),
            unrelated: secret_text(&mut rng),
        }
    }
}

struct Subject {
    verifier: GithubWebhookVerifier,
    secrets: Secrets,
}

impl Subject {
    fn new() -> Self {
        let secrets = Secrets::new();
        let verifier =
            GithubWebhookVerifier::new(vec![secret(&secrets.current), secret(&secrets.previous)])
                .expect("a verifier");
        Self { verifier, secrets }
    }
}

#[async_trait]
impl WebhookSubject for Subject {
    fn verifier(&self) -> &dyn WebhookVerifier {
        &self.verifier
    }
    fn sign_current(&self, body: &[u8]) -> String {
        sign_sha256(&self.secrets.current, body)
    }
    fn sign_previous(&self, body: &[u8]) -> String {
        sign_sha256(&self.secrets.previous, body)
    }
    fn sign_retired(&self, body: &[u8]) -> String {
        sign_sha256(&self.secrets.retired, body)
    }
    fn sign_unrelated(&self, body: &[u8]) -> String {
        sign_sha256(&self.secrets.unrelated, body)
    }
}

#[tokio::test]
async fn the_github_verifier_passes_the_webhook_contract() {
    let report = webhook::run(|| async { Subject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), webhook::checks().len());
}

fn headers(event: &str, delivery: &str, signature: String) -> WebhookHeaders {
    WebhookHeaders {
        event: Some(event.to_owned()),
        delivery: Some(delivery.to_owned()),
        signature_256: Some(signature),
        content_type: Some("application/json".to_owned()),
        has_legacy_signature: false,
    }
}

// ---- known answers from an independent script ------------------------------------------------

#[test]
fn known_answer_vectors_computed_by_python_verify_and_a_changed_digit_does_not() {
    let file: Value =
        serde_json::from_str(include_str!("vectors/webhook_known_answers.json")).unwrap();
    let vectors = file["vectors"].as_array().expect("a list of vectors");
    assert!(vectors.len() >= 4);
    for vector in vectors {
        let key = vector["key_text"].as_str().unwrap();
        let mut body = vector["body_text"]
            .as_str()
            .or_else(|| vector["body_start"].as_str())
            .unwrap()
            .as_bytes()
            .to_vec();
        if let Some(size) = vector["body_pad_to"].as_u64() {
            body.resize(usize::try_from(size).unwrap(), b' ');
        }
        let mac = vector["mac_hex"].as_str().unwrap();
        let verifier = GithubWebhookVerifier::new(vec![secret(key)]).unwrap();
        let good = headers("issues", "vector-0001", format!("sha256={mac}"));
        assert!(
            verifier.verify(&body, &good).is_ok(),
            "{}: the independent digest was refused",
            vector["name"]
        );
        let mut changed = mac.to_owned();
        let last = changed.pop().unwrap();
        changed.push(if last == '0' { '1' } else { '0' });
        let bad = headers("issues", "vector-0001", format!("sha256={changed}"));
        assert_eq!(
            verifier.verify(&body, &bad),
            Err(WebhookRejection::BadSignature),
            "{}",
            vector["name"]
        );
    }
}

// ---- secrets ---------------------------------------------------------------------------------

#[test]
fn a_weak_secret_and_an_empty_list_are_refused_and_a_secret_does_not_print() {
    assert_eq!(
        WebhookSecret::new(&[b'a'; MIN_SECRET_BYTES - 1]),
        Err(BadSecret::TooShort)
    );
    assert!(WebhookSecret::new(&[b'a'; MIN_SECRET_BYTES]).is_ok());
    assert_eq!(
        GithubWebhookVerifier::new(Vec::new()).err(),
        Some(NoSecrets)
    );
    let shown = format!("{:?}", secret(&"q".repeat(40)));
    assert!(!shown.contains("qqqq"), "{shown}");
}

// ---- limits ----------------------------------------------------------------------------------

#[test]
fn nesting_is_limited_and_the_limit_applies_only_after_the_signature_is_good() {
    let subject = Subject::new();
    let deep = format!("{}{}", "[".repeat(100), "]".repeat(100)).into_bytes();
    let signed = subject.sign_current(&deep);
    assert_eq!(
        subject
            .verifier
            .verify(&deep, &headers("issues", "delivery-0001", signed)),
        Err(WebhookRejection::Malformed)
    );
    // The same body with a bad signature is a bad signature: the body is not looked at.
    let forged = subject.sign_unrelated(&deep);
    assert_eq!(
        subject
            .verifier
            .verify(&deep, &headers("issues", "delivery-0001", forged)),
        Err(WebhookRejection::BadSignature)
    );
    // An ordinary payload nests about eight levels; thirty-two is accepted.
    let at_the_limit = format!(
        "{{\"installation\":{{\"id\":1}},\"action\":\"edited\",\"x\":{}1{}}}",
        "[".repeat(30),
        "]".repeat(30)
    )
    .into_bytes();
    let signed = subject.sign_current(&at_the_limit);
    assert!(
        subject
            .verifier
            .verify(&at_the_limit, &headers("issues", "delivery-0001", signed))
            .is_ok()
    );
}

#[test]
fn the_size_limit_is_checked_before_anything_else() {
    let subject = Subject::new();
    let body = vec![b' '; MAX_BODY_BYTES + 1];
    assert_eq!(
        subject.verifier.verify(&body, &WebhookHeaders::default()),
        Err(WebhookRejection::TooLarge),
        "even with no header at all"
    );
}

#[test]
fn a_key_that_appears_twice_is_malformed_even_when_the_signature_is_good() {
    let subject = Subject::new();
    let body = br#"{"action":"edited","action":"labeled","installation":{"id":1}}"#;
    let signed = subject.sign_current(body);
    assert_eq!(
        subject
            .verifier
            .verify(body, &headers("issues", "delivery-0001", signed)),
        Err(WebhookRejection::Malformed)
    );
    let nested = br#"{"action":"edited","installation":{"id":1,"id":2}}"#;
    let signed = subject.sign_current(nested);
    assert_eq!(
        subject
            .verifier
            .verify(nested, &headers("issues", "delivery-0001", signed)),
        Err(WebhookRejection::Malformed)
    );
}

// ---- the replay filter, against the store contract ---------------------------------------------

fn id(n: u128) -> WebhookDeliveryId {
    WebhookDeliveryId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

async fn store_transaction() -> Box<dyn factory_ports::store::Tx> {
    let clock = Arc::new(FakeClock::new());
    let store = InMemoryStore::new(clock);
    let tenant = TenantId::from_uuid(Uuid::from_u128(
        (9_u128 << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ));
    store.seed_repository(tenant);
    store
        .begin(factory_domain::scope::TenantScope::new(tenant))
        .await
        .expect("a tenant transaction")
}

fn labeled_body(label: &str) -> Vec<u8> {
    format!(
        r#"{{"action":"labeled","installation":{{"id":42}},"repository":{{"id":7,"full_name":"example-org/fixture"}},"sender":{{"id":77,"type":"User"}},"issue":{{"number":12,"node_id":"I_1","updated_at":"2026-10-28T10:00:00Z"}},"label":{{"name":"{label}"}}}}"#
    )
    .into_bytes()
}

#[tokio::test]
async fn a_delivery_is_recorded_once_and_a_replay_is_a_repeat_by_id_by_body_and_by_meaning() {
    let subject = Subject::new();
    let mut tx = store_transaction().await;

    let body = labeled_body("factory");
    let first = subject
        .verifier
        .verify(
            &body,
            &headers("issues", "delivery-0001", subject.sign_current(&body)),
        )
        .expect("a verified delivery");
    assert!(matches!(
        accept_delivery(&mut *tx, id(1), &first).await.unwrap(),
        Replay::New(_)
    ));

    // The same delivery id again (GitHub redelivers).
    assert_eq!(
        accept_delivery(&mut *tx, id(2), &first).await.unwrap(),
        Replay::Repeat(DuplicateOf::DeliveryId)
    );
    // The same bytes under a new delivery id (someone replays a captured request).
    let replayed = subject
        .verifier
        .verify(
            &body,
            &headers("issues", "delivery-0002", subject.sign_current(&body)),
        )
        .unwrap();
    assert_eq!(
        accept_delivery(&mut *tx, id(3), &replayed).await.unwrap(),
        Replay::Repeat(DuplicateOf::Body)
    );
    // Different bytes, same event on the same revision of the same issue by the same person.
    let spaced = [labeled_body("factory"), b" ".to_vec()].concat();
    let again = subject
        .verifier
        .verify(
            &spaced,
            &headers("issues", "delivery-0003", subject.sign_current(&spaced)),
        )
        .unwrap();
    assert_eq!(
        accept_delivery(&mut *tx, id(4), &again).await.unwrap(),
        Replay::Repeat(DuplicateOf::Semantic)
    );
    // Another label on the same issue in the same second is a different delivery.
    let other = labeled_body("other-label");
    let other = subject
        .verifier
        .verify(
            &other,
            &headers("issues", "delivery-0004", subject.sign_current(&other)),
        )
        .unwrap();
    assert!(matches!(
        accept_delivery(&mut *tx, id(5), &other).await.unwrap(),
        Replay::New(_)
    ));
}

#[test]
fn the_body_hash_and_the_hint_are_taken_from_the_exact_bytes() {
    let subject = Subject::new();
    let body = labeled_body("factory");
    let delivery = subject
        .verifier
        .verify(
            &body,
            &headers("issues", "delivery-0001", subject.sign_current(&body)),
        )
        .unwrap();
    assert_eq!(delivery.body_sha256, Sha256Digest::of(&body));
    assert_eq!(delivery.installation.0, 42);
    assert_eq!(delivery.sender_github_user_id, Some(77));
    assert!(delivery.semantic_key.is_some());
    assert!(
        matches!(delivery.hint, WebhookHint::IssueLabeled { ref label, .. } if label == "factory")
    );
}

#[test]
fn a_secret_in_the_rotation_window_verifies_and_the_two_secrets_are_both_tried() {
    let mut rng = FxRng::from_entropy();
    let (old, new) = (secret_text(&mut rng), secret_text(&mut rng));
    let verifier = GithubWebhookVerifier::new(vec![secret(&new), secret(&old)]).unwrap();
    let body = labeled_body("factory");
    for signer in [&old, &new] {
        assert!(
            verifier
                .verify(
                    &body,
                    &headers("issues", "delivery-0001", sign_sha256(signer, &body))
                )
                .is_ok()
        );
    }
    let after_retirement = GithubWebhookVerifier::new(vec![secret(&new)]).unwrap();
    assert_eq!(
        after_retirement.verify(
            &body,
            &headers("issues", "delivery-0001", sign_sha256(&old, &body))
        ),
        Err(WebhookRejection::BadSignature)
    );
}
