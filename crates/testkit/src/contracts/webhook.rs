//! The contract suite for the `WebhookVerifier` port (`policies/security.yaml`, `webhook`).
//!
//! The port is pure, so the suite needs no clock and no store. It needs the one thing a black-box
//! test cannot reach, the secrets, so a subject signs a body with the current secret, with the
//! previous one (still inside the rotation window), with one that was retired and with one that
//! was never configured. A real adapter's subject does the same with its own test secrets.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::values::Sha256Digest;
use factory_ports::githost::{WebhookHeaders, WebhookRejection, WebhookVerifier};
use factory_ports::store::{GithubRepositoryId, InstallationId};

use super::{Check, Report, check_list, ensure, ensure_eq, ensure_err, run_checks};

/// The largest body the verifier reads (`webhook.max_body_bytes`).
pub const MAX_BODY_BYTES: usize = 1_048_576;

const INSTALLATION: u64 = 42;
const REPOSITORY: u64 = 7;
const SENDER: u64 = 99;
const DELIVERY: &str = "delivery-0001";

/// What the suite needs beyond the `WebhookVerifier` port itself.
#[async_trait]
pub trait WebhookSubject: Send + Sync {
    /// The verifier under test.
    fn verifier(&self) -> &dyn WebhookVerifier;

    /// The `X-Hub-Signature-256` value of `body` under the current secret.
    fn sign_current(&self, body: &[u8]) -> String;

    /// The value under the previous secret, which is still inside the rotation window.
    fn sign_previous(&self, body: &[u8]) -> String;

    /// The value under a secret that was retired and is no longer in the window.
    fn sign_retired(&self, body: &[u8]) -> String;

    /// The value under a secret the verifier never held.
    fn sign_unrelated(&self, body: &[u8]) -> String;
}

/// A check of the webhook verifier contract.
pub type WebhookCheck = Check<dyn WebhookSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: WebhookSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn WebhookSubject>
    })
    .await
}

/// Every check of the webhook verifier contract.
#[must_use]
pub fn checks() -> Vec<WebhookCheck> {
    check_list![dyn WebhookSubject;
        a_good_signature_is_accepted_and_the_fields_are_read,
        the_body_hash_is_the_hash_of_the_exact_bytes,
        a_bad_signature_is_refused,
        a_signature_without_the_prefix_is_refused,
        a_legacy_header_alone_is_refused,
        a_legacy_header_next_to_a_good_signature_is_ignored,
        a_secret_in_the_rotation_window_is_accepted,
        a_retired_secret_is_refused,
        a_missing_header_is_named,
        a_wrong_content_type_is_refused,
        a_body_over_the_limit_is_refused,
        the_signature_is_checked_before_the_body_is_parsed,
        a_body_that_is_not_the_expected_shape_is_malformed,
        an_event_or_action_off_the_list_is_unsupported,
        a_delivery_id_outside_the_length_range_is_refused,
        the_same_input_gives_the_same_result,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[super::Waiver] = &[];

fn body_for(action: &str) -> Vec<u8> {
    format!(
        "{{\"action\":\"{action}\",\"installation\":{{\"id\":{INSTALLATION}}},\
         \"repository\":{{\"id\":{REPOSITORY}}},\"sender\":{{\"id\":{SENDER}}}}}"
    )
    .into_bytes()
}

fn headers_with(signature: Option<String>) -> WebhookHeaders {
    WebhookHeaders {
        event: Some("issues".to_owned()),
        delivery: Some(DELIVERY.to_owned()),
        signature_256: signature,
        content_type: Some("application/json".to_owned()),
        has_legacy_signature: false,
    }
}

fn good_headers(subject: &dyn WebhookSubject, body: &[u8]) -> WebhookHeaders {
    headers_with(Some(subject.sign_current(body)))
}

async fn a_good_signature_is_accepted_and_the_fields_are_read(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let body = body_for("edited");
    let delivery = subject
        .verifier()
        .verify(&body, &good_headers(subject, &body));
    let delivery = delivery.map_err(|error| format!("a good delivery was refused: {error:?}"))?;
    ensure_eq!(
        delivery.delivery_id.as_str(),
        DELIVERY,
        "the delivery id comes from the header"
    );
    ensure_eq!(delivery.event.as_str(), "issues", "the event");
    ensure_eq!(
        delivery.action.as_ref().map(|action| action.as_str()),
        Some("edited"),
        "the action"
    );
    ensure_eq!(
        delivery.installation,
        InstallationId(INSTALLATION),
        "the installation"
    );
    ensure_eq!(
        delivery.repository,
        Some(GithubRepositoryId(REPOSITORY)),
        "the repository"
    );
    ensure_eq!(
        delivery.sender_github_user_id,
        Some(SENDER),
        "the numeric sender id"
    );
    Ok(())
}

async fn the_body_hash_is_the_hash_of_the_exact_bytes(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    // Extra white space and keys out of order: a parse and re-write would change the bytes.
    let body = format!(
        "{{ \"sender\" : {{\"id\":{SENDER}}},\n  \"action\":\"edited\",\n  \
         \"repository\":{{\"id\":{REPOSITORY}}}, \"installation\":{{\"id\":{INSTALLATION}}} }}"
    )
    .into_bytes();
    let delivery = subject
        .verifier()
        .verify(&body, &good_headers(subject, &body))
        .map_err(|error| format!("the delivery was refused: {error:?}"))?;
    ensure_eq!(
        delivery.body_sha256,
        Sha256Digest::of(&body),
        "the hash covers the bytes as received"
    );
    Ok(())
}

async fn a_bad_signature_is_refused(subject: &dyn WebhookSubject) -> Result<(), String> {
    let body = body_for("edited");
    let verifier = subject.verifier();
    let unrelated = headers_with(Some(subject.sign_unrelated(&body)));
    ensure_err!(
        verifier.verify(&body, &unrelated),
        WebhookRejection::BadSignature,
        "a signature under another secret"
    );
    // One hex digit changed.
    let mut tampered = subject.sign_current(&body);
    let last = tampered.pop().unwrap_or('0');
    tampered.push(if last == '0' { '1' } else { '0' });
    ensure_err!(
        verifier.verify(&body, &headers_with(Some(tampered))),
        WebhookRejection::BadSignature,
        "a signature with one digit changed"
    );
    // A signature of another body.
    let other = body_for("labeled");
    ensure_err!(
        verifier.verify(&body, &headers_with(Some(subject.sign_current(&other)))),
        WebhookRejection::BadSignature,
        "the signature of another body"
    );
    ensure_err!(
        verifier.verify(&body, &headers_with(Some(String::new()))),
        WebhookRejection::BadSignature,
        "an empty signature"
    );
    Ok(())
}

async fn a_signature_without_the_prefix_is_refused(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let body = body_for("edited");
    let signed = subject.sign_current(&body);
    let bare = signed.strip_prefix("sha256=").unwrap_or(&signed).to_owned();
    ensure_err!(
        subject.verifier().verify(&body, &headers_with(Some(bare))),
        WebhookRejection::BadSignature,
        "a correct digest without `sha256=`"
    );
    Ok(())
}

async fn a_legacy_header_alone_is_refused(subject: &dyn WebhookSubject) -> Result<(), String> {
    let body = body_for("edited");
    let mut headers = headers_with(None);
    headers.has_legacy_signature = true;
    ensure_err!(
        subject.verifier().verify(&body, &headers),
        WebhookRejection::LegacySignatureOnly,
        "only the SHA-1 header"
    );
    Ok(())
}

async fn a_legacy_header_next_to_a_good_signature_is_ignored(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let body = body_for("edited");
    let mut headers = good_headers(subject, &body);
    headers.has_legacy_signature = true;
    subject
        .verifier()
        .verify(&body, &headers)
        .map_err(|error| format!("a delivery with both headers was refused: {error:?}"))?;
    Ok(())
}

async fn a_secret_in_the_rotation_window_is_accepted(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let body = body_for("edited");
    subject
        .verifier()
        .verify(&body, &headers_with(Some(subject.sign_previous(&body))))
        .map_err(|error| format!("the previous secret was refused: {error:?}"))?;
    Ok(())
}

async fn a_retired_secret_is_refused(subject: &dyn WebhookSubject) -> Result<(), String> {
    let body = body_for("edited");
    ensure_err!(
        subject
            .verifier()
            .verify(&body, &headers_with(Some(subject.sign_retired(&body)))),
        WebhookRejection::BadSignature,
        "a secret outside the rotation window"
    );
    Ok(())
}

async fn a_missing_header_is_named(subject: &dyn WebhookSubject) -> Result<(), String> {
    let body = body_for("edited");
    let verifier = subject.verifier();

    let mut no_event = good_headers(subject, &body);
    no_event.event = None;
    match verifier.verify(&body, &no_event) {
        Err(WebhookRejection::MissingHeader(name)) => ensure!(
            name.eq_ignore_ascii_case("X-GitHub-Event"),
            "the missing event header was named {name}"
        ),
        other => {
            return Err(format!(
                "no event header: expected MissingHeader, found {other:?}"
            ));
        }
    }

    let mut no_delivery = good_headers(subject, &body);
    no_delivery.delivery = None;
    match verifier.verify(&body, &no_delivery) {
        Err(WebhookRejection::MissingHeader(name)) => ensure!(
            name.eq_ignore_ascii_case("X-GitHub-Delivery"),
            "the missing delivery header was named {name}"
        ),
        other => {
            return Err(format!(
                "no delivery header: expected MissingHeader, found {other:?}"
            ));
        }
    }

    match verifier.verify(&body, &headers_with(None)) {
        Err(WebhookRejection::MissingHeader(name)) => ensure!(
            name.eq_ignore_ascii_case("X-Hub-Signature-256"),
            "the missing signature header was named {name}"
        ),
        other => {
            return Err(format!(
                "no signature header: expected MissingHeader, found {other:?}"
            ));
        }
    }
    Ok(())
}

async fn a_wrong_content_type_is_refused(subject: &dyn WebhookSubject) -> Result<(), String> {
    let body = body_for("edited");
    for content_type in ["text/plain", "application/x-www-form-urlencoded"] {
        let mut headers = good_headers(subject, &body);
        headers.content_type = Some(content_type.to_owned());
        ensure_err!(
            subject.verifier().verify(&body, &headers),
            WebhookRejection::BadContentType,
            "the content type {content_type}"
        );
    }
    Ok(())
}

async fn a_body_over_the_limit_is_refused(subject: &dyn WebhookSubject) -> Result<(), String> {
    // Trailing white space keeps the JSON valid, so only the size can refuse it.
    let mut at_the_limit = body_for("edited");
    at_the_limit.resize(MAX_BODY_BYTES, b' ');
    subject
        .verifier()
        .verify(&at_the_limit, &good_headers(subject, &at_the_limit))
        .map_err(|error| format!("a body of exactly the limit was refused: {error:?}"))?;

    let mut over = body_for("edited");
    over.resize(MAX_BODY_BYTES + 1, b' ');
    ensure_err!(
        subject
            .verifier()
            .verify(&over, &good_headers(subject, &over)),
        WebhookRejection::TooLarge,
        "a body one byte over the limit"
    );
    Ok(())
}

async fn the_signature_is_checked_before_the_body_is_parsed(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    // A body that cannot be parsed, with a signature that cannot be right: the signature decides.
    let body = b"this is not json".to_vec();
    ensure_err!(
        subject
            .verifier()
            .verify(&body, &headers_with(Some(subject.sign_unrelated(&body)))),
        WebhookRejection::BadSignature,
        "a bad signature on a body that is not JSON"
    );
    Ok(())
}

async fn a_body_that_is_not_the_expected_shape_is_malformed(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let verifier = subject.verifier();
    let no_installation = b"{\"action\":\"edited\"}".to_vec();
    for (what, body) in [
        ("text", b"this is not json".to_vec()),
        ("an array", b"[1,2,3]".to_vec()),
        ("an object without an installation", no_installation),
    ] {
        ensure_err!(
            verifier.verify(&body, &good_headers(subject, &body)),
            WebhookRejection::Malformed,
            "a signed body that is {what}"
        );
    }
    Ok(())
}

async fn an_event_or_action_off_the_list_is_unsupported(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let verifier = subject.verifier();
    let body = body_for("edited");
    let mut push = good_headers(subject, &body);
    push.event = Some("push".to_owned());
    ensure_err!(
        verifier.verify(&body, &push),
        WebhookRejection::UnsupportedEvent,
        "an event that is not on the list"
    );
    let opened = body_for("opened");
    ensure_err!(
        verifier.verify(&opened, &good_headers(subject, &opened)),
        WebhookRejection::UnsupportedEvent,
        "an action that is not on the list for `issues`"
    );
    Ok(())
}

async fn a_delivery_id_outside_the_length_range_is_refused(
    subject: &dyn WebhookSubject,
) -> Result<(), String> {
    let body = body_for("edited");
    for id in ["short", &"x".repeat(129)] {
        let mut headers = good_headers(subject, &body);
        headers.delivery = Some(id.to_owned());
        ensure!(
            subject.verifier().verify(&body, &headers).is_err(),
            "a delivery id of {} bytes was accepted; the range is 8 to 128",
            id.len()
        );
    }
    Ok(())
}

async fn the_same_input_gives_the_same_result(subject: &dyn WebhookSubject) -> Result<(), String> {
    let body = body_for("edited");
    let headers = good_headers(subject, &body);
    let first = subject.verifier().verify(&body, &headers);
    let second = subject.verifier().verify(&body, &headers);
    ensure!(first.is_ok(), "the first delivery was refused: {first:?}");
    ensure_eq!(
        second,
        first,
        "the same delivery verified twice (de-duplication is the store's job, not the verifier's)"
    );
    Ok(())
}
