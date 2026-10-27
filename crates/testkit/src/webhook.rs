//! A fake webhook verifier (ports-v1.1, `WebhookVerifier`).
//!
//! It follows `policies/security.yaml` (`webhook`): the size limit, the required headers, the
//! content type, an `HMAC-SHA256` of the raw body compared in constant time against every secret
//! in the rotation window, the refusal of the legacy SHA-1 header on its own, and only then the
//! parse. The HMAC is built here from the SHA-256 in `factory-domain`, because this crate's list
//! of outside crates has no HMAC crate; a unit test checks it against the published test vector of
//! RFC 4231. The secrets are fixed test values, made at run time.
//!
//! The fake reads the fields the engine needs (event, action, installation, repository, sender)
//! and leaves the hint as `Other` and the semantic key empty: both depend on payload shapes that
//! the `github` adapter owns.

use std::collections::BTreeSet;
use std::sync::Mutex;

use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    VerifiedDelivery, WebhookHeaders, WebhookHint, WebhookRejection, WebhookVerifier,
};
use factory_ports::store::{GithubRepositoryId, InstallationId};

use crate::contracts::webhook::{MAX_BODY_BYTES, WebhookSubject};

/// The signature header, as the rejection names it.
pub const SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
/// The event header.
pub const EVENT_HEADER: &str = "X-GitHub-Event";
/// The delivery header.
pub const DELIVERY_HEADER: &str = "X-GitHub-Delivery";
/// The content type header.
pub const CONTENT_TYPE_HEADER: &str = "Content-Type";

/// The events and actions the factory accepts (`webhook.accepted_events`).
const ACCEPTED: &[(&str, &[&str])] = &[
    (
        "issues",
        &[
            "labeled",
            "edited",
            "closed",
            "reopened",
            "transferred",
            "deleted",
        ],
    ),
    ("issue_comment", &["created"]),
    (
        "pull_request",
        &["synchronize", "closed", "reopened", "edited"],
    ),
    ("pull_request_review", &["submitted", "dismissed"]),
];

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookDefect {
    /// Any signature value is accepted.
    AcceptsAnySignature,
    /// A signature without the `sha256=` prefix is accepted.
    AcceptsMissingPrefix,
    /// A delivery with only the legacy header is accepted without a check.
    AcceptsLegacyOnly,
    /// A delivery that has both headers is refused because of the legacy one.
    RefusesLegacyNextToSha256,
    /// Only the current secret is tried.
    IgnoresRotationWindow,
    /// A retired secret is tried as well.
    AcceptsRetiredSecrets,
    /// A missing event or delivery header is not noticed.
    SkipsHeaderChecks,
    /// Any content type is accepted.
    AcceptsAnyContentType,
    /// A body over the limit is read anyway.
    SkipsSizeLimit,
    /// The body is parsed before the signature is checked.
    ParsesBeforeVerifying,
    /// The hash is taken from the parsed and re-written body, not from the bytes received.
    HashesTheParsedBody,
    /// Any event and action is accepted.
    AcceptsAnyEvent,
    /// A delivery id of any length is accepted.
    AcceptsAnyDeliveryId,
    /// A second delivery with the same id is refused: the verifier keeps state that the store owns.
    RefusesAReplay,
    /// The fields are not read from the payload.
    ReadsNoFields,
    /// A body that is not the expected shape is accepted.
    AcceptsMalformedBodies,
}

/// The seeded defects and the checks that must fail for each. `contract_register` reads this
/// table, and `tests/webhook_contract.rs` runs it.
pub const DEFECTS: &[(WebhookDefect, &[&str])] = &[
    (
        WebhookDefect::AcceptsAnySignature,
        &["a_bad_signature_is_refused"],
    ),
    (
        WebhookDefect::AcceptsMissingPrefix,
        &["a_signature_without_the_prefix_is_refused"],
    ),
    (
        WebhookDefect::AcceptsLegacyOnly,
        &["a_legacy_header_alone_is_refused"],
    ),
    (
        WebhookDefect::RefusesLegacyNextToSha256,
        &["a_legacy_header_next_to_a_good_signature_is_ignored"],
    ),
    (
        WebhookDefect::IgnoresRotationWindow,
        &["a_secret_in_the_rotation_window_is_accepted"],
    ),
    (
        WebhookDefect::AcceptsRetiredSecrets,
        &["a_retired_secret_is_refused"],
    ),
    (
        WebhookDefect::SkipsHeaderChecks,
        &["a_missing_header_is_named"],
    ),
    (
        WebhookDefect::AcceptsAnyContentType,
        &["a_wrong_content_type_is_refused"],
    ),
    (
        WebhookDefect::SkipsSizeLimit,
        &["a_body_over_the_limit_is_refused"],
    ),
    (
        WebhookDefect::ParsesBeforeVerifying,
        &["the_signature_is_checked_before_the_body_is_parsed"],
    ),
    (
        WebhookDefect::HashesTheParsedBody,
        &["the_body_hash_is_the_hash_of_the_exact_bytes"],
    ),
    (
        WebhookDefect::AcceptsAnyEvent,
        &["an_event_or_action_off_the_list_is_unsupported"],
    ),
    (
        WebhookDefect::AcceptsAnyDeliveryId,
        &["a_delivery_id_outside_the_length_range_is_refused"],
    ),
    (
        WebhookDefect::RefusesAReplay,
        &["the_same_input_gives_the_same_result"],
    ),
    (
        WebhookDefect::ReadsNoFields,
        &["a_good_signature_is_accepted_and_the_fields_are_read"],
    ),
    (
        WebhookDefect::AcceptsMalformedBodies,
        &["a_body_that_is_not_the_expected_shape_is_malformed"],
    ),
];

/// The secrets of the fake, as bytes. Made at run time so that no secret-shaped literal sits in
/// the source.
fn secret(name: &str) -> Vec<u8> {
    format!("fake-webhook-{name}-value").into_bytes()
}

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => 0,
        })
        .collect();
    digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair.get(1).copied().unwrap_or(0))
        .collect()
}

/// `HMAC-SHA256(key, message)` as lower-case hex (RFC 2104 over the SHA-256 of the domain crate).
#[must_use]
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = unhex(Sha256Digest::of(key).hex());
        block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
    inner.extend_from_slice(message);
    let inner_hash = unhex(Sha256Digest::of(&inner).hex());
    let mut outer: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    outer.extend_from_slice(&inner_hash);
    Sha256Digest::of(&outer).hex().to_owned()
}

/// A comparison whose time does not depend on where the two values first differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// The fake verifier.
#[derive(Debug, Default)]
pub struct FakeWebhookVerifier {
    defect: Option<WebhookDefect>,
    seen: Mutex<BTreeSet<String>>,
}

impl FakeWebhookVerifier {
    /// A verifier that follows the contract.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A verifier with one deliberate fault.
    #[must_use]
    pub fn with_defect(defect: WebhookDefect) -> Self {
        Self {
            defect: Some(defect),
            seen: Mutex::new(BTreeSet::new()),
        }
    }

    fn has(&self, defect: WebhookDefect) -> bool {
        self.defect == Some(defect)
    }

    fn secrets(&self) -> Vec<Vec<u8>> {
        if self.has(WebhookDefect::IgnoresRotationWindow) {
            vec![secret("current")]
        } else if self.has(WebhookDefect::AcceptsRetiredSecrets) {
            vec![secret("current"), secret("previous"), secret("retired")]
        } else {
            vec![secret("current"), secret("previous")]
        }
    }

    fn signature_matches(&self, header: &str, body: &[u8]) -> bool {
        if self.has(WebhookDefect::AcceptsAnySignature) {
            return true;
        }
        let hex = match header.strip_prefix("sha256=") {
            Some(hex) => hex,
            None if self.has(WebhookDefect::AcceptsMissingPrefix) => header,
            None => return false,
        };
        self.secrets().iter().fold(false, |found, key| {
            found | constant_time_eq(hex.as_bytes(), hmac_sha256_hex(key, body).as_bytes())
        })
    }
}

impl WebhookVerifier for FakeWebhookVerifier {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn verify(
        &self,
        raw_body: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<VerifiedDelivery, WebhookRejection> {
        if raw_body.len() > MAX_BODY_BYTES && !self.has(WebhookDefect::SkipsSizeLimit) {
            return Err(WebhookRejection::TooLarge);
        }
        let skip_headers = self.has(WebhookDefect::SkipsHeaderChecks);
        let event = match (&headers.event, skip_headers) {
            (Some(event), _) => event.clone(),
            (None, true) => String::new(),
            (None, false) => return Err(WebhookRejection::MissingHeader(EVENT_HEADER)),
        };
        let delivery = match (&headers.delivery, skip_headers) {
            (Some(delivery), _) => delivery.clone(),
            (None, true) => String::new(),
            (None, false) => return Err(WebhookRejection::MissingHeader(DELIVERY_HEADER)),
        };
        if !(8..=128).contains(&delivery.len())
            && !self.has(WebhookDefect::AcceptsAnyDeliveryId)
            && !skip_headers
        {
            return Err(WebhookRejection::MissingHeader(DELIVERY_HEADER));
        }
        let legacy_only = headers.signature_256.is_none() && headers.has_legacy_signature;
        if headers.signature_256.is_none()
            && !(legacy_only && self.has(WebhookDefect::AcceptsLegacyOnly))
        {
            return Err(if legacy_only {
                WebhookRejection::LegacySignatureOnly
            } else {
                WebhookRejection::MissingHeader(SIGNATURE_HEADER)
            });
        }
        if headers.signature_256.is_some()
            && headers.has_legacy_signature
            && self.has(WebhookDefect::RefusesLegacyNextToSha256)
        {
            return Err(WebhookRejection::LegacySignatureOnly);
        }
        if !self.has(WebhookDefect::AcceptsAnyContentType) {
            match &headers.content_type {
                None => return Err(WebhookRejection::MissingHeader(CONTENT_TYPE_HEADER)),
                Some(value) => {
                    let media = value.split(';').next().unwrap_or("").trim();
                    if !media.eq_ignore_ascii_case("application/json") {
                        return Err(WebhookRejection::BadContentType);
                    }
                }
            }
        }
        if self.has(WebhookDefect::ParsesBeforeVerifying)
            && serde_json::from_slice::<serde_json::Value>(raw_body).is_err()
        {
            return Err(WebhookRejection::Malformed);
        }
        if let Some(signature) = &headers.signature_256
            && !self.signature_matches(signature, raw_body)
        {
            return Err(WebhookRejection::BadSignature);
        }
        if self.has(WebhookDefect::RefusesAReplay)
            && !self
                .seen
                .lock()
                .expect("the lock is never poisoned")
                .insert(delivery.clone())
        {
            return Err(WebhookRejection::BadSignature);
        }
        self.read(raw_body, &event, delivery)
    }
}

impl FakeWebhookVerifier {
    fn read(
        &self,
        raw_body: &[u8],
        event: &str,
        delivery: String,
    ) -> Result<VerifiedDelivery, WebhookRejection> {
        let parsed: Option<serde_json::Value> = serde_json::from_slice(raw_body).ok();
        let lenient = self.has(WebhookDefect::AcceptsMalformedBodies);
        let value = match parsed {
            Some(value) if value.is_object() => value,
            _ if lenient => serde_json::Value::Object(serde_json::Map::new()),
            _ => return Err(WebhookRejection::Malformed),
        };
        let number = |path: &[&str]| -> Option<u64> {
            let mut at = &value;
            for key in path {
                at = at.get(*key)?;
            }
            at.as_u64()
        };
        let installation = match number(&["installation", "id"]) {
            Some(id) => id,
            None if lenient || self.has(WebhookDefect::ReadsNoFields) => 0,
            None => return Err(WebhookRejection::Malformed),
        };
        let action = match value.get("action") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(text)) => Some(text.clone()),
            Some(_) if lenient => None,
            Some(_) => return Err(WebhookRejection::Malformed),
        };
        let event_slug = Slug::parse(event).map_err(|_| {
            if lenient || self.has(WebhookDefect::SkipsHeaderChecks) {
                WebhookRejection::UnsupportedEvent
            } else {
                WebhookRejection::Malformed
            }
        });
        if !self.has(WebhookDefect::AcceptsAnyEvent) {
            let listed = ACCEPTED.iter().any(|(name, actions)| {
                *name == event
                    && action
                        .as_deref()
                        .is_some_and(|action| actions.contains(&action))
            });
            if !listed {
                return Err(WebhookRejection::UnsupportedEvent);
            }
        }
        let event_slug = event_slug?;
        let action = match action {
            Some(text) => Some(Slug::parse(&text).map_err(|_| WebhookRejection::Malformed)?),
            None => None,
        };
        let reads = !self.has(WebhookDefect::ReadsNoFields);
        let body_sha256 = if self.has(WebhookDefect::HashesTheParsedBody) {
            Sha256Digest::of(&serde_json::to_vec(&value).unwrap_or_default())
        } else {
            Sha256Digest::of(raw_body)
        };
        Ok(VerifiedDelivery {
            delivery_id: delivery,
            event: event_slug,
            action: if reads { action } else { None },
            installation: InstallationId(installation),
            repository: number(&["repository", "id"])
                .filter(|_| reads)
                .map(GithubRepositoryId),
            sender_github_user_id: number(&["sender", "id"]).filter(|_| reads),
            body_sha256,
            semantic_key: None,
            hint: WebhookHint::Other,
        })
    }
}

/// The fake as a subject of the contract suite.
#[derive(Debug, Default)]
pub struct FakeWebhookSubject {
    verifier: FakeWebhookVerifier,
}

impl FakeWebhookSubject {
    /// A subject over a verifier that follows the contract.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A subject over a verifier with one deliberate fault.
    #[must_use]
    pub fn with_defect(defect: WebhookDefect) -> Self {
        Self {
            verifier: FakeWebhookVerifier::with_defect(defect),
        }
    }
}

impl WebhookSubject for FakeWebhookSubject {
    fn verifier(&self) -> &dyn WebhookVerifier {
        &self.verifier
    }

    fn sign_current(&self, body: &[u8]) -> String {
        format!("sha256={}", hmac_sha256_hex(&secret("current"), body))
    }

    fn sign_previous(&self, body: &[u8]) -> String {
        format!("sha256={}", hmac_sha256_hex(&secret("previous"), body))
    }

    fn sign_retired(&self, body: &[u8]) -> String {
        format!("sha256={}", hmac_sha256_hex(&secret("retired"), body))
    }

    fn sign_unrelated(&self, body: &[u8]) -> String {
        format!("sha256={}", hmac_sha256_hex(&secret("unrelated"), body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hmac_matches_the_rfc_4231_test_vector() {
        // Test case 1: a 20-byte key of 0x0b and the data "Hi There".
        let key = [0x0b_u8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn the_hmac_matches_the_rfc_4231_vector_with_a_key_longer_than_a_block() {
        // Test case 6: a 131-byte key of 0xaa.
        let key = [0xaa_u8; 131];
        assert_eq!(
            hmac_sha256_hex(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn the_constant_time_compare_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
