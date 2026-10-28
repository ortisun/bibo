//! Webhook intake: the verifier and the replay filter.
//!
//! [`GithubWebhookVerifier`] is the `WebhookVerifier` port for GitHub. It is pure and
//! synchronous: the secrets are given when it is built, it reads no clock and no store, and a
//! forged request touches nothing. In this order:
//!
//! 1. the body size limit (1 MiB),
//! 2. the required headers, the delivery id shape and the content type,
//! 3. `HMAC-SHA256(secret, raw body)` against the `sha256=` header, compared in constant time
//!    against every secret in the rotation window. A delivery that has only the legacy SHA-1
//!    header is refused. The raw bytes are used: the body is not parsed, re-written or trimmed
//!    first,
//! 4. only now the body is read: nesting depth at most 32, no duplicate key anywhere (two parsers
//!    that pick different copies of a key are a way to forge a field), an object, with an
//!    installation id.
//!
//! The payload is a hint. The verifier reads identifiers from it (the installation, repository and
//! sender ids, the issue or pull request number, the comment id, the label name) and nothing else:
//! not the issue state, not the labels on the issue, not `author_association`, not a role. The
//! engine fetches the live state before it acts. A delivery whose sender is a bot, which includes
//! everything the factory's own App does, is recorded and gets the hint `Other`, so the factory
//! never reacts to its own comments, pushes or pull requests.
//!
//! [`accept_delivery`] is the replay filter. It records a verified delivery in the store and says
//! whether it is new or a repeat by delivery id, by body hash or by semantic key. Replay
//! protection is the factory's job: GitHub signs no timestamp.
//!
//! UNVERIFIED against the real GitHub: that `issue.pull_request` is present for a comment on a pull
//! request and absent for a comment on an issue (the documentation read does not say so). The
//! fixture in `tests/fixtures/` is written from the documented shape, not recorded from a real
//! delivery.

use factory_domain::ids::WebhookDeliveryId;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    CommentRef, CommentTarget, IssueRef, PullRequestRef, VerifiedDelivery, WebhookHeaders,
    WebhookHint, WebhookRejection, WebhookVerifier,
};
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    DeliveryOps, DeliveryOutcome, DuplicateOf, GithubRepositoryId, InstallationId,
    NewWebhookDelivery, StoreError,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The largest body read (`webhook.max_body_bytes`).
pub const MAX_BODY_BYTES: usize = 1_048_576;

/// The deepest nesting accepted in a body. Real deliveries nest about eight levels.
pub const MAX_DEPTH: usize = 32;

/// The shortest webhook secret accepted: 256 bits of entropy in hex is 64 characters; this is the
/// byte floor that refuses an obviously weak value.
pub const MIN_SECRET_BYTES: usize = 32;

const SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
const EVENT_HEADER: &str = "X-GitHub-Event";
const DELIVERY_HEADER: &str = "X-GitHub-Delivery";
const CONTENT_TYPE_HEADER: &str = "Content-Type";

/// The events and actions the factory accepts (`webhook.accepted_events` in the policy).
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

/// A webhook secret. It never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(Vec<u8>);

impl std::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

/// A secret was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BadSecret {
    /// Shorter than [`MIN_SECRET_BYTES`].
    #[error("a webhook secret must be at least {MIN_SECRET_BYTES} bytes")]
    TooShort,
}

impl WebhookSecret {
    /// Wraps a secret.
    ///
    /// # Errors
    /// [`BadSecret::TooShort`] for fewer than [`MIN_SECRET_BYTES`] bytes.
    pub fn new(value: &[u8]) -> Result<Self, BadSecret> {
        if value.len() < MIN_SECRET_BYTES {
            Err(BadSecret::TooShort)
        } else {
            Ok(Self(value.to_vec()))
        }
    }
}

/// The verifier holds no secret to build with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a webhook verifier needs at least one secret")]
pub struct NoSecrets;

/// The webhook verifier for GitHub.
#[derive(Debug, Clone)]
pub struct GithubWebhookVerifier {
    secrets: Vec<WebhookSecret>,
}

impl GithubWebhookVerifier {
    /// A verifier that accepts a signature made with any of these secrets (more than one during
    /// a rotation).
    ///
    /// # Errors
    /// [`NoSecrets`] for an empty list.
    pub fn new(secrets: Vec<WebhookSecret>) -> Result<Self, NoSecrets> {
        if secrets.is_empty() {
            Err(NoSecrets)
        } else {
            Ok(Self { secrets })
        }
    }

    /// True when `value` is `sha256=` and 64 lower-case hex digits that match the HMAC of `body`
    /// under at least one secret. Every secret is tried, so the time taken does not say which
    /// one matched.
    fn matches(&self, value: &str, body: &[u8]) -> bool {
        let Some(digits) = value.strip_prefix("sha256=") else {
            return false;
        };
        let well_formed = digits.len() == 64
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let Ok(provided) = hex::decode(digits) else {
            return false;
        };
        if !well_formed {
            return false;
        }
        let mut found = subtle::Choice::from(0);
        for secret in &self.secrets {
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&secret.0) else {
                continue;
            };
            mac.update(body);
            let expected = mac.finalize().into_bytes();
            found |= expected.as_slice().ct_eq(provided.as_slice());
        }
        bool::from(found)
    }
}

impl WebhookVerifier for GithubWebhookVerifier {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn verify(
        &self,
        raw_body: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<VerifiedDelivery, WebhookRejection> {
        if raw_body.len() > MAX_BODY_BYTES {
            return Err(WebhookRejection::TooLarge);
        }
        let event = headers
            .event
            .as_deref()
            .ok_or(WebhookRejection::MissingHeader(EVENT_HEADER))?;
        let delivery_id = headers
            .delivery
            .as_deref()
            .ok_or(WebhookRejection::MissingHeader(DELIVERY_HEADER))?;
        let id_shape_ok = (8..=128).contains(&delivery_id.len())
            && delivery_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
        if !id_shape_ok {
            return Err(WebhookRejection::MissingHeader(DELIVERY_HEADER));
        }
        let Some(presented) = headers.signature_256.as_deref() else {
            return Err(if headers.has_legacy_signature {
                WebhookRejection::LegacySignatureOnly
            } else {
                WebhookRejection::MissingHeader(SIGNATURE_HEADER)
            });
        };
        let content_type = headers
            .content_type
            .as_deref()
            .ok_or(WebhookRejection::MissingHeader(CONTENT_TYPE_HEADER))?;
        let media = content_type.split(';').next().unwrap_or_default().trim();
        if !media.eq_ignore_ascii_case("application/json") {
            return Err(WebhookRejection::BadContentType);
        }
        if !self.matches(presented, raw_body) {
            return Err(WebhookRejection::BadSignature);
        }
        // Verified. Only now is the body read.
        if !ACCEPTED.iter().any(|(name, _)| *name == event) {
            return Err(WebhookRejection::UnsupportedEvent);
        }
        let payload = read_strict(raw_body).ok_or(WebhookRejection::Malformed)?;
        let object = payload.as_object().ok_or(WebhookRejection::Malformed)?;
        let installation = object
            .get("installation")
            .and_then(|i| i.get("id"))
            .and_then(Value::as_u64)
            .ok_or(WebhookRejection::Malformed)?;
        let action = object.get("action").and_then(Value::as_str);
        let accepted = ACCEPTED
            .iter()
            .find(|(name, _)| *name == event)
            .is_some_and(|(_, actions)| action.is_some_and(|a| actions.contains(&a)));
        if !accepted {
            return Err(WebhookRejection::UnsupportedEvent);
        }
        let event_slug = Slug::parse(event).map_err(|_| WebhookRejection::UnsupportedEvent)?;
        let action_slug = action
            .map(Slug::parse)
            .transpose()
            .map_err(|_| WebhookRejection::UnsupportedEvent)?;
        let repository = object
            .get("repository")
            .and_then(|r| r.get("id"))
            .and_then(Value::as_u64)
            .map(GithubRepositoryId);
        let sender_id = object
            .get("sender")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_u64);
        Ok(VerifiedDelivery {
            delivery_id: delivery_id.to_owned(),
            event: event_slug,
            action: action_slug,
            installation: InstallationId(installation),
            repository,
            sender_github_user_id: sender_id,
            body_sha256: Sha256Digest::of(raw_body),
            semantic_key: semantic_key(event, action, installation, repository, sender_id, object),
            hint: hint_of(event, action, object),
        })
    }
}

/// True when the sender is a bot account, which includes the factory's own App.
fn sent_by_a_bot(object: &Map<String, Value>) -> bool {
    object.get("sender").is_some_and(|sender| {
        sender.get("type").and_then(Value::as_str) == Some("Bot")
            || sender
                .get("login")
                .and_then(Value::as_str)
                .is_some_and(|login| login.ends_with("[bot]"))
    })
}

fn text(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or_default()
}

/// The part of the payload the event is about: the issue, the pull request or the comment.
fn subject<'a>(event: &str, object: &'a Map<String, Value>) -> Option<&'a Value> {
    let key = match event {
        "issues" => "issue",
        "issue_comment" => "comment",
        "pull_request" => "pull_request",
        "pull_request_review" => "review",
        _ => return None,
    };
    object.get(key)
}

/// The hash of the fields the policy lists (`webhook.semantic_idempotency.key_fields`), plus the
/// label name for a `labeled` event, because two labels applied to one issue in the same second
/// are two different deliveries.
fn semantic_key(
    event: &str,
    action: Option<&str>,
    installation: u64,
    repository: Option<GithubRepositoryId>,
    sender: Option<u64>,
    object: &Map<String, Value>,
) -> Option<Sha256Digest> {
    let subject = subject(event, object)?;
    let node_id = subject.get("node_id").and_then(Value::as_str)?;
    let stamp = ["updated_at", "submitted_at", "created_at"]
        .iter()
        .find_map(|key| subject.get(*key).and_then(Value::as_str))?;
    let label = text(object.get("label").and_then(|l| l.get("name")));
    let line = format!(
        "{event}\n{}\n{installation}\n{}\n{node_id}\n{stamp}\n{}\n{label}",
        action.unwrap_or_default(),
        repository.map_or(0, |r| r.0),
        sender.unwrap_or(0),
    );
    Some(Sha256Digest::of(line.as_bytes()))
}

/// What the payload hints at: identifiers only.
fn hint_of(event: &str, action: Option<&str>, object: &Map<String, Value>) -> WebhookHint {
    if sent_by_a_bot(object) {
        return WebhookHint::Other;
    }
    let Some(repo) = object
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(Value::as_str)
        .and_then(|name| RepoRef::parse(name).ok())
    else {
        return WebhookHint::Other;
    };
    let number = |part: &str| {
        object
            .get(part)
            .and_then(|v| v.get("number"))
            .and_then(Value::as_u64)
    };
    match (event, action) {
        ("issues", Some("labeled")) => {
            let label = text(object.get("label").and_then(|l| l.get("name")));
            match (number("issue"), label.is_empty()) {
                (Some(number), false) => WebhookHint::IssueLabeled {
                    issue: IssueRef { repo, number },
                    label: label.to_owned(),
                },
                _ => WebhookHint::Other,
            }
        }
        ("issues", Some("edited")) => {
            number("issue").map_or(WebhookHint::Other, |number| WebhookHint::IssueEdited {
                issue: IssueRef { repo, number },
            })
        }
        ("issue_comment", Some("created")) => {
            let id = object
                .get("comment")
                .and_then(|c| c.get("id"))
                .and_then(Value::as_u64);
            // A pull request is an issue to the comment API. The payload says which it is by the
            // `pull_request` member of `issue`.
            let on_a_pull_request = object
                .get("issue")
                .is_some_and(|issue| issue.get("pull_request").is_some());
            match (id, number("issue")) {
                (Some(id), Some(number)) => WebhookHint::CommentCreated {
                    comment: CommentRef {
                        target: if on_a_pull_request {
                            CommentTarget::PullRequest(PullRequestRef { repo, number })
                        } else {
                            CommentTarget::Issue(IssueRef { repo, number })
                        },
                        id,
                    },
                },
                _ => WebhookHint::Other,
            }
        }
        ("pull_request" | "pull_request_review", _) => {
            number("pull_request").map_or(WebhookHint::Other, |number| {
                WebhookHint::PullRequestChanged {
                    pr: PullRequestRef { repo, number },
                }
            })
        }
        _ => WebhookHint::Other,
    }
}

// ---- reading the body strictly ---------------------------------------------------------------

/// A JSON value that cannot hold a duplicate key.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;
        impl<'de> Visitor<'de> for Reader {
            type Value = Strict;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value without a repeated key")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(
                    serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
                ))
            }
            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut members = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if members.contains_key(&key) {
                        return Err(de::Error::custom("a key is repeated"));
                    }
                    let Strict(value) = map.next_value()?;
                    members.insert(key, value);
                }
                Ok(Strict(Value::Object(members)))
            }
        }
        deserializer.deserialize_any(Reader)
    }
}

/// The deepest nesting of `{` and `[` outside strings.
fn nesting(bytes: &[u8]) -> usize {
    let (mut depth, mut deepest, mut in_string, mut escaped) = (0_usize, 0_usize, false, false);
    for byte in bytes {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// The body as a value, or `None` when it is not JSON, is nested deeper than [`MAX_DEPTH`], or has
/// a repeated key.
fn read_strict(body: &[u8]) -> Option<Value> {
    if nesting(body) > MAX_DEPTH {
        return None;
    }
    serde_json::from_slice::<Strict>(body).ok().map(|s| s.0)
}

// ---- the replay filter -----------------------------------------------------------------------

/// What the store said about a verified delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// A new delivery, now recorded.
    New(WebhookDeliveryId),
    /// A repeat, by delivery id, by body hash or by semantic key. Acknowledge and stop.
    Repeat(DuplicateOf),
}

/// Records a verified delivery. A repeat is not an error: GitHub redelivers, and so can anyone who
/// captured a request.
///
/// # Errors
/// [`StoreError`] from the store.
pub async fn accept_delivery(
    store: &mut dyn DeliveryOps,
    id: WebhookDeliveryId,
    delivery: &VerifiedDelivery,
) -> Result<Replay, StoreError> {
    let outcome = store
        .record_delivery(NewWebhookDelivery {
            id,
            delivery_id: delivery.delivery_id.clone(),
            event_name: delivery.event.clone(),
            action: delivery.action.clone(),
            installation: delivery.installation,
            repository: delivery.repository,
            sender_github_user_id: delivery.sender_github_user_id,
            body_sha256: delivery.body_sha256.clone(),
            semantic_key: delivery.semantic_key.clone(),
        })
        .await?;
    Ok(match outcome {
        DeliveryOutcome::Recorded(id) => Replay::New(id),
        DeliveryOutcome::Duplicate(of) => Replay::Repeat(of),
    })
}
