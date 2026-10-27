//! Webhook deliveries from the fake GitHub: signing, typed events, forged variants, and a
//! reference verifier.
//!
//! # Deliveries
//!
//! [`FakeGithub::deliver`] signs a payload with the fake's webhook secret and returns a
//! [`Delivery`] with the headers GitHub sends: `X-GitHub-Event`, `X-GitHub-Delivery`, a
//! SHA-256 signature in `X-Hub-Signature-256`, and the legacy SHA-1 signature in
//! `X-Hub-Signature`. [`Delivery::post_to`] sends it to a server under test.
//!
//! # Forged variants
//!
//! [`Delivery::attack_variants`] returns the forged deliveries of NT-WH-01 to NT-WH-03: no
//! signature, an empty one, the wrong secret, a truncated or non-hex or unprefixed one, an
//! uppercase prefix, only the legacy SHA-1 header, a space inside the value, a body changed by one
//! byte, two signature headers, and the original signature on a re-serialised body. Each is
//! listed with the verdict of the [`ReferenceVerifier`], and the tests of this module check that
//! the verifier agrees with every one, so each forged delivery is invalid for the documented
//! reason and not by accident.
//!
//! # The reference verifier and receiver
//!
//! [`ReferenceVerifier`] is a plain, strict implementation of the signature check the policy
//! asks for (`policies/security.yaml`, `webhook.signature`): the header `X-Hub-Signature-256`
//! exactly once, the prefix `sha256=` in lowercase, 64 lowercase hex digits, HMAC-SHA256 over the
//! raw body, compared in constant time, against each accepted secret. The legacy header never
//! counts. [`ReferenceReceiver`] adds the rest of the intake rules: required headers, content
//! type, a size cap, signature before any parsing, and one delivery id accepted once. It exists
//! to be compared with: the receiver in the API crate must give the same verdict on the same
//! delivery. It is not the implementation under test.

use std::collections::BTreeSet;
use std::io;
use std::net::SocketAddr;

use serde_json::{Value, json};

use super::routes::{issue_json, repo_json};
use super::{FakeGithub, State};
use crate::fx::digest::{constant_time_eq, hmac_sha1, hmac_sha256};
use crate::fx::encoding::hex_encode;
use crate::fx::http::{ClientResponse, send_request};

/// The body limit of the webhook endpoint (`webhook.max_body_bytes`).
pub const MAX_BODY_BYTES: usize = 1_048_576;

/// `sha256=` and the lowercase hex HMAC-SHA256 of `body` under `secret`.
#[must_use]
pub fn sign_sha256(secret: &str, body: &[u8]) -> String {
    format!(
        "sha256={}",
        hex_encode(&hmac_sha256(secret.as_bytes(), body), false)
    )
}

/// `sha1=` and the lowercase hex HMAC-SHA1 of `body` under `secret`. The legacy header.
#[must_use]
pub fn sign_sha1(secret: &str, body: &[u8]) -> String {
    format!(
        "sha1={}",
        hex_encode(&hmac_sha1(secret.as_bytes(), body), false)
    )
}

/// One webhook delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The value of `X-GitHub-Delivery`.
    pub id: String,
    /// The value of `X-GitHub-Event`.
    pub event: String,
    /// All headers, in the order GitHub sends them.
    pub headers: Vec<(String, String)>,
    /// The raw body. A signature covers exactly these bytes.
    pub body: Vec<u8>,
}

impl Delivery {
    /// The first header with this name, compared without regard to case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as JSON.
    ///
    /// # Panics
    /// Panics when the body is not JSON.
    #[must_use]
    pub fn payload(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a delivery body is JSON")
    }

    /// The delivery with every header of this name removed.
    #[must_use]
    pub fn without_header(mut self, name: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self
    }

    /// The delivery with the header set to this value, replacing any earlier one.
    #[must_use]
    pub fn with_header(self, name: &str, value: &str) -> Self {
        let mut delivery = self.without_header(name);
        delivery.headers.push((name.to_owned(), value.to_owned()));
        delivery
    }

    /// The delivery with another header added, keeping any with the same name.
    #[must_use]
    pub fn with_extra_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The delivery with a different body and every signature left as it was.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Posts the delivery to `path` on a server under test and returns the answer.
    ///
    /// # Errors
    /// Returns the I/O error when the connection fails.
    pub fn post_to(&self, addr: SocketAddr, path: &str) -> io::Result<ClientResponse> {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        send_request(addr, "POST", path, &headers, &self.body)
    }

    /// The forged variants of this delivery, each with what a correct verifier says about it.
    ///
    /// `secret` is the secret the delivery was signed with. The baseline (the delivery as it is)
    /// comes first and is valid.
    ///
    /// # Panics
    /// Panics when the body is not JSON, because the re-serialised variants need to read it.
    #[must_use]
    pub fn attack_variants(&self, secret: &str) -> Vec<Attack> {
        let body = self.body.clone();
        let good = sign_sha256(secret, &body);
        let hex = good.trim_start_matches("sha256=").to_owned();
        let original: Value = serde_json::from_slice(&body).expect("a delivery body is JSON");
        let with_sig = |value: &str| self.clone().with_header("X-Hub-Signature-256", value);
        let mut out = vec![Attack::new("baseline", Expect::Valid, self.clone())];
        out.push(Attack::new(
            "missing_signature",
            Expect::Invalid(Reason::MissingHeader),
            self.clone()
                .without_header("X-Hub-Signature-256")
                .without_header("X-Hub-Signature"),
        ));
        out.push(Attack::new(
            "empty_signature",
            Expect::Invalid(Reason::EmptyHeader),
            with_sig(""),
        ));
        out.push(Attack::new(
            "wrong_secret",
            Expect::Invalid(Reason::Mismatch),
            with_sig(&sign_sha256(&format!("{secret}-not"), &body)),
        ));
        out.push(Attack::new(
            "truncated",
            Expect::Invalid(Reason::WrongLength),
            with_sig(&good[..good.len() - 8]),
        ));
        out.push(Attack::new(
            "non_hex",
            Expect::Invalid(Reason::NotLowercaseHex),
            with_sig(&format!("sha256={}", "z".repeat(64))),
        ));
        out.push(Attack::new(
            "no_prefix",
            Expect::Invalid(Reason::WrongPrefix),
            with_sig(&hex),
        ));
        out.push(Attack::new(
            "uppercase_prefix",
            Expect::Invalid(Reason::WrongPrefix),
            with_sig(&format!("SHA256={hex}")),
        ));
        out.push(Attack::new(
            "space_inside_value",
            Expect::Invalid(Reason::WrongPrefix),
            with_sig(&format!("sha256= {hex}")),
        ));
        out.push(Attack::new(
            "sha1_header_only",
            Expect::Invalid(Reason::LegacyHeaderOnly),
            self.clone()
                .without_header("X-Hub-Signature-256")
                .with_header("X-Hub-Signature", &sign_sha1(secret, &body)),
        ));
        out.push(Attack::new(
            "two_signature_headers_valid_first",
            Expect::Invalid(Reason::DuplicateHeader),
            self.clone().with_extra_header(
                "X-Hub-Signature-256",
                &sign_sha256(&format!("{secret}-not"), &body),
            ),
        ));
        out.push(Attack::new(
            "two_signature_headers_invalid_first",
            Expect::Invalid(Reason::DuplicateHeader),
            self.clone()
                .without_header("X-Hub-Signature-256")
                .with_extra_header(
                    "X-Hub-Signature-256",
                    &sign_sha256(&format!("{secret}-not"), &body),
                )
                .with_extra_header("X-Hub-Signature-256", &good),
        ));

        // The body changed by one byte: the first digit goes up by one, so the JSON is still
        // valid and only the signature stands in the way.
        let mut changed = body.clone();
        if let Some(position) = changed.iter().position(u8::is_ascii_digit) {
            changed[position] = b'0' + (changed[position] - b'0' + 1) % 10;
        }
        out.push(Attack::new(
            "body_changed_by_one_byte",
            Expect::Invalid(Reason::Mismatch),
            self.clone().with_body(changed),
        ));
        // The same JSON written differently, with the original signature.
        out.push(Attack::new(
            "reserialized_pretty",
            Expect::Invalid(Reason::Mismatch),
            self.clone()
                .with_body(serde_json::to_vec_pretty(&original).expect("JSON writes")),
        ));
        if let Value::Object(map) = &original {
            let reversed: Vec<String> = map
                .iter()
                .rev()
                .map(|(k, v)| format!("{}:{v}", Value::String(k.clone())))
                .collect();
            out.push(Attack::new(
                "reserialized_key_order",
                Expect::Invalid(Reason::Mismatch),
                self.clone()
                    .with_body(format!("{{{}}}", reversed.join(",")).into_bytes()),
            ));
        }
        // A body with a duplicate key, signed correctly. The signature is fine; what the receiver
        // does with the ambiguity is for the receiver's own test to decide.
        let text = String::from_utf8_lossy(&body).into_owned();
        let duplicated = format!("{{\"action\":\"duplicate-key-first\",{}", &text[1..]);
        out.push(Attack::new(
            "duplicate_keys_validly_signed",
            Expect::Valid,
            self.clone()
                .with_body(duplicated.clone().into_bytes())
                .with_header(
                    "X-Hub-Signature-256",
                    &sign_sha256(secret, duplicated.as_bytes()),
                )
                .with_header("X-Hub-Signature", &sign_sha1(secret, duplicated.as_bytes())),
        ));
        out
    }
}

/// What a correct verifier says about a forged delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// The signature is valid.
    Valid,
    /// The signature is invalid, for this reason.
    Invalid(Reason),
}

/// One forged (or baseline) delivery with its expected verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attack {
    /// A short name, such as `sha1_header_only`.
    pub name: &'static str,
    /// What the reference verifier must say.
    pub expect: Expect,
    /// The delivery.
    pub delivery: Delivery,
}

impl Attack {
    fn new(name: &'static str, expect: Expect, delivery: Delivery) -> Self {
        Self {
            name,
            expect,
            delivery,
        }
    }
}

/// Why the reference verifier refused a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// There is no signature header at all.
    MissingHeader,
    /// Only the legacy SHA-1 header is there.
    LegacyHeaderOnly,
    /// The header is there and empty.
    EmptyHeader,
    /// The header appears more than once.
    DuplicateHeader,
    /// The value does not start with exactly `sha256=`.
    WrongPrefix,
    /// The hex part is not 64 characters.
    WrongLength,
    /// The hex part has a character that is not a lowercase hex digit.
    NotLowercaseHex,
    /// The value is well formed and does not match.
    Mismatch,
}

/// The reference verifier's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Valid under the accepted secret at this index (0 is the newest).
    Valid {
        /// Which accepted secret matched.
        secret_index: usize,
    },
    /// Not valid.
    Invalid(Reason),
}

impl Verdict {
    /// True for a valid signature.
    #[must_use]
    pub fn is_valid(self) -> bool {
        matches!(self, Verdict::Valid { .. })
    }

    fn matches(self, expect: Expect) -> bool {
        match (self, expect) {
            (Verdict::Valid { .. }, Expect::Valid) => true,
            (Verdict::Invalid(got), Expect::Invalid(want)) => got == want,
            _ => false,
        }
    }
}

/// The strict signature check.
#[derive(Debug, Clone)]
pub struct ReferenceVerifier {
    secrets: Vec<String>,
}

impl ReferenceVerifier {
    /// A verifier that accepts any of these secrets (more than one during a rotation).
    #[must_use]
    pub fn new(secrets: Vec<String>) -> Self {
        Self { secrets }
    }

    /// Checks one delivery's signature over its raw body.
    #[must_use]
    pub fn verify(&self, headers: &[(String, String)], body: &[u8]) -> Verdict {
        let named = |wanted: &str| -> Vec<&str> {
            headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(wanted))
                .map(|(_, v)| v.as_str())
                .collect()
        };
        let signatures = named("X-Hub-Signature-256");
        let value = match signatures.as_slice() {
            [] => {
                return Verdict::Invalid(if named("X-Hub-Signature").is_empty() {
                    Reason::MissingHeader
                } else {
                    Reason::LegacyHeaderOnly
                });
            }
            [one] => *one,
            _ => return Verdict::Invalid(Reason::DuplicateHeader),
        };
        if value.is_empty() {
            return Verdict::Invalid(Reason::EmptyHeader);
        }
        let Some(digits) = value.strip_prefix("sha256=") else {
            return Verdict::Invalid(Reason::WrongPrefix);
        };
        if digits.starts_with(char::is_whitespace) {
            return Verdict::Invalid(Reason::WrongPrefix);
        }
        if digits.len() != 64 {
            return Verdict::Invalid(Reason::WrongLength);
        }
        if !digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Verdict::Invalid(Reason::NotLowercaseHex);
        }
        for (index, secret) in self.secrets.iter().enumerate() {
            let expected = hex_encode(&hmac_sha256(secret.as_bytes(), body), false);
            if constant_time_eq(expected.as_bytes(), digits.as_bytes()) {
                return Verdict::Valid {
                    secret_index: index,
                };
            }
        }
        Verdict::Invalid(Reason::Mismatch)
    }
}

/// Why the reference receiver did not accept a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// A required header is missing: `X-GitHub-Event` or `X-GitHub-Delivery`.
    MissingHeader(&'static str),
    /// The content type is not `application/json`.
    WrongContentType,
    /// The body is over the limit.
    BodyTooLarge,
    /// The signature is wrong.
    Signature(Reason),
    /// The signature is right and the body is not JSON.
    InvalidJson,
}

/// What the reference receiver did with a delivery.
#[derive(Debug, Clone, PartialEq)]
pub enum ReceiveOutcome {
    /// Accepted and processed once.
    Accepted {
        /// The delivery id.
        delivery_id: String,
        /// The event.
        event: String,
        /// The parsed payload.
        payload: Value,
    },
    /// A delivery id that was already accepted. Acknowledged and ignored.
    Duplicate {
        /// The delivery id.
        delivery_id: String,
    },
    /// Refused.
    Rejected(Rejection),
}

/// The intake rules of `webhook` in the security policy, as a model to compare with.
#[derive(Debug)]
pub struct ReferenceReceiver {
    verifier: ReferenceVerifier,
    seen: BTreeSet<String>,
    json_parses: usize,
}

impl ReferenceReceiver {
    /// A receiver that accepts these secrets.
    #[must_use]
    pub fn new(secrets: Vec<String>) -> Self {
        Self {
            verifier: ReferenceVerifier::new(secrets),
            seen: BTreeSet::new(),
            json_parses: 0,
        }
    }

    /// How many bodies were parsed. A forged delivery must not add to it: the signature is
    /// checked first (NT-WH-03, `verify_before_parse`).
    #[must_use]
    pub fn json_parses(&self) -> usize {
        self.json_parses
    }

    /// Handles one delivery.
    pub fn receive(&mut self, headers: &[(String, String)], body: &[u8]) -> ReceiveOutcome {
        let first = |wanted: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(wanted))
                .map(|(_, v)| v.as_str())
        };
        let Some(event) = first("X-GitHub-Event") else {
            return ReceiveOutcome::Rejected(Rejection::MissingHeader("X-GitHub-Event"));
        };
        let Some(delivery_id) = first("X-GitHub-Delivery") else {
            return ReceiveOutcome::Rejected(Rejection::MissingHeader("X-GitHub-Delivery"));
        };
        let is_json = first("Content-Type").is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        });
        if !is_json {
            return ReceiveOutcome::Rejected(Rejection::WrongContentType);
        }
        if body.len() > MAX_BODY_BYTES {
            return ReceiveOutcome::Rejected(Rejection::BodyTooLarge);
        }
        // The signature first, over the raw bytes. Nothing is parsed before it passes.
        if let Verdict::Invalid(reason) = self.verifier.verify(headers, body) {
            return ReceiveOutcome::Rejected(Rejection::Signature(reason));
        }
        // A replay is only a replay of a delivery that was accepted, so a forged delivery with a
        // known id cannot use up the id.
        if self.seen.contains(delivery_id) {
            return ReceiveOutcome::Duplicate {
                delivery_id: delivery_id.to_owned(),
            };
        }
        self.json_parses += 1;
        let Ok(payload) = serde_json::from_slice::<Value>(body) else {
            return ReceiveOutcome::Rejected(Rejection::InvalidJson);
        };
        self.seen.insert(delivery_id.to_owned());
        ReceiveOutcome::Accepted {
            delivery_id: delivery_id.to_owned(),
            event: event.to_owned(),
            payload,
        }
    }
}

impl FakeGithub {
    /// Signs `payload` with the current webhook secret and returns the delivery.
    #[must_use]
    pub fn deliver(&self, event: &str, payload: &Value) -> Delivery {
        let secret = self.webhook_secret();
        self.deliver_signed_with(event, payload, &secret)
    }

    /// Signs `payload` with this secret instead, for a delivery that should fail.
    #[must_use]
    pub fn deliver_signed_with(&self, event: &str, payload: &Value, secret: &str) -> Delivery {
        let mut state = self.lock();
        let id = new_delivery_id(&mut state);
        let target = state.app.id;
        drop(state);
        let body = serde_json::to_vec(payload).expect("JSON writes");
        Delivery {
            id: id.clone(),
            event: event.to_owned(),
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("User-Agent".to_owned(), "GitHub-Hookshot/fake".to_owned()),
                ("X-GitHub-Delivery".to_owned(), id),
                ("X-GitHub-Event".to_owned(), event.to_owned()),
                ("X-GitHub-Hook-ID".to_owned(), "1".to_owned()),
                (
                    "X-GitHub-Hook-Installation-Target-ID".to_owned(),
                    target.to_string(),
                ),
                (
                    "X-GitHub-Hook-Installation-Target-Type".to_owned(),
                    "integration".to_owned(),
                ),
                ("X-Hub-Signature".to_owned(), sign_sha1(secret, &body)),
                ("X-Hub-Signature-256".to_owned(), sign_sha256(secret, &body)),
                ("X-Factory-Fidelity".to_owned(), "fake".to_owned()),
            ],
            body,
        }
    }

    /// An `issues` event with the action `labeled`, from `sender`, built from the fake's current
    /// state. The payload carries the issue's `author_association` and the sender's numeric id,
    /// as GitHub's does, and says nothing the allowlist should believe.
    ///
    /// # Panics
    /// Panics when the repository, issue or sender is not known.
    #[must_use]
    pub fn issues_labeled(&self, repo: &str, number: u64, label: &str, sender: &str) -> Delivery {
        let payload = {
            let state = self.lock();
            let repo_state = state.repos.get(repo).expect("a known repository");
            let issue = repo_state.issues.get(&number).expect("a known issue");
            let mut payload = envelope(&state, repo, "labeled", sender);
            payload["issue"] = issue_json(&state, repo_state, issue);
            payload["label"] = json!({"name": label});
            payload
        };
        self.deliver("issues", &payload)
    }

    /// An `issues` event with any other action, such as `edited` or `closed`.
    ///
    /// # Panics
    /// Panics when the repository, issue or sender is not known.
    #[must_use]
    pub fn issues_event(&self, action: &str, repo: &str, number: u64, sender: &str) -> Delivery {
        let payload = {
            let state = self.lock();
            let repo_state = state.repos.get(repo).expect("a known repository");
            let issue = repo_state.issues.get(&number).expect("a known issue");
            let mut payload = envelope(&state, repo, action, sender);
            payload["issue"] = issue_json(&state, repo_state, issue);
            payload
        };
        self.deliver("issues", &payload)
    }

    /// An `issue_comment` event with the action `created`.
    ///
    /// # Panics
    /// Panics when the repository, issue or sender is not known.
    #[must_use]
    pub fn issue_comment_created(
        &self,
        repo: &str,
        number: u64,
        text: &str,
        sender: &str,
    ) -> Delivery {
        let payload = {
            let state = self.lock();
            let repo_state = state.repos.get(repo).expect("a known repository");
            let issue = repo_state.issues.get(&number).expect("a known issue");
            let user = state.users.get(sender).expect("a known sender");
            let mut payload = envelope(&state, repo, "created", sender);
            payload["issue"] = issue_json(&state, repo_state, issue);
            payload["comment"] = json!({
                "id": 9_000_000 + number,
                "body": text,
                "user": user.json(),
                "author_association": user.association,
            });
            payload
        };
        self.deliver("issue_comment", &payload)
    }

    /// A `pull_request` event (`synchronize`, `closed`, `reopened`, `edited`).
    ///
    /// # Panics
    /// Panics when the repository, pull request or sender is not known.
    #[must_use]
    pub fn pull_request_event(
        &self,
        action: &str,
        repo: &str,
        number: u64,
        sender: &str,
    ) -> Delivery {
        let payload = {
            let state = self.lock();
            let repo_state = state.repos.get(repo).expect("a known repository");
            let pull = repo_state.pulls.get(&number).expect("a known pull request");
            let mut payload = envelope(&state, repo, action, sender);
            payload["number"] = json!(number);
            payload["pull_request"] =
                super::routes::pull_json(&state, repo_state, pull).expect("a pull request");
            payload
        };
        self.deliver("pull_request", &payload)
    }

    /// The `ping` GitHub sends when a webhook is set up.
    #[must_use]
    pub fn ping(&self) -> Delivery {
        self.deliver(
            "ping",
            &json!({"zen": "Keep it logically awesome.", "hook_id": 1}),
        )
    }

    /// An `installation` event (`created`, `deleted`, `suspend`, `unsuspend`).
    ///
    /// # Panics
    /// Panics when the installation is not known.
    #[must_use]
    pub fn installation_event(&self, action: &str, installation_id: u64) -> Delivery {
        let payload = {
            let state = self.lock();
            let installation = state
                .installations
                .get(&installation_id)
                .expect("a known installation");
            json!({
                "action": action,
                "installation": {
                    "id": installation.id,
                    "account": {"login": installation.account_login, "id": installation.account_id},
                    "app_id": state.app.id,
                },
                "repositories": installation.repositories.iter().map(|r| json!({"full_name": r})).collect::<Vec<_>>(),
                "sender": {"login": installation.account_login, "id": installation.account_id, "type": "User"},
            })
        };
        self.deliver("installation", &payload)
    }
}

/// The parts every repository event shares: action, repository, installation, sender.
fn envelope(state: &State, repo: &str, action: &str, sender: &str) -> Value {
    let repo_state = state.repos.get(repo).expect("a known repository");
    let installation = state
        .installations
        .values()
        .find(|i| i.repositories.contains(repo))
        .map_or(0, |i| i.id);
    let sender = state.users.get(sender).expect("a known sender");
    json!({
        "action": action,
        "repository": repo_json(repo_state),
        "installation": {"id": installation, "node_id": format!("I_fake_{installation}")},
        "sender": sender.json(),
    })
}

/// A random version-4 style identifier.
fn new_delivery_id(state: &mut State) -> String {
    let hex = |state: &mut State, n: usize| state.rng.string_from(crate::fx::rng::HEX_LOWER, n);
    let variant = ["8", "9", "a", "b"][state.rng.below(4)];
    format!(
        "{}-{}-4{}-{variant}{}-{}",
        hex(state, 8),
        hex(state, 4),
        hex(state, 3),
        hex(state, 3),
        hex(state, 12)
    )
}

/// True when the verifier's verdict is the one the attack table expects. Used by the tests of
/// this module and by consumers that run the same table against their own receiver.
#[must_use]
pub fn verdict_matches(verdict: Verdict, expect: Expect) -> bool {
    verdict.matches(expect)
}
