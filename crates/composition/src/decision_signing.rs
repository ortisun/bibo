//! The word that proves the API wrote a request for a decision (AUT-12, R-1 of the API review).
//!
//! # The problem
//!
//! A decision is a `decision.requested` row in the audit log. The worker's hook reads the log and
//! applies what it finds, as the person the row names. Any login of the API's database group can
//! write an audit row with any words in it, so a row by itself proves nothing about who wrote it. The
//! hook checks authority by numeric id when it applies (R-4) and the approval service judges the
//! binding, which limits a forged row to what the named person may do now. This module closes the
//! rest: a row carries a keyed word that only the API, which holds the key, can make.
//!
//! # The word
//!
//! `mac=` is HMAC-SHA256, in 64 lower-case hex digits, over this text, one field to a line:
//!
//! ```text
//! factory-decision-request/1
//! tenant=<tenant id>
//! actor=<principal id>
//! event=<audit event id>
//! at=<the time the API wrote in the subject>
//! verb=<verb> job=<job id> run=<run id or none> head=<head or none> evidence=<digest or none> target=<stage or none>
//! ```
//!
//! So it covers the tenant, the job, the stage run, the verb, the person, the event id and the time
//! of the request, and also the head, the evidence digest and the rework target the person named.
//! A row copied with another event id, for another job or verb or person, in another tenant, or with
//! any word changed, has the wrong word.
//!
//! The subject of the row is the six words of [`DecisionFields::subject`] followed by `at=` and
//! `mac=`. The hook accepts a row only after it has recomputed the word with each key it holds and
//! compared in constant time. A row with no word, or the wrong one, is rejected with the fixed code
//! `not_signed`, and nothing else about it is read.
//!
//! # The marker is signed too (RR-8)
//!
//! The row that ends a request, `decision.applied` or `decision.rejected`, is a row in the same log,
//! and a login of the API's group can write any row. So the worker's marker carries a word of its own,
//! made with the same key over a distinct first line, the tenant, the id of the marker row, the action,
//! the actor and the subject (see [`MarkerSigning`]). The hook counts a request as dealt with only when
//! the marker that names it has a good word. A marker without one, or with a wrong one, is ignored and
//! audited once. The id of the marker row is itself keyed ([`DecisionKeys::marker_id`]), so nobody can
//! write a row under the id the worker will use before the worker does.
//!
//! # The key
//!
//! The key is a file, named in the configuration of the API and of the worker (`decisions.key_file`):
//! a secret by reference, never inline, readable by its owner only. During a rotation a second file
//! (`decisions.previous_key_file`) holds the key the API signed with until now: the hook accepts a
//! word made with either, the API signs with the current one only. The production profile does not
//! start without the key. The `local` and `test` profiles create the file when it is missing, and
//! keep a key in memory when nothing is configured.

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;

use factory_domain::ids::{AuditEventId, PrincipalId, TenantId};
use factory_domain::redaction::Redactor;
use factory_domain::values::Timestamp;
use factory_ports::store::AuditActor;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

use crate::config::{ConfigError, DecisionSigning};
use crate::decisions::DecisionFields;
use crate::dependency_decisions::DependencyFields;
use crate::intake_rejections::RejectionFields;
use crate::profile::Profile;
use crate::stage_decisions::StageFields;
use crate::startup::StartupFailure;

/// The shortest key accepted, in bytes of key material: a key written as hex digits counts for the
/// bytes it spells (64 digits are 32 bytes), any other text for its own bytes.
pub const MIN_KEY_BYTES: usize = 32;

/// The fewest different byte values the key material may have. A random key of 32 bytes has about 28.
const MIN_DISTINCT_BYTES: usize = 8;

/// The longest repeating unit that makes a key a repetition: a key that is one unit of up to this
/// many bytes written again and again is refused.
const MAX_REPEATING_UNIT: usize = 16;

/// The length of the word, in hex digits.
pub const WORD_HEX_DIGITS: usize = 64;

/// The first line of what is signed, so that the same key could never sign another kind of text
/// into a valid word.
const CONTEXT: &str = "factory-decision-request/1";

/// The first line of what is signed for a decision on a dependency. It differs from [`CONTEXT`],
/// so a word made for one kind of request is never the word of the other, even if the rest of the
/// text could be made to look alike.
const DEPENDENCY_CONTEXT: &str = "factory-dependency-decision-request/1";
/// The context line of a request about a stage run: letting a blocked one go again, a decision on
/// the project's own build code, a decision on a translation warning. A word made for one kind of
/// request is never the word of another.
const STAGE_CONTEXT: &str = "factory-stage-decision-request/1";

/// The first line of what is signed for the marker of a decision. It differs from [`CONTEXT`] and
/// [`DEPENDENCY_CONTEXT`], so a word made for a request is never the word of a marker.
const MARKER_CONTEXT: &str = "factory-decision-marker/1";

/// The first line of what is hashed to make the id of a marker row.
const MARKER_ID_CONTEXT: &str = "factory-decision-marker-id/1";

/// The first line of what is signed for a request to answer a label from someone who may not ask.
/// It differs from the other contexts, so a word made for one kind of record is never the word of
/// another.
const REJECTION_CONTEXT: &str = "factory-intake-rejection-request/1";

/// The first line of what is hashed to make the id of the record that a rejection leaves.
const REJECTION_ID_CONTEXT: &str = "factory-intake-rejection-id/1";

/// Why a key cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The key is shorter than [`MIN_KEY_BYTES`].
    #[error("the decision signing key is shorter than {MIN_KEY_BYTES} bytes")]
    TooShort,
    /// The key has too little entropy to authenticate anything: one byte or one short word written
    /// again and again, a run of consecutive values, or too few different bytes (RR-5).
    #[error(
        "the decision signing key is not random: it repeats a short pattern or has too few different bytes"
    )]
    Weak,
    /// The previous key is the current key.
    #[error("the previous decision signing key is the same as the current one")]
    SameKey,
    /// The file is missing, unsafe or unreadable.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// A key could not be made or written.
    #[error("a decision signing key could not be made: {0}")]
    Make(String),
}

impl From<KeyError> for StartupFailure {
    fn from(error: KeyError) -> Self {
        StartupFailure::Other(error.to_string())
    }
}

/// One key. It never shows itself.
#[derive(Clone)]
struct Key(Vec<u8>);

/// The bytes a key text stands for: a text of hex digits is the bytes it spells, as the provisioning
/// script writes it (64 digits for 32 bytes), and any other text is its own bytes. Surrounding white
/// space is not part of the key.
fn material(text: &[u8]) -> Vec<u8> {
    let trimmed = text.trim_ascii();
    if !trimmed.is_empty()
        && trimmed.len().is_multiple_of(2)
        && trimmed.iter().all(u8::is_ascii_hexdigit)
    {
        let nibble = |digit: u8| match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => digit - b'A' + 10,
        };
        let (pairs, _) = trimmed.as_chunks::<2>();
        return pairs
            .iter()
            .map(|[high, low]| nibble(*high) << 4 | nibble(*low))
            .collect();
    }
    trimmed.to_vec()
}

/// True when the material shows no entropy: too few different values, a repeating unit of up to
/// [`MAX_REPEATING_UNIT`] bytes, or every byte one step from the one before.
fn is_weak(material: &[u8]) -> bool {
    let mut seen = [false; 256];
    for byte in material {
        seen[usize::from(*byte)] = true;
    }
    if seen.iter().filter(|present| **present).count() < MIN_DISTINCT_BYTES {
        return true;
    }
    let repeats = (1..=MAX_REPEATING_UNIT.min(material.len() / 2)).any(|unit| {
        material
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == material[index % unit])
    });
    if repeats {
        return true;
    }
    let step = material[1].wrapping_sub(material[0]);
    material
        .windows(2)
        .all(|pair| pair[1].wrapping_sub(pair[0]) == step)
}

impl Key {
    /// A key of this text: long enough, and not a repetition (RR-5).
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key = Self::fixed(bytes)?;
        let material = material(bytes);
        if material.len() < MIN_KEY_BYTES {
            return Err(KeyError::TooShort);
        }
        if is_weak(&material) {
            return Err(KeyError::Weak);
        }
        Ok(key)
    }

    /// A key of this text, long enough and nothing more. For a test that wants a known key.
    fn fixed(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() < MIN_KEY_BYTES {
            return Err(KeyError::TooShort);
        }
        Ok(Self(bytes.to_vec()))
    }

    fn word(&self, message: &[u8]) -> Option<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).ok()?;
        mac.update(message);
        let mut word = [0_u8; 32];
        word.copy_from_slice(&mac.finalize().into_bytes());
        Some(word)
    }
}

/// What a signature covers besides the words of the subject.
#[derive(Debug, Clone, Copy)]
pub struct Signing<'a> {
    /// The tenant the record belongs to.
    pub tenant: TenantId,
    /// The principal the record names as its actor.
    pub actor: PrincipalId,
    /// The id of the audit record.
    pub event: AuditEventId,
    /// The time of the request, as the text written in the subject.
    pub requested_at: &'a str,
    /// The words of the subject.
    pub fields: &'a DecisionFields,
}

impl Signing<'_> {
    fn message(&self) -> String {
        format!(
            "{CONTEXT}\ntenant={}\nactor={}\nevent={}\nat={}\n{}",
            self.tenant.as_text(),
            self.actor.as_text(),
            self.event.as_uuid().hyphenated(),
            self.requested_at,
            self.fields.subject(),
        )
    }
}

/// What a signature of a decision on a dependency covers besides the words of the subject.
#[derive(Debug, Clone, Copy)]
pub struct DependencySigning<'a> {
    /// The tenant the record belongs to.
    pub tenant: TenantId,
    /// The principal the record names as its actor.
    pub actor: PrincipalId,
    /// The id of the audit record.
    pub event: AuditEventId,
    /// The time of the request, as the text written in the subject.
    pub requested_at: &'a str,
    /// The words of the subject.
    pub fields: &'a DependencyFields,
}

impl DependencySigning<'_> {
    fn message(&self) -> String {
        format!(
            "{DEPENDENCY_CONTEXT}\ntenant={}\nactor={}\nevent={}\nat={}\n{}",
            self.tenant.as_text(),
            self.actor.as_text(),
            self.event.as_uuid().hyphenated(),
            self.requested_at,
            self.fields.subject(),
        )
    }
}

/// What a signature of a request about a stage run covers besides the words of the subject.
#[derive(Debug, Clone, Copy)]
pub struct StageSigning<'a> {
    /// The tenant the record belongs to.
    pub tenant: TenantId,
    /// The principal the record names as its actor.
    pub actor: PrincipalId,
    /// The id of the audit record.
    pub event: AuditEventId,
    /// The time of the request, as the text written in the subject.
    pub requested_at: &'a str,
    /// The words of the subject.
    pub fields: &'a StageFields,
}

impl StageSigning<'_> {
    fn message(&self) -> String {
        format!(
            "{STAGE_CONTEXT}\ntenant={}\nactor={}\nevent={}\nat={}\n{}",
            self.tenant.as_text(),
            self.actor.as_text(),
            self.event.as_uuid().hyphenated(),
            self.requested_at,
            self.fields.subject(),
        )
    }
}

/// What the signature of a request to answer a rejected label covers besides the words of the
/// subject. The API writes the request when it refuses to make a job for a label, and the worker
/// reads it, so the one grammar is [`RejectionFields`].
#[derive(Debug, Clone, Copy)]
pub struct RejectionSigning<'a> {
    /// The tenant the record belongs to.
    pub tenant: TenantId,
    /// The id of the audit record.
    pub event: AuditEventId,
    /// The time of the request, as the text written in the subject.
    pub requested_at: &'a str,
    /// The words of the subject.
    pub fields: &'a RejectionFields,
}

impl RejectionSigning<'_> {
    fn message(&self) -> String {
        format!(
            "{REJECTION_CONTEXT}\ntenant={}\nevent={}\nat={}\n{}",
            self.tenant.as_text(),
            self.event.as_uuid().hyphenated(),
            self.requested_at,
            self.fields.subject(),
        )
    }
}

/// What the signature of a marker covers besides its subject.
#[derive(Debug, Clone, Copy)]
pub struct MarkerSigning<'a> {
    /// The tenant the record belongs to.
    pub tenant: TenantId,
    /// The id of the marker row itself (see [`DecisionKeys::marker_id`]).
    pub event: AuditEventId,
    /// The audit action of the marker: `decision.applied` or `decision.rejected`.
    pub action: &'a str,
    /// The actor of the marker, as [`actor_text`] writes it.
    pub actor: &'a str,
    /// The subject without the word: `decision=<request id>` and the fixed words after it.
    pub subject: &'a str,
}

impl MarkerSigning<'_> {
    fn message(&self) -> String {
        format!(
            "{MARKER_CONTEXT}\ntenant={}\nevent={}\naction={}\nactor={}\n{}",
            self.tenant.as_text(),
            self.event.as_uuid().hyphenated(),
            self.action,
            self.actor,
            self.subject,
        )
    }
}

/// The actor of an audit record as one word, for the message of a marker. A person, a service and a
/// component of the system with the same text are different actors.
#[must_use]
pub fn actor_text(actor: &AuditActor) -> String {
    match actor {
        AuditActor::Human(id) => format!("human:{}", id.as_text()),
        AuditActor::Service(id) => format!("service:{}", id.as_text()),
        AuditActor::System(slug) => format!("system:{}", slug.as_str()),
        AuditActor::Anonymous(slug) => format!("anonymous:{}", slug.as_str()),
    }
}

/// The keys of the signing: the current one, and during a rotation the one before it.
#[derive(Clone)]
pub struct DecisionKeys {
    current: Key,
    previous: Option<Key>,
}

impl fmt::Debug for DecisionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecisionKeys")
            .field("previous", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let digits = text.as_bytes();
    if digits.len() != WORD_HEX_DIGITS {
        return None;
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut word = [0_u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (slot, [high, low]) in word.iter_mut().zip(pairs) {
        *slot = nibble(*high)? << 4 | nibble(*low)?;
    }
    Some(word)
}

fn random_key_text() -> Result<String, KeyError> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| KeyError::Make(error.to_string()))?;
    Ok(hex(&bytes))
}

impl DecisionKeys {
    /// Keys from the bytes of the files. A key that is a repeated byte or word, has too few different
    /// bytes or is shorter than 32 bytes of key material is refused, in every profile (RR-5).
    ///
    /// # Errors
    /// [`KeyError::TooShort`], [`KeyError::Weak`] or [`KeyError::SameKey`].
    pub fn from_bytes(current: &[u8], previous: Option<&[u8]>) -> Result<Self, KeyError> {
        let current = Key::from_bytes(current)?;
        let previous = previous.map(Key::from_bytes).transpose()?;
        if previous.as_ref().is_some_and(|old| old.0 == current.0) {
            return Err(KeyError::SameKey);
        }
        Ok(Self { current, previous })
    }

    /// Keys of a known text, for a test: the length is checked and the entropy is not, so a test may
    /// use `[7; 40]`. Nothing else calls this: [`load`](Self::load) and every other constructor
    /// refuse a key with no entropy.
    ///
    /// # Errors
    /// [`KeyError::TooShort`] or [`KeyError::SameKey`].
    #[doc(hidden)]
    pub fn fixed_for_tests(current: &[u8], previous: Option<&[u8]>) -> Result<Self, KeyError> {
        let current = Key::fixed(current)?;
        let previous = previous.map(Key::fixed).transpose()?;
        if previous.as_ref().is_some_and(|old| old.0 == current.0) {
            return Err(KeyError::SameKey);
        }
        Ok(Self { current, previous })
    }

    /// A random key that lives in this process only. For the `test` and `local` profiles when
    /// nothing is configured: a key like this is not shared, so a decision signed by one process
    /// is not applied by another.
    ///
    /// # Errors
    /// [`KeyError::Make`] when the operating system's random source cannot be read.
    pub fn generated() -> Result<Self, KeyError> {
        Self::from_bytes(random_key_text()?.as_bytes(), None)
    }

    /// The same keys, with `previous` as the key accepted for verification during a rotation.
    ///
    /// # Errors
    /// [`KeyError::TooShort`], [`KeyError::Weak`] or [`KeyError::SameKey`].
    pub fn rotated_from(self, previous: &[u8]) -> Result<Self, KeyError> {
        let old = Key::from_bytes(previous)?;
        if old.0 == self.current.0 {
            return Err(KeyError::SameKey);
        }
        Ok(Self {
            current: self.current,
            previous: Some(old),
        })
    }

    /// Reads the keys the configuration names. The files must be regular files that only their
    /// owner may read. A key is registered with the redactor, so a log line that prints one is
    /// redacted.
    ///
    /// The production profile needs the section and the files, and holds the files to more: every
    /// directory above a key file is closed to writers other than its owner (a sticky directory
    /// such as `/tmp` is allowed: there only the owner of a file can replace it), and the file
    /// belongs to the owner of its directory or the directory to root (RR-25). The previous key
    /// is used only until `previous_key_valid_until`, and not at all in production without one. The
    /// other profiles make the file when it is missing (mode 0600, written whole before it appears),
    /// and with no section at all they keep a key in memory.
    ///
    /// # Errors
    /// [`KeyError`].
    pub fn load(
        profile: Profile,
        settings: Option<&DecisionSigning>,
        redactor: &Redactor,
    ) -> Result<Self, KeyError> {
        let now = factory_ports::clock::Clock::now(&crate::system::SystemClock);
        Self::load_at(profile, settings, redactor, now)
    }

    /// [`load`](Self::load) at a given time, for the expiry of the previous key.
    ///
    /// # Errors
    /// [`KeyError`].
    pub fn load_at(
        profile: Profile,
        settings: Option<&DecisionSigning>,
        redactor: &Redactor,
        now: Timestamp,
    ) -> Result<Self, KeyError> {
        let Some(settings) = settings else {
            if profile == Profile::Production {
                return Err(KeyError::File(ConfigError::OutOfRange {
                    field: "decisions.key_file",
                    problem: "the production profile needs the key that signs decision requests",
                }));
            }
            tracing::warn!(
                "no decision signing key is configured; a key was made for this process, and a \
                 request signed by another process will not be applied"
            );
            return Self::generated();
        };
        if profile != Profile::Production {
            make_if_missing(settings.key_file.path())?;
        }
        if profile == Profile::Production {
            check_key_location(settings.key_file.path())?;
        }
        let current = settings.key_file.read()?;
        let previous = match &settings.previous_key_file {
            Some(file) if previous_key_in_force(profile, settings, now)? => {
                if profile == Profile::Production {
                    check_key_location(file.path())?;
                }
                Some(file.read()?)
            }
            _ => None,
        };
        let keys = Self::from_bytes(
            current.expose().as_bytes(),
            previous.as_ref().map(|key| key.expose().as_bytes()),
        )?;
        for text in std::iter::once(&current).chain(previous.as_ref()) {
            // A value too short for the redactor to register has already been refused as a key.
            redactor
                .register("decision_signing_key", text.expose())
                .map_err(|_| KeyError::Make("the key cannot be registered".to_owned()))?;
        }
        Ok(keys)
    }

    /// The word for a request, made with the current key.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn sign(&self, signing: &Signing<'_>) -> String {
        let word = self
            .current
            .word(signing.message().as_bytes())
            .expect("an HMAC key can have any length");
        hex(&word)
    }

    /// True when `word` is the word of this request under the current key or the previous one. The
    /// comparison takes the same time whichever key matches and wherever the words differ, and both
    /// keys are always tried.
    #[must_use]
    pub fn verify(&self, signing: &Signing<'_>, word: &str) -> bool {
        self.verify_message(&signing.message(), word)
    }

    fn verify_message(&self, message: &str, word: &str) -> bool {
        let Some(provided) = unhex(word) else {
            return false;
        };
        let mut found = Choice::from(0);
        for key in std::iter::once(&self.current).chain(self.previous.as_ref()) {
            if let Some(expected) = key.word(message.as_bytes()) {
                found |= expected.as_slice().ct_eq(provided.as_slice());
            }
        }
        bool::from(found)
    }

    /// The word for a decision on a dependency, made with the current key.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn sign_dependency(&self, signing: &DependencySigning<'_>) -> String {
        let word = self
            .current
            .word(signing.message().as_bytes())
            .expect("an HMAC key can have any length");
        hex(&word)
    }

    /// True when `word` is the word of this decision on a dependency under the current key or the
    /// previous one, compared as [`verify`](Self::verify) does.
    #[must_use]
    pub fn verify_dependency(&self, signing: &DependencySigning<'_>, word: &str) -> bool {
        self.verify_message(&signing.message(), word)
    }

    /// The subject of a signed decision on a dependency: the words, the time, the word.
    #[must_use]
    pub fn signed_dependency_subject(&self, signing: &DependencySigning<'_>) -> String {
        format!(
            "{} at={} mac={}",
            signing.fields.subject(),
            signing.requested_at,
            self.sign_dependency(signing)
        )
    }

    /// The word for a request about a stage run, made with the current key.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn sign_stage(&self, signing: &StageSigning<'_>) -> String {
        let word = self
            .current
            .word(signing.message().as_bytes())
            .expect("an HMAC key can have any length");
        hex(&word)
    }

    /// True when `word` is the word of this request about a stage run under the current key or
    /// the previous one, compared as [`verify`](Self::verify) does.
    #[must_use]
    pub fn verify_stage(&self, signing: &StageSigning<'_>, word: &str) -> bool {
        self.verify_message(&signing.message(), word)
    }

    /// The subject of a signed request about a stage run: the words, the time, the word.
    #[must_use]
    pub fn signed_stage_subject(&self, signing: &StageSigning<'_>) -> String {
        format!(
            "{} at={} mac={}",
            signing.fields.subject(),
            signing.requested_at,
            self.sign_stage(signing)
        )
    }

    /// The subject of a signed request: the six words, the time, the word.
    #[must_use]
    pub fn signed_subject(&self, signing: &Signing<'_>) -> String {
        format!(
            "{} at={} mac={}",
            signing.fields.subject(),
            signing.requested_at,
            self.sign(signing)
        )
    }

    /// The word for a marker, made with the current key.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn sign_marker(&self, signing: &MarkerSigning<'_>) -> String {
        let word = self
            .current
            .word(signing.message().as_bytes())
            .expect("an HMAC key can have any length");
        hex(&word)
    }

    /// True when `word` is the word of this marker under the current key or the previous one,
    /// compared as [`verify`](Self::verify) does.
    #[must_use]
    pub fn verify_marker(&self, signing: &MarkerSigning<'_>, word: &str) -> bool {
        self.verify_message(&signing.message(), word)
    }

    /// The subject of a signed marker: the words, then the word.
    #[must_use]
    pub fn signed_marker_subject(&self, signing: &MarkerSigning<'_>) -> String {
        format!("{} mac={}", signing.subject, self.sign_marker(signing))
    }

    /// The word for a request to answer a rejected label, made with the current key.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn sign_rejection(&self, signing: &RejectionSigning<'_>) -> String {
        let word = self
            .current
            .word(signing.message().as_bytes())
            .expect("an HMAC key can have any length");
        hex(&word)
    }

    /// True when `word` is the word of this request under the current key or the previous one,
    /// compared as [`verify`](Self::verify) does.
    #[must_use]
    pub fn verify_rejection(&self, signing: &RejectionSigning<'_>, word: &str) -> bool {
        self.verify_message(&signing.message(), word)
    }

    /// The subject of a signed request to answer a rejected label: the words, the time, the word.
    #[must_use]
    pub fn signed_rejection_subject(&self, signing: &RejectionSigning<'_>) -> String {
        format!(
            "{} at={} mac={}",
            signing.fields.subject(),
            signing.requested_at,
            self.sign_rejection(signing)
        )
    }

    /// The id of the record that a rejection leaves, for a request. It is a keyed function of the
    /// id of the request, so that it is the same on every pass and in every worker that holds the
    /// key: a second write of the record is a repeat and not a second record.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn rejection_id(&self, request: AuditEventId) -> AuditEventId {
        let word = self
            .current
            .word(format!("{REJECTION_ID_CONTEXT}\n{}", request.as_uuid().hyphenated()).as_bytes())
            .expect("an HMAC key can have any length");
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&word[..16]);
        AuditEventId::from_uuid(uuid::Builder::from_random_bytes(bytes).into_uuid())
    }

    /// The id of the marker row for a request (or for a record the hook ignores). It is a keyed
    /// function of the id, so that it is the same on every pass and in every worker that holds the
    /// key, and nobody without the key can tell it in advance and write a row under it.
    ///
    /// # Panics
    /// Never: an HMAC accepts a key of any length.
    #[must_use]
    pub fn marker_id(&self, decision: AuditEventId) -> AuditEventId {
        let word = self
            .current
            .word(format!("{MARKER_ID_CONTEXT}\n{}", decision.as_uuid().hyphenated()).as_bytes())
            .expect("an HMAC key can have any length");
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&word[..16]);
        AuditEventId::from_uuid(uuid::Builder::from_random_bytes(bytes).into_uuid())
    }
}

/// Whether the previous key still verifies at `now`: until `previous_key_valid_until`, and, with no
/// such time, in every profile but production (RR-25). A previous key that is ignored is logged, with
/// the reason and no key.
fn previous_key_in_force(
    profile: Profile,
    settings: &DecisionSigning,
    now: Timestamp,
) -> Result<bool, KeyError> {
    let Some(text) = settings.previous_key_valid_until.as_deref() else {
        if profile == Profile::Production {
            tracing::warn!(
                "the previous decision signing key is ignored: `decisions.previous_key_valid_until` \
                 is not set, and the production profile does not accept a previous key without an end"
            );
            return Ok(false);
        }
        return Ok(true);
    };
    let until = Timestamp::parse(text).map_err(|_| {
        KeyError::File(ConfigError::OutOfRange {
            field: "decisions.previous_key_valid_until",
            problem: "is not a UTC time such as 2026-11-02T12:00:00Z",
        })
    })?;
    if now > until {
        tracing::warn!(
            "the previous decision signing key is ignored: `decisions.previous_key_valid_until` has passed"
        );
        return Ok(false);
    }
    Ok(true)
}

/// The place of a key file, in the production profile (RR-25). The file is looked at as the
/// operating system resolves it, and every directory above it must not be writable by group or
/// others unless it is sticky (a writer there can replace the file), and the file belongs to the owner of its directory,
/// or the directory to root. Whether the owner is the user the process runs as cannot be asked
/// without a call into the operating system that this crate does not make; the mode of the file
/// (nothing for group or others) and its being readable make it the process's own or root's.
fn check_key_location(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let shown = path.display().to_string();
    let unsafe_place = |problem: &'static str| {
        KeyError::File(ConfigError::UnsafeSecretFile {
            path: shown.clone(),
            problem,
        })
    };
    let unreadable = || KeyError::File(ConfigError::Unreadable(shown.clone()));
    let resolved = std::fs::canonicalize(path).map_err(|_| unreadable())?;
    for directory in resolved.ancestors().skip(1) {
        let meta = std::fs::metadata(directory).map_err(|_| unreadable())?;
        let mode = meta.permissions().mode();
        // A sticky directory lets only the owner of a file rename or remove it, which is all that
        // matters for a file that is the process's own.
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(unsafe_place(
                "a directory above it can be written by group or others",
            ));
        }
    }
    let file = std::fs::metadata(&resolved).map_err(|_| unreadable())?;
    if let Some(parent) = resolved.parent() {
        let owner = std::fs::metadata(parent).map_err(|_| unreadable())?.uid();
        if file.uid() != owner && owner != 0 {
            return Err(unsafe_place(
                "owned by another user than the directory it is in",
            ));
        }
    }
    Ok(())
}

/// Makes the key file when it does not exist, so that two processes that start together end up with
/// one key: the file is written whole under another name and then linked to its place, and a link
/// never replaces a file that is already there.
fn make_if_missing(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::OpenOptionsExt;
    if std::fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("key"),
        std::process::id()
    ));
    let text = random_key_text()?;
    let made = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error),
        }
    })()
    .map_err(|error| KeyError::Make(error.to_string()));
    let _ = std::fs::remove_file(&temporary);
    made
}

/// What the subject of a `decision.requested` row holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKind {
    /// The six words, `at=` and `mac=`.
    Signed {
        /// The six words.
        fields: DecisionFields,
        /// The time the API wrote.
        requested_at: String,
        /// The word, as written. It is not known to be well formed.
        word: String,
    },
    /// The six words alone: a row nobody signed.
    Unsigned(DecisionFields),
}

/// Splits a signed subject into the words, the time and the word, when it has the shape of one.
fn split_signed(subject: &str) -> Option<(&str, &str, &str)> {
    let (rest, word) = subject.rsplit_once(" mac=")?;
    let (body, at) = rest.rsplit_once(" at=")?;
    (!word.is_empty()
        && !word.contains(char::is_whitespace)
        && !at.is_empty()
        && at.len() <= 40
        && at
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'T' | b'Z' | b'-' | b':' | b'.')))
    .then_some((body, at, word))
}

/// Reads a subject back. `None` when it is neither the signed nor the unsigned canonical text.
#[must_use]
pub fn read_subject(subject: &str) -> Option<SubjectKind> {
    if let Some((body, at, word)) = split_signed(subject)
        && let Some(fields) = DecisionFields::parse_canonical(body)
    {
        return Some(SubjectKind::Signed {
            fields,
            requested_at: at.to_owned(),
            word: word.to_owned(),
        });
    }
    DecisionFields::parse_canonical(subject).map(SubjectKind::Unsigned)
}

/// What the subject of a marker holds, split but not believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkerSubject<'a> {
    /// The request the marker says it belongs to.
    pub decision: AuditEventId,
    /// The subject without the word: what the word covers.
    pub base: &'a str,
    /// The word as written. [`DecisionKeys::verify_marker`] decides whether it is good.
    pub word: &'a str,
}

/// Splits the subject of a marker: `decision=<id> ... mac=<word>`. `None` when it has no word or does
/// not start with the id of a request.
#[must_use]
pub fn read_marker_subject(subject: &str) -> Option<MarkerSubject<'_>> {
    let (base, word) = subject.rsplit_once(" mac=")?;
    if word.is_empty() || word.contains(char::is_whitespace) {
        return None;
    }
    let first = base.split_whitespace().next()?;
    let decision = AuditEventId::parse(first.strip_prefix("decision=")?).ok()?;
    Some(MarkerSubject {
        decision,
        base,
        word,
    })
}

/// What the subject of a `decision.dependency_requested` row holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencySubject {
    /// The words, `at=` and `mac=`.
    Signed {
        /// The words.
        fields: DependencyFields,
        /// The time the API wrote.
        requested_at: String,
        /// The word, as written. It is not known to be well formed.
        word: String,
    },
    /// The words alone: a row nobody signed.
    Unsigned(DependencyFields),
}

/// Reads the subject of a decision on a dependency back. `None` when it is neither the signed nor
/// the unsigned canonical text.
#[must_use]
pub fn read_dependency_subject(subject: &str) -> Option<DependencySubject> {
    if let Some((body, at, word)) = split_signed(subject)
        && let Some(fields) = DependencyFields::parse_canonical(body)
    {
        return Some(DependencySubject::Signed {
            fields,
            requested_at: at.to_owned(),
            word: word.to_owned(),
        });
    }
    DependencyFields::parse_canonical(subject).map(DependencySubject::Unsigned)
}

/// What the subject of a `decision.stage_requested` row holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageSubject {
    /// The words, `at=` and `mac=`.
    Signed {
        /// The words.
        fields: StageFields,
        /// The time the API wrote.
        requested_at: String,
        /// The word, as written. It is not known to be well formed.
        word: String,
    },
    /// The words alone: a row nobody signed.
    Unsigned(StageFields),
}

/// Reads the subject of a request about a stage run back. `None` when it is neither the signed nor
/// the unsigned canonical text.
#[must_use]
pub fn read_stage_subject(subject: &str) -> Option<StageSubject> {
    if let Some((body, at, word)) = split_signed(subject)
        && let Some(fields) = StageFields::parse_canonical(body)
    {
        return Some(StageSubject::Signed {
            fields,
            requested_at: at.to_owned(),
            word: word.to_owned(),
        });
    }
    StageFields::parse_canonical(subject).map(StageSubject::Unsigned)
}

/// What the subject of a request to answer a rejected label holds, split but not believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionSubject {
    /// The words.
    pub fields: RejectionFields,
    /// The time the API wrote.
    pub requested_at: String,
    /// The word, as written. [`DecisionKeys::verify_rejection`] decides whether it is good.
    pub word: String,
}

/// Reads the subject of a request to answer a rejected label back. `None` when it does not have
/// the shape of a signed one, including a subject that is the canonical words alone.
#[must_use]
pub fn read_rejection_subject(subject: &str) -> Option<RejectionSubject> {
    let (body, at, word) = split_signed(subject)?;
    Some(RejectionSubject {
        fields: RejectionFields::parse_canonical(body)?,
        requested_at: at.to_owned(),
        word: word.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretFile;
    use crate::decisions::DecisionFields;
    use factory_domain::ids::{JobId, StageRunId};
    use factory_workflow::stages::approval::Verb;
    use sha2::Digest as _;

    fn uuid(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn fields(verb: Verb) -> DecisionFields {
        DecisionFields {
            verb,
            job: JobId::from_uuid(uuid(0x11)),
            stage_run: Some(StageRunId::from_uuid(uuid(0x22))),
            head: Some("a".repeat(40)),
            evidence: Some(format!("sha256:{}", "b".repeat(64))),
            target: None,
        }
    }

    fn keys(seed: u8) -> DecisionKeys {
        DecisionKeys::fixed_for_tests(&[seed; 40], None).expect("a key")
    }

    /// A key that has entropy: 64 hex digits of the SHA-256 of one byte. Different seeds, different keys.
    fn strong(seed: u8) -> String {
        hex(&Sha256::digest([seed]))
    }

    struct Parts {
        tenant: TenantId,
        actor: PrincipalId,
        event: AuditEventId,
        fields: DecisionFields,
    }

    fn parts() -> Parts {
        Parts {
            tenant: TenantId::from_uuid(uuid(1)),
            actor: PrincipalId::from_uuid(uuid(2)),
            event: AuditEventId::from_uuid(uuid(3)),
            fields: fields(Verb::Approve),
        }
    }

    impl Parts {
        fn signing(&self) -> Signing<'_> {
            Signing {
                tenant: self.tenant,
                actor: self.actor,
                event: self.event,
                requested_at: "2026-10-28T12:00:00Z",
                fields: &self.fields,
            }
        }
    }

    #[test]
    fn a_word_is_sixty_four_lower_case_hex_digits_and_verifies() {
        let keys = keys(7);
        let parts = parts();
        let word = keys.sign(&parts.signing());
        assert_eq!(word.len(), WORD_HEX_DIGITS);
        assert!(
            word.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert!(keys.verify(&parts.signing(), &word));
    }

    #[test]
    fn a_word_over_anything_else_does_not_verify() {
        let keys = keys(7);
        let parts = parts();
        let word = keys.sign(&parts.signing());
        // Another event id, tenant, actor, verb, job, time, head: each is a different message.
        type Change = fn(&mut Parts);
        let changes: [Change; 8] = [
            |p| p.event = AuditEventId::from_uuid(uuid(4)),
            |p| p.tenant = TenantId::from_uuid(uuid(5)),
            |p| p.actor = PrincipalId::from_uuid(uuid(6)),
            |p| p.fields.verb = Verb::Cancel,
            |p| p.fields.job = JobId::from_uuid(uuid(0x12)),
            |p| p.fields.stage_run = None,
            |p| p.fields.head = Some("c".repeat(40)),
            |p| p.fields.target = Some("review".to_owned()),
        ];
        for change in changes {
            let mut other = parts_clone(&parts);
            change(&mut other);
            assert!(!keys.verify(&other.signing(), &word));
        }
        let later = Signing {
            requested_at: "2026-10-28T12:00:01Z",
            ..parts.signing()
        };
        assert!(!keys.verify(&later, &word));
        // Another key, no word, a short word, upper case, extra characters.
        assert!(!self::keys(8).verify(&parts.signing(), &word));
        for bad in [
            "",
            &word[..63],
            &word.to_uppercase(),
            &format!("{word}0"),
            "z".repeat(64).as_str(),
        ] {
            assert!(!keys.verify(&parts.signing(), bad), "{bad:?}");
        }
    }

    fn parts_clone(parts: &Parts) -> Parts {
        Parts {
            tenant: parts.tenant,
            actor: parts.actor,
            event: parts.event,
            fields: parts.fields.clone(),
        }
    }

    #[test]
    fn a_rotation_accepts_both_keys_and_signs_with_the_new_one() {
        let old = DecisionKeys::from_bytes(strong(1).as_bytes(), None).expect("a key");
        let parts = parts();
        let by_old = old.sign(&parts.signing());
        let rotated = keys(2)
            .rotated_from(&strong(1).into_bytes())
            .expect("rotation");
        assert!(
            rotated.verify(&parts.signing(), &by_old),
            "the previous key still verifies"
        );
        let by_new = rotated.sign(&parts.signing());
        assert_ne!(by_new, by_old);
        assert!(rotated.verify(&parts.signing(), &by_new));
        // The key before the previous one is not accepted, and the old key alone does not accept
        // the new word.
        assert!(!keys(3).verify(&parts.signing(), &by_old));
        assert!(!old.verify(&parts.signing(), &by_new));
    }

    #[test]
    fn a_short_key_and_a_repeated_key_are_refused() {
        assert_eq!(
            DecisionKeys::fixed_for_tests(&[1; 31], None).err(),
            Some(KeyError::TooShort)
        );
        assert_eq!(
            DecisionKeys::fixed_for_tests(&[1; 40], Some(&[2; 10])).err(),
            Some(KeyError::TooShort)
        );
        assert_eq!(
            DecisionKeys::fixed_for_tests(&[1; 40], Some(&[1; 40])).err(),
            Some(KeyError::SameKey)
        );
    }

    /// A key with no entropy is refused by every constructor but the one for tests (RR-5).
    #[test]
    fn a_key_with_no_entropy_is_refused() {
        let hex = |bytes: &[u8]| hex(bytes).into_bytes();
        let counted: Vec<u8> = (0..40_u8).collect();
        let weak: Vec<(&str, Vec<u8>)> = vec![
            ("one byte", vec![b'z'; 40]),
            ("zeros", vec![0; 40]),
            (
                "a word repeated",
                b"passwordpasswordpasswordpassword".to_vec(),
            ),
            (
                "a unit of sixteen",
                b"ghijklmnopqrstuvghijklmnopqrstuv".to_vec(),
            ),
            ("hex of one byte", hex(&[0xab; 32])),
            ("hex of a short unit", hex(&[1, 2, 3, 4].repeat(8))),
            ("a run of consecutive bytes", counted),
            (
                "seven different bytes",
                b"abcdefgabcgfedcbagfedabcgfaebdcg".to_vec(),
            ),
        ];
        for (name, bytes) in weak {
            assert_eq!(
                DecisionKeys::from_bytes(&bytes, None).err(),
                Some(KeyError::Weak),
                "{name}"
            );
            assert!(
                DecisionKeys::fixed_for_tests(&bytes, None).is_ok(),
                "{name}: the test constructor checks the length only"
            );
        }
    }

    /// Thirty-two hex digits are sixteen bytes: shorter than the minimum once decoded.
    #[test]
    fn a_hex_key_counts_for_the_bytes_it_spells() {
        let sixteen = hex(&[
            0x5a, 0x13, 0xc4, 0x9e, 0x72, 0xb8, 0x01, 0xfd, 0x3a, 0x66, 0x90, 0xd2, 0x4b, 0x8c,
            0xe7, 0x29,
        ]);
        assert_eq!(sixteen.len(), 32);
        assert_eq!(
            DecisionKeys::from_bytes(sixteen.as_bytes(), None).err(),
            Some(KeyError::TooShort)
        );
    }

    #[test]
    fn a_random_key_is_accepted_as_text_hex_and_with_a_newline() {
        let text = random_key_text().expect("random");
        assert!(DecisionKeys::from_bytes(text.as_bytes(), None).is_ok());
        assert!(DecisionKeys::from_bytes(format!("{text}\n").as_bytes(), None).is_ok());
        let words = b"correct horse battery staple, a long enough passphrase 42";
        assert!(DecisionKeys::from_bytes(words, None).is_ok());
        assert!(DecisionKeys::generated().is_ok());
    }

    #[test]
    fn a_key_never_shows_itself() {
        let shown = format!("{:?}", keys(9));
        assert!(!shown.contains("09"), "{shown}");
        assert!(shown.contains("DecisionKeys"));
    }

    #[test]
    fn a_signed_subject_reads_back_and_an_unsigned_one_reads_as_unsigned() {
        let keys = keys(7);
        let parts = parts();
        let subject = keys.signed_subject(&parts.signing());
        assert!(subject.len() <= 500, "{}", subject.len());
        match read_subject(&subject) {
            Some(SubjectKind::Signed {
                fields,
                requested_at,
                word,
            }) => {
                assert_eq!(fields, parts.fields);
                assert_eq!(requested_at, "2026-10-28T12:00:00Z");
                assert!(keys.verify(&parts.signing(), &word));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            read_subject(&parts.fields.subject()),
            Some(SubjectKind::Unsigned(parts.fields.clone()))
        );
        assert_eq!(read_subject("verb=approve"), None);
        // A time word with a space, a second word after the mac, or a mac with a space is not read.
        assert_eq!(read_subject(&format!("{subject} extra=1")), None);
        assert_eq!(
            read_subject(&subject.replace(" at=", "  at=")),
            None,
            "the text is canonical byte for byte"
        );
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "factory-decision-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::from_u128(std::time::UNIX_EPOCH.elapsed().map_or(0, |d| d.as_nanos()))
                .simple()
        ));
        std::fs::create_dir_all(&dir).expect("a directory");
        dir
    }

    fn write_key(path: &Path, text: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, text).expect("a key file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("a mode");
    }

    fn redactor() -> Redactor {
        Redactor::builder().build().expect("a redactor")
    }

    fn settings(current: &Path, previous: Option<&Path>) -> DecisionSigning {
        DecisionSigning {
            key_file: SecretFile::at(current),
            previous_key_file: previous.map(SecretFile::at),
            previous_key_valid_until: None,
        }
    }

    /// The settings of a rotation that ends a long time from now.
    fn rotation(current: &Path, previous: &Path) -> DecisionSigning {
        DecisionSigning {
            previous_key_valid_until: Some("2999-01-01T00:00:00Z".to_owned()),
            ..settings(current, Some(previous))
        }
    }

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a time")
    }

    /// RR-25. The previous key verifies until the time the configuration gives, and in the production
    /// profile it does not verify without one.
    #[test]
    fn the_previous_key_ends_when_the_configuration_says_and_in_production_it_needs_an_end() {
        let dir = scratch("expiry");
        let (old, new) = (dir.join("old.key"), dir.join("new.key"));
        write_key(&old, &strong(20), 0o600);
        write_key(&new, &strong(21), 0o600);
        let parts = parts();
        let by_old = DecisionKeys::load(
            Profile::Production,
            Some(&settings(&old, None)),
            &redactor(),
        )
        .expect("old")
        .sign(&parts.signing());
        let load = |profile, settings: &DecisionSigning, now| {
            DecisionKeys::load_at(profile, Some(settings), &redactor(), now).expect("loads")
        };
        let until = |text: &str| DecisionSigning {
            previous_key_valid_until: Some(text.to_owned()),
            ..settings(&new, Some(&old))
        };
        // Before the end: accepted. At the end: accepted. After it: not.
        let window = until("2026-11-02T12:00:00Z");
        for (now, accepted) in [
            ("2026-11-01T12:00:00Z", true),
            ("2026-11-02T12:00:00Z", true),
            ("2026-11-02T12:00:01Z", false),
        ] {
            let keys = load(Profile::Production, &window, at(now));
            assert_eq!(keys.verify(&parts.signing(), &by_old), accepted, "{now}");
        }
        // No end: refused in production, kept in the other profiles (until the file is removed).
        let open = settings(&new, Some(&old));
        let now = at("2026-11-01T12:00:00Z");
        assert!(!load(Profile::Production, &open, now).verify(&parts.signing(), &by_old));
        assert!(load(Profile::Local, &open, now).verify(&parts.signing(), &by_old));
        // An end that is not a time is an error and not a guess.
        let broken = until("next tuesday");
        let refused = DecisionKeys::load_at(Profile::Production, Some(&broken), &redactor(), now);
        assert!(matches!(refused, Err(KeyError::File(_))), "{refused:?}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// RR-25. In the production profile a key file in a directory that group or others can write, or
    /// above one, is refused, and one in a closed directory is accepted.
    #[test]
    fn in_production_a_key_in_a_directory_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("location");
        let closed = dir.join("closed");
        std::fs::create_dir_all(&closed).expect("a directory");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let key = closed.join("decision.key");
        write_key(&key, &strong(22), 0o600);
        let load = || {
            DecisionKeys::load(
                Profile::Production,
                Some(&settings(&key, None)),
                &redactor(),
            )
        };
        assert!(load().is_ok(), "a closed directory");
        // The directory itself, then the one above it.
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o770)).expect("mode");
        assert!(
            matches!(load(), Err(KeyError::File(_))),
            "group-writable directory"
        );
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).expect("mode");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).expect("mode");
        assert!(
            matches!(load(), Err(KeyError::File(_))),
            "a directory above is writable by others"
        );
        // A sticky directory is allowed.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).expect("mode");
        assert!(load().is_ok(), "a sticky directory");
        // The other profiles do not look.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).expect("mode");
        assert!(
            DecisionKeys::load(Profile::Local, Some(&settings(&key, None)), &redactor()).is_ok(),
            "the local profile does not check the place"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("mode");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn the_production_profile_refuses_to_start_without_the_key() {
        let refused = DecisionKeys::load(Profile::Production, None, &redactor());
        assert!(matches!(refused, Err(KeyError::File(_))), "{refused:?}");
        // A configured file that does not exist is not made in production.
        let dir = scratch("production");
        let missing = dir.join("decision.key");
        let refused = DecisionKeys::load(
            Profile::Production,
            Some(&settings(&missing, None)),
            &redactor(),
        );
        assert!(matches!(refused, Err(KeyError::File(_))), "{refused:?}");
        assert!(!missing.exists(), "production made a key");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn the_other_profiles_make_the_file_and_two_processes_get_the_same_key() {
        let dir = scratch("local");
        let path = dir.join("decision.key");
        let parts = parts();
        let first = DecisionKeys::load(Profile::Local, Some(&settings(&path, None)), &redactor())
            .expect("made");
        let second = DecisionKeys::load(Profile::Test, Some(&settings(&path, None)), &redactor())
            .expect("read");
        let word = first.sign(&parts.signing());
        assert!(second.verify(&parts.signing(), &word));
        // With nothing configured a key lives in memory and is not shared.
        let alone = DecisionKeys::load(Profile::Local, None, &redactor()).expect("generated");
        assert!(!alone.verify(&parts.signing(), &word));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_key_file_that_group_or_others_can_read_is_refused() {
        let dir = scratch("mode");
        let path = dir.join("decision.key");
        write_key(&path, &"k".repeat(40), 0o640);
        for profile in [Profile::Production, Profile::Local] {
            let refused = DecisionKeys::load(profile, Some(&settings(&path, None)), &redactor());
            assert!(
                matches!(
                    refused,
                    Err(KeyError::File(ConfigError::UnsafeSecretFile { .. }))
                ),
                "{profile:?}: {refused:?}"
            );
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_rotation_by_files_accepts_the_previous_key_and_nothing_older() {
        let dir = scratch("rotation");
        let (old, new, older) = (
            dir.join("old.key"),
            dir.join("new.key"),
            dir.join("older.key"),
        );
        write_key(&old, &strong(10), 0o600);
        write_key(&new, &strong(11), 0o600);
        write_key(&older, &strong(12), 0o600);
        let parts = parts();
        let signed_by_old = DecisionKeys::load(
            Profile::Production,
            Some(&settings(&old, None)),
            &redactor(),
        )
        .expect("old")
        .sign(&parts.signing());
        let signed_by_older = DecisionKeys::load(
            Profile::Production,
            Some(&settings(&older, None)),
            &redactor(),
        )
        .expect("older")
        .sign(&parts.signing());
        let rotated = DecisionKeys::load(
            Profile::Production,
            Some(&rotation(&new, &old)),
            &redactor(),
        )
        .expect("rotated");
        assert!(rotated.verify(&parts.signing(), &signed_by_old));
        assert!(!rotated.verify(&parts.signing(), &signed_by_older));
        // The same key twice, and a key that is too short, are refused.
        let same = DecisionKeys::load(
            Profile::Production,
            Some(&rotation(&old, &old)),
            &redactor(),
        );
        assert!(matches!(same, Err(KeyError::SameKey)), "{same:?}");
        let short = dir.join("short.key");
        write_key(&short, "too short", 0o600);
        let refused = DecisionKeys::load(
            Profile::Production,
            Some(&settings(&short, None)),
            &redactor(),
        );
        assert!(matches!(refused, Err(KeyError::TooShort)), "{refused:?}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_loaded_key_is_known_to_the_redactor() {
        let dir = scratch("redactor");
        let path = dir.join("decision.key");
        let key = strong(13);
        write_key(&path, &key, 0o600);
        let redactor = redactor();
        DecisionKeys::load(Profile::Production, Some(&settings(&path, None)), &redactor)
            .expect("loaded");
        assert_eq!(redactor.contains_secret(key.as_bytes()), Ok(true));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_missing_key_file_is_made_once_with_a_private_mode_and_read_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("factory-decision-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("decision.key");
        let _ = std::fs::remove_file(&path);
        make_if_missing(&path).expect("made");
        let first = std::fs::read_to_string(&path).expect("read");
        assert!(first.trim_end().len() >= MIN_KEY_BYTES);
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A second start finds the file and leaves it alone.
        make_if_missing(&path).expect("kept");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), first);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
