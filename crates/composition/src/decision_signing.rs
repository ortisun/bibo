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
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

use crate::config::{ConfigError, DecisionSigning, SecretFile};
use crate::decisions::DecisionFields;
use crate::profile::Profile;
use crate::startup::StartupFailure;

/// The shortest key accepted, in bytes.
pub const MIN_KEY_BYTES: usize = 32;

/// The length of the word, in hex digits.
pub const WORD_HEX_DIGITS: usize = 64;

/// The first line of what is signed, so that the same key could never sign another kind of text
/// into a valid word.
const CONTEXT: &str = "factory-decision-request/1";

/// Why a key cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The key is shorter than [`MIN_KEY_BYTES`].
    #[error("the decision signing key is shorter than {MIN_KEY_BYTES} bytes")]
    TooShort,
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

impl Key {
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
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
    /// Keys from the bytes of the files.
    ///
    /// # Errors
    /// [`KeyError::TooShort`] or [`KeyError::SameKey`].
    pub fn from_bytes(current: &[u8], previous: Option<&[u8]>) -> Result<Self, KeyError> {
        let current = Key::from_bytes(current)?;
        let previous = previous.map(Key::from_bytes).transpose()?;
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
    /// [`KeyError::TooShort`] or [`KeyError::SameKey`].
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
    /// The production profile needs the section and the files. The other profiles make the file
    /// when it is missing (mode 0600, written whole before it appears), and with no section at all
    /// they keep a key in memory.
    ///
    /// # Errors
    /// [`KeyError`].
    pub fn load(
        profile: Profile,
        settings: Option<&DecisionSigning>,
        redactor: &Redactor,
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
        let current = settings.key_file.read()?;
        let previous = settings
            .previous_key_file
            .as_ref()
            .map(SecretFile::read)
            .transpose()?;
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
        let Some(provided) = unhex(word) else {
            return false;
        };
        let message = signing.message();
        let mut found = Choice::from(0);
        for key in std::iter::once(&self.current).chain(self.previous.as_ref()) {
            if let Some(expected) = key.word(message.as_bytes()) {
                found |= expected.as_slice().ct_eq(provided.as_slice());
            }
        }
        bool::from(found)
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

/// Reads a subject back. `None` when it is neither the signed nor the unsigned canonical text.
#[must_use]
pub fn read_subject(subject: &str) -> Option<SubjectKind> {
    if let Some((rest, word)) = subject.rsplit_once(" mac=")
        && let Some((body, at)) = rest.rsplit_once(" at=")
        && !word.is_empty()
        && !word.contains(char::is_whitespace)
        && !at.is_empty()
        && at.len() <= 40
        && at
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'T' | b'Z' | b'-' | b':' | b'.'))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decisions::DecisionFields;
    use factory_domain::ids::{JobId, StageRunId};
    use factory_workflow::stages::approval::Verb;

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
        DecisionKeys::from_bytes(&[seed; 40], None).expect("a key")
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
        let old = keys(1);
        let parts = parts();
        let by_old = old.sign(&parts.signing());
        let rotated = keys(2).rotated_from(&[1; 40]).expect("rotation");
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
            DecisionKeys::from_bytes(&[1; 31], None).err(),
            Some(KeyError::TooShort)
        );
        assert_eq!(
            DecisionKeys::from_bytes(&[1; 40], Some(&[2; 10])).err(),
            Some(KeyError::TooShort)
        );
        assert_eq!(
            DecisionKeys::from_bytes(&[1; 40], Some(&[1; 40])).err(),
            Some(KeyError::SameKey)
        );
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
        }
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
        write_key(&old, &"o".repeat(40), 0o600);
        write_key(&new, &"n".repeat(40), 0o600);
        write_key(&older, &"x".repeat(40), 0o600);
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
            Some(&settings(&new, Some(&old))),
            &redactor(),
        )
        .expect("rotated");
        assert!(rotated.verify(&parts.signing(), &signed_by_old));
        assert!(!rotated.verify(&parts.signing(), &signed_by_older));
        // The same key twice, and a key that is too short, are refused.
        let same = DecisionKeys::load(
            Profile::Production,
            Some(&settings(&old, Some(&old))),
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
        let key = "r".repeat(48);
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
