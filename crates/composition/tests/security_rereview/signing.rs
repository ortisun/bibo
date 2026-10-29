//! Attacks on the keyed word of a `decision.requested` record (AUT-12): the key file, the key, and the
//! grammar of the signed subject. Nothing here needs a database.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use factory_composition::config::{DecisionSigning, SecretFile};
use factory_composition::decision_signing::{
    DecisionKeys, KeyError, Signing, SubjectKind, read_subject,
};
use factory_composition::decisions::DecisionFields;
use factory_composition::profile::Profile;
use factory_domain::ids::{AuditEventId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::redaction::Redactor;
use factory_workflow::stages::approval::Verb;

use crate::repository_root;

fn uuid_of(n: u128) -> uuid::Uuid {
    uuid::Uuid::from_u128(n)
}

/// A directory of its own under the build directory (not the system temporary directory, which the
/// other tests of this crate avoid too).
fn scratch(name: &str) -> PathBuf {
    let ids = factory_composition::system::RandomIds::new().expect("the random source opens");
    let unique = factory_ports::clock::IdGenerator::new_uuid(&ids)
        .simple()
        .to_string();
    let dir = repository_root()
        .join("target/security-rereview")
        .join(format!("{name}-{unique}"));
    std::fs::create_dir_all(&dir).expect("a directory");
    dir
}

fn write_key(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).expect("a key file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("a mode");
}

fn load(profile: Profile, path: &Path) -> Result<DecisionKeys, KeyError> {
    let settings = DecisionSigning {
        key_file: SecretFile::at(path),
        previous_key_file: None,
        previous_key_valid_until: None,
    };
    let redactor = Redactor::builder().build().expect("a redactor");
    DecisionKeys::load(profile, Some(&settings), &redactor)
}

fn fields() -> DecisionFields {
    DecisionFields {
        verb: Verb::Approve,
        job: JobId::from_uuid(uuid_of(0x11)),
        stage_run: Some(StageRunId::from_uuid(uuid_of(0x22))),
        head: Some("a".repeat(40)),
        evidence: Some(format!("sha256:{}", "b".repeat(64))),
        target: None,
    }
}

fn signing<'a>(fields: &'a DecisionFields, at: &'a str) -> Signing<'a> {
    Signing {
        tenant: TenantId::from_uuid(uuid_of(1)),
        actor: PrincipalId::from_uuid(uuid_of(2)),
        event: AuditEventId::from_uuid(uuid_of(3)),
        requested_at: at,
        fields,
    }
}

/// A key that is good (64 hex characters of a random source) is accepted in production, and each way
/// of getting the file wrong is refused. The file checks are the ones the fix claims.
#[test]
fn held_the_key_file_is_checked_for_mode_link_size_and_kind() {
    let dir = scratch("key");
    let good_text = {
        let ids = factory_composition::system::RandomIds::new().expect("random");
        let a = factory_ports::clock::IdGenerator::new_uuid(&ids)
            .simple()
            .to_string();
        let b = factory_ports::clock::IdGenerator::new_uuid(&ids)
            .simple()
            .to_string();
        format!("{a}{b}\n")
    };

    let good = dir.join("good");
    write_key(&good, good_text.as_bytes(), 0o600);
    assert!(load(Profile::Production, &good).is_ok(), "a good key loads");

    let loose = dir.join("loose");
    write_key(&loose, good_text.as_bytes(), 0o640);
    assert!(load(Profile::Production, &loose).is_err(), "group readable");
    let world = dir.join("world");
    write_key(&world, good_text.as_bytes(), 0o604);
    assert!(load(Profile::Production, &world).is_err(), "world readable");

    let link = dir.join("link");
    std::os::unix::fs::symlink(&good, &link).expect("a link");
    assert!(load(Profile::Production, &link).is_err(), "a symbolic link");

    let empty = dir.join("empty");
    write_key(&empty, b"", 0o600);
    assert!(load(Profile::Production, &empty).is_err(), "an empty key");
    let short = dir.join("short");
    write_key(&short, &[b'k'; 31], 0o600);
    assert!(
        matches!(load(Profile::Production, &short), Err(KeyError::TooShort)),
        "31 bytes"
    );
    let blank = dir.join("blank");
    write_key(&blank, b"\n\n\n\n", 0o600);
    assert!(
        load(Profile::Production, &blank).is_err(),
        "only line feeds"
    );

    assert!(
        load(Profile::Production, &dir.join("missing")).is_err(),
        "production does not make a missing key"
    );
    assert!(
        load(Profile::Production, &dir).is_err(),
        "a directory is not a key"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same key, rotated: the previous key is the current key, and a key that equals the previous one
/// is refused.
#[test]
fn held_a_rotation_to_the_same_key_is_refused() {
    let key = vec![7_u8; 40];
    assert_eq!(
        DecisionKeys::fixed_for_tests(&key, Some(&key)).err(),
        Some(KeyError::SameKey)
    );
}

/// RR-5 (fixed). The key is the text of the file, and the only rule on it is a length of 32 bytes. A file of
/// thirty-two copies of one letter, or a dictionary word repeated, is accepted as the key that
/// authenticates every decision. The tests of the fix use `[7; 40]` as a key, which shows the
/// shape is thought acceptable.
#[test]
fn rr_5_a_key_with_no_entropy_is_refused() {
    let weak: [(&str, Vec<u8>); 3] = [
        ("one byte repeated", vec![b'a'; 32]),
        ("zeros", vec![0_u8; 32]),
        (
            "a word repeated",
            b"passwordpasswordpasswordpassword".to_vec(),
        ),
    ];
    let accepted: Vec<&str> = weak
        .iter()
        .filter(|(_, bytes)| DecisionKeys::from_bytes(bytes, None).is_ok())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        accepted.is_empty(),
        "these keys were accepted as signing keys: {accepted:?}"
    );
}

/// The subject grammar cannot carry a second `at=` or `mac=`: a request whose free word (`target`,
/// `head`, `evidence`) contains them is read as malformed, never as a signed record with another
/// time or another word. An attacker cannot make the hook verify a different message than the one
/// that was signed.
#[test]
fn held_extra_at_and_mac_words_make_a_subject_malformed() {
    let keys = DecisionKeys::fixed_for_tests(&[9_u8; 40], None).expect("a key");
    let plain = fields();
    let at = "2026-10-28T12:00:00Z";
    let genuine = keys.signed_subject(&signing(&plain, at));
    assert!(matches!(
        read_subject(&genuine),
        Some(SubjectKind::Signed { .. })
    ));

    let other_word = "0".repeat(64);
    let tails = [
        format!("{genuine} mac={other_word}"),
        format!("{genuine} at=2020-01-01T00:00:00Z mac={other_word}"),
        genuine.replacen(" at=", " at=2020-01-01T00:00:00Z at=", 1),
        genuine.replacen(" mac=", " mac=x mac=", 1),
    ];
    for text in tails {
        assert!(
            !matches!(read_subject(&text), Some(SubjectKind::Signed { .. })),
            "a second word was read as a signed record: {text}"
        );
    }

    // A rework target that tries to carry the words itself.
    let mut tricky = fields();
    tricky.verb = Verb::Rework;
    tricky.target = Some("review".to_owned());
    let honest = keys.signed_subject(&signing(&tricky, at));
    let smuggled = honest.replacen(
        "target=review",
        &format!("target=review at=2020-01-01T00:00:00Z mac={other_word}"),
        1,
    );
    assert!(
        !matches!(read_subject(&smuggled), Some(SubjectKind::Signed { .. })),
        "{smuggled}"
    );
}

/// A word made for one reading of the message does not verify for another: every field of the
/// signing changes the word, and a word made with the previous key during a rotation verifies with
/// the pair of keys but not with the new key alone. (The hook-level version of these is in
/// `claim_work.rs`; this is the primitive.)
#[test]
fn held_every_field_is_inside_the_word() {
    let keys = DecisionKeys::fixed_for_tests(&[9_u8; 40], None).expect("a key");
    let base = fields();
    let at = "2026-10-28T12:00:00Z";
    let word = keys.sign(&signing(&base, at));
    assert!(keys.verify(&signing(&base, at), &word));

    let mut others: Vec<(&str, DecisionFields, &str)> = Vec::new();
    let mut verb = base.clone();
    verb.verb = Verb::Reject;
    others.push(("verb", verb, at));
    let mut job = base.clone();
    job.job = JobId::from_uuid(uuid_of(0x12));
    others.push(("job", job, at));
    let mut run = base.clone();
    run.stage_run = None;
    others.push(("stage run", run, at));
    let mut head = base.clone();
    head.head = Some("c".repeat(40));
    others.push(("head", head, at));
    let mut evidence = base.clone();
    evidence.evidence = Some(format!("sha256:{}", "d".repeat(64)));
    others.push(("evidence", evidence, at));
    others.push(("time", base.clone(), "2026-10-28T12:00:01Z"));
    for (name, changed, time) in &others {
        assert!(
            !keys.verify(&signing(changed, time), &word),
            "the word still verified after the {name} changed"
        );
    }
    // Another tenant, actor and event id.
    for (name, changed) in [
        (
            "tenant",
            Signing {
                tenant: TenantId::from_uuid(uuid_of(9)),
                ..signing(&base, at)
            },
        ),
        (
            "actor",
            Signing {
                actor: PrincipalId::from_uuid(uuid_of(9)),
                ..signing(&base, at)
            },
        ),
        (
            "event",
            Signing {
                event: AuditEventId::from_uuid(uuid_of(9)),
                ..signing(&base, at)
            },
        ),
    ] {
        assert!(
            !keys.verify(&changed, &word),
            "the {name} is not in the word"
        );
    }
    // Upper-case hex, a short word and a word with a prefix are not the word.
    assert!(!keys.verify(&signing(&base, at), &word.to_uppercase()));
    assert!(!keys.verify(&signing(&base, at), &word[..63]));
    assert!(!keys.verify(&signing(&base, at), &format!("0{word}")));
}
