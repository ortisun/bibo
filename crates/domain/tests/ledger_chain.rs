//! The evidence ledger hash chain (ADR 0008).
//!
//! The expected hashes in `fixtures/ledger_chain.json` were computed by an independent Python
//! script, `oracle/ledger_chain_oracle.py`, written from the ADR text. `shasum` supplied the
//! known answers for the tiny inputs. The Rust code shares nothing with either.

use factory_domain::contracts::evidence_ledger_entry::Evidence;
use factory_domain::contracts::{Contract, EvidenceLedgerEntry};
use factory_domain::ids::LedgerEntryId;
use factory_domain::ledger::{
    ChainError, ChainHead, LedgerError, canonical_form, chain_hash, head_of, verify_chain,
    verify_chain_against_head,
};
use factory_domain::values::{HumanText, Sha256Digest, Timestamp};
use factory_domain::vocabulary::ConfidenceLevel;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

const ORACLE_CHAIN: &str = include_str!("fixtures/ledger_chain.json");

fn fixture() -> Vec<EvidenceLedgerEntry> {
    serde_json::from_str(ORACLE_CHAIN).expect("the oracle fixture holds valid entries")
}

fn digest(text: &str) -> Sha256Digest {
    Sha256Digest::parse(text).unwrap()
}

// ---- the oracle -----------------------------------------------------------------------------------

#[test]
fn chain_hash_matches_independent_oracle() {
    let entries = fixture();
    assert_eq!(entries.len(), 5, "the fixture chain has five entries");
    for entry in &entries {
        let canonical = canonical_form(entry).expect("the entry can be written canonically");
        let computed = chain_hash(entry.prev_entry_hash.as_ref(), &canonical);
        assert_eq!(
            computed, entry.entry_hash,
            "sequence {}: the Rust hash differs from the one the independent script computed",
            entry.metadata.sequence
        );
        assert_eq!(entry.computed_hash().unwrap(), entry.entry_hash);
    }
    assert_eq!(verify_chain(&entries), Ok(()));
}

#[test]
fn chain_hash_matches_values_computed_with_shasum() {
    // printf '\n{}' | shasum -a 256
    assert_eq!(
        chain_hash(None, b"{}"),
        digest("sha256:a062dd4952b935e430d409c4a5e5cd760e8781e3200d5c7e12a232dddba8a528")
    );
    // printf 'sha256:aaaa...aaaa\n{}' | shasum -a 256, with the prefix as part of the hash text.
    let previous = digest(&format!("sha256:{}", "a".repeat(64)));
    assert_eq!(
        chain_hash(Some(&previous), b"{}"),
        digest("sha256:d6955e6e810b04d466cc34b0ec51b0c35a85ee099a7ee9ce14ca72553aa54db5")
    );
    // Without the prefix the answer is different, so the prefix is part of the contract.
    assert_ne!(
        chain_hash(Some(&previous), b"{}"),
        digest("sha256:0a05bf1902a7f16998a00306debf916791fd0209e48c969fc0565585d6d16285")
    );
}

#[test]
fn the_canonical_form_follows_rfc_8785_for_awkward_text() {
    let entries = fixture();

    let first = String::from_utf8(canonical_form(&entries[0]).unwrap()).unwrap();
    assert!(first.starts_with("{\"claim\":{\"assurance_level\":\"IMPLEMENTED\","), "{first}");
    assert!(!first.contains("entry_hash"), "the hash itself is not part of the input");
    assert!(first.contains("\"prev_entry_hash\":null"), "{first}");
    assert!(first.contains("a tab\\tinside"), "tab is escaped as \\t: {first}");
    assert!(first.contains("a back\\\\slash"), "backslash is doubled: {first}");
    assert!(first.contains("“quoted”") && first.contains('🚀') && first.contains("Résumé"));
    assert!(first.contains("a slash / too"), "slash is not escaped: {first}");
    assert!(!first.contains(": ") && !first.contains(", "), "no insignificant whitespace");

    let second = String::from_utf8(canonical_form(&entries[1]).unwrap()).unwrap();
    assert!(second.contains("assumption.\\nLine two"), "newline is escaped as \\n: {second}");
    assert!(second.contains("x=1&y=2"), "ampersand is not escaped: {second}");

    let last = String::from_utf8(canonical_form(&entries[4]).unwrap()).unwrap();
    assert!(last.contains("person.\\u001fThe separator"), "control characters use lower-case \\u00xx: {last}");
}

#[test]
fn an_integer_that_a_float_cannot_hold_exactly_is_refused_rather_than_rounded() {
    // Entry 4 holds the seed 2^53 - 1, which hashes. A seed of 2^53 is a valid document (the
    // schema says "integer") but RFC 8785 would write it as a rounded float, so it is not hashed.
    let entry = fixture().remove(3);
    assert!(canonical_form(&entry).is_ok());
    let mut value = entry.to_json_value().unwrap();
    assert_eq!(value["evidence"][0]["seeds"][1], 9_007_199_254_740_991_u64);
    value["evidence"][0]["seeds"][1] = serde_json::json!(9_007_199_254_740_992_u64);
    let too_big = EvidenceLedgerEntry::from_json_value(value).expect("the schema allows it");
    assert!(matches!(
        canonical_form(&too_big),
        Err(LedgerError::IntegerNotRepresentable { .. })
    ));
    assert!(matches!(
        too_big.sealed(),
        Err(LedgerError::IntegerNotRepresentable { .. })
    ));
}

// ---- tampering ------------------------------------------------------------------------------------

#[test]
fn changing_any_field_of_any_past_entry_is_detected() {
    let chain = fixture();
    for index in 0..chain.len() {
        let mut tampered = chain.clone();
        tampered[index].claim.statement = HumanText::parse("A quietly rewritten statement.").unwrap();
        let sequence = tampered[index].metadata.sequence.get();
        match verify_chain(&tampered) {
            Err(ChainError::HashMismatch { sequence: found, .. }) => assert_eq!(found, sequence),
            other => panic!("editing entry {sequence} was not reported as a hash mismatch: {other:?}"),
        }
    }
}

#[test]
fn rewriting_a_past_entry_and_its_own_hash_breaks_the_link_from_the_next_one() {
    let chain = fixture();
    for index in 0..chain.len() - 1 {
        let mut tampered = chain.clone();
        tampered[index].confidence.level = ConfidenceLevel::Low;
        tampered[index] = tampered[index].clone().sealed().unwrap();
        match verify_chain(&tampered) {
            Err(ChainError::BrokenLink { sequence, .. }) => {
                assert_eq!(sequence, tampered[index + 1].metadata.sequence.get());
            }
            other => panic!("a resealed entry {index} was not caught by its successor: {other:?}"),
        }
    }
}

#[test]
fn rewriting_the_last_entry_and_its_hash_is_caught_only_against_a_known_head() {
    // ADR 0008: the chain cannot stop someone who rewrites the whole table from some point on.
    // A head hash held somewhere else (the pull request, an export) is what catches it.
    let chain = fixture();
    let known_head = head_of(&chain).expect("the chain has entries");
    let mut tampered = chain.clone();
    let last = tampered.len() - 1;
    tampered[last].confidence.level = ConfidenceLevel::Low;
    tampered[last] = tampered[last].clone().sealed().unwrap();

    assert_eq!(verify_chain(&tampered), Ok(()), "the chain alone cannot see this");
    assert!(matches!(
        verify_chain_against_head(&tampered, &known_head),
        Err(ChainError::HeadMismatch { .. })
    ));
    assert_eq!(verify_chain_against_head(&chain, &known_head), Ok(()));
}

#[test]
fn removing_the_tail_is_caught_only_against_a_known_head() {
    let chain = fixture();
    let known_head = head_of(&chain).unwrap();
    let shorter = &chain[..3];
    assert_eq!(verify_chain(shorter), Ok(()));
    assert!(matches!(
        verify_chain_against_head(shorter, &known_head),
        Err(ChainError::HeadMismatch { .. })
    ));
}

#[test]
fn removing_reordering_or_repeating_an_entry_is_detected() {
    let chain = fixture();

    let mut removed = chain.clone();
    removed.remove(2);
    assert!(matches!(verify_chain(&removed), Err(ChainError::WrongSequence { .. })));

    let mut swapped = chain.clone();
    swapped.swap(1, 2);
    assert!(matches!(verify_chain(&swapped), Err(ChainError::WrongSequence { .. })));

    let mut repeated = chain.clone();
    repeated.insert(2, chain[1].clone());
    assert!(verify_chain(&repeated).is_err());

    let mut without_first = chain.clone();
    without_first.remove(0);
    assert!(matches!(verify_chain(&without_first), Err(ChainError::WrongSequence { .. })));
}

#[test]
fn an_entry_from_another_job_cannot_join_the_chain() {
    let mut chain = fixture();
    chain[3].metadata.job_id =
        factory_domain::ids::JobId::parse("018f3a7e-0000-7000-8000-000000000999").unwrap();
    let sealed = chain[3].clone().sealed().unwrap();
    chain[3] = sealed;
    // Re-link the entry after it so only the job id is wrong.
    chain[4].prev_entry_hash = Some(chain[3].entry_hash.clone());
    chain[4] = chain[4].clone().sealed().unwrap();
    assert!(matches!(verify_chain(&chain), Err(ChainError::WrongJob { .. })));
}

#[test]
fn an_empty_ledger_verifies_and_has_no_head() {
    assert_eq!(verify_chain(&[]), Ok(()));
    assert_eq!(head_of(&[]), None);
}

#[test]
fn chain_errors_read_as_plain_english() {
    let mut chain = fixture();
    chain[1].claim.statement = HumanText::parse("A quietly rewritten statement.").unwrap();
    let message = verify_chain(&chain).unwrap_err().to_string();
    assert_eq!(
        message,
        "the entry with sequence 2 does not match its own hash: it was changed after it was written"
    );
}

// ---- properties -----------------------------------------------------------------------------------

/// A valid entry to vary, with the position and hash fields left for `seal_chain`.
fn template() -> EvidenceLedgerEntry {
    fixture().remove(2)
}

#[derive(Debug, Clone)]
struct Draft {
    statement: String,
    rationale: String,
    seconds: u32,
    id: u128,
    evidence_bytes: Vec<u8>,
    level: u8,
}

fn drafts() -> impl Strategy<Value = Vec<Draft>> {
    let draft = (
        "[A-Za-z]{10,40}",
        "[A-Za-z]{10,40}",
        0u32..86_400,
        1u128..u128::MAX,
        proptest::collection::vec(any::<u8>(), 0..32),
        0u8..3,
    )
        .prop_map(|(statement, rationale, seconds, id, evidence_bytes, level)| Draft {
            statement,
            rationale,
            seconds,
            id,
            evidence_bytes,
            level,
        });
    proptest::collection::vec(draft, 1..9)
}

fn seal_chain(drafts: &[Draft]) -> Vec<EvidenceLedgerEntry> {
    let mut chain: Vec<EvidenceLedgerEntry> = Vec::new();
    for (index, draft) in drafts.iter().enumerate() {
        let mut entry = template();
        entry.metadata.sequence = factory_domain::values::PositiveInt::new(index as i64 + 1).unwrap();
        entry.metadata.entry_id = LedgerEntryId::from_uuid(uuid::Uuid::from_u128(draft.id));
        entry.metadata.recorded_at = Timestamp::parse(&format!(
            "2026-10-27T{:02}:{:02}:{:02}Z",
            draft.seconds / 3600,
            draft.seconds / 60 % 60,
            draft.seconds % 60
        ))
        .unwrap();
        entry.claim.statement = HumanText::parse(&draft.statement).unwrap();
        entry.confidence.rationale = HumanText::parse(&draft.rationale).unwrap();
        entry.confidence.level = ConfidenceLevel::ALL[usize::from(draft.level)];
        entry.evidence = vec![Evidence::Artifact(
            factory_domain::contracts::evidence_ledger_entry::ArtifactEvidence {
                sha256: Sha256Digest::of(&draft.evidence_bytes),
                media_type: factory_domain::values::MediaType::parse("application/octet-stream").unwrap(),
                description: None,
            },
        )];
        entry.prev_entry_hash = chain.last().map(|previous| previous.entry_hash.clone());
        chain.push(entry.sealed().unwrap());
    }
    chain
}

/// Ways to change one entry that keep it a well-formed entry. Each one changes the value.
fn edit(entry: &mut EvidenceLedgerEntry, kind: u8) {
    match kind % 6 {
        0 => {
            let text = format!("{} (edited)", entry.claim.statement);
            entry.claim.statement = HumanText::parse(&text).unwrap();
        }
        1 => {
            let text = format!("{} (edited)", entry.confidence.rationale);
            entry.confidence.rationale = HumanText::parse(&text).unwrap();
        }
        2 => {
            entry.confidence.level = match entry.confidence.level {
                ConfidenceLevel::Low => ConfidenceLevel::Medium,
                ConfidenceLevel::Medium => ConfidenceLevel::High,
                ConfidenceLevel::High => ConfidenceLevel::Low,
            };
        }
        3 => {
            entry.metadata.recorded_at = Timestamp::parse("2031-01-01T00:00:00Z").unwrap();
        }
        4 => {
            entry.metadata.entry_id = LedgerEntryId::parse("018f3a00-0000-7000-8000-00000000dead").unwrap();
        }
        _ => {
            let extra = entry.evidence[0].clone();
            let mut more = vec![extra];
            more.push(Evidence::Artifact(
                factory_domain::contracts::evidence_ledger_entry::ArtifactEvidence {
                    sha256: Sha256Digest::of(b"one more artifact"),
                    media_type: factory_domain::values::MediaType::parse("text/plain").unwrap(),
                    description: None,
                },
            ));
            entry.evidence.extend(more);
        }
    }
}

fn runner() -> TestRunner {
    TestRunner::new(Config {
        cases: 256,
        ..Config::default()
    })
}

#[test]
fn a_chain_built_by_sealing_each_entry_verifies() {
    runner()
        .run(&drafts(), |drafts| {
            let chain = seal_chain(&drafts);
            prop_assert_eq!(verify_chain(&chain), Ok(()));
            let head = head_of(&chain).unwrap();
            prop_assert_eq!(head.sequence, drafts.len() as u64);
            prop_assert_eq!(verify_chain_against_head(&chain, &head), Ok(()));
            Ok(())
        })
        .unwrap();
}

#[test]
fn any_edit_to_any_past_entry_is_detected_by_the_chain_hash() {
    runner()
        .run(&(drafts(), any::<usize>(), any::<u8>()), |(drafts, which, how)| {
            let chain = seal_chain(&drafts);
            let index = which % chain.len();
            let mut tampered = chain.clone();
            edit(&mut tampered[index], how);
            prop_assert_ne!(&tampered[index], &chain[index], "the edit must change the entry");
            let outcome = verify_chain(&tampered);
            prop_assert!(
                matches!(&outcome, Err(ChainError::HashMismatch { sequence, .. }) if *sequence == index as u64 + 1),
                "editing entry {} gave {:?}",
                index + 1,
                outcome
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn an_edit_that_also_rewrites_the_entry_hash_is_caught_by_the_next_entry_or_the_known_head() {
    runner()
        .run(&(drafts(), any::<usize>(), any::<u8>()), |(drafts, which, how)| {
            let chain = seal_chain(&drafts);
            let known_head = head_of(&chain).unwrap();
            let index = which % chain.len();
            let mut tampered = chain.clone();
            edit(&mut tampered[index], how);
            tampered[index] = tampered[index].clone().sealed().unwrap();
            if index + 1 < chain.len() {
                let outcome = verify_chain(&tampered);
                prop_assert!(
                    matches!(&outcome, Err(ChainError::BrokenLink { sequence, .. }) if *sequence == index as u64 + 2),
                    "resealing entry {} gave {:?}",
                    index + 1,
                    outcome
                );
            } else {
                prop_assert_eq!(verify_chain(&tampered), Ok(()));
                prop_assert!(verify_chain_against_head(&tampered, &known_head).is_err());
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn dropping_an_entry_from_a_longer_chain_is_detected() {
    runner()
        .run(&(drafts(), any::<usize>()), |(drafts, which)| {
            let chain = seal_chain(&drafts);
            prop_assume!(chain.len() > 1);
            let index = which % (chain.len() - 1); // never the last: a dropped tail needs a known head
            let mut shorter = chain.clone();
            shorter.remove(index);
            prop_assert!(verify_chain(&shorter).is_err());
            Ok(())
        })
        .unwrap();
}

#[test]
fn chain_head_carries_the_sequence_and_hash_the_evidence_manifest_records() {
    let chain = fixture();
    let head = head_of(&chain).unwrap();
    assert_eq!(
        head,
        ChainHead {
            sequence: 5,
            hash: chain[4].entry_hash.clone()
        }
    );
    // A value the schema and the manifest use must read back the same through the contract trait.
    let value = chain[4].to_json_value().unwrap();
    assert_eq!(value["entry_hash"], head.hash.to_string());
}
