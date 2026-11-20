//! The hash chain of the evidence ledger (ADR 0008).
//!
//! Entries for a job form a chain. Each entry's `entry_hash` is the SHA-256 of
//!
//! 1. the previous entry's hash text, the whole `sha256:...` string, or nothing for the first
//!    entry,
//! 2. a newline, and
//! 3. the RFC 8785 canonical JSON of the entry without its `entry_hash` field. The entry still
//!    carries its own `prev_entry_hash`.
//!
//! Everything here is a pure function of its arguments: no storage, no clock, no randomness. The
//! storage adapter calls [`EvidenceLedgerEntry::sealed`] before an append and [`verify_chain`] on
//! demand, and the workflow engine calls it before completing a job.
//!
//! # What the chain can and cannot show
//!
//! A change to any past entry, a removed or reordered entry, and a new entry from another job
//! are all detected. Someone who can rewrite the whole table from some point onward can still
//! recompute every later hash, so the chain alone cannot see a rewritten last entry or a cut-off
//! tail. A head hash kept elsewhere, such as the one in the pull request's evidence manifest,
//! does: see [`verify_chain_against_head`].
//!
//! The expected hashes in `tests/fixtures/ledger_chain.json` come from an independent Python
//! script, `tests/oracle/ledger_chain_oracle.py`.

use serde_json::Value;

use crate::contracts::EvidenceLedgerEntry;
use crate::ids::JobId;
use crate::values::Sha256Digest;

/// The largest whole number that a 64-bit float holds exactly: 2^53 - 1 (ADR 0011).
///
/// The same number as [`crate::values::LARGEST_EXACT_INTEGER`], which bounds the integers of a
/// ledger entry when the entry is built. This is the second layer: the hash function refuses a
/// larger number even if a value got past the first one.
pub const LARGEST_EXACT_INTEGER: u64 = crate::values::LARGEST_EXACT_INTEGER.unsigned_abs();

/// An entry that cannot be turned into canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The entry could not be written as JSON at all.
    #[error("the entry cannot be written as canonical JSON: {reason}")]
    Canonicalization {
        /// What the JSON writer reported.
        reason: String,
    },
    /// The entry holds a number that RFC 8785 would round.
    #[error(
        "the entry holds the number {number}; a ledger entry may hold only whole numbers up to 9007199254740991, because RFC 8785 writes every number as a 64-bit float and a larger one would be rounded"
    )]
    IntegerNotRepresentable {
        /// The number as written in the entry.
        number: String,
    },
}

/// The last entry of a chain: what a pull request's evidence manifest records and what a later
/// check compares against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    /// The sequence of the last entry.
    pub sequence: u64,
    /// Its `entry_hash`.
    pub hash: Sha256Digest,
}

/// Why a chain does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// An entry is not at the position its sequence number claims.
    #[error(
        "the entry in position {position} has sequence {found}, but the chain has no gaps, so it should be {expected}"
    )]
    WrongSequence {
        /// Zero-based position in the list.
        position: usize,
        /// The sequence the position requires.
        expected: u64,
        /// The sequence the entry carries.
        found: u64,
    },
    /// An entry belongs to a different job than the first one.
    #[error("the entry with sequence {sequence} belongs to job {found}, not to job {expected}")]
    WrongJob {
        /// The entry's sequence.
        sequence: u64,
        /// The job of the first entry.
        expected: JobId,
        /// The job of this entry.
        found: JobId,
    },
    /// An entry does not point at the hash of the entry before it.
    #[error(
        "the entry with sequence {sequence} does not point at the hash of the entry before it: an earlier entry was changed, removed or replaced"
    )]
    BrokenLink {
        /// The entry's sequence.
        sequence: u64,
        /// The hash the previous entry has, or nothing for the first entry.
        expected: Option<Sha256Digest>,
        /// The hash the entry points at.
        found: Option<Sha256Digest>,
    },
    /// An entry's stored hash is not the hash of its content.
    #[error(
        "the entry with sequence {sequence} does not match its own hash: it was changed after it was written"
    )]
    HashMismatch {
        /// The entry's sequence.
        sequence: u64,
        /// The hash stored in the entry.
        stored: Sha256Digest,
        /// The hash its content has.
        computed: Sha256Digest,
    },
    /// An entry cannot be hashed.
    #[error("the entry with sequence {sequence} cannot be hashed: {source}")]
    Unhashable {
        /// The entry's sequence.
        sequence: u64,
        /// Why not.
        source: LedgerError,
    },
    /// The chain is internally consistent but does not end where it should.
    #[error(
        "the chain does not end at the known head (sequence {} with hash {}): the last entry was changed or the chain was cut short",
        expected.sequence,
        expected.hash
    )]
    HeadMismatch {
        /// The head that was recorded elsewhere.
        expected: ChainHead,
        /// The head of the chain that was checked, or nothing if it is empty.
        found: Option<ChainHead>,
    },
}

/// The canonical JSON bytes of an entry without its `entry_hash`, as RFC 8785 defines them.
///
/// # Errors
/// Returns [`LedgerError::IntegerNotRepresentable`] for a number that RFC 8785 would round, and
/// [`LedgerError::Canonicalization`] if the entry cannot be written as JSON.
pub fn canonical_form(entry: &EvidenceLedgerEntry) -> Result<Vec<u8>, LedgerError> {
    let mut document =
        serde_json::to_value(entry).map_err(|error| LedgerError::Canonicalization {
            reason: error.to_string(),
        })?;
    if let Some(object) = document.as_object_mut() {
        object.remove("entry_hash");
    }
    require_exact_numbers(&document)?;
    serde_jcs::to_vec(&document).map_err(|error| LedgerError::Canonicalization {
        reason: error.to_string(),
    })
}

fn require_exact_numbers(node: &Value) -> Result<(), LedgerError> {
    match node {
        Value::Number(number) => {
            let exact = number
                .as_u64()
                .is_some_and(|value| value <= LARGEST_EXACT_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|value| value.unsigned_abs() <= LARGEST_EXACT_INTEGER);
            if exact {
                Ok(())
            } else {
                Err(LedgerError::IntegerNotRepresentable {
                    number: number.to_string(),
                })
            }
        }
        Value::Array(items) => items.iter().try_for_each(require_exact_numbers),
        Value::Object(map) => map.values().try_for_each(require_exact_numbers),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// The hash of an entry: SHA-256 over the previous entry's hash text (nothing for the first
/// entry), a newline, and `canonical`, the canonical JSON of the entry without its `entry_hash`.
#[must_use]
pub fn chain_hash(previous: Option<&Sha256Digest>, canonical: &[u8]) -> Sha256Digest {
    let previous_text = previous.map_or("", Sha256Digest::as_str);
    let mut input = Vec::with_capacity(previous_text.len() + 1 + canonical.len());
    input.extend_from_slice(previous_text.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(canonical);
    Sha256Digest::of(&input)
}

impl EvidenceLedgerEntry {
    /// The entry's position in its job's chain, from 1.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        // The sequence is a positive integer, so the conversion cannot fail.
        u64::try_from(self.metadata.sequence.get()).unwrap_or(0)
    }

    /// The hash this entry should carry, from its content and its `prev_entry_hash`.
    ///
    /// # Errors
    /// Returns a [`LedgerError`] when the entry cannot be written canonically.
    pub fn computed_hash(&self) -> Result<Sha256Digest, LedgerError> {
        Ok(chain_hash(
            self.prev_entry_hash.as_ref(),
            &canonical_form(self)?,
        ))
    }

    /// Returns the entry with its `entry_hash` set to the hash of its content. Set the entry's
    /// `prev_entry_hash` to the previous entry's hash first.
    ///
    /// # Errors
    /// Returns a [`LedgerError`] when the entry cannot be written canonically.
    pub fn sealed(mut self) -> Result<Self, LedgerError> {
        self.entry_hash = self.computed_hash()?;
        Ok(self)
    }
}

/// The head of a chain, or `None` for an empty one.
#[must_use]
pub fn head_of(entries: &[EvidenceLedgerEntry]) -> Option<ChainHead> {
    entries.last().map(|last| ChainHead {
        sequence: last.sequence(),
        hash: last.entry_hash.clone(),
    })
}

/// Checks a whole chain from its first entry.
///
/// For every entry it checks, in this order: the sequence has no gap and starts at 1, the job is
/// the first entry's job, the entry points at the hash of the one before it (nothing for the
/// first), and its stored hash is the hash of its content. An empty chain verifies.
///
/// # Errors
/// Returns the first problem found, in plain English.
pub fn verify_chain(entries: &[EvidenceLedgerEntry]) -> Result<(), ChainError> {
    let Some(first) = entries.first() else {
        return Ok(());
    };
    let job = first.metadata.job_id;
    let mut previous: Option<&Sha256Digest> = None;
    for (position, entry) in entries.iter().enumerate() {
        let sequence = entry.sequence();
        let expected_sequence = position as u64 + 1;
        if sequence != expected_sequence {
            return Err(ChainError::WrongSequence {
                position,
                expected: expected_sequence,
                found: sequence,
            });
        }
        if entry.metadata.job_id != job {
            return Err(ChainError::WrongJob {
                sequence,
                expected: job,
                found: entry.metadata.job_id,
            });
        }
        if entry.prev_entry_hash.as_ref() != previous {
            return Err(ChainError::BrokenLink {
                sequence,
                expected: previous.cloned(),
                found: entry.prev_entry_hash.clone(),
            });
        }
        let computed = entry
            .computed_hash()
            .map_err(|source| ChainError::Unhashable { sequence, source })?;
        if computed != entry.entry_hash {
            return Err(ChainError::HashMismatch {
                sequence,
                stored: entry.entry_hash.clone(),
                computed,
            });
        }
        previous = Some(&entry.entry_hash);
    }
    Ok(())
}

/// Checks a chain and then that it ends at `head`, which was recorded somewhere else (the
/// evidence manifest in the pull request, an export). This is what catches a rewritten last entry
/// or a removed tail.
///
/// # Errors
/// Returns the first problem found, or [`ChainError::HeadMismatch`].
pub fn verify_chain_against_head(
    entries: &[EvidenceLedgerEntry],
    head: &ChainHead,
) -> Result<(), ChainError> {
    verify_chain(entries)?;
    let found = head_of(entries);
    if found.as_ref() == Some(head) {
        Ok(())
    } else {
        Err(ChainError::HeadMismatch {
            expected: head.clone(),
            found,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{LARGEST_EXACT_INTEGER, LedgerError, require_exact_numbers};

    #[test]
    fn the_ledger_limit_is_the_largest_whole_number_a_float_holds() {
        assert_eq!(LARGEST_EXACT_INTEGER, 9_007_199_254_740_991);
        assert_eq!(LARGEST_EXACT_INTEGER, (1_u64 << 53) - 1);
    }

    fn refused(document: &Value) -> Option<String> {
        match require_exact_numbers(document) {
            Err(LedgerError::IntegerNotRepresentable { number }) => Some(number),
            Err(other) => panic!("{other}"),
            Ok(()) => None,
        }
    }

    #[test]
    fn the_second_layer_still_refuses_a_number_the_first_layer_should_have_stopped() {
        // The types of a ledger entry cannot hold these numbers, so the check is tried directly.
        assert_eq!(
            refused(&json!(9_007_199_254_740_992_u64)),
            Some("9007199254740992".into())
        );
        assert_eq!(
            refused(&json!(-9_007_199_254_740_992_i64)),
            Some("-9007199254740992".into())
        );
        assert_eq!(refused(&json!(u64::MAX)), Some(u64::MAX.to_string()));
        assert_eq!(refused(&json!(i64::MIN)), Some(i64::MIN.to_string()));
    }

    #[test]
    fn the_second_layer_accepts_both_ends_of_the_exact_range() {
        assert_eq!(refused(&json!(9_007_199_254_740_991_u64)), None);
        assert_eq!(refused(&json!(-9_007_199_254_740_991_i64)), None);
        assert_eq!(refused(&json!(0)), None);
    }

    #[test]
    fn the_second_layer_looks_inside_arrays_and_objects() {
        let nested =
            json!({ "evidence": [{ "seeds": [1, 2, { "deep": [9_007_199_254_740_992_u64] }] }] });
        assert_eq!(refused(&nested), Some("9007199254740992".into()));
        let fine = json!({ "evidence": [{ "seeds": [1, 2, { "deep": [3] }] }], "text": "9007199254740992" });
        assert_eq!(refused(&fine), None);
    }
}
