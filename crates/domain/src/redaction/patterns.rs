//! The patterns of the policy, compiled, and the entropy heuristic.
//!
//! The regular expressions are compiled exactly as the policy writes them. Nothing here knows a
//! vendor format.
//!
//! They are compiled for bytes and with Unicode switched off. That has three effects, and all of
//! them make the redactor stricter, never looser:
//!
//! * a pattern can match inside text that is not valid UTF-8, and a class such as `[^\s@/]`
//!   takes any byte that is not ASCII white space;
//! * `(?i)` folds ASCII letters only, which keeps the crate free of the Unicode case tables;
//! * `\b` is a boundary between an ASCII word character and anything else, so a token that sits
//!   right behind a non-ASCII letter is still found.

use std::sync::Arc;

use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

use super::config::{EntropySpec, PatternAction, PatternSpec};
use super::error::BuildError;
use super::report::Severity;

/// The largest compiled size of one pattern.
const SIZE_LIMIT: usize = 1 << 20;

/// True for an identifier that can be written inside `[REDACTED:<id>]` without ambiguity.
pub(super) fn is_valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

pub(super) fn severity_of(action: PatternAction) -> Severity {
    match action {
        PatternAction::Block => Severity::Blocking,
        PatternAction::Flag => Severity::Flag,
    }
}

/// One pattern, compiled.
#[derive(Debug)]
pub(super) struct CompiledPattern {
    pub(super) id: Arc<str>,
    pub(super) regex: Regex,
    pub(super) severity: Severity,
}

/// The entropy heuristic, checked.
#[derive(Debug, Clone, Copy)]
pub(super) struct EntropyRule {
    pub(super) min_length: usize,
    pub(super) min_bits: f64,
    pub(super) severity: Severity,
}

/// All patterns of one redactor.
#[derive(Debug)]
pub(super) struct PatternSet {
    pub(super) patterns: Vec<CompiledPattern>,
    /// All the patterns together, to learn in one pass which of them match a stretch of text.
    set: Option<RegexSet>,
    pub(super) entropy: Option<EntropyRule>,
}

impl PatternSet {
    pub(super) fn compile(
        specs: &[PatternSpec],
        entropy: Option<EntropySpec>,
    ) -> Result<Self, BuildError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut patterns = Vec::with_capacity(specs.len());
        for spec in specs {
            if !is_valid_id(&spec.id) {
                return Err(BuildError::InvalidId {
                    id: spec.id.clone(),
                });
            }
            if !seen.insert(spec.id.as_str()) {
                return Err(BuildError::DuplicateId {
                    id: spec.id.clone(),
                });
            }
            let regex = RegexBuilder::new(&spec.regex)
                .unicode(false)
                .size_limit(SIZE_LIMIT)
                .build()
                .map_err(|e| BuildError::InvalidPattern {
                    id: spec.id.clone(),
                    reason: e.to_string(),
                })?;
            if regex.is_match(b"") {
                return Err(BuildError::EmptyMatch {
                    id: spec.id.clone(),
                });
            }
            patterns.push(CompiledPattern {
                id: Arc::from(spec.id.as_str()),
                regex,
                severity: severity_of(spec.action),
            });
        }
        let set = if specs.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(specs.iter().map(|s| s.regex.as_str()))
                    .unicode(false)
                    .build()
                    .map_err(|e| BuildError::InvalidPattern {
                        id: "(all patterns together)".to_owned(),
                        reason: e.to_string(),
                    })?,
            )
        };
        let entropy = entropy.map(check_entropy).transpose()?;
        Ok(Self {
            patterns,
            set,
            entropy,
        })
    }

    /// The indexes of the patterns that match `haystack` at or after `start`, in order.
    pub(super) fn matching(&self, haystack: &[u8], start: usize) -> Vec<usize> {
        self.set.as_ref().map_or_else(Vec::new, |set| {
            set.matches_at(haystack, start).iter().collect()
        })
    }
}

fn check_entropy(spec: EntropySpec) -> Result<EntropyRule, BuildError> {
    if spec.min_length == 0 {
        return Err(BuildError::InvalidEntropy {
            reason: "the shortest run must be at least one byte".to_owned(),
        });
    }
    if !(spec.min_bits_per_char.is_finite()
        && spec.min_bits_per_char > 0.0
        && spec.min_bits_per_char <= 8.0)
    {
        return Err(BuildError::InvalidEntropy {
            reason: "the threshold must be above 0 and at most 8 bits per byte".to_owned(),
        });
    }
    Ok(EntropyRule {
        min_length: spec.min_length,
        min_bits: spec.min_bits_per_char,
        severity: severity_of(spec.action),
    })
}

/// True for the bytes the entropy heuristic reads as one run: letters, digits and the
/// punctuation of base64 and of URL-safe base64.
pub(super) fn is_run_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// The Shannon entropy of `run`, in bits per byte.
pub(super) fn shannon_bits_per_byte(run: &[u8]) -> f64 {
    if run.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in run {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c += 1;
        }
    }
    let total = run.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_limited_to_what_a_marker_can_hold() {
        for ok in ["a", "github_token_classic", "x-y.z_9", &"a".repeat(64)] {
            assert!(is_valid_id(ok), "{ok}");
        }
        for bad in ["", "a b", "a]", "a:b", "a/b", "a\n", "é", &"a".repeat(65)] {
            assert!(!is_valid_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn entropy_is_zero_for_one_symbol_and_log2_of_the_alphabet_for_a_flat_one() {
        assert_eq!(shannon_bits_per_byte(b"aaaaaaaa"), 0.0);
        let flat: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_bits_per_byte(&flat) - 8.0).abs() < 1e-9);
        assert!((shannon_bits_per_byte(b"abababab") - 1.0).abs() < 1e-9);
        assert_eq!(shannon_bits_per_byte(b""), 0.0);
    }

    #[test]
    fn case_insensitive_patterns_compile_without_the_unicode_tables() {
        let set = PatternSet::compile(
            &[PatternSpec::new(
                "ci",
                r"(?i)\bauthorization:\s*bearer\s+[a-z0-9]{8,}",
                PatternAction::Block,
            )],
            None,
        )
        .unwrap();
        assert!(
            set.patterns[0]
                .regex
                .is_match(b"AUTHORIZATION: Bearer abcdefgh1")
        );
    }

    #[test]
    fn a_pattern_can_match_text_that_is_not_utf8() {
        let set = PatternSet::compile(
            &[PatternSpec::new(
                "any",
                r"k=[^\s]{4,}",
                PatternAction::Block,
            )],
            None,
        )
        .unwrap();
        assert!(set.patterns[0].regex.is_match(b"k=\xff\xfe\xfd\xfc"));
    }

    #[test]
    fn the_set_says_which_patterns_match_after_a_start() {
        let specs = [
            PatternSpec::new("a", "AAAA", PatternAction::Block),
            PatternSpec::new("b", "BBBB", PatternAction::Block),
        ];
        let set = PatternSet::compile(&specs, None).unwrap();
        assert_eq!(set.matching(b"xxAAAAxxBBBB", 0), vec![0, 1]);
        assert_eq!(set.matching(b"xxAAAAxxBBBB", 3), vec![1]);
        assert!(set.matching(b"nothing", 0).is_empty());
    }
}
