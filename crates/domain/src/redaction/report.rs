//! What a scan found. The report names what matched and where, and never holds a secret value.

use std::collections::BTreeSet;

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// A secret.
    Blocking,
    /// A signal that does not stop work.
    Flag,
}

/// Where a finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FindingSource {
    /// A value in the registry of the factory's own secrets.
    Registry,
    /// A pattern from the policy.
    Pattern,
    /// The entropy heuristic.
    Entropy,
}

/// One match. The offsets are byte offsets into the original input, from the first to one past
/// the last byte of the match. They include any escape sequence or invisible character inside it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Finding {
    /// The first byte offset of the match.
    pub start: u64,
    /// One past the last byte offset of the match.
    pub end: u64,
    /// The pattern identifier, the registry label, or `entropy`.
    pub id: String,
    /// Where the finding came from.
    pub source: FindingSource,
    /// How serious it is.
    pub severity: Severity,
}

/// The most findings a report lists. The counts stay exact beyond it.
pub const MAX_LISTED_FINDINGS: usize = 64;

/// The result of scanning or redacting one input or stream.
///
/// The same input gives the same report, whatever the chunk sizes it was fed in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub(super) replaced: u64,
    pub(super) findings: Vec<Finding>,
    pub(super) ids: BTreeSet<String>,
    pub(super) blocking: bool,
    pub(super) flagged: bool,
}

impl Report {
    /// True when nothing at all was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.blocking && !self.flagged
    }

    /// True when a secret was found: a registered value or a pattern whose action is block.
    /// This is the answer to "may this be published".
    #[must_use]
    pub fn has_blocking(&self) -> bool {
        self.blocking
    }

    /// True when a flag was raised.
    #[must_use]
    pub fn has_flagged(&self) -> bool {
        self.flagged
    }

    /// How many spans of the text were replaced by a marker.
    #[must_use]
    pub fn replacements(&self) -> u64 {
        self.replaced
    }

    /// The first findings by position, at most [`MAX_LISTED_FINDINGS`], without repeats.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Every identifier that matched at least once, in alphabetical order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().map(String::as_str)
    }
}
