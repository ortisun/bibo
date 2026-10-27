//! The settings a redactor keeps after it is built. They never change.

use super::config::{FlagHandling, Limits};
use super::encodings::Encoding;
use super::patterns::PatternSet;
use super::report::Severity;

#[derive(Debug)]
pub(super) struct Core {
    pub(super) patterns: PatternSet,
    pub(super) flagged: FlagHandling,
    pub(super) limits: Limits,
    pub(super) min_len: usize,
    pub(super) encodings: Vec<Encoding>,
}

impl Core {
    /// True when a match of this severity is replaced in the text. A secret always is. A flag
    /// is only when the redactor was set to redact flags.
    pub(super) fn replaces(&self, severity: Severity) -> bool {
        severity == Severity::Blocking || self.flagged == FlagHandling::Redact
    }
}
