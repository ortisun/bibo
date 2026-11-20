//! A finding: one rule that the text broke, where, and what to do about it.

use super::catalog::{RuleId, Severity};

/// Which part of the artifact a finding points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Part {
    /// The title.
    Title,
    /// The body.
    Body,
}

impl Part {
    /// The word used in the location of a finding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Body => "body",
        }
    }
}

/// One rule that an artifact broke. A rule gives at most one finding for each artifact, so a
/// hostile text cannot make the report grow with its own size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule. Its identifier is the `check_id` in the gate report.
    pub rule: RuleId,
    /// Whether the finding blocks or warns, as the catalog says.
    pub severity: Severity,
    /// The path of the artifact inside the stage output, empty when the caller gave none.
    pub artifact: String,
    /// The part that holds the problem.
    pub part: Part,
    /// The line of the body, from 1, when the rule can name one.
    pub line: Option<u32>,
    /// What was found, in plain English.
    pub message: String,
    /// What the author can do about it, from the catalog.
    pub suggested_fix: String,
}

impl Finding {
    /// The path written in the location of the gate report: `title`, `body`, or the same behind
    /// the artifact path (`tasks/12/title`).
    #[must_use]
    pub fn location_path(&self) -> String {
        if self.artifact.is_empty() {
            self.part.as_str().to_owned()
        } else {
            format!("{}/{}", self.artifact, self.part.as_str())
        }
    }
}
