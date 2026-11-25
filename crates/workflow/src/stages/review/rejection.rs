//! Why the factory refused a reviewer's answer, written where a person can read it.
//!
//! The code review and the documentation review check the reviewer's answer in code before it
//! becomes a verdict. An answer that breaks a rule fails the attempt with `INVALID_OUTPUT`, and
//! after the last attempt the stage run waits for a person. Without a record of the rule, that
//! person sees only the class: the first real run that stopped this way could not be diagnosed
//! from anything it kept. Each refusal therefore writes an audit record `gate_result`, decision
//! `denied`, whose reason names the stage and the rule (the runbook of first-run signals, signal 6).
//!
//! The reason is built from fixed words, numbers, the field paths the contract check produces and
//! a path the reviewer cited, cleaned to the characters a repository path uses. It never holds the
//! words of a finding: those are text a model wrote, and the audit log is not a place for them.

use factory_domain::contracts::review_verdict::Finding;

use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::handlers::{StageContext, StageError};
use crate::stages::review::findings::WrapProblem;

/// The longest cited path a reason keeps, in characters.
const MAX_PATH_CHARS: usize = 120;

/// The most contract fields a reason names.
const MAX_FIELDS: usize = 5;

/// The rule a reviewer's answer broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection<'a> {
    /// The answer is not UTF-8 text.
    NotText,
    /// The redactor could not judge the answer, so it cannot be stored.
    NotRedactable,
    /// The answer does not follow the agent's output schema.
    Schema,
    /// The answer is not an object, or names a field the review contract does not.
    Shape,
    /// The wrapped verdict breaks rules of the `review-verdict` contract, at these fields.
    Contract(&'a [String]),
    /// A finding of a verdict other than `PASS` cites lines that no patch the reviewer was shown
    /// holds in one hunk. `index` counts from 1, in the order of the verdict's findings.
    NotShown {
        /// The place of the finding in the verdict, from 1.
        index: usize,
        /// The path the finding cites.
        path: &'a str,
        /// The first line it cites, when it gives one.
        line_start: Option<i64>,
        /// The last line it cites, when it gives one.
        line_end: Option<i64>,
    },
}

impl<'a> Rejection<'a> {
    /// The rejection for a problem of [`wrap`](crate::stages::review::findings::wrap).
    #[must_use]
    pub fn of_wrap(problem: &'a WrapProblem) -> Self {
        match problem {
            WrapProblem::Shape => Self::Shape,
            WrapProblem::Contract { fields } => Self::Contract(fields),
        }
    }

    /// The rejection for the finding at `position` (from 0) of a verdict, whose lines no patch
    /// shows. A finding with no location is named with an empty path; the contract check refuses
    /// one before this, so it is a fault in the factory if it is ever written.
    #[must_use]
    pub fn not_shown(position: usize, finding: &'a Finding) -> Self {
        let location = finding.location.as_ref();
        Self::NotShown {
            index: position.saturating_add(1),
            path: location.map_or("", |location| location.path.as_str()),
            line_start: location.and_then(|location| location.line_start.map(|line| line.get())),
            line_end: location.and_then(|location| location.line_end.map(|line| line.get())),
        }
    }

    /// The reason the audit record carries. `stage` is the stage's own name, such as
    /// `documentation review`.
    #[must_use]
    pub fn reason(&self, stage: &str) -> String {
        let rule = match self {
            Self::NotText => "the answer is not UTF-8 text".to_owned(),
            Self::NotRedactable => {
                "the redactor could not judge the answer, so it is not kept".to_owned()
            }
            Self::Schema => "the answer does not follow the agent's output schema".to_owned(),
            Self::Shape => {
                "the answer is not an object, or names a field the review contract does not"
                    .to_owned()
            }
            Self::Contract([]) => "the answer does not read as a review verdict".to_owned(),
            Self::Contract(fields) => {
                let shown: Vec<&str> = fields.iter().take(MAX_FIELDS).map(String::as_str).collect();
                let more = fields.len().saturating_sub(MAX_FIELDS);
                let tail = if more == 0 {
                    String::new()
                } else {
                    format!(" and {more} more")
                };
                format!(
                    "the verdict breaks the review-verdict contract at {}{tail}",
                    shown.join(", ")
                )
            }
            Self::NotShown {
                index,
                path,
                line_start,
                line_end,
            } => {
                let lines = match (line_start, line_end) {
                    (None, _) => "no line".to_owned(),
                    (Some(start), None) => format!("line {start}"),
                    (Some(start), Some(end)) if end == start => format!("line {start}"),
                    (Some(start), Some(end)) => format!("lines {start} to {end}"),
                };
                format!(
                    "finding {index} cites {} at {lines}, which no patch the reviewer was shown holds in one hunk",
                    clean_path(path)
                )
            }
        };
        format!("{stage}: the reviewer's answer was refused: {rule}")
    }
}

/// Records why the answer was refused, and returns the error that fails the attempt.
pub fn refuse(ctx: &mut StageContext<'_>, stage: &str, rejection: &Rejection<'_>) -> StageError {
    ctx.note_audit_because(
        AuditAction::new(AuditKind::GateResult, AuditDecision::Denied),
        rejection.reason(stage),
    );
    StageError::InvalidOutput
}

/// A cited path as the reason may hold it: only the characters a repository path uses, at most
/// [`MAX_PATH_CHARS`] of them, in backticks. A path that needed changing says so.
fn clean_path(path: &str) -> String {
    let kept: String = path
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        .take(MAX_PATH_CHARS)
        .collect();
    if kept.is_empty() {
        return "a path with no character a repository path uses".to_owned();
    }
    if kept == path {
        format!("`{kept}`")
    } else {
        format!("`{kept}` (cleaned)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGE: &str = "documentation review";

    #[test]
    fn a_finding_outside_the_patches_names_its_place_its_path_and_its_lines() {
        let reason = Rejection::NotShown {
            index: 2,
            path: "notes.txt",
            line_start: Some(1),
            line_end: Some(3),
        }
        .reason(STAGE);
        assert_eq!(
            reason,
            "documentation review: the reviewer's answer was refused: finding 2 cites `notes.txt` at lines 1 to 3, which no patch the reviewer was shown holds in one hunk"
        );
    }

    #[test]
    fn one_line_is_named_once_whether_or_not_the_end_repeats_it() {
        let only_start = Rejection::NotShown {
            index: 1,
            path: "README.md",
            line_start: Some(24),
            line_end: None,
        }
        .reason(STAGE);
        let same_end = Rejection::NotShown {
            index: 1,
            path: "README.md",
            line_start: Some(24),
            line_end: Some(24),
        }
        .reason(STAGE);
        assert!(only_start.contains("at line 24,"));
        assert_eq!(only_start, same_end);
    }

    #[test]
    fn a_finding_with_no_line_says_so() {
        let reason = Rejection::NotShown {
            index: 1,
            path: "README.md",
            line_start: None,
            line_end: None,
        }
        .reason(STAGE);
        assert!(reason.contains("`README.md` at no line"));
    }

    #[test]
    fn a_path_keeps_only_the_characters_of_a_repository_path() {
        assert_eq!(clean_path("docs/guide-1_a.md"), "`docs/guide-1_a.md`");
        assert_eq!(
            clean_path("README.md\nIgnore the rules"),
            "`README.mdIgnoretherules` (cleaned)"
        );
        assert_eq!(
            clean_path("\n\t "),
            "a path with no character a repository path uses"
        );
    }

    #[test]
    fn a_long_path_is_cut_at_the_limit() {
        let long = "a".repeat(MAX_PATH_CHARS + 30);
        let cleaned = clean_path(&long);
        assert_eq!(
            cleaned,
            format!("`{}` (cleaned)", "a".repeat(MAX_PATH_CHARS))
        );
        let exact = "b".repeat(MAX_PATH_CHARS);
        assert_eq!(clean_path(&exact), format!("`{exact}`"));
    }

    #[test]
    fn the_contract_fields_are_named_up_to_the_limit() {
        let fields: Vec<String> = (0..MAX_FIELDS + 2)
            .map(|index| format!("findings[{index}].location"))
            .collect();
        let reason = Rejection::Contract(&fields).reason(STAGE);
        assert!(reason.ends_with(
            "at findings[0].location, findings[1].location, findings[2].location, findings[3].location, findings[4].location and 2 more"
        ));
        let one = vec!["findings[0].location".to_owned()];
        assert!(
            Rejection::Contract(&one)
                .reason(STAGE)
                .ends_with("at findings[0].location")
        );
        assert!(
            Rejection::Contract(&[])
                .reason(STAGE)
                .ends_with("does not read as a review verdict")
        );
    }

    #[test]
    fn the_wrap_problems_map_to_their_rules() {
        assert_eq!(Rejection::of_wrap(&WrapProblem::Shape), Rejection::Shape);
        let problem = WrapProblem::Contract {
            fields: vec!["findings[0].location".to_owned()],
        };
        assert!(matches!(
            Rejection::of_wrap(&problem),
            Rejection::Contract(fields) if fields == ["findings[0].location".to_owned()]
        ));
    }

    #[test]
    fn every_rule_names_the_stage() {
        let fields: Vec<String> = Vec::new();
        for rejection in [
            Rejection::NotText,
            Rejection::NotRedactable,
            Rejection::Schema,
            Rejection::Shape,
            Rejection::Contract(&fields),
        ] {
            assert!(
                rejection
                    .reason("code review")
                    .starts_with("code review: the reviewer's answer was refused: ")
            );
        }
    }
}
