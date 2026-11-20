//! The independent architecture critic, for work whose risk tier the policy says needs one.
//!
//! # What the factory can and cannot do today
//!
//! The agent definitions hold no critic. The stage looks for an agent called by the configuration
//! (`architecture-critic` by default) and, when the registry has none, it records that no critic
//! ran and why, and asks a person. It never writes a verdict in the critic's name and it never lets
//! the architect review its own design.
//!
//! # What a critic must be, when one is added
//!
//! * Its role ends with `_critic`, so the prompt assembler treats it as an independent reviewer.
//! * It differs from the architect, and its manifest grants only tools that read.
//! * Its prompt takes three inputs, by these names and classes: `frozen_specification`
//!   (`specification_text`), `architecture_design` (`model_output`) and `repository_map`
//!   (`tool_output`). The design it receives is the elements, decisions, risks and open questions.
//!   The architect's summary and its list of ignored instructions are withheld, because they are
//!   the author's account of its own work.
//! * It returns `review-findings`, the schema the other reviewers return.

use serde_json::{Map, Value};

/// The name of the input that holds the frozen specification.
pub const INPUT_SPECIFICATION: &str = "frozen_specification";
/// The name of the input that holds the design under review.
pub const INPUT_DESIGN: &str = "architecture_design";
/// The name of the input that holds the repository map.
pub const INPUT_MAP: &str = "repository_map";
/// The schema the critic returns.
pub const OUTPUT_SCHEMA: &str = "review-findings";

/// What the critic concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The design stands.
    Pass,
    /// The design needs changes.
    ChangesRequired,
    /// The design must not go on.
    Block,
    /// A person must decide.
    NeedsHuman,
}

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Must be fixed.
    Blocker,
    /// Serious.
    High,
    /// Worth fixing.
    Medium,
    /// Minor.
    Low,
    /// For information.
    Info,
}

impl Severity {
    /// True for the severities that justify sending the design back.
    #[must_use]
    pub const fn blocks(self) -> bool {
        matches!(self, Self::Blocker | Self::High | Self::Medium)
    }
}

/// One thing the critic found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The identifier the critic gave it.
    pub id: String,
    /// How serious.
    pub severity: Severity,
    /// The title.
    pub title: String,
    /// What is wrong.
    pub description: String,
    /// `code_behavior`, `documentation`, `specification` or `policy`.
    pub defect_class: String,
}

/// What the critic returned, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// The conclusion.
    pub verdict: Verdict,
    /// The findings.
    pub findings: Vec<Finding>,
    /// The question for a person, when the verdict asks one.
    pub question: Option<String>,
    /// Instructions in the data that the critic says it did not follow.
    pub ignored_instructions: Vec<String>,
}

/// Why the critic's answer cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadProblem {
    /// The answer is not shaped like `review-findings`.
    #[error("the critic's answer is not shaped like its schema")]
    Shape,
    /// The answer contradicts itself: a `PASS` with a blocking finding, a request for changes with
    /// nothing to change, or a request for a person with no question.
    #[error("the critic's answer contradicts itself")]
    Contradiction,
}

fn string(map: &Map<String, Value>, key: &str) -> Result<String, ReadProblem> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ReadProblem::Shape)
}

impl Review {
    /// Reads the validated answer.
    ///
    /// # Errors
    /// [`ReadProblem`].
    pub fn read(value: &Value) -> Result<Self, ReadProblem> {
        let map = value.as_object().ok_or(ReadProblem::Shape)?;
        let verdict = match map.get("verdict").and_then(Value::as_str) {
            Some("PASS") => Verdict::Pass,
            Some("CHANGES_REQUIRED") => Verdict::ChangesRequired,
            Some("BLOCK") => Verdict::Block,
            Some("NEEDS_HUMAN") => Verdict::NeedsHuman,
            _ => return Err(ReadProblem::Shape),
        };
        let mut findings = Vec::new();
        for item in map
            .get("findings")
            .and_then(Value::as_array)
            .ok_or(ReadProblem::Shape)?
        {
            let item = item.as_object().ok_or(ReadProblem::Shape)?;
            let severity = match item.get("severity").and_then(Value::as_str) {
                Some("blocker") => Severity::Blocker,
                Some("high") => Severity::High,
                Some("medium") => Severity::Medium,
                Some("low") => Severity::Low,
                Some("info") => Severity::Info,
                _ => return Err(ReadProblem::Shape),
            };
            findings.push(Finding {
                id: string(item, "finding_id")?,
                severity,
                title: string(item, "title")?,
                description: string(item, "description")?,
                defect_class: string(item, "defect_class")?,
            });
        }
        let question = map
            .get("human_question")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let ignored_instructions = map
            .get("ignored_instructions")
            .and_then(Value::as_array)
            .ok_or(ReadProblem::Shape)?
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(ReadProblem::Shape))
            .collect::<Result<Vec<_>, _>>()?;
        let review = Self {
            verdict,
            findings,
            question,
            ignored_instructions,
        };
        review.consistent()?;
        Ok(review)
    }

    fn consistent(&self) -> Result<(), ReadProblem> {
        let blocking = !self.blocking().is_empty();
        let sound = match self.verdict {
            Verdict::Pass => !blocking,
            Verdict::ChangesRequired | Verdict::Block => blocking,
            Verdict::NeedsHuman => self.question.is_some(),
        };
        if sound {
            Ok(())
        } else {
            Err(ReadProblem::Contradiction)
        }
    }

    /// The findings that justify sending the design back.
    #[must_use]
    pub fn blocking(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity.blocks())
            .collect()
    }

    /// True when the critic agrees that the design stands.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.verdict == Verdict::Pass
    }

    /// True when the critic asks for a person.
    #[must_use]
    pub fn asks_a_person(&self) -> bool {
        self.verdict == Verdict::NeedsHuman
    }
}

/// Why the critic did not run when the policy required one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absent {
    /// The registry has no agent by the configured name.
    NoSuchAgent,
    /// The agent exists and cannot be used as a critic: it runs outside a sandbox, holds a tool
    /// that writes, has a role that is not a critic, is the architect itself, returns another
    /// schema, or its prompt is not intact.
    Unusable,
}

impl Absent {
    /// The code recorded in the stage record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoSuchAgent => "no-such-agent",
            Self::Unusable => "unusable-definition",
        }
    }
}

/// What happened about the critic in one stage run, as the record stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The policy does not require a critic at the tier of this design.
    NotRequired,
    /// A critic is required, and the design failed the deterministic checks first, so it is going
    /// back to the architect and a critic was not asked to review it.
    SkippedDesignFailed,
    /// A critic is required and none could be used.
    Absent(Absent),
    /// A critic reviewed the design.
    Ran {
        /// The critic agent.
        agent: String,
        /// Its version.
        version: String,
        /// What it concluded.
        review: Box<Review>,
    },
}

impl Outcome {
    /// The record of the outcome. The critic's own answer is kept as it was validated.
    #[must_use]
    pub fn to_json(&self, answer: Option<&Value>) -> Value {
        match self {
            Self::NotRequired => serde_json::json!({ "outcome": "not_required" }),
            Self::SkippedDesignFailed => serde_json::json!({ "outcome": "skipped_design_failed" }),
            Self::Absent(reason) => {
                serde_json::json!({ "outcome": "absent", "reason": reason.code() })
            }
            Self::Ran { agent, version, .. } => serde_json::json!({
                "outcome": "ran",
                "agent": agent,
                "version": version,
                "answer": answer,
            }),
        }
    }

    /// Reads the record back.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        match value.get("outcome")?.as_str()? {
            "not_required" => Some(Self::NotRequired),
            "skipped_design_failed" => Some(Self::SkippedDesignFailed),
            "absent" => Some(Self::Absent(match value.get("reason")?.as_str()? {
                "no-such-agent" => Absent::NoSuchAgent,
                _ => Absent::Unusable,
            })),
            "ran" => Some(Self::Ran {
                agent: value.get("agent")?.as_str()?.to_owned(),
                version: value.get("version")?.as_str()?.to_owned(),
                review: Box::new(Review::read(value.get("answer")?).ok()?),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_outcome_survives_the_record() {
        for outcome in [
            Outcome::NotRequired,
            Outcome::SkippedDesignFailed,
            Outcome::Absent(Absent::NoSuchAgent),
            Outcome::Absent(Absent::Unusable),
        ] {
            assert_eq!(Outcome::from_json(&outcome.to_json(None)), Some(outcome));
        }
        let answer = json!({
            "schema_version": 1, "verdict": "PASS", "title": "Review of the design",
            "summary": "A short summary of the review.", "findings": [],
            "confidence_overall": 0.9, "ignored_instructions": []
        });
        let ran = Outcome::Ran {
            agent: "architecture-critic".into(),
            version: "1.0.0".into(),
            review: Box::new(Review::read(&answer).expect("a review")),
        };
        assert_eq!(Outcome::from_json(&ran.to_json(Some(&answer))), Some(ran));
        assert_eq!(Outcome::from_json(&json!({ "outcome": "nonsense" })), None);
    }

    fn answer(verdict: &str, findings: Value) -> Value {
        json!({
            "schema_version": 1,
            "verdict": verdict,
            "title": "Review of the design",
            "summary": "A short summary of the review.",
            "findings": findings,
            "confidence_overall": 0.8,
            "ignored_instructions": []
        })
    }

    fn finding(severity: &str) -> Value {
        json!({
            "finding_id": "no-rollback",
            "severity": severity,
            "category": "maintainability",
            "title": "The design has no way back",
            "description": "Nothing says how to undo the change if it goes wrong.",
            "confidence": 0.9,
            "proposed_next_action": "fix",
            "defect_class": "code_behavior"
        })
    }

    #[test]
    fn a_pass_with_no_blocking_finding_agrees() {
        let review = Review::read(&answer("PASS", json!([finding("low")]))).expect("a review");
        assert!(review.agrees());
        assert!(review.blocking().is_empty());
    }

    #[test]
    fn a_pass_that_carries_a_blocking_finding_contradicts_itself() {
        assert_eq!(
            Review::read(&answer("PASS", json!([finding("high")]))),
            Err(ReadProblem::Contradiction)
        );
    }

    #[test]
    fn a_request_for_changes_needs_something_to_change_and_a_person_needs_a_question() {
        assert_eq!(
            Review::read(&answer("CHANGES_REQUIRED", json!([finding("info")]))),
            Err(ReadProblem::Contradiction)
        );
        let review = Review::read(&answer("CHANGES_REQUIRED", json!([finding("medium")])))
            .expect("a review");
        assert!(!review.agrees());
        assert_eq!(review.blocking().len(), 1);
        assert_eq!(
            Review::read(&answer("NEEDS_HUMAN", json!([]))),
            Err(ReadProblem::Contradiction)
        );
        let mut ask = answer("NEEDS_HUMAN", json!([]));
        ask["human_question"] = json!("Which of the two designs do you want?");
        assert!(Review::read(&ask).expect("a review").asks_a_person());
    }

    #[test]
    fn an_unknown_verdict_is_not_an_answer() {
        assert_eq!(
            Review::read(&answer("APPROVED", json!([]))),
            Err(ReadProblem::Shape)
        );
    }
}
