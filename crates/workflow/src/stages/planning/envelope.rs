//! What the planner returns: an envelope around a plan.
//!
//! The planner's schema (`planner-result`, version 1) checks the envelope only: a status, a plan or
//! a question for a person, and the list of instructions the planner says it ignored. The plan
//! inside is checked afterwards against the typed `task-dag` contract, and by the validator. Like
//! every answer of an agent, the envelope is read strictly and never repaired.

use serde_json::Value;

/// Why an answer cannot be read as an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeProblem {
    /// The answer is not a JSON object.
    #[error("the planner's answer is not an object")]
    NotAnObject,
    /// The envelope has a field its schema does not name.
    #[error("the planner's answer has a field that its schema does not name")]
    UnknownField,
    /// The status is neither `DONE` nor `NEEDS_HUMAN`.
    #[error("the planner's status is not one the schema names")]
    Status,
    /// A `DONE` answer has no plan, or a `NEEDS_HUMAN` answer has no question.
    #[error("the planner's answer lacks the plan or the question its status needs")]
    Incomplete,
    /// A field has the wrong type.
    #[error("a field of the planner's answer has the wrong type")]
    Field,
}

/// What the planner said.
#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    /// A plan, still to be validated.
    Done {
        /// The plan, as the planner wrote it.
        plan: Value,
        /// Instructions in the data that the planner says it did not follow.
        ignored_instructions: Vec<String>,
    },
    /// The planner asks a person one question and offers no plan.
    NeedsHuman {
        /// The question.
        question: String,
        /// Instructions in the data that the planner says it did not follow.
        ignored_instructions: Vec<String>,
    },
}

const ALLOWED: [&str; 5] = [
    "schema_version",
    "status",
    "plan",
    "human_question",
    "ignored_instructions",
];

impl Envelope {
    /// Reads the validated answer.
    ///
    /// # Errors
    /// [`EnvelopeProblem`].
    pub fn read(value: &Value) -> Result<Self, EnvelopeProblem> {
        let map = value.as_object().ok_or(EnvelopeProblem::NotAnObject)?;
        if !map.keys().all(|key| ALLOWED.contains(&key.as_str())) {
            return Err(EnvelopeProblem::UnknownField);
        }
        if map.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err(EnvelopeProblem::Field);
        }
        let ignored_instructions = map
            .get("ignored_instructions")
            .and_then(Value::as_array)
            .ok_or(EnvelopeProblem::Field)?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or(EnvelopeProblem::Field)
            })
            .collect::<Result<Vec<_>, _>>()?;
        match map.get("status").and_then(Value::as_str) {
            Some("DONE") => {
                let plan = map.get("plan").ok_or(EnvelopeProblem::Incomplete)?;
                if !plan.is_object() {
                    return Err(EnvelopeProblem::Field);
                }
                Ok(Self::Done {
                    plan: plan.clone(),
                    ignored_instructions,
                })
            }
            Some("NEEDS_HUMAN") => {
                let question = map
                    .get("human_question")
                    .and_then(Value::as_str)
                    .ok_or(EnvelopeProblem::Incomplete)?;
                Ok(Self::NeedsHuman {
                    question: question.to_owned(),
                    ignored_instructions,
                })
            }
            _ => Err(EnvelopeProblem::Status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DONE: &str =
        include_str!("../../../../../agents/planner/fixtures/valid/json-output-plan.json");
    const ASKS: &str =
        include_str!("../../../../../agents/planner/fixtures/valid/needs-a-person.json");

    #[test]
    fn the_planner_fixtures_are_read_as_a_plan_and_as_a_question() {
        let done: Value = serde_json::from_str(DONE).expect("JSON");
        assert!(matches!(Envelope::read(&done), Ok(Envelope::Done { .. })));
        let asks: Value = serde_json::from_str(ASKS).expect("JSON");
        let Ok(Envelope::NeedsHuman { question, .. }) = Envelope::read(&asks) else {
            panic!("a question");
        };
        assert!(!question.is_empty());
    }

    #[test]
    fn an_envelope_with_a_missing_part_or_an_extra_field_is_refused() {
        let mut done: Value = serde_json::from_str(DONE).expect("JSON");
        done.as_object_mut().expect("object").remove("plan");
        assert_eq!(Envelope::read(&done), Err(EnvelopeProblem::Incomplete));
        let mut extra: Value = serde_json::from_str(DONE).expect("JSON");
        extra["metadata"] = json!({});
        assert_eq!(Envelope::read(&extra), Err(EnvelopeProblem::UnknownField));
        let mut status: Value = serde_json::from_str(DONE).expect("JSON");
        status["status"] = json!("PASS");
        assert_eq!(Envelope::read(&status), Err(EnvelopeProblem::Status));
        assert_eq!(
            Envelope::read(&json!([])),
            Err(EnvelopeProblem::NotAnObject)
        );
        let mut ask: Value = serde_json::from_str(ASKS).expect("JSON");
        ask.as_object_mut()
            .expect("object")
            .remove("human_question");
        assert_eq!(Envelope::read(&ask), Err(EnvelopeProblem::Incomplete));
    }
}
