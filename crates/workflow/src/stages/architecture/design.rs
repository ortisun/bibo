//! The architect's answer read into a typed design.
//!
//! The answer has already passed the agent's own output schema (`architecture-design`, version 1)
//! when it gets here. This is the second wall: the document is read field by field into a value
//! the checks can use, a field the schema does not name is refused, and nothing that the agent
//! wrote is repaired. A failure carries the name of the field, never the text of the agent.

use serde_json::{Map, Value};

/// Why an answer cannot be read as a design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadProblem {
    /// The answer is not a JSON object.
    #[error("the design is not an object")]
    NotAnObject,
    /// A field is missing or has the wrong type. The text names the field.
    #[error("the design field `{0}` is missing or has the wrong type")]
    Field(&'static str),
    /// The design has a field the schema does not name.
    #[error("the design has a field that its schema does not name")]
    UnknownField,
    /// The status is neither `DONE` nor `NEEDS_HUMAN`.
    #[error("the design status is not one the schema names")]
    Status,
}

/// Where the architect says the work stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// A design for every requirement.
    Done,
    /// The architect asks a person.
    NeedsHuman,
}

/// One part of the design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// The identifier.
    pub id: String,
    /// The title, in plain English.
    pub title: String,
    /// What it is responsible for.
    pub responsibility: String,
    /// `module`, `interface`, `data`, `process`, `test` or `documentation`.
    pub kind: String,
    /// The requirement identifiers it satisfies.
    pub satisfies: Vec<String>,
    /// The files it adds or changes.
    pub touches: Vec<String>,
}

/// One decision with the alternatives that were considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The identifier.
    pub id: String,
    /// The title.
    pub title: String,
    /// What was chosen and why.
    pub choice: String,
    /// The options that were weighed and not chosen.
    pub alternatives: Vec<String>,
    /// What follows from the choice.
    pub consequences: String,
    /// A person must approve it, such as a new dependency.
    pub needs_person: bool,
}

/// The design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Design {
    /// Done, or a question for a person.
    pub status: Status,
    /// The title.
    pub title: String,
    /// The summary. The independent critic is not given this, because it is the author's own
    /// account of the work.
    pub summary: String,
    /// The parts.
    pub elements: Vec<Element>,
    /// The decisions.
    pub decisions: Vec<Decision>,
    /// The risks, which are the ways the design could fail.
    pub risks: Vec<String>,
    /// Questions the architect left open.
    pub open_questions: Vec<String>,
    /// Requirements the architect says it could not cover.
    pub uncovered: Vec<String>,
    /// The question for a person, when the status asks one.
    pub human_question: Option<String>,
    /// Instructions the architect says it found in the data and did not follow.
    pub ignored_instructions: Vec<String>,
}

const TOP: [&str; 11] = [
    "schema_version",
    "status",
    "title",
    "summary",
    "design_elements",
    "decisions",
    "risks",
    "open_questions",
    "uncovered_requirements",
    "human_question",
    "ignored_instructions",
];
const ELEMENT: [&str; 6] = [
    "element_id",
    "title",
    "responsibility",
    "kind",
    "satisfies",
    "touches",
];
const DECISION: [&str; 6] = [
    "decision_id",
    "title",
    "choice",
    "alternatives",
    "consequences",
    "needs_person",
];

fn only(map: &Map<String, Value>, allowed: &[&str]) -> Result<(), ReadProblem> {
    if map.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(ReadProblem::UnknownField)
    }
}

fn text(map: &Map<String, Value>, key: &'static str) -> Result<String, ReadProblem> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ReadProblem::Field(key))
}

fn texts(map: &Map<String, Value>, key: &'static str) -> Result<Vec<String>, ReadProblem> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(ReadProblem::Field(key))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(ReadProblem::Field(key))
        })
        .collect()
}

fn objects<'a>(
    map: &'a Map<String, Value>,
    key: &'static str,
) -> Result<Vec<&'a Map<String, Value>>, ReadProblem> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(ReadProblem::Field(key))?
        .iter()
        .map(|item| item.as_object().ok_or(ReadProblem::Field(key)))
        .collect()
}

impl Design {
    /// Reads the validated answer.
    ///
    /// # Errors
    /// [`ReadProblem`] when the answer is not shaped like the schema says.
    pub fn read(value: &Value) -> Result<Self, ReadProblem> {
        let map = value.as_object().ok_or(ReadProblem::NotAnObject)?;
        only(map, &TOP)?;
        if map.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err(ReadProblem::Field("schema_version"));
        }
        let status = match map.get("status").and_then(Value::as_str) {
            Some("DONE") => Status::Done,
            Some("NEEDS_HUMAN") => Status::NeedsHuman,
            _ => return Err(ReadProblem::Status),
        };
        let mut elements = Vec::new();
        for item in objects(map, "design_elements")? {
            only(item, &ELEMENT)?;
            elements.push(Element {
                id: text(item, "element_id")?,
                title: text(item, "title")?,
                responsibility: text(item, "responsibility")?,
                kind: text(item, "kind")?,
                satisfies: texts(item, "satisfies")?,
                touches: if item.contains_key("touches") {
                    texts(item, "touches")?
                } else {
                    Vec::new()
                },
            });
        }
        let mut decisions = Vec::new();
        for item in objects(map, "decisions")? {
            only(item, &DECISION)?;
            decisions.push(Decision {
                id: text(item, "decision_id")?,
                title: text(item, "title")?,
                choice: text(item, "choice")?,
                alternatives: texts(item, "alternatives")?,
                consequences: text(item, "consequences")?,
                needs_person: item
                    .get("needs_person")
                    .and_then(Value::as_bool)
                    .ok_or(ReadProblem::Field("needs_person"))?,
            });
        }
        let human_question = match map.get("human_question") {
            None => None,
            Some(Value::String(question)) => Some(question.clone()),
            Some(_) => return Err(ReadProblem::Field("human_question")),
        };
        Ok(Self {
            status,
            title: text(map, "title")?,
            summary: text(map, "summary")?,
            elements,
            decisions,
            risks: texts(map, "risks")?,
            open_questions: texts(map, "open_questions")?,
            uncovered: texts(map, "uncovered_requirements")?,
            human_question,
            ignored_instructions: texts(map, "ignored_instructions")?,
        })
    }

    /// The files the design touches, without repeats, in the order they first appear.
    #[must_use]
    pub fn touched(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for element in &self.elements {
            for path in &element.touches {
                if !seen.contains(&path.as_str()) {
                    seen.push(path.as_str());
                }
            }
        }
        seen
    }

    /// The pieces of human-facing text the readability gate reads: a title and a body for each.
    /// The body of an element is its responsibility, and the body of a decision is its choice and
    /// its consequences.
    #[must_use]
    pub fn readable_texts(&self) -> Vec<(String, String)> {
        let mut found = vec![(self.title.clone(), self.summary.clone())];
        for element in &self.elements {
            found.push((element.title.clone(), element.responsibility.clone()));
        }
        for decision in &self.decisions {
            found.push((
                decision.title.clone(),
                format!("{} {}", decision.choice, decision.consequences),
            ));
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID: &str =
        include_str!("../../../../../agents/architect/fixtures/valid/json-output-design.json");

    #[test]
    fn the_architect_fixture_is_read_into_a_design() {
        let value: Value = serde_json::from_str(VALID).expect("JSON");
        let design = Design::read(&value).expect("a design");
        assert_eq!(design.status, Status::Done);
        assert_eq!(design.elements.len(), 1);
        assert_eq!(design.touched(), ["src/main.rs", "src/output.rs"]);
        assert_eq!(design.decisions[0].alternatives.len(), 1);
        assert_eq!(design.readable_texts().len(), 3);
    }

    #[test]
    fn a_field_the_schema_does_not_name_is_refused_at_every_level() {
        for path in ["", "/design_elements/0", "/decisions/0"] {
            let mut value: Value = serde_json::from_str(VALID).expect("JSON");
            value
                .pointer_mut(path)
                .and_then(Value::as_object_mut)
                .expect("an object")
                .insert("extra".into(), json!("anything"));
            assert_eq!(
                Design::read(&value),
                Err(ReadProblem::UnknownField),
                "{path}"
            );
        }
    }

    #[test]
    fn a_missing_field_and_a_wrong_type_name_the_field_and_not_the_text() {
        let mut value: Value = serde_json::from_str(VALID).expect("JSON");
        value["decisions"][0]["needs_person"] = json!("no");
        assert_eq!(
            Design::read(&value),
            Err(ReadProblem::Field("needs_person"))
        );
        let mut value: Value = serde_json::from_str(VALID).expect("JSON");
        value.as_object_mut().expect("object").remove("risks");
        assert_eq!(Design::read(&value), Err(ReadProblem::Field("risks")));
        assert_eq!(Design::read(&json!([])), Err(ReadProblem::NotAnObject));
        let mut value: Value = serde_json::from_str(VALID).expect("JSON");
        value["status"] = json!("PASS");
        assert_eq!(Design::read(&value), Err(ReadProblem::Status));
    }
}
