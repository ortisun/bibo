//! The checklist state of a specification.
//!
//! A checklist item is a question the specification must answer about its own quality. Spec Kit's
//! skills tick items of their own checklist after they wrote the specification, so a tick is an
//! author grading its own work. The adapter turns **every** item into an open question and reads
//! no tick, so a tick cannot reach this rule. An item stops being open in two ways only:
//!
//! * an independent reviewer passed the specification and named no finding about the item, or
//! * a person waived it and wrote a reason, in an answer that the engine recorded with the
//!   person's identity.
//!
//! A specification cannot pass with an item that is neither.

use std::collections::BTreeSet;

use factory_domain::contracts::SpecificationContract;
use factory_domain::contracts::specification_contract::QuestionStatus;

use super::Finding;
use super::rules::{CHECKLIST_PREFIX, Waived};

/// The fewest characters of a reason. A waiver without one is not a waiver.
pub const MIN_REASON: usize = 10;

/// A person's waiver of one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiver {
    /// The question, such as `Q-014`.
    pub question: String,
    /// Why it may stay unanswered.
    pub reason: String,
}

fn is_question_id(text: &str) -> bool {
    text.strip_prefix("Q-")
        .is_some_and(|digits| digits.len() >= 3 && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Reads the waivers in the text of an answer. One waiver is a line `waive Q-014: the reason`.
/// A line without a question identifier, or with a reason shorter than [`MIN_REASON`], is not a
/// waiver. Who may answer is the engine's decision, made before the answer reaches the stage.
#[must_use]
pub fn parse_waivers(text: &str) -> Vec<Waiver> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("waive ")?;
            let (id, reason) = rest.split_once(':')?;
            let (id, reason) = (id.trim(), reason.trim());
            (is_question_id(id) && reason.chars().count() >= MIN_REASON).then(|| Waiver {
                question: id.to_owned(),
                reason: reason.to_owned(),
            })
        })
        .collect()
}

/// The questions that waivers name.
#[must_use]
pub fn waived(waivers: &[Waiver]) -> Waived {
    waivers.iter().map(|w| w.question.clone()).collect()
}

/// What the rule is given.
#[derive(Debug, Clone, Copy)]
pub struct ChecklistInput<'a> {
    /// The independent reviewer passed the specification. False when there was no reviewer, when
    /// the reviewer could not run, and for every other verdict.
    pub reviewer_passed: bool,
    /// The title and description of every finding the reviewer made, whatever its severity.
    pub finding_texts: &'a [String],
    /// The waivers of people.
    pub waivers: &'a [Waiver],
}

/// How each checklist item stands.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolution {
    /// Items the reviewer verified, by question identifier.
    pub verified: BTreeSet<String>,
    /// Items a person waived, by question identifier.
    pub waived: BTreeSet<String>,
    /// Items that are neither: the question identifier and the item.
    pub unresolved: Vec<(String, String)>,
}

/// The label and the file of an item, from the text the adapter wrote: `Checklist item CHK001 of
/// requirements-quality.md: ...`.
fn label_of(question: &str) -> Option<(&str, &str)> {
    let rest = question.strip_prefix(CHECKLIST_PREFIX)?;
    let (label, rest) = rest.split_once(" of ")?;
    let (file, _) = rest.split_once(": ")?;
    Some((label, file))
}

/// Settles every checklist item of the contract.
#[must_use]
pub fn resolve(contract: &SpecificationContract, input: &ChecklistInput<'_>) -> Resolution {
    let waived = waived(input.waivers);
    let findings: Vec<String> = input
        .finding_texts
        .iter()
        .map(|t| t.to_lowercase())
        .collect();
    let mut out = Resolution::default();
    for q in &contract.open_questions {
        let text = q.question.as_str();
        if !text.starts_with(CHECKLIST_PREFIX) {
            continue;
        }
        let id = q.id.as_str().to_owned();
        if q.status == QuestionStatus::Answered {
            out.verified.insert(id);
            continue;
        }
        if waived.contains(&id) {
            out.waived.insert(id);
            continue;
        }
        let touched = label_of(text).is_some_and(|(label, file)| {
            let (label, file) = (label.to_lowercase(), file.to_lowercase());
            findings.iter().any(|f| {
                if let Some(line) = label.strip_prefix("on line ") {
                    f.contains(&file) && f.contains(&format!("line {line}"))
                } else {
                    f.contains(&label)
                }
            })
        });
        if input.reviewer_passed && !touched {
            out.verified.insert(id);
        } else {
            out.unresolved.push((id, text.to_owned()));
        }
    }
    out
}

/// The findings of a resolution.
#[must_use]
pub fn findings(resolution: &Resolution) -> Vec<Finding> {
    resolution
        .unresolved
        .iter()
        .map(|(id, text)| {
            Finding::new(
                "checklist-item-unresolved",
                format!(
                    "The question {id} is neither verified by an independent reviewer nor waived by a person with a reason. {text}"
                ),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_waiver_needs_a_question_and_a_reason() {
        let text = "waive Q-014: the gate is defined at architecture time\nwaive Q-015: ok\nwaive 14: a long enough reason here\nplease waive Q-016: not at the start of the line is fine\nwaive Q-017 no colon here at all";
        let found = parse_waivers(text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].question, "Q-014");
    }

    #[test]
    fn the_label_of_an_item_is_read_from_the_question() {
        assert_eq!(
            label_of("Checklist item CHK001 of requirements-quality.md: Is it defined?"),
            Some(("CHK001", "requirements-quality.md"))
        );
        assert_eq!(label_of("Who may answer?"), None);
    }
}
