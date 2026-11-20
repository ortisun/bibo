//! Architecture decision record drafts, made from the decisions of the design.
//!
//! A draft is not an accepted record. It carries what a person needs to accept or reject it: the
//! question, the choice, the options that were weighed and what follows. The documentation stage
//! turns an accepted draft into a record under `docs/adr`. Nothing here is written to the
//! repository.

use serde_json::{Value, json};

use super::design::Design;

/// The drafts, as the document the stage stores.
#[must_use]
pub fn drafts(design: &Design) -> Value {
    json!({
        "kind": "adr-drafts",
        "schema_version": 1,
        "drafts": design.decisions.iter().map(|decision| json!({
            "draft_id": format!("draft-{}", decision.id),
            "title": decision.title,
            "status": if decision.needs_person { "needs a person" } else { "proposed" },
            "decision": decision.choice,
            "alternatives_considered": decision.alternatives,
            "consequences": decision.consequences,
            "needs_person": decision.needs_person,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::architecture::design::{Decision, Status};

    #[test]
    fn each_decision_becomes_a_draft_that_says_whether_a_person_must_decide() {
        let design = Design {
            status: Status::Done,
            title: "A design for the change".into(),
            summary: "A short summary of the design.".into(),
            elements: Vec::new(),
            decisions: vec![
                Decision {
                    id: "hand-written-json".into(),
                    title: "Write the JSON by hand".into(),
                    choice: "Build the text with the standard library.".into(),
                    alternatives: vec!["Add a JSON library.".into()],
                    consequences: "No new dependency.".into(),
                    needs_person: false,
                },
                Decision {
                    id: "new-library".into(),
                    title: "Adopt a library".into(),
                    choice: "Use the library.".into(),
                    alternatives: Vec::new(),
                    consequences: "A new dependency.".into(),
                    needs_person: true,
                },
            ],
            risks: Vec::new(),
            open_questions: Vec::new(),
            uncovered: Vec::new(),
            human_question: None,
            ignored_instructions: Vec::new(),
        };
        let document = drafts(&design);
        assert_eq!(document["drafts"][0]["draft_id"], "draft-hand-written-json");
        assert_eq!(document["drafts"][0]["status"], "proposed");
        assert_eq!(document["drafts"][1]["status"], "needs a person");
        assert_eq!(document["drafts"][1]["needs_person"], true);
    }
}
