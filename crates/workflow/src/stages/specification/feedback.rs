//! What a rework round tells the writer of a specification.
//!
//! When the gate of the stage sends a draft back, the next run repairs that draft: it starts from
//! the commit the draft is in and runs the clarify skill over it, with this text in a file the
//! skill is told to read as data ([`FEEDBACK_FILE`](super::input::FEEDBACK_FILE)).
//!
//! The text is the reports of the gates that failed, never a summary of them
//! (`state-machine.json`, `rework_routes`). It differs from what a builder of code reads in two
//! ways:
//!
//! * **A finding is kept whole.** The messages of the review gate are the findings of the
//!   independent reviewer, and each says what is wrong and what a correct version would say. The
//!   second half is what the writer needs, so a message is cut only at the limit of the report
//!   schema.
//! * **The checklist gate is explained.** Every checklist item is an open question until the
//!   reviewer passes the specification (`gates::spec::checklist`), so that gate fails whenever the
//!   review does and lists every item. A writer that read the list as work to do would tick the
//!   items, and a tick by the author is exactly what the gate does not read. The text says so.
//!
//! The text is deterministic: the same feedback always gives the same bytes.

use factory_domain::vocabulary::GateOutcome;

use crate::gates::spec::CHECKLIST;
use crate::stages::implementation::feedback::render_with;
use crate::stages::implementation::seams::ReworkContext;

/// The most characters one message keeps: the longest text a gate report can hold.
const MESSAGE_MAX: usize = 4000;

/// The sentence that follows the reports when the checklist gate is among them.
const CHECKLIST_NOTE: &str = "\nAbout the gate specification-checklist: a checklist item stays open until the independent reviewer passes the specification. You cannot close an item, and a tick in a checklist file closes nothing. The items close when the findings of the gate specification-review are resolved, so resolve those and leave the checklist files as they are.\n";

/// The feedback as the writer reads it.
#[must_use]
pub fn render(context: &ReworkContext) -> String {
    let mut text = render_with(context, MESSAGE_MAX);
    let checklist_failed = context.failed_reports.iter().any(|report| {
        report.outcome != GateOutcome::Passed && report.metadata.gate_id.as_str() == CHECKLIST
    });
    if checklist_failed {
        text.push_str(CHECKLIST_NOTE);
    }
    text
}

#[cfg(test)]
mod tests {
    use factory_domain::contracts::{Contract, GateReport};
    use factory_ports::paths::CommitSha;
    use serde_json::{Value, json};

    use super::*;
    use crate::stages::specification::judge::REVIEW;

    const PASSED: &str = include_str!(
        "../../../../../schemas/examples/gate-report/valid/build-and-test-passed.json"
    );

    fn failed(gate: &str, check: &str, messages: &[&str]) -> GateReport {
        let mut doc: Value = serde_json::from_str(PASSED).expect("JSON");
        doc["metadata"]["gate_id"] = json!(gate);
        doc["outcome"] = json!("FAILED");
        doc["reason"] = json!(format!("The gate found {} problem(s).", messages.len()));
        doc["commands"] = json!([]);
        doc["failures"] = messages
            .iter()
            .map(|message| json!({ "check_id": check, "message": message }))
            .collect();
        GateReport::from_json_value(doc).expect("a valid report")
    }

    fn context(reports: Vec<GateReport>) -> ReworkContext {
        ReworkContext {
            previous_head: CommitSha::parse(&"a".repeat(40)).expect("a sha"),
            failed_reports: reports,
            findings: Vec::new(),
            round: 1,
            person_request: None,
            earlier_answers: Vec::new(),
        }
    }

    #[test]
    fn a_finding_of_the_reviewer_reaches_the_writer_whole() {
        // 900 characters: more than a builder of code keeps of one message, and what a real
        // reviewer writes when it says what a correct version would hold.
        let advice = "A correct version would put the layout in a functional requirement. ";
        let finding = format!(
            "Exact JSON layout is an assumption, not a requirement: {}END-OF-FINDING",
            advice.repeat(12)
        );
        assert!(finding.chars().count() > 800);
        let text = render(&context(vec![failed(
            REVIEW,
            "review-finding",
            &[&finding],
        )]));
        assert!(text.contains("Rework round 1."), "{text}");
        assert!(text.contains(REVIEW), "{text}");
        assert!(text.contains("END-OF-FINDING"), "{text}");
        assert!(!text.contains("(cut)"), "{text}");
    }

    #[test]
    fn the_checklist_gate_is_listed_and_explained() {
        let text = render(&context(vec![
            failed(
                CHECKLIST,
                "checklist-item-unresolved",
                &["The question Q-001 is neither verified nor waived."],
            ),
            failed(
                REVIEW,
                "review-finding",
                &["Standard error is not covered by any requirement."],
            ),
        ]));
        // The report itself, never a summary of it.
        assert!(
            text.contains("The question Q-001 is neither verified nor waived."),
            "{text}"
        );
        assert!(text.contains("Standard error is not covered"), "{text}");
        // And what the writer can do about it: nothing but resolve the findings.
        assert!(text.contains("You cannot close an item"), "{text}");
        assert!(
            text.contains("leave the checklist files as they are"),
            "{text}"
        );
    }

    #[test]
    fn a_round_without_the_checklist_gate_says_nothing_about_it() {
        let text = render(&context(vec![failed(
            "specification-structure",
            "section-missing",
            &["The section Edge Cases is missing."],
        )]));
        assert!(
            text.contains("The section Edge Cases is missing."),
            "{text}"
        );
        assert!(!text.contains("specification-checklist"), "{text}");
    }

    #[test]
    fn the_text_is_the_same_for_the_same_feedback() {
        let make = || {
            render(&context(vec![
                failed(
                    CHECKLIST,
                    "checklist-item-unresolved",
                    &["The question Q-002 is open."],
                ),
                failed(
                    REVIEW,
                    "review-finding",
                    &["The scope statement contradicts itself."],
                ),
            ]))
        };
        assert_eq!(make(), make());
    }
}
