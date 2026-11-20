//! What a rework round tells the builder.
//!
//! The only feedback a builder gets is the reports of the gates that failed and the findings of
//! the independent reviewer, already deduplicated (`state-machine.json`: "the builder receives the
//! gate reports, not a summary"). The text is deterministic: the same feedback always gives the
//! same bytes, so a rework run is reproducible. It goes into the `gate_reports` block of the
//! builder prompt, which the prompt assembler quotes as untrusted data. A message in it came from
//! a command's output or from a model, so it is data to read and never an instruction.

use factory_domain::contracts::GateReport;
use factory_domain::contracts::review_verdict::{Finding, Severity};
use factory_domain::vocabulary::GateOutcome;

use super::seams::ReworkContext;

/// The most characters one message keeps. A failure message can carry a long test output.
const MESSAGE_MAX: usize = 600;

/// The most characters one answer of a person keeps. An answer is short text typed by a person;
/// the bound only stops a pasted file from filling the prompt.
const ANSWER_MAX: usize = 4000;

/// The answers people gave in earlier rounds, as a block of text. Empty when there are none.
///
/// The lines of an answer are kept, because a person answers several questions one per line. The
/// same text goes to the agent that repairs the work and to the reviewer that judges it, so both
/// read the same decisions.
#[must_use]
pub fn earlier_answers(answers: &[String]) -> String {
    let mut text = String::new();
    for (index, answer) in answers.iter().enumerate() {
        let kept: String = answer.chars().take(ANSWER_MAX).collect();
        text.push_str(&format!("Answer {} from a person:\n", index + 1));
        for line in kept
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
        {
            text.push_str(&format!("    {line}\n"));
        }
        if kept.chars().count() < answer.chars().count() {
            text.push_str("    (cut)\n");
        }
    }
    text
}

/// The feedback as the builder reads it.
#[must_use]
pub fn render(context: &ReworkContext) -> String {
    render_with(context, MESSAGE_MAX)
}

/// The feedback, with each message cut at `message_max` characters. A stage whose failure
/// messages are findings written by a reviewer keeps more of each than a stage whose messages are
/// the output of a command.
#[must_use]
pub fn render_with(context: &ReworkContext, message_max: usize) -> String {
    let clip = |message: &str| clip(message, message_max);
    let mut text = format!(
        "Rework round {}. The previous attempt at this work was sent back. Fix only what is listed below.\n",
        context.round
    );
    if let Some(request) = &context.person_request {
        // The words of a person with the authority to send the work back. They come first: a
        // person who read the work outweighs what a gate or a reviewer said about it.
        text.push_str("\nA person sent the work back and asked for this:\n");
        text.push_str(&format!("    {}\n", clip(request)));
    }
    if !context.earlier_answers.is_empty() {
        // A decision a person took stays taken. Without it the next round asks the same question
        // again, or a reviewer who never saw the answer calls the decision out of scope.
        text.push_str(
            "\nPeople answered questions in earlier rounds of this work. Their decisions stand: do not ask them again, and when a gate or a finding below disagrees with a decision, keep the decision and say so. An identifier such as Q-001 names a question of the round the answer was given in.\n",
        );
        text.push_str(&earlier_answers(&context.earlier_answers));
    }
    let failed: Vec<&GateReport> = context
        .failed_reports
        .iter()
        .filter(|report| report.outcome != GateOutcome::Passed)
        .collect();
    if !failed.is_empty() {
        text.push_str("\nGates that did not pass:\n");
        for report in failed {
            text.push_str(&format!(
                "- {} ({}): {}\n",
                report.metadata.gate_id.as_str(),
                report.outcome.as_str(),
                clip(report.reason.as_str())
            ));
            for failure in report.failures.iter().flatten() {
                let place = failure
                    .location
                    .as_ref()
                    .map(|found| match found.line {
                        Some(line) => format!(" at {}:{}", found.path, line.get()),
                        None => format!(" at {}", found.path),
                    })
                    .unwrap_or_default();
                text.push_str(&format!(
                    "    - check {}{}: {}\n",
                    failure.check_id.as_str(),
                    place,
                    clip(failure.message.as_str())
                ));
            }
        }
    }
    let mut findings: Vec<&Finding> = context.findings.iter().collect();
    findings.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.finding_id.as_str().cmp(b.finding_id.as_str()))
    });
    if !findings.is_empty() {
        text.push_str("\nFindings of the independent review:\n");
        for finding in findings {
            let place = finding
                .location
                .as_ref()
                .map(|found| match found.line_start {
                    Some(line) => format!(" at {}:{}", found.path.as_str(), line.get()),
                    None => format!(" at {}", found.path.as_str()),
                })
                .unwrap_or_default();
            text.push_str(&format!(
                "- [{}] {}{}: {}\n",
                finding.severity.as_str(),
                finding.title.as_str(),
                place,
                clip(finding.description.as_str())
            ));
        }
    }
    text
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Blocker => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn clip(message: &str, max: usize) -> String {
    let flat: String = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let mut cut: String = flat.chars().take(max).collect();
        cut.push_str(" (cut)");
        cut
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::Contract;
    use factory_ports::paths::CommitSha;

    fn context() -> ReworkContext {
        let verdict: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../schemas/examples/review-verdict/valid/changes-required-missing-test.json"
        ))
        .expect("JSON");
        let verdict =
            factory_domain::contracts::ReviewVerdict::from_json_value(verdict).expect("a verdict");
        ReworkContext {
            previous_head: CommitSha::parse(&"a".repeat(40)).expect("a sha"),
            failed_reports: Vec::new(),
            findings: verdict.findings,
            round: 1,
            person_request: None,
            earlier_answers: Vec::new(),
        }
    }

    #[test]
    fn the_findings_are_listed_with_their_place_and_the_text_is_stable() {
        let first = render(&context());
        assert_eq!(first, render(&context()));
        assert!(first.contains("Rework round 1."), "{first}");
        assert!(
            first.contains("Findings of the independent review:"),
            "{first}"
        );
        assert!(first.contains(" at "), "{first}");
    }

    #[test]
    fn a_long_message_is_cut_and_whitespace_is_flattened() {
        let long = format!("start\n\n   {}", "word ".repeat(400));
        let cut = clip(&long, MESSAGE_MAX);
        assert!(cut.ends_with("(cut)"));
        assert!(!cut.contains('\n'));
        assert!(cut.chars().count() < 700);
    }

    #[test]
    fn a_round_with_nothing_listed_still_says_which_round_it_is() {
        let empty = ReworkContext {
            findings: Vec::new(),
            ..context()
        };
        let text = render(&empty);
        assert!(text.contains("Rework round 1."));
        assert!(!text.contains("Findings of"));
        assert!(!text.contains("Gates that did not pass"));
    }

    #[test]
    fn the_answers_of_earlier_rounds_stand_before_the_findings() {
        let answered = ReworkContext {
            earlier_answers: vec![
                "Q-001: One line, no spaces.\n\nQ-002: Yes, list it in the help.  ".to_owned(),
                "x".repeat(ANSWER_MAX + 1),
            ],
            ..context()
        };
        let text = render(&answered);
        assert_eq!(text, render(&answered), "the text is stable");
        let decisions = text.find("Their decisions stand").expect("the rule");
        let findings = text
            .find("Findings of the independent review:")
            .expect("findings");
        assert!(decisions < findings, "{text}");
        assert!(
            text.contains(
                "Answer 1 from a person:\n    Q-001: One line, no spaces.\n    Q-002: Yes, list it in the help.\n"
            ),
            "{text}"
        );
        // The bound is the number of characters, and a cut answer says that it was cut.
        let second = text.split("Answer 2 from a person:\n").nth(1).expect("two");
        assert!(second.starts_with(&format!("    {}\n    (cut)\n", "x".repeat(ANSWER_MAX))));
        // No answers, no section.
        assert!(!render(&context()).contains("Their decisions stand"));
        assert_eq!(earlier_answers(&[]), "");
        // An answer exactly at the bound is whole.
        assert!(!earlier_answers(&["y".repeat(ANSWER_MAX)]).contains("(cut)"));
    }

    #[test]
    fn what_a_person_asked_for_comes_first() {
        let asked = ReworkContext {
            person_request: Some("Say what goes to standard error.\nKeep the rest.".to_owned()),
            earlier_answers: Vec::new(),
            ..context()
        };
        let text = render(&asked);
        let person = text
            .find("A person sent the work back and asked for this:")
            .expect("the request of the person is in the text");
        let findings = text
            .find("Findings of the independent review:")
            .expect("the findings are in the text");
        assert!(person < findings, "{text}");
        // One line, so that a line break in a person's text cannot pose as another section.
        assert!(
            text.contains("    Say what goes to standard error. Keep the rest.\n"),
            "{text}"
        );
        assert!(!render(&context()).contains("A person sent the work back"));
    }
}
