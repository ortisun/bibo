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

/// The feedback as the builder reads it.
#[must_use]
pub fn render(context: &ReworkContext) -> String {
    let mut text = format!(
        "Rework round {}. The previous attempt at this work was sent back. Fix only what is listed below.\n",
        context.round
    );
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

fn clip(message: &str) -> String {
    let flat: String = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= MESSAGE_MAX {
        flat
    } else {
        let mut cut: String = flat.chars().take(MESSAGE_MAX).collect();
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
        let cut = clip(&long);
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
}
