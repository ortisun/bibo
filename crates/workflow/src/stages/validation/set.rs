//! The whole set of gate reports of one validation run.
//!
//! One report for each gate, always. A gate that has no observation says why in a `BLOCKED`
//! report, and the only gates that may be `NOT_APPLICABLE` are the conditional ones the project
//! does not define, decided by the domain profile and recorded as such.

use factory_domain::contracts::GateReport;
use factory_domain::contracts::gate_report::{BaselineDelta, BlockedCode};
use factory_domain::values::HumanText;

use super::assemble::{Assembler, HostResult, compare, title_of};
use super::host::HostResults;
use super::sandboxed::{GateRun, Sandboxed};
use crate::gates::command::report::{ReportError, not_compared};
use crate::gates::command::{
    CommandGate, Outcomes, Refusal, Resolved, Role, Status, TrustedGates, Verdict, gate_id,
};
use crate::gates::scope::Violation;
use crate::gates::scope::acceptance::{Before, Coverage, Requirement, coverage};

/// What is known about the frozen specification.
#[derive(Debug, Clone)]
pub enum SpecState {
    /// The specification stage produced no document, or it could not be read.
    Missing,
    /// The document is there but is not approved.
    NotApproved,
    /// The requirements of the approved specification.
    Ready(Vec<Requirement>),
}

/// Everything the reports are made from.
pub struct Findings<'a> {
    /// The gate definitions, or `None` when they could not be read at the base commit.
    pub definitions: Option<&'a TrustedGates>,
    /// The results of the host-side rules.
    pub host: &'a HostResults,
    /// The run on the candidate commit, or `None` when no command ran.
    pub head: Option<&'a Sandboxed>,
    /// The run of the test gate on the base commit.
    pub baseline: Option<&'a Sandboxed>,
    /// The frozen specification.
    pub spec: &'a SpecState,
}

/// The conditional gates of the profile: a project may define no command for them.
const CONDITIONAL: [&str; 2] = [gate_id::FORMAT, gate_id::LINT];

/// The command gates of the catalog, in report order.
const COMMANDS: [&str; 4] = [
    gate_id::FORMAT,
    gate_id::LINT,
    gate_id::BUILD,
    gate_id::UNIT_TESTS,
];

fn passed_outcomes(run: Option<&GateRun>) -> Option<Outcomes> {
    let run = run.filter(|run| !matches!(run.verdict(), Verdict::Blocked(_)))?;
    run.outcomes().filter(Outcomes::is_consistent)
}

/// Builds the reports of every gate except the evidence binding, which the evaluation adds.
///
/// # Errors
/// [`ReportError`] when a report would break the contract. That is a fault of the factory.
pub fn reports(asm: &Assembler<'_>, f: &Findings<'_>) -> Result<Vec<GateReport>, ReportError> {
    let head_tests = f
        .head
        .and_then(|s| s.runs.iter().find(|r| r.gate.role == Role::Tests));
    let head_outcomes = passed_outcomes(head_tests);
    let base_outcomes = passed_outcomes(f.baseline.and_then(|s| s.runs.first()));
    let comparison = match (&head_outcomes, &base_outcomes) {
        (Some(head), Some(base)) => Some(compare(base, head)),
        _ => None,
    };

    let mut out = Vec::new();
    for id in COMMANDS {
        out.push(command_gate(asm, f, id, comparison.as_ref())?);
    }
    if let Some(definitions) = f.definitions {
        for entry in definitions
            .entries()
            .iter()
            .filter(|entry| !COMMANDS.contains(&entry.id().as_str()))
        {
            out.push(entry_report(asm, f, entry, comparison.as_ref())?);
        }
    }
    out.push(asm.host(gate_id::PROTECTED_PATHS, f.host.protected.clone())?);
    out.push(asm.host(
        gate_id::TEST_PROTECTION,
        test_protection(f, comparison.as_ref()),
    )?);
    out.push(asm.host(gate_id::SECRET_SCAN, f.host.secrets.clone())?);
    let (result, evidence) = acceptance(f, head_outcomes.as_ref(), base_outcomes.as_ref());
    let compared = match evidence {
        Some((delta, notes)) => asm.comparison_with_notes(delta, &notes)?,
        None => not_compared(),
    };
    out.push(asm.host_compared(gate_id::ACCEPTANCE, result, compared)?);
    Ok(out)
}

fn command_gate(
    asm: &Assembler<'_>,
    f: &Findings<'_>,
    id: &str,
    comparison: Option<&(BaselineDelta, Vec<Violation>)>,
) -> Result<GateReport, ReportError> {
    // A relaxed lint is seen on the host, before any command. The lint gate cannot report that it
    // passed for a change that silences the lint (`lint_relaxation`, AUT-4).
    if id == gate_id::LINT && !matches!(f.host.lint, HostResult::Passed(_)) {
        return asm.host(gate_id::LINT, f.host.lint.clone());
    }
    // New build code is seen on the host too, and the build gate is blocked until a security
    // approver decides: the build would run it (`build_script_added`, AUT-5).
    if id == gate_id::BUILD && !matches!(f.host.build_code, HostResult::Passed(_)) {
        return asm.host(gate_id::BUILD, f.host.build_code.clone());
    }
    let Some(definitions) = f.definitions else {
        return asm.not_run(
            id,
            title_of(id),
            None,
            BlockedCode::PolicyUnresolvable,
            "gate definitions at the base commit",
            "The gate definitions could not be read from the protected base commit, so the gate cannot run.",
        );
    };
    match definitions.find(id) {
        Some(entry) => entry_report(asm, f, entry, comparison),
        None if CONDITIONAL.contains(&id) => asm.not_defined(id),
        None => asm.not_run(
            id,
            title_of(id),
            None,
            BlockedCode::PolicyUnresolvable,
            "a gate definition at the base commit",
            "The project manifest at the base commit defines no command for a gate that the profile makes mandatory.",
        ),
    }
}

fn entry_report(
    asm: &Assembler<'_>,
    f: &Findings<'_>,
    entry: &Resolved,
    comparison: Option<&(BaselineDelta, Vec<Violation>)>,
) -> Result<GateReport, ReportError> {
    match entry {
        Resolved::Refused { id, title, why } => {
            let reason = match why {
                Refusal::Denied { .. } => {
                    "The command policy denies the command of this gate, so it cannot run as written."
                }
                Refusal::NeedsPerson => {
                    "The command policy asks for a person before this command may run, so the gate cannot run."
                }
                Refusal::BadWorkingDirectory => {
                    "The working directory of this gate is not a path inside the repository, so it cannot run."
                }
            };
            asm.not_run(
                id.as_str(),
                title.as_str(),
                None,
                BlockedCode::PolicyUnresolvable,
                "a command the policy allows",
                reason,
            )
        }
        Resolved::Ready(gate) => ready_gate(asm, f, gate, comparison),
    }
}

fn ready_gate(
    asm: &Assembler<'_>,
    f: &Findings<'_>,
    gate: &CommandGate,
    comparison: Option<&(BaselineDelta, Vec<Violation>)>,
) -> Result<GateReport, ReportError> {
    let ran = f.head.and_then(|sandboxed| {
        sandboxed
            .runs
            .iter()
            .find(|run| run.gate.id == gate.id)
            .map(|run| (sandboxed, run))
    });
    let Some((sandboxed, run)) = ran else {
        return asm.not_run(
            gate.id.as_str(),
            gate.title.as_str(),
            Some(&gate.argv),
            BlockedCode::DependencyUnavailable,
            "host-side checks that passed",
            "The gate did not run, because a host-side check of the change did not pass first.",
        );
    };
    if gate.role == Role::Tests
        && let Some((delta, problems)) = comparison
    {
        return asm.command(run, &sandboxed.sandbox_id, asm.comparison(*delta), problems);
    }
    asm.command(run, &sandboxed.sandbox_id, not_compared(), &[])
}

/// The result of `test-file-protection`: the host rules first, then the comparison with the
/// run on the base commit.
fn test_protection(
    f: &Findings<'_>,
    comparison: Option<&(BaselineDelta, Vec<Violation>)>,
) -> HostResult {
    if !matches!(f.host.tests, HostResult::Passed(_)) {
        return f.host.tests.clone();
    }
    match comparison {
        Some((_, problems)) if problems.is_empty() => HostResult::Passed(
            "No test that passed on the base commit is missing or ignored in the candidate, and no new line skips a test."
                .to_owned(),
        ),
        Some((_, problems)) => HostResult::Failed(problems.clone()),
        None => HostResult::Blocked {
            missing: "a trusted test run on the base commit".to_owned(),
            reason: "The tests of the base commit were not run and read, so the tests of the candidate cannot be compared with them."
                .to_owned(),
        },
    }
}

/// The most tests one requirement lists in the report.
const MOST_TESTS_LISTED: usize = 5;

/// The most characters of a test name the report shows. A test name is text the builder wrote.
const MOST_NAME_CHARS: usize = 160;

/// The result of `acceptance-evidence`, and what the comparison with the base commit showed:
/// for each requirement, the tests that cover it and why each one counts.
///
/// A requirement is covered only by a passed test that names it and that did not pass on the
/// base commit (see [`crate::gates::scope::acceptance`]). Without a test run of the base commit
/// that could be read there is nothing to compare with, and the gate is blocked: it never passes
/// on the names alone.
fn acceptance(
    f: &Findings<'_>,
    head: Option<&Outcomes>,
    base: Option<&Outcomes>,
) -> (HostResult, Option<(BaselineDelta, String)>) {
    let blocked = |missing: &str, reason: &str| {
        (
            HostResult::Blocked {
                missing: missing.to_owned(),
                reason: reason.to_owned(),
            },
            None,
        )
    };
    let requirements = match f.spec {
        SpecState::Missing => {
            return blocked(
                "the frozen specification",
                "The specification stage produced no document that could be read, so the requirements are not known.",
            );
        }
        SpecState::NotApproved => {
            return blocked(
                "an approved specification",
                "The specification is not approved, so its requirements are not frozen.",
            );
        }
        SpecState::Ready(requirements) => requirements,
    };
    let Some(head) = head else {
        return blocked(
            "a verified test run",
            "No test run of the candidate was observed and read, so no requirement can be shown to be covered.",
        );
    };
    let Some(base) = base else {
        return blocked(
            "a trusted test run on the base commit",
            "The tests of the base commit were not run and read, so a test that passes now cannot be told from a test that passed before the change, and no requirement can be shown to be covered by this change.",
        );
    };
    let before = base
        .results()
        .iter()
        .map(|(test, status)| {
            let before = match status {
                Status::Passed => Before::Passed,
                Status::Failed => Before::Failed,
                Status::Ignored => Before::Ignored,
            };
            (test.clone(), before)
        })
        .collect();
    let found = coverage(requirements, &head.ids(Status::Passed), &before);
    let evidence = Some((
        if found.iter().any(Coverage::is_covered) {
            BaselineDelta::Improved
        } else {
            BaselineDelta::None
        },
        acceptance_notes(&found),
    ));
    let problems: Vec<Violation> = found
        .iter()
        .filter(|one| !one.is_covered())
        .map(|one| {
            let id = &one.requirement;
            if one.already_passing.is_empty() {
                Violation {
                    check: "requirement-uncovered",
                    message: format!("The requirement {id} has no passed test that names it."),
                    path: None,
                    line: None,
                }
            } else {
                Violation {
                    check: "requirement-covered-only-by-old-tests",
                    message: format!(
                        "The requirement {id} is named only by tests that already passed on the base commit ({}), so this change adds no evidence for it. Add a test named after the requirement that fails without the change.",
                        listed(one.already_passing.iter().map(|test| shown(test)))
                    ),
                    path: None,
                    line: None,
                }
            }
        })
        .collect();
    let result = if problems.is_empty() {
        HostResult::Passed(format!(
            "Every one of the {} requirement(s) of the frozen specification has a passed test that names it and that did not pass on the base commit. The notes of the baseline comparison name the tests of each requirement and why each one counts. The gate does not read what a test asserts.",
            requirements.len()
        ))
    } else {
        HostResult::Failed(problems)
    };
    (result, evidence)
}

/// A test name as a report shows it: one line, and not longer than a person would read.
fn shown(test: &str) -> String {
    let mut name: String = test
        .chars()
        .filter(|c| !c.is_control())
        .take(MOST_NAME_CHARS)
        .collect();
    if test.chars().count() > MOST_NAME_CHARS {
        name.push_str("...");
    }
    name
}

/// The first few items, and how many more there are.
fn listed(items: impl Iterator<Item = String>) -> String {
    let all: Vec<String> = items.collect();
    let mut text = all
        .iter()
        .take(MOST_TESTS_LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if all.len() > MOST_TESTS_LISTED {
        text.push_str(&format!("; and {} more", all.len() - MOST_TESTS_LISTED));
    }
    text
}

/// The evidence as a person and the reviewer read it: one line for each requirement, with the
/// tests that cover it and the basis of each.
///
/// The notes of a report hold at most [`HumanText::MAX_CHARS`] characters. When the lines do not
/// fit, the notes end by saying how many requirements are not listed; they are never cut in the
/// middle of a line.
fn acceptance_notes(found: &[Coverage]) -> String {
    const HEADING: &str = "A test counts for a requirement only when it names the requirement and did not pass on the base commit. The gate does not read what a test asserts.";
    // Room for the sentence that says how many requirements are left out.
    const RESERVED: usize = 120;
    let mut notes = HEADING.to_owned();
    let mut used = HEADING.chars().count();
    for (index, one) in found.iter().enumerate() {
        let line = if one.is_covered() {
            format!(
                "{}: {}.",
                one.requirement,
                listed(one.covering.iter().map(|test| format!(
                    "{} ({})",
                    shown(&test.test),
                    test.basis.words()
                )))
            )
        } else if one.already_passing.is_empty() {
            format!("{}: not covered. No passed test names it.", one.requirement)
        } else {
            format!(
                "{}: not covered. These tests name it and passed on the base commit already, so they do not count: {}.",
                one.requirement,
                listed(one.already_passing.iter().map(|test| shown(test)))
            )
        };
        let length = line.chars().count() + 1;
        if used + length + RESERVED > HumanText::MAX_CHARS {
            notes.push_str(&format!(
                "\n{} more requirement(s) are not listed here, because these notes have no room left.",
                found.len() - index
            ));
            break;
        }
        notes.push('\n');
        notes.push_str(&line);
        used += length;
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::scope::acceptance::{Basis, Covering};

    fn covered(requirement: &str, test: &str) -> Coverage {
        Coverage {
            requirement: requirement.to_owned(),
            covering: vec![Covering {
                test: test.to_owned(),
                basis: Basis::NewTest,
            }],
            already_passing: Vec::new(),
        }
    }

    #[test]
    fn the_notes_have_one_line_for_each_requirement_with_the_test_and_the_basis() {
        let mut old = covered("FR-002", "unused");
        old.covering.clear();
        old.already_passing
            .push("tests/it.rs::fr_002_old".to_owned());
        let notes = acceptance_notes(&[covered("FR-001", "tests/it.rs::fr_001_new"), old]);
        let lines: Vec<&str> = notes.lines().collect();
        assert_eq!(lines[1], "FR-001: tests/it.rs::fr_001_new (new test).");
        assert!(lines[2].starts_with("FR-002: not covered."), "{}", lines[2]);
        assert!(lines[2].contains("tests/it.rs::fr_002_old"), "{}", lines[2]);
    }

    #[test]
    fn notes_that_do_not_fit_say_how_many_requirements_are_left_out_and_keep_whole_lines() {
        // Test names are the builder's text: very long ones, and many of them.
        let long = "x".repeat(1000);
        let found: Vec<Coverage> = (0..200)
            .map(|n| {
                covered(
                    &format!("FR-{n:03}"),
                    &format!("tests/it.rs::fr_{n:03}_{long}"),
                )
            })
            .collect();
        let notes = acceptance_notes(&found);
        assert!(HumanText::parse(&notes).is_ok(), "the notes fit the schema");
        let lines: Vec<&str> = notes.lines().collect();
        let listed = lines.len() - 2;
        assert!(listed > 0);
        assert_eq!(
            lines.last().copied(),
            Some(
                format!(
                    "{} more requirement(s) are not listed here, because these notes have no room left.",
                    200 - listed
                )
                .as_str()
            )
        );
        assert!(
            lines[1..=listed]
                .iter()
                .all(|line| line.ends_with("(new test)."))
        );
    }
}
