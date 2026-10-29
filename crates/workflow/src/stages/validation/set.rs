//! The whole set of gate reports of one validation run.
//!
//! One report for each gate, always. A gate that has no observation says why in a `BLOCKED`
//! report, and the only gates that may be `NOT_APPLICABLE` are the conditional ones the project
//! does not define, decided by the domain profile and recorded as such.

use factory_domain::contracts::GateReport;
use factory_domain::contracts::gate_report::{BaselineDelta, BlockedCode};

use super::assemble::{Assembler, HostResult, compare, title_of};
use super::host::HostResults;
use super::sandboxed::{GateRun, Sandboxed};
use crate::gates::command::report::{ReportError, not_compared};
use crate::gates::command::{
    CommandGate, Outcomes, Refusal, Resolved, Role, Status, TrustedGates, Verdict, gate_id,
};
use crate::gates::scope::Violation;
use crate::gates::scope::acceptance::{Requirement, uncovered};

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
    out.push(asm.host(gate_id::ACCEPTANCE, acceptance(f, head_outcomes.as_ref()))?);
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

fn acceptance(f: &Findings<'_>, head: Option<&Outcomes>) -> HostResult {
    let blocked = |missing: &str, reason: &str| HostResult::Blocked {
        missing: missing.to_owned(),
        reason: reason.to_owned(),
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
    let passed = head.ids(Status::Passed);
    let missing = uncovered(requirements, &passed);
    if missing.is_empty() {
        HostResult::Passed(format!(
            "Every one of the {} requirement(s) of the frozen specification has a passed test that names it.",
            requirements.len()
        ))
    } else {
        HostResult::Failed(
            missing
                .into_iter()
                .map(|id| Violation {
                    check: "requirement-uncovered",
                    message: format!("The requirement {id} has no passed test that names it."),
                    path: None,
                    line: None,
                })
                .collect(),
        )
    }
}
