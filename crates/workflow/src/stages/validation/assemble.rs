//! From what was observed to the gate reports.
//!
//! The functions here build one report for each gate of the stage. They take the supervisor's
//! observations ([`GateRun`]) and the results of the host-side rules, and they never read
//! anything else. A gate with no observation is reported `BLOCKED` with the reason, a gate the
//! project does not define is `NOT_APPLICABLE` only where the profile makes it conditional, and
//! the outcome of a command gate comes from [`interpret`] and nowhere else.

use factory_domain::contracts::ArtifactRef;
use factory_domain::contracts::GateReport;
use factory_domain::contracts::gate_report::{
    BaselineComparison, BaselineDelta, BlockedCode, Failure, GateCommand, NotApplicableCode,
    NotApplicableDecider,
};
use factory_domain::ids::GateReportId;
use factory_domain::values::Sha256Digest;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::paths::CommitSha;

use super::sandboxed::{GateRun, Seen};
use crate::gates::command::report::{
    Draft, Outcome, ReportContext, ReportError, build, failure, in_process_environment,
    not_compared, observed_command, sandbox_environment, sandbox_info, unrun_command, warning,
};
use crate::gates::command::{Outcomes, Status, Verdict, gate_id};
use crate::gates::scope::Violation;

/// The most failures one report lists.
const MOST_FAILURES: usize = 50;

/// The result of a host-side rule, before it is a report.
#[derive(Debug, Clone)]
pub enum HostResult {
    /// The rule found nothing.
    Passed(String),
    /// The rule refuses the change.
    Failed(Vec<Violation>),
    /// The rule could not be applied.
    Blocked {
        /// What was absent.
        missing: String,
        /// A plain sentence.
        reason: String,
    },
}

/// The short title of each gate of the catalog.
#[must_use]
pub fn title_of(gate: &str) -> &'static str {
    match gate {
        gate_id::FORMAT => "Code formatting",
        gate_id::LINT => "Lint",
        gate_id::BUILD => "Build",
        gate_id::UNIT_TESTS => "Tests",
        gate_id::PROTECTED_PATHS => "Protected paths unchanged",
        gate_id::TEST_PROTECTION => "Test file protection",
        gate_id::SECRET_SCAN => "Secret scan",
        gate_id::ACCEPTANCE => "Acceptance evidence",
        gate_id::EVIDENCE_BINDING => "Evidence binding",
        _ => "Gate of the project manifest",
    }
}

/// Builds the reports of one validation run.
pub struct Assembler<'a> {
    /// What every report shares.
    pub cx: ReportContext,
    /// New report identifiers.
    pub ids: &'a dyn IdGenerator,
    /// The time.
    pub clock: &'a dyn Clock,
    /// An empty log, for a command that did not run.
    pub empty_log: ArtifactRef,
    /// The digest of the verify image.
    pub image: Sha256Digest,
    /// The architecture of the image.
    pub arch: String,
    /// The base commit, named in the baseline comparison.
    pub base: CommitSha,
}

impl Assembler<'_> {
    fn id(&self) -> GateReportId {
        GateReportId::from_uuid(self.ids.new_uuid())
    }

    /// A report for a rule applied by the control plane.
    ///
    /// # Errors
    /// [`ReportError`] when a value is out of bounds.
    pub fn host(&self, gate: &str, result: HostResult) -> Result<GateReport, ReportError> {
        let now = self.clock.now();
        let (reason, outcome) = match result {
            HostResult::Passed(reason) => (reason, Outcome::Passed),
            HostResult::Failed(violations) => (
                format!(
                    "The rule found {} problem(s) in the change, so the change cannot go on.",
                    violations.len()
                ),
                Outcome::Failed(failures(&violations)?),
            ),
            HostResult::Blocked { missing, reason } => (
                reason,
                Outcome::Blocked(BlockedCode::DependencyUnavailable, missing),
            ),
        };
        build(
            &self.cx,
            self.id(),
            Draft {
                gate: gate.to_owned(),
                title: title_of(gate).to_owned(),
                reason,
                started: now,
                finished: now,
                environment: in_process_environment(self.cx.fidelity)?,
                commands: Vec::new(),
                warnings: Vec::new(),
                baseline: not_compared(),
                outcome,
            },
        )
    }

    /// A report for a gate that did not run, with the command it would have run.
    ///
    /// # Errors
    /// [`ReportError`] when a value is out of bounds.
    pub fn not_run(
        &self,
        gate: &str,
        title: &str,
        would_run: Option<&[String]>,
        code: BlockedCode,
        missing: &str,
        reason: &str,
    ) -> Result<GateReport, ReportError> {
        let now = self.clock.now();
        let commands = match would_run {
            Some(argv) if !argv.is_empty() => {
                vec![unrun_command(argv, None, now, &self.empty_log)?]
            }
            _ => Vec::new(),
        };
        build(
            &self.cx,
            self.id(),
            Draft {
                gate: gate.to_owned(),
                title: title.to_owned(),
                reason: reason.to_owned(),
                started: now,
                finished: now,
                environment: in_process_environment(self.cx.fidelity)?,
                commands,
                warnings: Vec::new(),
                baseline: not_compared(),
                outcome: Outcome::Blocked(code, missing.to_owned()),
            },
        )
    }

    /// A report for a conditional gate that the project does not define.
    ///
    /// # Errors
    /// [`ReportError`] when a value is out of bounds.
    pub fn not_defined(&self, gate: &str) -> Result<GateReport, ReportError> {
        let now = self.clock.now();
        build(
            &self.cx,
            self.id(),
            Draft {
                gate: gate.to_owned(),
                title: title_of(gate).to_owned(),
                reason: "The profile makes this gate conditional and the project manifest at the base commit defines no command for it.".to_owned(),
                started: now,
                finished: now,
                environment: in_process_environment(self.cx.fidelity)?,
                commands: Vec::new(),
                warnings: Vec::new(),
                baseline: not_compared(),
                outcome: Outcome::NotApplicable {
                    code: NotApplicableCode::ProfileExcludesGate,
                    decided_by: NotApplicableDecider::DomainProfile,
                    justification: "The domain profile lists this gate as conditional, and the project manifest read at the base commit defines no command for it.".to_owned(),
                },
            },
        )
    }

    /// A report for a command gate that ran in the sandbox.
    ///
    /// `baseline` and `extra` come from the comparison with the base commit: when `extra` holds
    /// failures, a run that passed on its own is reported as failed, because a report that shows
    /// a regression cannot be `PASSED`.
    ///
    /// # Errors
    /// [`ReportError`] when a value is out of bounds or the report breaks the contract.
    pub fn command(
        &self,
        run: &GateRun,
        sandbox_id: &str,
        baseline: BaselineComparison,
        extra: &[Violation],
    ) -> Result<GateReport, ReportError> {
        let verdict = run.verdict();
        let mut commands: Vec<GateCommand> = Vec::new();
        for seen in &run.probes {
            commands.push(observed(seen)?);
        }
        let own = run.run.as_ref();
        match own {
            Some(seen) => commands.push(observed(seen)?),
            None => commands.push(unrun_command(
                &run.gate.argv,
                run.gate.cwd.as_ref().map(|dir| dir.as_str()),
                self.clock.now(),
                &self.empty_log,
            )?),
        }
        let (started, finished) = span(&commands, self.clock.now());
        let mut warnings = Vec::new();
        if let Some(first) = &run.first {
            warnings.push(warning(
                "flaky-retry",
                &format!(
                    "The tests failed once and were run again, because every failed test is in the central flaky registry. The first run exited with code {:?} and its logs are stored.",
                    first.exec.exit_code
                ),
                "Fix the test, or take it out of the flaky registry once it is stable.",
            )?);
        }
        let (reason, outcome) = match verdict {
            Verdict::Passed if extra.is_empty() => (
                format!(
                    "The command exited with code 0 and the supervisor recorded it. {}",
                    if run.gate.role.expects_tests() {
                        "The output shows tests that ran."
                    } else {
                        "No output is needed to read the result."
                    }
                ),
                Outcome::Passed,
            ),
            Verdict::Passed => (
                "The command exited with code 0, but the tests differ from the base commit's tests in a way the policy forbids.".to_owned(),
                Outcome::Failed(failures(extra)?),
            ),
            Verdict::Failed(list) => {
                let mut all = Vec::new();
                for item in list.iter().take(MOST_FAILURES) {
                    all.push(failure(item.check, &item.message, None)?);
                }
                (
                    "The command ran and its tool reported a problem.".to_owned(),
                    Outcome::Failed(all),
                )
            }
            Verdict::Blocked(why) => {
                let missing = run
                    .blocker
                    .as_ref()
                    .and_then(|blocker| blocker.tool.clone())
                    .map_or_else(|| why.missing.to_owned(), |tool| format!("the tool {tool}"));
                (
                    why.reason.to_owned(),
                    Outcome::Blocked(why.code, missing),
                )
            }
        };
        let info = sandbox_info(sandbox_id, self.image.clone(), &self.arch)?;
        build(
            &self.cx,
            self.id(),
            Draft {
                gate: run.gate.id.as_str().to_owned(),
                title: run.gate.title.as_str().to_owned(),
                reason,
                started,
                finished,
                environment: sandbox_environment(self.cx.fidelity, info, run.versions.clone()),
                commands,
                warnings,
                baseline,
                outcome,
            },
        )
    }

    /// The comparison with the base commit for a test gate.
    #[must_use]
    pub fn comparison(&self, delta: BaselineDelta) -> BaselineComparison {
        BaselineComparison {
            baseline_commit_sha: Some(self.base.clone()),
            delta,
            notes: None,
        }
    }
}

fn observed(seen: &Seen) -> Result<GateCommand, ReportError> {
    observed_command(&seen.argv, seen.cwd.as_deref(), &seen.exec)
}

/// The first start and the last finish of the commands.
fn span(
    commands: &[GateCommand],
    fallback: factory_domain::values::Timestamp,
) -> (
    factory_domain::values::Timestamp,
    factory_domain::values::Timestamp,
) {
    let started = commands
        .iter()
        .map(|command| command.started_at)
        .min_by_key(|at| (at.unix_seconds(), at.subsecond_nanos()))
        .unwrap_or(fallback);
    let finished = commands
        .iter()
        .map(|command| command.finished_at)
        .max_by_key(|at| (at.unix_seconds(), at.subsecond_nanos()))
        .unwrap_or(fallback);
    (started, finished)
}

/// Violations as the failures of a report.
///
/// # Errors
/// [`ReportError::Value`] when a message is outside the length the schema allows.
pub fn failures(violations: &[Violation]) -> Result<Vec<Failure>, ReportError> {
    violations
        .iter()
        .take(MOST_FAILURES)
        .map(|violation| {
            failure(
                violation.check,
                &violation.message,
                violation.path.as_deref().map(|path| (path, violation.line)),
            )
        })
        .collect()
}

/// How the head tests differ from the base tests, and the problems that forbids.
///
/// * A test that passed on the base commit and is absent or ignored now is a regression
///   (`forbid_removed_tests`, `forbid_newly_ignored_tests`).
/// * A test that is ignored now and was not ignored before is a newly ignored test.
/// * New tests, and new passing tests, are allowed (`new_tests_allowed`).
#[must_use]
pub fn compare(base: &Outcomes, head: &Outcomes) -> (BaselineDelta, Vec<Violation>) {
    let mut problems = Vec::new();
    for (id, status) in base.results() {
        if *status != Status::Passed {
            continue;
        }
        match head.results().get(id) {
            None => problems.push(test_problem(
                "test-removed",
                &format!("The test {id} passed on the base commit and does not appear in the run of the candidate."),
            )),
            Some(Status::Ignored) => problems.push(test_problem(
                "test-ignored",
                &format!("The test {id} passed on the base commit and is ignored in the run of the candidate."),
            )),
            Some(Status::Passed | Status::Failed) => {}
        }
    }
    for (id, status) in head.results() {
        if *status == Status::Ignored && base.results().get(id) != Some(&Status::Ignored) {
            problems.push(test_problem(
                "test-ignored",
                &format!("The test {id} is ignored in the run of the candidate and was not ignored on the base commit."),
            ));
        }
    }
    let newly_failing = base.results().iter().any(|(id, status)| {
        *status == Status::Passed && head.results().get(id) == Some(&Status::Failed)
    });
    let fixed = base.results().iter().any(|(id, status)| {
        *status == Status::Failed && head.results().get(id) == Some(&Status::Passed)
    });
    let delta = if !problems.is_empty() {
        BaselineDelta::Regressed
    } else if newly_failing {
        BaselineDelta::NewFailures
    } else if fixed {
        BaselineDelta::Improved
    } else {
        BaselineDelta::None
    };
    (delta, problems)
}

fn test_problem(check: &'static str, message: &str) -> Violation {
    Violation {
        check,
        message: message.to_owned(),
        path: None,
        line: None,
    }
}
