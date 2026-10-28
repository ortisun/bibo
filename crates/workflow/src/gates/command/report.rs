//! Building a gate report from what the factory observed.
//!
//! The report is the machine-readable record of one gate (`schemas/gate-report.schema.json`).
//! Everything in it comes from the control plane: the identifiers from the ports, the commands
//! and exit codes from the supervisor's [`ExecResult`], the definition from the protected base
//! commit. No field is read from a file that the sandbox wrote.
//!
//! The finished report is checked against the rules of the contract (a `PASSED` report must show
//! commands that ran and exited with code 0, and the tools it used) before it is returned, so a
//! report that the domain would refuse cannot leave this module.

use factory_domain::contracts::gate_report::{
    BaselineComparison, BlockedCode, BlockedReason, Failure, FailureLocation, GateCommand,
    GateEnvironment, GateMetadata, GateWarning, NotApplicableCode, NotApplicableDecider,
    NotApplicableReason, SandboxInfo, ToolVersion, TrustedDefinition,
};
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, SchemaVersion};
use factory_domain::ids::{AttemptId, GateReportId, JobId, StageRunId};
use factory_domain::values::{
    BoundedString, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, PositiveInt,
    SemanticVersion, Sha256Digest, Slug, Timestamp,
};
use factory_domain::vocabulary::{ExecutionMode, Fidelity, GateOutcome};
use factory_ports::sandbox::ExecResult;

/// The version of every gate of the validation stage. It changes when a rule changes.
pub const GATE_VERSION: &str = "1.0.0";

/// The tool name recorded for a gate that runs inside the control plane.
pub const IN_PROCESS_TOOL: &str = "factory-validation-gates";

/// A report could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// A value is outside what its type allows.
    #[error("a value of a gate report is outside the limits of the gate report schema")]
    Value,
    /// The finished report breaks a rule of the gate report contract.
    #[error("a gate report breaks a rule of the gate report contract")]
    Contract,
}

impl From<factory_domain::error::ValueError> for ReportError {
    fn from(_: factory_domain::error::ValueError) -> Self {
        Self::Value
    }
}

/// Which run the reports are about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// The attempt.
    pub attempt: AttemptId,
    /// Test mode allows fakes. Production mode does not.
    pub mode: ExecutionMode,
}

/// What every report of one validation run shares.
#[derive(Debug, Clone)]
pub struct ReportContext {
    /// The run.
    pub subject: Subject,
    /// Where the gate definitions came from and their hash.
    pub definition: TrustedDefinition,
    /// Whether the components that produced the evidence are real or fake.
    pub fidelity: Fidelity,
    /// The hash of the evidence binding. It enters the evidence hash of every report, so a
    /// report cannot be moved to another commit, policy or image.
    pub binding: Sha256Digest,
}

/// How a gate ended, with what the report must say about it.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// It passed.
    Passed,
    /// It failed, for these reasons.
    Failed(Vec<Failure>),
    /// It could not run.
    Blocked(BlockedCode, String),
    /// It does not apply, decided by a recorded rule.
    NotApplicable {
        /// The category.
        code: NotApplicableCode,
        /// Who decided.
        decided_by: NotApplicableDecider,
        /// Why, in a plain sentence.
        justification: String,
    },
}

/// Everything a report needs besides the context.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The gate.
    pub gate: String,
    /// What a person reads.
    pub title: String,
    /// Why the outcome is what it is.
    pub reason: String,
    /// When the gate started.
    pub started: Timestamp,
    /// When it finished.
    pub finished: Timestamp,
    /// Where and with what it ran.
    pub environment: GateEnvironment,
    /// The commands, as the supervisor observed them.
    pub commands: Vec<GateCommand>,
    /// Findings that do not stop the gate.
    pub warnings: Vec<GateWarning>,
    /// The comparison with the base commit.
    pub baseline: BaselineComparison,
    /// How it ended.
    pub outcome: Outcome,
}

/// The environment of a gate that runs inside the control plane.
///
/// # Errors
/// [`ReportError::Value`] when a constant is not valid, which does not happen.
pub fn in_process_environment(fidelity: Fidelity) -> Result<GateEnvironment, ReportError> {
    Ok(GateEnvironment {
        fidelity,
        executor_kind: factory_domain::contracts::gate_report::ExecutorKind::InProcess,
        sandbox: None,
        tool_versions: vec![ToolVersion {
            tool: NonEmptyString::parse(IN_PROCESS_TOOL)?,
            version: NonEmptyString::parse(GATE_VERSION)?,
        }],
    })
}

/// The environment of a gate that runs commands in the verify sandbox.
#[must_use]
pub fn sandbox_environment(
    fidelity: Fidelity,
    sandbox: SandboxInfo,
    tool_versions: Vec<ToolVersion>,
) -> GateEnvironment {
    GateEnvironment {
        fidelity,
        executor_kind: factory_domain::contracts::gate_report::ExecutorKind::SandboxCommand,
        sandbox: Some(sandbox),
        tool_versions,
    }
}

/// The sandbox a gate ran in.
///
/// # Errors
/// [`ReportError::Value`] when the sandbox name is not 1 to 128 characters.
pub fn sandbox_info(
    sandbox_id: &str,
    image: Sha256Digest,
    arch: &str,
) -> Result<SandboxInfo, ReportError> {
    Ok(SandboxInfo {
        sandbox_id: BoundedString::parse(sandbox_id)?,
        image_digest: image,
        os: NonEmptyString::parse("linux")?,
        arch: NonEmptyString::parse(arch)?,
        network: factory_domain::contracts::gate_report::SandboxNetwork::None,
    })
}

/// A command the supervisor observed.
///
/// # Errors
/// [`ReportError::Value`] for an empty vector.
pub fn observed_command(
    argv: &[String],
    cwd: Option<&str>,
    exec: &ExecResult,
) -> Result<GateCommand, ReportError> {
    Ok(GateCommand {
        argv: NonEmptyVec::new(argv.to_vec())?,
        cwd: cwd.map(str::to_owned),
        executed: true,
        exit_code: exec.exit_code.map(i64::from),
        terminated_by_signal: exec.signal.map(i64::from),
        timed_out: exec.timed_out,
        started_at: exec.started_at,
        finished_at: exec.finished_at,
        stdout: exec.stdout.clone(),
        stderr: exec.stderr.clone(),
    })
}

/// A command that was meant to run and did not.
///
/// # Errors
/// [`ReportError::Value`] for an empty vector.
pub fn unrun_command(
    argv: &[String],
    cwd: Option<&str>,
    at: Timestamp,
    empty_log: &ArtifactRef,
) -> Result<GateCommand, ReportError> {
    Ok(GateCommand {
        argv: NonEmptyVec::new(argv.to_vec())?,
        cwd: cwd.map(str::to_owned),
        executed: false,
        exit_code: None,
        terminated_by_signal: None,
        timed_out: false,
        started_at: at,
        finished_at: at,
        stdout: empty_log.clone(),
        stderr: empty_log.clone(),
    })
}

/// A failure of a check, optionally at a place in a file.
///
/// # Errors
/// [`ReportError::Value`] when the check is not a slug or the message is outside 10 to 4000
/// characters.
pub fn failure(
    check: &str,
    message: &str,
    at: Option<(&str, Option<u32>)>,
) -> Result<Failure, ReportError> {
    Ok(Failure {
        check_id: Slug::parse(check)?,
        message: HumanText::parse(&bounded(message))?,
        location: match at {
            None => None,
            Some((path, line)) => Some(FailureLocation {
                path: path.to_owned(),
                line: match line {
                    Some(n) => Some(PositiveInt::new(i64::from(n))?),
                    None => None,
                },
            }),
        },
    })
}

/// A finding that does not stop the gate.
///
/// # Errors
/// [`ReportError::Value`] as for [`failure`].
pub fn warning(check: &str, message: &str, fix: &str) -> Result<GateWarning, ReportError> {
    Ok(GateWarning {
        check_id: Slug::parse(check)?,
        message: HumanText::parse(&bounded(message))?,
        suggested_fix: HumanText::parse(&bounded(fix))?,
        location: None,
    })
}

/// Cuts a sentence at the length the schema allows.
fn bounded(text: &str) -> String {
    text.chars().take(HumanText::MAX_CHARS).collect()
}

/// The version string `tool --version` printed: its first line, split at the first space.
///
/// # Errors
/// [`ReportError::Value`] when the text has no first line.
pub fn tool_version(printed: &str) -> Result<ToolVersion, ReportError> {
    let line = printed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or(ReportError::Value)?;
    let (tool, version) = line.split_once(' ').unwrap_or((line, "unknown"));
    Ok(ToolVersion {
        tool: NonEmptyString::parse(tool)?,
        version: NonEmptyString::parse(version.trim())?,
    })
}

/// Builds one report.
///
/// # Errors
/// [`ReportError`] when a value is out of bounds or the report breaks the contract.
pub fn build(
    cx: &ReportContext,
    id: GateReportId,
    draft: Draft,
) -> Result<GateReport, ReportError> {
    let hash = evidence_hash(cx, &draft);
    let (outcome, failures, blocked_reason, not_applicable_reason) = match draft.outcome {
        Outcome::Passed => (GateOutcome::Passed, Some(Vec::new()), None, None),
        Outcome::Failed(list) => (GateOutcome::Failed, Some(list), None, None),
        Outcome::Blocked(code, missing) => (
            GateOutcome::Blocked,
            None,
            Some(BlockedReason {
                code,
                missing: NonEmptyVec::new(vec![NonEmptyString::parse(&missing)?])?,
            }),
            None,
        ),
        Outcome::NotApplicable {
            code,
            decided_by,
            justification,
        } => (
            GateOutcome::NotApplicable,
            None,
            None,
            Some(NotApplicableReason {
                code,
                justification: HumanText::parse(&bounded(&justification))?,
                decided_by,
            }),
        ),
    };
    let ran = matches!(outcome, GateOutcome::Passed | GateOutcome::Failed);
    let report = GateReport {
        schema_version: SchemaVersion,
        metadata: GateMetadata {
            gate_report_id: id,
            gate_id: Slug::parse(&draft.gate)?,
            gate_version: SemanticVersion::parse(GATE_VERSION)?,
            job_id: cx.subject.job,
            stage_run_id: cx.subject.stage_run,
            attempt_id: Some(cx.subject.attempt),
            execution_mode: cx.subject.mode,
            trusted_definition: cx.definition.clone(),
        },
        title: HumanTitle::parse(&draft.title)?,
        outcome,
        reason: HumanText::parse(&bounded(&draft.reason))?,
        started_at: draft.started,
        finished_at: draft.finished,
        environment: draft.environment,
        commands: draft.commands,
        failures,
        warnings: ran.then_some(draft.warnings),
        blocked_reason,
        not_applicable_reason,
        evidence_hash: hash,
        baseline_comparison: draft.baseline,
    };
    report.validate().map_err(|_| ReportError::Contract)?;
    Ok(report)
}

/// A hash over the canonical form of the commands, the logs, the failures and the binding.
fn evidence_hash(cx: &ReportContext, draft: &Draft) -> Sha256Digest {
    let unit = '\u{1f}';
    let mut text = format!(
        "{}{unit}{}{unit}{}{unit}{}{unit}{}",
        draft.gate,
        cx.definition.definition_sha256,
        cx.binding,
        cx.subject.attempt,
        match &draft.outcome {
            Outcome::Passed => "passed".to_owned(),
            Outcome::Failed(_) => "failed".to_owned(),
            Outcome::Blocked(code, missing) =>
                format!("blocked{unit}{}{unit}{missing}", code.as_str()),
            Outcome::NotApplicable { code, .. } => format!("not-applicable{unit}{}", code.as_str()),
        }
    );
    for command in &draft.commands {
        text.push('\n');
        text.push_str(&command.argv.as_slice().join(&unit.to_string()));
        text.push_str(&format!(
            "{unit}{:?}{unit}{:?}{unit}{}{unit}{}{unit}{}",
            command.exit_code,
            command.terminated_by_signal,
            command.timed_out,
            command.stdout.sha256,
            command.stderr.sha256
        ));
    }
    if let Outcome::Failed(list) = &draft.outcome {
        for failure in list {
            text.push('\n');
            text.push_str(&format!(
                "{}{unit}{}",
                failure.check_id.as_str(),
                failure.message.as_str()
            ));
            if let Some(at) = &failure.location {
                text.push_str(&format!(
                    "{unit}{}{unit}{:?}",
                    at.path,
                    at.line.map(PositiveInt::get)
                ));
            }
        }
    }
    Sha256Digest::of(text.as_bytes())
}

/// Splits `name@sha256:...` into the digest part, which is what a report records.
///
/// # Errors
/// [`ReportError::Value`] when the reference has no digest.
pub fn image_digest(reference: &str) -> Result<Sha256Digest, ReportError> {
    let (_, digest) = reference.split_once('@').ok_or(ReportError::Value)?;
    Ok(Sha256Digest::parse(digest)?)
}

/// A comparison that was not made.
#[must_use]
pub fn not_compared() -> BaselineComparison {
    BaselineComparison {
        baseline_commit_sha: None,
        delta: factory_domain::contracts::gate_report::BaselineDelta::NotCompared,
        notes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_version_is_the_first_line_split_at_the_first_space() {
        let v = tool_version("cargo 1.98.0 (797e8a9bc 2026-08-05)\n").expect("a version");
        assert_eq!(v.tool.as_str(), "cargo");
        assert_eq!(v.version.as_str(), "1.98.0 (797e8a9bc 2026-08-05)");
        assert!(tool_version("  \n\n").is_err());
        assert_eq!(
            tool_version("tool").expect("a tool").version.as_str(),
            "unknown"
        );
    }

    #[test]
    fn the_digest_of_an_image_reference_is_what_follows_the_at_sign() {
        let reference = format!("registry.local/x@sha256:{}", "a".repeat(64));
        assert_eq!(
            image_digest(&reference).expect("a digest").as_str(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(image_digest("no-digest").is_err());
    }

    #[test]
    fn a_long_sentence_is_cut_at_the_schema_limit() {
        assert_eq!(bounded(&"x".repeat(5000)).chars().count(), 4000);
    }
}
