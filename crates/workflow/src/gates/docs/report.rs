//! From the result of a check to the typed gate report the engine stores.
//!
//! The report is built with the same builder as the command gates of the validation stage
//! ([`crate::gates::command::report`]), so it follows the same rules of the gate report schema: a
//! `PASSED` report has commands that exited with 0 or an in-process gate, a `FAILED` report has
//! failures, a `BLOCKED` report says what was missing, and a `NOT_APPLICABLE` report has a
//! recorded reason and no commands.

use factory_domain::contracts::GateReport;
use factory_domain::contracts::gate_report::{
    DefinitionSource, GateCommand, NotApplicableDecider, TrustedDefinition,
};
use factory_domain::ids::GateReportId;
use factory_domain::values::{GitSha, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{Clock, IdGenerator};

use super::check::{CheckResult, Finding, Ran, Verdict};
use crate::gates::command::report::{
    Draft, Outcome, ReportContext, ReportError, Subject, build, failure, in_process_environment,
    not_compared, observed_command, sandbox_environment, sandbox_info, warning,
};
use crate::handlers::StageError;

/// The text of the definition of the Documentation Quality Gate, hashed into every report. A
/// change to a check changes this text.
pub const DEFINITION: &str = "documentation-quality-gate 1.0.0: links and anchors resolve (external links are counted and never fetched), examples run and print what the page says, named commands, flags and variables exist in the help output or the source, every visible or breaking change is documented, diagrams parse, planned pages exist, the changelog has its entry, no secret-shaped text, and the documents were written for the current code. A tool that is absent is blocked, and nothing to check is not applicable with its rule.";

/// Where the commands of a sandbox gate ran.
#[derive(Debug, Clone)]
pub struct SandboxFacts {
    /// The digest of the verify image.
    pub image: Sha256Digest,
    /// Its CPU architecture.
    pub arch: String,
}

/// Builds the reports of one stage run.
pub struct Reporter<'a> {
    /// The run.
    pub subject: Subject,
    /// The commit of the factory's gate definitions.
    pub definition_commit: GitSha,
    /// Whether the components that produced the evidence are real or fake.
    pub fidelity: Fidelity,
    /// A hash of what the evidence is about, so a report cannot move to another commit.
    pub binding: Sha256Digest,
    /// The verify sandbox, for the gates that ran commands.
    pub sandbox: Option<SandboxFacts>,
    /// The clock.
    pub clock: &'a dyn Clock,
    /// The identifiers.
    pub ids: &'a dyn IdGenerator,
}

fn internal(_: ReportError) -> StageError {
    StageError::Internal
}

fn failures(
    findings: &[Finding],
) -> Result<Vec<factory_domain::contracts::gate_report::Failure>, StageError> {
    findings
        .iter()
        .map(|found| {
            let place = found
                .file
                .as_deref()
                .map(|file| (file, found.line.and_then(|l| u32::try_from(l).ok())));
            failure(found.check, &found.message, place).map_err(internal)
        })
        .collect()
}

impl Reporter<'_> {
    fn context(&self, definition_text: &str) -> ReportContext {
        ReportContext {
            subject: self.subject,
            definition: TrustedDefinition {
                source: DefinitionSource::CentralConfig,
                commit_sha: self.definition_commit.clone(),
                definition_sha256: Sha256Digest::of(definition_text.as_bytes()),
            },
            fidelity: self.fidelity,
            binding: self.binding.clone(),
        }
    }

    /// The report of a check of the Documentation Quality Gate.
    ///
    /// # Errors
    /// [`StageError::Internal`] when the report breaks a rule of the gate report schema.
    pub fn check(
        &self,
        result: &CheckResult,
        sandbox_id: Option<&str>,
    ) -> Result<GateReport, StageError> {
        let commands: Vec<GateCommand> = result
            .commands
            .iter()
            .map(|ran: &Ran| observed_command(&ran.argv, None, &ran.exec).map_err(internal))
            .collect::<Result<_, _>>()?;
        let started = commands
            .iter()
            .map(|c| c.started_at)
            .min()
            .unwrap_or_else(|| self.clock.now());
        let finished = commands
            .iter()
            .map(|c| c.finished_at)
            .max()
            .unwrap_or_else(|| self.clock.now());
        let tools = in_process_environment(self.fidelity)
            .map_err(internal)?
            .tool_versions;
        let environment = match (&self.sandbox, sandbox_id, commands.is_empty()) {
            (Some(facts), Some(id), false) => sandbox_environment(
                self.fidelity,
                sandbox_info(id, facts.image.clone(), &facts.arch).map_err(internal)?,
                tools,
            ),
            (_, _, true) => in_process_environment(self.fidelity).map_err(internal)?,
            _ => return Err(StageError::Internal),
        };
        let outcome = match &result.verdict {
            Verdict::Passed => Outcome::Passed,
            Verdict::Failed => Outcome::Failed(failures(&result.findings)?),
            Verdict::Blocked { code, missing } => Outcome::Blocked(*code, missing.clone()),
            Verdict::NotApplicable {
                code,
                justification,
            } => Outcome::NotApplicable {
                code: *code,
                decided_by: NotApplicableDecider::DeterministicRule,
                justification: justification.clone(),
            },
        };
        let warnings = result
            .warnings
            .iter()
            .map(|note| {
                warning(
                    note.check,
                    &note.message,
                    "Check the link by hand before the release, because the gate cannot reach the network.",
                )
                .map_err(internal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut evidence = self.context(DEFINITION);
        // The evidence lines enter the binding of the report, so the lines a check read are part
        // of what the report vouches for.
        evidence.binding = Sha256Digest::of(
            format!("{}\n{}", self.binding, result.evidence.join("\n")).as_bytes(),
        );
        build(
            &evidence,
            GateReportId::from_uuid(self.ids.new_uuid()),
            Draft {
                gate: result.gate.to_owned(),
                title: result.title.to_owned(),
                reason: result.reason.clone(),
                started,
                finished,
                environment,
                commands,
                warnings,
                baseline: not_compared(),
                outcome,
            },
        )
        .map_err(internal)
    }

    /// The report of a gate of a stage that runs in the control plane and decides from stored
    /// documents: it passes, or it fails with these findings.
    ///
    /// # Errors
    /// [`StageError::Internal`] when the report breaks a rule of the gate report schema.
    pub fn in_process(
        &self,
        gate: &str,
        title: &str,
        definition_text: &str,
        reason: &str,
        findings: &[Finding],
    ) -> Result<GateReport, StageError> {
        let now = self.clock.now();
        build(
            &self.context(definition_text),
            GateReportId::from_uuid(self.ids.new_uuid()),
            Draft {
                gate: gate.to_owned(),
                title: title.to_owned(),
                reason: reason.to_owned(),
                started: now,
                finished: self.clock.now(),
                environment: in_process_environment(self.fidelity).map_err(internal)?,
                commands: Vec::new(),
                warnings: Vec::new(),
                baseline: not_compared(),
                outcome: if findings.is_empty() {
                    Outcome::Passed
                } else {
                    Outcome::Failed(failures(findings)?)
                },
            },
        )
        .map_err(internal)
    }
}
