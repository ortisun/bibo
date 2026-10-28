//! The gate: the findings of [`check`](super::check) as a gate report.
//!
//! The mapping follows policy sections 9.2, 9.3 and 9.6:
//!
//! | The gate found | Outcome |
//! |---|---|
//! | Nothing, or warnings only | `PASSED`, with the warnings in `warnings` and an empty `failures` |
//! | At least one blocking finding | `FAILED`, with the blocking findings in `failures` and the warnings in `warnings` |
//! | It could not run: the rule catalog did not load, or the text is over the size limit | `BLOCKED` |
//! | The stage requires the advisory review, which this gate does not run | `BLOCKED`, `tool_unavailable` |
//! | No artifact was handed over | `NOT_APPLICABLE`, with a recorded reason |
//!
//! A rule never produces `BLOCKED`. The reviewer rules of the catalog (the six that a model
//! judges) are not run here. When the stage contract makes the review optional, the reason of the
//! report says that the advisory review did not run. The report never claims a reviewer pass.
//!
//! The function is pure: the identifiers, the mode and the two timestamps come in with
//! [`ReportContext`], taken by the caller from the ports (`Clock`, `IdGenerator`), and the text is
//! only borrowed.

use std::sync::Arc;

use factory_domain::contracts::gate_report::{
    BaselineComparison, BaselineDelta, BlockedCode, BlockedReason, DefinitionSource, Failure,
    FailureLocation, GateEnvironment, GateMetadata, GateWarning, NotApplicableCode,
    NotApplicableDecider, NotApplicableReason, ToolVersion, TrustedDefinition,
};
use factory_domain::contracts::{Contract, GateReport, SchemaVersion};
use factory_domain::ids::{AttemptId, GateReportId, JobId, StageRunId};
use factory_domain::values::{
    GitSha, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, PositiveInt, SemanticVersion,
    Sha256Digest, Slug, Timestamp,
};
use factory_domain::vocabulary::{ExecutionMode, Fidelity, GateOutcome};

use super::artifact::Artifact;
use super::catalog::{Catalog, CatalogError, RULES_JSON, Severity};
use super::engine::{CheckError, MAX_TOTAL_BYTES, check};
use super::finding::Finding;
use super::options::Options;
use crate::gates::framework::GateDecision;

/// The identifier of the gate in a gate report and in a stage contract.
pub const GATE_ID: &str = "readability-gate";
/// The version of the gate. It changes when a rule or a list changes.
pub const GATE_VERSION: &str = "1.0.0";
/// The name under which the rules are listed in the tool versions of the report.
pub const TOOL_NAME: &str = "factory-readability-rules";

/// Whether the stage contract requires the independent language-quality reviewer.
///
/// This gate does not run the reviewer. `Required` means the stage needs that review and this
/// function cannot provide it, so the report is `BLOCKED` with `tool_unavailable` (policy 9.6).
/// A stage that runs the reviewer as a separate step of its evaluator hands its verdict to the
/// engine in the review slot of the gate decision, and passes `Optional` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewerPolicy {
    /// The advisory review is optional. The report says that it did not run.
    Optional,
    /// The advisory review is required and cannot run here.
    Required,
}

/// What the caller supplies for the report. None of it is read from the environment.
#[derive(Debug, Clone)]
pub struct ReportContext {
    /// The identifier of the new report, from the `IdGenerator` port.
    pub gate_report_id: GateReportId,
    /// The job.
    pub job_id: JobId,
    /// The stage run that is being judged.
    pub stage_run_id: StageRunId,
    /// The attempt that is being judged.
    pub attempt_id: Option<AttemptId>,
    /// Test mode allows fakes. Production mode does not. The gate itself is always real.
    pub execution_mode: ExecutionMode,
    /// Where the definition of the gate came from.
    pub definition_source: DefinitionSource,
    /// The commit of that definition.
    pub definition_commit: GitSha,
    /// When the gate started, from the `Clock` port.
    pub started_at: Timestamp,
    /// When the gate finished, from the `Clock` port.
    pub finished_at: Timestamp,
    /// Whether the advisory review is required.
    pub reviewer: ReviewerPolicy,
}

/// A report that could not be built. A text the gate wrote is within the limits of the schema, so
/// this does not happen for any input; the error exists so that the function never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// A value of the report is outside what its type allows.
    #[error("a value of the readability report is outside the limits of the gate report schema")]
    Value,
    /// The finished report breaks a rule of the gate report contract.
    #[error("the readability report breaks a rule of the gate report contract")]
    Contract,
}

impl From<factory_domain::error::ValueError> for ReportError {
    fn from(_: factory_domain::error::ValueError) -> Self {
        Self::Value
    }
}

/// The readability gate: a loaded catalog, the options of one repository, and the function that
/// turns text into a gate report.
#[derive(Debug, Clone)]
pub struct ReadabilityGate {
    catalog: Result<Arc<Catalog>, CatalogError>,
    options: Options,
}

impl ReadabilityGate {
    /// A gate with the embedded catalog. If that catalog does not load, the gate still exists
    /// and reports `BLOCKED` when it runs.
    #[must_use]
    pub fn new(options: Options) -> Self {
        Self {
            catalog: Catalog::embedded(),
            options,
        }
    }

    /// A gate with a catalog read from this text, for the tests of the blocked path.
    #[must_use]
    pub fn with_catalog_text(rules_json: &str, options: Options) -> Self {
        Self {
            catalog: Catalog::parse(rules_json).map(Arc::new),
            options,
        }
    }

    /// The findings, for a caller that wants more than the report.
    ///
    /// # Errors
    /// [`GateError`] when the catalog did not load or the text is over the size limit.
    pub fn findings(&self, artifacts: &[Artifact<'_>]) -> Result<Vec<Finding>, GateError> {
        let catalog = self
            .catalog
            .as_ref()
            .map_err(|e| GateError::Catalog(e.clone()))?;
        check(catalog, &self.options, artifacts).map_err(GateError::Check)
    }

    /// Checks the artifacts and returns the gate report.
    ///
    /// # Errors
    /// [`ReportError`] only if the report cannot be built, which no input causes.
    pub fn evaluate(
        &self,
        artifacts: &[Artifact<'_>],
        ctx: &ReportContext,
    ) -> Result<GateReport, ReportError> {
        let report = self.build(artifacts, ctx)?;
        report.validate().map_err(|_| ReportError::Contract)?;
        Ok(report)
    }

    /// The report wrapped as the evidence a stage handler hands to the engine: one report, no
    /// verdict, nothing that says "passed".
    ///
    /// # Errors
    /// The same as [`evaluate`](Self::evaluate).
    pub fn decide(
        &self,
        artifacts: &[Artifact<'_>],
        ctx: &ReportContext,
    ) -> Result<GateDecision, ReportError> {
        Ok(GateDecision {
            reports: vec![self.evaluate(artifacts, ctx)?],
            ..GateDecision::default()
        })
    }

    fn build(
        &self,
        artifacts: &[Artifact<'_>],
        ctx: &ReportContext,
    ) -> Result<GateReport, ReportError> {
        let catalog = match &self.catalog {
            Ok(catalog) => catalog,
            Err(error) => {
                return blocked(
                    ctx,
                    BlockedCode::PolicyUnresolvable,
                    "readability rule catalog",
                    &format!(
                        "The readability rules could not be loaded ({error}), so no text was checked."
                    ),
                );
            }
        };
        if artifacts.is_empty() {
            return not_applicable(ctx);
        }
        let findings = match check(catalog, &self.options, artifacts) {
            Ok(findings) => findings,
            Err(CheckError::TooLarge { bytes }) => {
                return blocked(
                    ctx,
                    BlockedCode::EnvironmentUnsupported,
                    "artifact text within the size limit of the readability gate",
                    &format!(
                        "The artifacts hold {bytes} bytes of text, more than the {MAX_TOTAL_BYTES} bytes the gate reads in one run, so no text was checked."
                    ),
                );
            }
        };
        if ctx.reviewer == ReviewerPolicy::Required {
            return blocked(
                ctx,
                BlockedCode::ToolUnavailable,
                "independent language-quality reviewer",
                &format!(
                    "The stage requires the independent language-quality reviewer, which this gate does not run. The deterministic rules found {} finding(s) that block and {} that only warn.",
                    count(&findings, Severity::Block),
                    count(&findings, Severity::Warn)
                ),
            );
        }
        ran(ctx, &findings, artifacts.len())
    }
}

/// Why [`ReadabilityGate::findings`] has no findings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// The rule catalog did not load.
    #[error(transparent)]
    Catalog(CatalogError),
    /// The text could not be checked.
    #[error(transparent)]
    Check(CheckError),
}

fn count(findings: &[Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// "1 rule that blocks" or "3 rules that block".
fn rules_that(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 rule that {one}")
    } else {
        format!("{count} rules that {many}")
    }
}

/// The canonical text that the evidence hash covers: one line for each finding, in the order of
/// the report, with the fields separated by the unit separator control character.
fn evidence_hash(lines: &[String]) -> Sha256Digest {
    let mut text = String::from("factory-readability-evidence-v1\n");
    for line in lines {
        text.push_str(line);
        text.push('\n');
    }
    Sha256Digest::of(text.as_bytes())
}

fn location(finding: &Finding) -> Result<FailureLocation, ReportError> {
    Ok(FailureLocation {
        path: finding.location_path(),
        line: finding
            .line
            .map(|line| PositiveInt::new(i64::from(line)))
            .transpose()?,
    })
}

fn metadata(ctx: &ReportContext) -> Result<GateMetadata, ReportError> {
    Ok(GateMetadata {
        gate_report_id: ctx.gate_report_id,
        gate_id: Slug::parse(GATE_ID)?,
        gate_version: SemanticVersion::parse(GATE_VERSION)?,
        job_id: ctx.job_id,
        stage_run_id: ctx.stage_run_id,
        attempt_id: ctx.attempt_id,
        execution_mode: ctx.execution_mode,
        trusted_definition: TrustedDefinition {
            source: ctx.definition_source,
            commit_sha: ctx.definition_commit.clone(),
            definition_sha256: Sha256Digest::of(RULES_JSON.as_bytes()),
        },
    })
}

fn environment() -> Result<GateEnvironment, ReportError> {
    Ok(GateEnvironment {
        fidelity: Fidelity::Real,
        executor_kind: factory_domain::contracts::gate_report::ExecutorKind::InProcess,
        sandbox: None,
        tool_versions: vec![ToolVersion {
            tool: NonEmptyString::parse(TOOL_NAME)?,
            version: NonEmptyString::parse(GATE_VERSION)?,
        }],
    })
}

/// A report with the fields that do not depend on the outcome. The caller fills in the rest.
fn skeleton(
    ctx: &ReportContext,
    outcome: GateOutcome,
    title: &str,
    reason: &str,
    hash: Sha256Digest,
) -> Result<GateReport, ReportError> {
    Ok(GateReport {
        schema_version: SchemaVersion,
        metadata: metadata(ctx)?,
        title: HumanTitle::parse(title)?,
        outcome,
        reason: HumanText::parse(reason)?,
        started_at: ctx.started_at,
        finished_at: ctx.finished_at,
        environment: environment()?,
        commands: Vec::new(),
        failures: None,
        warnings: None,
        blocked_reason: None,
        not_applicable_reason: None,
        evidence_hash: hash,
        baseline_comparison: BaselineComparison {
            baseline_commit_sha: None,
            delta: BaselineDelta::NotCompared,
            notes: None,
        },
    })
}

fn blocked(
    ctx: &ReportContext,
    code: BlockedCode,
    missing: &str,
    reason: &str,
) -> Result<GateReport, ReportError> {
    let mut report = skeleton(
        ctx,
        GateOutcome::Blocked,
        "The readability gate could not run",
        reason,
        evidence_hash(&[format!("blocked\u{1f}{}\u{1f}{missing}", code.as_str())]),
    )?;
    report.blocked_reason = Some(BlockedReason {
        code,
        missing: NonEmptyVec::new(vec![NonEmptyString::parse(missing)?])?,
    });
    Ok(report)
}

fn not_applicable(ctx: &ReportContext) -> Result<GateReport, ReportError> {
    let justification =
        "No artifact text was handed to the readability gate, so there was nothing to check.";
    let mut report = skeleton(
        ctx,
        GateOutcome::NotApplicable,
        "There was no text for the readability gate to check",
        justification,
        evidence_hash(&["not-applicable".to_owned()]),
    )?;
    report.not_applicable_reason = Some(NotApplicableReason {
        code: NotApplicableCode::NoMatchingFiles,
        justification: HumanText::parse(justification)?,
        decided_by: NotApplicableDecider::DeterministicRule,
    });
    Ok(report)
}

/// The report of a run that checked the text: `PASSED` with warnings, or `FAILED`.
fn ran(
    ctx: &ReportContext,
    findings: &[Finding],
    checked: usize,
) -> Result<GateReport, ReportError> {
    let mut failures = Vec::new();
    let mut warnings = Vec::new();
    let mut canonical = Vec::new();
    for finding in findings {
        canonical.push(format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            finding.severity.as_str(),
            finding.rule.as_str(),
            finding.location_path(),
            finding.line.unwrap_or(0),
            finding.message
        ));
        let check_id = Slug::parse(finding.rule.as_str())?;
        match finding.severity {
            Severity::Block => failures.push(Failure {
                check_id,
                message: HumanText::parse(&format!(
                    "{} Suggested fix: {}",
                    finding.message, finding.suggested_fix
                ))?,
                location: Some(location(finding)?),
            }),
            Severity::Warn => warnings.push(GateWarning {
                check_id,
                message: HumanText::parse(&finding.message)?,
                suggested_fix: HumanText::parse(&finding.suggested_fix)?,
                location: Some(location(finding)?),
            }),
        }
    }
    let advisory = match ctx.reviewer {
        ReviewerPolicy::Optional => {
            " The advisory language review by a model did not run in this gate, so only the deterministic rules were checked."
        }
        ReviewerPolicy::Required => "",
    };
    let (outcome, title, reason) = if failures.is_empty() {
        let title = if warnings.is_empty() {
            "The text meets the readability rules".to_owned()
        } else {
            format!(
                "The text reads clearly, with {}",
                plural(warnings.len(), "suggestion", "suggestions")
            )
        };
        let reason = if warnings.is_empty() {
            format!(
                "The deterministic rules found nothing to fix in {}.{advisory}",
                plural(checked, "artifact", "artifacts")
            )
        } else {
            format!(
                "No rule that blocks was broken, so the gate passes. {} found something to improve.{advisory}",
                rules_that(warnings.len(), "only warns", "only warn")
            )
        };
        (GateOutcome::Passed, title, reason)
    } else {
        let were = if failures.len() == 1 { "was" } else { "were" };
        let also = if warnings.is_empty() {
            String::new()
        } else {
            format!(
                " {} also found something to improve.",
                rules_that(warnings.len(), "only warns", "only warn")
            )
        };
        (
            GateOutcome::Failed,
            format!(
                "The text breaks {}",
                plural(failures.len(), "readability rule", "readability rules")
            ),
            format!(
                "{} {were} broken, so the text must be corrected before the stage can advance.{also}{advisory}",
                rules_that(failures.len(), "blocks", "block")
            ),
        )
    };
    let mut report = skeleton(ctx, outcome, &title, &reason, evidence_hash(&canonical))?;
    report.failures = Some(failures);
    report.warnings = Some(warnings);
    Ok(report)
}
