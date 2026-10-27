//! `schemas/gate-report.schema.json`: the machine-readable result of one deterministic gate.
//!
//! A report with outcome `PASSED` must show that every command ran and exited with code 0. A gate
//! that did not run is `BLOCKED`, never `PASSED` (invariant INV-06).

use serde::{Deserialize, Serialize};

use super::common::{ArtifactRef, SchemaVersion, required_nullable};
use super::{Violations, contract};
use crate::ids::{AttemptId, GateReportId, JobId, StageRunId};
use crate::macros::string_enum;
use crate::values::{
    BoundedString, GitSha, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, PositiveInt,
    SemanticVersion, Sha256Digest, Slug, Timestamp,
};
use crate::vocabulary::{ExecutionMode, Fidelity, GateOutcome};

string_enum! {
    /// Where the gate definition came from. Builders cannot edit either place.
    pub enum DefinitionSource("definition source") {
        /// The protected base branch of the target repository.
        ProtectedBaseBranch = "protected_base_branch",
        /// Central configuration.
        CentralConfig = "central_config",
    }
}

string_enum! {
    /// How the gate ran.
    pub enum ExecutorKind("executor kind") {
        /// Commands in a sandbox.
        SandboxCommand = "sandbox_command",
        /// Code inside the control plane.
        InProcess = "in_process",
    }
}

string_enum! {
    /// The sandbox's network.
    pub enum SandboxNetwork("sandbox network") {
        /// None.
        None = "none",
        /// An allow list.
        Allowlist = "allowlist",
    }
}

string_enum! {
    /// Why a gate could not run.
    pub enum BlockedCode("blocked code") {
        /// A tool is missing.
        ToolUnavailable = "tool_unavailable",
        /// A tool probe failed.
        ToolProbeFailed = "tool_probe_failed",
        /// A dependency is missing.
        DependencyUnavailable = "dependency_unavailable",
        /// Policy could not be resolved.
        PolicyUnresolvable = "policy_unresolvable",
        /// The environment is not supported.
        EnvironmentUnsupported = "environment_unsupported",
    }
}

string_enum! {
    /// Why a gate does not apply.
    pub enum NotApplicableCode("not applicable code") {
        /// There is nothing for the gate to check.
        NoMatchingFiles = "no_matching_files",
        /// The domain profile leaves it out.
        ProfileExcludesGate = "profile_excludes_gate",
        /// Policy leaves it out.
        PolicyExcludesGate = "policy_excludes_gate",
        /// The type of change leaves it out.
        ChangeTypeExcludesGate = "change_type_excludes_gate",
    }
}

string_enum! {
    /// Who decided that a gate does not apply. An agent opinion is never a valid decider.
    pub enum NotApplicableDecider("not applicable decider") {
        /// A deterministic rule.
        DeterministicRule = "deterministic_rule",
        /// A domain profile.
        DomainProfile = "domain_profile",
        /// Policy.
        Policy = "policy",
    }
}

string_enum! {
    /// How the result compares with the baseline.
    pub enum BaselineDelta("baseline delta") {
        /// No change.
        None = "none",
        /// Better.
        Improved = "improved",
        /// Worse.
        Regressed = "regressed",
        /// New failures appeared.
        NewFailures = "new_failures",
        /// Not compared.
        NotCompared = "not_compared",
    }
}

/// Where the gate definition came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedDefinition {
    /// The source.
    pub source: DefinitionSource,
    /// The commit.
    pub commit_sha: GitSha,
    /// The hash of the definition.
    pub definition_sha256: Sha256Digest,
}

/// Ids and the trusted definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateMetadata {
    /// This report.
    pub gate_report_id: GateReportId,
    /// The gate.
    pub gate_id: Slug,
    /// The gate's version.
    pub gate_version: SemanticVersion,
    /// The job.
    pub job_id: JobId,
    /// The stage run.
    pub stage_run_id: StageRunId,
    /// The attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<AttemptId>,
    /// Test mode allows fake adapters. Production mode does not.
    pub execution_mode: ExecutionMode,
    /// Where the definition came from.
    pub trusted_definition: TrustedDefinition,
}

/// The sandbox the commands ran in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxInfo {
    /// The sandbox, 1 to 128 characters.
    pub sandbox_id: BoundedString<1, 128>,
    /// The image digest.
    pub image_digest: Sha256Digest,
    /// The operating system.
    pub os: NonEmptyString,
    /// The CPU architecture.
    pub arch: NonEmptyString,
    /// The network.
    pub network: SandboxNetwork,
}

/// One tool and its version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolVersion {
    /// The tool.
    pub tool: NonEmptyString,
    /// Its version.
    pub version: NonEmptyString,
}

/// Where and with what the gate ran.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateEnvironment {
    /// Real or fake. Fake is allowed only in test mode.
    pub fidelity: Fidelity,
    /// How it ran.
    pub executor_kind: ExecutorKind,
    /// The sandbox. Required for sandbox commands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxInfo>,
    /// The tools and their versions.
    pub tool_versions: Vec<ToolVersion>,
}

/// One command the gate ran, or meant to run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateCommand {
    /// The executable and its arguments. Never a shell string.
    pub argv: NonEmptyVec<String>,
    /// The working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Whether the command actually ran.
    pub executed: bool,
    /// The exit code. `null` when the command did not run.
    #[serde(deserialize_with = "required_nullable")]
    pub exit_code: Option<i64>,
    /// The signal that ended it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminated_by_signal: Option<i64>,
    /// Whether it hit its time limit.
    pub timed_out: bool,
    /// When it started.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
    /// Standard output, stored.
    pub stdout: ArtifactRef,
    /// Standard error, stored.
    pub stderr: ArtifactRef,
}

/// Where in a file a failure is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureLocation {
    /// The path.
    pub path: String,
    /// The line, from 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<PositiveInt>,
}

/// One check that failed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    /// The check.
    pub check_id: Slug,
    /// What went wrong, in plain English.
    pub message: HumanText,
    /// Where.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<FailureLocation>,
}

/// Why the gate could not run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedReason {
    /// The category.
    pub code: BlockedCode,
    /// The tools, services or capabilities that were absent.
    pub missing: NonEmptyVec<NonEmptyString>,
}

/// Why the gate does not apply.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotApplicableReason {
    /// The category.
    pub code: NotApplicableCode,
    /// Why, in plain English.
    pub justification: HumanText,
    /// Who decided.
    pub decided_by: NotApplicableDecider,
}

/// The result compared with the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineComparison {
    /// The commit of the baseline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_commit_sha: Option<GitSha>,
    /// How the result compares.
    pub delta: BaselineDelta,
    /// Notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<HumanText>,
}

/// The machine-readable result of one deterministic gate run against one stage run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, remote = "Self")]
pub struct GateReport {
    /// Always 1.
    pub schema_version: SchemaVersion,
    /// Ids and the trusted definition.
    pub metadata: GateMetadata,
    /// A plain-English title.
    pub title: HumanTitle,
    /// The outcome.
    pub outcome: GateOutcome,
    /// Why the outcome is what it is.
    pub reason: HumanText,
    /// When the gate started.
    pub started_at: Timestamp,
    /// When it finished.
    pub finished_at: Timestamp,
    /// Where and with what it ran.
    pub environment: GateEnvironment,
    /// What was run.
    pub commands: Vec<GateCommand>,
    /// Failures, for a `FAILED` outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<Failure>>,
    /// Why it could not run, for a `BLOCKED` outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<BlockedReason>,
    /// Why it does not apply, for a `NOT_APPLICABLE` outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_applicable_reason: Option<NotApplicableReason>,
    /// A hash over the canonical form of commands, logs and failures.
    pub evidence_hash: Sha256Digest,
    /// How the result compares with the baseline.
    pub baseline_comparison: BaselineComparison,
}

impl GateReport {
    fn check(&self, found: &mut Violations) {
        for (index, command) in self.commands.iter().enumerate() {
            if command.executed {
                found.require(
                    command.exit_code.is_some(),
                    format!("commands[{index}].exit_code"),
                    "a command that ran has an exit code",
                );
            } else {
                found.require(
                    command.exit_code.is_none(),
                    format!("commands[{index}].exit_code"),
                    "a command that did not run has no exit code, so this must be null",
                );
            }
        }

        if self.environment.executor_kind == ExecutorKind::SandboxCommand {
            found.require(
                self.environment.sandbox.is_some(),
                "environment.sandbox",
                "a gate that runs commands in a sandbox must describe the sandbox",
            );
        }

        if self.metadata.execution_mode == ExecutionMode::Production {
            found.require(
                self.environment.fidelity == Fidelity::Real,
                "environment.fidelity",
                "a production job cannot use a fake adapter",
            );
        }

        found.require(
            self.blocked_reason.is_none() || self.outcome == GateOutcome::Blocked,
            "blocked_reason",
            "only a BLOCKED report carries a blocked reason",
        );
        found.require(
            self.not_applicable_reason.is_none() || self.outcome == GateOutcome::NotApplicable,
            "not_applicable_reason",
            "only a NOT_APPLICABLE report carries a reason for not applying",
        );

        match self.outcome {
            GateOutcome::Passed => self.check_passed(found),
            GateOutcome::Failed => found.require(
                self.failures.as_ref().is_some_and(|list| !list.is_empty()),
                "failures",
                "a FAILED report must list at least one failure",
            ),
            GateOutcome::Blocked => found.require(
                self.blocked_reason.is_some(),
                "blocked_reason",
                "a BLOCKED report must say what was missing",
            ),
            GateOutcome::NotApplicable => {
                found.require(
                    self.not_applicable_reason.is_some(),
                    "not_applicable_reason",
                    "a NOT_APPLICABLE report must say why the gate does not apply and who decided",
                );
                found.require(
                    self.commands.is_empty(),
                    "commands",
                    "a gate that does not apply runs no commands",
                );
            }
        }
    }

    fn check_passed(&self, found: &mut Violations) {
        for (index, command) in self.commands.iter().enumerate() {
            found.require(
                command.executed,
                format!("commands[{index}].executed"),
                "a PASSED report cannot include a command that never ran",
            );
            found.require(
                command.exit_code == Some(0),
                format!("commands[{index}].exit_code"),
                "a PASSED report needs every command to exit with code 0",
            );
            found.require(
                !command.timed_out,
                format!("commands[{index}].timed_out"),
                "a PASSED report cannot include a command that timed out",
            );
        }
        found.require(
            !self.environment.tool_versions.is_empty(),
            "environment.tool_versions",
            "a PASSED report must record the versions of the tools it used",
        );
        found.require(
            matches!(
                self.baseline_comparison.delta,
                BaselineDelta::None | BaselineDelta::Improved | BaselineDelta::NotCompared
            ),
            "baseline_comparison.delta",
            "a PASSED report cannot show a regression or new failures against the baseline",
        );
        found.require(
            self.failures.as_ref().is_none_or(Vec::is_empty),
            "failures",
            "a PASSED report lists no failures",
        );
        found.require(
            !self.commands.is_empty() || self.environment.executor_kind == ExecutorKind::InProcess,
            "commands",
            "a PASSED report needs at least one command, unless the gate ran in process",
        );
    }
}

contract!(GateReport, "gate-report");
