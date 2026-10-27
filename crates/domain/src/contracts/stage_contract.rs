//! `schemas/stage-contract.schema.json`: the resolved contract for one stage run.
//!
//! A stage cannot claim success because an agent says so. The evaluator named in the contract
//! must verify evidence and persist its decision.

use serde::{Deserialize, Serialize};

use super::common::{ArtifactRef, NetworkMode, SchemaRef, SchemaVersion, ShellMode, VersionedRef};
use super::{Violations, contract};
use crate::ids::{AttemptId, JobId, LedgerEntryId, StageRunId};
use crate::macros::string_enum;
use crate::values::{
    Bounded, GitSha, HumanText, HumanTitle, MediaType, NonEmptyString, NonEmptyVec, NonNegativeInt,
    NonNegativeNumber, PositiveInt, SemanticVersion, Slug, Timestamp, UniqueVec,
};
use crate::vocabulary::{ConfidenceLevel, ExecutionMode, RiskTier, StageKind};

string_enum! {
    /// Where an input came from.
    pub enum InputSource("input source") {
        /// Text from outside the factory, such as an issue.
        UntrustedExternal = "untrusted_external",
        /// A file in the target repository.
        Repository = "repository",
        /// The output of an earlier stage.
        PreviousStage = "previous_stage",
        /// A person's answer.
        Human = "human",
        /// A policy file.
        Policy = "policy",
    }
}

string_enum! {
    /// How far an input is trusted. Untrusted inputs are data, never instructions.
    pub enum Trust("trust level") {
        /// Data only.
        Untrusted = "untrusted",
        /// Produced inside the factory.
        TrustedInternal = "trusted_internal",
    }
}

string_enum! {
    /// How a precondition is checked.
    pub enum PreconditionCheck("precondition check") {
        /// An artifact exists.
        ArtifactPresent = "artifact_present",
        /// An upstream stage passed.
        UpstreamStagePassed = "upstream_stage_passed",
        /// Policy allows it.
        PolicyAllows = "policy_allows",
        /// A tool is available.
        ToolAvailable = "tool_available",
        /// A human approval is on record.
        HumanApprovalRecorded = "human_approval_recorded",
    }
}

string_enum! {
    /// Where the agent runtime runs the agent for this stage.
    pub enum Placement("placement") {
        /// Inside the hardened sandbox container.
        Sandbox = "sandbox",
        /// On the host with its own tools disabled, acting through factory tools.
        HostToolBridge = "host_tool_bridge",
        /// The stage runs no agent.
        NotApplicable = "not_applicable",
    }
}

string_enum! {
    /// How a criterion is verified.
    pub enum VerificationKind("verification kind") {
        /// A schema check.
        SchemaValidation = "schema_validation",
        /// A deterministic gate.
        Gate = "gate",
        /// A test.
        Test = "test",
        /// An independent review.
        Review = "review",
        /// A person's decision.
        HumanDecision = "human_decision",
    }
}

string_enum! {
    /// Who judges whether the stage succeeded.
    pub enum EvaluatorKind("evaluator kind") {
        /// Deterministic gates only.
        DeterministicGate = "deterministic_gate",
        /// An independent reviewer only.
        IndependentReviewer = "independent_reviewer",
        /// A person.
        Human = "human",
        /// Gates and a reviewer.
        GateAndReviewer = "gate_and_reviewer",
    }
}

string_enum! {
    /// What a reviewer must never be shown.
    pub enum HiddenInput("hidden reviewer input") {
        /// The builder's own account of its work.
        BuilderSelfAssessment = "builder_self_assessment",
        /// The builder's transcript.
        BuilderTranscript = "builder_transcript",
    }
}

string_enum! {
    /// How far an assumption has been dealt with.
    pub enum AssumptionStatus("assumption status") {
        /// Not examined.
        Open = "open",
        /// Limited, not resolved.
        Bounded = "bounded",
        /// Settled.
        Resolved = "resolved",
    }
}

string_enum! {
    /// How much randomness is added to a retry delay.
    pub enum Jitter("jitter") {
        /// None.
        None = "none",
        /// Half fixed, half random.
        Equal = "equal",
        /// Fully random.
        Full = "full",
    }
}

string_enum! {
    /// A failure class worth retrying. Budget exhaustion and policy denial are never retried.
    pub enum RetryClass("retry class") {
        /// A tool failed.
        ToolError = "TOOL_ERROR",
        /// The output did not match its schema.
        InvalidOutput = "INVALID_OUTPUT",
        /// The model provider failed.
        ProviderError = "PROVIDER_ERROR",
        /// The sandbox failed.
        SandboxError = "SANDBOX_ERROR",
        /// The attempt ran out of time.
        TimedOut = "TIMED_OUT",
        /// The lease expired.
        LeaseLost = "LEASE_LOST",
    }
}

string_enum! {
    /// What side effects a stage has.
    pub enum SideEffects("side effects") {
        /// None.
        None = "none",
        /// Only in the local workspace.
        LocalWorkspace = "local_workspace",
        /// On a system outside the sandbox.
        ExternalWrite = "external_write",
    }
}

string_enum! {
    /// Who a stage escalates to.
    pub enum EscalationTarget("escalation target") {
        /// An operator.
        Operator = "operator",
        /// An approver.
        Approver = "approver",
        /// A security approver.
        SecurityApprover = "security_approver",
        /// An organization administrator.
        OrgAdmin = "org_admin",
    }
}

string_enum! {
    /// What makes a stage escalate.
    pub enum EscalationTrigger("escalation trigger") {
        /// A budget limit was hit.
        BudgetExceeded = "budget_exceeded",
        /// The rework cap was reached.
        ReworkLimitReached = "rework_limit_reached",
        /// The stagnation detector fired.
        StagnationDetected = "stagnation_detected",
        /// A mandatory gate could not run.
        Blocked = "blocked",
        /// A reviewer asked for a human.
        NeedsHumanVerdict = "needs_human_verdict",
        /// A policy rule was broken.
        PolicyViolation = "policy_violation",
    }
}

/// A domain profile in force for the job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRef {
    /// The profile.
    pub id: Slug,
    /// Its version.
    pub version: PositiveInt,
}

/// Ids and timing. Run and attempt identifiers are metadata, never part of the title.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageMetadata {
    /// The stage definition this contract was resolved from.
    pub contract_id: Slug,
    /// Its version.
    pub contract_version: SemanticVersion,
    /// Which stage.
    pub stage_kind: StageKind,
    /// The job.
    pub job_id: JobId,
    /// The stage run.
    pub stage_run_id: StageRunId,
    /// The attempt, when one exists yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<AttemptId>,
    /// Production or test.
    pub execution_mode: ExecutionMode,
    /// When the contract was resolved.
    pub created_at: Timestamp,
    /// The domain profiles in force.
    pub domain_profiles: Vec<ProfileRef>,
}

/// Where an input came from and when it was read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The origin.
    pub source: InputSource,
    /// The stage run that produced it, for a previous stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced_by_stage_run_id: Option<StageRunId>,
    /// The commit, for repository content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<GitSha>,
    /// When it was read.
    pub retrieved_at: Timestamp,
}

/// One typed input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageInput {
    /// The input's name.
    pub name: Slug,
    /// What it is.
    pub description: HumanText,
    /// The stored bytes.
    pub artifact: ArtifactRef,
    /// The schema the bytes follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<SchemaRef>,
    /// Where it came from.
    pub provenance: Provenance,
    /// Untrusted inputs are data, never instructions.
    pub trust: Trust,
}

/// A condition that must hold before the stage starts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Precondition {
    /// The precondition.
    pub id: Slug,
    /// What must hold.
    pub description: HumanText,
    /// How it is checked.
    pub check: PreconditionCheck,
}

/// How risky the stage is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    /// The tier.
    pub tier: RiskTier,
    /// Why.
    pub rationale: HumanText,
    /// The domains it touches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<Slug>>,
}

/// A method that was considered and not chosen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    /// The alternative.
    pub name: HumanTitle,
    /// Why it was not chosen.
    pub why_not: HumanText,
}

/// The method the stage uses, with the alternatives it rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Method {
    /// The method.
    pub name: HumanTitle,
    /// Why it was chosen.
    pub rationale: HumanText,
    /// What else was considered. Never empty: a method with no alternative was not chosen.
    pub alternatives_considered: NonEmptyVec<Alternative>,
    /// The measurable condition under which a more complex method is justified.
    pub escalation_trigger: HumanText,
}

/// What the stage may touch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    /// Path globs the stage may read.
    pub filesystem_read: Vec<NonEmptyString>,
    /// Path globs the stage may write.
    pub filesystem_write: Vec<NonEmptyString>,
    /// Network access.
    pub network: NetworkMode,
    /// Hosts, when the network is an allow list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_allowlist: Option<Vec<NonEmptyString>>,
    /// Command execution.
    pub shell: ShellMode,
}

/// Least-privilege capabilities granted to the run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// The agent manifest in force.
    pub agent_manifest: VersionedRef,
    /// The tools the policy engine granted. A subset of the manifest's allowed tools.
    pub granted_tools: UniqueVec<Slug>,
    /// File, network and command permissions.
    pub permissions: Permissions,
    /// Where the agent runs. Required for the implementation stage, which must use the sandbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<Placement>,
}

/// A thing the stage must produce.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deliverable {
    /// The deliverable's name.
    pub name: Slug,
    /// What it is.
    pub description: HumanText,
    /// What kind of bytes.
    pub media_type: MediaType,
    /// The schema it must follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<SchemaRef>,
    /// Whether it must exist for the stage to succeed.
    pub required: bool,
}

/// How a criterion is checked and by what.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    /// The kind of check.
    pub kind: VerificationKind,
    /// The gate, test, schema or review that does it.
    #[serde(rename = "ref")]
    pub reference: Slug,
}

/// One acceptance criterion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceCriterion {
    /// The criterion.
    pub id: Slug,
    /// What must be true.
    pub description: HumanText,
    /// How it is verified.
    pub verification: Verification,
    /// Whether a machine can decide it.
    pub machine_verifiable: bool,
}

/// Who judges the stage's result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluator {
    /// The kind of evaluator.
    pub kind: EvaluatorKind,
    /// The gates, for the deterministic kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_ids: Option<UniqueVec<Slug>>,
    /// The reviewer, for the review kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_agent: Option<VersionedRef>,
    /// What the reviewer must not be shown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_must_not_see: Option<UniqueVec<HiddenInput>>,
}

/// A ledger entry the stage consumes as evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// The entry.
    pub ledger_entry_id: LedgerEntryId,
}

/// How sure the author of the contract is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageConfidence {
    /// The level.
    pub level: ConfidenceLevel,
    /// Why.
    pub notes: HumanText,
}

/// A stated assumption.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assumption {
    /// The assumption.
    pub id: Slug,
    /// What is assumed.
    pub statement: HumanText,
    /// How far it has been dealt with.
    pub status: AssumptionStatus,
}

/// Compute limits for the run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compute {
    /// CPU in thousandths of a core.
    pub cpu_millicores: NonNegativeInt,
    /// Memory in megabytes.
    pub memory_mb: NonNegativeInt,
    /// Disk in megabytes.
    pub disk_mb: NonNegativeInt,
}

/// What the stage may spend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Wall-clock seconds.
    pub max_wall_time_seconds: PositiveInt,
    /// Model tokens.
    pub max_tokens: NonNegativeInt,
    /// Money in US dollars.
    pub max_cost_usd: NonNegativeNumber,
    /// Compute.
    pub max_compute: Compute,
}

/// How the delay between retries grows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backoff {
    /// First delay in milliseconds.
    pub initial_ms: NonNegativeInt,
    /// Longest delay in milliseconds.
    pub max_ms: NonNegativeInt,
    /// Randomness.
    pub jitter: Jitter,
}

/// Time and retry limits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutAndRetries {
    /// Seconds before an attempt times out.
    pub attempt_timeout_seconds: PositiveInt,
    /// Attempts allowed, 1 to 10.
    pub max_attempts: Bounded<1, 10>,
    /// Retry delay.
    pub backoff: Backoff,
    /// Failure classes worth retrying.
    pub retry_on: UniqueVec<RetryClass>,
    /// Rework rounds allowed, 0 to 10.
    pub max_rework_iterations: Bounded<0, 10>,
}

/// How repeating the stage is made safe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Idempotency {
    /// How the idempotency key is built, for example the stage run id plus the input hashes.
    pub key_scheme: NonEmptyString,
    /// What the stage changes.
    pub side_effects: SideEffects,
    /// How to undo an external write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compensating_action: Option<HumanText>,
}

/// What happens when the stage cannot continue.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    /// How to roll back.
    pub rollback: HumanText,
    /// Who is asked.
    pub escalate_to: EscalationTarget,
    /// What triggers it. Never empty.
    pub on: UniqueVec<EscalationTrigger, 1>,
}

/// Span and metric names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    /// The trace span name.
    pub span_name: Slug,
    /// Span attributes.
    pub attributes: UniqueVec<Slug>,
    /// Metrics.
    pub metrics: UniqueVec<Slug>,
}

/// The resolved, versioned contract for one stage run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, remote = "Self")]
pub struct StageContract {
    /// Always 1.
    pub schema_version: SchemaVersion,
    /// Ids and timing.
    pub metadata: StageMetadata,
    /// A short plain-English title. Machine ids live in the metadata.
    pub title: HumanTitle,
    /// Why the stage exists.
    pub purpose: HumanText,
    /// The problem it solves.
    pub problem_statement: HumanText,
    /// The typed inputs.
    pub inputs: NonEmptyVec<StageInput>,
    /// Conditions before the stage starts.
    pub preconditions: Vec<Precondition>,
    /// The risk tier.
    pub risk: Risk,
    /// The methods chosen and the alternatives rejected.
    pub methods: NonEmptyVec<Method>,
    /// Least-privilege capabilities.
    pub capabilities: Capabilities,
    /// What the stage must produce.
    pub deliverables: NonEmptyVec<Deliverable>,
    /// How success is judged. At least one criterion is machine-verifiable.
    pub acceptance_criteria: NonEmptyVec<AcceptanceCriterion>,
    /// Who judges.
    pub evaluator: Evaluator,
    /// Ledger entries consumed as evidence.
    pub evidence_refs: Vec<EvidenceRef>,
    /// How sure the author is.
    pub confidence: StageConfidence,
    /// Stated assumptions.
    pub assumptions: Vec<Assumption>,
    /// What the stage may spend.
    pub budget: Budget,
    /// Time and retry limits.
    pub timeout_and_retries: TimeoutAndRetries,
    /// Safe repetition.
    pub idempotency: Idempotency,
    /// What happens when the stage cannot continue.
    pub escalation: Escalation,
    /// Span and metric names.
    pub telemetry: Telemetry,
}

impl StageContract {
    fn check(&self, found: &mut Violations) {
        for (index, input) in self.inputs.iter().enumerate() {
            let outside_the_factory = matches!(
                input.provenance.source,
                InputSource::UntrustedExternal | InputSource::Repository | InputSource::Human
            );
            found.require(
                !outside_the_factory || input.trust == Trust::Untrusted,
                format!("inputs[{index}].trust"),
                "content from outside the factory (an external request, the repository or a person) is untrusted data and cannot be marked trusted",
            );
        }

        let permissions = &self.capabilities.permissions;
        if permissions.network == NetworkMode::Allowlist {
            found.require(
                permissions
                    .network_allowlist
                    .as_ref()
                    .is_some_and(|hosts| !hosts.is_empty()),
                "capabilities.permissions.network_allowlist",
                "a network allow list needs at least one host",
            );
        }

        if self.metadata.stage_kind == StageKind::Implementation {
            found.require(
                self.capabilities.placement == Some(Placement::Sandbox),
                "capabilities.placement",
                "the implementation stage must run its agent inside the sandbox",
            );
        }

        found.require(
            self.acceptance_criteria
                .iter()
                .any(|criterion| criterion.machine_verifiable),
            "acceptance_criteria",
            "at least one acceptance criterion must be verifiable by a machine",
        );

        self.check_evaluator(found);

        if self.idempotency.side_effects == SideEffects::ExternalWrite {
            found.require(
                self.idempotency.compensating_action.is_some(),
                "idempotency.compensating_action",
                "a stage that writes to an outside system must say how to undo the write",
            );
        }
    }

    fn check_evaluator(&self, found: &mut Violations) {
        let evaluator = &self.evaluator;
        let uses_gates = matches!(
            evaluator.kind,
            EvaluatorKind::DeterministicGate | EvaluatorKind::GateAndReviewer
        );
        let uses_reviewer = matches!(
            evaluator.kind,
            EvaluatorKind::IndependentReviewer | EvaluatorKind::GateAndReviewer
        );
        if uses_gates {
            found.require(
                evaluator
                    .gate_ids
                    .as_ref()
                    .is_some_and(|ids| !ids.is_empty()),
                "evaluator.gate_ids",
                "an evaluator that uses gates must name at least one gate",
            );
        }
        if uses_reviewer {
            found.require(
                evaluator.reviewer_agent.is_some(),
                "evaluator.reviewer_agent",
                "an evaluator that uses a reviewer must name the reviewer agent",
            );
            found.require(
                evaluator
                    .reviewer_must_not_see
                    .as_ref()
                    .is_some_and(|hidden| hidden.contains(&HiddenInput::BuilderSelfAssessment)),
                "evaluator.reviewer_must_not_see",
                "a reviewer must never see the builder's own account of the work, so the list must include builder_self_assessment",
            );
        }
    }
}

contract!(StageContract, "stage-contract");
