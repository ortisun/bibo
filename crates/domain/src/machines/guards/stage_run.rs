//! Guards of the StageRun machine (transitions `S01` to `S20`).
//!
//! `G_NO_ACTIVE_ATTEMPT` (`S19`) is in [`attempt`](super::attempt), next to the other guards that
//! read attempts.

use super::{Check, GuardResult, any_of};
use crate::contracts::stage_contract::RetryClass;
use crate::machines::failure::FailureClass;
use crate::machines::limits::{RepairCap, ReworkCap};
use crate::machines::snapshot::{GateReportSnapshot, StageRunSnapshot};
use crate::state::{Guard, JobStatus, StageRunStatus};
use crate::values::Timestamp;
use crate::vocabulary::{GateOutcome, HumanRole, StageKind};

// ---- becoming ready (S01, S02) ------------------------------------------------------------------------

/// What decides whether a stage run can leave `PENDING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamFacts<'a> {
    /// The stage the run executes.
    pub stage: StageKind,
    /// Every stage run of the job, old runs included.
    pub stage_runs: &'a [StageRunSnapshot],
    /// Every artifact hash the stage consumes equals the current version.
    pub consumed_artifact_hashes_current: bool,
    /// The stage contract was resolved and validated against its schema.
    pub stage_contract_resolved_and_valid: bool,
}

/// True when a run of a stage satisfies the stages that require it and the completion of the
/// job (ADR 0010 decision 2): it is `PASSED`, or it is `SKIPPED` because a recorded rule says
/// the stage does not apply. A run in any other status, a superseded one included, does not.
///
/// A skipped run satisfies the dependency and is still not a pass. It produced no artifact and
/// no evidence, so no assurance level comes from it.
#[must_use]
pub const fn satisfies_dependants(status: StageRunStatus) -> bool {
    matches!(status, StageRunStatus::Passed | StageRunStatus::Skipped)
}

/// `G_UPSTREAM_PASSED`.
///
/// Each stage in [`StageKind::requires`] must have a run that is `PASSED`, or `SKIPPED` because
/// a recorded rule says the stage does not apply (see [`satisfies_dependants`]). A superseded
/// run does not count. A skipped stage produced no artifact, so "every consumed artifact hash is
/// current" holds for it as for any stage whose artifacts are all current.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn upstream_passed(facts: &UpstreamFacts<'_>) -> GuardResult {
    let every_required_stage_satisfied = facts.stage.requires().iter().all(|required| {
        facts
            .stage_runs
            .iter()
            .any(|run| run.kind == *required && satisfies_dependants(run.status))
    });
    Check::new(Guard::UpstreamPassed)
        .require(
            every_required_stage_satisfied,
            "a required upstream stage has no passed or skipped run that is still current",
        )
        .require(
            facts.consumed_artifact_hashes_current,
            "a consumed artifact hash is not the current version",
        )
        .require(
            facts.stage_contract_resolved_and_valid,
            "the stage contract did not resolve and validate against its schema",
        )
        .finish()
}

/// What states that a stage does not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApplicableBasis {
    /// A deterministic rule.
    DeterministicRule,
    /// A domain profile.
    DomainProfile,
    /// A policy.
    Policy,
    /// An agent said so. Never sufficient.
    AgentOpinion,
}

/// What decides whether a stage may be skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotApplicableFacts {
    /// What states that the stage does not apply, or `None` if nothing does.
    pub basis: Option<NotApplicableBasis>,
    /// The rule and its inputs are recorded in the ledger.
    pub rule_and_inputs_recorded: bool,
}

/// `G_NOT_APPLICABLE_DECIDED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn not_applicable_decided(facts: &NotApplicableFacts) -> GuardResult {
    let deterministic = matches!(
        facts.basis,
        Some(
            NotApplicableBasis::DeterministicRule
                | NotApplicableBasis::DomainProfile
                | NotApplicableBasis::Policy
        )
    );
    Check::new(Guard::NotApplicableDecided)
        .require(
            deterministic,
            "no rule, profile or policy states that the stage does not apply \
             (an agent's opinion is never sufficient)",
        )
        .require(
            facts.rule_and_inputs_recorded,
            "the rule and its inputs are not recorded in the ledger",
        )
        .finish()
}

// ---- starting and finishing an attempt (S03, S04) -------------------------------------------------------------

/// What decides whether a worker may start a stage run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseGrantFacts {
    /// The lease compare-and-swap succeeded.
    pub lease_compare_and_swap_succeeded: bool,
    /// The job's status.
    pub job_status: JobStatus,
    /// The moment of the request.
    pub now: Timestamp,
    /// The earliest moment the run may start, while a retry back-off is running.
    pub not_before: Option<Timestamp>,
    /// The concurrency quota allows another attempt.
    pub concurrency_quota_allows: bool,
    /// The runtime capability check passed.
    pub runtime_capability_check_passed: bool,
}

/// `G_LEASE_ACQUIRED`. The back-off is over at the not-before moment itself.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn lease_acquired(facts: &LeaseGrantFacts) -> GuardResult {
    let back_off_over = facts
        .not_before
        .is_none_or(|not_before| facts.now >= not_before);
    Check::new(Guard::LeaseAcquired)
        .require(
            facts.lease_compare_and_swap_succeeded,
            "the lease compare-and-swap did not succeed",
        )
        .require(
            facts.job_status == JobStatus::Active,
            "the job is not ACTIVE",
        )
        .require(
            back_off_over,
            "the retry back-off has not ended (not_before is in the future)",
        )
        .require(
            facts.concurrency_quota_allows,
            "the concurrency quota does not allow another attempt",
        )
        .require(
            facts.runtime_capability_check_passed,
            "the runtime capability check did not pass",
        )
        .finish()
}

/// What decides whether an attempt's output is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFacts {
    /// The attempt succeeded.
    pub attempt_succeeded: bool,
    /// The output validates against the stage outputs schema.
    pub output_validates_against_outputs_schema: bool,
    /// The output artifact hash is stored.
    pub output_artifact_hash_stored: bool,
}

/// `G_OUTPUT_SCHEMA_VALID`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn output_schema_valid(facts: &OutputFacts) -> GuardResult {
    Check::new(Guard::OutputSchemaValid)
        .require(facts.attempt_succeeded, "the attempt has not succeeded")
        .require(
            facts.output_validates_against_outputs_schema,
            "the output does not validate against the stage outputs schema",
        )
        .require(
            facts.output_artifact_hash_stored,
            "the output artifact hash is not stored",
        )
        .finish()
}

// ---- an attempt failed (S05, S06, S07) ----------------------------------------------------------------------------

/// What decides whether a failed attempt is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryFacts<'a> {
    /// How the attempt failed.
    pub class: FailureClass,
    /// The failure classes the stage contract lists as worth retrying.
    pub retry_on: &'a [RetryClass],
    /// Attempts used since the last human answer, counting the one that just failed. A human
    /// answer (`S13`) starts a new window, so the count begins again at the answer.
    pub attempts_used: u32,
    /// The most attempts the stage contract allows.
    pub max_attempts: u32,
    /// The budget has room for another attempt.
    pub budget_has_room: bool,
    /// Attempts since the last human answer that failed with `INVALID_OUTPUT`, counting the one
    /// that just failed if it did. A retry after such a failure is a repair, so the retry that
    /// would follow this failure is repair number `invalid_output_failures`.
    pub invalid_output_failures: u32,
    /// The most repairs the policy allows. Never above two.
    pub repair_cap: RepairCap,
}

impl RetryFacts<'_> {
    /// True when the stage contract lists the failure class as worth retrying.
    #[must_use]
    pub fn class_is_retryable(&self) -> bool {
        self.class.is_retryable_under(self.retry_on)
    }

    /// True when the attempt limit has not been reached.
    #[must_use]
    pub const fn attempts_remain(&self) -> bool {
        self.attempts_used < self.max_attempts
    }

    /// True when the repair cap does not stop a retry. Only a retry after an `INVALID_OUTPUT`
    /// failure is a repair, so every other class always has repairs left. The retry that follows
    /// the n-th invalid output of the window is repair number n, and it is allowed while n is at
    /// most the cap.
    #[must_use]
    pub fn repairs_remain(&self) -> bool {
        self.class != FailureClass::InvalidOutput
            || self.invalid_output_failures <= u32::from(self.repair_cap.get())
    }
}

/// `G_RETRY_ALLOWED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn retry_allowed(facts: &RetryFacts<'_>) -> GuardResult {
    Check::new(Guard::RetryAllowed)
        .require(
            facts.class_is_retryable(),
            "the failure class is not retryable under this stage contract",
        )
        .require(
            facts.attempts_remain(),
            "no attempts are left: attempts used since the last human answer has reached max_attempts",
        )
        .require(
            facts.repairs_remain(),
            "no repairs are left: the repair cap after an invalid output is reached",
        )
        .require(
            facts.budget_has_room,
            "the budget has no room for another attempt",
        )
        .finish()
}

/// `G_FAILURE_NONRETRYABLE`.
///
/// This is not the opposite of [`retry_allowed`]. A retryable failure with no attempt, repair or
/// budget left satisfies neither. That case asks a human (`G_ESCALATION_REQUIRED`).
///
/// # Errors
/// Returns the conditions that are not met.
pub fn failure_nonretryable(facts: &RetryFacts<'_>) -> GuardResult {
    // A budget limit asks a human (S07). `BUDGET_EXHAUSTED` has no retry class, so without this
    // clause it would count as "not in retry_on" and fail the stage run.
    Check::new(Guard::FailureNonretryable)
        .require(
            !facts.class_is_retryable(),
            "the failure class is retryable under this stage contract, so a limit asks a human \
             instead of failing the stage run",
        )
        .require(
            facts.class != FailureClass::BudgetExhausted,
            "the failure class is BUDGET_EXHAUSTED, which asks a human instead of failing the stage run",
        )
        .finish()
}

/// What decides whether a running stage run asks a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationFacts {
    /// A budget limit was hit.
    pub budget_limit_hit: bool,
    /// The attempt limit or the repair cap was reached on a failure class the stage contract
    /// lists as retryable (invariant INV-10: exhaustion escalates to a human and does not loop).
    pub attempt_limit_reached: bool,
    /// The agent returned a structured request for a human.
    pub agent_requested_a_human: bool,
    /// The stagnation detector fired.
    pub stagnation_detected: bool,
    /// Policy requires a human decision here.
    pub policy_requires_human_decision: bool,
}

/// `G_ESCALATION_REQUIRED`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn escalation_required(facts: &EscalationFacts) -> GuardResult {
    any_of(
        Guard::EscalationRequired,
        &[
            (facts.budget_limit_hit, "a budget limit was hit"),
            (
                facts.attempt_limit_reached,
                "the attempt limit or the repair cap was reached",
            ),
            (
                facts.agent_requested_a_human,
                "the agent returned a structured request for a human",
            ),
            (facts.stagnation_detected, "the stagnation detector fired"),
            (
                facts.policy_requires_human_decision,
                "policy requires a human decision here",
            ),
        ],
    )
}

// ---- the gate decides (S08 to S12) ------------------------------------------------------------------------------------

/// What decides whether a stage passes its gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatePassFacts<'a> {
    /// The gate decision is PASS and is persisted.
    pub decision_is_pass_and_persisted: bool,
    /// How many acceptance criteria of the stage contract have no ledger entry.
    pub criteria_without_ledger_entry: usize,
    /// The report of every mandatory gate.
    pub mandatory_gate_reports: &'a [GateReportSnapshot],
}

/// `G_GATE_PASS_EVIDENCED`. A gate that did not run is `BLOCKED` and never passes (INV-06).
///
/// # Errors
/// Returns the conditions that are not met.
pub fn gate_pass_evidenced(facts: &GatePassFacts<'_>) -> GuardResult {
    let reports = facts.mandatory_gate_reports;
    let none_blocked = reports.iter().all(|r| r.outcome != GateOutcome::Blocked);
    let each_passed_or_explained = reports.iter().all(|r| match r.outcome {
        GateOutcome::Passed => true,
        GateOutcome::NotApplicable => r.not_applicable_reason_recorded,
        GateOutcome::Failed | GateOutcome::Blocked => false,
    });
    Check::new(Guard::GatePassEvidenced)
        .require(
            facts.decision_is_pass_and_persisted,
            "the gate decision is not a persisted PASS",
        )
        .require(
            facts.criteria_without_ledger_entry == 0,
            "an acceptance criterion has no ledger entry",
        )
        .require(none_blocked, "a mandatory gate report is BLOCKED")
        .require(
            each_passed_or_explained,
            "a mandatory gate report is neither PASSED nor NOT_APPLICABLE with a recorded reason",
        )
        .finish()
}

/// What decides whether a gate sends the work back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReworkFacts {
    /// The review verdict is `CHANGES_REQUIRED`.
    pub verdict_is_changes_required: bool,
    /// A deterministic gate failed.
    pub deterministic_gate_failed: bool,
    /// Rework rounds used on the count this round would be charged to.
    pub rounds_used: u8,
    /// The cap on that count. It cannot be above two.
    pub cap: ReworkCap,
    /// The failing set differs from the previous round. True for the first round.
    pub failing_set_differs_from_previous_round: bool,
    /// Budget remains.
    pub budget_remains: bool,
}

/// `G_REWORK_ALLOWED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn rework_allowed(facts: &ReworkFacts) -> GuardResult {
    Check::new(Guard::ReworkAllowed)
        .require(
            facts.verdict_is_changes_required || facts.deterministic_gate_failed,
            "the verdict is not CHANGES_REQUIRED and no deterministic gate failed",
        )
        .require(
            facts.rounds_used < facts.cap.get(),
            "the rework cap is used up; after the last round a human decides",
        )
        .require(
            facts.failing_set_differs_from_previous_round,
            "the failing set does not differ from the previous round",
        )
        .require(facts.budget_remains, "no budget remains")
        .finish()
}

/// What decides whether a gate hands the stage to a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedsHumanFacts {
    /// The verdict is `NEEDS_HUMAN`.
    pub verdict_is_needs_human: bool,
    /// The rework limit was reached.
    pub rework_limit_reached: bool,
    /// The stagnation detector fired.
    pub stagnation_detected: bool,
    /// A budget limit was reached.
    pub budget_limit_reached: bool,
    /// The gate itself is a human gate.
    pub gate_is_a_human_gate: bool,
}

/// `G_NEEDS_HUMAN_VERDICT`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn needs_human_verdict(facts: &NeedsHumanFacts) -> GuardResult {
    any_of(
        Guard::NeedsHumanVerdict,
        &[
            (facts.verdict_is_needs_human, "the verdict is NEEDS_HUMAN"),
            (facts.rework_limit_reached, "the rework limit was reached"),
            (facts.stagnation_detected, "the stagnation detector fired"),
            (facts.budget_limit_reached, "a budget limit was reached"),
            (
                facts.gate_is_a_human_gate,
                "the gate itself is a human gate",
            ),
        ],
    )
}

/// What decides whether a gate blocks the stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingFacts {
    /// The verdict is `BLOCK`.
    pub verdict_is_block: bool,
    /// A mandatory gate could not run (a tool was unavailable or a probe failed).
    pub mandatory_gate_could_not_run: bool,
    /// A policy violation was detected.
    pub policy_violation_detected: bool,
}

/// `G_BLOCKING_CONDITION`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn blocking_condition(facts: &BlockingFacts) -> GuardResult {
    any_of(
        Guard::BlockingCondition,
        &[
            (facts.verdict_is_block, "the verdict is BLOCK"),
            (
                facts.mandatory_gate_could_not_run,
                "a mandatory gate could not run",
            ),
            (
                facts.policy_violation_detected,
                "a policy violation was detected",
            ),
        ],
    )
}

/// What decides whether a failed gate has nowhere to send the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoReworkFacts {
    /// The gate failed.
    pub gate_failed: bool,
    /// A rework route exists for this stage and this failure.
    pub a_rework_route_exists: bool,
}

/// `G_GATE_FAILED_NO_REWORK`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn gate_failed_no_rework(facts: &NoReworkFacts) -> GuardResult {
    Check::new(Guard::GateFailedNoRework)
        .require(facts.gate_failed, "the gate has not failed")
        .require(
            !facts.a_rework_route_exists,
            "the stage has a rework route for this failure",
        )
        .finish()
}

// ---- humans (S13 to S18) ----------------------------------------------------------------------------------------------

/// What decides whether a human answer unblocks a waiting stage run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerFacts {
    /// The answer is recorded with the principal who gave it.
    pub answer_recorded_with_principal: bool,
    /// The answer became a new input hash for the stage.
    pub answer_became_a_new_input_hash: bool,
    /// The answer raises a budget ceiling (`raise_budget_ceiling` in the approval policy).
    pub raises_a_ceiling: bool,
    /// The principal who gave the answer holds the `org_admin` role.
    pub principal_is_org_admin: bool,
}

/// `G_ANSWER_RECORDED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn answer_recorded(facts: &AnswerFacts) -> GuardResult {
    Check::new(Guard::AnswerRecorded)
        .require(
            facts.answer_recorded_with_principal,
            "the answer is not recorded with the principal who gave it",
        )
        .require(
            facts.answer_became_a_new_input_hash,
            "the answer did not become a new input hash for the stage",
        )
        .require(
            !facts.raises_a_ceiling || facts.principal_is_org_admin,
            "an answer that raises a ceiling is accepted only from an org_admin",
        )
        .finish()
}

/// What decides whether a human approval passes the stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalFacts {
    /// The decision is approve.
    pub decision_is_approve: bool,
    /// The principal holds the role the approval policy requires for this stage and risk tier.
    pub principal_holds_required_role: bool,
    /// The evidence digest the human saw equals the current evidence digest.
    pub evidence_digest_seen_equals_current: bool,
}

/// `G_APPROVER_AUTHORIZED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn approver_authorized(facts: &ApprovalFacts) -> GuardResult {
    Check::new(Guard::ApproverAuthorized)
        .require(facts.decision_is_approve, "the decision is not approve")
        .require(
            facts.principal_holds_required_role,
            "the principal does not hold the role the approval policy requires",
        )
        .require(
            facts.evidence_digest_seen_equals_current,
            "the evidence digest the human saw is not the current digest",
        )
        .finish()
}

/// What decides whether a human may send a stage back for rework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanReworkFacts<'a> {
    /// The roles the principal holds.
    pub principal_roles: &'a [HumanRole],
    /// Rework rounds used on the count this round would be charged to.
    pub rounds_used: u8,
    /// The cap on that count. It cannot be above two.
    pub cap: ReworkCap,
}

/// `G_HUMAN_REWORK_ALLOWED`. The stagnation detector does not apply to a human's request.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn human_rework_allowed(facts: &HumanReworkFacts<'_>) -> GuardResult {
    let holds_role = facts.principal_roles.contains(&HumanRole::Approver)
        || facts.principal_roles.contains(&HumanRole::Operator);
    Check::new(Guard::HumanReworkAllowed)
        .require(
            holds_role,
            "the principal holds neither the approver nor the operator role",
        )
        .require(
            facts.rounds_used < facts.cap.get(),
            "the rework cap is used up; a human must choose to continue and record the decision",
        )
        .finish()
}

/// What decides whether a human rejection fails the stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanRejectFacts {
    /// The person is an authorized approver.
    pub decider_is_authorized_approver: bool,
    /// A reject decision is recorded.
    pub reject_decision_recorded: bool,
    /// The reason is recorded.
    pub reason_recorded: bool,
}

/// `G_HUMAN_REJECTED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn human_rejected(facts: &HumanRejectFacts) -> GuardResult {
    Check::new(Guard::HumanRejected)
        .require(
            facts.decider_is_authorized_approver,
            "the person who rejected is not an authorized approver",
        )
        .require(
            facts.reject_decision_recorded,
            "no reject decision is recorded",
        )
        .require(facts.reason_recorded, "no reason is recorded")
        .finish()
}

/// What decides whether a blocked stage can run again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnblockFacts {
    /// The capability re-probe passed.
    pub capability_reprobe_passed: bool,
    /// The missing dependency is now available.
    pub missing_dependency_now_available: bool,
}

/// `G_BLOCK_CLEARED_RERUN`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn block_cleared_rerun(facts: &UnblockFacts) -> GuardResult {
    any_of(
        Guard::BlockClearedRerun,
        &[
            (
                facts.capability_reprobe_passed,
                "the capability re-probe passed",
            ),
            (
                facts.missing_dependency_now_available,
                "the missing dependency is now available",
            ),
        ],
    )
}

/// What decides whether a blocked stage may be passed by override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideFacts<'a> {
    /// Policy permits an override for this block code.
    pub policy_permits_override_for_block_code: bool,
    /// The block is a security-class block.
    pub block_is_security_class: bool,
    /// The roles the principal holds.
    pub principal_roles: &'a [HumanRole],
    /// The role policy requires for this override.
    pub role_required_by_policy: HumanRole,
    /// A justification is recorded.
    pub justification_recorded: bool,
    /// The blocked gate is a mandatory gate of an active domain profile.
    pub blocked_gate_is_mandatory_of_active_profile: bool,
}

/// `G_OVERRIDE_PERMITTED`. An override never applies to a mandatory gate of an active domain
/// profile (INV-07), and it records accepted risk: it never creates an assurance level.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn override_permitted(facts: &OverrideFacts<'_>) -> GuardResult {
    let holds_required_role = facts
        .principal_roles
        .contains(&facts.role_required_by_policy);
    let security_rule_met = !facts.block_is_security_class
        || facts.principal_roles.contains(&HumanRole::SecurityApprover);
    Check::new(Guard::OverridePermitted)
        .require(
            facts.policy_permits_override_for_block_code,
            "policy does not permit an override for this block code",
        )
        .require(
            holds_required_role,
            "the principal does not hold the required role",
        )
        .require(
            security_rule_met,
            "a security-class block needs a security approver",
        )
        .require(facts.justification_recorded, "no justification is recorded")
        .require(
            !facts.blocked_gate_is_mandatory_of_active_profile,
            "the blocked gate is a mandatory gate of an active domain profile",
        )
        .finish()
}

// ---- supersession (S20) ----------------------------------------------------------------------------------------------------

/// What decides whether a stage run is superseded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersedeFacts {
    /// A consumed upstream artifact was superseded by a newer version.
    pub consumed_artifact_superseded_by_newer_version: bool,
    /// An upstream stage run was reworked.
    pub upstream_stage_run_was_reworked: bool,
}

/// `G_UPSTREAM_INVALIDATED`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn upstream_invalidated(facts: &SupersedeFacts) -> GuardResult {
    any_of(
        Guard::UpstreamInvalidated,
        &[
            (
                facts.consumed_artifact_superseded_by_newer_version,
                "a consumed upstream artifact was superseded by a newer version",
            ),
            (
                facts.upstream_stage_run_was_reworked,
                "an upstream stage run was reworked",
            ),
        ],
    )
}
