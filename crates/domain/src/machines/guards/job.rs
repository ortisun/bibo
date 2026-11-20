//! Guards of the Job machine (transitions `J01` to `J13`).

use super::digest::facts;
use super::stage_run::satisfies_dependants;
use super::{Check, GuardResult, any_of};
use crate::machines::snapshot::StageRunSnapshot;
use crate::state::{Guard, StageRunStatus};
use crate::vocabulary::{HumanRole, StageKind};

// ---- admission (J01, J02) ----------------------------------------------------------------------------

facts! {
/// What admission looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionFacts {
    /// The requester is on the tenant's named requester allowlist in protected configuration.
    /// Holding a GitHub role is not enough.
    pub requester_on_allowlist: bool,
    /// The tenant is within its job quota.
    pub tenant_within_job_quota: bool,
    /// The repository is registered and enabled.
    pub repository_registered_and_enabled: bool,
    /// Policy allows this class of request.
    pub policy_allows_request_class: bool,
    /// What the repository has spent and the jobs it has started in the current day are below the
    /// ceilings of `budgets.hard_ceilings.per_repo_day`. False when a reading could not be made.
    pub repository_day_budget_has_room: bool,
    /// What the organization has spent in the current day is below the ceiling of
    /// `budgets.hard_ceilings.per_org_day`. False when the reading could not be made.
    pub organization_day_budget_has_room: bool,
    /// The repository passed the protection preflight. This does not decide admission. If it did
    /// not pass, the job is admitted but may only run at autonomy level L0.
    pub protection_preflight_passed: bool,
}
}

impl AdmissionFacts {
    /// True when the job, if admitted, may run only at autonomy level L0.
    #[must_use]
    pub const fn autonomy_limited_to_l0(&self) -> bool {
        !self.protection_preflight_passed
    }
}

/// What admission says when the repository's day ceiling holds a job back. It names the ceiling
/// by its key in `policies/security.yaml`, because this text goes to the audit record.
pub const REPOSITORY_DAY_CEILING_REACHED: &str = "the repository reached a ceiling of budgets.hard_ceilings.per_repo_day for the day, or its usage could not be read";

/// What admission says when the organization's day ceiling holds a job back.
pub const ORGANIZATION_DAY_CEILING_REACHED: &str = "the organization reached the ceiling of budgets.hard_ceilings.per_org_day for the day, or its spend could not be read";

/// `G_ADMISSION_OK`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn admission_ok(facts: &AdmissionFacts) -> GuardResult {
    Check::new(Guard::AdmissionOk)
        .require(
            facts.requester_on_allowlist,
            "the requester is not on the tenant's requester allowlist",
        )
        .require(
            facts.tenant_within_job_quota,
            "the tenant has used up its job quota",
        )
        .require(
            facts.repository_registered_and_enabled,
            "the repository is not registered and enabled",
        )
        .require(
            facts.policy_allows_request_class,
            "policy does not allow this class of request",
        )
        .require(
            facts.repository_day_budget_has_room,
            REPOSITORY_DAY_CEILING_REACHED,
        )
        .require(
            facts.organization_day_budget_has_room,
            ORGANIZATION_DAY_CEILING_REACHED,
        )
        .finish()
}

/// `G_ADMISSION_DENIED`. Holds exactly when [`admission_ok`] does not.
///
/// The reasons are for the audit record. A reply to the requester must not say which test
/// failed.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn admission_denied(facts: &AdmissionFacts) -> GuardResult {
    any_of(
        Guard::AdmissionDenied,
        &[
            (
                !facts.requester_on_allowlist,
                "the requester is not on the allowlist",
            ),
            (!facts.tenant_within_job_quota, "the quota is exceeded"),
            (
                !facts.repository_registered_and_enabled,
                "the repository is not registered or is disabled",
            ),
            (
                !facts.policy_allows_request_class,
                "policy forbids this class of request",
            ),
            (
                !facts.repository_day_budget_has_room,
                REPOSITORY_DAY_CEILING_REACHED,
            ),
            (
                !facts.organization_day_budget_has_room,
                ORGANIZATION_DAY_CEILING_REACHED,
            ),
        ],
    )
}

// ---- the board of stage runs (J03, J04, J07, J08) -------------------------------------------------------

facts! {
/// The stage runs of one job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageBoardFacts<'a> {
    /// Every stage run of the job, old runs included.
    pub stage_runs: &'a [StageRunSnapshot],
}
}

impl StageBoardFacts<'_> {
    fn any(&self, status: StageRunStatus) -> bool {
        self.stage_runs.iter().any(|run| run.status == status)
    }
}

/// `G_ANY_STAGE_WAITING`.
///
/// # Errors
/// Returns the unmet condition.
pub fn any_stage_waiting(facts: &StageBoardFacts<'_>) -> GuardResult {
    Check::new(Guard::AnyStageWaiting)
        .require(
            facts.any(StageRunStatus::WaitingForHuman),
            "no stage run of the job is waiting for a human",
        )
        .finish()
}

/// `G_NO_STAGE_WAITING`.
///
/// # Errors
/// Returns the unmet condition.
pub fn no_stage_waiting(facts: &StageBoardFacts<'_>) -> GuardResult {
    Check::new(Guard::NoStageWaiting)
        .require(
            !facts.any(StageRunStatus::WaitingForHuman),
            "a stage run of the job is waiting for a human",
        )
        .finish()
}

/// `G_ANY_STAGE_BLOCKED`.
///
/// # Errors
/// Returns the unmet condition.
pub fn any_stage_blocked(facts: &StageBoardFacts<'_>) -> GuardResult {
    Check::new(Guard::AnyStageBlocked)
        .require(
            facts.any(StageRunStatus::Blocked),
            "no stage run of the job is blocked",
        )
        .finish()
}

/// `G_BLOCK_DISPOSITIONS_RECORDED`. A job with no blocked run satisfies it trivially.
///
/// # Errors
/// Returns the unmet condition.
pub fn block_dispositions_recorded(facts: &StageBoardFacts<'_>) -> GuardResult {
    let every_blocked_run_has_one = facts
        .stage_runs
        .iter()
        .filter(|run| run.status == StageRunStatus::Blocked)
        .all(|run| run.block_disposition.is_some());
    Check::new(Guard::BlockDispositionsRecorded)
        .require(
            every_blocked_run_has_one,
            "a blocked stage run has no recorded disposition",
        )
        .finish()
}

// ---- who may act (J05, J06, J09) ------------------------------------------------------------------------

facts! {
/// The principal who asks for a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrincipalFacts<'a> {
    /// The roles the principal holds on the tenant, from protected configuration.
    pub roles: &'a [HumanRole],
    /// The principal is the person who submitted this job.
    pub is_job_requester: bool,
}
}

/// `G_ACTOR_MAY_PAUSE`.
///
/// # Errors
/// Returns the unmet condition.
pub fn actor_may_pause(facts: &PrincipalFacts<'_>) -> GuardResult {
    Check::new(Guard::ActorMayPause)
        .require(
            facts.roles.contains(&HumanRole::Operator),
            "the principal does not hold the operator role",
        )
        .finish()
}

/// `G_ACTOR_MAY_CANCEL`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn actor_may_cancel(facts: &PrincipalFacts<'_>) -> GuardResult {
    any_of(
        Guard::ActorMayCancel,
        &[
            (
                facts.is_job_requester,
                "the principal is the requester of the job",
            ),
            (
                facts.roles.contains(&HumanRole::Operator),
                "the principal holds the operator role",
            ),
        ],
    )
}

// ---- failure and rejection (J11, J12) -----------------------------------------------------------------------

facts! {
/// What decides whether a job can no longer go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnrecoverableFacts {
    /// The newest run of a stage kind in the job's scope is `FAILED` (by `S06`, `S12` or `S16`).
    pub stage_run_failed: bool,
    /// A newer run of the same stage kind exists, so the failed run is already replaced. The
    /// engine builds this from the listing of the job's stage runs. A rework that created the
    /// newer run first leaves the guard unmet.
    pub newer_run_of_kind_exists: bool,
    /// A rework route is still open for the failed work.
    pub rework_route_remains: bool,
    /// Retry budget is left.
    pub retry_budget_remains: bool,
    /// A job-level hard limit was reached.
    pub hard_limit_reached: bool,
    /// The policy for that limit says the job fails (and does not ask a human).
    pub policy_says_fail: bool,
}
}

/// `G_UNRECOVERABLE`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn unrecoverable(facts: &UnrecoverableFacts) -> GuardResult {
    any_of(
        Guard::Unrecoverable,
        &[
            (
                facts.stage_run_failed
                    && !facts.newer_run_of_kind_exists
                    && !facts.rework_route_remains
                    && !facts.retry_budget_remains,
                "the newest run of a stage kind failed, no newer run replaces it, and no rework \
                 route or retry budget remains",
            ),
            (
                facts.hard_limit_reached && facts.policy_says_fail,
                "a job-level hard limit was reached under a policy that says fail",
            ),
        ],
    )
}

facts! {
/// What decides whether a job is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectionFacts {
    /// The intake decision is decline.
    pub intake_decision_is_decline: bool,
    /// A reject decision is recorded.
    pub reject_decision_recorded: bool,
    /// The person who recorded it is an authorized approver.
    pub decider_is_authorized_approver: bool,
}
}

/// `G_REJECTION_RECORDED`.
///
/// # Errors
/// Returns the alternatives, none of which is true.
pub fn rejection_recorded(facts: &RejectionFacts) -> GuardResult {
    any_of(
        Guard::RejectionRecorded,
        &[
            (
                facts.intake_decision_is_decline,
                "the intake decision is decline",
            ),
            (
                facts.reject_decision_recorded && facts.decider_is_authorized_approver,
                "an authorized approver recorded a reject decision",
            ),
        ],
    )
}

// ---- completion (J13) ------------------------------------------------------------------------------------------

facts! {
/// What decides whether a job is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineScopeFacts<'a> {
    /// The stage kinds in the job's configured scope.
    pub scope: &'a [StageKind],
    /// Every stage run of the job, old runs included.
    pub stage_runs: &'a [StageRunSnapshot],
    /// The approval decision is approve.
    pub approval_decision_is_approve: bool,
    /// The evidence ledger hash chain verifies.
    pub ledger_chain_verifies: bool,
}
}

/// `G_PIPELINE_SCOPE_COMPLETE`.
///
/// A stage in scope is done when it has a run that is `PASSED`, or `SKIPPED` because a recorded
/// rule says the stage does not apply (ADR 0010 decision 2, see [`satisfies_dependants`]). A run
/// that was superseded has another status, so it never counts. A scope that lists no stage never
/// completes: the definition says "every stage kind in the scope", and a job with nothing in
/// scope would otherwise finish with no work done.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn pipeline_scope_complete(facts: &PipelineScopeFacts<'_>) -> GuardResult {
    let every_stage_in_scope_done = facts.scope.iter().all(|kind| {
        facts
            .stage_runs
            .iter()
            .any(|run| run.kind == *kind && satisfies_dependants(run.status))
    });
    Check::new(Guard::PipelineScopeComplete)
        .require(!facts.scope.is_empty(), "the job's scope lists no stage")
        .require(
            every_stage_in_scope_done,
            "a stage in the job's scope has no passed or skipped run that is still current",
        )
        .require(
            facts.approval_decision_is_approve,
            "the approval decision is not approve",
        )
        .require(
            facts.ledger_chain_verifies,
            "the evidence ledger hash chain does not verify",
        )
        .finish()
}
