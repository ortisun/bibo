//! Guards of the Attempt machine (transitions `A01` to `A10`), and the two guards about attempts
//! that the Job and StageRun machines use (`G_ALL_ATTEMPTS_TERMINAL`, `G_NO_ACTIVE_ATTEMPT`).

use super::digest::facts;
use super::{Check, GuardResult};
use crate::machines::snapshot::{AttemptSnapshot, SandboxState};
use crate::state::{AttemptStatus, Guard, JobStatus, Status};
use crate::values::Timestamp;

// ---- attempts of a job or a stage run -----------------------------------------------------------------

facts! {
/// The attempts under one job or one stage run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptsFacts<'a> {
    /// The attempts, with the state of their sandboxes.
    pub attempts: &'a [AttemptSnapshot],
}
}

/// `G_ALL_ATTEMPTS_TERMINAL`. A sandbox that could not be confirmed gone counts as flagged as
/// leaked, and that is enough here: the alert is the follow-up.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn all_attempts_terminal(facts: &AttemptsFacts<'_>) -> GuardResult {
    Check::new(Guard::AllAttemptsTerminal)
        .require(
            facts.attempts.iter().all(|a| a.status.is_terminal()),
            "an attempt of the job is not in a terminal state",
        )
        .require(
            facts.attempts.iter().all(|a| a.sandbox != SandboxState::Up),
            "a sandbox is still up and has not been flagged as leaked",
        )
        .finish()
}

/// `G_NO_ACTIVE_ATTEMPT`: none is `STARTING`, `RUNNING` or `CANCELLING`.
///
/// # Errors
/// Returns the unmet condition.
pub fn no_active_attempt(facts: &AttemptsFacts<'_>) -> GuardResult {
    Check::new(Guard::NoActiveAttempt)
        .require(
            facts.attempts.iter().all(|a| a.status.is_terminal()),
            "an attempt is still starting, running or cancelling",
        )
        .finish()
}

// ---- the lease epoch -----------------------------------------------------------------------------------------

facts! {
/// The lease epoch a worker sent and the one on record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochFacts {
    /// The epoch the worker sent with its request.
    pub sent_epoch: u64,
    /// The epoch stored on the attempt.
    pub stored_epoch: u64,
}
}

impl EpochFacts {
    const fn is_current(&self) -> bool {
        self.sent_epoch == self.stored_epoch
    }
}

/// `G_EPOCH_CURRENT`. Only an equal epoch passes. An older one is a zombie worker, and a newer
/// one is a bug, so neither may write.
///
/// # Errors
/// Returns the unmet condition.
pub fn epoch_current(facts: &EpochFacts) -> GuardResult {
    Check::new(Guard::EpochCurrent)
        .require(
            facts.is_current(),
            "the epoch sent by the worker is not the stored epoch",
        )
        .finish()
}

facts! {
/// What decides whether a heartbeat is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseEpochFacts {
    /// The epochs.
    pub epoch: EpochFacts,
    /// The moment of the request.
    pub now: Timestamp,
    /// When the lease runs out.
    pub lease_expires_at: Timestamp,
}
}

/// `G_LEASE_EPOCH_CURRENT`. The last instant of the lease still counts.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn lease_epoch_current(facts: &LeaseEpochFacts) -> GuardResult {
    Check::new(Guard::LeaseEpochCurrent)
        .require(
            facts.epoch.is_current(),
            "the epoch sent by the worker is not the stored epoch",
        )
        .require(
            facts.now <= facts.lease_expires_at,
            "the lease has already run out",
        )
        .finish()
}

// ---- starting -----------------------------------------------------------------------------------------------------

facts! {
/// What decides whether the sandbox is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxProvisionFacts {
    /// The sandbox provider returned a session. That means it created the container, read its
    /// posture back, found every part equal to the spec and the policy, started it and passed
    /// the runtime self-check. The engine sets this from "`create_verified` returned a session"
    /// and from nothing else.
    pub posture_verified: bool,
    /// The tool grants that policy approved are recorded in the audit log.
    pub tool_grants_recorded: bool,
    /// The runtime probe of this attempt supports every capability the stage needs.
    pub probe_satisfies_stage: bool,
    /// The lease epoch.
    pub epoch: EpochFacts,
}
}

/// `G_SANDBOX_PROVISIONED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn sandbox_provisioned(facts: &SandboxProvisionFacts) -> GuardResult {
    Check::new(Guard::SandboxProvisioned)
        .require(
            facts.posture_verified,
            "the sandbox posture was not verified against the spec and the policy",
        )
        .require(
            facts.tool_grants_recorded,
            "the policy-approved tool grants are not recorded in the audit log",
        )
        .require(
            facts.probe_satisfies_stage,
            "the runtime probe does not satisfy what the stage needs",
        )
        .require(facts.epoch.is_current(), "the lease epoch is not current")
        .finish()
}

// ---- deadlines and leases (the sweeper) ----------------------------------------------------------------

facts! {
/// What decides whether the attempt ran out of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineFacts {
    /// The moment of the check.
    pub now: Timestamp,
    /// The attempt deadline.
    pub attempt_deadline: Timestamp,
}
}

/// `G_DEADLINE_PASSED`: now is after the deadline, not at it.
///
/// # Errors
/// Returns the unmet condition.
pub fn deadline_passed(facts: &DeadlineFacts) -> GuardResult {
    Check::new(Guard::DeadlinePassed)
        .require(
            facts.now > facts.attempt_deadline,
            "the attempt deadline has not passed yet",
        )
        .finish()
}

facts! {
/// What decides whether the lease was lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseExpiryFacts {
    /// The moment of the check.
    pub now: Timestamp,
    /// When the lease runs out.
    pub lease_expires_at: Timestamp,
    /// A heartbeat arrived that the check has not yet seen in `lease_expires_at`.
    pub heartbeat_arrived: bool,
}
}

/// `G_LEASE_EXPIRED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn lease_expired(facts: &LeaseExpiryFacts) -> GuardResult {
    Check::new(Guard::LeaseExpired)
        .require(
            facts.now > facts.lease_expires_at,
            "the lease has not expired yet",
        )
        .require(!facts.heartbeat_arrived, "a heartbeat arrived")
        .finish()
}

// ---- cancelling -------------------------------------------------------------------------------------------------------

facts! {
/// What decides whether an attempt may be told to cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelFacts {
    /// The attempt.
    pub attempt: AttemptStatus,
    /// The job.
    pub job: JobStatus,
    /// The stage run of the attempt is being superseded.
    pub stage_run_is_being_superseded: bool,
}
}

/// `G_CANCEL_ALLOWED`: the attempt is not terminal, and the job is `CANCELLING` or the stage
/// run is being superseded.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn cancel_allowed(facts: &CancelFacts) -> GuardResult {
    Check::new(Guard::CancelAllowed)
        .require(
            !facts.attempt.is_terminal(),
            "the attempt is already in a terminal state",
        )
        .require(
            facts.job == JobStatus::Cancelling || facts.stage_run_is_being_superseded,
            "the job is not cancelling and the stage run is not being superseded",
        )
        .finish()
}

facts! {
/// What decides whether teardown is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxGoneFacts {
    /// The sandbox provider confirmed the sandbox no longer exists.
    pub provider_confirms_sandbox_gone: bool,
}
}

/// `G_SANDBOX_GONE`.
///
/// # Errors
/// Returns the unmet condition.
pub fn sandbox_gone(facts: &SandboxGoneFacts) -> GuardResult {
    Check::new(Guard::SandboxGone)
        .require(
            facts.provider_confirms_sandbox_gone,
            "the sandbox provider has not confirmed the sandbox is gone",
        )
        .finish()
}

facts! {
/// What decides whether the teardown grace period is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeardownFacts {
    /// The moment of the check.
    pub now: Timestamp,
    /// When the cancel was requested and teardown began.
    pub cancel_requested_at: Timestamp,
    /// The grace period, 30 seconds by default.
    pub grace_seconds: u32,
}
}

/// `G_TEARDOWN_DEADLINE_PASSED`: the grace period has elapsed in full.
///
/// # Errors
/// Returns the unmet condition.
pub fn teardown_deadline_passed(facts: &TeardownFacts) -> GuardResult {
    const NANOS: i128 = 1_000_000_000;
    let (now, start) = (facts.now, facts.cancel_requested_at);
    let elapsed = (i128::from(now.unix_seconds()) - i128::from(start.unix_seconds())) * NANOS
        + i128::from(now.subsecond_nanos())
        - i128::from(start.subsecond_nanos());
    Check::new(Guard::TeardownDeadlinePassed)
        .require(
            elapsed >= i128::from(facts.grace_seconds) * NANOS,
            "the teardown grace period has not elapsed",
        )
        .finish()
}
