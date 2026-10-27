//! The named guards of `state-machine.json`, evaluated against facts.
//!
//! A transition in the state tables carries a [`Guard`] name. The name says what must be true
//! before the engine applies the move. This module is where that becomes code: one pure
//! predicate for each guard, which reads a small struct of facts and says whether the guard
//! holds.
//!
//! # How the engine uses it
//!
//! The engine loads rows, the policy and the clock, builds the facts for the guard of the
//! transition it is about to apply, and calls [`evaluate`]. The domain never reads those things
//! itself, so every predicate here is a pure function: the same facts always give the same
//! answer.
//!
//! * [`facts_kind`] says which kind of facts a guard reads, so the engine builds the right one.
//! * [`evaluate`] runs the predicate and returns `Ok(())` when the guard holds. When it does not,
//!   the [`GuardFailure`] lists every unmet condition in plain English, for the audit record.
//!   Those texts are for operators. A reply to a requester must not repeat them (for example,
//!   `G_ADMISSION_DENIED` says that no reply reveals which test failed).
//! * Each predicate is also a public function in [`job`], [`stage_run`], [`attempt`] or
//!   [`task_node`], for a caller that already holds the typed facts.
//!
//! # Rules the predicates follow
//!
//! * **Fail closed.** A fact that is missing or unknown counts against the guard. A list of
//!   conditions is checked in full, so a failure names all of them and not just the first.
//! * **Words from the file.** A predicate follows the plain-English definition in
//!   `state-machine.json` clause by clause. Where a definition says "or", any one clause is
//!   enough. A test per guard covers each clause.
//! * **Time is a parameter.** Moments come in as [`Timestamp`](crate::values::Timestamp) values. A `Timestamp` compares by
//!   instant, so `10:00:00Z` and `10:00:00.000Z` are the same moment (ADR 0011).
//!
//! Every [`Guard`] has a predicate. The `match` in [`evaluate`] names every guard with no
//! catch-all arm, so adding a guard to the enum without a predicate does not compile.

pub mod attempt;
pub mod job;
pub mod stage_run;
pub mod task_node;

use std::fmt;

use crate::macros::string_enum;
use crate::state::Guard;

pub use attempt::{
    AttemptsFacts, CancelFacts, DeadlineFacts, EpochFacts, LeaseEpochFacts, LeaseExpiryFacts,
    SandboxGoneFacts, SandboxProvisionFacts, TeardownFacts,
};
pub use job::{
    AdmissionFacts, PipelineScopeFacts, PrincipalFacts, RejectionFacts, StageBoardFacts,
    UnrecoverableFacts,
};
pub use stage_run::{
    AnswerFacts, ApprovalFacts, BlockingFacts, EscalationFacts, GatePassFacts, HumanRejectFacts,
    HumanReworkFacts, LeaseGrantFacts, NeedsHumanFacts, NoReworkFacts, NotApplicableBasis,
    NotApplicableFacts, OutputFacts, OverrideFacts, RetryFacts, ReworkFacts, SupersedeFacts,
    UnblockFacts, UpstreamFacts,
};
pub use task_node::{TaskDepsFacts, TaskEvidenceFacts, TaskRetryFacts, TaskStartFacts};

/// A guard that does not hold, with every condition that was not met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardFailure {
    /// The guard that was evaluated.
    pub guard: Guard,
    /// What was not true, in plain English. For a guard that needs all of its conditions this
    /// lists the ones that failed. For a guard that needs any one of several, this lists all of
    /// them, because none was true.
    pub unmet: Vec<&'static str>,
    /// True when the guard needs only one of its conditions, so `unmet` lists alternatives.
    pub any_of: bool,
}

impl fmt::Display for GuardFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = self.unmet.join("; ");
        if self.any_of {
            write!(
                f,
                "guard {} does not hold because none of these is true: {list}",
                self.guard
            )
        } else {
            write!(f, "guard {} does not hold: {list}", self.guard)
        }
    }
}

impl std::error::Error for GuardFailure {}

/// What a predicate returns: `Ok(())` when the guard holds.
pub type GuardResult = Result<(), GuardFailure>;

/// Why [`evaluate`] did not return `Ok(())`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// The guard was evaluated and does not hold.
    #[error(transparent)]
    Unmet(#[from] GuardFailure),
    /// The caller supplied facts of a different kind than the guard reads. This is a mistake in
    /// the caller, not a decision about the transition.
    #[error("guard {guard} reads {expected} facts, but {given} facts were supplied")]
    WrongFacts {
        /// The guard.
        guard: Guard,
        /// The kind of facts it reads.
        expected: FactsKind,
        /// The kind that was supplied.
        given: FactsKind,
    },
}

/// A guard that needs all of its conditions. Every condition is checked, so the failure lists
/// all that are unmet.
struct Check {
    guard: Guard,
    unmet: Vec<&'static str>,
}

impl Check {
    fn new(guard: Guard) -> Self {
        Self {
            guard,
            unmet: Vec::new(),
        }
    }

    /// Records `otherwise` as unmet unless `holds`.
    fn require(mut self, holds: bool, otherwise: &'static str) -> Self {
        if !holds {
            self.unmet.push(otherwise);
        }
        self
    }

    fn finish(self) -> GuardResult {
        if self.unmet.is_empty() {
            Ok(())
        } else {
            Err(GuardFailure {
                guard: self.guard,
                unmet: self.unmet,
                any_of: false,
            })
        }
    }
}

/// A guard that needs any one of several conditions.
fn any_of(guard: Guard, alternatives: &[(bool, &'static str)]) -> GuardResult {
    if alternatives.iter().any(|(holds, _)| *holds) {
        Ok(())
    } else {
        Err(GuardFailure {
            guard,
            unmet: alternatives.iter().map(|(_, text)| *text).collect(),
            any_of: true,
        })
    }
}

string_enum! {
    /// The kind of facts a guard reads. Several guards can read the same kind.
    pub enum FactsKind("facts kind") {
        /// [`AdmissionFacts`].
        Admission = "admission",
        /// [`StageBoardFacts`].
        StageBoard = "stage board",
        /// [`PrincipalFacts`].
        Principal = "principal",
        /// [`AttemptsFacts`].
        Attempts = "attempts",
        /// [`UnrecoverableFacts`].
        Unrecoverable = "unrecoverable",
        /// [`RejectionFacts`].
        Rejection = "rejection",
        /// [`PipelineScopeFacts`].
        PipelineScope = "pipeline scope",
        /// [`UpstreamFacts`].
        Upstream = "upstream",
        /// [`NotApplicableFacts`].
        NotApplicable = "not applicable",
        /// [`LeaseGrantFacts`].
        LeaseGrant = "lease grant",
        /// [`OutputFacts`].
        Output = "output",
        /// [`RetryFacts`].
        Retry = "retry",
        /// [`EscalationFacts`].
        Escalation = "escalation",
        /// [`GatePassFacts`].
        GatePass = "gate pass",
        /// [`ReworkFacts`].
        Rework = "rework",
        /// [`NeedsHumanFacts`].
        NeedsHuman = "needs human",
        /// [`BlockingFacts`].
        Blocking = "blocking",
        /// [`NoReworkFacts`].
        NoRework = "no rework",
        /// [`AnswerFacts`].
        Answer = "answer",
        /// [`ApprovalFacts`].
        Approval = "approval",
        /// [`HumanReworkFacts`].
        HumanRework = "human rework",
        /// [`HumanRejectFacts`].
        HumanReject = "human reject",
        /// [`UnblockFacts`].
        Unblock = "unblock",
        /// [`OverrideFacts`].
        Override = "override",
        /// [`SupersedeFacts`].
        Supersede = "supersede",
        /// [`SandboxProvisionFacts`].
        SandboxProvision = "sandbox provision",
        /// [`EpochFacts`].
        Epoch = "epoch",
        /// [`LeaseEpochFacts`].
        LeaseEpoch = "lease epoch",
        /// [`DeadlineFacts`].
        Deadline = "deadline",
        /// [`LeaseExpiryFacts`].
        LeaseExpiry = "lease expiry",
        /// [`CancelFacts`].
        Cancel = "cancel",
        /// [`SandboxGoneFacts`].
        SandboxGone = "sandbox gone",
        /// [`TeardownFacts`].
        Teardown = "teardown",
        /// [`TaskDepsFacts`].
        TaskDeps = "task dependencies",
        /// [`TaskStartFacts`].
        TaskStart = "task start",
        /// [`TaskEvidenceFacts`].
        TaskEvidence = "task evidence",
        /// [`TaskRetryFacts`].
        TaskRetry = "task retry",
    }
}

/// Facts for one guard, tagged with their kind.
#[derive(Debug, Clone, Copy)]
pub enum GuardFacts<'a> {
    /// See [`AdmissionFacts`].
    Admission(AdmissionFacts),
    /// See [`StageBoardFacts`].
    StageBoard(StageBoardFacts<'a>),
    /// See [`PrincipalFacts`].
    Principal(PrincipalFacts<'a>),
    /// See [`AttemptsFacts`].
    Attempts(AttemptsFacts<'a>),
    /// See [`UnrecoverableFacts`].
    Unrecoverable(UnrecoverableFacts),
    /// See [`RejectionFacts`].
    Rejection(RejectionFacts),
    /// See [`PipelineScopeFacts`].
    PipelineScope(PipelineScopeFacts<'a>),
    /// See [`UpstreamFacts`].
    Upstream(UpstreamFacts<'a>),
    /// See [`NotApplicableFacts`].
    NotApplicable(NotApplicableFacts),
    /// See [`LeaseGrantFacts`].
    LeaseGrant(LeaseGrantFacts),
    /// See [`OutputFacts`].
    Output(OutputFacts),
    /// See [`RetryFacts`].
    Retry(RetryFacts<'a>),
    /// See [`EscalationFacts`].
    Escalation(EscalationFacts),
    /// See [`GatePassFacts`].
    GatePass(GatePassFacts<'a>),
    /// See [`ReworkFacts`].
    Rework(ReworkFacts),
    /// See [`NeedsHumanFacts`].
    NeedsHuman(NeedsHumanFacts),
    /// See [`BlockingFacts`].
    Blocking(BlockingFacts),
    /// See [`NoReworkFacts`].
    NoRework(NoReworkFacts),
    /// See [`AnswerFacts`].
    Answer(AnswerFacts),
    /// See [`ApprovalFacts`].
    Approval(ApprovalFacts),
    /// See [`HumanReworkFacts`].
    HumanRework(HumanReworkFacts<'a>),
    /// See [`HumanRejectFacts`].
    HumanReject(HumanRejectFacts),
    /// See [`UnblockFacts`].
    Unblock(UnblockFacts),
    /// See [`OverrideFacts`].
    Override(OverrideFacts<'a>),
    /// See [`SupersedeFacts`].
    Supersede(SupersedeFacts),
    /// See [`SandboxProvisionFacts`].
    SandboxProvision(SandboxProvisionFacts),
    /// See [`EpochFacts`].
    Epoch(EpochFacts),
    /// See [`LeaseEpochFacts`].
    LeaseEpoch(LeaseEpochFacts),
    /// See [`DeadlineFacts`].
    Deadline(DeadlineFacts),
    /// See [`LeaseExpiryFacts`].
    LeaseExpiry(LeaseExpiryFacts),
    /// See [`CancelFacts`].
    Cancel(CancelFacts),
    /// See [`SandboxGoneFacts`].
    SandboxGone(SandboxGoneFacts),
    /// See [`TeardownFacts`].
    Teardown(TeardownFacts),
    /// See [`TaskDepsFacts`].
    TaskDeps(TaskDepsFacts<'a>),
    /// See [`TaskStartFacts`].
    TaskStart(TaskStartFacts),
    /// See [`TaskEvidenceFacts`].
    TaskEvidence(TaskEvidenceFacts),
    /// See [`TaskRetryFacts`].
    TaskRetry(TaskRetryFacts),
}

impl GuardFacts<'_> {
    /// The kind of these facts.
    #[must_use]
    pub const fn kind(&self) -> FactsKind {
        match self {
            GuardFacts::Admission(_) => FactsKind::Admission,
            GuardFacts::StageBoard(_) => FactsKind::StageBoard,
            GuardFacts::Principal(_) => FactsKind::Principal,
            GuardFacts::Attempts(_) => FactsKind::Attempts,
            GuardFacts::Unrecoverable(_) => FactsKind::Unrecoverable,
            GuardFacts::Rejection(_) => FactsKind::Rejection,
            GuardFacts::PipelineScope(_) => FactsKind::PipelineScope,
            GuardFacts::Upstream(_) => FactsKind::Upstream,
            GuardFacts::NotApplicable(_) => FactsKind::NotApplicable,
            GuardFacts::LeaseGrant(_) => FactsKind::LeaseGrant,
            GuardFacts::Output(_) => FactsKind::Output,
            GuardFacts::Retry(_) => FactsKind::Retry,
            GuardFacts::Escalation(_) => FactsKind::Escalation,
            GuardFacts::GatePass(_) => FactsKind::GatePass,
            GuardFacts::Rework(_) => FactsKind::Rework,
            GuardFacts::NeedsHuman(_) => FactsKind::NeedsHuman,
            GuardFacts::Blocking(_) => FactsKind::Blocking,
            GuardFacts::NoRework(_) => FactsKind::NoRework,
            GuardFacts::Answer(_) => FactsKind::Answer,
            GuardFacts::Approval(_) => FactsKind::Approval,
            GuardFacts::HumanRework(_) => FactsKind::HumanRework,
            GuardFacts::HumanReject(_) => FactsKind::HumanReject,
            GuardFacts::Unblock(_) => FactsKind::Unblock,
            GuardFacts::Override(_) => FactsKind::Override,
            GuardFacts::Supersede(_) => FactsKind::Supersede,
            GuardFacts::SandboxProvision(_) => FactsKind::SandboxProvision,
            GuardFacts::Epoch(_) => FactsKind::Epoch,
            GuardFacts::LeaseEpoch(_) => FactsKind::LeaseEpoch,
            GuardFacts::Deadline(_) => FactsKind::Deadline,
            GuardFacts::LeaseExpiry(_) => FactsKind::LeaseExpiry,
            GuardFacts::Cancel(_) => FactsKind::Cancel,
            GuardFacts::SandboxGone(_) => FactsKind::SandboxGone,
            GuardFacts::Teardown(_) => FactsKind::Teardown,
            GuardFacts::TaskDeps(_) => FactsKind::TaskDeps,
            GuardFacts::TaskStart(_) => FactsKind::TaskStart,
            GuardFacts::TaskEvidence(_) => FactsKind::TaskEvidence,
            GuardFacts::TaskRetry(_) => FactsKind::TaskRetry,
        }
    }
}

/// The kind of facts that `guard` reads.
#[must_use]
pub const fn facts_kind(guard: Guard) -> FactsKind {
    match guard {
        Guard::AdmissionOk | Guard::AdmissionDenied => FactsKind::Admission,
        Guard::AnyStageWaiting
        | Guard::NoStageWaiting
        | Guard::AnyStageBlocked
        | Guard::BlockDispositionsRecorded => FactsKind::StageBoard,
        Guard::ActorMayPause | Guard::ActorMayCancel => FactsKind::Principal,
        Guard::AllAttemptsTerminal | Guard::NoActiveAttempt => FactsKind::Attempts,
        Guard::Unrecoverable => FactsKind::Unrecoverable,
        Guard::RejectionRecorded => FactsKind::Rejection,
        Guard::PipelineScopeComplete => FactsKind::PipelineScope,
        Guard::UpstreamPassed => FactsKind::Upstream,
        Guard::NotApplicableDecided => FactsKind::NotApplicable,
        Guard::LeaseAcquired => FactsKind::LeaseGrant,
        Guard::OutputSchemaValid => FactsKind::Output,
        Guard::RetryAllowed | Guard::RetryExhaustedOrNonretryable => FactsKind::Retry,
        Guard::EscalationRequired => FactsKind::Escalation,
        Guard::GatePassEvidenced => FactsKind::GatePass,
        Guard::ReworkAllowed => FactsKind::Rework,
        Guard::NeedsHumanVerdict => FactsKind::NeedsHuman,
        Guard::BlockingCondition => FactsKind::Blocking,
        Guard::GateFailedNoRework => FactsKind::NoRework,
        Guard::AnswerRecorded => FactsKind::Answer,
        Guard::ApproverAuthorized => FactsKind::Approval,
        Guard::HumanReworkAllowed => FactsKind::HumanRework,
        Guard::HumanRejected => FactsKind::HumanReject,
        Guard::BlockClearedRerun => FactsKind::Unblock,
        Guard::OverridePermitted => FactsKind::Override,
        Guard::UpstreamInvalidated => FactsKind::Supersede,
        Guard::SandboxProvisioned => FactsKind::SandboxProvision,
        Guard::EpochCurrent => FactsKind::Epoch,
        Guard::LeaseEpochCurrent => FactsKind::LeaseEpoch,
        Guard::DeadlinePassed => FactsKind::Deadline,
        Guard::LeaseExpired => FactsKind::LeaseExpiry,
        Guard::CancelAllowed => FactsKind::Cancel,
        Guard::SandboxGone => FactsKind::SandboxGone,
        Guard::TeardownDeadlinePassed => FactsKind::Teardown,
        Guard::TaskDepsSucceeded => FactsKind::TaskDeps,
        Guard::TaskStartedByAttempt => FactsKind::TaskStart,
        Guard::TaskEvidenceRecorded => FactsKind::TaskEvidence,
        Guard::TaskRetryAllowed => FactsKind::TaskRetry,
    }
}

/// Runs the predicate of `guard` on `facts`.
///
/// # Errors
/// * [`GuardError::Unmet`] when the guard does not hold. The failure lists what was not true.
/// * [`GuardError::WrongFacts`] when `facts` are not of the kind `guard` reads.
pub fn evaluate(guard: Guard, facts: &GuardFacts<'_>) -> Result<(), GuardError> {
    // Picks the facts out of the enum and runs one predicate. Facts of another kind are a
    // mistake in the caller and are reported as such, never read as if they were right.
    macro_rules! run {
        ($kind:ident => $predicate:path) => {
            match facts {
                GuardFacts::$kind(inner) => $predicate(inner).map_err(GuardError::from),
                other => Err(GuardError::WrongFacts {
                    guard,
                    expected: FactsKind::$kind,
                    given: other.kind(),
                }),
            }
        };
    }
    match guard {
        Guard::AdmissionOk => run!(Admission => job::admission_ok),
        Guard::AdmissionDenied => run!(Admission => job::admission_denied),
        Guard::AnyStageWaiting => run!(StageBoard => job::any_stage_waiting),
        Guard::NoStageWaiting => run!(StageBoard => job::no_stage_waiting),
        Guard::ActorMayPause => run!(Principal => job::actor_may_pause),
        Guard::AnyStageBlocked => run!(StageBoard => job::any_stage_blocked),
        Guard::BlockDispositionsRecorded => run!(StageBoard => job::block_dispositions_recorded),
        Guard::ActorMayCancel => run!(Principal => job::actor_may_cancel),
        Guard::AllAttemptsTerminal => run!(Attempts => attempt::all_attempts_terminal),
        Guard::Unrecoverable => run!(Unrecoverable => job::unrecoverable),
        Guard::RejectionRecorded => run!(Rejection => job::rejection_recorded),
        Guard::PipelineScopeComplete => run!(PipelineScope => job::pipeline_scope_complete),
        Guard::UpstreamPassed => run!(Upstream => stage_run::upstream_passed),
        Guard::NotApplicableDecided => run!(NotApplicable => stage_run::not_applicable_decided),
        Guard::LeaseAcquired => run!(LeaseGrant => stage_run::lease_acquired),
        Guard::OutputSchemaValid => run!(Output => stage_run::output_schema_valid),
        Guard::RetryAllowed => run!(Retry => stage_run::retry_allowed),
        Guard::RetryExhaustedOrNonretryable => {
            run!(Retry => stage_run::retry_exhausted_or_nonretryable)
        }
        Guard::EscalationRequired => run!(Escalation => stage_run::escalation_required),
        Guard::GatePassEvidenced => run!(GatePass => stage_run::gate_pass_evidenced),
        Guard::ReworkAllowed => run!(Rework => stage_run::rework_allowed),
        Guard::NeedsHumanVerdict => run!(NeedsHuman => stage_run::needs_human_verdict),
        Guard::BlockingCondition => run!(Blocking => stage_run::blocking_condition),
        Guard::GateFailedNoRework => run!(NoRework => stage_run::gate_failed_no_rework),
        Guard::AnswerRecorded => run!(Answer => stage_run::answer_recorded),
        Guard::ApproverAuthorized => run!(Approval => stage_run::approver_authorized),
        Guard::HumanReworkAllowed => run!(HumanRework => stage_run::human_rework_allowed),
        Guard::HumanRejected => run!(HumanReject => stage_run::human_rejected),
        Guard::BlockClearedRerun => run!(Unblock => stage_run::block_cleared_rerun),
        Guard::OverridePermitted => run!(Override => stage_run::override_permitted),
        Guard::NoActiveAttempt => run!(Attempts => attempt::no_active_attempt),
        Guard::UpstreamInvalidated => run!(Supersede => stage_run::upstream_invalidated),
        Guard::SandboxProvisioned => run!(SandboxProvision => attempt::sandbox_provisioned),
        Guard::LeaseEpochCurrent => run!(LeaseEpoch => attempt::lease_epoch_current),
        Guard::EpochCurrent => run!(Epoch => attempt::epoch_current),
        Guard::DeadlinePassed => run!(Deadline => attempt::deadline_passed),
        Guard::LeaseExpired => run!(LeaseExpiry => attempt::lease_expired),
        Guard::CancelAllowed => run!(Cancel => attempt::cancel_allowed),
        Guard::SandboxGone => run!(SandboxGone => attempt::sandbox_gone),
        Guard::TeardownDeadlinePassed => run!(Teardown => attempt::teardown_deadline_passed),
        Guard::TaskDepsSucceeded => run!(TaskDeps => task_node::task_deps_succeeded),
        Guard::TaskStartedByAttempt => run!(TaskStart => task_node::task_started_by_attempt),
        Guard::TaskEvidenceRecorded => run!(TaskEvidence => task_node::task_evidence_recorded),
        Guard::TaskRetryAllowed => run!(TaskRetry => task_node::task_retry_allowed),
    }
}

#[cfg(test)]
mod tests;
