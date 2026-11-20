//! The Stage run state machine.
//!
//! One execution of one stage kind for a job. Terminal runs are immutable. Rework creates a new run; it never reopens an old one. When more than one of S21, S05, S06 and S07 is legal for a failed attempt, the engine takes the first that applies in this order: S21 when the cause is the environment (a missing or unsafe setting that retrying cannot fix), S07 for BUDGET_EXHAUSTED, S05 when a retry is allowed, S06 when the class is not retryable, otherwise S07 because the attempt limit, the repair cap or the budget stopped a retry.
//!
//! Written from `docs/architecture/state-machine.json`. If the file changes, change this one to match;
//! `tests/state_machine_conformance.rs` compares every status, event and transition with
//! the file, in both directions.

use super::{Actor, Guard, Status, Transition};
use crate::macros::string_enum;

string_enum! {
    /// The status of a stage run. The spelling of each value is the one stored in
    /// the database and written in documents.
    pub enum StageRunStatus("stage run status") {
        /// Created. Upstream requirements are not met yet.
        Pending = "PENDING",
        /// Schedulable. Needs an attempt. Also the state during retry back-off, with not_before in the future.
        Ready = "READY",
        /// An attempt is in progress.
        Running = "RUNNING",
        /// Work is done. The deterministic gate or independent evaluator is deciding. Success claimed by an agent has no effect here.
        Gating = "GATING",
        /// Needs a human answer, budget decision, gate decision or approval.
        WaitingForHuman = "WAITING_FOR_HUMAN",
        /// Cannot proceed or be promoted. Needs a recorded disposition.
        Blocked = "BLOCKED",
        /// The gate decision is PASS with evidence. Settled, but becomes SUPERSEDED if its inputs are invalidated.
        Passed = "PASSED",
        /// The gate sent the work back. A new run of the route target stage replaces this one.
        ReworkRequested = "REWORK_REQUESTED",
        /// Retries or rework exhausted, or the failure is not retryable, or a human rejected.
        Failed = "FAILED",
        /// NOT_APPLICABLE by deterministic rule, profile or policy, with the rule recorded. Counts as satisfied for the stages that require it and for completion, never as passed, and never as evidence for an assurance level. Becomes SUPERSEDED when an input of the decision changes.
        Skipped = "SKIPPED",
        /// Replaced because an upstream input changed.
        Superseded = "SUPERSEDED",
        /// Cancelled with the job.
        Cancelled = "CANCELLED",
    }
}

string_enum! {
    /// An event that asks the stage run machine to move.
    pub enum StageRunEvent("stage run event") {
        PreconditionsMet = "preconditions_met",
        MarkNotApplicable = "mark_not_applicable",
        Start = "start",
        AttemptSucceeded = "attempt_succeeded",
        AttemptFailedRetryable = "attempt_failed_retryable",
        AttemptFailedFinal = "attempt_failed_final",
        EscalateToHuman = "escalate_to_human",
        GatePassed = "gate_passed",
        GateRequiresRework = "gate_requires_rework",
        GateNeedsHuman = "gate_needs_human",
        GateBlocks = "gate_blocks",
        GateFailedFinal = "gate_failed_final",
        HumanAnswered = "human_answered",
        HumanApproved = "human_approved",
        HumanRequestedRework = "human_requested_rework",
        HumanRejected = "human_rejected",
        UnblockedRerun = "unblocked_rerun",
        OverrideAccepted = "override_accepted",
        Cancel = "cancel",
        Supersede = "supersede",
        AttemptBlocked = "attempt_blocked",
        RequireReauthorization = "require_reauthorization",
    }
}

/// Every legal stage run transition, in the order of the file.
pub static STAGE_RUN_TRANSITIONS: &[Transition<StageRunStatus, StageRunEvent>] = &[
    Transition {
        id: "S01",
        from: &[StageRunStatus::Pending],
        event: StageRunEvent::PreconditionsMet,
        guard: Guard::UpstreamPassed,
        to: StageRunStatus::Ready,
        actors: &[Actor::Engine],
        emits: Some("stage_run.ready"),
    },
    Transition {
        id: "S02",
        from: &[StageRunStatus::Pending, StageRunStatus::Ready],
        event: StageRunEvent::MarkNotApplicable,
        guard: Guard::NotApplicableDecided,
        to: StageRunStatus::Skipped,
        actors: &[Actor::Engine],
        emits: Some("stage_run.skipped"),
    },
    Transition {
        id: "S03",
        from: &[StageRunStatus::Ready],
        event: StageRunEvent::Start,
        guard: Guard::LeaseAcquired,
        to: StageRunStatus::Running,
        actors: &[Actor::Worker],
        emits: Some("stage_run.started"),
    },
    Transition {
        id: "S04",
        from: &[StageRunStatus::Running],
        event: StageRunEvent::AttemptSucceeded,
        guard: Guard::OutputSchemaValid,
        to: StageRunStatus::Gating,
        actors: &[Actor::Engine],
        emits: Some("stage_run.gating"),
    },
    Transition {
        id: "S05",
        from: &[StageRunStatus::Running],
        event: StageRunEvent::AttemptFailedRetryable,
        guard: Guard::RetryAllowed,
        to: StageRunStatus::Ready,
        actors: &[Actor::Engine],
        emits: Some("stage_run.retry_scheduled"),
    },
    Transition {
        id: "S06",
        from: &[StageRunStatus::Running],
        event: StageRunEvent::AttemptFailedFinal,
        guard: Guard::FailureNonretryable,
        to: StageRunStatus::Failed,
        actors: &[Actor::Engine],
        emits: Some("stage_run.failed"),
    },
    Transition {
        id: "S07",
        from: &[StageRunStatus::Running],
        event: StageRunEvent::EscalateToHuman,
        guard: Guard::EscalationRequired,
        to: StageRunStatus::WaitingForHuman,
        actors: &[Actor::Engine],
        emits: Some("stage_run.waiting_for_human"),
    },
    Transition {
        id: "S08",
        from: &[StageRunStatus::Gating],
        event: StageRunEvent::GatePassed,
        guard: Guard::GatePassEvidenced,
        to: StageRunStatus::Passed,
        actors: &[Actor::Gate],
        emits: Some("stage_run.passed"),
    },
    Transition {
        id: "S09",
        from: &[StageRunStatus::Gating],
        event: StageRunEvent::GateRequiresRework,
        guard: Guard::ReworkAllowed,
        to: StageRunStatus::ReworkRequested,
        actors: &[Actor::Gate],
        emits: Some("stage_run.rework_requested"),
    },
    Transition {
        id: "S10",
        from: &[StageRunStatus::Gating],
        event: StageRunEvent::GateNeedsHuman,
        guard: Guard::NeedsHumanVerdict,
        to: StageRunStatus::WaitingForHuman,
        actors: &[Actor::Gate],
        emits: Some("stage_run.waiting_for_human"),
    },
    Transition {
        id: "S11",
        from: &[StageRunStatus::Gating],
        event: StageRunEvent::GateBlocks,
        guard: Guard::BlockingCondition,
        to: StageRunStatus::Blocked,
        actors: &[Actor::Gate],
        emits: Some("stage_run.blocked"),
    },
    Transition {
        id: "S12",
        from: &[StageRunStatus::Gating],
        event: StageRunEvent::GateFailedFinal,
        guard: Guard::GateFailedNoRework,
        to: StageRunStatus::Failed,
        actors: &[Actor::Gate],
        emits: Some("stage_run.failed"),
    },
    Transition {
        id: "S13",
        from: &[StageRunStatus::WaitingForHuman],
        event: StageRunEvent::HumanAnswered,
        guard: Guard::AnswerRecorded,
        to: StageRunStatus::Ready,
        actors: &[
            Actor::Requester,
            Actor::Operator,
            Actor::Approver,
            Actor::OrgAdmin,
        ],
        emits: Some("stage_run.ready"),
    },
    Transition {
        id: "S14",
        from: &[StageRunStatus::WaitingForHuman],
        event: StageRunEvent::HumanApproved,
        guard: Guard::ApproverAuthorized,
        to: StageRunStatus::Passed,
        actors: &[Actor::Approver],
        emits: Some("stage_run.passed"),
    },
    Transition {
        id: "S15",
        from: &[StageRunStatus::WaitingForHuman, StageRunStatus::Blocked],
        event: StageRunEvent::HumanRequestedRework,
        guard: Guard::HumanReworkAllowed,
        to: StageRunStatus::ReworkRequested,
        actors: &[Actor::Approver, Actor::Operator],
        emits: Some("stage_run.rework_requested"),
    },
    Transition {
        id: "S16",
        from: &[StageRunStatus::WaitingForHuman],
        event: StageRunEvent::HumanRejected,
        guard: Guard::HumanRejected,
        to: StageRunStatus::Failed,
        actors: &[Actor::Approver],
        emits: Some("stage_run.failed"),
    },
    Transition {
        id: "S17",
        from: &[StageRunStatus::Blocked],
        event: StageRunEvent::UnblockedRerun,
        guard: Guard::BlockClearedRerun,
        to: StageRunStatus::Ready,
        actors: &[Actor::Operator],
        emits: Some("stage_run.ready"),
    },
    Transition {
        id: "S18",
        from: &[StageRunStatus::Blocked],
        event: StageRunEvent::OverrideAccepted,
        guard: Guard::OverridePermitted,
        to: StageRunStatus::Passed,
        actors: &[Actor::Approver, Actor::SecurityApprover],
        emits: Some("stage_run.passed"),
    },
    Transition {
        id: "S19",
        from: &[
            StageRunStatus::Pending,
            StageRunStatus::Ready,
            StageRunStatus::Running,
            StageRunStatus::Gating,
            StageRunStatus::WaitingForHuman,
            StageRunStatus::Blocked,
        ],
        event: StageRunEvent::Cancel,
        guard: Guard::NoActiveAttempt,
        to: StageRunStatus::Cancelled,
        actors: &[Actor::Engine],
        emits: Some("stage_run.cancelled"),
    },
    Transition {
        id: "S20",
        from: &[
            StageRunStatus::Pending,
            StageRunStatus::Ready,
            StageRunStatus::Running,
            StageRunStatus::Gating,
            StageRunStatus::WaitingForHuman,
            StageRunStatus::Blocked,
            StageRunStatus::Passed,
            StageRunStatus::Skipped,
        ],
        event: StageRunEvent::Supersede,
        guard: Guard::UpstreamInvalidated,
        to: StageRunStatus::Superseded,
        actors: &[Actor::Engine],
        emits: Some("stage_run.superseded"),
    },
    Transition {
        id: "S21",
        from: &[StageRunStatus::Running],
        event: StageRunEvent::AttemptBlocked,
        guard: Guard::EnvironmentBlocked,
        to: StageRunStatus::Blocked,
        actors: &[Actor::Engine],
        emits: Some("stage_run.blocked"),
    },
    Transition {
        id: "S22",
        from: &[StageRunStatus::Ready],
        event: StageRunEvent::RequireReauthorization,
        guard: Guard::ReauthorizationRequired,
        to: StageRunStatus::WaitingForHuman,
        actors: &[Actor::Engine],
        emits: Some("stage_run.waiting_for_human"),
    },
];

impl Status for StageRunStatus {
    type Event = StageRunEvent;
    const MACHINE: &'static str = "stage_run";
    const TRANSITION_PREFIX: char = 'S';
    const INITIAL: Self = StageRunStatus::Pending;
    const STATES: &'static [Self] = StageRunStatus::ALL;
    const EVENTS: &'static [StageRunEvent] = StageRunEvent::ALL;
    const TRANSITIONS: &'static [Transition<Self, StageRunEvent>] = STAGE_RUN_TRANSITIONS;

    fn is_terminal(self) -> bool {
        matches!(
            self,
            StageRunStatus::Passed
                | StageRunStatus::ReworkRequested
                | StageRunStatus::Failed
                | StageRunStatus::Skipped
                | StageRunStatus::Superseded
                | StageRunStatus::Cancelled
        )
    }

    fn parse_name(name: &str) -> Option<Self> {
        Self::parse(name).ok()
    }
}
