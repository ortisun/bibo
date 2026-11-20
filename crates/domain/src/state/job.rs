//! The Job state machine.
//!
//! Lifecycle of one request. Says whether the factory is still working on it, not how far the work has been verified. Verification maturity is tracked separately as assurance levels.
//!
//! Written from `docs/architecture/state-machine.json`. If the file changes, change this one to match;
//! `tests/state_machine_conformance.rs` compares every status, event and transition with
//! the file, in both directions.

use super::{Actor, Guard, Status, Transition};
use crate::macros::string_enum;

string_enum! {
    /// The status of a job. The spelling of each value is the one stored in
    /// the database and written in documents.
    pub enum JobStatus("job status") {
        /// The request passed authorization at the API boundary and is stored. Not yet admitted.
        Received = "RECEIVED",
        /// Stage runs are being scheduled and executed.
        Active = "ACTIVE",
        /// At least one stage run needs a human answer, decision or approval.
        WaitingForHuman = "WAITING_FOR_HUMAN",
        /// An operator paused the job. No new attempt is leased. Running attempts finish or time out.
        Paused = "PAUSED",
        /// A stage run cannot proceed or be promoted without an explicit disposition.
        Blocked = "BLOCKED",
        /// Cancellation was requested. Attempts and sandboxes are being torn down.
        Cancelling = "CANCELLING",
        /// Every stage in the job's configured scope passed and the approval decision is recorded. This does not mean merged, released or deployed, and it says nothing about verification maturity.
        Completed = "COMPLETED",
        /// The job cannot continue and no rework route or budget remains.
        Failed = "FAILED",
        /// Cancelled by an authorized human and fully torn down.
        Cancelled = "CANCELLED",
        /// Refused at admission, declined at intake, or rejected by an approver.
        Rejected = "REJECTED",
    }
}

string_enum! {
    /// An event that asks the job machine to move.
    pub enum JobEvent("job event") {
        Admit = "admit",
        RejectAtAdmission = "reject_at_admission",
        StageNeedsHuman = "stage_needs_human",
        HumanWaitResolved = "human_wait_resolved",
        Pause = "pause",
        Resume = "resume",
        Block = "block",
        Unblock = "unblock",
        RequestCancel = "request_cancel",
        CancellationComplete = "cancellation_complete",
        FailJob = "fail_job",
        RejectJob = "reject_job",
        Complete = "complete",
    }
}

/// Every legal job transition, in the order of the file.
pub static JOB_TRANSITIONS: &[Transition<JobStatus, JobEvent>] = &[
    Transition {
        id: "J01",
        from: &[JobStatus::Received],
        event: JobEvent::Admit,
        guard: Guard::AdmissionOk,
        to: JobStatus::Active,
        actors: &[Actor::Engine],
        emits: Some("job.admitted"),
    },
    Transition {
        id: "J02",
        from: &[JobStatus::Received],
        event: JobEvent::RejectAtAdmission,
        guard: Guard::AdmissionDenied,
        to: JobStatus::Rejected,
        actors: &[Actor::Engine],
        emits: Some("job.rejected"),
    },
    Transition {
        id: "J03",
        from: &[JobStatus::Active],
        event: JobEvent::StageNeedsHuman,
        guard: Guard::AnyStageWaiting,
        to: JobStatus::WaitingForHuman,
        actors: &[Actor::Engine],
        emits: Some("job.waiting_for_human"),
    },
    Transition {
        id: "J04",
        from: &[JobStatus::WaitingForHuman],
        event: JobEvent::HumanWaitResolved,
        guard: Guard::NoStageWaiting,
        to: JobStatus::Active,
        actors: &[Actor::Engine],
        emits: Some("job.resumed"),
    },
    Transition {
        id: "J05",
        from: &[JobStatus::Active, JobStatus::WaitingForHuman],
        event: JobEvent::Pause,
        guard: Guard::ActorMayPause,
        to: JobStatus::Paused,
        actors: &[Actor::Operator],
        emits: Some("job.paused"),
    },
    Transition {
        id: "J06",
        from: &[JobStatus::Paused],
        event: JobEvent::Resume,
        guard: Guard::ActorMayPause,
        to: JobStatus::Active,
        actors: &[Actor::Operator],
        emits: Some("job.resumed"),
    },
    Transition {
        id: "J07",
        from: &[JobStatus::Active],
        event: JobEvent::Block,
        guard: Guard::AnyStageBlocked,
        to: JobStatus::Blocked,
        actors: &[Actor::Engine],
        emits: Some("job.blocked"),
    },
    Transition {
        id: "J08",
        from: &[JobStatus::Blocked],
        event: JobEvent::Unblock,
        guard: Guard::BlockDispositionsRecorded,
        to: JobStatus::Active,
        actors: &[Actor::Operator, Actor::SecurityApprover],
        emits: Some("job.unblocked"),
    },
    Transition {
        id: "J09",
        from: &[
            JobStatus::Active,
            JobStatus::WaitingForHuman,
            JobStatus::Paused,
            JobStatus::Blocked,
        ],
        event: JobEvent::RequestCancel,
        guard: Guard::ActorMayCancel,
        to: JobStatus::Cancelling,
        actors: &[Actor::Requester, Actor::Operator],
        emits: Some("job.cancel_requested"),
    },
    Transition {
        id: "J10",
        from: &[JobStatus::Cancelling],
        event: JobEvent::CancellationComplete,
        guard: Guard::AllAttemptsTerminal,
        to: JobStatus::Cancelled,
        actors: &[Actor::Engine, Actor::Sweeper],
        emits: Some("job.cancelled"),
    },
    Transition {
        id: "J11",
        from: &[JobStatus::Active],
        event: JobEvent::FailJob,
        guard: Guard::Unrecoverable,
        to: JobStatus::Failed,
        actors: &[Actor::Engine],
        emits: Some("job.failed"),
    },
    Transition {
        id: "J12",
        from: &[JobStatus::Active, JobStatus::WaitingForHuman],
        event: JobEvent::RejectJob,
        guard: Guard::RejectionRecorded,
        to: JobStatus::Rejected,
        actors: &[Actor::Engine, Actor::Approver],
        emits: Some("job.rejected"),
    },
    Transition {
        id: "J13",
        from: &[JobStatus::Active],
        event: JobEvent::Complete,
        guard: Guard::PipelineScopeComplete,
        to: JobStatus::Completed,
        actors: &[Actor::Engine],
        emits: Some("job.completed"),
    },
];

impl Status for JobStatus {
    type Event = JobEvent;
    const MACHINE: &'static str = "job";
    const TRANSITION_PREFIX: char = 'J';
    const INITIAL: Self = JobStatus::Received;
    const STATES: &'static [Self] = JobStatus::ALL;
    const EVENTS: &'static [JobEvent] = JobEvent::ALL;
    const TRANSITIONS: &'static [Transition<Self, JobEvent>] = JOB_TRANSITIONS;

    fn is_terminal(self) -> bool {
        matches!(
            self,
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled | JobStatus::Rejected
        )
    }

    fn parse_name(name: &str) -> Option<Self> {
        Self::parse(name).ok()
    }
}
