//! The Attempt state machine.
//!
//! One try at a stage run, owned by one worker through one lease. The attempt is created together with its lease, so there is no pre-lease state.
//!
//! Written from `docs/architecture/state-machine.json`. If the file changes, change this one to match;
//! `tests/state_machine_conformance.rs` compares every status, event and transition with
//! the file, in both directions.

use super::{Actor, Guard, Status, Transition};
use crate::macros::string_enum;

string_enum! {
    /// The status of a attempt. The spelling of each value is the one stored in
    /// the database and written in documents.
    pub enum AttemptStatus("attempt status") {
        /// Lease acquired. Sandbox and agent runtime are being prepared.
        Starting = "STARTING",
        /// The agent or tool is executing and the worker is heartbeating.
        Running = "RUNNING",
        /// Cancel requested. Teardown in progress. Reports are kept for audit and cannot change the outcome.
        Cancelling = "CANCELLING",
        /// Output received, validated against the outputs schema and stored. Says nothing about quality; the gate decides that.
        Succeeded = "SUCCEEDED",
        /// Ended with a failure class: TOOL_ERROR, INVALID_OUTPUT, BUDGET_EXHAUSTED, POLICY_DENIED, PROVIDER_ERROR, SANDBOX_ERROR or INTERNAL.
        Failed = "FAILED",
        /// The attempt deadline passed. The sandbox is killed.
        TimedOut = "TIMED_OUT",
        /// The lease expired without heartbeat. The worker is presumed dead. Its later writes are rejected by the lease epoch.
        LeaseLost = "LEASE_LOST",
        /// Torn down after a cancel request.
        Cancelled = "CANCELLED",
    }
}

string_enum! {
    /// An event that asks the attempt machine to move.
    pub enum AttemptEvent("attempt event") {
        SandboxReady = "sandbox_ready",
        ProvisionFailed = "provision_failed",
        Heartbeat = "heartbeat",
        ReportSuccess = "report_success",
        ReportFailure = "report_failure",
        DeadlineExceeded = "deadline_exceeded",
        LeaseExpired = "lease_expired",
        RequestCancel = "request_cancel",
        TeardownComplete = "teardown_complete",
        TeardownDeadline = "teardown_deadline",
    }
}

/// Every legal attempt transition, in the order of the file.
pub static ATTEMPT_TRANSITIONS: &[Transition<AttemptStatus, AttemptEvent>] = &[
    Transition {
        id: "A01",
        from: &[AttemptStatus::Starting],
        event: AttemptEvent::SandboxReady,
        guard: Guard::SandboxProvisioned,
        to: AttemptStatus::Running,
        actors: &[Actor::Worker],
        emits: Some("attempt.running"),
    },
    Transition {
        id: "A02",
        from: &[AttemptStatus::Starting],
        event: AttemptEvent::ProvisionFailed,
        guard: Guard::EpochCurrent,
        to: AttemptStatus::Failed,
        actors: &[Actor::Worker],
        emits: Some("attempt.failed"),
    },
    Transition {
        id: "A03",
        from: &[AttemptStatus::Running],
        event: AttemptEvent::Heartbeat,
        guard: Guard::LeaseEpochCurrent,
        to: AttemptStatus::Running,
        actors: &[Actor::Worker],
        emits: None,
    },
    Transition {
        id: "A04",
        from: &[AttemptStatus::Running],
        event: AttemptEvent::ReportSuccess,
        guard: Guard::OutputSchemaValid,
        to: AttemptStatus::Succeeded,
        actors: &[Actor::Worker],
        emits: Some("attempt.succeeded"),
    },
    Transition {
        id: "A05",
        from: &[AttemptStatus::Running],
        event: AttemptEvent::ReportFailure,
        guard: Guard::EpochCurrent,
        to: AttemptStatus::Failed,
        actors: &[Actor::Worker, Actor::Engine],
        emits: Some("attempt.failed"),
    },
    Transition {
        id: "A06",
        from: &[AttemptStatus::Starting, AttemptStatus::Running],
        event: AttemptEvent::DeadlineExceeded,
        guard: Guard::DeadlinePassed,
        to: AttemptStatus::TimedOut,
        actors: &[Actor::Sweeper],
        emits: Some("attempt.timed_out"),
    },
    Transition {
        id: "A07",
        from: &[AttemptStatus::Starting, AttemptStatus::Running],
        event: AttemptEvent::LeaseExpired,
        guard: Guard::LeaseExpired,
        to: AttemptStatus::LeaseLost,
        actors: &[Actor::Sweeper],
        emits: Some("attempt.lease_lost"),
    },
    Transition {
        id: "A08",
        from: &[AttemptStatus::Starting, AttemptStatus::Running],
        event: AttemptEvent::RequestCancel,
        guard: Guard::CancelAllowed,
        to: AttemptStatus::Cancelling,
        actors: &[Actor::Engine],
        emits: Some("attempt.cancel_requested"),
    },
    Transition {
        id: "A09",
        from: &[AttemptStatus::Cancelling],
        event: AttemptEvent::TeardownComplete,
        guard: Guard::SandboxGone,
        to: AttemptStatus::Cancelled,
        actors: &[Actor::Worker, Actor::Sweeper],
        emits: Some("attempt.cancelled"),
    },
    Transition {
        id: "A10",
        from: &[AttemptStatus::Cancelling],
        event: AttemptEvent::TeardownDeadline,
        guard: Guard::TeardownDeadlinePassed,
        to: AttemptStatus::Cancelled,
        actors: &[Actor::Sweeper],
        emits: Some("attempt.cancelled"),
    },
];

impl Status for AttemptStatus {
    type Event = AttemptEvent;
    const MACHINE: &'static str = "attempt";
    const TRANSITION_PREFIX: char = 'A';
    const INITIAL: Self = AttemptStatus::Starting;
    const STATES: &'static [Self] = AttemptStatus::ALL;
    const EVENTS: &'static [AttemptEvent] = AttemptEvent::ALL;
    const TRANSITIONS: &'static [Transition<Self, AttemptEvent>] = ATTEMPT_TRANSITIONS;

    fn is_terminal(self) -> bool {
        matches!(
            self,
            AttemptStatus::Succeeded
                | AttemptStatus::Failed
                | AttemptStatus::TimedOut
                | AttemptStatus::LeaseLost
                | AttemptStatus::Cancelled
        )
    }

    fn parse_name(name: &str) -> Option<Self> {
        Self::parse(name).ok()
    }
}
