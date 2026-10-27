//! The Task node (Slice 1 minimal) state machine.
//!
//! Status of one node of the task DAG. In Slice 1 the DAG runs sequentially inside a single IMPLEMENTATION attempt, so task nodes are bookkeeping for resume and evidence, not independently leased work. Slice 3 replaces this with independently leased work items and supersedes this section.
//!
//! Written from `docs/architecture/state-machine.json`. If the file changes, change this one to match;
//! `tests/state_machine_conformance.rs` compares every status, event and transition with
//! the file, in both directions.

use super::{Actor, Guard, Status, Transition};
use crate::macros::string_enum;

string_enum! {
    /// The status of a task node (slice 1 minimal). The spelling of each value is the one stored in
    /// the database and written in documents.
    pub enum TaskNodeStatus("task node status") {
        /// Waiting for dependencies.
        Pending = "PENDING",
        /// All dependencies succeeded. Next in topological order.
        Ready = "READY",
        /// The IMPLEMENTATION attempt is working on it.
        Running = "RUNNING",
        /// A commit exists and the per-task checks passed.
        Succeeded = "SUCCEEDED",
        /// The attempt could not complete this task. Can be retried.
        Failed = "FAILED",
        /// Cancelled with the stage run.
        Cancelled = "CANCELLED",
    }
}

string_enum! {
    /// An event that asks the task node machine to move.
    pub enum TaskNodeEvent("task node event") {
        DependenciesSatisfied = "dependencies_satisfied",
        Start = "start",
        TaskSucceeded = "task_succeeded",
        TaskFailed = "task_failed",
        AttemptInterrupted = "attempt_interrupted",
        RetryTask = "retry_task",
        Cancel = "cancel",
    }
}

/// Every legal task node transition, in the order of the file.
pub static TASK_NODE_TRANSITIONS: &[Transition<TaskNodeStatus, TaskNodeEvent>] = &[
    Transition {
        id: "T01",
        from: &[TaskNodeStatus::Pending],
        event: TaskNodeEvent::DependenciesSatisfied,
        guard: Guard::TaskDepsSucceeded,
        to: TaskNodeStatus::Ready,
        actors: &[Actor::Engine],
        emits: Some("task_node.ready"),
    },
    Transition {
        id: "T02",
        from: &[TaskNodeStatus::Ready],
        event: TaskNodeEvent::Start,
        guard: Guard::TaskStartedByAttempt,
        to: TaskNodeStatus::Running,
        actors: &[Actor::Engine],
        emits: Some("task_node.started"),
    },
    Transition {
        id: "T03",
        from: &[TaskNodeStatus::Running],
        event: TaskNodeEvent::TaskSucceeded,
        guard: Guard::TaskEvidenceRecorded,
        to: TaskNodeStatus::Succeeded,
        actors: &[Actor::Engine],
        emits: Some("task_node.succeeded"),
    },
    Transition {
        id: "T04",
        from: &[TaskNodeStatus::Running],
        event: TaskNodeEvent::TaskFailed,
        guard: Guard::EpochCurrent,
        to: TaskNodeStatus::Failed,
        actors: &[Actor::Engine],
        emits: Some("task_node.failed"),
    },
    Transition {
        id: "T05",
        from: &[TaskNodeStatus::Running],
        event: TaskNodeEvent::AttemptInterrupted,
        guard: Guard::EpochCurrent,
        to: TaskNodeStatus::Ready,
        actors: &[Actor::Engine],
        emits: Some("task_node.ready"),
    },
    Transition {
        id: "T06",
        from: &[TaskNodeStatus::Failed],
        event: TaskNodeEvent::RetryTask,
        guard: Guard::TaskRetryAllowed,
        to: TaskNodeStatus::Ready,
        actors: &[Actor::Engine],
        emits: Some("task_node.ready"),
    },
    Transition {
        id: "T07",
        from: &[
            TaskNodeStatus::Pending,
            TaskNodeStatus::Ready,
            TaskNodeStatus::Running,
            TaskNodeStatus::Failed,
        ],
        event: TaskNodeEvent::Cancel,
        guard: Guard::NoActiveAttempt,
        to: TaskNodeStatus::Cancelled,
        actors: &[Actor::Engine],
        emits: Some("task_node.cancelled"),
    },
];

impl Status for TaskNodeStatus {
    type Event = TaskNodeEvent;
    const MACHINE: &'static str = "task_node";
    const TRANSITION_PREFIX: char = 'T';
    const INITIAL: Self = TaskNodeStatus::Pending;
    const STATES: &'static [Self] = TaskNodeStatus::ALL;
    const EVENTS: &'static [TaskNodeEvent] = TaskNodeEvent::ALL;
    const TRANSITIONS: &'static [Transition<Self, TaskNodeEvent>] = TASK_NODE_TRANSITIONS;

    fn is_terminal(self) -> bool {
        matches!(self, TaskNodeStatus::Succeeded | TaskNodeStatus::Cancelled)
    }

    fn parse_name(name: &str) -> Option<Self> {
        Self::parse(name).ok()
    }
}
