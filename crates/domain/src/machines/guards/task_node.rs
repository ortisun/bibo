//! Guards of the TaskNode machine (transitions `T01` to `T07`).
//!
//! `G_EPOCH_CURRENT` (`T04`, `T05`) is in [`attempt`](super::attempt) and `G_NO_ACTIVE_ATTEMPT`
//! (`T07`) is there too, because both read attempts.

use super::digest::facts;
use super::{Check, GuardResult};
use crate::ids::TaskNodeId;
use crate::state::{Guard, TaskNodeStatus};

facts! {
/// What decides whether a task node can leave `PENDING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskDepsFacts<'a> {
    /// The status of every task this node depends on.
    pub dependencies: &'a [TaskNodeStatus],
}
}

/// `G_TASK_DEPS_SUCCEEDED`. A node with no dependency is ready at once.
///
/// # Errors
/// Returns the unmet condition.
pub fn task_deps_succeeded(facts: &TaskDepsFacts<'_>) -> GuardResult {
    Check::new(Guard::TaskDepsSucceeded)
        .require(
            facts
                .dependencies
                .iter()
                .all(|status| *status == TaskNodeStatus::Succeeded),
            "a task this node depends on has not succeeded",
        )
        .finish()
}

facts! {
/// What decides whether a task node starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStartFacts {
    /// The node.
    pub this_task: TaskNodeId,
    /// The task the `IMPLEMENTATION` attempt picked as the next one in topological order.
    pub next_in_topological_order: Option<TaskNodeId>,
}
}

/// `G_TASK_STARTED_BY_ATTEMPT`.
///
/// # Errors
/// Returns the unmet condition.
pub fn task_started_by_attempt(facts: &TaskStartFacts) -> GuardResult {
    Check::new(Guard::TaskStartedByAttempt)
        .require(
            facts.next_in_topological_order == Some(facts.this_task),
            "the attempt did not pick this task as the next one in topological order",
        )
        .finish()
}

facts! {
/// What decides whether a task counts as done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskEvidenceFacts {
    /// A commit exists for the task.
    pub commit_exists_for_task: bool,
    /// Every changed path is inside the task's owned files.
    pub changed_paths_inside_owned_files: bool,
    /// A protected path changed.
    pub protected_path_changed: bool,
    /// The per-task checks passed.
    pub per_task_checks_passed: bool,
}
}

/// `G_TASK_EVIDENCE_RECORDED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn task_evidence_recorded(facts: &TaskEvidenceFacts) -> GuardResult {
    Check::new(Guard::TaskEvidenceRecorded)
        .require(
            facts.commit_exists_for_task,
            "no commit exists for the task",
        )
        .require(
            facts.changed_paths_inside_owned_files,
            "a changed path is outside the task's owned files",
        )
        .require(!facts.protected_path_changed, "a protected path changed")
        .require(
            facts.per_task_checks_passed,
            "the per-task checks did not pass",
        )
        .finish()
}

facts! {
/// What decides whether a failed task is tried again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRetryFacts {
    /// Retries used on this task.
    pub retries_used: u32,
    /// The per-task retry limit.
    pub per_task_limit: u32,
    /// The stage budget has room.
    pub stage_budget_has_room: bool,
}
}

/// `G_TASK_RETRY_ALLOWED`.
///
/// # Errors
/// Returns the conditions that are not met.
pub fn task_retry_allowed(facts: &TaskRetryFacts) -> GuardResult {
    Check::new(Guard::TaskRetryAllowed)
        .require(
            facts.retries_used < facts.per_task_limit,
            "the task retry count has reached the per-task limit",
        )
        .require(facts.stage_budget_has_room, "the stage budget has no room")
        .finish()
}
