//! The Job, StageRun, Attempt and TaskNode state machines.
//!
//! `docs/architecture/state-machine.json` is the single source of truth for which moves are legal.
//! This module holds the same information as code: a status enum and an event enum for each
//! machine, and a table of transitions. A move that the table does not list is rejected with an
//! [`IllegalTransition`] and the stored status stays as it was (invariant INV-02).
//!
//! The machines are pure. A transition says which status comes next, which guard must hold, who
//! may ask for it and which domain event it emits. Whether the guard holds is for the workflow
//! crate to decide, because guards need the database, the clock and policy. Applying the result
//! to storage is the engine's job, inside one transaction.
//!
//! `tests/state_machine_conformance.rs` embeds the JSON file and compares it with these tables in
//! both directions, so the code cannot drift from the documented machine.

mod attempt;
mod guard;
mod job;
mod stage_run;
mod task_node;

use std::fmt::{Debug, Display};
use std::hash::Hash;

pub use attempt::{ATTEMPT_TRANSITIONS, AttemptEvent, AttemptStatus};
pub use guard::{Actor, Guard};
pub use job::{JOB_TRANSITIONS, JobEvent, JobStatus};
pub use stage_run::{STAGE_RUN_TRANSITIONS, StageRunEvent, StageRunStatus};
pub use task_node::{TASK_NODE_TRANSITIONS, TaskNodeEvent, TaskNodeStatus};

/// One row of a transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition<S: 'static, E: 'static> {
    /// The id in `state-machine.json`, such as `S08`. Domain events carry it as their reason.
    pub id: &'static str,
    /// The statuses the move may start from.
    pub from: &'static [S],
    /// The event that asks for the move.
    pub event: E,
    /// The condition the engine must have established before it applies the move.
    pub guard: Guard,
    /// The status after the move.
    pub to: S,
    /// Who may ask for the move.
    pub actors: &'static [Actor],
    /// The domain event type the move emits, or `None` for a heartbeat.
    pub emits: Option<&'static str>,
}

/// A move that the state machine does not allow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the {machine} state machine has no transition from {from} on the event {event}")]
pub struct IllegalTransition {
    /// The machine, such as `job` or `stage_run`.
    pub machine: &'static str,
    /// The status the move started from.
    pub from: String,
    /// The event that was refused.
    pub event: String,
}

/// The status of one of the four machines, with the machine's whole table.
///
/// Implemented for [`JobStatus`], [`StageRunStatus`], [`AttemptStatus`] and [`TaskNodeStatus`].
pub trait Status: Copy + Eq + Hash + Debug + Display + 'static {
    /// The events that move this machine.
    type Event: Copy + Eq + Hash + Debug + Display + 'static;

    /// The machine's name in `state-machine.json`, such as `stage_run`.
    const MACHINE: &'static str;
    /// The letter that starts the id of every transition of this machine.
    const TRANSITION_PREFIX: char;
    /// The status a new aggregate starts in.
    const INITIAL: Self;
    /// Every status.
    const STATES: &'static [Self];
    /// Every event.
    const EVENTS: &'static [Self::Event];
    /// Every legal transition.
    const TRANSITIONS: &'static [Transition<Self, Self::Event>];

    /// True when the status is terminal. A terminal status has no exit, with one documented
    /// exception: a passed stage run can still be superseded.
    fn is_terminal(self) -> bool;

    /// Reads a status name, or returns `None` for text that is not a status of this machine.
    fn parse_name(name: &str) -> Option<Self>;

    /// Finds the transition that `event` triggers from this status.
    ///
    /// # Errors
    /// Returns [`IllegalTransition`] when the table does not list the pair.
    fn transition(
        self,
        event: Self::Event,
    ) -> Result<&'static Transition<Self, Self::Event>, IllegalTransition> {
        Self::TRANSITIONS
            .iter()
            .find(|row| row.event == event && row.from.contains(&self))
            .ok_or_else(|| IllegalTransition {
                machine: Self::MACHINE,
                from: self.to_string(),
                event: event.to_string(),
            })
    }

    /// The status after `event`, without changing anything.
    ///
    /// # Errors
    /// Returns [`IllegalTransition`] when the table does not list the pair.
    fn apply(self, event: Self::Event) -> Result<Self, IllegalTransition> {
        self.transition(event).map(|row| row.to)
    }

    /// Moves `self` to the next status. On an illegal move `self` is left as it was.
    ///
    /// # Errors
    /// Returns [`IllegalTransition`] when the table does not list the pair.
    fn advance(
        &mut self,
        event: Self::Event,
    ) -> Result<&'static Transition<Self, Self::Event>, IllegalTransition> {
        let row = self.transition(event)?;
        *self = row.to;
        Ok(row)
    }

    /// The events that are legal from this status, in declaration order.
    fn legal_events(self) -> Vec<Self::Event> {
        Self::EVENTS
            .iter()
            .copied()
            .filter(|event| self.transition(*event).is_ok())
            .collect()
    }
}
