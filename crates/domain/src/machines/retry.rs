//! What a failed attempt does to its stage run.
//!
//! When an attempt ends badly, the stage run is in `RUNNING` and one of three things follows:
//!
//! * **Retry** (`S05`, `attempt_failed_retryable`): the stage run goes back to `READY` for
//!   another attempt, after a back-off.
//! * **Ask a human** (`S07`, `escalate_to_human`): the stage run goes to `WAITING_FOR_HUMAN`.
//! * **Fail** (`S06`, `attempt_failed_final`): the stage run goes to `FAILED`.
//!
//! The guards of `S05` and `S06` exclude each other, because the class is retryable for one and
//! not for the other. `S07` is legal whenever neither of them is, and also for
//! `BUDGET_EXHAUSTED`, which `G_FAILURE_NONRETRYABLE` leaves out on purpose. So the file lets a
//! failed attempt reach more than one move only through `S07`, and the order in which
//! [`decide_after_failure`] takes them follows `state-machine.json` and ADR 0010: a limit never
//! fails a stage run, it asks a person, and only a failure that retrying cannot fix fails it.
//!
//! | Order | The attempt failed with | Move |
//! |---|---|---|
//! | 0 | An environment cause (runtime unreachable, image absent, posture differs, spec weaker than policy, tool absent, policy unreadable) | `S21`, the stage run is blocked |
//! | 1 | `BUDGET_EXHAUSTED` | `S07`, and the job's broker token is revoked |
//! | 2 | A class the contract lists in `retry_on`, with attempts, repairs and budget left | `S05` |
//! | 3 | `POLICY_DENIED`, `INTERNAL`, or a class not in `retry_on` | `S06` |
//! | 4 | A class in `retry_on`, with no attempt or repair left, or with no budget | `S07` |
//!
//! # The attempt window
//!
//! Attempts and repairs are counted from the last human answer (`S13`). A person who answers a
//! stage run that stopped at its limit gets a new window, so the first failure after the answer
//! does not escalate again at once, and the total stays bounded because a person is in the loop
//! each time. [`AttemptWindow`] derives the two counts that [`RetryFacts`] carries from the
//! history of a stage run, so the restart at an answer is one rule in one place.
//!
//! A **repair** is a retry that follows an `INVALID_OUTPUT` failure. It also counts as an
//! attempt, so the attempt limit and the repair cap both apply, and the first to be reached
//! sends the stage run to a person.

use crate::machines::failure::FailureClass;
use crate::machines::guards::stage_run::retry_allowed;
use crate::machines::guards::{EnvironmentCause, EscalationFacts, RetryFacts};
use crate::state::StageRunEvent;

/// Why a failed attempt ends up with a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationCause {
    /// A budget limit was hit.
    BudgetLimit,
    /// The attempt limit or the repair cap was reached on a class the contract lists as
    /// retryable (INV-10).
    AttemptLimit,
}

impl EscalationCause {
    /// The facts for guard `G_ESCALATION_REQUIRED` that this cause stands for. The guard holds
    /// for them.
    #[must_use]
    pub const fn facts(self) -> EscalationFacts {
        match self {
            EscalationCause::BudgetLimit => EscalationFacts {
                budget_limit_hit: true,
                attempt_limit_reached: false,
                agent_requested_a_human: false,
                stagnation_detected: false,
                policy_requires_human_decision: false,
            },
            EscalationCause::AttemptLimit => EscalationFacts {
                budget_limit_hit: false,
                attempt_limit_reached: true,
                agent_requested_a_human: false,
                stagnation_detected: false,
                policy_requires_human_decision: false,
            },
        }
    }
}

/// What happens to the stage run after a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptDisposition {
    /// Try again.
    Retry,
    /// Ask a human.
    Escalate(EscalationCause),
    /// The stage run fails.
    Fail,
    /// The environment is missing or unsafe, so the stage run is blocked (`S21`). Nothing is
    /// retried and no other settings are tried.
    Block(EnvironmentCause),
}

impl AttemptDisposition {
    /// The stage run event that applies this disposition to a `RUNNING` stage run.
    #[must_use]
    pub const fn stage_run_event(self) -> StageRunEvent {
        match self {
            AttemptDisposition::Retry => StageRunEvent::AttemptFailedRetryable,
            AttemptDisposition::Escalate(_) => StageRunEvent::EscalateToHuman,
            AttemptDisposition::Fail => StageRunEvent::AttemptFailedFinal,
            AttemptDisposition::Block(_) => StageRunEvent::AttemptBlocked,
        }
    }
}

/// Decides what a failed attempt does to its stage run. See the module documentation for the
/// order and the table.
///
/// `facts.attempts_used` and `facts.invalid_output_failures` count the attempt that just failed
/// and only the attempts since the last human answer (see [`AttemptWindow`]).
#[must_use]
pub fn decide_after_failure(facts: &RetryFacts<'_>) -> AttemptDisposition {
    // 0. A missing or unsafe environment blocks the stage run, whatever else holds. Retrying
    // with the same settings cannot help, and a person is not asked to decide something that is
    // not a decision.
    if let Some(cause) = facts.environment {
        return AttemptDisposition::Block(cause);
    }
    // 1. A budget limit asks a person, whatever else holds.
    if facts.class == FailureClass::BudgetExhausted {
        return AttemptDisposition::Escalate(EscalationCause::BudgetLimit);
    }
    // 2. A retry, when the class, the attempts, the repairs and the budget all allow it.
    if retry_allowed(facts).is_ok() {
        return AttemptDisposition::Retry;
    }
    // 3. A failure that retrying cannot fix.
    if !facts.class_is_retryable() {
        return AttemptDisposition::Fail;
    }
    // 4. The class is worth retrying, so a limit stopped it: the attempts, the repair cap, or
    // the budget. The attempt limit and the repair cap are one cause, because a repair is an
    // attempt.
    if facts.attempts_remain() && facts.repairs_remain() {
        AttemptDisposition::Escalate(EscalationCause::BudgetLimit)
    } else {
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    }
}

/// One thing that happened to a stage run, as far as the attempt window counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEvent {
    /// An attempt ended with this failure class.
    AttemptFailed(FailureClass),
    /// A person answered the stage run (`S13`). The window starts again.
    HumanAnswered,
}

/// The attempts and the invalid outputs counted since the last human answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttemptWindow {
    attempts_used: u32,
    invalid_output_failures: u32,
}

impl AttemptWindow {
    /// The window after `history`, oldest event first. Include the failure that has just
    /// happened, because [`RetryFacts`] counts it.
    ///
    /// A retry only follows a failure, and a stage run that did not fail waits for a person
    /// before it can try again. So every attempt in a window except the last one failed, and
    /// counting failures counts attempts.
    #[must_use]
    pub fn from_history(history: &[WindowEvent]) -> Self {
        history
            .iter()
            .fold(Self::default(), |window, event| match event {
                WindowEvent::HumanAnswered => Self::default(),
                WindowEvent::AttemptFailed(class) => Self {
                    attempts_used: window.attempts_used.saturating_add(1),
                    invalid_output_failures: window
                        .invalid_output_failures
                        .saturating_add(u32::from(*class == FailureClass::InvalidOutput)),
                },
            })
    }

    /// Attempts used since the last human answer. Goes into [`RetryFacts::attempts_used`].
    #[must_use]
    pub const fn attempts_used(self) -> u32 {
        self.attempts_used
    }

    /// Attempts since the last human answer that failed with `INVALID_OUTPUT`. Goes into
    /// [`RetryFacts::invalid_output_failures`].
    #[must_use]
    pub const fn invalid_output_failures(self) -> u32 {
        self.invalid_output_failures
    }
}

#[cfg(test)]
mod tests;
