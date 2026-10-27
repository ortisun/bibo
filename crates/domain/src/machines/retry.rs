//! What a failed attempt does to its stage run.
//!
//! When an attempt ends badly, the stage run is in `RUNNING` and one of three things follows:
//!
//! * **Retry** (`S05`, `attempt_failed_retryable`): the stage run goes back to `READY` for
//!   another attempt, after a back-off.
//! * **Ask a human** (`S07`, `escalate_to_human`): the stage run goes to `WAITING_FOR_HUMAN`.
//! * **Fail** (`S06`, `attempt_failed_final`): the stage run goes to `FAILED`.
//!
//! The guards of those three transitions are not mutually exclusive, and the file does not say
//! which wins when more than one holds. [`decide_after_failure`] settles it with one rule:
//! **retry when allowed, otherwise ask a human when a limit was hit, otherwise fail.**
//!
//! | Failure | Attempts and budget | Result |
//! |---|---|---|
//! | Listed in the contract's `retry_on` | attempts left and budget has room | retry |
//! | Listed in `retry_on` | attempts used up | ask a human (invariant INV-10) |
//! | Listed in `retry_on` | attempts left, budget gone | ask a human (a budget limit was hit) |
//! | `BUDGET_EXHAUSTED` | any | ask a human (a budget limit was hit) |
//! | `POLICY_DENIED`, `INTERNAL`, or not in `retry_on` | any | fail |
//!
//! The rows that ask a human are where the file disagrees with itself. Guard
//! `G_RETRY_EXHAUSTED_OR_NONRETRYABLE` is true when `max_attempts` is reached, which would let
//! `S06` fail the stage. Invariant INV-10 and the ground rule "reaching a limit sends the stage
//! to a human" say a human decides. `S06` stays legal in those rows, because its guard holds. This
//! function chooses `S07`, because failing a stage on a transient provider outage is hard to
//! undo and asking a human is not. The choice is in this one function so it is cheap to change.

use crate::machines::failure::FailureClass;
use crate::machines::guards::stage_run::retry_allowed;
use crate::machines::guards::{EscalationFacts, RetryFacts};
use crate::state::StageRunEvent;

/// Why a failed attempt ends up with a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationCause {
    /// A budget limit was hit.
    BudgetLimit,
    /// The attempt limit was reached, and policy sends the decision to a human (INV-10).
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
                agent_requested_a_human: false,
                stagnation_detected: false,
                policy_requires_human_decision: false,
            },
            EscalationCause::AttemptLimit => EscalationFacts {
                budget_limit_hit: false,
                agent_requested_a_human: false,
                stagnation_detected: false,
                policy_requires_human_decision: true,
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
}

impl AttemptDisposition {
    /// The stage run event that applies this disposition to a `RUNNING` stage run.
    #[must_use]
    pub const fn stage_run_event(self) -> StageRunEvent {
        match self {
            AttemptDisposition::Retry => StageRunEvent::AttemptFailedRetryable,
            AttemptDisposition::Escalate(_) => StageRunEvent::EscalateToHuman,
            AttemptDisposition::Fail => StageRunEvent::AttemptFailedFinal,
        }
    }
}

/// Decides what a failed attempt does to its stage run. See the module documentation for the
/// rule and the table.
///
/// `facts.attempts_used` counts the attempt that just failed.
#[must_use]
pub fn decide_after_failure(facts: &RetryFacts<'_>) -> AttemptDisposition {
    if facts.class == FailureClass::BudgetExhausted {
        return AttemptDisposition::Escalate(EscalationCause::BudgetLimit);
    }
    if retry_allowed(facts).is_ok() {
        return AttemptDisposition::Retry;
    }
    if !facts.class_is_retryable() {
        return AttemptDisposition::Fail;
    }
    // The class is worth retrying, so either the attempts or the budget ran out.
    if facts.attempts_remain() {
        AttemptDisposition::Escalate(EscalationCause::BudgetLimit)
    } else {
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    }
}

#[cfg(test)]
mod tests;
