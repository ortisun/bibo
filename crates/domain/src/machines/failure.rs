//! Why an attempt ended badly, and what each reason means for the attempt machine.
//!
//! `state-machine.md` lists the failure classes of a `FAILED` attempt (`TOOL_ERROR`,
//! `INVALID_OUTPUT`, `BUDGET_EXHAUSTED`, `POLICY_DENIED`, `PROVIDER_ERROR`, `SANDBOX_ERROR` and
//! `INTERNAL`). Two more ways to end badly have a status of their own: `TIMED_OUT` and
//! `LEASE_LOST`. The stage contract treats all of these alike when it lists which ones are worth
//! retrying, so one type covers them.
//!
//! This file says what each class is and which attempt event records it. What happens to the
//! stage run next (retry, ask a human, or fail) is a separate decision.

use crate::contracts::stage_contract::RetryClass;
use crate::macros::string_enum;
use crate::state::{AttemptEvent, AttemptStatus, Status};

string_enum! {
    /// How an attempt ended without producing a valid result.
    pub enum FailureClass("failure class") {
        /// A tool the attempt used failed.
        ToolError = "TOOL_ERROR",
        /// The output did not match the stage outputs schema.
        InvalidOutput = "INVALID_OUTPUT",
        /// A budget limit was hit. Never retried: the same budget would be hit again.
        BudgetExhausted = "BUDGET_EXHAUSTED",
        /// Policy denied something the attempt tried. Never retried: policy does not change
        /// between tries.
        PolicyDenied = "POLICY_DENIED",
        /// The model provider failed or was unavailable.
        ProviderError = "PROVIDER_ERROR",
        /// The sandbox could not start or failed while running.
        SandboxError = "SANDBOX_ERROR",
        /// A fault in the factory itself. The stage contract cannot list it as retryable.
        Internal = "INTERNAL",
        /// The attempt deadline passed.
        TimedOut = "TIMED_OUT",
        /// The lease expired without a heartbeat.
        LeaseLost = "LEASE_LOST",
    }
}

impl FailureClass {
    /// The matching class the stage contract can list in `retry_on`, or `None` when the contract
    /// cannot list this class at all. A class with no match is never retried, whatever the
    /// contract says.
    #[must_use]
    pub const fn retry_class(self) -> Option<RetryClass> {
        match self {
            FailureClass::ToolError => Some(RetryClass::ToolError),
            FailureClass::InvalidOutput => Some(RetryClass::InvalidOutput),
            FailureClass::ProviderError => Some(RetryClass::ProviderError),
            FailureClass::SandboxError => Some(RetryClass::SandboxError),
            FailureClass::TimedOut => Some(RetryClass::TimedOut),
            FailureClass::LeaseLost => Some(RetryClass::LeaseLost),
            FailureClass::BudgetExhausted | FailureClass::PolicyDenied | FailureClass::Internal => {
                None
            }
        }
    }

    /// True when the stage contract lists this class in `retry_on`.
    #[must_use]
    pub fn is_retryable_under(self, retry_on: &[RetryClass]) -> bool {
        self.retry_class()
            .is_some_and(|class| retry_on.contains(&class))
    }

    /// The terminal status an attempt reaches when it ends this way.
    #[must_use]
    pub const fn attempt_status(self) -> AttemptStatus {
        match self {
            FailureClass::TimedOut => AttemptStatus::TimedOut,
            FailureClass::LeaseLost => AttemptStatus::LeaseLost,
            FailureClass::ToolError
            | FailureClass::InvalidOutput
            | FailureClass::BudgetExhausted
            | FailureClass::PolicyDenied
            | FailureClass::ProviderError
            | FailureClass::SandboxError
            | FailureClass::Internal => AttemptStatus::Failed,
        }
    }

    /// The attempt event that records this failure while the attempt is in `from`, or `None`
    /// when the attempt machine has no such move from that status.
    ///
    /// * A timeout and a lost lease are found by the sweeper, in either live status.
    /// * A sandbox that fails to start uses `provision_failed`, which is the only failure legal
    ///   in `STARTING`.
    /// * Every other class is reported with `report_failure`, which is legal only in `RUNNING`.
    #[must_use]
    pub fn attempt_event(self, from: AttemptStatus) -> Option<AttemptEvent> {
        let event = match (self, from) {
            (FailureClass::TimedOut, _) => AttemptEvent::DeadlineExceeded,
            (FailureClass::LeaseLost, _) => AttemptEvent::LeaseExpired,
            (FailureClass::SandboxError, AttemptStatus::Starting) => AttemptEvent::ProvisionFailed,
            _ => AttemptEvent::ReportFailure,
        };
        from.apply(event).is_ok().then_some(event)
    }
}

#[cfg(test)]
mod tests;
