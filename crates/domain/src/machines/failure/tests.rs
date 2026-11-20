use super::*;
use crate::contracts::stage_contract::RetryClass;
use crate::state::{AttemptEvent, AttemptStatus, Status};

#[test]
fn the_failure_classes_are_the_ones_the_state_machine_names() {
    let names: Vec<&str> = FailureClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        names,
        [
            "TOOL_ERROR",
            "INVALID_OUTPUT",
            "BUDGET_EXHAUSTED",
            "POLICY_DENIED",
            "PROVIDER_ERROR",
            "SANDBOX_ERROR",
            "INTERNAL",
            "TIMED_OUT",
            "LEASE_LOST",
        ]
    );
}

#[test]
fn the_contract_can_list_only_six_classes_as_worth_retrying() {
    let pairs: Vec<(FailureClass, Option<RetryClass>)> = FailureClass::ALL
        .iter()
        .map(|c| (*c, c.retry_class()))
        .collect();
    assert_eq!(
        pairs,
        [
            (FailureClass::ToolError, Some(RetryClass::ToolError)),
            (FailureClass::InvalidOutput, Some(RetryClass::InvalidOutput)),
            (FailureClass::BudgetExhausted, None),
            (FailureClass::PolicyDenied, None),
            (FailureClass::ProviderError, Some(RetryClass::ProviderError)),
            (FailureClass::SandboxError, Some(RetryClass::SandboxError)),
            (FailureClass::Internal, None),
            (FailureClass::TimedOut, Some(RetryClass::TimedOut)),
            (FailureClass::LeaseLost, Some(RetryClass::LeaseLost)),
        ]
    );
}

#[test]
fn a_class_the_contract_cannot_list_is_never_retried() {
    let everything = [
        RetryClass::ToolError,
        RetryClass::InvalidOutput,
        RetryClass::ProviderError,
        RetryClass::SandboxError,
        RetryClass::TimedOut,
        RetryClass::LeaseLost,
    ];
    for class in [
        FailureClass::BudgetExhausted,
        FailureClass::PolicyDenied,
        FailureClass::Internal,
    ] {
        assert!(!class.is_retryable_under(&everything), "{class}");
    }
}

#[test]
fn a_listed_class_is_retried_and_an_unlisted_one_is_not() {
    let only_provider = [RetryClass::ProviderError];
    assert!(FailureClass::ProviderError.is_retryable_under(&only_provider));
    assert!(!FailureClass::ToolError.is_retryable_under(&only_provider));
    assert!(!FailureClass::TimedOut.is_retryable_under(&[]));
}

#[test]
fn each_class_ends_the_attempt_in_the_status_the_machine_names() {
    for class in FailureClass::ALL {
        let mut reached = 0;
        for from in AttemptStatus::STATES {
            if let Some(event) = class.attempt_event(*from) {
                assert_eq!(
                    from.apply(event),
                    Ok(class.attempt_status()),
                    "{class} from {from}"
                );
                reached += 1;
            }
        }
        assert!(reached > 0, "{class} can be recorded from no status at all");
    }
}

#[test]
fn a_timeout_and_a_lost_lease_are_found_by_the_sweeper_in_both_live_statuses() {
    for from in [AttemptStatus::Starting, AttemptStatus::Running] {
        assert_eq!(
            FailureClass::TimedOut.attempt_event(from),
            Some(AttemptEvent::DeadlineExceeded)
        );
        assert_eq!(
            FailureClass::LeaseLost.attempt_event(from),
            Some(AttemptEvent::LeaseExpired)
        );
    }
}

#[test]
fn a_sandbox_that_does_not_start_uses_the_provision_event() {
    assert_eq!(
        FailureClass::SandboxError.attempt_event(AttemptStatus::Starting),
        Some(AttemptEvent::ProvisionFailed)
    );
    assert_eq!(
        FailureClass::SandboxError.attempt_event(AttemptStatus::Running),
        Some(AttemptEvent::ReportFailure)
    );
}

#[test]
fn a_worker_reported_failure_is_only_legal_while_running() {
    for class in [
        FailureClass::ToolError,
        FailureClass::InvalidOutput,
        FailureClass::BudgetExhausted,
        FailureClass::PolicyDenied,
        FailureClass::ProviderError,
        FailureClass::Internal,
    ] {
        assert_eq!(
            class.attempt_event(AttemptStatus::Running),
            Some(AttemptEvent::ReportFailure),
            "{class}"
        );
        assert_eq!(
            class.attempt_event(AttemptStatus::Starting),
            None,
            "{class}"
        );
    }
}

#[test]
fn a_finished_attempt_records_no_failure() {
    for done in [
        AttemptStatus::Succeeded,
        AttemptStatus::Failed,
        AttemptStatus::TimedOut,
        AttemptStatus::LeaseLost,
        AttemptStatus::Cancelled,
        AttemptStatus::Cancelling,
    ] {
        for class in FailureClass::ALL {
            assert_eq!(class.attempt_event(done), None, "{class} from {done}");
        }
    }
}
