use super::*;
use crate::contracts::stage_contract::RetryClass;
use crate::machines::failure::FailureClass;
use crate::machines::guards::RetryFacts;
use crate::machines::guards::stage_run::{
    escalation_required, retry_allowed, retry_exhausted_or_nonretryable,
};
use crate::state::{StageRunEvent, StageRunStatus, Status};

const ALL_RETRY: [RetryClass; 6] = [
    RetryClass::ToolError,
    RetryClass::InvalidOutput,
    RetryClass::ProviderError,
    RetryClass::SandboxError,
    RetryClass::TimedOut,
    RetryClass::LeaseLost,
];

fn facts<'a>(
    class: FailureClass,
    retry_on: &'a [RetryClass],
    used: u32,
    max: u32,
    budget: bool,
) -> RetryFacts<'a> {
    RetryFacts {
        class,
        retry_on,
        attempts_used: used,
        max_attempts: max,
        budget_has_room: budget,
    }
}

#[test]
fn a_listed_failure_with_attempts_and_budget_left_is_retried() {
    let decision =
        decide_after_failure(&facts(FailureClass::ProviderError, &ALL_RETRY, 1, 3, true));
    assert_eq!(decision, AttemptDisposition::Retry);
    assert_eq!(
        decision.stage_run_event(),
        StageRunEvent::AttemptFailedRetryable
    );
    assert_eq!(
        StageRunStatus::Running.apply(decision.stage_run_event()),
        Ok(StageRunStatus::Ready)
    );
}

#[test]
fn a_provider_outage_is_retried_but_a_policy_block_never_is() {
    let outage = decide_after_failure(&facts(FailureClass::ProviderError, &ALL_RETRY, 1, 3, true));
    let blocked = decide_after_failure(&facts(FailureClass::PolicyDenied, &ALL_RETRY, 1, 3, true));
    assert_eq!(outage, AttemptDisposition::Retry);
    assert_eq!(blocked, AttemptDisposition::Fail);
    assert_eq!(
        StageRunStatus::Running.apply(blocked.stage_run_event()),
        Ok(StageRunStatus::Failed)
    );
}

#[test]
fn a_timeout_is_retried_only_when_the_stage_contract_lists_it() {
    let listed = decide_after_failure(&facts(
        FailureClass::TimedOut,
        &[RetryClass::TimedOut],
        1,
        3,
        true,
    ));
    let unlisted = decide_after_failure(&facts(
        FailureClass::TimedOut,
        &[RetryClass::ProviderError],
        1,
        3,
        true,
    ));
    assert_eq!(listed, AttemptDisposition::Retry);
    assert_eq!(unlisted, AttemptDisposition::Fail);
}

#[test]
fn an_internal_fault_is_final_whatever_the_contract_lists() {
    assert_eq!(
        decide_after_failure(&facts(FailureClass::Internal, &ALL_RETRY, 0, 10, true)),
        AttemptDisposition::Fail
    );
}

#[test]
fn a_budget_that_ran_out_asks_a_human_and_does_not_fail_the_stage() {
    let decision = decide_after_failure(&facts(
        FailureClass::BudgetExhausted,
        &ALL_RETRY,
        1,
        3,
        true,
    ));
    assert_eq!(
        decision,
        AttemptDisposition::Escalate(EscalationCause::BudgetLimit)
    );
    assert_eq!(decision.stage_run_event(), StageRunEvent::EscalateToHuman);
    assert_eq!(
        StageRunStatus::Running.apply(decision.stage_run_event()),
        Ok(StageRunStatus::WaitingForHuman)
    );
}

#[test]
fn running_out_of_attempts_asks_a_human_instead_of_looping() {
    // INV-10: exhaustion escalates to a human and does not loop.
    let decision = decide_after_failure(&facts(FailureClass::ToolError, &ALL_RETRY, 3, 3, true));
    assert_eq!(
        decision,
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    );
}

#[test]
fn a_retryable_failure_with_no_budget_left_asks_a_human() {
    let decision = decide_after_failure(&facts(FailureClass::ToolError, &ALL_RETRY, 1, 3, false));
    assert_eq!(
        decision,
        AttemptDisposition::Escalate(EscalationCause::BudgetLimit)
    );
}

#[test]
fn an_always_failing_runtime_stops_retrying_within_max_attempts() {
    // The engine test for INV-10 in miniature: keep failing and count the retries.
    for max in 1..=10 {
        let mut used = 0;
        let mut retries = 0;
        let last = loop {
            used += 1;
            let decision = decide_after_failure(&facts(
                FailureClass::ProviderError,
                &ALL_RETRY,
                used,
                max,
                true,
            ));
            if decision != AttemptDisposition::Retry {
                break decision;
            }
            retries += 1;
            assert!(used <= max, "kept retrying past max_attempts={max}");
        };
        assert_eq!(retries, max - 1, "max_attempts={max}");
        assert_eq!(
            last,
            AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
        );
    }
}

#[test]
fn the_facts_an_escalation_cause_stands_for_satisfy_the_escalation_guard() {
    for cause in [EscalationCause::BudgetLimit, EscalationCause::AttemptLimit] {
        assert!(escalation_required(&cause.facts()).is_ok(), "{cause:?}");
    }
    assert!(EscalationCause::BudgetLimit.facts().budget_limit_hit);
    assert!(
        EscalationCause::AttemptLimit
            .facts()
            .policy_requires_human_decision
    );
}

#[test]
fn every_decision_is_backed_by_its_own_guard_over_a_grid_of_inputs() {
    let subsets: [&[RetryClass]; 3] = [&[], &[RetryClass::ProviderError], &ALL_RETRY];
    for class in FailureClass::ALL {
        for retry_on in subsets {
            for used in 0..=4 {
                for max in 1..=3 {
                    for budget in [false, true] {
                        let input = facts(*class, retry_on, used, max, budget);
                        let decision = decide_after_failure(&input);
                        match decision {
                            AttemptDisposition::Retry => {
                                assert!(retry_allowed(&input).is_ok(), "{input:?}");
                                assert!(used < max, "retried past the limit: {input:?}");
                            }
                            AttemptDisposition::Fail => assert!(
                                retry_exhausted_or_nonretryable(&input).is_ok()
                                    && retry_allowed(&input).is_err(),
                                "{input:?}"
                            ),
                            AttemptDisposition::Escalate(cause) => assert!(
                                escalation_required(&cause.facts()).is_ok()
                                    && retry_allowed(&input).is_err(),
                                "{input:?}"
                            ),
                        }
                        // The stage run machine accepts the event from RUNNING.
                        assert!(
                            StageRunStatus::Running
                                .apply(decision.stage_run_event())
                                .is_ok(),
                            "{input:?}"
                        );
                    }
                }
            }
        }
    }
}
