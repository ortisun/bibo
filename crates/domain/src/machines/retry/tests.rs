use super::*;
use crate::contracts::stage_contract::RetryClass;
use crate::machines::failure::FailureClass;
use crate::machines::guards::RetryFacts;
use crate::machines::guards::stage_run::{
    escalation_required, failure_nonretryable, retry_allowed,
};
use crate::machines::limits::RepairCap;
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
        invalid_output_failures: 0,
        repair_cap: RepairCap::DEFAULT,
        environment: None,
    }
}

/// An `INVALID_OUTPUT` failure that is the `failures`-th invalid output of its window, with
/// attempts to spare.
fn invalid_output(failures: u32, cap: RepairCap) -> RetryFacts<'static> {
    RetryFacts {
        class: FailureClass::InvalidOutput,
        retry_on: &ALL_RETRY,
        attempts_used: failures,
        max_attempts: 10,
        budget_has_room: true,
        invalid_output_failures: failures,
        repair_cap: cap,
        environment: None,
    }
}

#[test]
fn a_missing_environment_blocks_before_anything_else() {
    use crate::machines::guards::EnvironmentCause;
    for cause in EnvironmentCause::ALL {
        // A class that would otherwise be retried, with attempts and budget to spare.
        let mut input = facts(FailureClass::SandboxError, &ALL_RETRY, 1, 3, true);
        input.environment = Some(*cause);
        let decision = decide_after_failure(&input);
        assert_eq!(decision, AttemptDisposition::Block(*cause), "{cause}");
        assert_eq!(decision.stage_run_event(), StageRunEvent::AttemptBlocked);
        assert_eq!(
            StageRunStatus::Running.apply(decision.stage_run_event()),
            Ok(StageRunStatus::Blocked)
        );
    }
}

#[test]
fn the_environment_blocks_ahead_of_a_budget_limit_and_a_non_retryable_class() {
    use crate::machines::guards::EnvironmentCause;
    for class in [
        FailureClass::BudgetExhausted,
        FailureClass::PolicyDenied,
        FailureClass::Internal,
    ] {
        let mut input = facts(class, &ALL_RETRY, 1, 3, true);
        input.environment = Some(EnvironmentCause::PostureMismatch);
        assert_eq!(
            decide_after_failure(&input),
            AttemptDisposition::Block(EnvironmentCause::PostureMismatch),
            "{class}"
        );
    }
}

#[test]
fn a_provision_failure_is_still_retried() {
    // ProvisionFailed, Timeout and ResourceExceeded are not environment causes: no cause is set.
    let input = facts(FailureClass::SandboxError, &ALL_RETRY, 1, 3, true);
    assert_eq!(input.environment, None);
    assert_eq!(decide_after_failure(&input), AttemptDisposition::Retry);
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
fn the_first_two_repairs_are_retried_and_the_third_asks_a_human() {
    let cap = RepairCap::DEFAULT;
    assert_eq!(
        decide_after_failure(&invalid_output(1, cap)),
        AttemptDisposition::Retry
    );
    assert_eq!(
        decide_after_failure(&invalid_output(2, cap)),
        AttemptDisposition::Retry
    );
    // The repair cap is reported as the attempt limit, and the stage run waits for a person.
    let third = decide_after_failure(&invalid_output(3, cap));
    assert_eq!(
        third,
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    );
    assert_eq!(
        StageRunStatus::Running.apply(third.stage_run_event()),
        Ok(StageRunStatus::WaitingForHuman)
    );
}

#[test]
fn a_policy_that_lowers_the_repair_cap_stops_repairs_sooner_and_never_later() {
    assert_eq!(
        decide_after_failure(&invalid_output(1, RepairCap::from_policy(1))),
        AttemptDisposition::Retry
    );
    assert_eq!(
        decide_after_failure(&invalid_output(2, RepairCap::from_policy(1))),
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    );
    assert_eq!(
        decide_after_failure(&invalid_output(1, RepairCap::from_policy(0))),
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    );
    // A value above two is lowered to two, so the third repair is still refused.
    assert_eq!(
        decide_after_failure(&invalid_output(3, RepairCap::from_policy(200))),
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    );
}

#[test]
fn an_invalid_output_that_the_contract_does_not_list_fails_the_stage_run() {
    let mut input = invalid_output(1, RepairCap::DEFAULT);
    input.retry_on = &[RetryClass::ProviderError];
    assert_eq!(decide_after_failure(&input), AttemptDisposition::Fail);
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
    // The attempt limit names itself and no longer passes for a policy decision (ADR 0010).
    let attempt = EscalationCause::AttemptLimit.facts();
    assert!(attempt.attempt_limit_reached);
    assert!(!attempt.policy_requires_human_decision);
    assert!(!attempt.budget_limit_hit);
}

/// Every class, three contracts, and the counts around each limit.
fn grid(mut check: impl FnMut(&RetryFacts<'_>)) {
    let subsets: [&[RetryClass]; 3] = [&[], &[RetryClass::ProviderError], &ALL_RETRY];
    for class in FailureClass::ALL {
        for retry_on in subsets {
            for used in 0..=4 {
                for max in 1..=3 {
                    for budget in [false, true] {
                        for invalid in 0..=4 {
                            for cap in 0..=3 {
                                check(&RetryFacts {
                                    class: *class,
                                    retry_on,
                                    attempts_used: used,
                                    max_attempts: max,
                                    budget_has_room: budget,
                                    invalid_output_failures: invalid,
                                    repair_cap: RepairCap::from_policy(cap),
                                    environment: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn every_decision_is_backed_by_its_own_guard_over_a_grid_of_inputs() {
    grid(|input| {
        let decision = decide_after_failure(input);
        match decision {
            AttemptDisposition::Retry => {
                assert!(retry_allowed(input).is_ok(), "{input:?}");
                assert!(input.attempts_used < input.max_attempts, "{input:?}");
                assert!(failure_nonretryable(input).is_err(), "{input:?}");
            }
            AttemptDisposition::Fail => assert!(
                failure_nonretryable(input).is_ok() && retry_allowed(input).is_err(),
                "{input:?}"
            ),
            AttemptDisposition::Escalate(cause) => assert!(
                escalation_required(&cause.facts()).is_ok()
                    && retry_allowed(input).is_err()
                    && failure_nonretryable(input).is_err(),
                "{input:?}"
            ),
            AttemptDisposition::Block(_) => {
                panic!("the grid sets no environment cause, yet it blocked: {input:?}")
            }
        }
        // The stage run machine accepts the event from RUNNING.
        assert!(
            StageRunStatus::Running
                .apply(decision.stage_run_event())
                .is_ok(),
            "{input:?}"
        );
    });
}

#[test]
fn budget_and_attempt_limit_escalate_and_never_fail_the_stage_run() {
    // ADR 0010 and INV-10: a budget limit, an attempt limit and a repair cap choose S07 and
    // never S06, whatever the other facts are.
    let mut seen = [0_u32; 3];
    grid(|input| {
        let decision = decide_after_failure(input);
        let escalates = matches!(decision, AttemptDisposition::Escalate(_));
        if input.class == FailureClass::BudgetExhausted {
            seen[0] += 1;
            assert_eq!(
                decision,
                AttemptDisposition::Escalate(EscalationCause::BudgetLimit),
                "{input:?}"
            );
        }
        if input.class_is_retryable() && !input.attempts_remain() {
            seen[1] += 1;
            assert!(escalates, "{input:?}");
            assert!(failure_nonretryable(input).is_err(), "{input:?}");
        }
        if input.class == FailureClass::InvalidOutput
            && input.class_is_retryable()
            && input.invalid_output_failures > u32::from(input.repair_cap.get())
        {
            seen[2] += 1;
            assert!(escalates, "{input:?}");
            assert!(failure_nonretryable(input).is_err(), "{input:?}");
        }
        // Whenever the stage run fails, the class is one that retrying cannot fix.
        if decision == AttemptDisposition::Fail {
            assert!(!input.class_is_retryable(), "{input:?}");
            assert_ne!(input.class, FailureClass::BudgetExhausted, "{input:?}");
        }
    });
    assert!(seen.iter().all(|count| *count > 0), "{seen:?}");
}

// ---- the attempt window ------------------------------------------------------------------------------------

use FailureClass::{InvalidOutput, ToolError};

fn failed(class: FailureClass) -> WindowEvent {
    WindowEvent::AttemptFailed(class)
}

#[test]
fn a_new_window_has_used_nothing() {
    let window = AttemptWindow::from_history(&[]);
    assert_eq!(window.attempts_used(), 0);
    assert_eq!(window.invalid_output_failures(), 0);
}

#[test]
fn without_an_answer_every_failure_counts() {
    let window = AttemptWindow::from_history(&[
        failed(ToolError),
        failed(InvalidOutput),
        failed(ToolError),
        failed(InvalidOutput),
    ]);
    assert_eq!(window.attempts_used(), 4);
    assert_eq!(window.invalid_output_failures(), 2);
}

#[test]
fn a_human_answer_starts_a_new_window_for_attempts_and_repairs() {
    let window = AttemptWindow::from_history(&[
        failed(InvalidOutput),
        failed(InvalidOutput),
        failed(InvalidOutput),
        WindowEvent::HumanAnswered,
        failed(InvalidOutput),
    ]);
    assert_eq!(window.attempts_used(), 1);
    assert_eq!(window.invalid_output_failures(), 1);

    // An answer with nothing after it leaves an empty window, and a second answer changes nothing.
    let after_answers = AttemptWindow::from_history(&[
        failed(ToolError),
        WindowEvent::HumanAnswered,
        WindowEvent::HumanAnswered,
    ]);
    assert_eq!(after_answers, AttemptWindow::default());
}

#[test]
fn the_first_failure_after_an_answer_does_not_escalate_again_at_once() {
    // Three attempts failed and the stage run waited for a person. Without the restart, the
    // fourth failure would be over the limit already.
    let history = [
        failed(ToolError),
        failed(ToolError),
        failed(ToolError),
        WindowEvent::HumanAnswered,
        failed(ToolError),
    ];
    let window = AttemptWindow::from_history(&history);
    let mut input = facts(ToolError, &ALL_RETRY, window.attempts_used(), 3, true);
    input.invalid_output_failures = window.invalid_output_failures();
    assert_eq!(decide_after_failure(&input), AttemptDisposition::Retry);

    // The same failures with no answer in between do escalate.
    let no_answer: Vec<WindowEvent> = history
        .iter()
        .copied()
        .filter(|event| *event != WindowEvent::HumanAnswered)
        .collect();
    let window = AttemptWindow::from_history(&no_answer);
    assert_eq!(window.attempts_used(), 4);
    let input = facts(ToolError, &ALL_RETRY, window.attempts_used(), 3, true);
    assert_eq!(
        decide_after_failure(&input),
        AttemptDisposition::Escalate(EscalationCause::AttemptLimit)
    );
}

#[test]
fn an_answer_gives_back_the_repairs_too() {
    let history = [
        failed(InvalidOutput),
        failed(InvalidOutput),
        failed(InvalidOutput),
        WindowEvent::HumanAnswered,
        failed(InvalidOutput),
    ];
    let window = AttemptWindow::from_history(&history);
    let input = RetryFacts {
        class: InvalidOutput,
        retry_on: &ALL_RETRY,
        attempts_used: window.attempts_used(),
        max_attempts: 3,
        budget_has_room: true,
        invalid_output_failures: window.invalid_output_failures(),
        repair_cap: RepairCap::DEFAULT,
        environment: None,
    };
    assert_eq!(decide_after_failure(&input), AttemptDisposition::Retry);
}

#[test]
fn a_stage_run_that_a_person_keeps_answering_stays_within_max_attempts_between_answers() {
    // INV-10 with people in the loop: the always-failing runtime asks a person after at most
    // `max_attempts` attempts each time, and each answer opens one more window of the same size.
    let max = 3;
    let mut history = Vec::new();
    for round in 1..=5 {
        let mut attempts_in_window = 0;
        loop {
            history.push(failed(ToolError));
            attempts_in_window += 1;
            let window = AttemptWindow::from_history(&history);
            assert_eq!(window.attempts_used(), attempts_in_window, "round {round}");
            let input = facts(ToolError, &ALL_RETRY, window.attempts_used(), max, true);
            match decide_after_failure(&input) {
                AttemptDisposition::Retry => assert!(attempts_in_window < max),
                AttemptDisposition::Escalate(EscalationCause::AttemptLimit) => {
                    assert_eq!(attempts_in_window, max, "round {round}");
                    break;
                }
                other => panic!("round {round}: {other:?}"),
            }
        }
        history.push(WindowEvent::HumanAnswered);
    }
}
