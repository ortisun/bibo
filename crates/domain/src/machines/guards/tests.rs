//! Behavior of the guard predicates. Each guard gets a case where it holds and a case for every
//! condition in its definition that can fail on its own, so a clause cannot be dropped unseen.
//! The comparison with `state-machine.json` is in `tests/state_machine_conformance.rs`.

use super::*;
use crate::contracts::stage_contract::RetryClass;
use crate::ids::{StageRunId, TaskNodeId};
use crate::machines::failure::FailureClass;
use crate::machines::limits::ReworkCap;
use crate::machines::snapshot::{
    AttemptSnapshot, BlockDisposition, GateReportSnapshot, SandboxState, StageRunSnapshot,
};
use crate::state::{AttemptStatus, Guard, JobStatus, StageRunStatus, Status, TaskNodeStatus};
use crate::values::Timestamp;
use crate::vocabulary::{GateOutcome, HumanRole, StageKind};

// ---- helpers ------------------------------------------------------------------------------------

fn assert_holds(result: GuardResult) {
    if let Err(failure) = result {
        panic!("the guard should hold, but: {failure}");
    }
}

/// The guard must fail, and one of the unmet conditions must contain `fragment`.
fn assert_unmet(result: GuardResult, fragment: &str) {
    let failure = result.expect_err("the guard should not hold");
    assert!(
        failure.unmet.iter().any(|text| text.contains(fragment)),
        "no unmet condition mentions {fragment:?}: {failure}"
    );
}

fn run(n: u128, kind: StageKind, status: StageRunStatus) -> StageRunSnapshot {
    StageRunSnapshot::new(
        StageRunId::from_uuid(uuid::Uuid::from_u128(n)),
        kind,
        status,
    )
}

fn task_id(n: u128) -> TaskNodeId {
    TaskNodeId::from_uuid(uuid::Uuid::from_u128(n))
}

/// A moment `second` seconds after 10:00:00 on a fixed day.
fn at(second: u32) -> Timestamp {
    Timestamp::parse(&format!(
        "2026-10-27T10:{:02}:{:02}Z",
        second / 60,
        second % 60
    ))
    .unwrap()
}

// ---- the failure record ----------------------------------------------------------------------------

#[test]
fn a_failure_names_the_guard_and_every_unmet_condition() {
    let facts = AdmissionFacts {
        requester_on_allowlist: false,
        tenant_within_job_quota: false,
        repository_registered_and_enabled: true,
        policy_allows_request_class: true,
        protection_preflight_passed: true,
    };
    let failure = job::admission_ok(&facts).unwrap_err();
    assert_eq!(failure.guard, Guard::AdmissionOk);
    assert_eq!(failure.unmet.len(), 2);
    assert!(!failure.any_of);
    let text = failure.to_string();
    assert!(
        text.starts_with("guard G_ADMISSION_OK does not hold: "),
        "{text}"
    );
}

#[test]
fn an_any_of_guard_that_fails_says_none_of_the_alternatives_held() {
    let facts = BlockingFacts {
        verdict_is_block: false,
        mandatory_gate_could_not_run: false,
        policy_violation_detected: false,
    };
    let failure = stage_run::blocking_condition(&facts).unwrap_err();
    assert!(failure.any_of);
    assert_eq!(failure.unmet.len(), 3);
    assert!(
        failure.to_string().starts_with(
            "guard G_BLOCKING_CONDITION does not hold because none of these is true: "
        ),
        "{failure}"
    );
}

// ---- job: admission ----------------------------------------------------------------------------------

fn admission() -> AdmissionFacts {
    AdmissionFacts {
        requester_on_allowlist: true,
        tenant_within_job_quota: true,
        repository_registered_and_enabled: true,
        policy_allows_request_class: true,
        protection_preflight_passed: true,
    }
}

#[test]
fn admission_holds_when_the_four_conditions_hold() {
    assert_holds(job::admission_ok(&admission()));
    assert!(job::admission_denied(&admission()).is_err());
}

#[test]
fn each_admission_condition_is_required_on_its_own() {
    type Break = fn(&mut AdmissionFacts);
    let breaks: [(&str, Break); 4] = [
        ("allowlist", |f| f.requester_on_allowlist = false),
        ("quota", |f| f.tenant_within_job_quota = false),
        ("repository", |f| {
            f.repository_registered_and_enabled = false
        }),
        ("policy", |f| f.policy_allows_request_class = false),
    ];
    for (fragment, break_it) in breaks {
        let mut facts = admission();
        break_it(&mut facts);
        assert_unmet(job::admission_ok(&facts), fragment);
        assert_holds(job::admission_denied(&facts));
    }
}

#[test]
fn a_failed_protection_preflight_limits_autonomy_but_does_not_deny_admission() {
    let mut facts = admission();
    facts.protection_preflight_passed = false;
    assert_holds(job::admission_ok(&facts));
    assert!(job::admission_denied(&facts).is_err());
    assert!(facts.autonomy_limited_to_l0());
    assert!(!admission().autonomy_limited_to_l0());
}

#[test]
fn admission_is_either_ok_or_denied_never_both_and_never_neither() {
    for bits in 0..32u32 {
        let facts = AdmissionFacts {
            requester_on_allowlist: bits & 1 != 0,
            tenant_within_job_quota: bits & 2 != 0,
            repository_registered_and_enabled: bits & 4 != 0,
            policy_allows_request_class: bits & 8 != 0,
            protection_preflight_passed: bits & 16 != 0,
        };
        let ok = job::admission_ok(&facts).is_ok();
        let denied = job::admission_denied(&facts).is_ok();
        assert!(ok ^ denied, "{facts:?}: ok={ok} denied={denied}");
    }
}

// ---- job: the board of stage runs -----------------------------------------------------------------------

#[test]
fn waiting_and_not_waiting_are_opposites() {
    let runs = [
        run(1, StageKind::Intake, StageRunStatus::Passed),
        run(2, StageKind::Specification, StageRunStatus::WaitingForHuman),
    ];
    let facts = StageBoardFacts { stage_runs: &runs };
    assert_holds(job::any_stage_waiting(&facts));
    assert_unmet(job::no_stage_waiting(&facts), "waiting for a human");

    let calm = StageBoardFacts {
        stage_runs: &runs[..1],
    };
    assert_unmet(job::any_stage_waiting(&calm), "waiting for a human");
    assert_holds(job::no_stage_waiting(&calm));
    assert_holds(job::no_stage_waiting(&StageBoardFacts { stage_runs: &[] }));
}

#[test]
fn a_blocked_stage_run_is_found() {
    let runs = [run(1, StageKind::DomainDiscovery, StageRunStatus::Blocked)];
    assert_holds(job::any_stage_blocked(&StageBoardFacts {
        stage_runs: &runs,
    }));
    assert_unmet(
        job::any_stage_blocked(&StageBoardFacts { stage_runs: &[] }),
        "blocked",
    );
}

#[test]
fn every_blocked_run_needs_a_recorded_disposition_before_the_job_is_unblocked() {
    let mut cleared = run(1, StageKind::DomainDiscovery, StageRunStatus::Blocked);
    cleared.block_disposition = Some(BlockDisposition::CapabilityReprobePassed);
    let bare = run(2, StageKind::Validation, StageRunStatus::Blocked);
    let passed = run(3, StageKind::Intake, StageRunStatus::Passed);

    assert_holds(job::block_dispositions_recorded(&StageBoardFacts {
        stage_runs: &[cleared, passed],
    }));
    assert_unmet(
        job::block_dispositions_recorded(&StageBoardFacts {
            stage_runs: &[cleared, bare, passed],
        }),
        "disposition",
    );
}

// ---- job: who may act ----------------------------------------------------------------------------------------

#[test]
fn only_the_operator_role_may_pause_and_resume() {
    for role in HumanRole::ALL {
        let facts = PrincipalFacts {
            roles: &[*role],
            is_job_requester: true,
        };
        assert_eq!(
            job::actor_may_pause(&facts).is_ok(),
            *role == HumanRole::Operator,
            "{role}"
        );
    }
    assert!(
        job::actor_may_pause(&PrincipalFacts {
            roles: &[],
            is_job_requester: true,
        })
        .is_err()
    );
}

#[test]
fn the_requester_of_the_job_or_an_operator_may_cancel() {
    let requester = PrincipalFacts {
        roles: &[],
        is_job_requester: true,
    };
    let operator = PrincipalFacts {
        roles: &[HumanRole::Operator],
        is_job_requester: false,
    };
    let approver = PrincipalFacts {
        roles: &[HumanRole::Approver, HumanRole::SecurityApprover],
        is_job_requester: false,
    };
    assert_holds(job::actor_may_cancel(&requester));
    assert_holds(job::actor_may_cancel(&operator));
    assert_unmet(job::actor_may_cancel(&approver), "operator");
}

// ---- job and stage run: attempts ----------------------------------------------------------------------------------

fn an_attempt(status: AttemptStatus, sandbox: SandboxState) -> AttemptSnapshot {
    AttemptSnapshot { status, sandbox }
}

#[test]
fn cancellation_is_complete_only_when_every_attempt_and_sandbox_is_done() {
    let done = [
        an_attempt(AttemptStatus::Cancelled, SandboxState::TornDown),
        an_attempt(AttemptStatus::Failed, SandboxState::NeverCreated),
        an_attempt(AttemptStatus::TimedOut, SandboxState::Leaked),
    ];
    assert_holds(attempt::all_attempts_terminal(&AttemptsFacts {
        attempts: &done,
    }));
    assert_holds(attempt::all_attempts_terminal(&AttemptsFacts {
        attempts: &[],
    }));

    let still_running = [an_attempt(
        AttemptStatus::Cancelling,
        SandboxState::TornDown,
    )];
    assert_unmet(
        attempt::all_attempts_terminal(&AttemptsFacts {
            attempts: &still_running,
        }),
        "attempt",
    );
    let sandbox_up = [an_attempt(AttemptStatus::Cancelled, SandboxState::Up)];
    assert_unmet(
        attempt::all_attempts_terminal(&AttemptsFacts {
            attempts: &sandbox_up,
        }),
        "sandbox",
    );
}

#[test]
fn a_stage_run_may_be_cancelled_only_when_no_attempt_is_active() {
    for status in AttemptStatus::STATES {
        let attempts = [an_attempt(*status, SandboxState::TornDown)];
        let active = matches!(
            status,
            AttemptStatus::Starting | AttemptStatus::Running | AttemptStatus::Cancelling
        );
        assert_eq!(
            attempt::no_active_attempt(&AttemptsFacts {
                attempts: &attempts
            })
            .is_ok(),
            !active,
            "{status}"
        );
    }
    assert_holds(attempt::no_active_attempt(&AttemptsFacts { attempts: &[] }));
}

// ---- job: failure, rejection, completion ---------------------------------------------------------------------------

#[test]
fn a_job_fails_only_when_nothing_is_left_to_try() {
    let base = UnrecoverableFacts {
        stage_run_failed: true,
        rework_route_remains: false,
        retry_budget_remains: false,
        hard_limit_reached: false,
        policy_says_fail: false,
    };
    assert_holds(job::unrecoverable(&base));

    let route_left = UnrecoverableFacts {
        rework_route_remains: true,
        ..base
    };
    assert!(job::unrecoverable(&route_left).is_err());
    let budget_left = UnrecoverableFacts {
        retry_budget_remains: true,
        ..base
    };
    assert!(job::unrecoverable(&budget_left).is_err());
    let not_failed = UnrecoverableFacts {
        stage_run_failed: false,
        ..base
    };
    assert!(job::unrecoverable(&not_failed).is_err());
}

#[test]
fn a_hard_limit_fails_the_job_only_under_a_policy_that_says_fail() {
    let none = UnrecoverableFacts {
        stage_run_failed: false,
        rework_route_remains: true,
        retry_budget_remains: true,
        hard_limit_reached: true,
        policy_says_fail: false,
    };
    assert!(job::unrecoverable(&none).is_err());
    assert_holds(job::unrecoverable(&UnrecoverableFacts {
        policy_says_fail: true,
        ..none
    }));
    assert!(
        job::unrecoverable(&UnrecoverableFacts {
            hard_limit_reached: false,
            policy_says_fail: true,
            ..none
        })
        .is_err()
    );
}

#[test]
fn a_job_is_rejected_on_a_declined_intake_or_an_authorized_reject() {
    let nothing = RejectionFacts {
        intake_decision_is_decline: false,
        reject_decision_recorded: false,
        decider_is_authorized_approver: false,
    };
    assert!(job::rejection_recorded(&nothing).is_err());
    assert_holds(job::rejection_recorded(&RejectionFacts {
        intake_decision_is_decline: true,
        ..nothing
    }));
    assert_holds(job::rejection_recorded(&RejectionFacts {
        reject_decision_recorded: true,
        decider_is_authorized_approver: true,
        ..nothing
    }));
    // A reject from someone who is not an authorized approver counts for nothing.
    assert!(
        job::rejection_recorded(&RejectionFacts {
            reject_decision_recorded: true,
            ..nothing
        })
        .is_err()
    );
}

fn scope_runs() -> [StageRunSnapshot; 3] {
    [
        run(1, StageKind::Intake, StageRunStatus::Passed),
        run(2, StageKind::Specification, StageRunStatus::Passed),
        run(3, StageKind::Approval, StageRunStatus::Passed),
    ]
}

const SCOPE: [StageKind; 3] = [
    StageKind::Intake,
    StageKind::Specification,
    StageKind::Approval,
];

#[test]
fn a_job_completes_when_every_stage_in_scope_passed_and_the_approval_is_recorded() {
    let runs = scope_runs();
    let facts = PipelineScopeFacts {
        scope: &SCOPE,
        stage_runs: &runs,
        approval_decision_is_approve: true,
        ledger_chain_verifies: true,
    };
    assert_holds(job::pipeline_scope_complete(&facts));
}

#[test]
fn a_superseded_or_missing_run_does_not_count_as_passed() {
    let mut runs = scope_runs();
    runs[1].status = StageRunStatus::Superseded;
    let facts = PipelineScopeFacts {
        scope: &SCOPE,
        stage_runs: &runs,
        approval_decision_is_approve: true,
        ledger_chain_verifies: true,
    };
    assert_unmet(job::pipeline_scope_complete(&facts), "passed");

    let missing = PipelineScopeFacts {
        stage_runs: &scope_runs()[..2],
        ..facts
    };
    assert_unmet(job::pipeline_scope_complete(&missing), "passed");
}

#[test]
fn completion_also_needs_an_approve_decision_and_a_verified_ledger() {
    let runs = scope_runs();
    let facts = PipelineScopeFacts {
        scope: &SCOPE,
        stage_runs: &runs,
        approval_decision_is_approve: true,
        ledger_chain_verifies: true,
    };
    assert_unmet(
        job::pipeline_scope_complete(&PipelineScopeFacts {
            approval_decision_is_approve: false,
            ..facts
        }),
        "approve",
    );
    assert_unmet(
        job::pipeline_scope_complete(&PipelineScopeFacts {
            ledger_chain_verifies: false,
            ..facts
        }),
        "ledger",
    );
}

#[test]
fn a_job_with_an_empty_scope_never_completes() {
    let runs = scope_runs();
    let facts = PipelineScopeFacts {
        scope: &[],
        stage_runs: &runs,
        approval_decision_is_approve: true,
        ledger_chain_verifies: true,
    };
    assert_unmet(job::pipeline_scope_complete(&facts), "scope");
}

// ---- stage run: starting ------------------------------------------------------------------------------------------

#[test]
fn a_stage_run_is_ready_when_every_stage_it_requires_has_a_passed_run() {
    let runs = [
        run(1, StageKind::Specification, StageRunStatus::Passed),
        run(2, StageKind::DomainDiscovery, StageRunStatus::Passed),
    ];
    let facts = UpstreamFacts {
        stage: StageKind::Architecture,
        stage_runs: &runs,
        consumed_artifact_hashes_current: true,
        stage_contract_resolved_and_valid: true,
    };
    assert_holds(stage_run::upstream_passed(&facts));
}

#[test]
fn a_required_stage_that_is_not_passed_holds_the_run_back() {
    for status in StageRunStatus::STATES {
        let runs = [
            run(1, StageKind::Specification, StageRunStatus::Passed),
            run(2, StageKind::DomainDiscovery, *status),
        ];
        let facts = UpstreamFacts {
            stage: StageKind::Architecture,
            stage_runs: &runs,
            consumed_artifact_hashes_current: true,
            stage_contract_resolved_and_valid: true,
        };
        assert_eq!(
            stage_run::upstream_passed(&facts).is_ok(),
            *status == StageRunStatus::Passed,
            "{status}"
        );
    }
}

#[test]
fn a_stage_with_no_requirements_is_ready_at_once() {
    let facts = UpstreamFacts {
        stage: StageKind::Intake,
        stage_runs: &[],
        consumed_artifact_hashes_current: true,
        stage_contract_resolved_and_valid: true,
    };
    assert_holds(stage_run::upstream_passed(&facts));
}

#[test]
fn a_stale_artifact_hash_or_an_invalid_contract_holds_the_run_back() {
    let runs = [run(1, StageKind::Intake, StageRunStatus::Passed)];
    let facts = UpstreamFacts {
        stage: StageKind::RepositoryIntelligence,
        stage_runs: &runs,
        consumed_artifact_hashes_current: true,
        stage_contract_resolved_and_valid: true,
    };
    assert_holds(stage_run::upstream_passed(&facts));
    assert_unmet(
        stage_run::upstream_passed(&UpstreamFacts {
            consumed_artifact_hashes_current: false,
            ..facts
        }),
        "hash",
    );
    assert_unmet(
        stage_run::upstream_passed(&UpstreamFacts {
            stage_contract_resolved_and_valid: false,
            ..facts
        }),
        "contract",
    );
}

#[test]
fn only_a_rule_a_profile_or_a_policy_can_mark_a_stage_not_applicable() {
    for (basis, expected) in [
        (Some(NotApplicableBasis::DeterministicRule), true),
        (Some(NotApplicableBasis::DomainProfile), true),
        (Some(NotApplicableBasis::Policy), true),
        (Some(NotApplicableBasis::AgentOpinion), false),
        (None, false),
    ] {
        let facts = NotApplicableFacts {
            basis,
            rule_and_inputs_recorded: true,
        };
        assert_eq!(
            stage_run::not_applicable_decided(&facts).is_ok(),
            expected,
            "{basis:?}"
        );
    }
}

#[test]
fn a_not_applicable_decision_must_be_in_the_ledger() {
    let facts = NotApplicableFacts {
        basis: Some(NotApplicableBasis::Policy),
        rule_and_inputs_recorded: false,
    };
    assert_unmet(stage_run::not_applicable_decided(&facts), "ledger");
}

fn lease_grant() -> LeaseGrantFacts {
    LeaseGrantFacts {
        lease_compare_and_swap_succeeded: true,
        job_status: JobStatus::Active,
        now: at(10),
        not_before: Some(at(5)),
        concurrency_quota_allows: true,
        runtime_capability_check_passed: true,
    }
}

#[test]
fn a_lease_is_granted_when_all_five_conditions_hold() {
    assert_holds(stage_run::lease_acquired(&lease_grant()));
    assert_holds(stage_run::lease_acquired(&LeaseGrantFacts {
        not_before: None,
        ..lease_grant()
    }));
    // Exactly at the not-before moment is allowed: the back-off has run out.
    assert_holds(stage_run::lease_acquired(&LeaseGrantFacts {
        not_before: Some(at(10)),
        ..lease_grant()
    }));
}

#[test]
fn each_lease_condition_is_required_on_its_own() {
    type Break = fn(&mut LeaseGrantFacts);
    let breaks: [(&str, Break); 5] = [
        ("compare-and-swap", |f| {
            f.lease_compare_and_swap_succeeded = false
        }),
        ("ACTIVE", |f| f.job_status = JobStatus::Paused),
        ("back-off", |f| f.not_before = Some(at(11))),
        ("concurrency", |f| f.concurrency_quota_allows = false),
        ("capability", |f| f.runtime_capability_check_passed = false),
    ];
    for (fragment, break_it) in breaks {
        let mut facts = lease_grant();
        break_it(&mut facts);
        assert_unmet(stage_run::lease_acquired(&facts), fragment);
    }
}

#[test]
fn a_not_before_time_is_compared_as_an_instant_not_as_text() {
    // The same instant written with and without a fraction is the same moment.
    let with_fraction = Timestamp::parse("2026-10-27T10:00:10.000Z").unwrap();
    assert_holds(stage_run::lease_acquired(&LeaseGrantFacts {
        now: at(10),
        not_before: Some(with_fraction),
        ..lease_grant()
    }));
}

// ---- stage run: the attempt ended -----------------------------------------------------------------------------------------

#[test]
fn an_output_is_accepted_only_when_valid_and_its_hash_is_stored() {
    let facts = OutputFacts {
        attempt_succeeded: true,
        output_validates_against_outputs_schema: true,
        output_artifact_hash_stored: true,
    };
    assert_holds(stage_run::output_schema_valid(&facts));
    assert_unmet(
        stage_run::output_schema_valid(&OutputFacts {
            attempt_succeeded: false,
            ..facts
        }),
        "succeeded",
    );
    assert_unmet(
        stage_run::output_schema_valid(&OutputFacts {
            output_validates_against_outputs_schema: false,
            ..facts
        }),
        "schema",
    );
    assert_unmet(
        stage_run::output_schema_valid(&OutputFacts {
            output_artifact_hash_stored: false,
            ..facts
        }),
        "hash",
    );
}

fn retry<'a>(
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
    let on = [RetryClass::ProviderError];
    let facts = retry(FailureClass::ProviderError, &on, 1, 3, true);
    assert_holds(stage_run::retry_allowed(&facts));
    assert!(stage_run::retry_exhausted_or_nonretryable(&facts).is_err());
}

#[test]
fn the_last_allowed_attempt_is_the_third_of_three() {
    let on = [RetryClass::ToolError];
    assert_holds(stage_run::retry_allowed(&retry(
        FailureClass::ToolError,
        &on,
        2,
        3,
        true,
    )));
    let spent = retry(FailureClass::ToolError, &on, 3, 3, true);
    assert_unmet(stage_run::retry_allowed(&spent), "attempts");
    assert_holds(stage_run::retry_exhausted_or_nonretryable(&spent));
}

#[test]
fn an_unlisted_failure_is_not_retried_and_is_final() {
    let on = [RetryClass::ProviderError];
    let facts = retry(FailureClass::ToolError, &on, 1, 3, true);
    assert_unmet(stage_run::retry_allowed(&facts), "retryable");
    assert_holds(stage_run::retry_exhausted_or_nonretryable(&facts));
}

#[test]
fn budget_policy_and_internal_failures_are_never_retried() {
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
        let facts = retry(class, &everything, 0, 10, true);
        assert!(stage_run::retry_allowed(&facts).is_err(), "{class}");
        assert_holds(stage_run::retry_exhausted_or_nonretryable(&facts));
    }
}

#[test]
fn a_retryable_failure_with_no_budget_left_is_neither_retried_nor_final() {
    // The stage run neither retries nor fails here. It asks a human, because a budget limit
    // was hit (guard G_ESCALATION_REQUIRED).
    let on = [RetryClass::ProviderError];
    let facts = retry(FailureClass::ProviderError, &on, 1, 3, false);
    assert_unmet(stage_run::retry_allowed(&facts), "budget");
    assert!(stage_run::retry_exhausted_or_nonretryable(&facts).is_err());
}

#[test]
fn a_human_is_asked_when_any_one_reason_applies() {
    let none = EscalationFacts {
        budget_limit_hit: false,
        agent_requested_a_human: false,
        stagnation_detected: false,
        policy_requires_human_decision: false,
    };
    assert!(stage_run::escalation_required(&none).is_err());
    for facts in [
        EscalationFacts {
            budget_limit_hit: true,
            ..none
        },
        EscalationFacts {
            agent_requested_a_human: true,
            ..none
        },
        EscalationFacts {
            stagnation_detected: true,
            ..none
        },
        EscalationFacts {
            policy_requires_human_decision: true,
            ..none
        },
    ] {
        assert_holds(stage_run::escalation_required(&facts));
    }
}

// ---- stage run: the gate --------------------------------------------------------------------------------------------------

fn report(outcome: GateOutcome, reason: bool) -> GateReportSnapshot {
    GateReportSnapshot {
        outcome,
        not_applicable_reason_recorded: reason,
    }
}

fn gate_pass<'a>(reports: &'a [GateReportSnapshot]) -> GatePassFacts<'a> {
    GatePassFacts {
        decision_is_pass_and_persisted: true,
        criteria_without_ledger_entry: 0,
        mandatory_gate_reports: reports,
    }
}

#[test]
fn a_pass_needs_the_decision_every_criterion_and_every_mandatory_gate() {
    let reports = [
        report(GateOutcome::Passed, false),
        report(GateOutcome::NotApplicable, true),
    ];
    assert_holds(stage_run::gate_pass_evidenced(&gate_pass(&reports)));
    assert_holds(stage_run::gate_pass_evidenced(&gate_pass(&[])));

    let ok = report(GateOutcome::Passed, false);
    assert_unmet(
        stage_run::gate_pass_evidenced(&GatePassFacts {
            decision_is_pass_and_persisted: false,
            ..gate_pass(&[ok])
        }),
        "decision",
    );
    assert_unmet(
        stage_run::gate_pass_evidenced(&GatePassFacts {
            criteria_without_ledger_entry: 1,
            ..gate_pass(&[ok])
        }),
        "criterion",
    );
}

#[test]
fn a_blocked_mandatory_gate_never_lets_a_stage_pass() {
    // INV-06: a mandatory gate that did not run is BLOCKED, and BLOCKED is never PASSED.
    let reports = [
        report(GateOutcome::Passed, false),
        report(GateOutcome::Blocked, true),
    ];
    assert_unmet(
        stage_run::gate_pass_evidenced(&gate_pass(&reports)),
        "BLOCKED",
    );
}

#[test]
fn a_failed_gate_or_an_unexplained_not_applicable_never_lets_a_stage_pass() {
    assert!(
        stage_run::gate_pass_evidenced(&gate_pass(&[report(GateOutcome::Failed, true)])).is_err()
    );
    assert_unmet(
        stage_run::gate_pass_evidenced(&gate_pass(&[report(GateOutcome::NotApplicable, false)])),
        "reason",
    );
}

fn rework() -> ReworkFacts {
    ReworkFacts {
        verdict_is_changes_required: true,
        deterministic_gate_failed: false,
        rounds_used: 0,
        cap: ReworkCap::DEFAULT,
        failing_set_differs_from_previous_round: true,
        budget_remains: true,
    }
}

#[test]
fn rework_is_allowed_for_a_changes_required_verdict_or_a_failed_gate() {
    assert_holds(stage_run::rework_allowed(&rework()));
    assert_holds(stage_run::rework_allowed(&ReworkFacts {
        verdict_is_changes_required: false,
        deterministic_gate_failed: true,
        ..rework()
    }));
    assert_unmet(
        stage_run::rework_allowed(&ReworkFacts {
            verdict_is_changes_required: false,
            deterministic_gate_failed: false,
            ..rework()
        }),
        "CHANGES_REQUIRED",
    );
}

#[test]
fn rework_stops_at_the_cap_of_two() {
    assert_holds(stage_run::rework_allowed(&ReworkFacts {
        rounds_used: 1,
        ..rework()
    }));
    assert_unmet(
        stage_run::rework_allowed(&ReworkFacts {
            rounds_used: 2,
            ..rework()
        }),
        "cap",
    );
}

#[test]
fn a_lower_project_cap_stops_rework_sooner() {
    let facts = ReworkFacts {
        rounds_used: 1,
        cap: ReworkCap::from_policy(1),
        ..rework()
    };
    assert_unmet(stage_run::rework_allowed(&facts), "cap");
    // A higher policy value cannot buy a third round.
    let facts = ReworkFacts {
        rounds_used: 2,
        cap: ReworkCap::from_policy(9),
        ..rework()
    };
    assert_unmet(stage_run::rework_allowed(&facts), "cap");
}

#[test]
fn rework_stops_when_the_same_findings_come_back_or_the_budget_is_gone() {
    assert_unmet(
        stage_run::rework_allowed(&ReworkFacts {
            failing_set_differs_from_previous_round: false,
            ..rework()
        }),
        "differ",
    );
    assert_unmet(
        stage_run::rework_allowed(&ReworkFacts {
            budget_remains: false,
            ..rework()
        }),
        "budget",
    );
}

#[test]
fn a_human_is_asked_at_a_gate_when_any_one_reason_applies() {
    let none = NeedsHumanFacts {
        verdict_is_needs_human: false,
        rework_limit_reached: false,
        stagnation_detected: false,
        budget_limit_reached: false,
        gate_is_a_human_gate: false,
    };
    assert!(stage_run::needs_human_verdict(&none).is_err());
    for facts in [
        NeedsHumanFacts {
            verdict_is_needs_human: true,
            ..none
        },
        NeedsHumanFacts {
            rework_limit_reached: true,
            ..none
        },
        NeedsHumanFacts {
            stagnation_detected: true,
            ..none
        },
        NeedsHumanFacts {
            budget_limit_reached: true,
            ..none
        },
        NeedsHumanFacts {
            gate_is_a_human_gate: true,
            ..none
        },
    ] {
        assert_holds(stage_run::needs_human_verdict(&facts));
    }
}

#[test]
fn a_gate_blocks_on_a_block_verdict_a_gate_that_could_not_run_or_a_policy_violation() {
    let none = BlockingFacts {
        verdict_is_block: false,
        mandatory_gate_could_not_run: false,
        policy_violation_detected: false,
    };
    assert!(stage_run::blocking_condition(&none).is_err());
    for facts in [
        BlockingFacts {
            verdict_is_block: true,
            ..none
        },
        BlockingFacts {
            mandatory_gate_could_not_run: true,
            ..none
        },
        BlockingFacts {
            policy_violation_detected: true,
            ..none
        },
    ] {
        assert_holds(stage_run::blocking_condition(&facts));
    }
}

#[test]
fn a_gate_fails_for_good_only_when_it_failed_and_no_route_exists() {
    let facts = NoReworkFacts {
        gate_failed: true,
        a_rework_route_exists: false,
    };
    assert_holds(stage_run::gate_failed_no_rework(&facts));
    assert_unmet(
        stage_run::gate_failed_no_rework(&NoReworkFacts {
            a_rework_route_exists: true,
            ..facts
        }),
        "route",
    );
    assert_unmet(
        stage_run::gate_failed_no_rework(&NoReworkFacts {
            gate_failed: false,
            ..facts
        }),
        "failed",
    );
}

// ---- stage run: humans -----------------------------------------------------------------------------------------------------

#[test]
fn an_answer_counts_when_it_is_recorded_with_the_principal_and_hashed() {
    let facts = AnswerFacts {
        answer_recorded_with_principal: true,
        answer_became_a_new_input_hash: true,
    };
    assert_holds(stage_run::answer_recorded(&facts));
    assert!(
        stage_run::answer_recorded(&AnswerFacts {
            answer_recorded_with_principal: false,
            ..facts
        })
        .is_err()
    );
    assert!(
        stage_run::answer_recorded(&AnswerFacts {
            answer_became_a_new_input_hash: false,
            ..facts
        })
        .is_err()
    );
}

#[test]
fn an_approval_needs_the_role_and_the_evidence_the_human_actually_saw() {
    let facts = ApprovalFacts {
        decision_is_approve: true,
        principal_holds_required_role: true,
        evidence_digest_seen_equals_current: true,
    };
    assert_holds(stage_run::approver_authorized(&facts));
    assert_unmet(
        stage_run::approver_authorized(&ApprovalFacts {
            decision_is_approve: false,
            ..facts
        }),
        "approve",
    );
    assert_unmet(
        stage_run::approver_authorized(&ApprovalFacts {
            principal_holds_required_role: false,
            ..facts
        }),
        "role",
    );
    assert_unmet(
        stage_run::approver_authorized(&ApprovalFacts {
            evidence_digest_seen_equals_current: false,
            ..facts
        }),
        "digest",
    );
}

#[test]
fn a_human_rework_request_needs_the_approver_or_operator_role_and_a_free_round() {
    for role in HumanRole::ALL {
        let facts = HumanReworkFacts {
            principal_roles: &[*role],
            rounds_used: 0,
            cap: ReworkCap::DEFAULT,
        };
        let allowed = matches!(role, HumanRole::Approver | HumanRole::Operator);
        assert_eq!(
            stage_run::human_rework_allowed(&facts).is_ok(),
            allowed,
            "{role}"
        );
    }
}

#[test]
fn a_human_rework_request_stops_at_the_cap_but_ignores_stagnation() {
    let roles = [HumanRole::Approver];
    assert_holds(stage_run::human_rework_allowed(&HumanReworkFacts {
        principal_roles: &roles,
        rounds_used: 1,
        cap: ReworkCap::DEFAULT,
    }));
    assert_unmet(
        stage_run::human_rework_allowed(&HumanReworkFacts {
            principal_roles: &roles,
            rounds_used: 2,
            cap: ReworkCap::DEFAULT,
        }),
        "cap",
    );
}

#[test]
fn a_rejection_needs_an_authorized_approver_a_decision_and_a_reason() {
    let facts = HumanRejectFacts {
        decider_is_authorized_approver: true,
        reject_decision_recorded: true,
        reason_recorded: true,
    };
    assert_holds(stage_run::human_rejected(&facts));
    for broken in [
        HumanRejectFacts {
            decider_is_authorized_approver: false,
            ..facts
        },
        HumanRejectFacts {
            reject_decision_recorded: false,
            ..facts
        },
        HumanRejectFacts {
            reason_recorded: false,
            ..facts
        },
    ] {
        assert!(stage_run::human_rejected(&broken).is_err());
    }
}

#[test]
fn a_block_is_cleared_by_a_passing_probe_or_an_available_dependency() {
    let neither = UnblockFacts {
        capability_reprobe_passed: false,
        missing_dependency_now_available: false,
    };
    assert!(stage_run::block_cleared_rerun(&neither).is_err());
    assert_holds(stage_run::block_cleared_rerun(&UnblockFacts {
        capability_reprobe_passed: true,
        ..neither
    }));
    assert_holds(stage_run::block_cleared_rerun(&UnblockFacts {
        missing_dependency_now_available: true,
        ..neither
    }));
}

fn override_facts<'a>(roles: &'a [HumanRole]) -> OverrideFacts<'a> {
    OverrideFacts {
        policy_permits_override_for_block_code: true,
        block_is_security_class: false,
        principal_roles: roles,
        role_required_by_policy: HumanRole::Approver,
        justification_recorded: true,
        blocked_gate_is_mandatory_of_active_profile: false,
    }
}

#[test]
fn an_override_needs_policy_the_role_and_a_recorded_justification() {
    let roles = [HumanRole::Approver];
    assert_holds(stage_run::override_permitted(&override_facts(&roles)));
    assert_unmet(
        stage_run::override_permitted(&OverrideFacts {
            policy_permits_override_for_block_code: false,
            ..override_facts(&roles)
        }),
        "policy",
    );
    assert_unmet(
        stage_run::override_permitted(&OverrideFacts {
            justification_recorded: false,
            ..override_facts(&roles)
        }),
        "justification",
    );
    assert_unmet(
        stage_run::override_permitted(&override_facts(&[HumanRole::Requester])),
        "role",
    );
}

#[test]
fn an_override_of_a_mandatory_gate_of_an_active_profile_is_never_permitted() {
    // INV-07.
    let roles = [
        HumanRole::Approver,
        HumanRole::SecurityApprover,
        HumanRole::OrgAdmin,
    ];
    assert_unmet(
        stage_run::override_permitted(&OverrideFacts {
            blocked_gate_is_mandatory_of_active_profile: true,
            ..override_facts(&roles)
        }),
        "mandatory",
    );
}

#[test]
fn a_security_class_block_needs_a_security_approver() {
    let approver_only = [HumanRole::Approver];
    let facts = OverrideFacts {
        block_is_security_class: true,
        ..override_facts(&approver_only)
    };
    assert_unmet(stage_run::override_permitted(&facts), "security");

    let both = [HumanRole::Approver, HumanRole::SecurityApprover];
    assert_holds(stage_run::override_permitted(&OverrideFacts {
        block_is_security_class: true,
        ..override_facts(&both)
    }));
}

#[test]
fn a_run_is_superseded_when_an_input_changed_or_an_upstream_run_was_reworked() {
    let neither = SupersedeFacts {
        consumed_artifact_superseded_by_newer_version: false,
        upstream_stage_run_was_reworked: false,
    };
    assert!(stage_run::upstream_invalidated(&neither).is_err());
    assert_holds(stage_run::upstream_invalidated(&SupersedeFacts {
        consumed_artifact_superseded_by_newer_version: true,
        ..neither
    }));
    assert_holds(stage_run::upstream_invalidated(&SupersedeFacts {
        upstream_stage_run_was_reworked: true,
        ..neither
    }));
}

// ---- attempt ------------------------------------------------------------------------------------------------------------------------

#[test]
fn the_epoch_is_current_only_when_it_equals_the_stored_one() {
    assert_holds(attempt::epoch_current(&EpochFacts {
        sent_epoch: 7,
        stored_epoch: 7,
    }));
    // A worker that was paused sends an older epoch. A newer one is just as wrong.
    assert_unmet(
        attempt::epoch_current(&EpochFacts {
            sent_epoch: 6,
            stored_epoch: 7,
        }),
        "epoch",
    );
    assert!(
        attempt::epoch_current(&EpochFacts {
            sent_epoch: 8,
            stored_epoch: 7,
        })
        .is_err()
    );
}

#[test]
fn a_sandbox_is_provisioned_when_limits_grants_probe_and_epoch_all_hold() {
    let facts = SandboxProvisionFacts {
        sandbox_started_within_limits: true,
        policy_tool_grants_in_place: true,
        runtime_capability_probe_satisfied: true,
        epoch: EpochFacts {
            sent_epoch: 1,
            stored_epoch: 1,
        },
    };
    assert_holds(attempt::sandbox_provisioned(&facts));
    type Break = fn(&mut SandboxProvisionFacts);
    let breaks: [(&str, Break); 4] = [
        ("limits", |f| f.sandbox_started_within_limits = false),
        ("grants", |f| f.policy_tool_grants_in_place = false),
        ("probe", |f| f.runtime_capability_probe_satisfied = false),
        ("epoch", |f| f.epoch.sent_epoch = 0),
    ];
    for (fragment, break_it) in breaks {
        let mut broken = facts;
        break_it(&mut broken);
        assert_unmet(attempt::sandbox_provisioned(&broken), fragment);
    }
}

#[test]
fn a_heartbeat_needs_the_current_epoch_and_a_lease_that_has_not_run_out() {
    let epoch = EpochFacts {
        sent_epoch: 3,
        stored_epoch: 3,
    };
    let facts = LeaseEpochFacts {
        epoch,
        now: at(10),
        lease_expires_at: at(60),
    };
    assert_holds(attempt::lease_epoch_current(&facts));
    // On the last instant of the lease the heartbeat is still accepted.
    assert_holds(attempt::lease_epoch_current(&LeaseEpochFacts {
        now: at(60),
        ..facts
    }));
    assert_unmet(
        attempt::lease_epoch_current(&LeaseEpochFacts {
            now: at(61),
            ..facts
        }),
        "lease",
    );
    assert_unmet(
        attempt::lease_epoch_current(&LeaseEpochFacts {
            epoch: EpochFacts {
                sent_epoch: 2,
                ..epoch
            },
            ..facts
        }),
        "epoch",
    );
}

#[test]
fn the_deadline_has_passed_only_after_it_not_at_it() {
    let facts = DeadlineFacts {
        now: at(100),
        attempt_deadline: at(100),
    };
    assert_unmet(attempt::deadline_passed(&facts), "deadline");
    assert_holds(attempt::deadline_passed(&DeadlineFacts {
        now: at(101),
        ..facts
    }));
    assert!(
        attempt::deadline_passed(&DeadlineFacts {
            now: at(99),
            ..facts
        })
        .is_err()
    );
}

#[test]
fn the_deadline_is_compared_as_an_instant_even_when_written_with_a_fraction() {
    let same_moment = Timestamp::parse("2026-10-27T10:01:40.000Z").unwrap();
    assert!(
        attempt::deadline_passed(&DeadlineFacts {
            now: at(100),
            attempt_deadline: same_moment,
        })
        .is_err()
    );
    assert!(
        attempt::deadline_passed(&DeadlineFacts {
            now: same_moment,
            attempt_deadline: at(100),
        })
        .is_err()
    );
}

#[test]
fn a_lease_is_lost_only_after_it_expired_with_no_heartbeat() {
    let facts = LeaseExpiryFacts {
        now: at(61),
        lease_expires_at: at(60),
        heartbeat_arrived: false,
    };
    assert_holds(attempt::lease_expired(&facts));
    assert_unmet(
        attempt::lease_expired(&LeaseExpiryFacts {
            heartbeat_arrived: true,
            ..facts
        }),
        "heartbeat",
    );
    assert_unmet(
        attempt::lease_expired(&LeaseExpiryFacts {
            now: at(60),
            ..facts
        }),
        "expire",
    );
}

#[test]
fn an_attempt_can_be_cancelled_while_live_and_the_job_is_cancelling_or_the_run_superseded() {
    for attempt_status in AttemptStatus::STATES {
        for job_status in JobStatus::STATES {
            for superseded in [false, true] {
                let facts = CancelFacts {
                    attempt: *attempt_status,
                    job: *job_status,
                    stage_run_is_being_superseded: superseded,
                };
                let live = !attempt_status.is_terminal();
                let reason = *job_status == JobStatus::Cancelling || superseded;
                assert_eq!(
                    attempt::cancel_allowed(&facts).is_ok(),
                    live && reason,
                    "{facts:?}"
                );
            }
        }
    }
}

#[test]
fn a_sandbox_is_gone_only_when_the_provider_says_so() {
    assert_holds(attempt::sandbox_gone(&SandboxGoneFacts {
        provider_confirms_sandbox_gone: true,
    }));
    assert!(
        attempt::sandbox_gone(&SandboxGoneFacts {
            provider_confirms_sandbox_gone: false,
        })
        .is_err()
    );
}

#[test]
fn the_teardown_grace_period_is_over_when_thirty_seconds_have_passed() {
    let facts = TeardownFacts {
        now: at(29),
        cancel_requested_at: at(0),
        grace_seconds: 30,
    };
    assert_unmet(attempt::teardown_deadline_passed(&facts), "grace");
    assert_holds(attempt::teardown_deadline_passed(&TeardownFacts {
        now: at(30),
        ..facts
    }));
    assert_holds(attempt::teardown_deadline_passed(&TeardownFacts {
        now: at(500),
        ..facts
    }));
}

// ---- task node -------------------------------------------------------------------------------------------------------------------------

#[test]
fn a_task_is_ready_when_every_dependency_succeeded() {
    assert_holds(task_node::task_deps_succeeded(&TaskDepsFacts {
        dependencies: &[TaskNodeStatus::Succeeded, TaskNodeStatus::Succeeded],
    }));
    assert_holds(task_node::task_deps_succeeded(&TaskDepsFacts {
        dependencies: &[],
    }));
    for status in TaskNodeStatus::STATES {
        let facts = TaskDepsFacts {
            dependencies: &[TaskNodeStatus::Succeeded, *status],
        };
        assert_eq!(
            task_node::task_deps_succeeded(&facts).is_ok(),
            *status == TaskNodeStatus::Succeeded,
            "{status}"
        );
    }
}

#[test]
fn a_task_starts_only_when_the_attempt_picked_it_next() {
    let this = task_id(1);
    assert_holds(task_node::task_started_by_attempt(&TaskStartFacts {
        this_task: this,
        next_in_topological_order: Some(this),
    }));
    assert!(
        task_node::task_started_by_attempt(&TaskStartFacts {
            this_task: this,
            next_in_topological_order: Some(task_id(2)),
        })
        .is_err()
    );
    assert!(
        task_node::task_started_by_attempt(&TaskStartFacts {
            this_task: this,
            next_in_topological_order: None,
        })
        .is_err()
    );
}

#[test]
fn a_task_succeeds_only_with_a_commit_inside_its_files_and_passing_checks() {
    let facts = TaskEvidenceFacts {
        commit_exists_for_task: true,
        changed_paths_inside_owned_files: true,
        protected_path_changed: false,
        per_task_checks_passed: true,
    };
    assert_holds(task_node::task_evidence_recorded(&facts));
    type Break = fn(&mut TaskEvidenceFacts);
    let breaks: [(&str, Break); 4] = [
        ("commit", |f| f.commit_exists_for_task = false),
        ("owned", |f| f.changed_paths_inside_owned_files = false),
        ("protected", |f| f.protected_path_changed = true),
        ("checks", |f| f.per_task_checks_passed = false),
    ];
    for (fragment, break_it) in breaks {
        let mut broken = facts;
        break_it(&mut broken);
        assert_unmet(task_node::task_evidence_recorded(&broken), fragment);
    }
}

#[test]
fn a_task_is_retried_below_its_limit_while_the_stage_budget_has_room() {
    assert_holds(task_node::task_retry_allowed(&TaskRetryFacts {
        retries_used: 1,
        per_task_limit: 2,
        stage_budget_has_room: true,
    }));
    assert_unmet(
        task_node::task_retry_allowed(&TaskRetryFacts {
            retries_used: 2,
            per_task_limit: 2,
            stage_budget_has_room: true,
        }),
        "limit",
    );
    assert_unmet(
        task_node::task_retry_allowed(&TaskRetryFacts {
            retries_used: 0,
            per_task_limit: 2,
            stage_budget_has_room: false,
        }),
        "budget",
    );
}

// ---- dispatch ---------------------------------------------------------------------------------------------------------------------------

#[test]
fn evaluate_runs_the_predicate_the_guard_names() {
    let mut facts = admission();
    facts.requester_on_allowlist = false;
    let wrapped = GuardFacts::Admission(facts);
    assert_eq!(
        evaluate(Guard::AdmissionOk, &wrapped),
        Err(GuardError::Unmet(job::admission_ok(&facts).unwrap_err()))
    );
    assert_eq!(evaluate(Guard::AdmissionDenied, &wrapped), Ok(()));
}

#[test]
fn evaluate_refuses_facts_of_the_wrong_kind_instead_of_guessing() {
    let wrapped = GuardFacts::Output(OutputFacts {
        attempt_succeeded: true,
        output_validates_against_outputs_schema: true,
        output_artifact_hash_stored: true,
    });
    let error = evaluate(Guard::AdmissionOk, &wrapped).unwrap_err();
    assert_eq!(
        error,
        GuardError::WrongFacts {
            guard: Guard::AdmissionOk,
            expected: FactsKind::Admission,
            given: FactsKind::Output,
        }
    );
    assert_eq!(
        error.to_string(),
        "guard G_ADMISSION_OK reads admission facts, but output facts were supplied"
    );
}

#[test]
fn the_shared_guards_read_one_kind_of_facts_whichever_machine_asks() {
    assert_eq!(facts_kind(Guard::EpochCurrent), FactsKind::Epoch);
    assert_eq!(facts_kind(Guard::OutputSchemaValid), FactsKind::Output);
    assert_eq!(facts_kind(Guard::NoActiveAttempt), FactsKind::Attempts);
    assert_eq!(facts_kind(Guard::AllAttemptsTerminal), FactsKind::Attempts);
}

#[test]
fn two_guards_may_share_facts_but_each_has_its_own_name_in_a_failure() {
    let facts = GuardFacts::Retry(retry(
        FailureClass::ToolError,
        &[RetryClass::ToolError],
        3,
        3,
        true,
    ));
    let allowed = evaluate(Guard::RetryAllowed, &facts).unwrap_err();
    match allowed {
        GuardError::Unmet(failure) => assert_eq!(failure.guard, Guard::RetryAllowed),
        other @ GuardError::WrongFacts { .. } => panic!("{other}"),
    }
    assert_eq!(
        evaluate(Guard::RetryExhaustedOrNonretryable, &facts),
        Ok(())
    );
}
