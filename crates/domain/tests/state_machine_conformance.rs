//! The Rust state machines must equal `docs/architecture/state-machine.json`, in both directions.
//!
//! The JSON file is the single source of truth. It is embedded at compile time, so this test does
//! no file I/O. Every check goes from the file to the code (nothing in the file is missing from
//! the code) and from the code to the file (nothing in the code is missing from the file), so
//! neither side can drift without a test failing.
//!
//! Every check takes the document as an argument. That is what lets
//! `conformance_detects_a_changed_table` feed a changed copy of the file to the same checks and
//! see them fail, so the checks are known not to pass vacuously.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;

use factory_domain::contracts::review_verdict::DefectClass;
use factory_domain::contracts::stage_contract::RetryClass;
use factory_domain::ids::{StageRunId, TaskNodeId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{
    AdmissionFacts, AnswerFacts, ApprovalFacts, AttemptsFacts, BlockingFacts, CancelFacts,
    DeadlineFacts, EnvironmentCause, EnvironmentFacts, EpochFacts, EscalationFacts, FactsKind,
    GatePassFacts, GuardError, GuardFacts, HumanRejectFacts, HumanReworkFacts, LeaseEpochFacts,
    LeaseExpiryFacts, LeaseGrantFacts, NeedsHumanFacts, NoReworkFacts, NotApplicableFacts,
    OutputFacts, OverrideFacts, PipelineScopeFacts, PrincipalFacts, ReauthorizationFacts,
    RejectionFacts, RetryFacts, ReworkFacts, SandboxGoneFacts, SandboxProvisionFacts,
    StageBoardFacts, SupersedeFacts, TaskDepsFacts, TaskEvidenceFacts, TaskRetryFacts,
    TaskStartFacts, TeardownFacts, UnblockFacts, UnrecoverableFacts, UpstreamFacts, evaluate,
    facts_kind,
};
use factory_domain::machines::invalidation::{ArtifactChange, INVALIDATION_RULES, plan_for_change};
use factory_domain::machines::limits::{
    DEFAULT_REWORK_CAP, RepairCap, ReworkCap, ReworkLedger, ReworkLimits, ReworkTrack,
};
use factory_domain::machines::rework::{
    DEFECT_PRECEDENCE, DEFECT_ROUTED_STAGES, DefectOutcome, GateFinding, GateReworkDecision,
    GateReworkRequest, HUMAN_REWORK_ROUTES, HumanReworkDecision, HumanReworkRequest,
    NeedsHumanCause, NoReworkRoute, REWORK_ROUTES, ReworkCause, ReworkTrigger, decide_gate_rework,
    decide_human_rework, defect_outcome, human_targets, route,
};
use factory_domain::machines::snapshot::StageRunSnapshot;
use factory_domain::state::{
    Actor, AttemptEvent, AttemptStatus, Guard, IllegalTransition, JobEvent, JobStatus,
    StageRunEvent, StageRunStatus, Status, TaskNodeEvent, TaskNodeStatus,
};
use factory_domain::values::{EventType, Sha256Digest, Timestamp, TransitionId};
use factory_domain::vocabulary::{AssuranceLevel, HumanRole, ReleaseState, StageKind};
use serde_json::{Value, json};

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../docs/architecture/state-machine.json"
    ))
    .expect("state-machine.json is valid JSON")
});

/// The stage contract schema. Its `retry_on` list says which failure classes a contract can name.
const STAGE_CONTRACT_SCHEMA: &str = include_str!("../../../schemas/stage-contract.schema.json");

/// The review verdict schema. Its `defect_class` list says which classes a finding can carry.
const REVIEW_VERDICT_SCHEMA: &str = include_str!("../../../schemas/review-verdict.schema.json");

fn strings_of(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

fn keys_of(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect()
}

fn machine_json<'a>(doc: &'a Value, name: &str) -> &'a Value {
    &doc["machines"][name]
}

// ---- names ------------------------------------------------------------------------------------

fn check_status_names<S: Status>(doc: &Value) {
    let json = machine_json(doc, S::MACHINE);
    let documented = keys_of(&json["states"]);
    let in_code: BTreeSet<String> = S::STATES.iter().map(ToString::to_string).collect();
    assert_eq!(
        in_code,
        documented,
        "the {} statuses in code and in state-machine.json differ",
        S::MACHINE
    );
    assert_eq!(
        S::STATES.len(),
        documented.len(),
        "a status is listed twice in the {} code",
        S::MACHINE
    );
    assert_eq!(S::INITIAL.to_string(), json["initial"].as_str().unwrap());
    for state in S::STATES {
        let flags = &json["states"][state.to_string()];
        assert_eq!(
            state.is_terminal(),
            flags["terminal"].as_bool().unwrap(),
            "{}.{state}: terminal flag differs from the file",
            S::MACHINE
        );
        // Every documented spelling reads back to the same value.
        assert_eq!(S::parse_name(&state.to_string()), Some(*state));
        // A terminal status leaves only through `supersede`, and only where the file says it is
        // supersedable (PASSED and SKIPPED of a stage run).
        if state.is_terminal() {
            let exits: Vec<String> = S::EVENTS
                .iter()
                .filter(|event| state.apply(**event).is_ok())
                .map(ToString::to_string)
                .collect();
            let supersedable = flags["supersedable"].as_bool().unwrap_or(false);
            assert_eq!(
                exits == ["supersede"],
                supersedable,
                "{}.{state}: the supersedable flag differs from the file",
                S::MACHINE
            );
            assert!(
                supersedable || exits.is_empty(),
                "{}.{state} is terminal and not supersedable but exits on {exits:?}",
                S::MACHINE
            );
        }
    }
}

fn status_names_match(doc: &Value) {
    check_status_names::<JobStatus>(doc);
    check_status_names::<StageRunStatus>(doc);
    check_status_names::<AttemptStatus>(doc);
    check_status_names::<TaskNodeStatus>(doc);
}

#[test]
fn status_names_match_state_machine_json() {
    status_names_match(&DOCUMENT);
}

fn check_event_names<S: Status>(doc: &Value) {
    let json = machine_json(doc, S::MACHINE);
    let documented: BTreeSet<String> = json["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["event"].as_str().unwrap().to_owned())
        .collect();
    let in_code: BTreeSet<String> = S::EVENTS.iter().map(ToString::to_string).collect();
    assert_eq!(in_code, documented, "{} events differ", S::MACHINE);
}

fn event_names_match(doc: &Value) {
    check_event_names::<JobStatus>(doc);
    check_event_names::<StageRunStatus>(doc);
    check_event_names::<AttemptStatus>(doc);
    check_event_names::<TaskNodeStatus>(doc);
}

#[test]
fn event_names_match_state_machine_json() {
    event_names_match(&DOCUMENT);
}

fn guard_and_actor_names_match(doc: &Value) {
    let guards: BTreeSet<String> = Guard::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(
        guards,
        keys_of(&doc["guards"]),
        "the guards in code and in the file differ"
    );
    let actors: BTreeSet<String> = Actor::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(
        actors,
        keys_of(&doc["actors"]),
        "the actors in code and in the file differ"
    );
}

#[test]
fn guard_and_actor_names_match_state_machine_json() {
    guard_and_actor_names_match(&DOCUMENT);
}

fn assurance_levels_release_states_and_stage_kinds_match(doc: &Value) {
    let levels: BTreeSet<String> = doc["assurance_levels"]["levels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["level"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        AssuranceLevel::ALL
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        levels,
        "the assurance levels differ"
    );

    assert_eq!(
        ReleaseState::ALL
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        strings_of(&doc["assurance_levels"]["release_states"]["values"]),
        "the release states differ"
    );

    // Stage kinds, in pipeline order, with the stages each one waits for.
    let stages = doc["pipeline"]["stages"].as_array().unwrap();
    let documented_order: Vec<&str> = stages.iter().map(|s| s["kind"].as_str().unwrap()).collect();
    let code_order: Vec<&str> = StageKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(
        code_order, documented_order,
        "stage kinds or their order differ"
    );
    for stage in stages {
        let kind = StageKind::parse(stage["kind"].as_str().unwrap()).unwrap();
        let documented_requires = strings_of(&stage["requires"]);
        let in_code: BTreeSet<String> = kind.requires().iter().map(ToString::to_string).collect();
        assert_eq!(in_code, documented_requires, "{kind} requires");
    }
}

#[test]
fn assurance_levels_release_states_and_stage_kinds_match_state_machine_json() {
    assurance_levels_release_states_and_stage_kinds_match(&DOCUMENT);
}

// ---- transitions ------------------------------------------------------------------------------

fn check_transition_table<S: Status>(doc: &Value) {
    let json = machine_json(doc, S::MACHINE);
    let documented = json["transitions"].as_array().unwrap();
    assert_eq!(
        S::TRANSITIONS.len(),
        documented.len(),
        "{}: the number of transitions differs from the file",
        S::MACHINE
    );

    let in_code: BTreeMap<&str, _> = S::TRANSITIONS.iter().map(|t| (t.id, t)).collect();
    assert_eq!(
        in_code.len(),
        S::TRANSITIONS.len(),
        "a transition id repeats"
    );

    for entry in documented {
        let id = entry["id"].as_str().unwrap();
        let t = in_code.get(id).unwrap_or_else(|| {
            panic!(
                "{}: transition {id} is in the file but not in code",
                S::MACHINE
            )
        });
        let from_in_code: BTreeSet<String> = t.from.iter().map(ToString::to_string).collect();
        assert_eq!(from_in_code, strings_of(&entry["from"]), "{id}: from");
        assert_eq!(
            t.event.to_string(),
            entry["event"].as_str().unwrap(),
            "{id}: event"
        );
        assert_eq!(
            t.guard.to_string(),
            entry["guard"].as_str().unwrap(),
            "{id}: guard"
        );
        assert_eq!(t.to.to_string(), entry["to"].as_str().unwrap(), "{id}: to");
        let actors_in_code: BTreeSet<String> = t.actors.iter().map(ToString::to_string).collect();
        assert_eq!(actors_in_code, strings_of(&entry["actors"]), "{id}: actors");
        assert_eq!(t.emits, entry["emits"].as_str(), "{id}: emits");
        // The id must be one the domain event schema accepts.
        TransitionId::parse(id).unwrap();
    }
}

fn transition_tables_match(doc: &Value) {
    check_transition_table::<JobStatus>(doc);
    check_transition_table::<StageRunStatus>(doc);
    check_transition_table::<AttemptStatus>(doc);
    check_transition_table::<TaskNodeStatus>(doc);
}

#[test]
fn transition_tables_match_state_machine_json() {
    transition_tables_match(&DOCUMENT);
}

/// The cross product of all statuses and all events: a pair is accepted if and only if the file
/// lists it (INV-02). The oracle is the JSON file, not the Rust table.
fn check_cross_product<S: Status>(doc: &Value) {
    let json = machine_json(doc, S::MACHINE);
    let mut documented: BTreeMap<(String, String), String> = BTreeMap::new();
    for t in json["transitions"].as_array().unwrap() {
        for from in t["from"].as_array().unwrap() {
            documented.insert(
                (
                    from.as_str().unwrap().to_owned(),
                    t["event"].as_str().unwrap().to_owned(),
                ),
                t["to"].as_str().unwrap().to_owned(),
            );
        }
    }
    let mut accepted = 0;
    for state in S::STATES {
        for event in S::EVENTS {
            let expected = documented.get(&(state.to_string(), event.to_string()));
            match (state.apply(*event), expected) {
                (Ok(next), Some(to)) => {
                    assert_eq!(&next.to_string(), to, "{state} on {event}");
                    accepted += 1;
                }
                (Err(error), None) => {
                    assert_eq!(error.machine, S::MACHINE);
                    assert_eq!(error.from, state.to_string());
                    assert_eq!(error.event, event.to_string());
                }
                (Ok(next), None) => panic!(
                    "{}: {state} on {event} was accepted and led to {next}, but the file does not list it",
                    S::MACHINE
                ),
                (Err(error), Some(_)) => panic!(
                    "{}: {state} on {event} is in the file but was rejected: {error}",
                    S::MACHINE
                ),
            }
        }
    }
    assert_eq!(accepted, documented.len(), "{}", S::MACHINE);
}

fn cross_products_match(doc: &Value) {
    check_cross_product::<JobStatus>(doc);
    check_cross_product::<StageRunStatus>(doc);
    check_cross_product::<AttemptStatus>(doc);
    check_cross_product::<TaskNodeStatus>(doc);
}

#[test]
fn every_status_and_event_pair_outside_the_table_is_rejected() {
    cross_products_match(&DOCUMENT);
}

#[test]
fn a_rejected_transition_explains_itself_in_plain_english() {
    let error: IllegalTransition = JobStatus::Completed.apply(JobEvent::Admit).unwrap_err();
    assert_eq!(
        error.to_string(),
        "the job state machine has no transition from COMPLETED on the event admit"
    );
}

#[test]
fn emitted_event_types_are_valid_domain_event_types_of_the_right_aggregate() {
    fn check<S: Status>() {
        for t in S::TRANSITIONS {
            if let Some(name) = t.emits {
                let event_type = EventType::parse(name).unwrap_or_else(|e| {
                    panic!("{}: {} emits an invalid type: {e}", S::MACHINE, t.id)
                });
                assert!(
                    event_type.as_str().starts_with(&format!("{}.", S::MACHINE)),
                    "{} emits {name}, which is not an event of the {} aggregate",
                    t.id,
                    S::MACHINE
                );
                assert_eq!(
                    t.id.chars().next().unwrap(),
                    S::TRANSITION_PREFIX,
                    "{} has the wrong prefix for the {} machine",
                    t.id,
                    S::MACHINE
                );
            }
        }
    }
    check::<JobStatus>();
    check::<StageRunStatus>();
    check::<AttemptStatus>();
    check::<TaskNodeStatus>();
}

#[test]
fn only_the_heartbeat_emits_no_event() {
    let silent: Vec<&str> = [
        JobStatus::TRANSITIONS
            .iter()
            .map(|t| (t.id, t.emits))
            .collect::<Vec<_>>(),
        StageRunStatus::TRANSITIONS
            .iter()
            .map(|t| (t.id, t.emits))
            .collect(),
        AttemptStatus::TRANSITIONS
            .iter()
            .map(|t| (t.id, t.emits))
            .collect(),
        TaskNodeStatus::TRANSITIONS
            .iter()
            .map(|t| (t.id, t.emits))
            .collect(),
    ]
    .into_iter()
    .flatten()
    .filter(|(_, emits)| emits.is_none())
    .map(|(id, _)| id)
    .collect();
    assert_eq!(
        silent,
        ["A03"],
        "the heartbeat is the only silent transition"
    );
    assert_eq!(
        AttemptStatus::Running.apply(AttemptEvent::Heartbeat),
        Ok(AttemptStatus::Running)
    );
}

// ---- the documented exceptions to "terminal means no exit" -----------------------------------

#[test]
fn a_passed_or_skipped_stage_run_can_only_be_superseded() {
    // ADR 0010 decision 2: a skipped run was decided on recorded inputs, so it goes stale like a
    // passed one. These two are the only terminal statuses with an exit.
    for status in [StageRunStatus::Passed, StageRunStatus::Skipped] {
        assert!(status.is_terminal());
        let exits: Vec<StageRunEvent> = StageRunStatus::EVENTS
            .iter()
            .copied()
            .filter(|event| status.apply(*event).is_ok())
            .collect();
        assert_eq!(exits, [StageRunEvent::Supersede], "{status}");
        assert_eq!(
            status.apply(StageRunEvent::Supersede),
            Ok(StageRunStatus::Superseded)
        );
    }
    let with_an_exit: Vec<StageRunStatus> = StageRunStatus::STATES
        .iter()
        .copied()
        .filter(|status| status.is_terminal())
        .filter(|status| {
            StageRunStatus::EVENTS
                .iter()
                .any(|event| status.apply(*event).is_ok())
        })
        .collect();
    assert_eq!(
        with_an_exit,
        [StageRunStatus::Passed, StageRunStatus::Skipped]
    );
}

#[test]
fn failed_task_nodes_are_not_terminal_so_they_can_be_retried() {
    assert!(!TaskNodeStatus::Failed.is_terminal());
    assert_eq!(
        TaskNodeStatus::Failed.apply(TaskNodeEvent::RetryTask),
        Ok(TaskNodeStatus::Ready)
    );
}

#[test]
fn job_admission_and_rejection_start_from_received() {
    assert_eq!(JobStatus::INITIAL, JobStatus::Received);
    assert_eq!(
        JobStatus::Received.apply(JobEvent::Admit),
        Ok(JobStatus::Active)
    );
    assert_eq!(
        JobStatus::Received.apply(JobEvent::RejectAtAdmission),
        Ok(JobStatus::Rejected)
    );
    assert!(
        JobStatus::Active
            .apply(JobEvent::RejectAtAdmission)
            .is_err()
    );
}

// ---- the guard registry ----------------------------------------------------------------------

fn moment() -> Timestamp {
    Timestamp::parse("2026-10-27T10:00:00Z").unwrap()
}

/// A request hash that facts can borrow for the whole run of the test.
static REQUEST_HASH: LazyLock<Sha256Digest> = LazyLock::new(|| Sha256Digest::of(b"request"));

/// Facts of each kind, built from the public fields. The `match` has no catch-all arm, so a new
/// kind of facts cannot be added without adding it here.
fn sample_facts(kind: FactsKind) -> GuardFacts<'static> {
    let epoch = EpochFacts {
        sent_epoch: 1,
        stored_epoch: 1,
    };
    match kind {
        FactsKind::Admission => GuardFacts::Admission(AdmissionFacts {
            requester_on_allowlist: true,
            tenant_within_job_quota: true,
            repository_registered_and_enabled: true,
            policy_allows_request_class: true,
            repository_day_budget_has_room: true,
            organization_day_budget_has_room: true,
            protection_preflight_passed: true,
        }),
        FactsKind::StageBoard => GuardFacts::StageBoard(StageBoardFacts { stage_runs: &[] }),
        FactsKind::Principal => GuardFacts::Principal(PrincipalFacts {
            roles: &[],
            is_job_requester: false,
        }),
        FactsKind::Attempts => GuardFacts::Attempts(AttemptsFacts { attempts: &[] }),
        FactsKind::Unrecoverable => GuardFacts::Unrecoverable(UnrecoverableFacts {
            stage_run_failed: false,
            newer_run_of_kind_exists: false,
            rework_route_remains: false,
            retry_budget_remains: false,
            hard_limit_reached: false,
            policy_says_fail: false,
        }),
        FactsKind::Rejection => GuardFacts::Rejection(RejectionFacts {
            intake_decision_is_decline: false,
            reject_decision_recorded: false,
            decider_is_authorized_approver: false,
        }),
        FactsKind::PipelineScope => GuardFacts::PipelineScope(PipelineScopeFacts {
            scope: &[],
            stage_runs: &[],
            approval_decision_is_approve: false,
            ledger_chain_verifies: false,
        }),
        FactsKind::Upstream => GuardFacts::Upstream(UpstreamFacts {
            stage: StageKind::Intake,
            stage_runs: &[],
            consumed_artifact_hashes_current: true,
            stage_contract_resolved_and_valid: true,
        }),
        FactsKind::NotApplicable => GuardFacts::NotApplicable(NotApplicableFacts {
            basis: None,
            rule_and_inputs_recorded: false,
        }),
        FactsKind::Environment => GuardFacts::Environment(EnvironmentFacts {
            cause: EnvironmentCause::DaemonUnavailable,
            attempt_ended_failed: true,
        }),
        FactsKind::Reauthorization => GuardFacts::Reauthorization(ReauthorizationFacts {
            authorized_request: None,
            current_request: &REQUEST_HASH,
            policy_asks_confirmation: false,
        }),
        FactsKind::LeaseGrant => GuardFacts::LeaseGrant(LeaseGrantFacts {
            claim_candidate_current: true,
            job_status: JobStatus::Active,
            now: moment(),
            not_before: None,
            concurrency_quota_allows: true,
            runtime_capability_check_passed: true,
        }),
        FactsKind::Output => GuardFacts::Output(OutputFacts {
            attempt_succeeded: true,
            output_validates_against_outputs_schema: true,
            output_artifact_hash_stored: true,
        }),
        FactsKind::Retry => GuardFacts::Retry(RetryFacts {
            class: FailureClass::ToolError,
            retry_on: &[],
            attempts_used: 0,
            max_attempts: 1,
            budget_has_room: true,
            invalid_output_failures: 0,
            repair_cap: RepairCap::DEFAULT,
            environment: None,
        }),
        FactsKind::Escalation => GuardFacts::Escalation(EscalationFacts {
            budget_limit_hit: false,
            attempt_limit_reached: false,
            agent_requested_a_human: false,
            stagnation_detected: false,
            policy_requires_human_decision: false,
        }),
        FactsKind::GatePass => GuardFacts::GatePass(GatePassFacts {
            decision_is_pass_and_persisted: true,
            criteria_without_ledger_entry: 0,
            mandatory_gate_reports: &[],
        }),
        FactsKind::Rework => GuardFacts::Rework(ReworkFacts {
            verdict_is_changes_required: true,
            deterministic_gate_failed: false,
            rounds_used: 0,
            cap: ReworkCap::DEFAULT,
            failing_set_differs_from_previous_round: true,
            budget_remains: true,
        }),
        FactsKind::NeedsHuman => GuardFacts::NeedsHuman(NeedsHumanFacts {
            verdict_is_needs_human: false,
            rework_limit_reached: false,
            stagnation_detected: false,
            budget_limit_reached: false,
            gate_is_a_human_gate: false,
            defect_needs_a_person: false,
        }),
        FactsKind::Blocking => GuardFacts::Blocking(BlockingFacts {
            verdict_is_block: false,
            mandatory_gate_could_not_run: false,
            policy_violation_detected: false,
        }),
        FactsKind::NoRework => GuardFacts::NoRework(NoReworkFacts {
            gate_failed: true,
            a_rework_route_exists: false,
        }),
        FactsKind::Answer => GuardFacts::Answer(AnswerFacts {
            answer_recorded_with_principal: true,
            answer_became_a_new_input_hash: true,
            raises_a_ceiling: false,
            principal_is_org_admin: false,
        }),
        FactsKind::Approval => GuardFacts::Approval(ApprovalFacts {
            decision_is_approve: true,
            principal_holds_required_role: true,
            evidence_digest_seen_equals_current: true,
            translation_warnings_decided: true,
        }),
        FactsKind::HumanRework => GuardFacts::HumanRework(HumanReworkFacts {
            principal_roles: &[],
            rounds_used: 0,
            cap: ReworkCap::DEFAULT,
        }),
        FactsKind::HumanReject => GuardFacts::HumanReject(HumanRejectFacts {
            decider_is_authorized_approver: true,
            reject_decision_recorded: true,
            reason_recorded: true,
        }),
        FactsKind::Unblock => GuardFacts::Unblock(UnblockFacts {
            capability_reprobe_passed: true,
            missing_dependency_now_available: false,
            dependency_decision_recorded: false,
        }),
        FactsKind::Override => GuardFacts::Override(OverrideFacts {
            policy_permits_override_for_block_code: true,
            block_is_security_class: false,
            principal_roles: &[],
            role_required_by_policy: HumanRole::Approver,
            justification_recorded: true,
            blocked_gate_is_mandatory_of_active_profile: false,
        }),
        FactsKind::Supersede => GuardFacts::Supersede(SupersedeFacts {
            consumed_artifact_superseded_by_newer_version: true,
            upstream_stage_run_was_reworked: false,
            external_change_recorded: false,
        }),
        FactsKind::SandboxProvision => GuardFacts::SandboxProvision(SandboxProvisionFacts {
            posture_verified: true,
            tool_grants_recorded: true,
            probe_satisfies_stage: true,
            epoch,
        }),
        FactsKind::Epoch => GuardFacts::Epoch(epoch),
        FactsKind::LeaseEpoch => GuardFacts::LeaseEpoch(LeaseEpochFacts {
            epoch,
            now: moment(),
            lease_expires_at: moment(),
        }),
        FactsKind::Deadline => GuardFacts::Deadline(DeadlineFacts {
            now: moment(),
            attempt_deadline: moment(),
        }),
        FactsKind::LeaseExpiry => GuardFacts::LeaseExpiry(LeaseExpiryFacts {
            now: moment(),
            lease_expires_at: moment(),
            heartbeat_arrived: false,
        }),
        FactsKind::Cancel => GuardFacts::Cancel(CancelFacts {
            attempt: AttemptStatus::Running,
            job: JobStatus::Cancelling,
            stage_run_is_being_superseded: false,
        }),
        FactsKind::SandboxGone => GuardFacts::SandboxGone(SandboxGoneFacts {
            provider_confirms_sandbox_gone: true,
        }),
        FactsKind::Teardown => GuardFacts::Teardown(TeardownFacts {
            now: moment(),
            cancel_requested_at: moment(),
            grace_seconds: 30,
        }),
        FactsKind::TaskDeps => GuardFacts::TaskDeps(TaskDepsFacts { dependencies: &[] }),
        FactsKind::TaskStart => GuardFacts::TaskStart(TaskStartFacts {
            this_task: TaskNodeId::from_uuid(uuid::Uuid::from_u128(1)),
            next_in_topological_order: None,
        }),
        FactsKind::TaskEvidence => GuardFacts::TaskEvidence(TaskEvidenceFacts {
            commit_exists_for_task: true,
            changed_paths_inside_owned_files: true,
            protected_path_changed: false,
            per_task_checks_passed: true,
        }),
        FactsKind::TaskRetry => GuardFacts::TaskRetry(TaskRetryFacts {
            retries_used: 0,
            per_task_limit: 1,
            stage_budget_has_room: true,
        }),
    }
}

/// Every guard id in the file has a named predicate that can be run, every predicate has an
/// entry in the file, and every guard the transitions use is defined.
fn guard_registry_matches(doc: &Value) {
    let documented = keys_of(&doc["guards"]);

    // From the file to the code: each id has a name in code.
    for id in &documented {
        assert!(
            Guard::parse(id).is_ok(),
            "guard {id} is in the file but has no name in code"
        );
    }
    // From the code to the file: each predicate has an entry.
    for guard in Guard::ALL {
        assert!(
            documented.contains(&guard.to_string()),
            "the predicate for {guard} has no entry in the file"
        );
    }

    // Each predicate runs on the facts it reads, and refuses facts of another kind.
    for guard in Guard::ALL {
        let kind = facts_kind(*guard);
        let facts = sample_facts(kind);
        assert_eq!(
            facts.kind(),
            kind,
            "{guard}: the sample is of the wrong kind"
        );
        match evaluate(*guard, &facts) {
            Ok(cleared) => {
                // The clearance names the guard that was run and the digest of these facts.
                assert_eq!(
                    cleared.guard(),
                    *guard,
                    "{guard}: the clearance is for another guard"
                );
                assert_eq!(
                    cleared.facts_sha256(),
                    &facts.digest(),
                    "{guard}: the clearance carries another digest"
                );
            }
            Err(GuardError::Unmet(_)) => {}
            Err(error @ GuardError::WrongFacts { .. }) => {
                panic!("{guard} refused the facts it reads: {error}")
            }
        }
        let other = FactsKind::ALL
            .iter()
            .copied()
            .find(|candidate| *candidate != kind)
            .expect("there is more than one kind of facts");
        assert!(
            matches!(
                evaluate(*guard, &sample_facts(other)),
                Err(GuardError::WrongFacts { .. })
            ),
            "{guard} accepted facts of the wrong kind ({other})"
        );
    }

    // No kind of facts is left without a guard that reads it.
    let read: BTreeSet<FactsKind> = Guard::ALL.iter().map(|g| facts_kind(*g)).collect();
    for kind in FactsKind::ALL {
        assert!(read.contains(kind), "no guard reads {kind} facts");
    }

    // The file is consistent with itself: the guards that transitions name are the guards that
    // are defined, no more and no fewer.
    let mut used = BTreeSet::new();
    for machine in doc["machines"].as_object().unwrap().values() {
        for transition in machine["transitions"].as_array().unwrap() {
            used.insert(transition["guard"].as_str().unwrap().to_owned());
        }
    }
    assert_eq!(
        used, documented,
        "the guards used by transitions and the guards defined in the file differ"
    );
}

#[test]
fn guard_registry_matches_json() {
    guard_registry_matches(&DOCUMENT);
}

// ---- invalidation -----------------------------------------------------------------------------

/// A run of every stage kind, all passed, in pipeline order.
fn one_passed_run_per_stage() -> Vec<StageRunSnapshot> {
    StageKind::ALL
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            StageRunSnapshot::new(
                StageRunId::from_uuid(uuid::Uuid::from_u128(index as u128 + 1)),
                *kind,
                StageRunStatus::Passed,
            )
        })
        .collect()
}

fn invalidation_rules_match(doc: &Value) {
    let rows = doc["pipeline"]["invalidation_rules"].as_array().unwrap();
    assert_eq!(
        INVALIDATION_RULES.len(),
        rows.len(),
        "the number of invalidation rules differs from the file"
    );
    let runs = one_passed_run_per_stage();
    for row in rows {
        let when = row["when"].as_str().unwrap();
        let change = ArtifactChange::parse(when).unwrap_or_else(|_| {
            panic!("invalidation rule {when:?} is in the file but not in code")
        });
        let documented: Vec<&str> = row["supersedes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stage| stage.as_str().unwrap())
            .collect();
        let in_code: Vec<&str> = change.stale_stages().iter().map(|k| k.as_str()).collect();
        assert_eq!(in_code, documented, "invalidation rule {when:?}");

        // The function, not only the table: planning for the change picks the run of each
        // documented stage and of no other stage.
        let planned = plan_for_change(&runs, change);
        let planned_kinds: Vec<&str> = runs
            .iter()
            .filter(|run| planned.contains(&run.id))
            .map(|run| run.kind.as_str())
            .collect();
        assert_eq!(planned_kinds, documented, "the plan for {when:?}");
    }
    for rule in INVALIDATION_RULES {
        assert!(
            rows.iter()
                .any(|row| row["when"].as_str() == Some(rule.change.as_str())),
            "invalidation rule {:?} is in code but not in the file",
            rule.change.as_str()
        );
    }
}

#[test]
fn invalidation_rules_match_json() {
    invalidation_rules_match(&DOCUMENT);
}

// ---- rework routes ----------------------------------------------------------------------------

fn rework_routes_match(doc: &Value) {
    let rows = doc["pipeline"]["rework_routes"].as_array().unwrap();
    let documented: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|row| {
            (
                row["from_stage"].as_str().unwrap(),
                row["trigger"].as_str().unwrap(),
                row["target_stage"].as_str().unwrap(),
            )
        })
        .collect();
    let in_code: Vec<(&str, &str, &str)> = REWORK_ROUTES
        .iter()
        .map(|r| (r.from.as_str(), r.trigger.as_str(), r.target.as_str()))
        .collect();
    assert_eq!(in_code, documented, "the rework routes differ");

    // The lookup, not only the table: each documented row is found from the request that its
    // trigger describes.
    for (from, trigger, target) in documented {
        let from = StageKind::parse(from).unwrap();
        let trigger = ReworkTrigger::parse(trigger).unwrap_or_else(|_| {
            panic!("rework trigger {trigger:?} is in the file but not in code")
        });
        let cause = match trigger {
            ReworkTrigger::HumanRequestsRework => ReworkCause::Human,
            _ => ReworkCause::Gate {
                defect: trigger.defect(),
            },
        };
        assert_eq!(
            route(from, cause).map(|r| r.target.as_str()),
            Ok(target),
            "rework from {from} on {trigger}"
        );
    }
}

#[test]
fn rework_routes_match_json() {
    rework_routes_match(&DOCUMENT);
}

#[test]
fn the_defect_classes_that_route_rework_are_the_ones_the_review_verdict_names() {
    // The route table reads two defect classes by name, and the defect matrix reads all four. If
    // the verdict schema renames or adds one, this fails.
    let named_by_routes: BTreeSet<DefectClass> = REWORK_ROUTES
        .iter()
        .filter_map(|r| r.trigger.defect())
        .collect();
    assert_eq!(
        named_by_routes,
        BTreeSet::from([DefectClass::Documentation, DefectClass::CodeBehavior])
    );
    let named_by_matrix: BTreeSet<DefectClass> = DEFECT_PRECEDENCE.iter().copied().collect();
    assert_eq!(
        named_by_matrix.len(),
        DEFECT_PRECEDENCE.len(),
        "a class is listed twice"
    );
    let schema: Value = serde_json::from_str(REVIEW_VERDICT_SCHEMA).unwrap();
    let in_schema = strings_of(
        &schema["properties"]["findings"]["items"]["properties"]["defect_class"]["enum"],
    );
    assert_eq!(
        named_by_matrix
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        in_schema,
        "the defect classes of the matrix and of the review verdict schema differ"
    );
    assert_eq!(named_by_matrix, DefectClass::ALL.iter().copied().collect());
}

// ---- defect routing ---------------------------------------------------------------------------

/// A verdict that asks for changes, at `stage`, with a fresh ledger and room in every limit.
fn verdict_at(stage: StageKind, defect: DefectClass) -> GateReworkRequest {
    GateReworkRequest {
        from: stage,
        defect: Some(defect),
        finding: GateFinding::VerdictChangesRequired,
        ledger: ReworkLedger::default(),
        limits: ReworkLimits::default(),
        failing_set_differs: true,
        budget_remains: true,
    }
}

fn defect_routing_matches(doc: &Value) {
    let routing = &doc["pipeline"]["defect_routing"];

    // The order that decides between classes.
    let precedence: Vec<&str> = routing["precedence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|class| class.as_str().unwrap())
        .collect();
    let in_code: Vec<&str> = DEFECT_PRECEDENCE
        .iter()
        .map(|class| class.as_str())
        .collect();
    assert_eq!(
        in_code, precedence,
        "the defect precedence differs from the file"
    );

    // The stages that route by class, and every cell of the matrix.
    let documented_stages = keys_of(&routing["stages"]);
    let stages_in_code: BTreeSet<String> = DEFECT_ROUTED_STAGES
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        stages_in_code, documented_stages,
        "the stages with a defect routing differ from the file"
    );
    let class_names: BTreeSet<String> = DefectClass::ALL.iter().map(ToString::to_string).collect();
    for (stage_name, row) in routing["stages"].as_object().unwrap() {
        let stage = StageKind::parse(stage_name).unwrap();
        assert_eq!(
            keys_of(row),
            class_names,
            "defect routing {stage_name}: the file does not name every class once"
        );
        for class in DefectClass::ALL {
            let documented = row[class.as_str()].as_str().unwrap();
            let outcome = defect_outcome(stage, *class);
            assert_eq!(
                outcome.map(DefectOutcome::as_str),
                Some(documented),
                "defect routing {stage_name} / {class}"
            );

            // The decision, not only the table.
            let decision = decide_gate_rework(&verdict_at(stage, *class));
            match documented {
                "rework" => {
                    // A `rework` cell finds a route in `rework_routes`, and the decision follows it.
                    let found = route(
                        stage,
                        ReworkCause::Gate {
                            defect: Some(*class),
                        },
                    )
                    .unwrap_or_else(|error| {
                        panic!("defect routing {stage_name} / {class} says rework: {error}")
                    });
                    let GateReworkDecision::Rework(plan) = decision else {
                        panic!("defect routing {stage_name} / {class}: {decision:?}");
                    };
                    assert_eq!(plan.target, found.target, "{stage_name} / {class}");
                }
                "human" => assert_eq!(
                    decision,
                    GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(*class)),
                    "defect routing {stage_name} / {class}"
                ),
                other => panic!("defect routing {stage_name} / {class}: unknown outcome {other}"),
            }
        }
    }

    // A stage the file does not list has no outcome for any class.
    for stage in StageKind::ALL {
        if documented_stages.contains(stage.as_str()) {
            continue;
        }
        for class in DefectClass::ALL {
            assert_eq!(defect_outcome(*stage, *class), None, "{stage} / {class}");
        }
    }
}

#[test]
fn defect_routing_matches_json() {
    defect_routing_matches(&DOCUMENT);
}

// ---- human rework routes ----------------------------------------------------------------------

fn human_rework_routes_match(doc: &Value) {
    let rows = doc["pipeline"]["human_rework_routes"]["routes"]
        .as_array()
        .unwrap();
    let documented: Vec<(&str, Vec<&str>)> = rows
        .iter()
        .map(|row| {
            (
                row["from_stage"].as_str().unwrap(),
                row["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|target| target.as_str().unwrap())
                    .collect(),
            )
        })
        .collect();
    let in_code: Vec<(&str, Vec<&str>)> = HUMAN_REWORK_ROUTES
        .iter()
        .map(|row| {
            (
                row.from.as_str(),
                row.targets.iter().map(|target| target.as_str()).collect(),
            )
        })
        .collect();
    assert_eq!(
        in_code, documented,
        "the human rework routes differ from the file"
    );

    // The lookup and the decision, for every pair of stages: a person may send rework from `from`
    // to `target` if and only if the file lists the target for that stage.
    let roles = [HumanRole::Approver];
    for from in StageKind::ALL {
        let listed: Vec<&str> = documented
            .iter()
            .find(|(name, _)| *name == from.as_str())
            .map(|(_, targets)| targets.clone())
            .unwrap_or_default();
        let found: Vec<&str> = human_targets(*from).iter().map(|t| t.as_str()).collect();
        assert_eq!(found, listed, "human targets from {from}");

        for target in StageKind::ALL {
            let decision = decide_human_rework(&HumanReworkRequest {
                from: *from,
                target: *target,
                principal_roles: &roles,
                ledger: ReworkLedger::default(),
                limits: ReworkLimits::default(),
            });
            if listed.contains(&target.as_str()) {
                let HumanReworkDecision::Rework(plan) = decision else {
                    panic!("human rework {from} -> {target} is in the file: {decision:?}");
                };
                assert_eq!(plan.target, *target);
                // The count follows the target: documentation for DOCUMENTING, code otherwise.
                let expected_track = if *target == StageKind::Documenting {
                    ReworkTrack::Documentation
                } else {
                    ReworkTrack::Code
                };
                assert_eq!(plan.track, expected_track, "{from} -> {target}");
            } else {
                let expected = if listed.is_empty() {
                    NoReworkRoute::Human(*from)
                } else {
                    NoReworkRoute::HumanTarget {
                        from: *from,
                        target: *target,
                    }
                };
                assert_eq!(
                    decision,
                    HumanReworkDecision::NoRoute(expected),
                    "human rework {from} -> {target} is not in the file"
                );
            }
        }
    }
}

#[test]
fn human_rework_routes_match_json() {
    human_rework_routes_match(&DOCUMENT);
}

// ---- the rework cap ---------------------------------------------------------------------------

fn rework_cap_matches(doc: &Value) {
    let invariant = doc["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "INV-10")
        .expect("INV-10 is in the file");
    let statement = invariant["statement"].as_str().unwrap();
    assert!(
        statement.contains("two rework rounds for code and two for documentation"),
        "INV-10 no longer says two and two: {statement}"
    );
    assert_eq!(DEFAULT_REWORK_CAP, 2, "INV-10 and ADR 0009 say two");
}

#[test]
fn the_rework_cap_matches_the_documented_bound() {
    rework_cap_matches(&DOCUMENT);
}

// ---- failure classes --------------------------------------------------------------------------

/// The classes that the `FAILED` attempt state lists in its meaning, such as
/// "Ended with a failure class: TOOL_ERROR, INVALID_OUTPUT or INTERNAL.".
fn listed_failure_classes(doc: &Value) -> BTreeSet<String> {
    let meaning = doc["machines"]["attempt"]["states"]["FAILED"]["meaning"]
        .as_str()
        .unwrap();
    let (_, list) = meaning
        .split_once("failure class: ")
        .expect("the FAILED meaning lists failure classes");
    list.trim_end_matches('.')
        .replace(" or ", ", ")
        .split(", ")
        .map(str::to_owned)
        .collect()
}

fn failure_classes_match(doc: &Value) {
    // Seven classes are reported with a FAILED attempt. Two more have a status of their own.
    let documented = listed_failure_classes(doc);
    let with_failed_status: BTreeSet<String> = FailureClass::ALL
        .iter()
        .filter(|c| c.attempt_status() == AttemptStatus::Failed)
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        with_failed_status, documented,
        "the failure classes of a FAILED attempt differ from the file"
    );
    for class in FailureClass::ALL {
        let status = class.attempt_status();
        assert!(
            doc["machines"]["attempt"]["states"][status.to_string()].is_object(),
            "{class} ends in {status}, which the file does not define"
        );
        if status != AttemptStatus::Failed {
            assert_eq!(
                status.to_string(),
                class.to_string(),
                "{class} has a status of its own, spelled the same"
            );
        }
    }

    // The attempt event for each class leads to the status the file names for that event.
    for class in FailureClass::ALL {
        for from in AttemptStatus::STATES {
            if let Some(event) = class.attempt_event(*from) {
                let row = doc["machines"]["attempt"]["transitions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|t| {
                        t["event"].as_str() == Some(event.as_str())
                            && strings_of(&t["from"]).contains(&from.to_string())
                    })
                    .unwrap_or_else(|| panic!("{class}: the file has no {event} from {from}"));
                assert_eq!(
                    row["to"].as_str().unwrap(),
                    class.attempt_status().to_string(),
                    "{class} through {event} from {from}"
                );
            }
        }
    }
    let provision = doc["machines"]["attempt"]["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == "A02")
        .unwrap();
    assert!(
        strings_of(&provision["effects"]).contains("failure class SANDBOX_ERROR"),
        "A02 no longer records SANDBOX_ERROR, so the provision event no longer means that class"
    );

    // The stage contract can list exactly the classes that code calls retryable.
    let schema: Value = serde_json::from_str(STAGE_CONTRACT_SCHEMA).unwrap();
    let listable = strings_of(
        &schema["properties"]["timeout_and_retries"]["properties"]["retry_on"]["items"]["enum"],
    );
    let retryable: BTreeSet<String> = FailureClass::ALL
        .iter()
        .filter_map(|c| c.retry_class())
        .map(|c| c.to_string())
        .collect();
    assert_eq!(
        retryable, listable,
        "the classes code can retry and the classes the stage contract can list differ"
    );
    // The two classes the schema says are never retried have no retry class.
    for never in [FailureClass::BudgetExhausted, FailureClass::PolicyDenied] {
        assert_eq!(never.retry_class(), None, "{never}");
    }
    assert_eq!(
        FailureClass::TimedOut.retry_class(),
        Some(RetryClass::TimedOut)
    );
}

#[test]
fn failure_classes_match_json() {
    failure_classes_match(&DOCUMENT);
}

// ---- the whole file ---------------------------------------------------------------------------

fn conforms(doc: &Value) {
    status_names_match(doc);
    event_names_match(doc);
    guard_and_actor_names_match(doc);
    assurance_levels_release_states_and_stage_kinds_match(doc);
    transition_tables_match(doc);
    cross_products_match(doc);
    invalidation_rules_match(doc);
    rework_routes_match(doc);
    defect_routing_matches(doc);
    human_rework_routes_match(doc);
    rework_cap_matches(doc);
    guard_registry_matches(doc);
    failure_classes_match(doc);
}

#[test]
fn the_unchanged_file_conforms() {
    conforms(&DOCUMENT);
}

/// Runs every check on a changed copy and returns the message of the first one that fails, or
/// `None` if all of them pass.
fn first_failure(changed: &Value) -> Option<String> {
    catch_unwind(AssertUnwindSafe(|| conforms(changed)))
        .err()
        .map(|payload| {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "a check failed without a message".to_owned())
        })
}

fn array_mut<'a>(doc: &'a mut Value, pointer: &str) -> &'a mut Vec<Value> {
    doc.pointer_mut(pointer)
        .and_then(Value::as_array_mut)
        .unwrap_or_else(|| panic!("{pointer} is not an array"))
}

fn transition_mut<'a>(doc: &'a mut Value, machine: &str, id: &str) -> &'a mut Value {
    array_mut(doc, &format!("/machines/{machine}/transitions"))
        .iter_mut()
        .find(|t| t["id"] == id)
        .unwrap_or_else(|| panic!("{id} is not in the {machine} machine"))
}

#[test]
fn conformance_detects_a_changed_table() {
    type Change = fn(&mut Value);
    // Each case changes one thing in a copy of the file and names a phrase that the failing
    // check must print, so a case fails for the wrong reason as loudly as it passes.
    let cases: &[(&str, Change, &str)] = &[
        (
            "a transition added to the stage run table",
            |doc| {
                let mut extra = transition_mut(doc, "stage_run", "S19").clone();
                extra["id"] = json!("S21");
                extra["from"] = json!(["SKIPPED"]);
                array_mut(doc, "/machines/stage_run/transitions").push(extra);
            },
            "stage_run: the number of transitions differs",
        ),
        (
            "a transition removed from the job table",
            |doc| {
                array_mut(doc, "/machines/job/transitions").pop();
            },
            // `complete` is used by one row only, so its event name disappears with it.
            "job events differ",
        ),
        (
            "the target of a transition changed",
            |doc| transition_mut(doc, "stage_run", "S08")["to"] = json!("FAILED"),
            "S08: to",
        ),
        (
            "a source status dropped from a transition",
            |doc| transition_mut(doc, "stage_run", "S20")["from"] = json!(["PENDING", "READY"]),
            "S20: from",
        ),
        (
            "the actors of a transition changed",
            |doc| transition_mut(doc, "attempt", "A09")["actors"] = json!(["engine"]),
            "A09: actors",
        ),
        (
            "the event a transition emits changed",
            |doc| transition_mut(doc, "stage_run", "S08")["emits"] = json!("stage_run.done"),
            "S08: emits",
        ),
        (
            "the guard of a transition changed",
            |doc| transition_mut(doc, "stage_run", "S01")["guard"] = json!("G_ANY_STAGE_BLOCKED"),
            "S01: guard",
        ),
        (
            "an event renamed",
            |doc| transition_mut(doc, "attempt", "A06")["event"] = json!("deadline_hit"),
            "attempt events differ",
        ),
        (
            "a status added to a machine",
            |doc| {
                doc["machines"]["task_node"]["states"]["PARKED"] =
                    json!({ "terminal": false, "meaning": "Invented." });
            },
            "task_node statuses in code and in state-machine.json differ",
        ),
        (
            "a terminal flag flipped",
            |doc| doc["machines"]["task_node"]["states"]["FAILED"]["terminal"] = json!(true),
            "terminal flag differs",
        ),
        (
            "a settled status made supersedable in the file only",
            |doc| {
                doc["machines"]["stage_run"]["states"]["CANCELLED"]["supersedable"] = json!(true);
            },
            "the supersedable flag differs from the file",
        ),
        (
            "the supersedable flag removed from SKIPPED",
            |doc| {
                doc["machines"]["stage_run"]["states"]["SKIPPED"]
                    .as_object_mut()
                    .unwrap()
                    .remove("supersedable");
            },
            "the supersedable flag differs from the file",
        ),
        (
            "a guard added to the file",
            |doc| {
                doc["guards"]["G_INVENTED"] = json!("A guard that code does not have.");
            },
            "the guards in code and in the file differ",
        ),
        (
            "a guard removed from the file",
            |doc| {
                doc["guards"]
                    .as_object_mut()
                    .unwrap()
                    .remove("G_SANDBOX_GONE");
            },
            "the guards in code and in the file differ",
        ),
        (
            "an actor added to the file",
            |doc| {
                doc["actors"]["auditor"] = json!("An actor that code does not have.");
            },
            "the actors in code and in the file differ",
        ),
        (
            "a stage added to an invalidation rule",
            |doc| {
                array_mut(doc, "/pipeline/invalidation_rules/4/supersedes").push(json!("MERGE"));
            },
            "invalidation rule \"DOCUMENTING produces a new documentation commit\"",
        ),
        (
            "an invalidation rule added",
            |doc| {
                let extra = doc["pipeline"]["invalidation_rules"][4].clone();
                array_mut(doc, "/pipeline/invalidation_rules").push(extra);
            },
            "the number of invalidation rules differs",
        ),
        (
            "the intake dropped from the request edit rule",
            |doc| {
                array_mut(doc, "/pipeline/invalidation_rules/5/supersedes").remove(0);
            },
            "invalidation rule \"The source request is edited after the intake snapshot\"",
        ),
        (
            "documenting added to the gate evidence rule",
            |doc| {
                array_mut(doc, "/pipeline/invalidation_rules/7/supersedes")
                    .push(json!("DOCUMENTING"));
            },
            "invalidation rule \"A value bound to gate evidence changes\"",
        ),
        (
            "an invalidation rule removed",
            |doc| {
                array_mut(doc, "/pipeline/invalidation_rules").pop();
            },
            "the number of invalidation rules differs",
        ),
        (
            "an invalidation rule renamed",
            |doc| {
                doc["pipeline"]["invalidation_rules"][6]["when"] =
                    json!("REPOSITORY_INTELLIGENCE produces a map");
            },
            "is in the file but not in code",
        ),
        (
            "a rework route added",
            |doc| {
                let extra = doc["pipeline"]["rework_routes"][0].clone();
                array_mut(doc, "/pipeline/rework_routes").push(extra);
            },
            "the rework routes differ",
        ),
        (
            "the target of a rework route changed",
            |doc| {
                doc["pipeline"]["rework_routes"][4]["target_stage"] = json!("TASK_PLANNING");
            },
            "the rework routes differ",
        ),
        (
            "a cell of the defect routing changed",
            |doc| {
                doc["pipeline"]["defect_routing"]["stages"]["REVIEW"]["policy"] = json!("rework");
            },
            "defect routing REVIEW / policy",
        ),
        (
            "the defect precedence reordered",
            |doc| {
                doc["pipeline"]["defect_routing"]["precedence"] =
                    json!(["policy", "specification", "code_behavior", "documentation"]);
            },
            "the defect precedence differs from the file",
        ),
        (
            "a stage added to the defect routing",
            |doc| {
                let row = doc["pipeline"]["defect_routing"]["stages"]["REVIEW"].clone();
                doc["pipeline"]["defect_routing"]["stages"]["VALIDATION"] = row;
            },
            "the stages with a defect routing differ from the file",
        ),
        (
            "a human rework target added",
            |doc| {
                array_mut(doc, "/pipeline/human_rework_routes/routes/5/targets")
                    .push(json!("DOCUMENTING"));
            },
            "the human rework routes differ from the file",
        ),
        (
            "a human rework target removed",
            |doc| {
                array_mut(doc, "/pipeline/human_rework_routes/routes/9/targets").pop();
            },
            "the human rework routes differ from the file",
        ),
        (
            "a human rework route removed",
            |doc| {
                array_mut(doc, "/pipeline/human_rework_routes/routes").remove(0);
            },
            "the human rework routes differ from the file",
        ),
        (
            "the stages a stage requires changed",
            |doc| {
                array_mut(doc, "/pipeline/stages/4/requires").push(json!("INTAKE"));
            },
            "ARCHITECTURE requires",
        ),
        (
            "a failure class added to the FAILED attempt state",
            |doc| {
                doc["machines"]["attempt"]["states"]["FAILED"]["meaning"] =
                    json!("Ended with a failure class: TOOL_ERROR or ALIEN_ERROR.");
            },
            "the failure classes of a FAILED attempt differ from the file",
        ),
        (
            "the rework cap changed in the invariant",
            |doc| {
                let invariants = array_mut(doc, "/invariants");
                for invariant in invariants.iter_mut().filter(|i| i["id"] == "INV-10") {
                    invariant["statement"] = json!("Attempts are bounded. Three rework rounds.");
                }
            },
            "INV-10 no longer says two and two",
        ),
    ];

    for (name, change, expected) in cases {
        let mut changed = DOCUMENT.clone();
        change(&mut changed);
        assert_ne!(changed, *DOCUMENT, "{name}: the case changed nothing");
        let failure = first_failure(&changed)
            .unwrap_or_else(|| panic!("{name}: the conformance checks did not notice"));
        assert!(
            failure.contains(expected),
            "{name}: the checks failed, but not on {expected:?}. They said: {failure}"
        );
    }
}
