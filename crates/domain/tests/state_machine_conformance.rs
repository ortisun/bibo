//! The Rust state machines must equal `docs/architecture/state-machine.json`, in both directions.
//!
//! The JSON file is the single source of truth. It is embedded at compile time, so this test does
//! no file I/O. Every check goes from the file to the code (nothing in the file is missing from
//! the code) and from the code to the file (nothing in the code is missing from the file), so
//! neither side can drift without a test failing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use factory_domain::state::{
    Actor, AttemptEvent, AttemptStatus, Guard, IllegalTransition, JobEvent, JobStatus, Status,
    StageRunEvent, StageRunStatus, TaskNodeEvent, TaskNodeStatus,
};
use factory_domain::values::{EventType, TransitionId};
use factory_domain::vocabulary::{AssuranceLevel, ReleaseState, StageKind};
use serde_json::Value;

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../docs/architecture/state-machine.json"))
        .expect("state-machine.json is valid JSON")
});

fn strings_of(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

fn keys_of(value: &Value) -> BTreeSet<String> {
    value.as_object().expect("an object").keys().cloned().collect()
}

fn machine_json(name: &str) -> &'static Value {
    &DOCUMENT["machines"][name]
}

// ---- names ------------------------------------------------------------------------------------

fn check_status_names<S: Status>() {
    let json = machine_json(S::MACHINE);
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
    }
}

#[test]
fn status_names_match_state_machine_json() {
    check_status_names::<JobStatus>();
    check_status_names::<StageRunStatus>();
    check_status_names::<AttemptStatus>();
    check_status_names::<TaskNodeStatus>();
}

fn check_event_names<S: Status>() {
    let json = machine_json(S::MACHINE);
    let documented: BTreeSet<String> = json["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["event"].as_str().unwrap().to_owned())
        .collect();
    let in_code: BTreeSet<String> = S::EVENTS.iter().map(ToString::to_string).collect();
    assert_eq!(in_code, documented, "{} events differ", S::MACHINE);
}

#[test]
fn event_names_match_state_machine_json() {
    check_event_names::<JobStatus>();
    check_event_names::<StageRunStatus>();
    check_event_names::<AttemptStatus>();
    check_event_names::<TaskNodeStatus>();
}

#[test]
fn guard_and_actor_names_match_state_machine_json() {
    let guards: BTreeSet<String> = Guard::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(guards, keys_of(&DOCUMENT["guards"]));
    let actors: BTreeSet<String> = Actor::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(actors, keys_of(&DOCUMENT["actors"]));
}

#[test]
fn assurance_levels_release_states_and_stage_kinds_match_state_machine_json() {
    let levels: BTreeSet<String> = DOCUMENT["assurance_levels"]["levels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["level"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        AssuranceLevel::ALL.iter().map(ToString::to_string).collect::<BTreeSet<_>>(),
        levels
    );

    assert_eq!(
        ReleaseState::ALL.iter().map(ToString::to_string).collect::<BTreeSet<_>>(),
        strings_of(&DOCUMENT["assurance_levels"]["release_states"]["values"])
    );

    // Stage kinds, in pipeline order, with the stages each one waits for.
    let stages = DOCUMENT["pipeline"]["stages"].as_array().unwrap();
    let documented_order: Vec<&str> = stages.iter().map(|s| s["kind"].as_str().unwrap()).collect();
    let code_order: Vec<&str> = StageKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(code_order, documented_order, "stage kinds or their order differ");
    for stage in stages {
        let kind = StageKind::parse(stage["kind"].as_str().unwrap()).unwrap();
        let documented_requires = strings_of(&stage["requires"]);
        let in_code: BTreeSet<String> = kind.requires().iter().map(ToString::to_string).collect();
        assert_eq!(in_code, documented_requires, "{kind} requires");
    }
}

// ---- transitions ------------------------------------------------------------------------------

fn check_transition_table<S: Status>() {
    let json = machine_json(S::MACHINE);
    let documented = json["transitions"].as_array().unwrap();
    assert_eq!(
        S::TRANSITIONS.len(),
        documented.len(),
        "{}: the number of transitions differs from the file",
        S::MACHINE
    );

    let in_code: BTreeMap<&str, _> = S::TRANSITIONS.iter().map(|t| (t.id, t)).collect();
    assert_eq!(in_code.len(), S::TRANSITIONS.len(), "a transition id repeats");

    for entry in documented {
        let id = entry["id"].as_str().unwrap();
        let t = in_code
            .get(id)
            .unwrap_or_else(|| panic!("{}: transition {id} is in the file but not in code", S::MACHINE));
        let from_in_code: BTreeSet<String> = t.from.iter().map(ToString::to_string).collect();
        assert_eq!(from_in_code, strings_of(&entry["from"]), "{id}: from");
        assert_eq!(t.event.to_string(), entry["event"].as_str().unwrap(), "{id}: event");
        assert_eq!(t.guard.to_string(), entry["guard"].as_str().unwrap(), "{id}: guard");
        assert_eq!(t.to.to_string(), entry["to"].as_str().unwrap(), "{id}: to");
        let actors_in_code: BTreeSet<String> = t.actors.iter().map(ToString::to_string).collect();
        assert_eq!(actors_in_code, strings_of(&entry["actors"]), "{id}: actors");
        assert_eq!(t.emits, entry["emits"].as_str(), "{id}: emits");
        // The id must be one the domain event schema accepts.
        TransitionId::parse(id).unwrap();
    }
}

#[test]
fn transition_tables_match_state_machine_json() {
    check_transition_table::<JobStatus>();
    check_transition_table::<StageRunStatus>();
    check_transition_table::<AttemptStatus>();
    check_transition_table::<TaskNodeStatus>();
}

/// The cross product of all statuses and all events: a pair is accepted if and only if the file
/// lists it (INV-02). The oracle is the JSON file, not the Rust table.
fn check_cross_product<S: Status>() {
    let json = machine_json(S::MACHINE);
    let mut documented: BTreeMap<(String, String), String> = BTreeMap::new();
    for t in json["transitions"].as_array().unwrap() {
        for from in t["from"].as_array().unwrap() {
            documented.insert(
                (from.as_str().unwrap().to_owned(), t["event"].as_str().unwrap().to_owned()),
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

#[test]
fn every_status_and_event_pair_outside_the_table_is_rejected() {
    check_cross_product::<JobStatus>();
    check_cross_product::<StageRunStatus>();
    check_cross_product::<AttemptStatus>();
    check_cross_product::<TaskNodeStatus>();
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
                let event_type = EventType::parse(name)
                    .unwrap_or_else(|e| panic!("{}: {} emits an invalid type: {e}", S::MACHINE, t.id));
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
        JobStatus::TRANSITIONS.iter().map(|t| (t.id, t.emits)).collect::<Vec<_>>(),
        StageRunStatus::TRANSITIONS.iter().map(|t| (t.id, t.emits)).collect(),
        AttemptStatus::TRANSITIONS.iter().map(|t| (t.id, t.emits)).collect(),
        TaskNodeStatus::TRANSITIONS.iter().map(|t| (t.id, t.emits)).collect(),
    ]
    .into_iter()
    .flatten()
    .filter(|(_, emits)| emits.is_none())
    .map(|(id, _)| id)
    .collect();
    assert_eq!(silent, ["A03"], "the heartbeat is the only silent transition");
    assert_eq!(
        AttemptStatus::Running.apply(AttemptEvent::Heartbeat),
        Ok(AttemptStatus::Running)
    );
}

// ---- the documented exceptions to "terminal means no exit" -----------------------------------

#[test]
fn a_passed_stage_run_can_only_be_superseded() {
    assert!(StageRunStatus::Passed.is_terminal());
    let exits: Vec<StageRunEvent> = StageRunStatus::EVENTS
        .iter()
        .copied()
        .filter(|event| StageRunStatus::Passed.apply(*event).is_ok())
        .collect();
    assert_eq!(exits, [StageRunEvent::Supersede]);
    assert_eq!(
        StageRunStatus::Passed.apply(StageRunEvent::Supersede),
        Ok(StageRunStatus::Superseded)
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
    assert_eq!(JobStatus::Received.apply(JobEvent::Admit), Ok(JobStatus::Active));
    assert_eq!(
        JobStatus::Received.apply(JobEvent::RejectAtAdmission),
        Ok(JobStatus::Rejected)
    );
    assert!(JobStatus::Active.apply(JobEvent::RejectAtAdmission).is_err());
}
