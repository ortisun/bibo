//! Property-based tests for the four state machines.
//!
//! The oracle is `docs/architecture/state-machine.json`, not the Rust table, so a mistake copied
//! into both the table and a test cannot hide. A walk picks a legal event most of the time and a
//! random event the rest of the time, so the tests meet both accepted and rejected moves.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::LazyLock;

use factory_domain::state::{
    AttemptStatus, JobStatus, StageRunEvent, StageRunStatus, Status, TaskNodeStatus,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use serde_json::Value;

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../docs/architecture/state-machine.json"
    ))
    .expect("state-machine.json is valid JSON")
});

/// What the file allows: (from, event) to the next status.
fn documented_moves(machine: &str) -> BTreeMap<(String, String), String> {
    let mut moves = BTreeMap::new();
    for t in DOCUMENT["machines"][machine]["transitions"]
        .as_array()
        .unwrap()
    {
        for from in t["from"].as_array().unwrap() {
            moves.insert(
                (
                    from.as_str().unwrap().to_owned(),
                    t["event"].as_str().unwrap().to_owned(),
                ),
                t["to"].as_str().unwrap().to_owned(),
            );
        }
    }
    moves
}

fn documented_terminal(machine: &str) -> BTreeSet<String> {
    DOCUMENT["machines"][machine]["states"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, flags)| flags["terminal"].as_bool().unwrap())
        .map(|(name, _)| name.clone())
        .collect()
}

fn documented_supersedable(machine: &str) -> BTreeSet<String> {
    DOCUMENT["machines"][machine]["states"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, flags)| flags["supersedable"].as_bool().unwrap_or(false))
        .map(|(name, _)| name.clone())
        .collect()
}

/// One step of a walk: prefer a legal event when `prefer_legal`, pick by `index` modulo the pool.
fn steps() -> impl Strategy<Value = Vec<(bool, usize)>> {
    vec((proptest::bool::weighted(0.8), any::<usize>()), 0..60)
}

fn pick<S: Status>(state: S, (prefer_legal, index): (bool, usize)) -> S::Event {
    let legal = state.legal_events();
    if prefer_legal && !legal.is_empty() {
        legal[index % legal.len()]
    } else {
        S::EVENTS[index % S::EVENTS.len()]
    }
}

fn run<S: Status>(property: impl Fn(Vec<(bool, usize)>) -> Result<(), TestCaseError>) {
    let mut runner = TestRunner::new(Config {
        cases: 512,
        ..Config::default()
    });
    runner
        .run(&steps(), property)
        .unwrap_or_else(|failure| panic!("{} machine: {failure}", S::MACHINE));
}

// ---- walks stay inside the documented machine ---------------------------------------------------

fn walks_follow_the_file<S: Status>() {
    let moves = documented_moves(S::MACHINE);
    run::<S>(|walk| {
        let mut state = S::INITIAL;
        for step in walk {
            let event = pick(state, step);
            let before = state;
            let documented = moves.get(&(before.to_string(), event.to_string()));
            match state.advance(event) {
                Ok(transition) => {
                    prop_assert_eq!(
                        Some(&state.to_string()),
                        documented,
                        "{} on {} was accepted but the file disagrees",
                        before,
                        event
                    );
                    prop_assert_eq!(transition.to, state);
                    prop_assert!(S::STATES.contains(&state));
                }
                Err(_) => {
                    prop_assert!(
                        documented.is_none(),
                        "{} on {} is documented but was rejected",
                        before,
                        event
                    );
                    prop_assert_eq!(
                        state,
                        before,
                        "a rejected event must leave the status unchanged"
                    );
                }
            }
        }
        Ok(())
    });
}

#[test]
fn random_walks_follow_the_documented_machine() {
    walks_follow_the_file::<JobStatus>();
    walks_follow_the_file::<StageRunStatus>();
    walks_follow_the_file::<AttemptStatus>();
    walks_follow_the_file::<TaskNodeStatus>();
}

// ---- terminal states have no exits ----------------------------------------------------------------

fn terminal_statuses_absorb<S: Status>() {
    let supersedable = documented_supersedable(S::MACHINE);
    run::<S>(|walk| {
        let mut state = S::INITIAL;
        let mut reached_terminal = false;
        for step in walk {
            let event = pick(state, step);
            let before = state;
            let _ = state.advance(event);
            if reached_terminal {
                let allowed =
                    supersedable.contains(&before.to_string()) && event.to_string() == "supersede";
                prop_assert!(
                    state == before || allowed,
                    "left the terminal status {} on {}",
                    before,
                    event
                );
            }
            reached_terminal = state.is_terminal();
        }
        Ok(())
    });
}

#[test]
fn terminal_states_have_no_exits_on_any_random_walk() {
    terminal_statuses_absorb::<JobStatus>();
    terminal_statuses_absorb::<StageRunStatus>();
    terminal_statuses_absorb::<AttemptStatus>();
    terminal_statuses_absorb::<TaskNodeStatus>();
}

fn terminal_statuses_have_no_exit_in_the_cross_product<S: Status>() {
    let supersedable = documented_supersedable(S::MACHINE);
    let terminal = documented_terminal(S::MACHINE);
    assert!(
        !terminal.is_empty(),
        "{} has no terminal status",
        S::MACHINE
    );
    for state in S::STATES.iter().filter(|s| s.is_terminal()) {
        let exits: Vec<String> = S::EVENTS
            .iter()
            .filter(|event| state.apply(**event).is_ok())
            .map(ToString::to_string)
            .collect();
        if supersedable.contains(&state.to_string()) {
            assert_eq!(exits, ["supersede"], "{}.{state}", S::MACHINE);
        } else {
            assert!(
                exits.is_empty(),
                "{}.{state} is terminal but exits on {exits:?}",
                S::MACHINE
            );
        }
    }
}

#[test]
fn terminal_states_have_no_exits_over_the_whole_cross_product() {
    terminal_statuses_have_no_exit_in_the_cross_product::<JobStatus>();
    terminal_statuses_have_no_exit_in_the_cross_product::<StageRunStatus>();
    terminal_statuses_have_no_exit_in_the_cross_product::<AttemptStatus>();
    terminal_statuses_have_no_exit_in_the_cross_product::<TaskNodeStatus>();
}

// ---- reachability and liveness ----------------------------------------------------------------------

fn successors<S: Status>(state: S) -> Vec<S> {
    state
        .legal_events()
        .into_iter()
        .filter_map(|e| state.apply(e).ok())
        .collect()
}

fn reachable<S: Status>(start: S) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([start.to_string()]);
    let mut queue = VecDeque::from([start]);
    while let Some(state) = queue.pop_front() {
        for next in successors(state) {
            if seen.insert(next.to_string()) {
                queue.push_back(next);
            }
        }
    }
    seen
}

fn every_status_is_reachable_and_can_finish<S: Status>() {
    let from_start = reachable(S::INITIAL);
    let all: BTreeSet<String> = S::STATES.iter().map(ToString::to_string).collect();
    assert_eq!(
        from_start,
        all,
        "{}: some status cannot be reached from the initial one",
        S::MACHINE
    );
    for state in S::STATES {
        let can_reach_terminal = reachable(*state)
            .iter()
            .any(|name| S::parse_name(name).is_some_and(Status::is_terminal));
        assert!(
            can_reach_terminal,
            "{}.{state} can never reach a terminal status",
            S::MACHINE
        );
    }
}

#[test]
fn every_status_is_reachable_and_none_is_a_dead_end() {
    every_status_is_reachable_and_can_finish::<JobStatus>();
    every_status_is_reachable_and_can_finish::<StageRunStatus>();
    every_status_is_reachable_and_can_finish::<AttemptStatus>();
    every_status_is_reachable_and_can_finish::<TaskNodeStatus>();
}

// ---- supersession and rework never reopen a run ------------------------------------------------------

#[test]
fn a_superseded_or_reworked_stage_run_never_comes_back() {
    for dead in [
        StageRunStatus::Superseded,
        StageRunStatus::ReworkRequested,
        StageRunStatus::Failed,
        StageRunStatus::Skipped,
        StageRunStatus::Cancelled,
    ] {
        assert!(dead.is_terminal());
        for event in StageRunStatus::EVENTS {
            assert!(
                dead.apply(*event).is_err(),
                "{dead} must not leave on {event}: a terminal stage run is never reopened (INV-04)"
            );
        }
    }
    assert!(
        StageRunStatus::Passed
            .apply(StageRunEvent::Supersede)
            .is_ok()
    );
}
