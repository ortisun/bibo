//! Property-based tests for the four state machines.
//!
//! The oracle is `docs/architecture/state-machine.json`, not the Rust table, so a mistake copied
//! into both the table and a test cannot hide. A walk picks a legal event most of the time and a
//! random event the rest of the time, so the tests meet both accepted and rejected moves.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::LazyLock;

use factory_domain::contracts::review_verdict::DefectClass;
use factory_domain::contracts::stage_contract::RetryClass;
use factory_domain::ids::StageRunId;
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::stage_run::{
    escalation_required, failure_nonretryable, gate_pass_evidenced, override_permitted,
    retry_allowed, rework_allowed,
};
use factory_domain::machines::guards::{
    AdmissionFacts, DeadlineFacts, EnvironmentCause, GatePassFacts, LeaseExpiryFacts,
    OverrideFacts, PipelineScopeFacts, RetryFacts, ReworkFacts,
};
use factory_domain::machines::guards::{attempt, job};
use factory_domain::machines::invalidation::{ArtifactChange, plan_for_change, plan_for_rework};
use factory_domain::machines::limits::{
    DEFAULT_REWORK_CAP, RepairCap, ReworkCap, ReworkLedger, ReworkLimits, ReworkTrack,
};
use factory_domain::machines::retry::{
    AttemptDisposition, AttemptWindow, EscalationCause, WindowEvent, decide_after_failure,
};
use factory_domain::machines::rework::{
    GateFinding, GateReworkDecision, GateReworkRequest, HumanReworkDecision, HumanReworkRequest,
    decide_gate_rework, decide_human_rework, human_targets,
};
use factory_domain::machines::snapshot::{GateReportSnapshot, StageRunSnapshot};
use factory_domain::state::{
    AttemptStatus, JobStatus, StageRunEvent, StageRunStatus, Status, TaskNodeStatus,
};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{GateOutcome, HumanRole, StageKind};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
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

/// How many generated command sequences each machine must survive (QA-1).
const SEQUENCES: u32 = 10_000;

fn run<S: Status>(property: impl Fn(Vec<(bool, usize)>) -> Result<(), TestCaseError>) {
    let mut runner = TestRunner::new(Config {
        cases: SEQUENCES,
        // A failing case is reported in the test output. No regression file is written into
        // the source tree.
        failure_persistence: None,
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
    // A passed run and a skipped run can still go stale (ADR 0010).
    for settled in [StageRunStatus::Passed, StageRunStatus::Skipped] {
        assert!(settled.apply(StageRunEvent::Supersede).is_ok());
    }
}

// =================================================================================================
// The rules on top of the tables: guards, failures, rework, invalidation.
// =================================================================================================

/// How many generated pipelines the simulation must survive.
const SIMULATIONS: u32 = 3_000;

fn runner(cases: u32) -> TestRunner {
    TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    })
}

// ---- a pipeline simulation -----------------------------------------------------------------------------
//
// One stage run per stage kind to start with. Random actions then move the runs through the
// stage run table, plant artifact changes, and ask for rework from gates and from humans. The
// simulation applies only what the domain functions decide, with the same events the engine
// would use, and checks the rules of the package after every action.

#[derive(Debug, Clone)]
enum Action {
    /// A random stage run event on a random run, other than the two rework events, which only
    /// the rework decisions may cause.
    Event { run: usize, step: (bool, usize) },
    /// A run takes one step along the happy path: ready, running, gating. Without this the
    /// random events rarely carry a run as far as its gate.
    Advance { run: usize },
    /// An upstream artifact changed.
    Change { which: usize },
    /// A gate finding on a run that is `GATING`.
    GateRework {
        run: usize,
        defect: usize,
        verdict: bool,
        differs: bool,
        budget: bool,
    },
    /// A human asks for rework on a run that is waiting or blocked, naming a target stage.
    HumanRework {
        run: usize,
        roles: u8,
        target: usize,
    },
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        6 => (any::<usize>(), (proptest::bool::weighted(0.85), any::<usize>()))
            .prop_map(|(run, step)| Action::Event { run, step }),
        5 => any::<usize>().prop_map(|run| Action::Advance { run }),
        1 => any::<usize>().prop_map(|which| Action::Change { which }),
        6 => (
            any::<usize>(),
            any::<usize>(),
            any::<bool>(),
            proptest::bool::weighted(0.8),
            proptest::bool::weighted(0.9),
        )
            .prop_map(|(run, defect, verdict, differs, budget)| Action::GateRework {
                run,
                defect,
                verdict,
                differs,
                budget,
            }),
        2 => (any::<usize>(), any::<u8>(), any::<usize>())
            .prop_map(|(run, roles, target)| Action::HumanRework { run, roles, target }),
    ]
}

fn defect_from(index: usize) -> Option<DefectClass> {
    [
        None,
        Some(DefectClass::CodeBehavior),
        Some(DefectClass::Documentation),
        Some(DefectClass::Specification),
        Some(DefectClass::Policy),
    ][index % 5]
}

fn roles_from(bits: u8) -> Vec<HumanRole> {
    HumanRole::ALL
        .iter()
        .enumerate()
        .filter(|(index, _)| bits & (1 << index) != 0)
        .map(|(_, role)| *role)
        .collect()
}

struct Sim {
    runs: Vec<StageRunSnapshot>,
    ledger: ReworkLedger,
    limits: ReworkLimits,
    granted: [u8; 2],
    next_id: u128,
}

fn track_index(track: ReworkTrack) -> usize {
    match track {
        ReworkTrack::Code => 0,
        ReworkTrack::Documentation => 1,
    }
}

impl Sim {
    fn new(limits: ReworkLimits) -> Self {
        let runs: Vec<StageRunSnapshot> = StageKind::ALL
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                StageRunSnapshot::new(
                    StageRunId::from_uuid(uuid::Uuid::from_u128(index as u128 + 1)),
                    *kind,
                    StageRunStatus::Pending,
                )
            })
            .collect();
        let next_id = runs.len() as u128 + 1;
        Self {
            runs,
            ledger: ReworkLedger::default(),
            limits,
            granted: [0, 0],
            next_id,
        }
    }

    fn statuses(&self) -> BTreeMap<StageRunId, StageRunStatus> {
        self.runs.iter().map(|r| (r.id, r.status)).collect()
    }

    fn run_mut(&mut self, id: StageRunId) -> &mut StageRunSnapshot {
        self.runs
            .iter_mut()
            .find(|r| r.id == id)
            .expect("the run exists")
    }

    fn supersede(&mut self, planned: &[StageRunId]) -> Result<(), TestCaseError> {
        for id in planned {
            let result = self.run_mut(*id).status.advance(StageRunEvent::Supersede);
            prop_assert!(result.is_ok(), "a planned run refused to be superseded");
        }
        Ok(())
    }

    fn start_new_run(&mut self, kind: StageKind) {
        let id = StageRunId::from_uuid(uuid::Uuid::from_u128(self.next_id));
        self.next_id += 1;
        self.runs
            .push(StageRunSnapshot::new(id, kind, StageRunStatus::Pending));
    }

    /// Starts the rework a plan describes. The failing run has already taken its event.
    fn start_rework(
        &mut self,
        index: usize,
        event: StageRunEvent,
        target: StageKind,
        track: ReworkTrack,
        ledger_after: ReworkLedger,
    ) -> Result<(), TestCaseError> {
        let failing = self.runs[index].id;
        // Plan first, while the failing run is still in its gate. The plan must leave the failing
        // run out, because that run takes the rework transition and a run has one outcome.
        let planned = plan_for_rework(&self.runs, target, failing);
        prop_assert!(
            !planned.contains(&failing),
            "the failing run was planned for supersession"
        );
        let accepted = self.runs[index].status.advance(event);
        prop_assert!(accepted.is_ok(), "{event} is not legal for the failing run");
        self.supersede(&planned)?;
        self.start_new_run(target);
        self.ledger = ledger_after;
        self.granted[track_index(track)] += 1;

        // The failing run took the rework transition, and was not superseded on the way.
        prop_assert_eq!(
            self.run_mut(failing).status,
            StageRunStatus::ReworkRequested
        );
        // No old run of the target or of anything after it is left live, except the new one.
        let newest = self.runs.last().map(|r| r.id);
        let replaced = factory_domain::machines::invalidation::rework_stages(target);
        for run in &self.runs {
            if replaced.contains(&run.kind) && Some(run.id) != newest && run.id != failing {
                prop_assert!(
                    run.status.apply(StageRunEvent::Supersede).is_err(),
                    "an old {} run is still live after rework to {}",
                    run.kind,
                    target
                );
            }
        }
        Ok(())
    }

    fn step(&mut self, action: &Action) -> Result<(), TestCaseError> {
        let before = self.statuses();
        let ledger_before = self.ledger;
        match action {
            Action::Event { run, step } => {
                let index = run % self.runs.len();
                let status = self.runs[index].status;
                let event = pick(status, *step);
                if !matches!(
                    event,
                    StageRunEvent::GateRequiresRework | StageRunEvent::HumanRequestedRework
                ) {
                    let _ = self.runs[index].status.advance(event);
                }
            }
            Action::Advance { run } => {
                let index = run % self.runs.len();
                for event in [
                    StageRunEvent::PreconditionsMet,
                    StageRunEvent::Start,
                    StageRunEvent::AttemptSucceeded,
                ] {
                    if self.runs[index].status.advance(event).is_ok() {
                        break;
                    }
                }
            }
            Action::Change { which } => {
                let change = ArtifactChange::ALL[which % ArtifactChange::ALL.len()];
                let producer_before: Vec<_> = self
                    .runs
                    .iter()
                    .filter(|r| Some(r.kind) == change.producer())
                    .map(|r| r.status)
                    .collect();
                let planned = plan_for_change(&self.runs, change);
                self.supersede(&planned)?;
                // Nothing that the change makes stale is left live.
                prop_assert!(
                    plan_for_change(&self.runs, change).is_empty(),
                    "a stale run is still live after {change}"
                );
                // The stage that produced the artifact is never made stale by it. A change that no
                // stage produces (an edited request, a moved base branch) spares nobody.
                let producer_after: Vec<_> = self
                    .runs
                    .iter()
                    .filter(|r| Some(r.kind) == change.producer())
                    .map(|r| r.status)
                    .collect();
                prop_assert_eq!(producer_before, producer_after);
            }
            Action::GateRework {
                run,
                defect,
                verdict,
                differs,
                budget,
            } => {
                let gating: Vec<usize> = (0..self.runs.len())
                    .filter(|i| self.runs[*i].status == StageRunStatus::Gating)
                    .collect();
                if gating.is_empty() {
                    return self.check(&before, ledger_before);
                }
                let index = gating[run % gating.len()];
                let failing = self.runs[index];
                let decision = decide_gate_rework(&GateReworkRequest {
                    from: failing.kind,
                    defect: defect_from(*defect),
                    finding: if *verdict {
                        GateFinding::VerdictChangesRequired
                    } else {
                        GateFinding::DeterministicGateFailed
                    },
                    ledger: self.ledger,
                    limits: self.limits,
                    failing_set_differs: *differs,
                    budget_remains: *budget,
                });
                if let GateReworkDecision::Rework(plan) = decision {
                    self.start_rework(
                        index,
                        decision.event(),
                        plan.target,
                        plan.track,
                        plan.ledger_after,
                    )?;
                } else {
                    let accepted = self.runs[index].status.advance(decision.event());
                    prop_assert!(accepted.is_ok(), "{decision:?} is not legal from GATING");
                    prop_assert_eq!(self.ledger, ledger_before);
                }
            }
            Action::HumanRework { run, roles, target } => {
                let waiting: Vec<usize> = (0..self.runs.len())
                    .filter(|i| {
                        matches!(
                            self.runs[*i].status,
                            StageRunStatus::WaitingForHuman | StageRunStatus::Blocked
                        )
                    })
                    .collect();
                if waiting.is_empty() {
                    return self.check(&before, ledger_before);
                }
                let index = waiting[run % waiting.len()];
                let failing = self.runs[index];
                let roles = roles_from(*roles);
                let target = StageKind::ALL[target % StageKind::ALL.len()];
                let decision = decide_human_rework(&HumanReworkRequest {
                    from: failing.kind,
                    target,
                    principal_roles: &roles,
                    ledger: self.ledger,
                    limits: self.limits,
                });
                match decision {
                    HumanReworkDecision::Rework(plan) => {
                        // Only a target that the file lists for the waiting stage is accepted.
                        prop_assert_eq!(plan.target, target);
                        prop_assert!(human_targets(failing.kind).contains(&target));
                        self.start_rework(
                            index,
                            StageRunEvent::HumanRequestedRework,
                            plan.target,
                            plan.track,
                            plan.ledger_after,
                        )?;
                    }
                    HumanReworkDecision::Refused(_) | HumanReworkDecision::NoRoute(_) => {
                        prop_assert_eq!(self.ledger, ledger_before);
                    }
                }
            }
        }
        self.check(&before, ledger_before)
    }

    /// The rules that must hold after every action.
    fn check(
        &self,
        before: &BTreeMap<StageRunId, StageRunStatus>,
        ledger_before: ReworkLedger,
    ) -> Result<(), TestCaseError> {
        for (id, was) in before {
            let now = self
                .runs
                .iter()
                .find(|r| r.id == *id)
                .map(|r| r.status)
                .expect("a run is never deleted");
            // Terminal means no exit, except that a passed or a skipped run can be superseded.
            if was.is_terminal() {
                prop_assert!(
                    now == *was
                        || (matches!(*was, StageRunStatus::Passed | StageRunStatus::Skipped)
                            && now == StageRunStatus::Superseded),
                    "{was} became {now}"
                );
            }
            // A superseded run is never resurrected.
            if *was == StageRunStatus::Superseded {
                prop_assert_eq!(now, StageRunStatus::Superseded);
            }
        }
        // Invalidation only ever adds to the stale set.
        let superseded_before: BTreeSet<StageRunId> = before
            .iter()
            .filter(|(_, s)| **s == StageRunStatus::Superseded)
            .map(|(id, _)| *id)
            .collect();
        let superseded_now: BTreeSet<StageRunId> = self
            .runs
            .iter()
            .filter(|r| r.status == StageRunStatus::Superseded)
            .map(|r| r.id)
            .collect();
        prop_assert!(superseded_before.is_subset(&superseded_now));

        // Rework never goes over the cap, and the cap never goes over two.
        for track in [ReworkTrack::Code, ReworkTrack::Documentation] {
            let used = self.ledger.used(track);
            let cap = self.limits.cap(track).get();
            prop_assert!(used <= cap, "{track} rework used {used} of a cap of {cap}");
            prop_assert!(cap <= DEFAULT_REWORK_CAP);
            prop_assert_eq!(used, self.granted[track_index(track)]);
            // A ledger only moves forward.
            prop_assert!(used >= ledger_before.used(track));
        }
        Ok(())
    }
}

fn limits_from(code: u8, documentation: u8) -> ReworkLimits {
    ReworkLimits::from_policy(code, documentation)
}

#[test]
fn a_simulated_pipeline_keeps_every_rule_after_every_action() {
    let strategy = (any::<u8>(), any::<u8>(), vec(action(), 0..80));
    runner(SIMULATIONS)
        .run(&strategy, |(code, documentation, actions)| {
            let mut sim = Sim::new(limits_from(code, documentation));
            for action in &actions {
                sim.step(action)?;
            }
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

/// A runner whose random numbers come from a fixed seed, so a test that counts what the
/// generator reaches counts the same thing on every run.
fn seeded_runner(cases: u32, seed: u8) -> TestRunner {
    TestRunner::new_with_rng(
        Config {
            cases,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &[seed; 32]),
    )
}

/// Index of the newest run of `kind`.
fn newest(sim: &Sim, kind: StageKind) -> usize {
    sim.runs
        .iter()
        .rposition(|run| run.kind == kind)
        .expect("a run of the stage exists")
}

/// Carries the newest run of `kind` from PENDING to GATING with the happy-path action.
fn advance_to_gating(sim: &mut Sim, kind: StageKind) {
    for _ in 0..3 {
        let run = newest(sim, kind);
        sim.step(&Action::Advance { run })
            .expect("the happy path keeps every rule");
    }
    let run = newest(sim, kind);
    assert_eq!(
        sim.runs[run].status,
        StageRunStatus::Gating,
        "three happy-path steps carry a {kind} run to its gate"
    );
}

/// A gate finding on the only run that is gating: a verdict that asks for changes, with a failing
/// set that differs from the last round and budget left.
fn ask_for_rework() -> Action {
    Action::GateRework {
        run: 0,
        defect: 0,
        verdict: true,
        differs: true,
        budget: true,
    }
}

#[test]
fn a_directed_route_reaches_rework_supersession_and_the_cap() {
    // The simulation must be able to grant rework, supersede runs and use the whole cap, or its
    // checks would be vacuous. This route proves it with no randomness: a specification run is
    // sent back twice, and the third request meets the cap.
    let mut sim = Sim::new(limits_from(2, 2));
    assert_eq!(
        sim.limits.cap(ReworkTrack::Code).get(),
        2,
        "the cap is two rounds"
    );

    advance_to_gating(&mut sim, StageKind::Specification);
    sim.step(&ask_for_rework())
        .expect("round one keeps every rule");
    assert_eq!(sim.granted[0], 1, "the first request was granted");
    assert!(
        sim.runs
            .iter()
            .any(|r| r.status == StageRunStatus::Superseded),
        "rework to the specification superseded the runs after it"
    );
    assert_eq!(
        sim.runs[newest(&sim, StageKind::Specification)].status,
        StageRunStatus::Pending,
        "the rework started a new specification run"
    );

    advance_to_gating(&mut sim, StageKind::Specification);
    sim.step(&ask_for_rework())
        .expect("round two keeps every rule");
    assert_eq!(sim.granted[0], 2, "the second request was granted");
    assert_eq!(
        sim.granted[0],
        sim.limits.cap(ReworkTrack::Code).get(),
        "the whole cap is used"
    );

    advance_to_gating(&mut sim, StageKind::Specification);
    sim.step(&ask_for_rework())
        .expect("a request over the cap keeps every rule");
    assert_eq!(
        sim.granted[0], 2,
        "a third request is not granted: the cap holds"
    );
    assert_eq!(
        sim.runs[newest(&sim, StageKind::Specification)].status,
        StageRunStatus::WaitingForHuman,
        "a request over the cap asks a person"
    );
}

#[test]
fn the_generated_simulation_reaches_rework_supersession_and_the_cap() {
    // The same guard for the random strategy, with a fixed seed: it counts the same on every run,
    // so it cannot fail by bad luck. If the strategy or the simulation stops reaching rework, the
    // cap or supersession, the counts drop to zero and this fails on every run.
    let strategy = (any::<u8>(), any::<u8>(), vec(action(), 40..80));
    let mut runner = seeded_runner(1_000, 7);
    let seen = std::cell::RefCell::new((0u32, 0u32, 0u32));
    runner
        .run(&strategy, |(code, documentation, actions)| {
            let mut sim = Sim::new(limits_from(code, documentation));
            for action in &actions {
                sim.step(action)?;
            }
            let mut seen = seen.borrow_mut();
            if sim.granted.iter().any(|g| *g > 0) {
                seen.0 += 1;
            }
            if sim.granted[0] == sim.limits.cap(ReworkTrack::Code).get() && sim.granted[0] > 0 {
                seen.1 += 1;
            }
            if sim
                .runs
                .iter()
                .any(|r| r.status == StageRunStatus::Superseded)
            {
                seen.2 += 1;
            }
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
    let (granted, hit_cap, superseded) = *seen.borrow();
    assert!(granted > 0, "no simulation ever granted rework");
    assert!(hit_cap > 0, "no simulation ever used the whole cap");
    assert!(superseded > 0, "no simulation ever superseded a run");
}

// ---- rework never exceeds the cap ----------------------------------------------------------------------------

#[test]
fn rework_never_exceeds_the_cap_whatever_the_policy_says() {
    let strategy = (
        any::<u8>(),
        any::<u8>(),
        vec(
            (
                any::<usize>(),
                any::<usize>(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
            ),
            0..40,
        ),
    );
    runner(SEQUENCES)
        .run(&strategy, |(code, documentation, requests)| {
            let limits = limits_from(code, documentation);
            let mut ledger = ReworkLedger::default();
            for (stage, defect, verdict, differs, budget) in requests {
                let request = GateReworkRequest {
                    from: StageKind::ALL[stage % StageKind::ALL.len()],
                    defect: defect_from(defect),
                    finding: if verdict {
                        GateFinding::VerdictChangesRequired
                    } else {
                        GateFinding::DeterministicGateFailed
                    },
                    ledger,
                    limits,
                    failing_set_differs: differs,
                    budget_remains: budget,
                };
                let decision = decide_gate_rework(&request);
                match decision {
                    GateReworkDecision::Rework(plan) => {
                        // The round was within the cap before it was taken.
                        prop_assert!(ledger.has_room(plan.track, limits));
                        prop_assert_eq!(plan.round, ledger.used(plan.track) + 1);
                        ledger = plan.ledger_after;
                    }
                    GateReworkDecision::NeedsHuman(_) | GateReworkDecision::NoRoute(_) => {
                        // Asking a human changes nothing in the ledger.
                    }
                }
                for track in [ReworkTrack::Code, ReworkTrack::Documentation] {
                    prop_assert!(ledger.used(track) <= limits.cap(track).get());
                    prop_assert!(ledger.used(track) <= DEFAULT_REWORK_CAP);
                }
            }
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn a_ledger_cannot_be_pushed_past_its_cap_by_any_number_of_requests() {
    for configured in 0..=u8::MAX {
        let limits = limits_from(configured, configured);
        let mut ledger = ReworkLedger::default();
        let mut taken = 0u32;
        for _ in 0..600 {
            if let Ok(next) = ledger.start_round(ReworkTrack::Code, limits) {
                ledger = next;
                taken += 1;
            }
        }
        assert_eq!(taken, u32::from(configured.min(DEFAULT_REWORK_CAP)));
    }
}

// ---- failures ---------------------------------------------------------------------------------------------------

fn retry_classes_from(mask: u8) -> Vec<RetryClass> {
    [
        RetryClass::ToolError,
        RetryClass::InvalidOutput,
        RetryClass::ProviderError,
        RetryClass::SandboxError,
        RetryClass::TimedOut,
        RetryClass::LeaseLost,
    ]
    .into_iter()
    .enumerate()
    .filter(|(index, _)| mask & (1 << index) != 0)
    .map(|(_, class)| class)
    .collect()
}

#[test]
fn an_always_failing_runtime_ends_in_a_human_or_a_failure_within_max_attempts() {
    // INV-10 in miniature: keep failing, whatever the class and the contract, and the stage run
    // stops within `max_attempts` attempts, in WAITING_FOR_HUMAN or FAILED. It never loops.
    let strategy = (
        0..FailureClass::ALL.len(),
        any::<u8>(),
        1u32..=10,
        vec(any::<bool>(), 1..12),
        any::<u8>(),
    );
    runner(SEQUENCES)
        .run(
            &strategy,
            |(class, mask, max_attempts, budget, repair_cap)| {
                let class = FailureClass::ALL[class];
                let retry_on = retry_classes_from(mask);
                let mut stage = StageRunStatus::Running;
                let mut used = 0;
                loop {
                    used += 1;
                    prop_assert!(
                        used <= max_attempts,
                        "still going after {max_attempts} attempts"
                    );
                    let decision = decide_after_failure(&RetryFacts {
                        class,
                        retry_on: &retry_on,
                        attempts_used: used,
                        max_attempts,
                        budget_has_room: budget[(used as usize - 1) % budget.len()],
                        invalid_output_failures: if class == FailureClass::InvalidOutput {
                            used
                        } else {
                            0
                        },
                        repair_cap: RepairCap::from_policy(repair_cap),
                        environment: None,
                    });
                    prop_assert!(stage.advance(decision.stage_run_event()).is_ok());
                    match decision {
                        AttemptDisposition::Retry => {
                            prop_assert_eq!(stage, StageRunStatus::Ready);
                            prop_assert!(used < max_attempts, "retried on the last attempt");
                            prop_assert!(stage.advance(StageRunEvent::Start).is_ok());
                        }
                        AttemptDisposition::Escalate(_) => {
                            prop_assert_eq!(stage, StageRunStatus::WaitingForHuman);
                            break;
                        }
                        AttemptDisposition::Fail => {
                            prop_assert_eq!(stage, StageRunStatus::Failed);
                            // FAILED is terminal: nothing leaves it.
                            for event in StageRunStatus::EVENTS {
                                prop_assert!(stage.apply(*event).is_err());
                            }
                            break;
                        }
                        AttemptDisposition::Block(_) => {
                            prop_assert!(false, "no environment cause was set, yet it blocked");
                        }
                    }
                }
                Ok(())
            },
        )
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn an_environment_cause_blocks_whatever_the_other_facts_are() {
    // S21 comes first in the order of ADR 0010: over generated facts, a cause always gives
    // `Block`, never a retry, an escalation or a failure, and the move is legal from RUNNING.
    let strategy = (
        0..FailureClass::ALL.len(),
        any::<u8>(),
        0u32..14,
        1u32..12,
        any::<bool>(),
        0u32..14,
        any::<u8>(),
        0..EnvironmentCause::ALL.len(),
    );
    runner(SEQUENCES)
        .run(
            &strategy,
            |(class, mask, used, max, budget, invalid, repair_cap, cause)| {
                let retry_on = retry_classes_from(mask);
                let cause = EnvironmentCause::ALL[cause];
                let facts = RetryFacts {
                    class: FailureClass::ALL[class],
                    retry_on: &retry_on,
                    attempts_used: used,
                    max_attempts: max,
                    budget_has_room: budget,
                    invalid_output_failures: invalid,
                    repair_cap: RepairCap::from_policy(repair_cap),
                    environment: Some(cause),
                };
                let decision = decide_after_failure(&facts);
                prop_assert_eq!(decision, AttemptDisposition::Block(cause));
                prop_assert_eq!(
                    StageRunStatus::Running.apply(decision.stage_run_event()),
                    Ok(StageRunStatus::Blocked)
                );
                Ok(())
            },
        )
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn budget_and_attempt_limit_escalate_over_generated_facts() {
    // ADR 0010 and INV-10: BUDGET_EXHAUSTED, an exhausted attempt limit and an exhausted repair
    // cap choose S07 and never S06, whatever the other facts are. S06 is for a failure that
    // retrying cannot fix, and S05 and S06 never hold together.
    let strategy = (
        0..FailureClass::ALL.len(),
        any::<u8>(),
        0u32..14,
        1u32..12,
        any::<bool>(),
        0u32..14,
        any::<u8>(),
    );
    runner(SEQUENCES)
        .run(
            &strategy,
            |(class, mask, used, max, budget, invalid, repair_cap)| {
                let retry_on = retry_classes_from(mask);
                let facts = RetryFacts {
                    class: FailureClass::ALL[class],
                    retry_on: &retry_on,
                    attempts_used: used,
                    max_attempts: max,
                    budget_has_room: budget,
                    invalid_output_failures: invalid,
                    repair_cap: RepairCap::from_policy(repair_cap),
                    environment: None,
                };
                let decision = decide_after_failure(&facts);
                let escalates = matches!(decision, AttemptDisposition::Escalate(_));

                if facts.class == FailureClass::BudgetExhausted {
                    prop_assert_eq!(
                        decision,
                        AttemptDisposition::Escalate(EscalationCause::BudgetLimit)
                    );
                    prop_assert!(failure_nonretryable(&facts).is_err());
                }
                if facts.class_is_retryable() && used >= max {
                    prop_assert!(escalates);
                    prop_assert!(failure_nonretryable(&facts).is_err());
                }
                if facts.class == FailureClass::InvalidOutput
                    && facts.class_is_retryable()
                    && invalid > u32::from(repair_cap.min(2))
                {
                    prop_assert!(escalates);
                    prop_assert!(failure_nonretryable(&facts).is_err());
                }
                // The stage run fails exactly when the guard of S06 holds, and S05 and S06 never
                // hold together.
                prop_assert_eq!(
                    decision == AttemptDisposition::Fail,
                    failure_nonretryable(&facts).is_ok()
                );
                prop_assert!(
                    retry_allowed(&facts).is_err() || failure_nonretryable(&facts).is_err()
                );
                // Every escalation names a cause whose facts satisfy the guard of S07.
                if let AttemptDisposition::Escalate(cause) = decision {
                    prop_assert!(escalation_required(&cause.facts()).is_ok());
                }
                Ok(())
            },
        )
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn an_attempt_window_counts_only_what_follows_the_last_human_answer() {
    // A reference that slices the history at the last answer and counts, compared with the
    // function that folds over it.
    let event = prop_oneof![
        3 => (0..FailureClass::ALL.len()).prop_map(|i| WindowEvent::AttemptFailed(FailureClass::ALL[i])),
        1 => Just(WindowEvent::HumanAnswered),
    ];
    runner(SEQUENCES)
        .run(&vec(event, 0..40), |history| {
            let after_last_answer = match history
                .iter()
                .rposition(|e| *e == WindowEvent::HumanAnswered)
            {
                Some(index) => &history[index + 1..],
                None => &history[..],
            };
            let window = AttemptWindow::from_history(&history);
            prop_assert_eq!(window.attempts_used() as usize, after_last_answer.len());
            prop_assert_eq!(
                window.invalid_output_failures() as usize,
                after_last_answer
                    .iter()
                    .filter(|e| **e == WindowEvent::AttemptFailed(FailureClass::InvalidOutput))
                    .count()
            );
            // The window of the tail alone is the same window: nothing before the answer matters.
            prop_assert_eq!(window, AttemptWindow::from_history(after_last_answer));
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn a_failure_is_recorded_only_by_an_event_the_attempt_machine_accepts() {
    for class in FailureClass::ALL {
        for from in AttemptStatus::STATES {
            match class.attempt_event(*from) {
                Some(event) => assert_eq!(
                    from.apply(event),
                    Ok(class.attempt_status()),
                    "{class} from {from}"
                ),
                None => {
                    // A finished attempt records nothing more.
                    assert!(
                        !from.is_terminal() || from.legal_events().is_empty(),
                        "{class} from {from}"
                    );
                }
            }
        }
    }
}

// ---- guards ---------------------------------------------------------------------------------------------------------

fn gate_outcome_from(index: usize) -> GateOutcome {
    GateOutcome::ALL[index % GateOutcome::ALL.len()]
}

#[test]
fn a_gate_never_passes_with_a_blocked_or_failed_mandatory_gate() {
    let strategy = vec((any::<usize>(), any::<bool>()), 0..8);
    runner(SEQUENCES)
        .run(&strategy, |reports| {
            let reports: Vec<GateReportSnapshot> = reports
                .into_iter()
                .map(|(outcome, reason)| GateReportSnapshot {
                    outcome: gate_outcome_from(outcome),
                    not_applicable_reason_recorded: reason,
                })
                .collect();
            let passed = gate_pass_evidenced(&GatePassFacts {
                decision_is_pass_and_persisted: true,
                criteria_without_ledger_entry: 0,
                mandatory_gate_reports: &reports,
            })
            .is_ok();
            let any_bad = reports.iter().any(|r| {
                matches!(r.outcome, GateOutcome::Blocked | GateOutcome::Failed)
                    || (r.outcome == GateOutcome::NotApplicable
                        && !r.not_applicable_reason_recorded)
            });
            // A pass is exactly the absence of a bad report. A gate that did not run is never
            // converted to a pass (INV-06).
            prop_assert_eq!(passed, !any_bad);
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn an_override_is_never_permitted_for_a_mandatory_gate_of_an_active_profile() {
    let strategy = (
        any::<bool>(),
        any::<bool>(),
        any::<u8>(),
        any::<bool>(),
        any::<bool>(),
        0..HumanRole::ALL.len(),
    );
    runner(SEQUENCES)
        .run(
            &strategy,
            |(policy, security, roles, justification, mandatory, required)| {
                let roles = roles_from(roles);
                let facts = OverrideFacts {
                    policy_permits_override_for_block_code: policy,
                    block_is_security_class: security,
                    principal_roles: &roles,
                    role_required_by_policy: HumanRole::ALL[required],
                    justification_recorded: justification,
                    blocked_gate_is_mandatory_of_active_profile: mandatory,
                };
                if override_permitted(&facts).is_ok() {
                    // INV-07, and the other clauses besides.
                    prop_assert!(!mandatory);
                    prop_assert!(policy && justification);
                    prop_assert!(roles.contains(&HumanRole::ALL[required]));
                    prop_assert!(!security || roles.contains(&HumanRole::SecurityApprover));
                }
                Ok(())
            },
        )
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn retry_and_rework_guards_never_allow_more_than_the_limits() {
    let strategy = (
        0..FailureClass::ALL.len(),
        any::<u8>(),
        0u32..12,
        1u32..12,
        any::<bool>(),
        any::<u8>(),
        any::<u8>(),
        0u32..12,
        any::<u8>(),
    );
    runner(SEQUENCES)
        .run(
            &strategy,
            |(class, mask, used, max, budget, rounds, policy_cap, invalid, repair_cap)| {
                let retry_on = retry_classes_from(mask);
                let retry = RetryFacts {
                    class: FailureClass::ALL[class],
                    retry_on: &retry_on,
                    attempts_used: used,
                    max_attempts: max,
                    budget_has_room: budget,
                    invalid_output_failures: invalid,
                    repair_cap: RepairCap::from_policy(repair_cap),
                    environment: None,
                };
                if retry_allowed(&retry).is_ok() {
                    prop_assert!(used < max);
                    prop_assert!(budget);
                    prop_assert!(retry.class_is_retryable());
                    // A repair is allowed only up to the cap, and the cap is at most two.
                    if retry.class == FailureClass::InvalidOutput {
                        prop_assert!(invalid <= u32::from(repair_cap.min(2)));
                        prop_assert!(invalid <= 2);
                    }
                }
                let rework = ReworkFacts {
                    verdict_is_changes_required: true,
                    deterministic_gate_failed: false,
                    rounds_used: rounds,
                    cap: ReworkCap::from_policy(policy_cap),
                    failing_set_differs_from_previous_round: true,
                    budget_remains: true,
                };
                if rework_allowed(&rework).is_ok() {
                    prop_assert!(rounds < policy_cap.min(DEFAULT_REWORK_CAP));
                    prop_assert!(rounds < DEFAULT_REWORK_CAP);
                }
                Ok(())
            },
        )
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn admission_is_always_exactly_one_of_ok_and_denied() {
    let strategy = (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    );
    runner(SEQUENCES)
        .run(&strategy, |(a, b, c, d, e, f, g)| {
            let facts = AdmissionFacts {
                requester_on_allowlist: a,
                tenant_within_job_quota: b,
                repository_registered_and_enabled: c,
                policy_allows_request_class: d,
                protection_preflight_passed: e,
                repository_day_budget_has_room: f,
                organization_day_budget_has_room: g,
            };
            prop_assert!(job::admission_ok(&facts).is_ok() ^ job::admission_denied(&facts).is_ok());
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn a_job_completes_only_when_every_stage_in_scope_has_a_passed_or_skipped_run() {
    let strategy = (
        vec(0..StageKind::ALL.len(), 0..6),
        vec(
            (0..StageKind::ALL.len(), 0..StageRunStatus::STATES.len()),
            0..14,
        ),
        any::<bool>(),
        any::<bool>(),
    );
    runner(SEQUENCES)
        .run(&strategy, |(scope, runs, approve, verified)| {
            let scope: Vec<StageKind> = scope.into_iter().map(|i| StageKind::ALL[i]).collect();
            let runs: Vec<StageRunSnapshot> = runs
                .into_iter()
                .enumerate()
                .map(|(n, (kind, status))| {
                    StageRunSnapshot::new(
                        StageRunId::from_uuid(uuid::Uuid::from_u128(n as u128 + 1)),
                        StageKind::ALL[kind],
                        StageRunStatus::STATES[status],
                    )
                })
                .collect();
            let complete = job::pipeline_scope_complete(&PipelineScopeFacts {
                scope: &scope,
                stage_runs: &runs,
                approval_decision_is_approve: approve,
                ledger_chain_verifies: verified,
            })
            .is_ok();
            if complete {
                prop_assert!(approve && verified && !scope.is_empty());
                for kind in &scope {
                    prop_assert!(runs.iter().any(|r| r.kind == *kind
                        && matches!(r.status, StageRunStatus::Passed | StageRunStatus::Skipped)));
                }
            }
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

// ---- time guards compare instants -----------------------------------------------------------------------------------

/// A moment written as the schema allows: with no fraction, or with three digits. The same instant
/// can be written both ways when the milliseconds are zero.
fn stamp(second: u32, millis: u32, spell_zero_fraction: bool) -> (Timestamp, (u32, u32)) {
    let text = if millis == 0 && !spell_zero_fraction {
        format!("2026-10-27T10:{:02}:{:02}Z", second / 60, second % 60)
    } else {
        format!(
            "2026-10-27T10:{:02}:{:02}.{millis:03}Z",
            second / 60,
            second % 60
        )
    };
    (Timestamp::parse(&text).unwrap(), (second, millis))
}

#[test]
fn time_guards_compare_the_instant_whatever_the_spelling() {
    // Zero milliseconds are common and the second moment is often the same instant as the first,
    // written the other way. That is the case where comparing the stored values goes wrong.
    let millis = prop_oneof![Just(0u32), 0u32..1000];
    let strategy = (
        0u32..120,
        millis.clone(),
        any::<bool>(),
        any::<bool>(),
        0u32..120,
        millis,
        any::<bool>(),
    );
    runner(SEQUENCES)
        .run(&strategy, |(s1, m1, z1, same_instant, s2, m2, z2)| {
            let (s2, m2) = if same_instant { (s1, m1) } else { (s2, m2) };
            let (now, now_instant) = stamp(s1, m1, z1);
            let (other, other_instant) = stamp(s2, m2, z2);

            let deadline = attempt::deadline_passed(&DeadlineFacts {
                now,
                attempt_deadline: other,
            })
            .is_ok();
            prop_assert_eq!(deadline, now_instant > other_instant);

            let expired = attempt::lease_expired(&LeaseExpiryFacts {
                now,
                lease_expires_at: other,
                heartbeat_arrived: false,
            })
            .is_ok();
            prop_assert_eq!(expired, now_instant > other_instant);

            // A heartbeat that arrived always keeps the lease.
            let kept = attempt::lease_expired(&LeaseExpiryFacts {
                now,
                lease_expires_at: other,
                heartbeat_arrived: true,
            })
            .is_err();
            prop_assert!(kept);
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}
