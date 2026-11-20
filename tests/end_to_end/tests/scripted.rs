//! The scenarios, run through the scripted wiring: the real workflow engine over the testkit
//! fakes and the fake GitHub server. Every result is test mode with labelled fakes, and none of
//! them is the real proof of E1 or E2.

use factory_e2e::runner::{RunOptions, ScenarioReport, Status, render, run_scenario};
use factory_e2e::scenarios::{self, Adapters};
use factory_e2e::scripted::Scripted;
use factory_e2e::{Env, repository_root};

fn run(id: &str) -> ScenarioReport {
    let root = repository_root();
    let env = Env::load(&root).expect("the state machine file loads");
    let mut wiring = Scripted::new(&root).expect("the scripted wiring starts");
    let options = RunOptions {
        test_mode_for_real_scenarios: true,
    };
    let scenario = scenarios::by_id(id).expect("a scenario");
    run_scenario(&mut wiring, scenario, &env, options, &|_| None)
}

fn assert_passes(id: &str) {
    let report = run(id);
    assert_eq!(report.status, Status::Passed, "\n{}", render(&report));
}

#[test]
fn e1_the_english_request_passes_all_fourteen_assertions_in_test_mode() {
    let report = run("E1");
    assert_eq!(report.status, Status::Passed, "\n{}", render(&report));
    assert!(report.label.starts_with("TEST MODE with labelled fakes"));
    assert!(
        report
            .verdicts
            .iter()
            .filter(|v| v.id.starts_with('A'))
            .count()
            == 14
    );
}

#[test]
fn e2_the_portuguese_request_passes_all_fourteen_assertions_in_test_mode() {
    assert_passes("E2");
}

#[test]
fn e3_a_failing_check_blocks_promotion() {
    assert_passes("E3");
}

#[test]
fn e4_a_hostile_issue_has_no_effect() {
    assert_passes("E4");
}

#[test]
fn e5_a_worker_killed_at_every_boundary_still_completes() {
    assert_passes("E5");
}

#[test]
fn e6_a_stranger_is_rejected_at_admission() {
    assert_passes("E6");
}

#[test]
fn e7_fifty_identical_deliveries_make_one_job() {
    assert_passes("E7");
}

#[test]
fn e8_a_protected_path_change_fails_the_scope_gate() {
    assert_passes("E8");
}

#[test]
fn e9_a_fake_is_refused_in_production() {
    assert_passes("E9");
}

#[test]
fn e10_an_edited_request_restarts_from_intake() {
    assert_passes("E10");
}

#[test]
fn e11_budget_exhaustion_asks_a_person() {
    assert_passes("E11");
}

#[test]
fn e12_an_ambiguous_request_gets_one_question() {
    assert_passes("E12");
}

#[test]
fn e13_an_out_of_policy_request_is_declined() {
    assert_passes("E13");
}

#[test]
fn a_remote_whose_protection_fails_the_preflight_blocks_the_scenario() {
    let root = repository_root();
    let env = Env::load(&root).expect("env");
    let mut wiring = Scripted::new(&root)
        .expect("wiring")
        .with_weak_protection(|protection| {
            protection.bypass_apps.push("factory-test-app".to_owned());
            protection.required_checks[0].app_id = None;
        });
    let scenario = scenarios::by_id("E3").expect("E3");
    let report = run_scenario(&mut wiring, scenario, &env, RunOptions::default(), &|_| {
        None
    });
    assert_eq!(report.status, Status::Blocked, "{}", render(&report));
    assert_eq!(report.blocked.len(), 2, "{:?}", report.blocked);
    assert!(
        report.verdicts.is_empty(),
        "nothing ran against the weak remote"
    );
}

#[test]
fn without_the_flag_e1_and_e2_are_blocked_on_the_scripted_wiring() {
    let root = repository_root();
    let env = Env::load(&root).expect("env");
    let mut wiring = Scripted::new(&root).expect("wiring");
    for scenario in scenarios::SCENARIOS
        .iter()
        .filter(|s| s.adapters == Adapters::Real)
    {
        let report = run_scenario(&mut wiring, scenario, &env, RunOptions::default(), &|_| {
            None
        });
        assert_eq!(report.status, Status::Blocked, "{}", scenario.id);
    }
}
