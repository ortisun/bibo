//! Every assertion fails on evidence that has been deliberately corrupted.

use factory_e2e::mutations::{self, run_one, self_test};
use factory_e2e::{Env, repository_root};

fn env() -> Env {
    Env::load(&repository_root()).expect("the state machine file loads")
}

#[test]
fn every_mutation_is_detected_by_the_assertion_it_targets() {
    let env = env();
    let mut missed = Vec::new();
    for mutation in mutations::all() {
        let result = run_one(&mutation, &env);
        if !result.detected {
            missed.push(format!(
                "{} ({}): expected a reason with '{}', got: {}",
                mutation.name, mutation.assertion, mutation.expect, result.reason
            ));
        }
    }
    assert!(missed.is_empty(), "{missed:#?}");
}

#[test]
fn every_assertion_has_at_least_two_mutations() {
    let all = mutations::all();
    for check in factory_e2e::assertions::all() {
        let count = all.iter().filter(|m| m.assertion == check.id).count();
        assert!(count >= 2, "{} has {count} mutation(s)", check.id);
    }
}

#[test]
fn mutation_names_are_unique() {
    let all = mutations::all();
    let mut names: Vec<_> = all.iter().map(|m| m.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len());
}

#[test]
fn the_self_test_passes() {
    let report = self_test(&env());
    assert!(
        report.honest_problems.is_empty(),
        "{:#?}",
        report.honest_problems
    );
    assert!(report.uncovered.is_empty(), "{:#?}", report.uncovered);
    assert!(report.passed());
}

#[test]
fn a_mutation_that_changes_nothing_is_not_counted_as_detected() {
    let env = env();
    let noop = mutations::Mutation {
        name: "does-nothing",
        assertion: "A1",
        what: "Nothing.",
        expect: "",
        base: mutations::Base::Production,
        apply: |_| {},
    };
    assert!(!run_one(&noop, &env).detected);
}
