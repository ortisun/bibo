//! The canned honest evidence passes every assertion, in production mode for the English and the
//! Portuguese request and in test mode with labelled fakes.

use factory_e2e::assertions::run_all;
use factory_e2e::canned::{Options, honest};
use factory_e2e::{Env, repository_root};

fn env() -> Env {
    Env::load(&repository_root()).expect("the state machine file loads")
}

fn assert_all_pass(options: Options) {
    let env = env();
    let evidence = honest(&env, options);
    let verdicts = run_all(&evidence, &env);
    assert_eq!(verdicts.len(), 14);
    let failures: Vec<String> = verdicts
        .iter()
        .filter(|verdict| !verdict.pass)
        .map(ToString::to_string)
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_honest_english_run_with_real_adapters_passes_all_fourteen() {
    assert_all_pass(Options::e1_production());
}

#[test]
fn the_honest_portuguese_run_with_real_adapters_passes_all_fourteen() {
    assert_all_pass(Options::e2_production());
}

#[test]
fn the_honest_english_run_in_test_mode_passes_all_fourteen() {
    assert_all_pass(Options::e1_test_mode());
}

#[test]
fn the_stage_list_comes_from_the_state_machine_file_and_is_not_counted_in_code() {
    let env = env();
    let kinds: Vec<&str> = env.stages.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds.first(), Some(&"INTAKE"));
    assert_eq!(kinds.last(), Some(&"APPROVAL"));
    assert!(!kinds.contains(&"MERGE"), "MERGE belongs to a later slice");
    let evidence = honest(&env, Options::e1_production());
    assert_eq!(evidence.stage_runs.len(), env.stages.len());
}
