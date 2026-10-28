//! The command line: the exit codes that `scripts/e2e.sh` relies on.

use factory_e2e::cli::main;

fn code(args: &[&str]) -> i32 {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    main(&args)
}

#[test]
fn list_succeeds() {
    assert_eq!(code(&["list"]), 0);
}

#[test]
fn wrong_usage_exits_with_two() {
    assert_eq!(code(&[]), 2);
    assert_eq!(code(&["no-such-command"]), 2);
    assert_eq!(code(&["run"]), 2);
    assert_eq!(code(&["run", "--scenario"]), 2);
    assert_eq!(code(&["run", "--scenario", "E99"]), 2);
    assert_eq!(code(&["run", "--scenario", "E3", "--wiring", "magic"]), 2);
    assert_eq!(code(&["run", "--scenario", "E3", "--bogus"]), 2);
    assert_eq!(code(&["help"]), 0);
}

#[test]
fn the_self_tests_pass() {
    assert_eq!(code(&["self-test"]), 0);
    assert_eq!(code(&["blocked-self-test"]), 0);
    assert_eq!(code(&["preflight-self-test"]), 0);
}

#[test]
fn a_test_mode_scenario_runs_on_the_scripted_wiring_and_passes() {
    assert_eq!(
        code(&["run", "--scenario", "E3", "--wiring", "scripted"]),
        0
    );
}

#[test]
fn a_real_scenario_on_the_scripted_wiring_is_blocked_with_exit_three() {
    assert_eq!(
        code(&["run", "--scenario", "E1", "--wiring", "scripted"]),
        3
    );
}

#[test]
fn a_real_scenario_with_the_test_mode_flag_runs_and_is_labelled() {
    let dir = std::env::temp_dir().join(format!("e2e-evidence-{}", std::process::id()));
    let dir_text = dir.to_string_lossy().into_owned();
    assert_eq!(
        code(&[
            "run",
            "--scenario",
            "E1",
            "--test-mode",
            "--evidence-dir",
            &dir_text
        ]),
        0
    );
    let recorded = std::fs::read_to_string(dir.join("E1.json")).expect("a recording");
    assert!(recorded.contains("TEST MODE with labelled fakes"));
    assert!(recorded.contains("\"status\": \"PASSED\""));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_acceptance_report_is_blocked_and_not_a_pass() {
    assert_eq!(code(&["check-report", "/no/such/report.md"]), 3);
}
