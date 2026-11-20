//! The fixture's own commands, run on a copy: they pass on the real fixture, and each one fails on
//! a copy with a deliberate defect. The same commands run in the pinned verify image in
//! `verify_image.rs`.

use std::fs;

use fixture_contract::exec::{self, Behaviour};
use fixture_contract::workdir::{TempDir, copy_fixture};
use fixture_contract::{Outcome, checks, fixture_dir};

fn blocked_unless_cargo() {
    assert!(
        exec::cargo_available(),
        "BLOCKED: cargo is not installed on this host, so the fixture cannot be built here"
    );
}

struct Built {
    copy: TempDir,
    target: TempDir,
}

fn build(label: &str, change: impl FnOnce(&std::path::Path)) -> (Built, Vec<exec::CommandResult>) {
    blocked_unless_cargo();
    let copy = copy_fixture(&fixture_dir(), label).expect("the fixture copies");
    change(copy.path());
    let target = TempDir::new("target").expect("a build directory");
    let results = exec::run_on_host(copy.path(), target.path());
    (Built { copy, target }, results)
}

#[test]
fn the_real_fixture_passes_its_four_commands_offline() {
    let (built, results) = build("commands-real", |_| {});
    for result in &results {
        assert!(
            result.succeeded(),
            "{} failed: {}\n{}",
            result.label,
            result.argv.join(" "),
            result.stderr
        );
    }
    assert_eq!(exec::outcome_of(&results), Outcome::Passed);
    assert_eq!(results.len(), 4);

    // The README matches the tool that was just built, and the gap is open.
    let behaviour: Behaviour = exec::probe_behaviour(built.copy.path(), built.target.path());
    let readme = checks::readme_matches_reality(
        built.copy.path(),
        &behaviour.help,
        &behaviour.example_outputs,
    );
    assert!(readme.is_empty(), "{readme:#?}");
    let gap = exec::gap_is_open(&behaviour);
    assert!(gap.is_empty(), "{gap:#?}");
}

#[test]
fn a_formatting_defect_fails_the_format_command() {
    let (_built, results) = build("commands-format", |dir| {
        let path = dir.join("src/lib.rs");
        let text = fs::read_to_string(&path).expect("read");
        fs::write(
            path,
            text.replace("pub fn count(text: &str)", "pub fn   count( text:&str )"),
        )
        .expect("write");
    });
    let format = results
        .iter()
        .find(|r| r.label == "format")
        .expect("format ran");
    assert!(!format.succeeded());
    assert!(matches!(exec::outcome_of(&results), Outcome::Failed(_)));
}

#[test]
fn a_lint_defect_fails_the_lint_command() {
    let (_built, results) = build("commands-lint", |dir| {
        let path = dir.join("src/lib.rs");
        let text = fs::read_to_string(&path).expect("read");
        let defect = "\n#[must_use]\npub fn unused_helper() -> bool {\n    let flag = true;\n    return flag;\n}\n";
        fs::write(path, format!("{text}{defect}")).expect("write");
    });
    let lint = results
        .iter()
        .find(|r| r.label == "lint")
        .expect("lint ran");
    assert!(!lint.succeeded(), "{}", lint.stderr);
}

#[test]
fn a_failing_test_fails_the_unit_tests_command() {
    let (_built, results) = build("commands-tests", |dir| {
        let path = dir.join("tests/golden/sample.plain.txt");
        fs::write(path, "      9       9       9 tests/golden/sample.txt\n").expect("write");
    });
    let tests = results
        .iter()
        .find(|r| r.label == "unit-tests")
        .expect("tests ran");
    assert!(!tests.succeeded());
    assert!(tests.stdout.contains("FAILED") || tests.stderr.contains("FAILED"));
}

#[test]
fn a_fixture_that_already_accepts_json_has_no_open_gap() {
    let (built, results) = build("commands-gap", |dir| {
        let path = dir.join("src/main.rs");
        let text = fs::read_to_string(&path).expect("read");
        // Accept the option and ignore it: enough to close the gap for the probe.
        fs::write(
            path,
            text.replace("\"-\" => {}", "\"-\" | \"--json\" => {}"),
        )
        .expect("write");
    });
    assert_eq!(exec::outcome_of(&results), Outcome::Passed);
    let behaviour = exec::probe_behaviour(built.copy.path(), built.target.path());
    let gap = exec::gap_is_open(&behaviour);
    assert!(
        !gap.is_empty(),
        "the probe should see that --json is accepted"
    );
}
