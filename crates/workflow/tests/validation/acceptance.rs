//! The acceptance evidence gate over a whole stage run: a test counts for a requirement only when
//! it did not pass on the base commit.
//!
//! The frozen specification of the world has three requirements, `FR-001`, `FR-002` and `FR-003`.

use factory_domain::contracts::gate_report::BaselineDelta;
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::framework::Resolution;

use crate::cargo::TestRun;
use crate::gates::{IT_BASE, IT_NEW, base_run, head_run, it_with_requirement_tests, run_of};
use crate::world::{Ran, World};

const GATE: &str = "acceptance-evidence";

/// A run of the stage over the usual change, with these two test runs.
async fn run_with(head: TestRun, baseline: TestRun) -> Ran {
    let w = World::new();
    let more = it_with_requirement_tests();
    let (base, head_commit) = w.project(&[("tests/it.rs", Some(&more))]).await;
    w.cargo.queue_test_run(head);
    w.cargo.queue_test_run(baseline);
    w.run(&base, &head_commit).await
}

fn notes(ran: &Ran) -> String {
    ran.report(GATE)
        .baseline_comparison
        .notes
        .as_ref()
        .map(|notes| notes.as_str().to_owned())
        .unwrap_or_default()
}

fn failures(ran: &Ran) -> Vec<(String, String)> {
    ran.report(GATE)
        .failures
        .iter()
        .flatten()
        .map(|failure| {
            (
                failure.check_id.as_str().to_owned(),
                failure.message.as_str().to_owned(),
            )
        })
        .collect()
}

/// The usual head run, and a run of the base commit that holds `extra_on_base` as well.
fn both(extra_on_base: &[(&'static str, &'static str)]) -> (TestRun, TestRun) {
    let mut base = IT_BASE.to_vec();
    base.extend_from_slice(extra_on_base);
    let exit = if extra_on_base.iter().any(|(_, status)| *status == "FAILED") {
        101
    } else {
        0
    };
    (head_run(), run_of(&base, exit))
}

#[tokio::test]
async fn a_new_passing_test_covers_its_requirement_and_the_report_names_the_test_and_the_basis() {
    let ran = run_with(head_run(), base_run()).await;
    assert_eq!(ran.outcome(GATE), GateOutcome::Passed);
    assert_eq!(ran.resolution, Resolution::Pass);
    let report = ran.report(GATE);
    assert!(
        report.baseline_comparison.baseline_commit_sha.is_some(),
        "the report names the commit the tests were compared with"
    );
    assert_eq!(report.baseline_comparison.delta, BaselineDelta::Improved);
    let notes = notes(&ran);
    for (requirement, test) in [
        ("FR-001", IT_NEW[0].0),
        ("FR-002", IT_NEW[1].0),
        ("FR-003", IT_NEW[2].0),
    ] {
        let line = notes
            .lines()
            .find(|line| line.starts_with(requirement))
            .unwrap_or_else(|| panic!("a line for {requirement} in {notes:?}"));
        assert!(line.contains(&format!("tests/it.rs::{test}")), "{line}");
        assert!(line.contains("new test"), "{line}");
    }
}

#[tokio::test]
async fn a_test_that_already_passed_on_the_base_commit_does_not_cover_its_requirement() {
    // The test named after FR-001 was there before the change and passed before the change.
    let (head, baseline) = both(&[(IT_NEW[0].0, "ok")]);
    let ran = run_with(head, baseline).await;
    assert_eq!(ran.outcome(GATE), GateOutcome::Failed);
    assert!(matches!(ran.resolution, Resolution::Failed { .. }));
    let failures = failures(&ran);
    assert_eq!(failures.len(), 1, "{failures:?}");
    let (check, message) = &failures[0];
    assert_eq!(check, "requirement-covered-only-by-old-tests");
    assert!(message.contains("FR-001"), "{message}");
    assert!(
        message.contains("tests/it.rs::fr_001_counts_a_tab"),
        "the failure names the test that does not count: {message}"
    );
    // The requirements that are covered are still listed with their tests, and the one that is
    // not covered says so.
    let notes = notes(&ran);
    assert!(
        notes
            .lines()
            .any(|line| line.starts_with("FR-002") && line.contains("new test")),
        "{notes}"
    );
    assert!(
        notes
            .lines()
            .any(|line| line.starts_with("FR-001") && line.contains("not covered")),
        "{notes}"
    );
}

#[tokio::test]
async fn a_test_that_failed_on_the_base_commit_and_passes_now_covers_its_requirement() {
    let (head, baseline) = both(&[(IT_NEW[1].0, "FAILED")]);
    let ran = run_with(head, baseline).await;
    assert_eq!(ran.outcome(GATE), GateOutcome::Passed);
    let notes = notes(&ran);
    let line = notes
        .lines()
        .find(|line| line.starts_with("FR-002"))
        .expect("a line for FR-002");
    assert!(
        line.contains("tests/it.rs::fr_002_counts_a_line_break"),
        "{line}"
    );
    assert!(line.contains("failed on the base commit"), "{line}");
}

#[tokio::test]
async fn a_requirement_that_no_passed_test_names_is_still_uncovered() {
    let ran = run_with(base_run(), base_run()).await;
    assert_eq!(ran.outcome(GATE), GateOutcome::Failed);
    let checks: Vec<String> = failures(&ran).into_iter().map(|(check, _)| check).collect();
    assert_eq!(checks, ["requirement-uncovered"; 3]);
}

#[tokio::test]
async fn without_a_readable_test_run_of_the_base_commit_the_gate_is_blocked_and_never_passed() {
    // The run on the base commit prints a summary with no test line behind it: it cannot be read.
    let unreadable = TestRun {
        stdout:
            "\nrunning 99 tests\n\ntest result: ok. 99 passed; 0 failed; 0 ignored; 0 measured\n"
                .to_owned(),
        stderr: "     Running tests/it.rs (/out/x)\n".to_owned(),
        exit: 0,
    };
    let ran = run_with(head_run(), unreadable).await;
    assert_eq!(ran.outcome(GATE), GateOutcome::Blocked);
    let reason = ran.report(GATE).blocked_reason.as_ref().expect("a reason");
    assert!(
        reason
            .missing
            .iter()
            .any(|missing| missing.as_str().contains("base commit")),
        "{reason:?}"
    );
    assert!(!matches!(ran.resolution, Resolution::Pass));
}
