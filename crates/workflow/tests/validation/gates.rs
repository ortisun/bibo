//! Each gate on its own paths: passed, failed and blocked.

use factory_domain::contracts::gate_report::{BaselineDelta, BlockedCode, DefinitionSource};
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::framework::{BlockCause, Resolution};
use serde_json::{Value, json};

use crate::cargo::{TestRun, libtest};
use crate::world::{MANIFEST, World, base_files, with};

const IT_BASE: [(&str, &str); 3] = [
    ("fr_001_counts_a_line", "ok"),
    ("fr_002_counts_one_word", "ok"),
    ("fr_003_counts_nothing", "ok"),
];

pub fn run_of(tests: &[(&str, &str)], exit: i32) -> TestRun {
    libtest(
        &[
            (
                "unittests src/lib.rs",
                &[("tests::unit_counts_words", "ok")],
            ),
            ("tests/it.rs", tests),
            ("doc-tests word_count", &[]),
        ],
        exit,
    )
}

/// The tests of the base commit, all passing.
pub fn base_run() -> TestRun {
    run_of(&IT_BASE, 0)
}

/// The text of `tests/it.rs` with one more test at the end.
pub fn it_with_one_more() -> String {
    let mut text = base_files()
        .into_iter()
        .find(|(path, _)| path == "tests/it.rs")
        .map(|(_, text)| text)
        .expect("the file exists");
    text.push_str(
        "\n#[test]\nfn fr_004_counts_a_tab() {\n    assert_eq!(count(\"a\\tb\"), 2);\n}\n",
    );
    text
}

/// The tests of a head commit that adds one passing test.
pub fn head_run() -> TestRun {
    let mut tests = IT_BASE.to_vec();
    tests.push(("fr_004_counts_a_tab", "ok"));
    run_of(&tests, 0)
}

/// A manifest with these gates in place of the four universal ones.
pub fn manifest_with(gates: Value) -> String {
    let mut manifest: Value = serde_json::from_str(MANIFEST).expect("the manifest is JSON");
    manifest["gates"] = gates;
    manifest.to_string()
}

pub fn gate(id: &str, argv: &[&str]) -> Value {
    json!({ "id": id, "title": format!("Gate {id}"), "argv": argv, "timeout_seconds": 60, "mandatory": true })
}

/// A passing change: one more test appended to the existing test file.
pub async fn passing_world() -> (
    World,
    factory_ports::paths::CommitSha,
    factory_ports::paths::CommitSha,
) {
    let w = World::new();
    let more = it_with_one_more();
    let (base, head) = w.project(&[("tests/it.rs", Some(&more))]).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    (w, base, head)
}

#[tokio::test]
async fn a_clean_change_passes_every_gate() {
    let (w, base, head) = passing_world().await;
    let ran = w.run(&base, &head).await;
    for gate in factory_workflow::stages::validation::GATES.map(|(id, _)| id) {
        assert_eq!(ran.outcome(gate), GateOutcome::Passed, "{gate}");
    }
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(ran.problem, None, "the engine accepts the evidence");
    assert!(!ran.decision.policy_violation);
    // Two fresh containers over two checkouts: the candidate, then the base for the baseline.
    assert_eq!(w.sandbox.created(), 2);
    assert_eq!(w.sandbox.live(), 0, "nothing is left running");
    assert_eq!(w.cargo.ran("fmt"), 1);
    assert_eq!(w.cargo.ran("clippy"), 1);
    assert_eq!(w.cargo.ran("build"), 1);
    assert_eq!(w.cargo.ran("test"), 2);
}

#[tokio::test]
async fn the_commands_that_run_are_the_policy_vectors_with_the_forced_arguments() {
    let (w, base, head) = passing_world().await;
    w.run(&base, &head).await;
    let tests = w.cargo.last("test").expect("the tests ran");
    assert_eq!(tests, ["cargo", "test", "--offline", "--locked"]);
    let build = w.cargo.last("build").expect("the build ran");
    assert_eq!(build, ["cargo", "build", "--offline", "--locked"]);
    // `cargo fmt` rejects the forced arguments (exit 2 in the pinned image), so it keeps its own.
    let fmt = w.cargo.last("fmt").expect("the formatter ran");
    assert_eq!(fmt, ["cargo", "fmt", "--check"]);
}

#[tokio::test]
async fn a_passed_test_gate_shows_the_comparison_with_the_base_commit() {
    let (w, base, head) = passing_world().await;
    let ran = w.run(&base, &head).await;
    let report = ran.report("unit-tests");
    assert_eq!(report.baseline_comparison.delta, BaselineDelta::None);
    assert_eq!(
        report
            .baseline_comparison
            .baseline_commit_sha
            .as_ref()
            .map(|sha| sha.as_str()),
        Some(base.as_str())
    );
    assert!(
        report
            .environment
            .tool_versions
            .iter()
            .any(|v| v.tool.as_str() == "cargo")
    );
    assert!(
        report
            .environment
            .tool_versions
            .iter()
            .any(|v| v.tool.as_str() == "rustc")
    );
}

#[tokio::test]
async fn the_format_lint_build_and_test_gates_fail_on_a_nonzero_exit() {
    for (gate, subcommand) in [("format", "fmt"), ("lint", "clippy"), ("build", "build")] {
        let (w, base, head) = passing_world().await;
        w.cargo.exit_of(subcommand, 1);
        let ran = w.run(&base, &head).await;
        assert_eq!(ran.outcome(gate), GateOutcome::Failed, "{gate}");
        assert_eq!(ran.failure_checks(gate), ["exit-code"]);
        assert!(
            matches!(ran.resolution, Resolution::Failed { .. }),
            "{gate}"
        );
    }
    let w = World::new();
    let more = it_with_one_more();
    let (base, head) = w.project(&[("tests/it.rs", Some(&more))]).await;
    let mut failing = IT_BASE.to_vec();
    failing.push(("fr_004_counts_a_tab", "FAILED"));
    w.cargo.queue_test_run(run_of(&failing, 101));
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Failed);
    assert!(
        ran.failure_checks("unit-tests")
            .contains(&"test-failed".to_owned())
    );
    assert!(matches!(ran.resolution, Resolution::Failed { .. }));
}

#[tokio::test]
async fn a_tool_missing_from_the_image_blocks_its_gate() {
    let (w, base, head) = passing_world().await;
    w.cargo.lacks("clippy");
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("lint"), GateOutcome::Blocked);
    let reason = ran
        .report("lint")
        .blocked_reason
        .as_ref()
        .expect("a reason");
    assert_eq!(reason.code, BlockedCode::ToolProbeFailed);
    assert!(reason.missing.iter().any(|m| m.as_str().contains("clippy")));
    assert!(matches!(
        ran.resolution,
        Resolution::Blocked(BlockCause::GateBlocked(_))
    ));
    assert_eq!(w.cargo.ran("clippy"), 0, "the gate itself never ran");
}

#[tokio::test]
async fn conditional_gates_the_project_does_not_define_do_not_apply_by_a_recorded_rule() {
    let w = World::new();
    let manifest = manifest_with(json!([
        gate("build", &["cargo", "build"]),
        gate("unit-tests", &["cargo", "test"]),
    ]));
    let base = w
        .push(&with(&[(".factory/project.json", Some(&manifest))]))
        .await;
    w.cargo.queue_test_run(base_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &base).await;
    for gate in ["format", "lint"] {
        assert_eq!(ran.outcome(gate), GateOutcome::NotApplicable, "{gate}");
        let reason = ran
            .report(gate)
            .not_applicable_reason
            .as_ref()
            .expect("a reason");
        assert_eq!(
            reason.decided_by,
            factory_domain::contracts::gate_report::NotApplicableDecider::DomainProfile
        );
    }
    assert_eq!(ran.resolution, Resolution::Pass);
}

#[tokio::test]
async fn a_mandatory_gate_the_base_manifest_does_not_define_is_blocked() {
    let w = World::new();
    let manifest = manifest_with(json!([gate("build", &["cargo", "build"])]));
    let base = w
        .push(&with(&[(".factory/project.json", Some(&manifest))]))
        .await;
    let ran = w.run(&base, &base).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
    assert!(matches!(ran.resolution, Resolution::Blocked(_)));
}

#[tokio::test]
async fn definitions_that_cannot_be_read_at_the_base_commit_block_every_command_gate() {
    for manifest in [None, Some("this is not a manifest")] {
        let w = World::new();
        let base = w.push(&with(&[(".factory/project.json", manifest)])).await;
        let ran = w.run(&base, &base).await;
        for gate in ["format", "lint", "build", "unit-tests"] {
            assert_eq!(ran.outcome(gate), GateOutcome::Blocked, "{gate}");
        }
        assert!(matches!(ran.resolution, Resolution::Blocked(_)));
        assert_eq!(
            w.cargo.calls().len(),
            0,
            "no command ran without definitions"
        );
    }
}

#[tokio::test]
async fn a_command_the_policy_denies_is_blocked_and_never_run() {
    let w = World::new();
    let manifest = manifest_with(json!([
        gate("build", &["cargo", "build"]),
        gate("unit-tests", &["curl", "https://example.invalid/x"]),
    ]));
    let base = w
        .push(&with(&[(".factory/project.json", Some(&manifest))]))
        .await;
    let ran = w.run(&base, &base).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
    assert_eq!(
        ran.report("unit-tests")
            .blocked_reason
            .as_ref()
            .map(|r| r.code),
        Some(BlockedCode::PolicyUnresolvable)
    );
}

#[tokio::test]
async fn every_report_names_the_base_commit_as_the_source_of_the_definitions() {
    let (w, base, head) = passing_world().await;
    let ran = w.run(&base, &head).await;
    for report in &ran.decision.reports {
        let trusted = &report.metadata.trusted_definition;
        assert_eq!(trusted.source, DefinitionSource::ProtectedBaseBranch);
        assert_eq!(trusted.commit_sha.as_str(), base.as_str());
    }
    let hashes: std::collections::BTreeSet<_> = ran
        .decision
        .reports
        .iter()
        .map(|r| r.metadata.trusted_definition.definition_sha256.clone())
        .collect();
    assert_eq!(hashes.len(), 1, "one set of definitions for the whole run");
}

#[tokio::test]
async fn a_cancelled_attempt_stops_the_stage_and_leaves_nothing_running() {
    let (w, base, head) = passing_world().await;
    let handler = w.handler();
    let upstream = w.upstream(&base, &head).await;
    let contract = w
        .resolve_contract(&handler, &upstream, &w.policy_hash)
        .expect("a contract");
    w.cancel.cancel();
    let result = w.execute(&handler, &contract, &upstream).await;
    assert_eq!(
        result.err(),
        Some(factory_workflow::handlers::StageError::Cancelled)
    );
    assert_eq!(w.sandbox.live(), 0);
}

#[tokio::test]
async fn an_implementation_that_named_no_commit_blocks_the_contract() {
    let w = World::new();
    let handler = w.handler();
    let result = w.resolve_contract(&handler, &[], &w.policy_hash);
    assert!(matches!(
        result,
        Err(factory_workflow::handlers::StageError::Blocked(
            BlockedCode::DependencyUnavailable
        ))
    ));
}
