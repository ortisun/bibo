//! The negative tests of the catalog that the implementation stage owns: a builder that edits what
//! it must not, an output that is not what it says, a worker that lost its lease, and a budget.

use factory_domain::machines::failure::FailureClass;
use factory_domain::state::{StageRunStatus, TaskNodeStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::{CostMicroUsd, Usage};
use factory_testkit::agent::AdversarialScript;
use factory_testkit::contracts::workspace::TreeEdit;
use factory_workflow::engine::AttemptOutcome;
use serde_json::{Value, json};

use crate::rig::{CheckMode, MAIN, Rig, done, path, write};

const FIRST: &str = "add-json-output-formatter";

/// Runs the first task with these edits and returns the rig, the evidence and the outcome.
async fn first_task_with(edits: Vec<TreeEdit>) -> (Rig, Value, AttemptOutcome) {
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    rig.builder_will(edits, done(FIRST, &["src/main.rs"]));
    let (_, outcome) = rig.run_next().await;
    let evidence = rig
        .deliverable(StageKind::Implementation, "implementation-evidence")
        .await
        .unwrap_or(Value::Null);
    (rig, evidence, outcome)
}

/// The stage run is blocked, the refusal names every path and the rule, and nothing was committed.
async fn assert_refused(rig: &Rig, evidence: &Value, outcome: &AttemptOutcome, code: &str) {
    assert_eq!(*outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(evidence["refusal"]["code"], code, "{evidence}");
    assert!(
        rig.events_of("workspace.commit").is_empty(),
        "nothing of a refused change is committed"
    );
    // The result names the base as the head: the refused change is in no commit.
    assert_eq!(evidence["head_commit"], evidence["base_commit"]);
    let view = rig.world.view(rig.job).await;
    assert_eq!(
        view.newest(StageKind::Implementation)
            .expect("a run")
            .status,
        StageRunStatus::Blocked,
        "a refusal blocks the stage run"
    );
    let run = rig.run_of(StageKind::Implementation).await;
    assert_eq!(rig.ledger.statuses(run)[0].1, TaskNodeStatus::Failed);
    // The reason is in the ledger as a failed gate report that names the path.
    let reports = rig.gate_reports().await;
    let protected = reports
        .iter()
        .find(|r| r["metadata"]["gate_id"] == "protected-paths-unchanged")
        .expect("a report for the protected paths gate");
    assert_eq!(protected["outcome"], "FAILED", "{protected}");
}

/// NT-GATE-03 and NT-GATE-05: the builder edits a workflow, a CI script or the factory's own
/// directory, next to a change it is allowed to make. The change is refused and the refusal says
/// which path and which rule. It is never dropped silently and never committed.
#[tokio::test]
async fn negative_nt_gate_03_the_builder_edits_ci_and_gate_files() {
    for protected in [
        ".github/workflows/ci.yml",
        "scripts/ci/run.sh",
        ".factory/project.json",
    ] {
        let (rig, evidence, outcome) = first_task_with(vec![
            write("src/main.rs", MAIN),
            write(protected, "echo changed\n"),
        ])
        .await;
        assert_refused(&rig, &evidence, &outcome, "protected-path-changed").await;
        let paths = evidence["refusal"]["paths"].as_array().expect("paths");
        assert_eq!(paths.len(), 1, "{protected}: {evidence}");
        assert_eq!(paths[0]["path"], protected);
        assert_eq!(paths[0]["rule"], "deny_write");
        // The allowed change next to it is not committed either: the task is refused as a whole.
        let reports = rig.gate_reports().await;
        let message = reports
            .iter()
            .find(|r| r["metadata"]["gate_id"] == "protected-paths-unchanged")
            .map(|r| {
                r["failures"][0]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .expect("a report");
        assert!(message.contains(protected), "{message}");
    }
}

/// NT-GATE-01 and NT-GATE-02: the builder changes a test fixture, rewrites an assertion of an
/// existing test, or deletes a test file. Adding a test is allowed (the plan run adds three).
#[tokio::test]
async fn negative_nt_gate_01_the_builder_weakens_a_test_or_edits_a_fixture() {
    let weakened = "use word_count::count;\n\n#[test]\nfn counts_a_line() {\n    assert!(count(\"one two\") > 0);\n}\n\n#[test]\nfn counts_one_word() {\n    assert_eq!(count(\"one\"), 1);\n}\n";
    let cases: Vec<(&str, Vec<TreeEdit>, &str)> = vec![
        (
            "tests/fixtures/sample.txt",
            vec![write("tests/fixtures/sample.txt", "changed\n")],
            "deny_write",
        ),
        (
            "tests/it.rs",
            vec![write("tests/it.rs", weakened)],
            "additions_only",
        ),
        (
            "tests/it.rs",
            vec![TreeEdit::Delete(path("tests/it.rs"))],
            "additions_only",
        ),
    ];
    for (changed, edits, rule) in cases {
        let (rig, evidence, outcome) = first_task_with(edits).await;
        assert_refused(&rig, &evidence, &outcome, "protected-path-changed").await;
        assert_eq!(evidence["refusal"]["paths"][0]["path"], changed);
        assert_eq!(evidence["refusal"]["paths"][0]["rule"], rule);
    }
}

/// A hidden path in the tree, a link that leaves the workspace, a gitlink and a secret are
/// refused with the same record, and the secret itself is in no report and no evidence.
#[tokio::test]
async fn negative_nt_sec_05_unsafe_entries_and_secrets_in_the_tree_are_refused() {
    // Built at run time so that no secret-shaped literal sits in the source. The prefix is the one
    // the fake workspace's scan knows.
    let token = format!("{}{}", "ghs_", "a1B2".repeat(9));
    let cases: Vec<(Vec<TreeEdit>, &str, &str)> = vec![
        (
            vec![write(".env", "KEY=value\n")],
            "hidden-path-present",
            ".env",
        ),
        (
            vec![TreeEdit::Symlink {
                path: path("src/link"),
                target: "../../etc/passwd".to_owned(),
            }],
            "escaping-symlink",
            "src/link",
        ),
        (
            vec![TreeEdit::Gitlink(path("src/module"))],
            "gitlink",
            "src/module",
        ),
        (
            vec![write(
                "src/main.rs",
                &format!("fn main() {{\n    let key = \"{token}\";\n}}\n"),
            )],
            "secret-found",
            "src/main.rs",
        ),
    ];
    for (edits, code, refused) in cases {
        let (rig, evidence, outcome) = first_task_with(edits).await;
        assert_refused(&rig, &evidence, &outcome, code).await;
        assert_eq!(evidence["refusal"]["paths"][0]["path"], refused);
        // Nothing the stage stored holds the secret.
        let everything = format!(
            "{}{}",
            evidence,
            serde_json::to_string(&rig.gate_reports().await).expect("serializes")
        );
        assert!(!everything.contains(&token), "{code}");
    }
}

/// The builder's output is checked twice and never repaired. A document that fails its schema, a
/// report with a field it does not have, a `DONE` over a tree that did not change, and a report
/// about another task are all invalid output, and nothing is committed.
#[tokio::test]
async fn invalid_builder_output_is_never_accepted() {
    for case in 0..5 {
        let rig = Rig::new().await;
        rig.run_until_implementation().await;
        let mut report = done(FIRST, &["src/main.rs"]);
        let mut edits = vec![write("src/main.rs", MAIN)];
        match case {
            0 => rig.check.set(CheckMode::Refusing),
            1 => report["verdict"] = json!("PASS"),
            2 => edits.clear(),
            3 => report["task_id"] = json!("cover-unreadable-file-error"),
            _ => report = json!("DONE"),
        }
        rig.builder_will(edits, report);
        let (_, outcome) = rig.run_next().await;
        match outcome {
            AttemptOutcome::Failed { class, .. } => {
                assert_eq!(class, FailureClass::InvalidOutput, "case {case}");
            }
            other => panic!("case {case}: {other:?}"),
        }
        assert!(rig.events_of("workspace.commit").is_empty(), "case {case}");
        let run = rig.run_of(StageKind::Implementation).await;
        assert_eq!(rig.ledger.statuses(run)[0].1, TaskNodeStatus::Failed);
    }
}

/// `BLOCKED` and `NEEDS_HUMAN` from the builder, and a request for a dependency, stop the stage
/// and ask a person. Nothing is committed and nothing is retried.
#[tokio::test]
async fn a_builder_that_is_blocked_or_needs_a_decision_asks_a_person() {
    for case in 0..3 {
        let rig = Rig::new().await;
        rig.run_until_implementation().await;
        let mut report = done(FIRST, &["src/main.rs"]);
        match case {
            0 => {
                report["status"] = json!("BLOCKED");
                report["blocked_reason"] =
                    json!("The task needs a file outside the files it owns.");
                report["files_changed"] = json!([]);
            }
            1 => {
                report["status"] = json!("NEEDS_HUMAN");
                report["human_question"] = json!("Which of the two readings of the task is meant?");
                report["files_changed"] = json!([]);
            }
            _ => {
                report["dependency_requests"] = json!([{
                    "ecosystem": "cargo",
                    "name": "serde_json",
                    "version_req": "1",
                    "justification": "The formatter needs a JSON writer."
                }]);
            }
        }
        rig.builder_will(vec![write("src/main.rs", MAIN)], report);
        let (_, outcome) = rig.run_next().await;
        assert_eq!(outcome, AttemptOutcome::NeedsHuman, "case {case}");
        assert!(rig.events_of("workspace.ingest").is_empty(), "case {case}");
        assert!(rig.events_of("workspace.commit").is_empty(), "case {case}");
    }
}

/// NT-LSE-01: the worker loses its lease while the builder runs, and another worker takes the
/// stage run. The stale worker makes no commit and moves no task.
#[tokio::test]
async fn negative_nt_lse_01_a_stale_worker_makes_no_commit() {
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    let ledger = rig.ledger.clone();
    rig.runtime.hook("builder", move || ledger.take_over());
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Cancelled | AttemptOutcome::LeaseLost | AttemptOutcome::Failed { .. }
        ),
        "{outcome:?}"
    );
    assert!(
        rig.events_of("workspace.commit").is_empty(),
        "a worker that lost its lease commits nothing"
    );
    assert!(rig.events_of("ledger.finish").is_empty());
    let run = rig.run_of(StageKind::Implementation).await;
    assert!(
        rig.ledger
            .statuses(run)
            .iter()
            .all(|(_, status)| *status != TaskNodeStatus::Succeeded),
        "no task moved to SUCCEEDED"
    );
    assert_eq!(
        rig.runtime.runs("builder"),
        1,
        "the stale worker started no other task"
    );
}

/// NT-BUD-01: a builder run that goes over its own cost limit ends the stage for a person. It is
/// not retried: the same limit would be hit again.
#[tokio::test]
async fn negative_nt_bud_01_a_run_over_its_limit_is_not_retried() {
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    let mut script = AdversarialScript::returning(done(FIRST, &["src/main.rs"]));
    script.usage = Usage {
        input_tokens: 10,
        output_tokens: 10,
        cost: CostMicroUsd(6_000_000),
        requests: 1,
    };
    rig.runtime
        .edits("builder", vec![write("src/main.rs", MAIN)]);
    rig.runtime.inner.queue(script);
    let (_, outcome) = rig.run_next().await;
    match outcome {
        AttemptOutcome::Failed { class, then } => {
            assert_eq!(class, FailureClass::BudgetExhausted);
            assert!(
                !matches!(
                    then,
                    factory_domain::machines::retry::AttemptDisposition::Retry
                ),
                "{then:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(rig.events_of("workspace.commit").is_empty());
}

/// The stage has its own limit for all the tasks together. Once the tasks have used it, the next
/// task does not start, and what was already committed is kept for the run that goes on after a
/// person raises the limit.
#[tokio::test]
async fn the_stage_budget_stops_the_next_task_and_keeps_the_commits() {
    let rig = Rig::build(crate::rig::Options {
        budget: Some(factory_workflow::stages::implementation::StageBudget {
            wall_time_seconds: 14_400,
            max_tokens: 2_000_000,
            max_cost_usd: 1.0,
            attempt_timeout_seconds: 14_400,
            max_attempts: 3,
        }),
        ..crate::rig::Options::default()
    })
    .await;
    rig.run_until_implementation().await;
    let mut first = AdversarialScript::returning(done(
        FIRST,
        &["src/main.rs", "src/output.rs", "tests/json_output.rs"],
    ));
    first.usage = Usage {
        input_tokens: 100,
        output_tokens: 100,
        cost: CostMicroUsd(2_000_000),
        requests: 2,
    };
    rig.runtime.edits(
        "builder",
        vec![
            write("src/main.rs", MAIN),
            write("src/output.rs", crate::rig::OUTPUT),
            write("tests/json_output.rs", crate::rig::JSON_TEST),
        ],
    );
    rig.runtime.inner.queue(first);
    let (_, outcome) = rig.run_next().await;
    match outcome {
        AttemptOutcome::Failed { class, .. } => {
            assert_eq!(class, FailureClass::BudgetExhausted);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        rig.runtime.runs("builder"),
        1,
        "the second task never started"
    );
    let run = rig.run_of(StageKind::Implementation).await;
    let statuses = rig.ledger.statuses(run);
    assert_eq!(statuses[0].1, TaskNodeStatus::Succeeded);
    assert_eq!(statuses[1].1, TaskNodeStatus::Pending);
    assert_eq!(rig.ledger.commits(run).len(), 1);
}
