//! The gate reports against `schemas/gate-report.schema.json`.

use factory_domain::contracts::{Contract, GateReport};
use serde_json::Value;

use crate::gates::{base_run, head_run, it_with_requirement_tests, passing_world};
use crate::schema_check;
use crate::world::{Ran, World};

fn every_report(ran: &Ran) -> Vec<Value> {
    ran.decision
        .reports
        .iter()
        .map(|report| report.to_json_value().expect("a report is JSON"))
        .collect()
}

fn problems_of(report: &Value) -> Vec<String> {
    let schema: Value = serde_json::from_str(schema_check::SCHEMA).expect("the schema is JSON");
    schema_check::problems(&schema, report)
}

#[tokio::test]
async fn gate_reports_match_the_schema() {
    let mut reports: Vec<Value> = Vec::new();

    // Every outcome: passed, failed, blocked and not applicable.
    let (w, base, head) = passing_world().await;
    reports.extend(every_report(&w.run(&base, &head).await));

    let (w, base, head) = passing_world().await;
    w.cargo.exit_of("fmt", 1);
    w.cargo.lacks("clippy");
    reports.extend(every_report(&w.run(&base, &head).await));

    let w = World::new();
    let more = it_with_requirement_tests();
    let (base, head) = w
        .project(&[
            ("tests/it.rs", Some(&more)),
            (".github/workflows/ci.yml", Some("x\n")),
        ])
        .await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    reports.extend(every_report(&w.run(&base, &head).await));

    let w = World::new();
    let manifest = crate::gates::manifest_with(serde_json::json!([
        crate::gates::gate("build", &["cargo", "build"]),
        crate::gates::gate("unit-tests", &["cargo", "test"]),
    ]));
    let base = w
        .push(&crate::world::with(&[(
            ".factory/project.json",
            Some(&manifest),
        )]))
        .await;
    w.cargo.queue_test_run(base_run());
    w.cargo.queue_test_run(base_run());
    reports.extend(every_report(&w.run(&base, &base).await));

    let outcomes: std::collections::BTreeSet<&str> = reports
        .iter()
        .filter_map(|report| report["outcome"].as_str())
        .collect();
    assert_eq!(
        outcomes.into_iter().collect::<Vec<_>>(),
        ["BLOCKED", "FAILED", "NOT_APPLICABLE", "PASSED"],
        "the run covers every outcome"
    );

    for report in &reports {
        let gate = report["metadata"]["gate_id"].as_str().unwrap_or("?");
        let problems = problems_of(report);
        assert!(problems.is_empty(), "{gate}: {problems:?}");
        GateReport::from_json_value(report.clone())
            .unwrap_or_else(|error| panic!("{gate}: the domain refuses the report: {error}"));
        let trusted = &report["metadata"]["trusted_definition"];
        assert_eq!(trusted["source"], "protected_base_branch", "{gate}");
        assert!(
            trusted["commit_sha"]
                .as_str()
                .is_some_and(|sha| sha.len() == 40),
            "{gate}"
        );
        assert!(
            trusted["definition_sha256"]
                .as_str()
                .is_some_and(|h| h.starts_with("sha256:")),
            "{gate}"
        );
    }
}

#[tokio::test]
async fn the_schema_check_can_fail_on_a_report_that_does_not_name_its_definition() {
    let (w, base, head) = passing_world().await;
    let ran = w.run(&base, &head).await;
    let mut report = every_report(&ran).remove(0);
    report["metadata"]
        .as_object_mut()
        .expect("metadata is an object")
        .remove("trusted_definition");
    assert!(!problems_of(&report).is_empty());
}
