//! The task plan validator, driven through its public interface on the example plan of the schema.
//!
//! Each test starts from the valid example, breaks one rule, and expects the validator to name
//! that rule. The deliberate-break tests of the work package go further: they remove a check and
//! show that one of these tests then fails, which is what makes the test worth having.

use std::collections::BTreeSet;

use factory_domain::contracts::{Contract, SpecificationContract, TaskDag};
use factory_workflow::gates::dag::{Check, Limits, Report, SpecFacts, validate};
use serde_json::{Value, json};

const PLAN: &str =
    include_str!("../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
const SPEC: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);

fn facts() -> SpecFacts {
    let spec = SpecificationContract::from_json_str(SPEC).expect("the example specification");
    SpecFacts::from_contract(&spec)
}

fn broken(change: impl FnOnce(&mut Value)) -> Value {
    let mut value: Value = serde_json::from_str(PLAN).expect("the example is JSON");
    change(&mut value);
    value
}

fn run(value: Value, limits: &Limits) -> Report {
    let plan = TaskDag::from_json_value(value).expect("a plan that is valid by shape");
    validate(&plan, &facts(), limits)
}

fn found(report: &Report) -> BTreeSet<Check> {
    report.findings.iter().map(|f| f.check).collect()
}

#[test]
fn dag_validator_accepts_the_valid_schema_example() {
    let report = run(broken(|_| {}), &Limits::default());
    assert!(report.is_clean(), "{:?}", report.findings);
    assert!(report.analysis.is_some());
}

#[test]
fn dag_validator_rejects_a_cycle() {
    let report = run(
        broken(|v| v["tasks"][0]["depends_on"] = json!(["document-json-flag"])),
        &Limits::default(),
    );
    assert!(
        found(&report).contains(&Check::Cycle),
        "{:?}",
        report.findings
    );
}

#[test]
fn dag_validator_rejects_a_dangling_dependency() {
    let report = run(
        broken(|v| v["tasks"][1]["depends_on"] = json!(["a-task-that-does-not-exist"])),
        &Limits::default(),
    );
    assert!(found(&report).contains(&Check::DanglingDependency));
}

#[test]
fn dag_validator_rejects_a_duplicate_task_id() {
    let report = run(
        broken(|v| v["tasks"][2]["task_id"] = json!("add-json-output-formatter")),
        &Limits::default(),
    );
    assert!(found(&report).contains(&Check::DuplicateTask));
}

#[test]
fn dag_validator_rejects_overlapping_owned_files_without_an_ordering_edge() {
    let report = run(
        broken(|v| {
            v["tasks"][2]["depends_on"] = json!([]);
            v["tasks"][2]["owned_files"] = json!(["README.md", "tests/**"]);
        }),
        &Limits::default(),
    );
    assert!(
        found(&report).contains(&Check::ParallelFileConflict),
        "{:?}",
        report.findings
    );
}

#[test]
fn dag_validator_accepts_overlapping_owned_files_when_one_task_depends_on_the_other() {
    let report = run(
        broken(|v| {
            v["tasks"][2]["owned_files"] = json!(["README.md", "tests/**"]);
            v["tasks"][2]["depends_on"] =
                json!(["add-json-output-formatter", "cover-unreadable-file-error"]);
        }),
        &Limits::default(),
    );
    assert!(report.is_clean(), "{:?}", report.findings);
}

#[test]
fn dag_validator_rejects_an_uncovered_acceptance_scenario() {
    let report = run(
        broken(|v| {
            v["tasks"][1]["acceptance_mapping"]["acceptance_scenario_ids"] = json!(["AS-003"]);
        }),
        &Limits::default(),
    );
    let uncovered: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.check == Check::UncoveredScenario)
        .map(|f| f.subject.as_str())
        .collect();
    assert_eq!(uncovered, ["AS-004"]);
}

#[test]
fn dag_validator_rejects_an_over_large_plan() {
    let limits = Limits {
        max_tasks: 2,
        ..Limits::default()
    };
    let report = run(broken(|_| {}), &limits);
    assert!(found(&report).contains(&Check::TooManyTasks));
}

#[test]
fn dag_validator_rejects_a_task_missing_a_template_part() {
    // A task with no verification step is refused when the plan is read, before any check runs:
    // the typed plan cannot hold one. The check that follows is the second wall.
    let mut value = broken(|v| {
        v["tasks"][1]
            .as_object_mut()
            .expect("a task")
            .remove("verification");
    });
    assert!(TaskDag::from_json_value(value.clone()).is_err());
    value["tasks"][1]["verification"] = json!([]);
    assert!(TaskDag::from_json_value(value).is_err());
}
