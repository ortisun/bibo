//! The schema of the repository map, which the stage `REPOSITORY_INTELLIGENCE` of `factory-workflow`
//! keeps next to its code (`crates/workflow/src/stages/repo_intel/repository-map.v1.schema.json`).
//!
//! `factory-workflow` cannot depend on this crate, so it cannot check its own schema. This test
//! does it with the schema engine: the schema compiles with the keywords the engine supports, the
//! example (which a test of `factory-workflow` proves to be the map of its fixture repository)
//! follows it, and a map that breaks it in any of the usual ways is refused.

mod support;

use factory_contracts::agent_schema::AgentSchema;
use factory_contracts::validator::{IssueKind, OutputLimits};
use serde_json::{Value, json};
use support::{read_text, repo_root};

fn schema_text() -> String {
    read_text(
        &repo_root().join("crates/workflow/src/stages/repo_intel/repository-map.v1.schema.json"),
    )
}

fn example() -> Value {
    serde_json::from_str(&read_text(
        &repo_root().join("crates/workflow/src/stages/repo_intel/repository-map.example.json"),
    ))
    .expect("the example is JSON")
}

fn schema() -> AgentSchema {
    AgentSchema::from_text(&schema_text(), OutputLimits::AGENT_OUTPUT)
        .unwrap_or_else(|e| panic!("the repository map schema does not compile: {e}"))
}

fn refused(document: &Value) -> Vec<IssueKind> {
    schema()
        .parse_and_validate(&serde_json::to_vec(document).expect("serializes"))
        .expect_err("the map must be refused")
        .iter()
        .map(|issue| issue.kind)
        .collect()
}

#[test]
fn the_schema_compiles_and_declares_its_id() {
    let compiled = schema();
    assert_eq!(
        compiled.id(),
        Some("urn:ortisun:factory:schema:stage:repository-map:1")
    );
}

#[test]
fn the_example_map_follows_the_schema() {
    let bytes = serde_json::to_vec(&example()).expect("serializes");
    schema()
        .parse_and_validate(&bytes)
        .unwrap_or_else(|issues| panic!("{issues:?}"));
}

#[test]
fn a_map_that_breaks_the_schema_is_refused() {
    let base = example();
    let broken = |edit: &dyn Fn(&mut Value)| {
        let mut copy = base.clone();
        edit(&mut copy);
        refused(&copy)
    };
    // An unknown field, a missing field, a wrong value.
    assert!(!broken(&|v| v["approved"] = json!(true)).is_empty());
    assert!(
        !broken(&|v| {
            v.as_object_mut().expect("object").remove("counts");
        })
        .is_empty()
    );
    assert!(!broken(&|v| v["schema_version"] = json!(2)).is_empty());
    assert!(!broken(&|v| v["commit_sha"] = json!("not-a-commit")).is_empty());
    assert!(!broken(&|v| v["baseline"]["status"] = json!("green")).is_empty());
    // A claim with no provenance.
    assert!(
        !broken(&|v| {
            v["languages"][0]
                .as_object_mut()
                .expect("object")
                .remove("evidence");
        })
        .is_empty()
    );
    // A line before the first.
    assert!(
        !broken(&|v| v["languages"][0]["evidence"]["line_range"]["start"] = json!(0)).is_empty()
    );
    // A path that leaves the repository, in a claim.
    let issues = broken(&|v| v["languages"][0]["evidence"]["path"] = json!("../../etc/passwd"));
    assert!(issues.contains(&IssueKind::UnsafePath), "{issues:?}");
    // A blocked baseline must say why; a ready one must name its toolchain.
    assert!(
        !broken(&|v| {
            v["baseline"] = json!({ "status": "blocked" });
        })
        .is_empty()
    );
    assert!(
        !broken(&|v| {
            v["baseline"] = json!({ "status": "ready" });
        })
        .is_empty()
    );
}
