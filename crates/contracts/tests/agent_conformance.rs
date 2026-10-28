//! Conformance fixtures for the Slice 1 agents.
//!
//! These are conformance checks, not quality evaluations. They prove that the scripted outputs a
//! fake runtime would return follow each agent's output schema, that outputs which break the
//! schema are refused, and that the input and output schemas close the set of fields an agent
//! receives and returns. They say nothing about how well a real model does the work.
//!
//! The scripted runtime in `factory-testkit` plays an attacker's script and the contracts crate may
//! not depend on it, so the fixtures under `agents/<agent>/fixtures/` stand in for the outputs of a
//! scripted runtime: `valid/` holds outputs that must pass and `invalid/` holds outputs that must
//! be refused.

mod agent_defs;
mod support;

use factory_contracts::validator::SchemaOutputValidator;
use factory_ports::registry::{ContractKind, OutputValidator};
use serde_json::Value;

use agent_defs::{
    OUTPUT_SCHEMA_OF, SLICE_1_AGENTS, agent_schema_path, compile_schema, fixtures, some_fixtures,
    violations,
};

fn output_schema_name(agent: &str) -> &'static str {
    OUTPUT_SCHEMA_OF
        .iter()
        .find(|(id, _)| *id == agent)
        .map(|(_, name)| *name)
        .unwrap_or_else(|| panic!("no output schema is recorded for {agent}"))
}

/// The planner's result holds a task graph in `plan`. The envelope schema checks the status and
/// the question, and the engine validates the plan against the factory's `task-dag` schema.
fn nested_plan_problems(agent: &str, output: &Value) -> Vec<String> {
    if agent != "planner" {
        return Vec::new();
    }
    let Some(plan) = output.get("plan") else {
        return Vec::new();
    };
    let validator = SchemaOutputValidator::new().expect("the embedded schemas compile");
    match validator.validate_value(ContractKind::TaskDag, 1, plan) {
        Ok(()) => Vec::new(),
        Err(found) => found
            .iter()
            .map(|v| format!("plan: {}", v.message))
            .collect(),
    }
}

fn output_problems(agent: &str, output: &Value) -> Vec<String> {
    let schema = compile_schema(&agent_schema_path(output_schema_name(agent), 1));
    let mut problems = violations(&schema, output);
    problems.extend(nested_plan_problems(agent, output));
    problems
}

#[test]
fn every_agent_has_valid_and_invalid_conformance_fixtures() {
    for agent in SLICE_1_AGENTS {
        assert!(
            !fixtures(agent, "valid").is_empty(),
            "{agent} has no fixture under fixtures/valid/"
        );
        assert!(
            fixtures(agent, "invalid").len() >= 2,
            "{agent} needs at least two fixtures under fixtures/invalid/"
        );
    }
}

#[test]
fn the_scripted_outputs_validate_against_the_agents_output_schema() {
    for agent in SLICE_1_AGENTS {
        for fixture in some_fixtures(agent, "valid") {
            let problems = output_problems(agent, &fixture.value);
            assert!(
                problems.is_empty(),
                "{agent}/valid/{} breaks the output schema: {problems:?}",
                fixture.name
            );
        }
    }
}

#[test]
fn outputs_that_break_the_schema_are_refused() {
    for agent in SLICE_1_AGENTS {
        for fixture in some_fixtures(agent, "invalid") {
            assert!(
                !output_problems(agent, &fixture.value).is_empty(),
                "{agent}/invalid/{} was accepted, so the schema does not catch it",
                fixture.name
            );
        }
    }
}

#[test]
fn every_output_schema_and_input_schema_compiles_and_is_closed() {
    for agent in SLICE_1_AGENTS {
        for name in [
            output_schema_name(agent).to_owned(),
            format!("{agent}-input"),
        ] {
            let path = agent_schema_path(&name, 1);
            let text = support::read_text(&path);
            let document: Value = serde_json::from_str(&text).expect("JSON");
            assert_eq!(
                document["additionalProperties"],
                Value::Bool(false),
                "{name} accepts fields it does not name"
            );
            compile_schema(&path);
        }
    }
}

#[test]
fn every_output_requires_the_list_of_ignored_instructions() {
    let mut names: Vec<&str> = OUTPUT_SCHEMA_OF.iter().map(|(_, n)| *n).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let document: Value =
            serde_json::from_str(&support::read_text(&agent_schema_path(name, 1))).expect("JSON");
        let required = document["required"].as_array().expect("required");
        assert!(
            required.iter().any(|r| r == "ignored_instructions"),
            "{name} lets an agent leave out the list of instructions it ignored"
        );
    }
}

/// A reviewer returns findings only. The facts about what it was given are built by the engine, so
/// a reviewer output has no place to report, or to leak, the builder's account.
#[test]
fn a_review_output_has_no_field_for_the_inputs_it_saw() {
    let document: Value = serde_json::from_str(&support::read_text(&agent_schema_path(
        "review-findings",
        1,
    )))
    .expect("JSON");
    let properties = document["properties"].as_object().expect("properties");
    for forbidden in [
        "inputs_reviewed",
        "saw_builder_self_assessment",
        "metadata",
        "builder_summary",
    ] {
        assert!(
            !properties.contains_key(forbidden),
            "review-findings has a {forbidden} field"
        );
    }
}
