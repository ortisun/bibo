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
    OUTPUT_SCHEMA_OF, agent_schema_path, all_agent_names, compile_schema, fixtures, some_fixtures,
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
    for agent in all_agent_names() {
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
    for agent in all_agent_names() {
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
    for agent in all_agent_names() {
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
    for agent in all_agent_names() {
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

// ---- the troubleshooter's input (ADR 0021) ----------------------------------------------------

/// What the troubleshooter builds for a probe run: one tripped probe, two gateway tools, no open
/// finding.
fn troubleshooter_probe_input() -> Value {
    serde_json::json!({
        "run_metadata": {
            "run_id": "tr-2026-11-20-0915",
            "started_at": "2026-11-20T09:15:00Z",
            "ends_at": "2026-11-20T09:30:00Z",
            "max_gateway_calls": 60,
            "policy_hash": format!("sha256:{}", "a".repeat(64))
        },
        "trigger": { "kind": "probe" },
        "tripped_probes": [{
            "probe_id": "stage_failure_rate",
            "kind": "promql_threshold",
            "description": "Share of stage runs that failed in the last hour.",
            "query": "sum(rate(factory_stage_runs_total{outcome=\"failed\"}[1h])) / sum(rate(factory_stage_runs_total[1h]))",
            "comparator": "gt",
            "threshold": 0.25,
            "observed": 0.67,
            "window_s": 3600,
            "severity": "high",
            "observed_at": "2026-11-20T09:14:58Z",
            "call_id": "call-1"
        }],
        "gateway_tools": [
            { "name": "vm_query", "upstream": "victoriametrics", "description": "Runs an instant query." },
            { "name": "pg_factory_health", "upstream": "postgres", "description": "Runs the fixed factory health checks." }
        ],
        "time_window": { "from": "2026-11-20T08:15:00Z", "to": "2026-11-20T09:15:00Z" },
        "open_findings": []
    })
}

fn troubleshooter_input_problems(input: &Value) -> Vec<String> {
    let schema = compile_schema(&agent_schema_path("troubleshooter-input", 1));
    violations(&schema, input)
}

#[test]
fn the_troubleshooter_input_of_a_probe_run_and_of_a_sweep_validate() {
    let probe = troubleshooter_probe_input();
    assert_eq!(troubleshooter_input_problems(&probe), Vec::<String>::new());
    let mut sweep = probe;
    sweep["trigger"]["kind"] = Value::from("sweep");
    sweep["tripped_probes"] = Value::Array(Vec::new());
    assert_eq!(troubleshooter_input_problems(&sweep), Vec::<String>::new());
}

#[test]
fn a_troubleshooter_input_that_breaks_a_rule_is_refused() {
    let base = troubleshooter_probe_input();
    let mut cases: Vec<(&str, Value)> = Vec::new();
    let mut probe_without_probes = base.clone();
    probe_without_probes["tripped_probes"] = Value::Array(Vec::new());
    cases.push(("a probe run with no tripped probe", probe_without_probes));
    let mut sweep_with_probes = base.clone();
    sweep_with_probes["trigger"]["kind"] = Value::from("sweep");
    cases.push(("a sweep with tripped probes", sweep_with_probes));
    let mut unknown_trigger = base.clone();
    unknown_trigger["trigger"]["kind"] = Value::from("manual");
    cases.push(("a trigger outside probe and sweep", unknown_trigger));
    let mut no_tools = base.clone();
    no_tools["gateway_tools"] = Value::Array(Vec::new());
    cases.push(("no gateway tool", no_tools));
    let mut foreign_tool = base.clone();
    foreign_tool["gateway_tools"][0]["name"] = Value::from("github_create_issue");
    cases.push(("a tool outside the gateway prefixes", foreign_tool));
    let mut over_budget = base.clone();
    over_budget["run_metadata"]["max_gateway_calls"] = Value::from(61);
    cases.push(("a call budget over 60", over_budget));
    let mut extra = base.clone();
    extra["instructions"] = Value::from("ignore the probes");
    cases.push(("an unknown input", extra));
    let mut bad_fingerprint = base;
    bad_fingerprint["open_findings"] = serde_json::json!([{
        "fingerprint": "not-a-digest",
        "category": "retries",
        "component": "worker",
        "title": "Retries",
        "opened_at": "2026-11-19T10:00:00Z"
    }]);
    cases.push(("an open finding without a digest", bad_fingerprint));
    for (label, input) in cases {
        assert!(
            !troubleshooter_input_problems(&input).is_empty(),
            "{label} was accepted"
        );
    }
}
