//! The playbook, on its own: every answer it gives is valid against the schema of the agent it
//! speaks for, an answer it has not planned for fails loudly, and a second answer for the same
//! question is refused.
//!
//! These tests need no database and no engine. The full run (`full_run.rs`) is what shows the
//! answers are right for the stages that read them.

#[allow(dead_code)]
mod playbook;

use std::path::PathBuf;

use factory_composition::seams::SchemaChecker;
use factory_contracts::registry::FileAgentRegistry;
use factory_domain::values::Slug;
use factory_ports::registry::{AgentRegistry, VersionReq};
use factory_workflow::stages::specification::AgentOutputCheck;
use playbook::{Playbook, block};
use serde_json::json;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// A prompt with one data block, in the shape the factory's prompt template writes.
fn data_block(name: &str, text: &str) -> String {
    let quoted: Vec<String> = text.lines().map(|line| format!("> {line}")).collect();
    format!(
        "<<<DATA name={name} class=tool_output>>>\n{}\n<<<END name={name}>>>\n",
        quoted.join("\n")
    )
}

fn spec_prompt(skill: &str) -> String {
    format!(
        "/speckit-{skill} Write the feature specification in the directory specs/add-a-json-option-1a2b3c4d, and use add-a-json-option-1a2b3c4d as the short name of the feature. The request is in the file inputs/request.md."
    )
}

/// Asks the playbook the way each agent's stage would, with just enough prompt for the entry.
fn ask(playbook: &Playbook, agent: &str) -> playbook::Reply {
    match agent {
        "specification-writer" => playbook.answer(agent, &spec_prompt("specify")),
        "planner" => {
            let example = std::fs::read_to_string(
                root().join("schemas/examples/task-dag/valid/json-output-flag-plan.json"),
            )
            .expect("the plan example");
            let plan: serde_json::Value = serde_json::from_str(&example).expect("JSON");
            let specification = json!({
                "requirements": [
                    {"id": "FR-001", "acceptance_scenario_ids": ["AS-0000000001"]},
                    {"id": "FR-002", "acceptance_scenario_ids": ["AS-0000000002"]},
                    {"id": "FR-003", "acceptance_scenario_ids": ["AS-0000000003"]},
                    {"id": "FR-004", "acceptance_scenario_ids": ["AS-0000000001"]},
                ]
            });
            let prompt = format!(
                "{}{}",
                data_block("plan_metadata", &plan["metadata"].to_string()),
                data_block("frozen_specification", &specification.to_string())
            );
            playbook.answer(agent, &prompt)
        }
        "builder" => playbook.answer(
            agent,
            &data_block("task", "The task write-json-formatter: write the counts."),
        ),
        other => playbook.answer(other, ""),
    }
}

#[test]
fn every_answer_is_valid_against_the_schema_of_its_agent() {
    let root = root();
    let registry = FileAgentRegistry::load(&root).expect("the real agent registry");
    let checker = SchemaChecker::new(&root);
    let playbook = Playbook::word_count(&root);
    for agent in [
        "intake-classifier",
        "specification-writer",
        "specification-reviewer",
        "architect",
        "planner",
        "builder",
        "code-reviewer",
        "documentation-writer",
        "documentation-reviewer",
    ] {
        let manifest = registry
            .manifest(&Slug::parse(agent).expect("a slug"), &VersionReq::Any)
            .unwrap_or_else(|error| panic!("{agent} is in the registry: {error:?}"));
        let reply = ask(&playbook, agent);
        let bytes = serde_json::to_vec(&reply.output).expect("JSON");
        checker
            .check(&manifest.outputs_schema, &bytes)
            .unwrap_or_else(|violations| {
                panic!(
                    "{agent}: the entry {} breaks the schema {}: {violations:?}",
                    reply.entry, manifest.outputs_schema.name
                )
            });
    }
}

#[test]
fn the_plan_is_a_task_graph_the_domain_accepts() {
    use factory_domain::contracts::{Contract as _, TaskDag};
    let playbook = Playbook::word_count(&root());
    let reply = ask(&playbook, "planner");
    let plan = TaskDag::from_json_value(reply.output["plan"].clone())
        .unwrap_or_else(|error| panic!("the plan is not a task graph: {error:?}"));
    assert_eq!(plan.tasks.as_slice().len(), 2);
}

#[test]
fn the_builder_gets_the_patch_of_its_task_and_nothing_else() {
    let playbook = Playbook::word_count(&root());
    let first = playbook.answer(
        "builder",
        &data_block("task", "The task write-json-formatter: write the counts."),
    );
    let paths: Vec<&str> = first.writes.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, ["src/lib.rs"]);
    let second = playbook.answer(
        "builder",
        &data_block("task", "The task read-json-option: read the option."),
    );
    let paths: Vec<&str> = second
        .writes
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(paths, ["src/main.rs", "tests/json_output.rs"]);
}

#[test]
fn a_prompt_that_names_two_tasks_is_not_guessed() {
    let playbook = Playbook::word_count(&root());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        playbook.answer(
            "builder",
            &data_block(
                "task",
                "Work on read-json-option, which needs write-json-formatter first.",
            ),
        )
    }));
    assert!(result.is_err());
    assert!(playbook.misses()[0].contains("several known tasks"));
}

#[test]
fn a_task_the_playbook_does_not_know_fails_loudly_and_is_recorded() {
    let playbook = Playbook::word_count(&root());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        playbook.answer(
            "builder",
            &data_block("task", "Rename the project to something else."),
        )
    }));
    assert!(result.is_err(), "an unknown task must not be answered");
    assert_eq!(playbook.misses().len(), 1);
    assert!(playbook.misses()[0].contains("builder"));
}

#[test]
fn an_agent_the_playbook_does_not_play_fails_loudly() {
    let playbook = Playbook::word_count(&root());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        playbook.answer("security", "")
    }));
    assert!(result.is_err());
    assert!(playbook.misses()[0].contains("not an agent the playbook plays"));
}

#[test]
fn a_skill_the_playbook_does_not_have_fails_loudly() {
    let playbook = Playbook::word_count(&root());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        playbook.answer("specification-writer", &spec_prompt("plan"))
    }));
    assert!(
        result.is_err(),
        "the plan skill is not one the factory runs"
    );
    assert!(playbook.misses()[0].contains("plan"));
}

#[test]
fn a_second_question_for_the_same_entry_fails_loudly() {
    let playbook = Playbook::word_count(&root());
    let first = playbook.answer("architect", "");
    assert_eq!(first.entry, "architect");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        playbook.answer("architect", "")
    }));
    assert!(
        result.is_err(),
        "the playbook has one answer for the architect"
    );
    assert!(playbook.misses()[0].contains("for the 2 time"));
    assert_eq!(playbook.times_served("architect"), 1);
}

#[test]
fn a_deliberate_break_replaces_an_answer_in_view_of_the_reader() {
    let playbook = Playbook::word_count(&root());
    playbook.replace(
        "architect",
        playbook::Reply {
            entry: "architect".to_owned(),
            output: json!({"status": "NEEDS_HUMAN"}),
            writes: Vec::new(),
        },
    );
    let reply = playbook.answer("architect", "");
    assert_eq!(reply.output["status"], "NEEDS_HUMAN");
    // The same key can be asked again once it was replaced: the test that replaced it owns that.
    let _ = block("", "none");
}
