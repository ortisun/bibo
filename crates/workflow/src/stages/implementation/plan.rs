//! The task plan, read for what the implementation stage needs: the order to run tasks in, the
//! text of one task for the builder's prompt, and the files each task owns.
//!
//! The planner's validator (another package) rejects a cycle, a dangling dependency and a
//! duplicate id before the plan reaches this stage. This module does not rely on that: it checks
//! the same three things again, because a stage that runs commands in an order it never checked
//! would trust a document it did not make.

use std::collections::BTreeSet;

use factory_domain::contracts::task_dag::Task;
use factory_domain::contracts::{Contract, TaskDag};
use factory_domain::values::Slug;

/// Why a plan cannot be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanProblem {
    /// The bytes are not a task plan.
    #[error("the bytes are not a valid task plan")]
    NotAPlan,
    /// Two tasks share an identifier.
    #[error("two tasks share the identifier `{0}`")]
    DuplicateTask(String),
    /// A task depends on a task the plan does not hold.
    #[error("task `{task}` depends on `{missing}`, which the plan does not hold")]
    DanglingDependency {
        /// The task.
        task: String,
        /// The identifier it names.
        missing: String,
    },
    /// The dependencies form a cycle, so no order exists.
    #[error("the task dependencies form a cycle")]
    Cycle,
}

/// Reads a task plan from the bytes of the stored document.
///
/// # Errors
/// [`PlanProblem::NotAPlan`] when the bytes do not follow the `task-dag` contract.
pub fn read(bytes: &[u8]) -> Result<TaskDag, PlanProblem> {
    let text = std::str::from_utf8(bytes).map_err(|_| PlanProblem::NotAPlan)?;
    TaskDag::from_json_str(text).map_err(|_| PlanProblem::NotAPlan)
}

/// The tasks in the order they run: every task after the tasks it depends on, and among tasks
/// that are ready together, in the order the plan lists them. The same plan always gives the same
/// order, so a restarted attempt resumes at the same place.
///
/// # Errors
/// [`PlanProblem`] for a duplicate identifier, a dangling dependency or a cycle.
pub fn order(plan: &TaskDag) -> Result<Vec<&Task>, PlanProblem> {
    let tasks = plan.tasks.as_slice();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for task in tasks {
        if !seen.insert(task.task_id.as_str()) {
            return Err(PlanProblem::DuplicateTask(task.task_id.as_str().to_owned()));
        }
    }
    for task in tasks {
        for dependency in task.depends_on.as_slice() {
            if !seen.contains(dependency.as_str()) {
                return Err(PlanProblem::DanglingDependency {
                    task: task.task_id.as_str().to_owned(),
                    missing: dependency.as_str().to_owned(),
                });
            }
        }
    }
    let mut done: BTreeSet<&str> = BTreeSet::new();
    let mut ordered: Vec<&Task> = Vec::with_capacity(tasks.len());
    while ordered.len() < tasks.len() {
        let next = tasks.iter().find(|task| {
            !done.contains(task.task_id.as_str())
                && task
                    .depends_on
                    .as_slice()
                    .iter()
                    .all(|dependency| done.contains(dependency.as_str()))
        });
        let Some(task) = next else {
            return Err(PlanProblem::Cycle);
        };
        done.insert(task.task_id.as_str());
        ordered.push(task);
    }
    Ok(ordered)
}

/// The globs a task may change.
#[must_use]
pub fn owned_files(task: &Task) -> Vec<String> {
    task.owned_files
        .as_ref()
        .map(|files| {
            files
                .as_slice()
                .iter()
                .map(|glob| glob.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Every glob any task of the plan owns, without repeats, in the order they appear.
#[must_use]
pub fn all_owned_files(plan: &TaskDag) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for task in plan.tasks.as_slice() {
        for glob in owned_files(task) {
            if !found.contains(&glob) {
                found.push(glob);
            }
        }
    }
    found
}

/// The task as the builder reads it: what to change, why, how it is judged, and the only files it
/// may touch. It is plain text that goes into an untrusted data block, so nothing in it can act as
/// an instruction.
#[must_use]
pub fn render_task(task: &Task) -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "Task {}: {}\n\n",
        task.task_id.as_str(),
        task.title.as_str()
    ));
    text.push_str(&format!(
        "Why it matters: {}\n\n",
        task.why_this_matters.as_str()
    ));
    text.push_str(&format!(
        "What needs to change: {}\n\n",
        task.what_needs_to_change.as_str()
    ));
    text.push_str("Acceptance criteria:\n");
    for criterion in task.acceptance_criteria.as_slice() {
        text.push_str(&format!("- {}\n", criterion.as_str()));
    }
    text.push_str("\nVerification:\n");
    for step in task.verification.as_slice() {
        text.push_str(&format!("- {}\n", step.as_str()));
    }
    let mapping = &task.acceptance_mapping;
    let requirements: Vec<&str> = mapping
        .requirement_ids
        .as_slice()
        .iter()
        .map(|id| id.as_str())
        .collect();
    let scenarios: Vec<&str> = mapping
        .acceptance_scenario_ids
        .as_slice()
        .iter()
        .map(|id| id.as_str())
        .collect();
    text.push_str(&format!(
        "\nSpecification ids this task serves: requirements {}; acceptance scenarios {}.\n",
        requirements.join(", "),
        scenarios.join(", ")
    ));
    text.push_str("\nFiles you may change (every other path is out of scope):\n");
    for glob in owned_files(task) {
        text.push_str(&format!("- {glob}\n"));
    }
    text
}

/// The key of a task as a slug, for the ledger.
#[must_use]
pub fn key(task: &Task) -> Slug {
    task.task_id.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const EXAMPLE: &str =
        include_str!("../../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");

    fn plan_with(mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_str(EXAMPLE).expect("the example is JSON");
        mutate(&mut value);
        serde_json::to_vec(&value).expect("serializes")
    }

    #[test]
    fn the_example_plan_runs_its_formatter_task_first() {
        let plan = read(EXAMPLE.as_bytes()).expect("the example is a plan");
        let ids: Vec<&str> = order(&plan)
            .expect("an order exists")
            .iter()
            .map(|task| task.task_id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "add-json-output-formatter",
                "cover-unreadable-file-error",
                "document-json-flag"
            ]
        );
    }

    #[test]
    fn a_task_listed_first_still_waits_for_its_dependency() {
        let bytes = plan_with(|value| {
            let tasks = value["tasks"].as_array_mut().expect("tasks");
            tasks.reverse();
        });
        let plan = read(&bytes).expect("still a plan");
        let ids: Vec<&str> = order(&plan)
            .expect("an order exists")
            .iter()
            .map(|task| task.task_id.as_str())
            .collect();
        assert_eq!(ids[0], "add-json-output-formatter");
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn a_cycle_a_dangling_dependency_and_a_duplicate_have_no_order() {
        let cycle = plan_with(|value| {
            value["tasks"][0]["depends_on"] = json!(["document-json-flag"]);
        });
        assert_eq!(
            order(&read(&cycle).expect("a plan")).unwrap_err(),
            PlanProblem::Cycle
        );
        let dangling = plan_with(|value| {
            value["tasks"][1]["depends_on"] = json!(["no-such-task"]);
        });
        assert!(matches!(
            order(&read(&dangling).expect("a plan")).unwrap_err(),
            PlanProblem::DanglingDependency { .. }
        ));
        let duplicate = plan_with(|value| {
            value["tasks"][1]["task_id"] = json!("add-json-output-formatter");
        });
        assert!(matches!(
            order(&read(&duplicate).expect("a plan")).unwrap_err(),
            PlanProblem::DuplicateTask(_)
        ));
    }

    #[test]
    fn bytes_that_are_not_a_plan_are_refused() {
        assert_eq!(read(b"{}").unwrap_err(), PlanProblem::NotAPlan);
        assert_eq!(read(&[0xff, 0xfe]).unwrap_err(), PlanProblem::NotAPlan);
    }

    #[test]
    fn the_rendered_task_names_the_files_it_may_change_and_the_spec_ids_it_serves() {
        let plan = read(EXAMPLE.as_bytes()).expect("a plan");
        let first = order(&plan).expect("an order")[0];
        let text = render_task(first);
        assert!(text.contains("- src/output.rs"), "{text}");
        assert!(text.contains("FR-001"), "{text}");
        assert!(text.contains("AS-002"), "{text}");
        assert!(text.contains("Acceptance criteria:"), "{text}");
    }

    #[test]
    fn the_owned_files_of_the_plan_are_listed_once() {
        let plan = read(EXAMPLE.as_bytes()).expect("a plan");
        let all = all_owned_files(&plan);
        let mut unique = all.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(all.len(), unique.len());
        assert!(all.contains(&"src/main.rs".to_owned()));
    }
}
