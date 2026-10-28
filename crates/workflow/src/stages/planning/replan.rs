//! Partial replanning: which tasks of a plan that was sent back can be kept.
//!
//! The engine sends a plan whose check failed to a new run of the planning stage. That run does not
//! have to start from nothing. The stage validates the earlier plan again, finds the tasks the
//! findings name, adds every task that depends on one of them (a change to a task can change what
//! its dependants need), and tells the planner that the others passed every check and should stay
//! as they are. The planner is asked, not forced: the new plan is validated whole, like any plan.

use std::collections::BTreeSet;

use factory_domain::contracts::TaskDag;

use crate::gates::dag::Finding;

/// The tasks of `plan` that none of the `findings` names and that depend on no task a finding
/// names, in the order the plan lists them.
#[must_use]
pub fn kept_tasks(plan: &TaskDag, findings: &[Finding]) -> Vec<String> {
    let ids: BTreeSet<&str> = plan
        .tasks
        .iter()
        .map(|task| task.task_id.as_str())
        .collect();
    let mut affected: BTreeSet<&str> = BTreeSet::new();
    for finding in findings {
        for part in finding.subject.split([',', '>', '|']) {
            if let Some(found) = ids.get(part.trim()) {
                affected.insert(found);
            }
        }
    }
    loop {
        let before = affected.len();
        for task in plan.tasks.iter() {
            if task
                .depends_on
                .iter()
                .any(|dependency| affected.contains(dependency.as_str()))
            {
                affected.insert(task.task_id.as_str());
            }
        }
        if affected.len() == before {
            break;
        }
    }
    plan.tasks
        .iter()
        .map(|task| task.task_id.as_str())
        .filter(|id| !affected.contains(id))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::dag::{Limits, SpecFacts, validate};
    use factory_domain::contracts::{Contract, SpecificationContract};
    use serde_json::json;

    const PLAN: &str =
        include_str!("../../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
    const SPEC: &str = include_str!(
        "../../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
    );

    fn plan_with(change: impl FnOnce(&mut serde_json::Value)) -> TaskDag {
        let mut value: serde_json::Value = serde_json::from_str(PLAN).expect("JSON");
        change(&mut value);
        TaskDag::from_json_value(value).expect("a plan")
    }

    fn findings(plan: &TaskDag) -> Vec<Finding> {
        let spec = SpecificationContract::from_json_str(SPEC).expect("spec");
        validate(plan, &SpecFacts::from_contract(&spec), &Limits::default()).findings
    }

    #[test]
    fn a_plan_with_no_finding_keeps_every_task() {
        let plan = plan_with(|_| {});
        assert_eq!(kept_tasks(&plan, &findings(&plan)).len(), 3);
    }

    #[test]
    fn a_task_a_finding_names_and_its_dependants_are_not_kept() {
        let plan = plan_with(|v| {
            v["tasks"][1]["depends_on"] = json!(["ghost"]);
        });
        let list = findings(&plan);
        assert!(!list.is_empty());
        // The dangling dependency names the second task; nothing depends on it.
        assert_eq!(
            kept_tasks(&plan, &list),
            ["add-json-output-formatter", "document-json-flag"]
        );
    }

    #[test]
    fn a_finding_about_the_first_task_takes_its_dependants_with_it() {
        let plan = plan_with(|v| {
            v["tasks"][0]["estimated_cost"]["tokens"] = json!(10_000_000);
        });
        let list = findings(&plan);
        assert!(
            list.iter()
                .any(|f| f.subject == "add-json-output-formatter")
        );
        assert!(kept_tasks(&plan, &list).is_empty());
    }

    #[test]
    fn a_finding_about_the_whole_plan_keeps_what_exists() {
        let plan = plan_with(|_| {});
        let spec = SpecificationContract::from_json_str(SPEC).expect("spec");
        let small = Limits {
            max_tasks: 2,
            ..Limits::default()
        };
        let list = validate(&plan, &SpecFacts::from_contract(&spec), &small).findings;
        assert!(list.iter().any(|f| f.subject == "plan"));
        assert_eq!(kept_tasks(&plan, &list).len(), 3);
    }
}
