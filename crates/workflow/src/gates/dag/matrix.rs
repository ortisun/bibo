//! The traceability matrix: from each requirement forward to the design, the tasks, the tests and
//! the documentation, and from each task and each design element back to the requirements.
//!
//! The matrix is built from the frozen specification, the approved design and the validated plan,
//! and from nothing an agent wrote about itself. It is stored as an artifact so a reviewer can
//! follow any requirement to the work that serves it and any task to the requirement that asked
//! for it. A gap is recorded with its kind and a severity; only the gaps marked `blocker` stop a
//! plan, and the DAG validator reports those on its own.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::TaskDag;
use factory_domain::contracts::task_dag::{RequiredEvidence, Task, TaskKind};
use serde_json::{Value, json};

use super::glob;

/// One design element, as the matrix needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesignLink {
    /// The element identifier.
    pub element_id: String,
    /// The requirements the element says it satisfies.
    pub satisfies: Vec<String>,
    /// The files the element says it touches.
    pub touches: Vec<String>,
}

/// What the matrix is built from.
#[derive(Debug, Clone, Copy)]
pub struct MatrixInput<'a> {
    /// Every requirement identifier of the specification: functional, non-functional and success
    /// criteria.
    pub requirements: &'a BTreeSet<String>,
    /// The acceptance scenarios, each with the requirements it shows.
    pub scenarios: &'a BTreeMap<String, BTreeSet<String>>,
    /// The design elements.
    pub design: &'a [DesignLink],
    /// The plan.
    pub plan: &'a TaskDag,
}

/// How serious a gap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The plan cannot go on.
    Blocker,
    /// Worth a person's attention. The plan can go on.
    Note,
}

impl Severity {
    const fn name(self) -> &'static str {
        match self {
            Self::Blocker => "blocker",
            Self::Note => "note",
        }
    }
}

/// A link that is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// What is missing, as a slug: `requirement-without-task`, and so on.
    pub kind: &'static str,
    /// The requirement, task or element it is about.
    pub subject: String,
    /// How serious.
    pub severity: Severity,
}

/// The matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix {
    rows: Vec<Row>,
    tasks: Vec<TaskRow>,
    elements: Vec<ElementRow>,
    gaps: Vec<Gap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    requirement: String,
    scenarios: BTreeSet<String>,
    design_elements: BTreeSet<String>,
    tasks: BTreeSet<String>,
    tests: BTreeSet<String>,
    documentation: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskRow {
    task: String,
    requirements: BTreeSet<String>,
    scenarios: BTreeSet<String>,
    design_elements: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElementRow {
    element: String,
    requirements: BTreeSet<String>,
    tasks: BTreeSet<String>,
}

fn is_test(task: &Task) -> bool {
    task.kind == TaskKind::Test
        || task.evidence_required.iter().any(|evidence| {
            matches!(
                evidence,
                RequiredEvidence::UnitTestResult
                    | RequiredEvidence::IntegrationTestResult
                    | RequiredEvidence::ContractTestResult
            )
        })
}

fn is_documentation(task: &Task) -> bool {
    task.kind == TaskKind::Documentation
        || task
            .evidence_required
            .contains(&RequiredEvidence::DocumentationCheck)
}

/// A task serves a design element when it cites a requirement the element satisfies, or when a
/// file the element touches is one the task owns.
fn serves(task: &Task, element: &DesignLink) -> bool {
    let cited = task
        .acceptance_mapping
        .requirement_ids
        .iter()
        .any(|id| element.satisfies.iter().any(|s| s == id.as_str()));
    cited
        || task.owned_files.as_ref().is_some_and(|owned| {
            element.touches.iter().any(|touched| {
                owned
                    .iter()
                    .any(|pattern| glob::matches(pattern.as_str(), touched))
            })
        })
}

impl Matrix {
    /// Builds the matrix.
    #[must_use]
    pub fn build(input: &MatrixInput<'_>) -> Self {
        let tasks = input.plan.tasks.as_slice();
        let mut gaps = Vec::new();

        let mut element_tasks: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        let mut task_elements: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for task in tasks {
            for element in input.design {
                if serves(task, element) {
                    element_tasks
                        .entry(element.element_id.as_str())
                        .or_default()
                        .insert(task.task_id.as_str().to_owned());
                    task_elements
                        .entry(task.task_id.as_str())
                        .or_default()
                        .insert(element.element_id.clone());
                }
            }
        }

        let mut rows = Vec::new();
        for requirement in input.requirements {
            let scenarios: BTreeSet<String> = input
                .scenarios
                .iter()
                .filter(|(_, shown)| shown.contains(requirement))
                .map(|(id, _)| id.clone())
                .collect();
            let design_elements: BTreeSet<String> = input
                .design
                .iter()
                .filter(|element| element.satisfies.contains(requirement))
                .map(|element| element.element_id.clone())
                .collect();
            let cites = |task: &Task, id: &str| {
                task.acceptance_mapping
                    .requirement_ids
                    .iter()
                    .any(|cited| cited.as_str() == id)
            };
            // A task serves a requirement when it cites it. Sharing a file with a design element
            // does not make a task answer the element's requirements.
            let mut serving: BTreeSet<String> = tasks
                .iter()
                .filter(|task| cites(task, requirement))
                .map(|task| task.task_id.as_str().to_owned())
                .collect();
            // A task cannot cite a non-functional requirement or a success criterion. Those are
            // followed through the design elements that satisfy them, to the functional
            // requirements the same elements satisfy, and from there to the tasks that cite them.
            if !requirement.starts_with("FR-") {
                for element in input
                    .design
                    .iter()
                    .filter(|element| element.satisfies.contains(requirement))
                {
                    for functional in element.satisfies.iter().filter(|id| id.starts_with("FR-")) {
                        serving.extend(
                            tasks
                                .iter()
                                .filter(|task| cites(task, functional))
                                .map(|task| task.task_id.as_str().to_owned()),
                        );
                    }
                }
            }
            let named = |wanted: fn(&Task) -> bool| -> BTreeSet<String> {
                tasks
                    .iter()
                    .filter(|task| serving.contains(task.task_id.as_str()) && wanted(task))
                    .map(|task| task.task_id.as_str().to_owned())
                    .collect()
            };
            let row = Row {
                requirement: requirement.clone(),
                scenarios,
                design_elements,
                tests: named(is_test),
                documentation: named(is_documentation),
                tasks: serving.clone(),
            };
            if row.design_elements.is_empty() {
                gaps.push(Gap {
                    kind: "requirement-without-design",
                    subject: requirement.clone(),
                    severity: Severity::Blocker,
                });
            }
            if row.tasks.is_empty() {
                gaps.push(Gap {
                    kind: "requirement-without-task",
                    subject: requirement.clone(),
                    severity: Severity::Blocker,
                });
            } else {
                if row.tests.is_empty() {
                    gaps.push(Gap {
                        kind: "requirement-without-test",
                        subject: requirement.clone(),
                        severity: Severity::Note,
                    });
                }
                if row.documentation.is_empty() {
                    gaps.push(Gap {
                        kind: "requirement-without-documentation",
                        subject: requirement.clone(),
                        severity: Severity::Note,
                    });
                }
            }
            rows.push(row);
        }

        let task_rows: Vec<TaskRow> = tasks
            .iter()
            .map(|task| {
                let id = task.task_id.as_str();
                let row = TaskRow {
                    task: id.to_owned(),
                    requirements: task
                        .acceptance_mapping
                        .requirement_ids
                        .iter()
                        .map(|r| r.as_str().to_owned())
                        .collect(),
                    scenarios: task
                        .acceptance_mapping
                        .acceptance_scenario_ids
                        .iter()
                        .map(|s| s.as_str().to_owned())
                        .collect(),
                    design_elements: task_elements.get(id).cloned().unwrap_or_default(),
                };
                if !input.design.is_empty() && row.design_elements.is_empty() {
                    gaps.push(Gap {
                        kind: "task-without-design",
                        subject: id.to_owned(),
                        severity: Severity::Note,
                    });
                }
                row
            })
            .collect();

        let element_rows: Vec<ElementRow> = input
            .design
            .iter()
            .map(|element| {
                let row = ElementRow {
                    element: element.element_id.clone(),
                    requirements: element.satisfies.iter().cloned().collect(),
                    tasks: element_tasks
                        .get(element.element_id.as_str())
                        .cloned()
                        .unwrap_or_default(),
                };
                if row.tasks.is_empty() {
                    gaps.push(Gap {
                        kind: "design-element-without-task",
                        subject: element.element_id.clone(),
                        severity: Severity::Note,
                    });
                }
                row
            })
            .collect();

        Self {
            rows,
            tasks: task_rows,
            elements: element_rows,
            gaps,
        }
    }

    /// The gaps, in the order they were found.
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// True when a gap stops the plan.
    #[must_use]
    pub fn has_blocker(&self) -> bool {
        self.gaps
            .iter()
            .any(|gap| gap.severity == Severity::Blocker)
    }

    /// The tasks that serve a requirement.
    #[must_use]
    pub fn tasks_of(&self, requirement: &str) -> Vec<&str> {
        self.rows
            .iter()
            .find(|row| row.requirement == requirement)
            .map(|row| row.tasks.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The requirements a task serves, read backwards from the task.
    #[must_use]
    pub fn requirements_of(&self, task: &str) -> Vec<&str> {
        self.tasks
            .iter()
            .find(|row| row.task == task)
            .map(|row| row.requirements.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The matrix as the document that is stored.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let list = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>();
        json!({
            "kind": "plan-traceability",
            "schema_version": 1,
            "requirements": self.rows.iter().map(|row| json!({
                "requirement": row.requirement,
                "acceptance_scenarios": list(&row.scenarios),
                "design_elements": list(&row.design_elements),
                "tasks": list(&row.tasks),
                "tests": list(&row.tests),
                "documentation": list(&row.documentation),
            })).collect::<Vec<_>>(),
            "tasks": self.tasks.iter().map(|row| json!({
                "task": row.task,
                "requirements": list(&row.requirements),
                "acceptance_scenarios": list(&row.scenarios),
                "design_elements": list(&row.design_elements),
            })).collect::<Vec<_>>(),
            "design_elements": self.elements.iter().map(|row| json!({
                "element": row.element,
                "requirements": list(&row.requirements),
                "tasks": list(&row.tasks),
            })).collect::<Vec<_>>(),
            "gaps": self.gaps.iter().map(|gap| json!({
                "kind": gap.kind,
                "subject": gap.subject,
                "severity": gap.severity.name(),
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::{Contract, SpecificationContract};

    const PLAN: &str =
        include_str!("../../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
    const SPEC: &str = include_str!(
        "../../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
    );

    fn build(design: &[DesignLink]) -> Matrix {
        let spec = SpecificationContract::from_json_str(SPEC).expect("spec");
        let plan = TaskDag::from_json_str(PLAN).expect("plan");
        let requirements: BTreeSet<String> = spec
            .requirements
            .iter()
            .map(|r| r.id.as_str().to_owned())
            .chain(
                spec.nonfunctional_requirements
                    .iter()
                    .map(|n| n.id.as_str().to_owned()),
            )
            .collect();
        let scenarios = super::super::validate::SpecFacts::from_contract(&spec).scenarios;
        Matrix::build(&MatrixInput {
            requirements: &requirements,
            scenarios: &scenarios,
            design,
            plan: &plan,
        })
    }

    fn link(id: &str, satisfies: &[&str], touches: &[&str]) -> DesignLink {
        DesignLink {
            element_id: id.to_owned(),
            satisfies: satisfies.iter().map(|s| (*s).to_owned()).collect(),
            touches: touches.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn a_requirement_is_followed_forward_to_its_tasks_tests_and_documentation() {
        let matrix = build(&[
            link("json-formatter", &["FR-001", "FR-002"], &["src/output.rs"]),
            link("errors", &["FR-003", "SC-001"], &["tests/errors.rs"]),
        ]);
        assert_eq!(
            matrix.tasks_of("FR-001"),
            ["add-json-output-formatter", "document-json-flag"]
        );
        let document = matrix.to_json();
        let row = &document["requirements"][0];
        assert_eq!(row["requirement"], "FR-001");
        assert_eq!(row["documentation"], json!(["document-json-flag"]));
        assert_eq!(row["tests"], json!(["add-json-output-formatter"]));
    }

    #[test]
    fn a_task_is_followed_backward_to_its_requirements_and_design_elements() {
        let matrix = build(&[link("json-formatter", &["FR-001"], &["src/output.rs"])]);
        assert_eq!(
            matrix.requirements_of("add-json-output-formatter"),
            ["FR-001", "FR-002"]
        );
        let document = matrix.to_json();
        assert_eq!(
            document["tasks"][0]["design_elements"],
            json!(["json-formatter"])
        );
        assert_eq!(
            document["design_elements"][0]["tasks"],
            json!(["add-json-output-formatter", "document-json-flag"])
        );
    }

    #[test]
    fn a_requirement_with_no_design_element_is_a_blocking_gap() {
        let matrix = build(&[link("json-formatter", &["FR-001", "FR-002"], &[])]);
        assert!(matrix.has_blocker());
        assert!(
            matrix
                .gaps()
                .iter()
                .any(|gap| { gap.kind == "requirement-without-design" && gap.subject == "FR-003" })
        );
    }

    #[test]
    fn a_requirement_with_a_design_and_no_documentation_is_only_a_note() {
        let matrix = build(&[
            link("json-formatter", &["FR-001", "FR-002"], &[]),
            link("errors", &["FR-003", "SC-001"], &[]),
        ]);
        assert!(
            !matrix.has_blocker() || matrix.gaps().iter().all(|g| g.subject != "FR-003"),
            "{:?}",
            matrix.gaps()
        );
        assert!(matrix.gaps().iter().any(|gap| {
            gap.kind == "requirement-without-documentation" && gap.subject == "FR-003"
        }));
    }
}
