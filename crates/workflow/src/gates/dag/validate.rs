//! The deterministic checks of a task plan.
//!
//! The schema and the typed `TaskDag` check the shape of each task. The checks here are the ones a
//! shape cannot hold: unique identifiers, no dangling dependency, no cycle, every acceptance
//! scenario and requirement of the frozen specification covered, no task that serves nothing, no
//! two tasks that could run together and write the same file, and a plan of a size a person can
//! review. Each finding is a plain-English sentence and a stable check identifier, so the planner
//! can be told what to fix and the engine can tell a repeated failure from a new one.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::SpecificationContract;
use factory_domain::contracts::TaskDag;
use factory_domain::contracts::task_dag::Task;
use factory_domain::values::Sha256Digest;

use super::glob;
use super::graph::{CriticalPath, Graph, Node, ShapeProblem};

/// How large a plan and a task may be. The numbers come from the policy of the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most tasks in one plan.
    pub max_tasks: usize,
    /// The most tasks per requirement of the specification. A plan with more tasks than this
    /// allows has been cut into pieces that no requirement asked for.
    pub max_tasks_per_requirement: usize,
    /// The most file patterns one task may own.
    pub max_files_per_task: usize,
    /// The most model tokens one task may be estimated to need.
    pub max_task_tokens: u64,
    /// The most seconds one task may be estimated to take.
    pub max_task_seconds: u64,
    /// The specialist roles a task may ask for. The implementation stage runs one agent, the
    /// builder, so a deployment that runs only that agent lists it here. An empty list allows any
    /// role, because the schema leaves roles open and its own example uses several.
    pub allowed_roles: &'static [&'static str],
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tasks: 30,
            max_tasks_per_requirement: 4,
            max_files_per_task: 25,
            max_task_tokens: 400_000,
            max_task_seconds: 3_600,
            allowed_roles: &[],
        }
    }
}

/// What the plan must cover: the requirements and acceptance scenarios of the frozen
/// specification, and which requirements each scenario shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpecFacts {
    /// The functional requirements (`FR-001`).
    pub requirements: BTreeSet<String>,
    /// The acceptance scenarios (`AS-001`), each with the requirements it covers.
    pub scenarios: BTreeMap<String, BTreeSet<String>>,
}

impl SpecFacts {
    /// Reads the facts from the typed specification.
    #[must_use]
    pub fn from_contract(spec: &SpecificationContract) -> Self {
        Self {
            requirements: spec
                .requirements
                .iter()
                .map(|requirement| requirement.id.as_str().to_owned())
                .collect(),
            scenarios: spec
                .acceptance_scenarios
                .iter()
                .map(|scenario| {
                    (
                        scenario.id.as_str().to_owned(),
                        scenario
                            .requirement_ids
                            .iter()
                            .map(|id| id.as_str().to_owned())
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

/// Which rule a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Check {
    /// Two tasks share an identifier.
    DuplicateTask,
    /// A task depends on itself.
    SelfDependency,
    /// A task depends on a task the plan does not hold.
    DanglingDependency,
    /// The dependencies form a cycle.
    Cycle,
    /// An acceptance scenario of the specification has no task.
    UncoveredScenario,
    /// A requirement of the specification has no task.
    UncoveredRequirement,
    /// A task names a scenario the specification does not hold.
    UnknownScenario,
    /// A task names a requirement the specification does not hold.
    UnknownRequirement,
    /// A task cites a scenario that none of the requirements it cites is shown by.
    ScenarioWithoutItsRequirement,
    /// A task serves nothing the specification asked for.
    OrphanTask,
    /// Two tasks that nothing orders may write the same file.
    ParallelFileConflict,
    /// Two tasks that nothing orders own the same interface.
    ParallelInterfaceConflict,
    /// The plan has more tasks than the limit.
    TooManyTasks,
    /// The plan has more tasks than its requirements justify.
    OverDecomposed,
    /// A task owns more file patterns than the limit.
    TaskOwnsTooMuch,
    /// A task is estimated at more tokens or time than the limit.
    TaskTooCostly,
    /// A task expects to change a path that none of its owned patterns covers.
    ChangeOutsideOwnedFiles,
    /// The critical path the plan declares names a task the plan does not hold.
    CriticalPathUnknownTask,
    /// A part of the task template is blank.
    MissingTemplatePart,
    /// A task owns a path that policy protects.
    ProtectedPath,
    /// A task asks for a specialist role that the factory does not run.
    SpecialistNotAvailable,
}

impl Check {
    /// The stable name, in the form of a slug.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DuplicateTask => "duplicate-task",
            Self::SelfDependency => "self-dependency",
            Self::DanglingDependency => "dangling-dependency",
            Self::Cycle => "dependency-cycle",
            Self::UncoveredScenario => "uncovered-scenario",
            Self::UncoveredRequirement => "uncovered-requirement",
            Self::UnknownScenario => "unknown-scenario",
            Self::UnknownRequirement => "unknown-requirement",
            Self::ScenarioWithoutItsRequirement => "scenario-without-its-requirement",
            Self::OrphanTask => "orphan-task",
            Self::ParallelFileConflict => "parallel-file-conflict",
            Self::ParallelInterfaceConflict => "parallel-interface-conflict",
            Self::TooManyTasks => "too-many-tasks",
            Self::OverDecomposed => "over-decomposed",
            Self::TaskOwnsTooMuch => "task-owns-too-much",
            Self::TaskTooCostly => "task-too-costly",
            Self::ChangeOutsideOwnedFiles => "change-outside-owned-files",
            Self::CriticalPathUnknownTask => "critical-path-unknown-task",
            Self::MissingTemplatePart => "missing-template-part",
            Self::ProtectedPath => "protected-path-owned",
            Self::SpecialistNotAvailable => "specialist-not-available",
        }
    }
}

/// One thing wrong with a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule.
    pub check: Check,
    /// What the finding is about: a task identifier, a scenario identifier or a pair of tasks.
    pub subject: String,
    /// What is wrong and what to do about it, in plain English.
    pub message: String,
}

impl Finding {
    fn new(check: Check, subject: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check,
            subject: subject.into(),
            message: message.into(),
        }
    }

    /// The identifier a gate report gives the failed check: the rule, and a short hash of the
    /// subject, so the same problem in the same place has the same identifier in every round.
    #[must_use]
    pub fn check_id(&self) -> String {
        let digest = Sha256Digest::of(self.subject.as_bytes());
        format!(
            "{}.{}",
            self.check.name(),
            digest.hex().get(..8).unwrap_or("00000000")
        )
    }
}

/// What the validator learned about a plan whose graph is sound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// The order the tasks run in.
    pub order: Vec<String>,
    /// The longest chain, computed here whatever the plan declares.
    pub critical_path: CriticalPath,
    /// The chain the plan declares, when it declares one.
    pub declared_critical_path: Option<Vec<String>>,
    /// The pairs of tasks that nothing orders. Each was shown to be independent, or it is a
    /// finding.
    pub parallel_pairs: Vec<(String, String)>,
}

/// The result of validating one plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Everything wrong, in a fixed order.
    pub findings: Vec<Finding>,
    /// Present when the dependency graph is sound.
    pub analysis: Option<Analysis>,
}

impl Report {
    /// True when nothing is wrong.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

fn texts(list: Option<&[factory_domain::values::NonEmptyString]>) -> Vec<&str> {
    list.map(|items| items.iter().map(|item| item.as_str()).collect())
        .unwrap_or_default()
}

fn owned_files(task: &Task) -> Vec<&str> {
    texts(task.owned_files.as_ref().map(|files| files.as_slice()))
}

fn owned_interfaces(task: &Task) -> Vec<&str> {
    task.owned_interfaces
        .as_ref()
        .map(|items| items.iter().map(|item| item.as_str()).collect())
        .unwrap_or_default()
}

/// Validates a plan against the frozen specification and the limits.
#[must_use]
pub fn validate(plan: &TaskDag, spec: &SpecFacts, limits: &Limits) -> Report {
    let tasks = plan.tasks.as_slice();
    let mut findings = Vec::new();

    let nodes: Vec<Node> = tasks
        .iter()
        .map(|task| Node {
            id: task.task_id.as_str().to_owned(),
            depends_on: task
                .depends_on
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            seconds: u64::try_from(task.estimated_cost.wall_time_seconds.get()).unwrap_or(0),
        })
        .collect();
    let graph = match Graph::build(&nodes) {
        Ok(graph) => Some(graph),
        Err(problems) => {
            for problem in problems {
                findings.push(shape_finding(problem));
            }
            None
        }
    };

    sizes(tasks, spec, limits, &mut findings);
    specialists(tasks, limits, &mut findings);
    parts(tasks, &mut findings);
    coverage(tasks, spec, &mut findings);
    changes(tasks, &mut findings);

    let analysis = graph.map(|graph| {
        ownership(tasks, &graph, &mut findings);
        let declared: Option<Vec<String>> = plan
            .critical_path
            .as_ref()
            .map(|path| path.iter().map(|id| id.as_str().to_owned()).collect());
        if let Some(declared) = &declared {
            for id in declared {
                if !nodes.iter().any(|node| &node.id == id) {
                    findings.push(Finding::new(
                        Check::CriticalPathUnknownTask,
                        id.clone(),
                        format!(
                            "The critical path names the task {id}, which the plan does not hold. Remove it or add the task."
                        ),
                    ));
                }
            }
        }
        Analysis {
            order: graph.order().into_iter().map(str::to_owned).collect(),
            critical_path: graph.critical_path(),
            declared_critical_path: declared,
            parallel_pairs: graph
                .unordered_pairs()
                .into_iter()
                .map(|(a, b)| (graph.id(a).to_owned(), graph.id(b).to_owned()))
                .collect(),
        }
    });
    Report { findings, analysis }
}

fn specialists(tasks: &[Task], limits: &Limits, findings: &mut Vec<Finding>) {
    for task in tasks {
        let role = task.required_specialist.role.as_str();
        if !limits.allowed_roles.is_empty() && !limits.allowed_roles.contains(&role) {
            let id = task.task_id.as_str();
            findings.push(Finding::new(
                Check::SpecialistNotAvailable,
                id,
                format!(
                    "The task {id} asks for the specialist role {role}, and the factory runs only: {}. Ask for one of those.",
                    limits.allowed_roles.join(", ")
                ),
            ));
        }
    }
}

/// A path that stands for the files a pattern names: the wildcards become a plain letter, so that
/// the path policy can be asked about it.
fn representative(pattern: &str) -> String {
    pattern
        .trim_start_matches("./")
        .split('/')
        .map(|segment| segment.replace(['*', '?'], "x"))
        .collect::<Vec<_>>()
        .join("/")
}

/// The tasks that own a path the policy protects. `refuses` is the policy's answer for one path.
/// The check is made on a path that stands for each pattern, so `.github/**` is asked about as a
/// file below `.github`.
#[must_use]
pub fn protected(plan: &TaskDag, refuses: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    for task in plan.tasks.iter() {
        let id = task.task_id.as_str();
        for pattern in owned_files(task) {
            if refuses(&representative(pattern)) {
                findings.push(Finding::new(
                    Check::ProtectedPath,
                    format!("{id}>{pattern}"),
                    format!(
                        "The task {id} owns {pattern}, which policy protects. A plan cannot give a builder a protected path."
                    ),
                ));
            }
        }
    }
    findings
}

fn shape_finding(problem: ShapeProblem) -> Finding {
    match problem {
        ShapeProblem::Duplicate(id) => Finding::new(
            Check::DuplicateTask,
            id.clone(),
            format!("Two tasks share the identifier {id}. Give each task its own identifier."),
        ),
        ShapeProblem::SelfDependency(id) => Finding::new(
            Check::SelfDependency,
            id.clone(),
            format!("The task {id} depends on itself, so it could never start."),
        ),
        ShapeProblem::Dangling { task, missing } => Finding::new(
            Check::DanglingDependency,
            format!("{task}>{missing}"),
            format!(
                "The task {task} depends on {missing}, which the plan does not hold. Add that task or remove the dependency."
            ),
        ),
        ShapeProblem::Cycle(tasks) => Finding::new(
            Check::Cycle,
            tasks.join(","),
            format!(
                "The dependencies form a cycle, so no order exists. The tasks that cannot be placed are: {}.",
                tasks.join(", ")
            ),
        ),
    }
}

fn sizes(tasks: &[Task], spec: &SpecFacts, limits: &Limits, findings: &mut Vec<Finding>) {
    if tasks.len() > limits.max_tasks {
        findings.push(Finding::new(
            Check::TooManyTasks,
            "plan",
            format!(
                "The plan has {} tasks, and a plan may have at most {}. Merge tasks that belong together or split the work into two plans.",
                tasks.len(),
                limits.max_tasks
            ),
        ));
    }
    let allowed = spec
        .requirements
        .len()
        .max(1)
        .saturating_mul(limits.max_tasks_per_requirement);
    if tasks.len() > allowed {
        findings.push(Finding::new(
            Check::OverDecomposed,
            "plan",
            format!(
                "The plan has {} tasks for {} requirements, and the limit is {} tasks per requirement. Join tasks that no requirement tells apart.",
                tasks.len(),
                spec.requirements.len(),
                limits.max_tasks_per_requirement
            ),
        ));
    }
    for task in tasks {
        let id = task.task_id.as_str();
        let files = owned_files(task).len();
        if files > limits.max_files_per_task {
            findings.push(Finding::new(
                Check::TaskOwnsTooMuch,
                id,
                format!(
                    "The task {id} owns {files} file patterns, and the limit is {}. Split it so that a reviewer can read each part.",
                    limits.max_files_per_task
                ),
            ));
        }
        let tokens = u64::try_from(task.estimated_cost.tokens.get()).unwrap_or(u64::MAX);
        let seconds =
            u64::try_from(task.estimated_cost.wall_time_seconds.get()).unwrap_or(u64::MAX);
        if tokens > limits.max_task_tokens || seconds > limits.max_task_seconds {
            findings.push(Finding::new(
                Check::TaskTooCostly,
                id,
                format!(
                    "The task {id} is estimated at {tokens} tokens and {seconds} seconds, and the limits are {} tokens and {} seconds. Split it into smaller tasks.",
                    limits.max_task_tokens, limits.max_task_seconds
                ),
            ));
        }
    }
}

/// The four parts of the task template are present. The typed plan already refuses an empty one;
/// this stays as the second check, because a plan that was edited in code is not read again.
fn parts(tasks: &[Task], findings: &mut Vec<Finding>) {
    for task in tasks {
        let id = task.task_id.as_str();
        let blank = |text: &str| text.trim().is_empty();
        let missing: Vec<&str> = [
            ("why this matters", blank(task.why_this_matters.as_str())),
            (
                "what needs to change",
                blank(task.what_needs_to_change.as_str()),
            ),
            (
                "acceptance criteria",
                task.acceptance_criteria.iter().all(|c| blank(c.as_str())),
            ),
            (
                "verification",
                task.verification.iter().all(|v| blank(v.as_str())),
            ),
        ]
        .into_iter()
        .filter_map(|(name, absent)| absent.then_some(name))
        .collect();
        if !missing.is_empty() {
            findings.push(Finding::new(
                Check::MissingTemplatePart,
                id,
                format!(
                    "The task {id} leaves out part of the task template: {}.",
                    missing.join(", ")
                ),
            ));
        }
    }
}

fn coverage(tasks: &[Task], spec: &SpecFacts, findings: &mut Vec<Finding>) {
    let mut scenarios_covered: BTreeSet<&str> = BTreeSet::new();
    let mut requirements_covered: BTreeSet<&str> = BTreeSet::new();
    for task in tasks {
        let id = task.task_id.as_str();
        let mapping = &task.acceptance_mapping;
        let mut valid_scenarios = 0_usize;
        let cited_requirements: BTreeSet<&str> = mapping
            .requirement_ids
            .iter()
            .map(|requirement| requirement.as_str())
            .collect();
        for scenario in mapping.acceptance_scenario_ids.iter() {
            let name = scenario.as_str();
            match spec.scenarios.get(name) {
                None => findings.push(Finding::new(
                    Check::UnknownScenario,
                    format!("{id}>{name}"),
                    format!(
                        "The task {id} cites the acceptance scenario {name}, which the specification does not hold."
                    ),
                )),
                Some(shown) => {
                    valid_scenarios += 1;
                    scenarios_covered.insert(name);
                    let consistent = shown
                        .iter()
                        .any(|requirement| cited_requirements.contains(requirement.as_str()));
                    if !consistent {
                        findings.push(Finding::new(
                            Check::ScenarioWithoutItsRequirement,
                            format!("{id}>{name}"),
                            format!(
                                "The task {id} cites the scenario {name} but none of the requirements that scenario shows. Cite the requirement as well."
                            ),
                        ));
                    }
                }
            }
        }
        for requirement in &cited_requirements {
            if spec.requirements.contains(*requirement) {
                requirements_covered.insert(requirement);
            } else {
                findings.push(Finding::new(
                    Check::UnknownRequirement,
                    format!("{id}>{requirement}"),
                    format!(
                        "The task {id} cites the requirement {requirement}, which the specification does not hold."
                    ),
                ));
            }
        }
        let serves_a_requirement = cited_requirements
            .iter()
            .any(|requirement| spec.requirements.contains(*requirement));
        if valid_scenarios == 0 && !serves_a_requirement {
            findings.push(Finding::new(
                Check::OrphanTask,
                id,
                format!(
                    "The task {id} serves no acceptance scenario and no requirement of the specification. Remove it or tie it to what the specification asks for."
                ),
            ));
        }
    }
    for scenario in spec.scenarios.keys() {
        if !scenarios_covered.contains(scenario.as_str()) {
            findings.push(Finding::new(
                Check::UncoveredScenario,
                scenario.clone(),
                format!(
                    "No task covers the acceptance scenario {scenario}. Every scenario of the specification needs a task."
                ),
            ));
        }
    }
    for requirement in &spec.requirements {
        if !requirements_covered.contains(requirement.as_str()) {
            findings.push(Finding::new(
                Check::UncoveredRequirement,
                requirement.clone(),
                format!(
                    "No task covers the requirement {requirement}. Every requirement of the specification needs a task."
                ),
            ));
        }
    }
}

fn changes(tasks: &[Task], findings: &mut Vec<Finding>) {
    for task in tasks {
        let owned = owned_files(task);
        if owned.is_empty() {
            continue;
        }
        let id = task.task_id.as_str();
        for change in task.expected_changes.iter() {
            let wanted = change.path_glob.as_str();
            // An owned pattern covers the change when it is the same text or matches it. A change
            // that is itself a pattern is matched as written, which errs towards covered.
            let covered = owned
                .iter()
                .any(|pattern| *pattern == wanted || glob::matches(pattern, wanted));
            if !covered {
                findings.push(Finding::new(
                    Check::ChangeOutsideOwnedFiles,
                    format!("{id}>{wanted}"),
                    format!(
                        "The task {id} expects to change {wanted}, which none of the files it owns covers. The scope check would refuse the change."
                    ),
                ));
            }
        }
    }
}

/// Two tasks that nothing orders could run at the same time, so they must be shown independent:
/// no file they may write in common, and no interface they both own.
fn ownership(tasks: &[Task], graph: &Graph, findings: &mut Vec<Finding>) {
    for (a, b) in graph.unordered_pairs() {
        let (Some(first), Some(second)) = (tasks.get(a), tasks.get(b)) else {
            continue;
        };
        let pair = format!("{}|{}", first.task_id.as_str(), second.task_id.as_str());
        let mut shared_file: Option<(String, String)> = None;
        'search: for left in owned_files(first) {
            for right in owned_files(second) {
                if glob::may_overlap(left, right) {
                    shared_file = Some((left.to_owned(), right.to_owned()));
                    break 'search;
                }
            }
        }
        if let Some((left, right)) = shared_file {
            let detail = if left == right {
                format!("both own {left}")
            } else {
                format!("one owns {left} and the other owns {right}")
            };
            findings.push(Finding::new(
                Check::ParallelFileConflict,
                pair.clone(),
                format!(
                    "The tasks {} and {} could run at the same time and {detail}. Make one depend on the other, or give them files that do not overlap.",
                    first.task_id.as_str(),
                    second.task_id.as_str()
                ),
            ));
        }
        let interfaces_a = owned_interfaces(first);
        if let Some(shared) = owned_interfaces(second)
            .into_iter()
            .find(|name| interfaces_a.contains(name))
        {
            findings.push(Finding::new(
                Check::ParallelInterfaceConflict,
                pair,
                format!(
                    "The tasks {} and {} could run at the same time and both own the interface {shared}. Make one depend on the other.",
                    first.task_id.as_str(),
                    second.task_id.as_str()
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::Contract;
    use serde_json::{Value, json};

    const PLAN: &str =
        include_str!("../../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
    const SPEC: &str = include_str!(
        "../../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
    );

    fn spec() -> SpecFacts {
        let spec = SpecificationContract::from_json_str(SPEC).expect("the example spec is valid");
        SpecFacts::from_contract(&spec)
    }

    fn plan(change: impl FnOnce(&mut Value)) -> TaskDag {
        let mut value: Value = serde_json::from_str(PLAN).expect("JSON");
        change(&mut value);
        TaskDag::from_json_value(value).expect("still a valid plan by shape")
    }

    fn checks(report: &Report) -> Vec<Check> {
        report
            .findings
            .iter()
            .map(|finding| finding.check)
            .collect()
    }

    #[test]
    fn the_valid_example_plan_has_no_finding() {
        let report = validate(&plan(|_| {}), &spec(), &Limits::default());
        assert!(report.is_clean(), "{:?}", report.findings);
        let analysis = report.analysis.expect("a sound graph is analysed");
        assert_eq!(analysis.order[0], "add-json-output-formatter");
        assert_eq!(analysis.critical_path.tasks.len(), 2);
    }

    #[test]
    fn a_cycle_is_a_finding_and_no_analysis_is_made() {
        let report = validate(
            &plan(|v| v["tasks"][0]["depends_on"] = json!(["document-json-flag"])),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&report).contains(&Check::Cycle));
        assert!(report.analysis.is_none());
    }

    #[test]
    fn a_dangling_dependency_a_duplicate_id_and_a_self_loop_are_findings() {
        let dangling = validate(
            &plan(|v| v["tasks"][1]["depends_on"] = json!(["ghost"])),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&dangling).contains(&Check::DanglingDependency));
        let duplicate = validate(
            &plan(|v| v["tasks"][2]["task_id"] = json!("cover-unreadable-file-error")),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&duplicate).contains(&Check::DuplicateTask));
        let own = validate(
            &plan(|v| v["tasks"][1]["depends_on"] = json!(["cover-unreadable-file-error"])),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&own).contains(&Check::SelfDependency));
    }

    #[test]
    fn an_acceptance_scenario_no_task_covers_is_a_finding() {
        let report = validate(
            &plan(|v| {
                v["tasks"][1]["acceptance_mapping"]["acceptance_scenario_ids"] = json!(["AS-003"])
            }),
            &spec(),
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
    fn a_requirement_no_task_covers_is_a_finding() {
        let report = validate(
            &plan(|v| v["tasks"][1]["acceptance_mapping"]["requirement_ids"] = json!(["FR-001"])),
            &spec(),
            &Limits::default(),
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.check == Check::UncoveredRequirement && f.subject == "FR-003")
        );
    }

    #[test]
    fn a_task_that_serves_nothing_the_specification_holds_is_an_orphan() {
        let report = validate(
            &plan(|v| {
                v["tasks"][2]["acceptance_mapping"] = json!({
                    "acceptance_scenario_ids": ["AS-900"],
                    "requirement_ids": ["FR-900"]
                });
            }),
            &spec(),
            &Limits::default(),
        );
        let found = checks(&report);
        assert!(found.contains(&Check::OrphanTask));
        assert!(found.contains(&Check::UnknownScenario));
        assert!(found.contains(&Check::UnknownRequirement));
    }

    #[test]
    fn a_scenario_cited_without_any_requirement_it_shows_is_inconsistent() {
        let report = validate(
            &plan(|v| {
                v["tasks"][2]["acceptance_mapping"]["acceptance_scenario_ids"] =
                    json!(["AS-001", "AS-004"]);
            }),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&report).contains(&Check::ScenarioWithoutItsRequirement));
    }

    #[test]
    fn two_tasks_that_nothing_orders_and_that_own_the_same_file_conflict() {
        let report = validate(
            &plan(|v| {
                v["tasks"][2]["depends_on"] = json!([]);
                v["tasks"][2]["owned_files"] = json!(["tests/errors.rs", "README.md"]);
            }),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&report).contains(&Check::ParallelFileConflict));
    }

    #[test]
    fn the_same_file_is_fine_when_one_task_depends_on_the_other() {
        let report = validate(
            &plan(|v| {
                v["tasks"][1]["owned_files"] = json!(["tests/errors.rs", "README.md"]);
                v["tasks"][2]["depends_on"] =
                    json!(["add-json-output-formatter", "cover-unreadable-file-error"]);
            }),
            &spec(),
            &Limits::default(),
        );
        assert!(report.is_clean(), "{:?}", report.findings);
    }

    #[test]
    fn two_parallel_tasks_that_own_one_interface_conflict() {
        let report = validate(
            &plan(|v| {
                v["tasks"][1]["owned_interfaces"] = json!(["json-output"]);
                v["tasks"][2]["owned_interfaces"] = json!(["json-output"]);
            }),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&report).contains(&Check::ParallelInterfaceConflict));
    }

    #[test]
    fn plan_and_task_sizes_are_bounded() {
        let small = Limits {
            max_tasks: 2,
            max_tasks_per_requirement: 0,
            max_files_per_task: 1,
            max_task_tokens: 10,
            max_task_seconds: 10,
            allowed_roles: &["builder"],
        };
        let found = checks(&validate(&plan(|_| {}), &spec(), &small));
        for expected in [
            Check::TooManyTasks,
            Check::OverDecomposed,
            Check::TaskOwnsTooMuch,
            Check::TaskTooCostly,
        ] {
            assert!(found.contains(&expected), "{expected:?} in {found:?}");
        }
    }

    #[test]
    fn a_change_outside_the_owned_files_is_a_finding() {
        let report = validate(
            &plan(|v| {
                v["tasks"][1]["expected_changes"] =
                    json!([{ "path_glob": "src/lib.rs", "change": "modify" }]);
            }),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&report).contains(&Check::ChangeOutsideOwnedFiles));
    }

    #[test]
    fn a_declared_critical_path_is_recorded_and_only_unknown_tasks_in_it_are_findings() {
        let report = validate(&plan(|_| {}), &spec(), &Limits::default());
        let analysis = report.analysis.expect("analysis");
        assert_eq!(analysis.declared_critical_path.map(|p| p.len()), Some(3));
        let bad = validate(
            &plan(|v| v["critical_path"] = json!(["add-json-output-formatter", "ghost"])),
            &spec(),
            &Limits::default(),
        );
        assert!(checks(&bad).contains(&Check::CriticalPathUnknownTask));
    }

    #[test]
    fn a_role_the_factory_does_not_run_and_a_protected_path_are_findings() {
        let builders_only = Limits {
            allowed_roles: &["builder"],
            ..Limits::default()
        };
        let report = validate(&plan(|_| {}), &spec(), &builders_only);
        assert!(checks(&report).contains(&Check::SpecialistNotAvailable));
        let report = validate(
            &plan(|v| {
                for task in v["tasks"].as_array_mut().expect("tasks") {
                    task["required_specialist"]["role"] = json!("builder");
                }
            }),
            &spec(),
            &builders_only,
        );
        assert!(report.is_clean(), "{:?}", report.findings);
        let owns = plan(|v| {
            v["tasks"][2]["owned_files"] = json!([".github/**"]);
            v["tasks"][2]["expected_changes"] =
                json!([{ "path_glob": ".github/workflows/ci.yml", "change": "modify" }]);
        });
        let found = protected(&owns, &|path| path.starts_with(".github/"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].check, Check::ProtectedPath);
        assert!(protected(&owns, &|_| false).is_empty());
    }

    #[test]
    fn the_check_id_is_stable_and_names_the_subject() {
        let one = Finding::new(Check::Cycle, "a,b", "x");
        let again = Finding::new(Check::Cycle, "a,b", "different words");
        let other = Finding::new(Check::Cycle, "c,d", "x");
        assert_eq!(one.check_id(), again.check_id());
        assert_ne!(one.check_id(), other.check_id());
        assert!(one.check_id().starts_with("dependency-cycle."));
    }
}
