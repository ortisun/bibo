//! `schemas/task-dag.schema.json`: the factory's own implementation plan.
//!
//! This type checks the shape of each task. The planner validator in the workflow crate checks
//! what a schema cannot: unique task ids, no cycles, no dangling dependencies, no overlapping
//! file ownership without an ordering edge, and coverage of every acceptance scenario.

use serde::{Deserialize, Serialize};

use super::common::{RequirementId, ScenarioId, SchemaVersion};
use super::{Violations, contract};
use crate::ids::{JobId, PlanId, SpecId};
use crate::macros::string_enum;
use crate::values::{
    HumanText, HumanTitle, NonEmptyString, NonEmptyVec, NonNegativeInt, NonNegativeNumber,
    PositiveInt, Sha256Digest, Slug, Timestamp, UniqueVec,
};
use crate::vocabulary::ExecutionMode;

/// Most tasks one plan may hold.
pub const MAX_TASKS: usize = 60;

string_enum! {
    /// What a task produces. Non-code deliverables are first-class tasks.
    pub enum TaskKind("task kind") {
        /// Source code.
        CodeChange = "code_change",
        /// Tests.
        Test = "test",
        /// Documentation.
        Documentation = "documentation",
        /// A schema.
        Schema = "schema",
        /// Data.
        Data = "data",
        /// Configuration.
        Configuration = "configuration",
        /// An experiment.
        Experiment = "experiment",
        /// A design asset.
        DesignAsset = "design_asset",
    }
}

string_enum! {
    /// How a path changes.
    pub enum ChangeKind("change kind") {
        /// A new path.
        Add = "add",
        /// An existing path changes.
        Modify = "modify",
        /// A path goes away.
        Delete = "delete",
    }
}

string_enum! {
    /// Which kind of model, if any, a task is routed to. Routine steps go to code or a small model.
    pub enum ModelTier("model tier") {
        /// Plain code, no model.
        DeterministicCode = "deterministic_code",
        /// A small model.
        Small = "small",
        /// A standard model.
        Standard = "standard",
        /// A large model, kept for hard or high-risk work.
        Large = "large",
    }
}

string_enum! {
    /// Evidence a task must leave behind.
    pub enum RequiredEvidence("required evidence") {
        /// A unit test result.
        UnitTestResult = "unit_test_result",
        /// An integration test result.
        IntegrationTestResult = "integration_test_result",
        /// A contract test result.
        ContractTestResult = "contract_test_result",
        /// A gate report.
        GateReport = "gate_report",
        /// A review verdict.
        ReviewVerdict = "review_verdict",
        /// The diff.
        Diff = "diff",
        /// A documentation check.
        DocumentationCheck = "documentation_check",
        /// A benchmark.
        Benchmark = "benchmark",
        /// An experiment record.
        ExperimentRecord = "experiment_record",
    }
}

/// The specification the plan implements.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecRef {
    /// The specification.
    pub spec_id: SpecId,
    /// Its version.
    pub spec_version: PositiveInt,
    /// Its content hash.
    pub sha256: Sha256Digest,
}

/// The architecture the plan follows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureRef {
    /// Its content hash.
    pub sha256: Sha256Digest,
}

/// Ids and references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanMetadata {
    /// This plan.
    pub plan_id: PlanId,
    /// Its version.
    pub plan_version: PositiveInt,
    /// The job.
    pub job_id: JobId,
    /// Production or test.
    pub execution_mode: ExecutionMode,
    /// The frozen specification.
    pub spec_ref: SpecRef,
    /// The approved architecture.
    pub architecture_ref: ArchitectureRef,
    /// When it was made.
    pub created_at: Timestamp,
}

/// A point at which the work is checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// The tasks that must be done first.
    pub after_task_ids: NonEmptyVec<Slug>,
    /// What is checked.
    pub check: HumanText,
}

/// Which scenarios and requirements a task serves.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceMapping {
    /// The scenarios.
    pub acceptance_scenario_ids: UniqueVec<ScenarioId, 1>,
    /// The requirements.
    pub requirement_ids: UniqueVec<RequirementId, 1>,
}

/// An artifact the task reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputArtifact {
    /// What it is for.
    pub role: NonEmptyString,
    /// Its content hash.
    pub sha256: Sha256Digest,
}

/// A path the task is expected to change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedChange {
    /// A path glob.
    pub path_glob: NonEmptyString,
    /// How it changes.
    pub change: ChangeKind,
}

/// The specialist the task needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredSpecialist {
    /// The role.
    pub role: Slug,
    /// The skills.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<UniqueVec<Slug>>,
}

/// How the task is routed to a model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPolicy {
    /// The tier.
    pub tier: ModelTier,
    /// Extra routing advice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_hint: Option<HumanText>,
}

/// What the task is expected to cost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstimatedCost {
    /// Model tokens.
    pub tokens: NonNegativeInt,
    /// US dollars.
    pub usd: NonNegativeNumber,
    /// Wall-clock seconds.
    pub wall_time_seconds: PositiveInt,
}

/// A risk and what reduces it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRisk {
    /// What could go wrong.
    pub description: HumanText,
    /// What reduces it.
    pub mitigation: HumanText,
}

/// One task of the plan. It reads like an instruction from a capable teammate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    /// The stable machine identifier. Never shown as the title.
    pub task_id: Slug,
    /// A plain-English title.
    pub title: HumanTitle,
    /// What kind of deliverable.
    pub kind: TaskKind,
    /// Why the task matters.
    pub why_this_matters: HumanText,
    /// What needs to change.
    pub what_needs_to_change: HumanText,
    /// What must be true when it is done.
    pub acceptance_criteria: NonEmptyVec<HumanText>,
    /// How a reviewer or a gate will confirm each criterion.
    pub verification: NonEmptyVec<HumanText>,
    /// The scenarios and requirements it serves.
    pub acceptance_mapping: AcceptanceMapping,
    /// Artifacts it reads.
    pub input_artifacts: Vec<InputArtifact>,
    /// Paths it is expected to change.
    pub expected_changes: NonEmptyVec<ExpectedChange>,
    /// Path globs it may write. The scope gate rejects any other changed path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned_files: Option<UniqueVec<NonEmptyString>>,
    /// Interfaces it owns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned_interfaces: Option<UniqueVec<Slug>>,
    /// Tasks that must finish first.
    pub depends_on: UniqueVec<Slug>,
    /// The specialist it needs.
    pub required_specialist: RequiredSpecialist,
    /// How it is routed to a model.
    pub model_policy: ModelPolicy,
    /// What it should cost.
    pub estimated_cost: EstimatedCost,
    /// Risks and mitigations.
    pub risks: Vec<TaskRisk>,
    /// Evidence it must leave behind.
    pub evidence_required: UniqueVec<RequiredEvidence, 1>,
}

contract! {
    "task-dag";
    /// A directed acyclic graph of tasks derived from a frozen specification and an approved
    /// architecture.
    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct TaskDag {
        /// Always 1.
        pub schema_version: SchemaVersion,
        /// Ids and references.
        pub metadata: PlanMetadata,
        /// The plan in a few words.
        pub title: HumanTitle,
        /// A short summary.
        pub summary: HumanText,
        /// Task ids on the longest dependency chain, in order.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub critical_path: Option<UniqueVec<Slug>>,
        /// Points at which the work is checked.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub checkpoints: Option<Vec<Checkpoint>>,
        /// How to roll the plan back.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rollback_note: Option<HumanText>,
        /// The tasks, at most [`MAX_TASKS`].
        pub tasks: NonEmptyVec<Task>,
    }
}

impl TaskDag {
    fn check(&self, found: &mut Violations) {
        found.require(
            self.tasks.len() <= MAX_TASKS,
            "tasks",
            format!("a plan has at most {MAX_TASKS} tasks; split larger work into several plans"),
        );
        for (index, task) in self.tasks.iter().enumerate() {
            let owns_files = task
                .owned_files
                .as_ref()
                .is_some_and(|files| !files.is_empty());
            let owns_interfaces = task
                .owned_interfaces
                .as_ref()
                .is_some_and(|interfaces| !interfaces.is_empty());
            found.require(
                owns_files || owns_interfaces,
                format!("tasks[{index}]"),
                "a task must own at least one file pattern or one interface, so the scope gate knows what it may change",
            );
        }
    }
}
