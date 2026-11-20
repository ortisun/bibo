//! When something that later work was built on changes, which later work becomes stale.
//!
//! A later stage consumes an artifact by its content hash. If that artifact changes, every run
//! that consumed the old one is out of date. Some changes do not come from a stage at all: a
//! person edits the request, or the base branch moves. The `invalidation_rules` of
//! `state-machine.json` list, for each change, the stages whose runs become `SUPERSEDED` (guard
//! `G_UPSTREAM_INVALIDATED`, transition `S20`). There are eight rows (ADR 0010 decision 4).
//!
//! | Change | Produced by | What goes stale |
//! |---|---|---|
//! | A new approved spec version (the requirements) | `SPECIFICATION` | domain discovery, architecture, the plan, the tasks, validation, both reviews, documentation, delivery and approval |
//! | A new architecture version | `ARCHITECTURE` | the plan, the tasks and everything after them |
//! | A new plan version | `TASK_PLANNING` | the tasks (`IMPLEMENTATION`) and everything after them |
//! | A new implementation commit | `IMPLEMENTATION` | validation, both reviews, documentation, delivery and approval |
//! | A new documentation commit | `DOCUMENTING` | the documentation review, delivery and approval |
//! | The source request is edited after the intake snapshot | no stage | **every** stage, the intake included |
//! | A new repository map | `REPOSITORY_INTELLIGENCE` | the specification and everything after it |
//! | A value bound to gate evidence changes | no stage | validation, the code review, the documentation review, delivery and approval, but not `DOCUMENTING` |
//!
//! The last row covers the base commit, the gate definition hash, the policy hash and the sandbox
//! image digest. The engine checks them at two points, before `DELIVERY` pushes and when an
//! approval is recorded, so a busy base branch does not restart a job on every move. A rebase
//! writes new commits, so it is a new implementation commit.
//!
//! Two rules keep this safe.
//!
//! * **Only live work is touched.** A run that is already terminal (failed, cancelled,
//!   superseded, or sent back for rework) is left alone. A `PASSED` run and a `SKIPPED` run are
//!   terminal but can still be superseded, which is the one exception the state table allows.
//!   A skip decision was made on recorded inputs, so when they change it must be made again. A
//!   superseded run can never become live again, so stale work only ever grows.
//! * **The producer is never stale.** A change does not supersede the stage that made it. A
//!   change that no stage makes has no producer to spare, so every listed run is superseded, the
//!   first one too.
//!
//! A human answer (`S13`) is not a change in this table. The stage run that waits for a person
//! has produced nothing yet, so no later run exists to become stale.
//!
//! Rework uses the same machinery. When a stage sends the work back to an earlier stage, the old
//! run of that stage and every run after it is out of date for the same reason: the target stage
//! is about to produce a new artifact.

use crate::ids::StageRunId;
use crate::machines::snapshot::StageRunSnapshot;
use crate::macros::string_enum;
use crate::state::{StageRunEvent, Status, TaskNodeEvent, TaskNodeStatus};
use crate::vocabulary::StageKind;

string_enum! {
    /// A change to an artifact that later stages consumed. The spelling is the `when` text of the
    /// invalidation table in `state-machine.json`.
    pub enum ArtifactChange("artifact change") {
        /// The requirements changed: the specification has a new approved version.
        SpecificationApproved = "SPECIFICATION produces a new approved spec version",
        /// The design changed.
        ArchitectureVersion = "ARCHITECTURE produces a new version",
        /// The task plan changed.
        PlanVersion = "TASK_PLANNING produces a new plan version",
        /// The code changed: the job branch has a new commit.
        ImplementationCommit = "IMPLEMENTATION produces a new commit",
        /// The documentation changed: the job branch has a new documentation commit.
        DocumentationCommit = "DOCUMENTING produces a new documentation commit",
        /// A person edited the source request after the intake snapshot. Nothing in the pipeline
        /// produces this, and the intake run goes stale with all the others: the text every later
        /// stage read is no longer the text a person authorized.
        RequestEdited = "The source request is edited after the intake snapshot",
        /// The repository map changed. The specification consumed the map and the baseline.
        RepositoryMapVersion = "REPOSITORY_INTELLIGENCE produces a new repository map",
        /// A value that the gate evidence is bound to changed: the base commit, the gate
        /// definition hash, the policy hash or the sandbox image digest. Nothing in the pipeline
        /// produces this. The documentation text did not change, so `DOCUMENTING` stays.
        GateEvidenceBinding = "A value bound to gate evidence changes",
    }
}

const AFTER_SPECIFICATION: &[StageKind] = &[
    StageKind::DomainDiscovery,
    StageKind::Architecture,
    StageKind::TaskPlanning,
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

const AFTER_ARCHITECTURE: &[StageKind] = &[
    StageKind::TaskPlanning,
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

const AFTER_PLAN: &[StageKind] = &[
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

const AFTER_IMPLEMENTATION: &[StageKind] = &[
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

const AFTER_DOCUMENTING: &[StageKind] = &[
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

/// Every stage, the intake first: the edited request is the input of all of them.
const AFTER_REQUEST_EDIT: &[StageKind] = &[
    StageKind::Intake,
    StageKind::RepositoryIntelligence,
    StageKind::Specification,
    StageKind::DomainDiscovery,
    StageKind::Architecture,
    StageKind::TaskPlanning,
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

const AFTER_REPOSITORY_MAP: &[StageKind] = &[
    StageKind::Specification,
    StageKind::DomainDiscovery,
    StageKind::Architecture,
    StageKind::TaskPlanning,
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

/// The stages whose evidence is bound to the base commit, the gate definition, the policy and the
/// image. `DOCUMENTING` is not one of them.
const AFTER_EVIDENCE_BINDING: &[StageKind] = &[
    StageKind::Validation,
    StageKind::Review,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

impl ArtifactChange {
    /// The stage whose run produces this change, or `None` for a change that comes from outside
    /// the pipeline (an edited request, a moved base branch). A change with no producer
    /// supersedes every stage it lists, the first one included.
    #[must_use]
    pub const fn producer(self) -> Option<StageKind> {
        match self {
            ArtifactChange::SpecificationApproved => Some(StageKind::Specification),
            ArtifactChange::ArchitectureVersion => Some(StageKind::Architecture),
            ArtifactChange::PlanVersion => Some(StageKind::TaskPlanning),
            ArtifactChange::ImplementationCommit => Some(StageKind::Implementation),
            ArtifactChange::DocumentationCommit => Some(StageKind::Documenting),
            ArtifactChange::RepositoryMapVersion => Some(StageKind::RepositoryIntelligence),
            ArtifactChange::RequestEdited | ArtifactChange::GateEvidenceBinding => None,
        }
    }

    /// The change that a run of `stage` can cause, or `None` for a stage whose output no later
    /// stage consumes by hash.
    #[must_use]
    pub const fn produced_by(stage: StageKind) -> Option<Self> {
        match stage {
            StageKind::Specification => Some(ArtifactChange::SpecificationApproved),
            StageKind::Architecture => Some(ArtifactChange::ArchitectureVersion),
            StageKind::TaskPlanning => Some(ArtifactChange::PlanVersion),
            StageKind::Implementation => Some(ArtifactChange::ImplementationCommit),
            StageKind::Documenting => Some(ArtifactChange::DocumentationCommit),
            StageKind::RepositoryIntelligence => Some(ArtifactChange::RepositoryMapVersion),
            _ => None,
        }
    }

    /// The stages whose runs become stale when this artifact changes, in pipeline order.
    #[must_use]
    pub const fn stale_stages(self) -> &'static [StageKind] {
        match self {
            ArtifactChange::SpecificationApproved => AFTER_SPECIFICATION,
            ArtifactChange::ArchitectureVersion => AFTER_ARCHITECTURE,
            ArtifactChange::PlanVersion => AFTER_PLAN,
            ArtifactChange::ImplementationCommit => AFTER_IMPLEMENTATION,
            ArtifactChange::DocumentationCommit => AFTER_DOCUMENTING,
            ArtifactChange::RequestEdited => AFTER_REQUEST_EDIT,
            ArtifactChange::RepositoryMapVersion => AFTER_REPOSITORY_MAP,
            ArtifactChange::GateEvidenceBinding => AFTER_EVIDENCE_BINDING,
        }
    }
}

/// One row of the invalidation table in `state-machine.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidationRule {
    /// The change.
    pub change: ArtifactChange,
    /// The stages whose runs become `SUPERSEDED`.
    pub supersedes: &'static [StageKind],
}

/// Every invalidation rule, in the order of the file.
pub static INVALIDATION_RULES: &[InvalidationRule] = &[
    InvalidationRule {
        change: ArtifactChange::SpecificationApproved,
        supersedes: AFTER_SPECIFICATION,
    },
    InvalidationRule {
        change: ArtifactChange::ArchitectureVersion,
        supersedes: AFTER_ARCHITECTURE,
    },
    InvalidationRule {
        change: ArtifactChange::PlanVersion,
        supersedes: AFTER_PLAN,
    },
    InvalidationRule {
        change: ArtifactChange::ImplementationCommit,
        supersedes: AFTER_IMPLEMENTATION,
    },
    InvalidationRule {
        change: ArtifactChange::DocumentationCommit,
        supersedes: AFTER_DOCUMENTING,
    },
    InvalidationRule {
        change: ArtifactChange::RequestEdited,
        supersedes: AFTER_REQUEST_EDIT,
    },
    InvalidationRule {
        change: ArtifactChange::RepositoryMapVersion,
        supersedes: AFTER_REPOSITORY_MAP,
    },
    InvalidationRule {
        change: ArtifactChange::GateEvidenceBinding,
        supersedes: AFTER_EVIDENCE_BINDING,
    },
];

/// The runs, in the order given, that are of one of `stages` and can still be superseded.
fn supersedable(runs: &[StageRunSnapshot], stages: &[StageKind]) -> Vec<StageRunId> {
    runs.iter()
        .filter(|run| stages.contains(&run.kind))
        .filter(|run| run.status.apply(StageRunEvent::Supersede).is_ok())
        .map(|run| run.id)
        .collect()
}

/// The runs that `change` makes stale: every live run of a stale stage, old or new. A skipped
/// run is live in this sense, because the decision to skip it can be made again.
///
/// Each returned run takes the `supersede` event. The result is empty once the plan has been
/// applied, so applying a plan twice does nothing.
#[must_use]
pub fn plan_for_change(runs: &[StageRunSnapshot], change: ArtifactChange) -> Vec<StageRunId> {
    supersedable(runs, change.stale_stages())
}

/// The stages whose live runs are replaced when work goes back to `target`: the target itself,
/// then every stage that a new artifact from the target makes stale.
#[must_use]
pub fn rework_stages(target: StageKind) -> Vec<StageKind> {
    let mut stages = vec![target];
    if let Some(change) = ArtifactChange::produced_by(target) {
        stages.extend_from_slice(change.stale_stages());
    }
    stages
}

/// The runs superseded when `failing_run` sends the work back to `target`.
///
/// The failing run is left out. It takes the `REWORK_REQUESTED` transition instead, and a run
/// has only one outcome.
#[must_use]
pub fn plan_for_rework(
    runs: &[StageRunSnapshot],
    target: StageKind,
    failing_run: StageRunId,
) -> Vec<StageRunId> {
    let mut planned = supersedable(runs, &rework_stages(target));
    planned.retain(|id| *id != failing_run);
    planned
}

/// What a task node does when the stage run it belongs to is superseded.
///
/// A node that is not finished is cancelled. A node that already succeeded keeps its result,
/// which belongs to the superseded run, and a cancelled node is already done.
#[must_use]
pub fn task_node_event_on_supersession(status: TaskNodeStatus) -> Option<TaskNodeEvent> {
    status
        .apply(TaskNodeEvent::Cancel)
        .is_ok()
        .then_some(TaskNodeEvent::Cancel)
}

#[cfg(test)]
mod tests;
