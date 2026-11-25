//! What the implementation and review stages need from the outside and no port offers. Each is a
//! small trait that the composition root implements and the tests implement with a list. See
//! `crate::stages::intake::seams` for why they are traits of this crate.
//!
//! The schema check (`AgentOutputCheck`), the runtime probes (`CapabilityProbes`) and the closed
//! `SeamError` are those of the intake stage, so the composition root builds each once.

use async_trait::async_trait;
use factory_domain::contracts::GateReport;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::review_verdict::Finding;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::state::TaskNodeStatus;
use factory_domain::values::{NonEmptyString, Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{JobTokenRef, RuntimeId};
use factory_ports::paths::CommitSha;
use factory_ports::sandbox::{SandboxProfile, SandboxSpec};
use factory_ports::store::{LeaseEpoch, MeteredUsage};
use factory_ports::workspace::WorkspaceMounts;

pub use crate::stages::intake::seams::{AgentOutputCheck, CapabilityProbes, SeamError};

use factory_domain::machines::guards::EnvironmentCause;

use crate::handlers::{RunIdentity, StageError};

/// What the checkout is for.
///
/// The sandbox port allows the `agent` profile only a writable checkout
/// (`SandboxRule::WorkspaceAccessMismatch`), because the builder must edit files. A reviewer runs
/// in the same profile, since only that profile reaches the model broker, so its checkout is
/// writable at the mount too. What keeps the reviewer from changing anything is therefore not the
/// mount. It is that the reviewer is granted no tool that writes or runs commands, that its
/// checkout is its own copy, and that the stage disposes of the copy without ever ingesting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceAccess {
    /// The builder: the stage ingests the checkout, audits it and commits what it holds.
    Edit,
    /// The reviewer: a copy to read. The stage never ingests it, and disposes of it unread.
    Inspect,
}

/// Builds the sandbox spec of the `agent` profile for an agent that works on a checkout: image,
/// limits, the mounts of the workspace, the network attachment behind the egress sidecar and the
/// job token mount. The policy decides every value, so the stage cannot widen a sandbox.
///
/// The stage does not trust the answer. It checks the profile and that the spec mounts exactly the
/// workspace it made before it creates a sandbox, and the sandbox port checks the posture of the
/// container against the spec and the policy.
pub trait WorkspaceAgentSpecs: Send + Sync {
    /// The spec for the attempt, over these mounts.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the policy or the image cannot be resolved.
    fn spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
        mounts: WorkspaceMounts,
        access: WorkspaceAccess,
    ) -> Result<SandboxSpec, SeamError>;
}

/// The fence a write to the task ledger carries: the attempt and the epoch of its lease. The
/// store refuses a write whose epoch is not the current one, so a worker that lost its lease
/// cannot move a task (NT-LSE-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    /// The attempt that writes.
    pub attempt: AttemptId,
    /// The epoch of its lease.
    pub epoch: LeaseEpoch,
}

/// Why a ledger call failed. The set is closed and carries no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The epoch is not the current one: another worker holds the stage run now.
    #[error("the lease epoch is no longer current")]
    Fenced,
    /// The move is not one the task machine allows.
    #[error("the task machine does not allow this move")]
    Illegal,
    /// The store cannot be reached.
    #[error("the task ledger cannot be reached")]
    Unavailable,
}

/// One task of the plan, as the ledger needs it to create a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTask {
    /// The key of the task in the plan.
    pub key: Slug,
    /// The keys it depends on.
    pub depends_on: Vec<Slug>,
}

/// One node of the task graph, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    /// The key of the task in the plan.
    pub key: Slug,
    /// Where the node stands.
    pub status: TaskNodeStatus,
    /// The commit that finished it, for a node that `SUCCEEDED`.
    pub commit: Option<CommitSha>,
}

/// One run of the builder on a task: the model that ran, and what the model broker metered for
/// it (ports v1.5). The process metrics read it: the tokens of a task and whether a task needed a
/// larger model (ADR 0029).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunRecord {
    /// The runtime the router chose.
    pub runtime: RuntimeId,
    /// The model the router chose.
    pub model: NonEmptyString,
    /// The tier the stage asked the router for.
    pub tier: RecommendedTier,
    /// What the broker metered between the start and the end of the run. `None` when a reading
    /// of the meter failed: the use is then not known, and it is never taken for zero.
    pub metered: Option<MeteredUsage>,
}

/// The durable state of the tasks of one `IMPLEMENTATION` stage run. The composition root
/// implements it with `TaskNodeOps` of the `Store` port: `insert_task_graph`, `list_task_nodes`
/// and `transition_task_node` with a fence made from the hold.
///
/// This is what makes a crash cheap. A node that `SUCCEEDED` has a commit in the job's object
/// store, so the next attempt skips it and builds on that commit.
#[async_trait]
pub trait TaskLedger: Send + Sync {
    /// Says whether this reads the real store (`real`) or a list (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Creates every node and edge of the plan for the stage run in one step, or returns the
    /// nodes already stored for it. A different plan hash for a stage run that has nodes is an
    /// error. The nodes come back in the order of `tasks`.
    ///
    /// # Errors
    /// [`LedgerError`].
    async fn open(
        &self,
        run: &RunIdentity,
        plan: &Sha256Digest,
        tasks: &[PlannedTask],
    ) -> Result<Vec<TaskRecord>, LedgerError>;

    /// Takes the node for the attempt (`RUNNING`). The stage calls it only for a node whose
    /// dependencies have all `SUCCEEDED`, which the topological order guarantees, so a node
    /// that is still `PENDING` is first made `READY` (`T01`), a `FAILED` node is retried
    /// (`T06`), and a node that an earlier attempt left `RUNNING` is first returned to `READY`
    /// (`T05`), all in the same call.
    ///
    /// # Errors
    /// [`LedgerError::Fenced`] when the epoch is stale, [`LedgerError::Illegal`] when the node
    /// is not one the attempt may take.
    async fn start(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError>;

    /// Checks that `hold` is still the current one, without writing. The stage calls it right
    /// before it makes a commit, so a worker that lost its lease while the builder ran makes no
    /// commit at all. Between this call and the commit the answer can still change, and then the
    /// fenced `finish` refuses the record: the commit is an object in the job's store that
    /// nothing points at, and the next attempt builds the task again.
    ///
    /// # Errors
    /// [`LedgerError::Fenced`] when the epoch is stale.
    async fn confirm(&self, run: &RunIdentity, hold: &Hold) -> Result<(), LedgerError>;

    /// Records that the attempt ran the builder on the node, with the model that ran and what it
    /// used (`TaskRunOps::record_task_run`). The stage calls it once, when the builder has
    /// stopped, whatever becomes of the task afterwards: a run that is refused by the audit, or
    /// whose report is invalid, used its tokens all the same. The same record a second time
    /// changes nothing.
    ///
    /// # Errors
    /// [`LedgerError::Fenced`] when the epoch is stale, [`LedgerError::Illegal`] when the node is
    /// not one of the stage run or the attempt already has another record for it.
    async fn record_run(
        &self,
        run: &RunIdentity,
        task: &Slug,
        hold: &Hold,
        ran: &TaskRunRecord,
    ) -> Result<(), LedgerError>;

    /// Records the commit that finished the node (`SUCCEEDED`).
    ///
    /// # Errors
    /// [`LedgerError`].
    async fn finish(
        &self,
        run: &RunIdentity,
        task: &Slug,
        commit: &CommitSha,
        hold: &Hold,
    ) -> Result<(), LedgerError>;

    /// Records that the attempt could not finish the node (`FAILED`).
    ///
    /// # Errors
    /// [`LedgerError`].
    async fn fail(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError>;
}

/// What the builder is told about the round that was sent back.
#[derive(Debug, Clone, PartialEq)]
pub struct ReworkContext {
    /// The head commit of the run that was replaced. The new run builds on it, so the builder
    /// fixes what is there instead of starting again.
    pub previous_head: CommitSha,
    /// The reports of the gates that failed, as the stage that ran them stored them. The builder
    /// receives these, never a summary (`state-machine.json`, `rework_routes`).
    pub failed_reports: Vec<GateReport>,
    /// The findings of the independent reviewer, already deduplicated by the review stage.
    pub findings: Vec<Finding>,
    /// Which round this is, from 1.
    pub round: u8,
    /// What a person asked for when they sent the work back, in their words. `None` when a gate
    /// sent it back, or when the person gave no instructions.
    pub person_request: Option<String>,
    /// What people answered when the runs this one replaces asked them, in their words and oldest
    /// first. A decision a person took stays taken when the work is sent back: the next run and
    /// its reviewer read it, so that nobody asks it again or calls it out of scope.
    pub earlier_answers: Vec<String>,
}

/// Where the stage learns that its run replaces another one, and why. The engine hands a handler
/// no feedback, so the composition root implements this over the stage runs and the artifacts the
/// store holds (`StageRun::rework_of`, the stored gate reports and the stored review verdict).
#[async_trait]
pub trait ReworkSource: Send + Sync {
    /// Says whether this reads the store (`real`) or a fixed answer (`fake`). The profile check
    /// refuses a `fake` in production (RR-6): a stand-in that always says "first run" drops the
    /// feedback of a reviewer.
    fn fidelity(&self) -> Fidelity;

    /// The feedback for this run, or `None` for a first run.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the store cannot be read. The stage fails closed: a rework
    /// run that cannot read its feedback must not run as if it were a first run.
    async fn of(&self, run: &RunIdentity) -> Result<Option<ReworkContext>, SeamError>;
}

/// Where a stage learns what people answered to the earlier runs of the same stage in its job.
///
/// A run of a reviewing stage is re-created when a later round sends the work back past it, and
/// superseded when the work it judged changes. The new run has no answers of its own yet, so a
/// reviewer without the earlier ones asks a settled question again (documentation policy 9.9).
/// [`ReworkSource`] does not serve this: it answers only for the run a rework move sent the work
/// back to, and a re-created run after that target is a first run to it.
#[async_trait]
pub trait AnswerHistory: Send + Sync {
    /// Says whether this reads the store (`real`) or a fixed answer (`fake`). The profile check
    /// refuses a `fake` in production: a stand-in that always says "nobody answered" brings back
    /// the question a person settled.
    fn fidelity(&self) -> Fidelity;

    /// The answers people gave to every run of the same stage that came before `run` in its job,
    /// in their words: the oldest run first, and in each run in the order given. The answers of
    /// `run` itself are not in it; the stage reads those from its own context. Empty for the
    /// first run of the stage, or when nobody answered.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the store cannot be read. The stage fails closed: a run
    /// that cannot read what people decided must not run as if nobody had.
    async fn earlier_answers(&self, run: &RunIdentity) -> Result<Vec<String>, SeamError>;
}

/// Checks a spec before a sandbox is made from it. The agent runs only in the `agent` profile, over
/// exactly the workspace the stage made, with the job token it needs and nothing else.
///
/// # Errors
/// [`StageError::Environment`] with the policy cause: the spec is for another profile, mounts a
/// different workspace than the one the stage made, or has no job token. Nothing is retried:
/// another try would be given the same spec.
pub fn verify_spec(spec: &SandboxSpec, mounts: &WorkspaceMounts) -> Result<(), StageError> {
    let refused = || StageError::Environment(EnvironmentCause::PolicyViolation);
    if spec.profile != SandboxProfile::Agent {
        return Err(refused());
    }
    if &spec.mounts.workspace != mounts {
        return Err(refused());
    }
    if spec.job_token.is_none() {
        return Err(refused());
    }
    Ok(())
}

/// Checks that an agent that must not change anything has no tool that could. A reviewer is granted
/// tools that read, and a tool that writes or runs commands is refused before anything is made.
///
/// # Errors
/// [`StageError::Environment`] with the policy cause.
pub fn verify_read_only_tools(
    manifest: &factory_domain::contracts::AgentManifest,
) -> Result<(), StageError> {
    use factory_domain::contracts::agent_manifest::ToolAccess;
    let writes = manifest
        .allowed_tools
        .as_slice()
        .iter()
        .any(|tool| tool.access != ToolAccess::Read);
    let permissions = &manifest.permissions;
    if writes || !permissions.filesystem.write.is_empty() {
        return Err(StageError::Environment(EnvironmentCause::PolicyViolation));
    }
    Ok(())
}
