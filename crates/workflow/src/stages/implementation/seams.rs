//! What the implementation and review stages need from the outside and no port offers. Each is a
//! small trait that the composition root implements and the tests implement with a list. See
//! `crate::stages::intake::seams` for why they are traits of this crate.
//!
//! The schema check (`AgentOutputCheck`), the runtime probes (`CapabilityProbes`) and the closed
//! `SeamError` are those of the intake stage, so the composition root builds each once.

use async_trait::async_trait;
use factory_domain::contracts::GateReport;
use factory_domain::contracts::review_verdict::Finding;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::state::TaskNodeStatus;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::JobTokenRef;
use factory_ports::paths::CommitSha;
use factory_ports::sandbox::SandboxSpec;
use factory_ports::store::LeaseEpoch;
use factory_ports::workspace::WorkspaceMounts;

pub use crate::stages::intake::seams::{AgentOutputCheck, CapabilityProbes, SeamError};

use crate::handlers::RunIdentity;

/// What the agent in the sandbox may do with the checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceAccess {
    /// The builder: the checkout is writable. Protected paths are re-mounted read-only over it.
    ReadWrite,
    /// The reviewer: the checkout is read-only. The reviewer changes nothing and pushes nothing.
    ReadOnly,
}

/// Builds the sandbox spec of the `agent` profile for an agent that works on a checkout: image,
/// limits, the mounts of the workspace, the network attachment behind the egress sidecar and the
/// job token mount. The policy decides every value, so the stage cannot widen a sandbox.
///
/// The stage does not trust the answer. It checks the profile, that the spec mounts exactly the
/// workspace it made, and that a read-only request came back read-only, before it creates a
/// sandbox, and it checks the posture of the sandbox that was created.
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

    /// Takes the node for the attempt (`RUNNING`). A node that an earlier attempt left `RUNNING`
    /// is first returned to `READY` (`T05`) in the same call.
    ///
    /// # Errors
    /// [`LedgerError::Fenced`] when the epoch is stale, [`LedgerError::Illegal`] when the node
    /// is not one the attempt may take.
    async fn start(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError>;

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
}

/// Where the stage learns that its run replaces another one, and why. The engine hands a handler
/// no feedback, so the composition root implements this over the stage runs and the artifacts the
/// store holds (`StageRun::rework_of`, the stored gate reports and the stored review verdict).
#[async_trait]
pub trait ReworkSource: Send + Sync {
    /// The feedback for this run, or `None` for a first run.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the store cannot be read. The stage fails closed: a rework
    /// run that cannot read its feedback must not run as if it were a first run.
    async fn of(&self, run: &RunIdentity) -> Result<Option<ReworkContext>, SeamError>;
}
