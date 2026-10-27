//! The store port: transactional state, the evidence ledger and the outbox (ADR 0004, 0007, 0008).
//!
//! One [`Tx`] is one database transaction. The engine writes a status change, its ledger entries
//! and its outbox rows in one `Tx` and commits them together (invariant INV-03). Everything in a
//! `Tx` is scoped to a tenant, with one exception: a system transaction, which only the workflow
//! crate may open, sees every tenant so it can claim work and sweep expired leases.
//!
//! # Scope rules
//!
//! * A **tenant** transaction (`Store::begin`) sees only rows of its own tenant. A row of another
//!   tenant looks exactly like a row that does not exist: the call returns
//!   [`StoreError::NotFound`], so a caller cannot learn that the other row exists.
//! * A **system** transaction (`Store::begin_system`) sees every tenant. It may not create a row
//!   that has no parent to take a tenant from (jobs, principals, artifact index rows): those calls
//!   return [`StoreError::ScopeNotAllowed`]. `claim_ready` and `expired_leases` work in a system
//!   transaction only.
//! * A value that names a tenant, such as a [`DomainEvent`], must name the tenant that owns the
//!   job it belongs to. A mismatch is [`StoreError::TenantMismatch`].
//!
//! # Concurrency rules
//!
//! * Every mutable row carries a [`Version`]. An update says which version it read. A stale
//!   version, or a status that is not the one the update started from, is
//!   [`StoreError::Conflict`] and changes nothing.
//! * A worker holds a [`Lease`] on a stage run. Claiming increments the stage run's
//!   [`LeaseEpoch`]. Every write from a worker carries the epoch it was given, and the store
//!   rejects a write whose epoch is not the current one with [`StoreError::LeaseFenced`]
//!   (invariant INV-05). Lease expiry is judged by the database clock ([`Tx::database_time`]).
//! * Two open transactions never both succeed in claiming the same stage run, and a row claimed
//!   by an open transaction is skipped, not waited for, by `claim_ready` in another.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, DomainEvent, EvidenceLedgerEntry};
use factory_domain::error::ValueError;
use factory_domain::ids::{
    AttemptId, CorrelationId, JobId, PrincipalId, StageRunId, TaskNodeId, TenantId,
};
use factory_domain::ledger::ChainHead;
use factory_domain::scope::TenantScope;
use factory_domain::state::{
    AttemptStatus, IllegalTransition, JobStatus, StageRunStatus, Status, TaskNodeStatus,
};
use factory_domain::values::{AggregateVersion, NonEmptyString, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{Fidelity, StageKind};

/// The version counter of a mutable row. A new row starts at [`AggregateVersion::FIRST`].
pub type Version = AggregateVersion;

/// The position of an entry in a job's evidence ledger. The first entry is 1.
pub type Sequence = u64;

/// The position of an event in the outbox. It grows with every enqueued event. Gaps are allowed
/// and arrival order is not a guarantee across aggregates (ADR 0004), so a reader uses it only to
/// resume reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboxSeq(u64);

impl OutboxSeq {
    /// The position before every event. Reading `from` this position reads everything.
    pub const START: Self = Self(0);

    /// Wraps a position.
    #[must_use]
    pub const fn new(position: u64) -> Self {
        Self(position)
    }

    /// The position as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The version of the database schema, which is the number of the last migration applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// Wraps a migration number.
    #[must_use]
    pub const fn new(migration: u32) -> Self {
        Self(migration)
    }

    /// The migration number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The fencing counter of a stage run's lease. Claiming the stage run makes it one higher. A write
/// that carries an older epoch comes from a worker that lost its lease and is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseEpoch(u64);

impl LeaseEpoch {
    /// The epoch of a stage run that was never claimed.
    pub const NEVER_CLAIMED: Self = Self(0);

    /// Wraps an epoch.
    #[must_use]
    pub const fn new(epoch: u64) -> Self {
        Self(epoch)
    }

    /// The epoch as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The epoch after one more claim.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// The name of a worker process, such as `worker-1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerId(Slug);

impl WorkerId {
    /// Checks and wraps a worker name.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless the name is a slug.
    pub fn new(name: &str) -> Result<Self, ValueError> {
        Slug::parse(name).map(Self)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Proof that the caller is the engine and may see every tenant. Only the workflow crate calls
/// `Store::begin_system` (rule DEP-09, checked by `cargo xtask check-architecture`).
#[derive(Debug)]
pub struct SystemScope(());

impl SystemScope {
    /// The engine's scope. The workflow crate is the only caller.
    #[must_use]
    pub const fn engine() -> Self {
        Self(())
    }
}

/// A value and the version it was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versioned<T> {
    /// The row.
    pub value: T,
    /// Its version. Pass it back as `expected` to update the row.
    pub version: Version,
}

/// A state change that the state machine allows, ready to be stored.
///
/// It can only be made by [`AppliedTransition::plan`], which asks the domain's transition table, so
/// a store never receives a move the table does not list. The store checks `from` against the
/// stored status and writes `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedTransition<S: Status> {
    from: S,
    event: S::Event,
    to: S,
    transition_id: &'static str,
    at: Timestamp,
}

impl<S: Status> AppliedTransition<S> {
    /// Looks up the move that `event` causes from `from`.
    ///
    /// # Errors
    /// Returns [`IllegalTransition`] when the state machine has no such move.
    pub fn plan(from: S, event: S::Event, at: Timestamp) -> Result<Self, IllegalTransition> {
        let row = from.transition(event)?;
        Ok(Self {
            from,
            event,
            to: row.to,
            transition_id: row.id,
            at,
        })
    }

    /// The status the move starts from.
    #[must_use]
    pub const fn from_status(&self) -> S {
        self.from
    }

    /// The event that asked for the move.
    #[must_use]
    pub const fn event(&self) -> S::Event {
        self.event
    }

    /// The status after the move.
    #[must_use]
    pub const fn to_status(&self) -> S {
        self.to
    }

    /// The transition id in `state-machine.json`, such as `S03`.
    #[must_use]
    pub const fn transition_id(&self) -> &'static str {
        self.transition_id
    }

    /// When the engine applied the move.
    #[must_use]
    pub const fn at(&self) -> Timestamp {
        self.at
    }
}

/// A job to create. The status starts at the machine's initial status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    /// The new job's id, from the `IdGenerator`.
    pub id: JobId,
    /// Shared by every event and log line of the job.
    pub correlation_id: CorrelationId,
    /// The person who asked for the work.
    pub requester: PrincipalId,
    /// When the job was created.
    pub created_at: Timestamp,
}

/// A stored job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The job.
    pub id: JobId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// Shared by every event and log line of the job.
    pub correlation_id: CorrelationId,
    /// The person who asked for the work.
    pub requester: PrincipalId,
    /// Where the job stands.
    pub status: JobStatus,
    /// When the job was created.
    pub created_at: Timestamp,
}

/// A stage run to create. The status starts at the machine's initial status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewStageRun {
    /// The new stage run's id.
    pub id: StageRunId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// Which stage this is a run of.
    pub kind: StageKind,
    /// When it was created.
    pub created_at: Timestamp,
}

/// The lease a worker holds on a stage run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The worker that holds it.
    pub worker: WorkerId,
    /// The fencing epoch the worker must send with every write.
    pub epoch: LeaseEpoch,
    /// When the lease ends unless a heartbeat renews it, by the database clock.
    pub expires_at: Timestamp,
    /// How long each claim or heartbeat extends the lease.
    pub ttl: Duration,
}

/// A stored stage run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRun {
    /// The stage run.
    pub id: StageRunId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// Which stage this is a run of.
    pub kind: StageKind,
    /// Where it stands.
    pub status: StageRunStatus,
    /// The highest epoch ever granted on this stage run. It never goes down.
    pub lease_epoch: LeaseEpoch,
    /// The current lease, kept after it expires until the next claim replaces it.
    pub lease: Option<Lease>,
    /// When it was created.
    pub created_at: Timestamp,
}

/// Work that a call to `claim_ready` handed to a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedWork {
    /// The stage run, as stored after the claim. Its status is still `READY`.
    pub stage_run: Versioned<StageRun>,
    /// The lease the worker now holds.
    pub lease: Lease,
}

/// An attempt to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttempt {
    /// The new attempt's id.
    pub id: AttemptId,
    /// The stage run it is a try at. The caller must hold its current lease.
    pub stage_run_id: StageRunId,
    /// The epoch from the claim. It must be the stage run's current epoch.
    pub epoch: LeaseEpoch,
    /// When it was created.
    pub created_at: Timestamp,
}

/// A stored attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The attempt.
    pub id: AttemptId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// The stage run it is a try at.
    pub stage_run_id: StageRunId,
    /// Which try this is for the stage run, from 1.
    pub number: u32,
    /// Where it stands.
    pub status: AttemptStatus,
    /// The worker that holds the lease.
    pub worker: WorkerId,
    /// The epoch the worker must send with every write.
    pub epoch: LeaseEpoch,
    /// When it was created.
    pub created_at: Timestamp,
}

/// A node of the task graph to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTaskNode {
    /// The new node's id.
    pub id: TaskNodeId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// The node's key in the task plan, such as `T-001`.
    pub key: Slug,
    /// When it was created.
    pub created_at: Timestamp,
}

/// A stored node of the task graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskNode {
    /// The node.
    pub id: TaskNodeId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// The node's key in the task plan.
    pub key: Slug,
    /// Where it stands.
    pub status: TaskNodeStatus,
    /// When it was created.
    pub created_at: Timestamp,
}

/// A person or service to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrincipal {
    /// The new principal's id.
    pub id: PrincipalId,
    /// How the outside world names them, for example a numeric GitHub user id.
    pub external_ref: NonEmptyString,
    /// When it was recorded.
    pub created_at: Timestamp,
}

/// A stored person or service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The principal.
    pub id: PrincipalId,
    /// The tenant that owns the record.
    pub tenant_id: TenantId,
    /// How the outside world names them.
    pub external_ref: NonEmptyString,
    /// When it was recorded.
    pub created_at: Timestamp,
}

/// An artifact to index for the tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifactIndexEntry {
    /// The artifact, by content hash.
    pub artifact: ArtifactRef,
    /// The stage run that made it, when one did.
    pub stage_run_id: Option<StageRunId>,
    /// When it was indexed.
    pub created_at: Timestamp,
}

/// The tenant's record that it holds an artifact. A blob in the artifact store is shared by hash,
/// but a tenant may read it only after its own index row says so (ADR 0008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIndexEntry {
    /// The tenant that holds the artifact.
    pub tenant_id: TenantId,
    /// The artifact, by content hash.
    pub artifact: ArtifactRef,
    /// The stage run that made it, when one did.
    pub stage_run_id: Option<StageRunId>,
    /// When it was indexed.
    pub created_at: Timestamp,
}

/// An event in the outbox with its position.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxRow {
    /// The position the store gave the event.
    pub seq: OutboxSeq,
    /// The event.
    pub event: DomainEvent,
}

/// Who did something that is recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditActor {
    /// A person or service principal.
    Principal(PrincipalId),
    /// A factory component, such as `workflow.engine`.
    Component(Slug),
}

/// One audit record. The log is append only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The job the action concerns. The record belongs to that job's tenant.
    pub job_id: JobId,
    /// Who did it.
    pub actor: AuditActor,
    /// What was done, such as `approval.recorded`.
    pub action: Slug,
    /// The hash of the policy that was in force when it was done.
    pub policy_hash: Sha256Digest,
    /// Shared by everything in the job.
    pub correlation_id: CorrelationId,
    /// When it was done.
    pub occurred_at: Timestamp,
}

/// Why a store call failed. The set is closed: an adapter maps every failure of its database
/// library onto one of these and never lets a library error type through.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The update started from a version or a status that is no longer current, or an append lost
    /// a race. Read the row again and decide.
    #[error("the row changed since it was read; read it again and retry")]
    Conflict,
    /// No such row for this scope. A row of another tenant is reported the same way.
    #[error("no such row for this scope")]
    NotFound,
    /// A value names a tenant that does not own the job it belongs to.
    #[error("the value names a tenant that does not own this job")]
    TenantMismatch,
    /// The write carries a lease epoch that is not the current one, or the lease has expired.
    #[error("the lease epoch is not current: this worker no longer holds the lease")]
    LeaseFenced,
    /// A ledger entry does not extend the job's hash chain: it skips a position, points at the
    /// wrong previous hash or carries a hash that does not match its content.
    #[error("the ledger entry does not extend the job's hash chain")]
    ChainBroken,
    /// The call is not allowed in this kind of transaction.
    #[error("this call is not allowed in this kind of transaction")]
    ScopeNotAllowed,
    /// The database cannot be reached or refused the call for a reason that is not the caller's.
    #[error("the database is unavailable")]
    Unavailable,
    /// A uniqueness or integrity rule of the database was broken. The text names the rule and
    /// never includes a value from the row.
    #[error("a database rule was broken: {0}")]
    Constraint(String),
}

/// The entry point to the store.
///
/// # Preconditions
/// The schema is at the version the code expects. A caller that wants to be sure checks
/// [`Store::schema_version`] at start-up and refuses to become ready if it is behind (ADR 0007).
///
/// # Postconditions
/// Each `begin` returns a new, independent transaction. Nothing a transaction writes is visible
/// to another until it commits, and nothing is visible after it rolls back or is dropped.
///
/// # Errors
/// [`StoreError::Unavailable`] when the database cannot be reached. No other variant is returned
/// by this trait.
///
/// # Idempotency
/// Beginning a transaction changes nothing, so it can be repeated. `schema_version` is a read.
#[async_trait]
pub trait Store: Send + Sync {
    /// Says whether this store is the real database (`real`) or an in-memory stand-in (`fake`).
    /// A production run refuses a store that reports `fake`.
    fn fidelity(&self) -> Fidelity;

    /// Opens a transaction that sees only the rows of `scope`'s tenant.
    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError>;

    /// Opens a transaction that sees every tenant. Only the workflow crate calls this (DEP-09).
    async fn begin_system(&self, scope: SystemScope) -> Result<Box<dyn Tx>, StoreError>;

    /// The version of the schema the database is at.
    async fn schema_version(&self) -> Result<SchemaVersion, StoreError>;
}

/// One database transaction. Dropping it without calling `commit` rolls it back.
///
/// # Preconditions
/// The transaction is open: it was returned by [`Store::begin`] or [`Store::begin_system`] and
/// has not been committed or rolled back. While it is open the caller awaits nothing but the
/// store (ADR 0007).
///
/// # Postconditions
/// After `commit` succeeds, every write made in the transaction is visible to every later
/// transaction, all together. After `commit` fails, `rollback`, or a drop, none of them is. A
/// transaction reads its own writes.
///
/// # Errors
/// `commit` returns [`StoreError::Conflict`] when another transaction committed a change to a row
/// this one changed (first committer wins) and [`StoreError::Unavailable`] when the database is
/// gone. A failed commit leaves nothing behind. `rollback` returns [`StoreError::Unavailable`]
/// only.
///
/// # Idempotency
/// A transaction is used once: `commit` and `rollback` take it by value. Calling
/// `database_time` repeatedly is a read.
#[async_trait]
pub trait Tx:
    JobOps
    + StageRunOps
    + AttemptOps
    + TaskNodeOps
    + LedgerOps
    + OutboxOps
    + AuditOps
    + ArtifactIndexOps
    + PrincipalOps
    + Send
{
    /// The database's current time. Lease and deadline checks use this and never the `Clock`
    /// port.
    async fn database_time(&mut self) -> Result<Timestamp, StoreError>;

    /// Makes every write of the transaction visible, all together.
    async fn commit(self: Box<Self>) -> Result<(), StoreError>;

    /// Discards every write of the transaction.
    async fn rollback(self: Box<Self>) -> Result<(), StoreError>;
}

/// Jobs.
///
/// # Preconditions
/// Tenant transaction for `insert_job`. `get_job` and `transition_job` also work in a system
/// transaction.
///
/// # Postconditions
/// A new job has the machine's initial status and version
/// [`AggregateVersion::FIRST`]. A transition writes `to`, bumps the version by one and returns it.
///
/// # Errors
/// [`StoreError::NotFound`] (also for another tenant's job), [`StoreError::Conflict`] (stale
/// `expected` or the stored status is not the move's `from`), [`StoreError::Constraint`]
/// (duplicate id), [`StoreError::ScopeNotAllowed`] (`insert_job` in a system transaction).
///
/// # Idempotency
/// `insert_job` is not idempotent: a second insert with the same id is a constraint error.
/// `transition_job` applied twice with the same `expected` succeeds once and conflicts after.
#[async_trait]
pub trait JobOps {
    /// Creates a job.
    async fn insert_job(&mut self, new: NewJob) -> Result<Versioned<Job>, StoreError>;

    /// Reads a job.
    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError>;

    /// Compare and swap on the job's status and version.
    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError>;
}

/// Stage runs and the claiming of ready work.
///
/// # Preconditions
/// `claim_ready` and `expired_leases` need a system transaction. The others work in either kind.
///
/// # Postconditions
/// `claim_ready` gives each ready stage run to at most one worker: a stage run whose lease has not
/// expired, or that another open transaction has claimed, is skipped. Each claim makes the stage
/// run's epoch one higher than before and sets a lease that ends `lease_ttl` after the database
/// time. Stage runs are claimed oldest first. At most `limit` are returned.
///
/// # Errors
/// [`StoreError::NotFound`], [`StoreError::Conflict`] and [`StoreError::Constraint`] as for jobs;
/// [`StoreError::ScopeNotAllowed`] when `claim_ready` or `expired_leases` is called in a tenant
/// transaction.
///
/// # Idempotency
/// `claim_ready` is not idempotent: a repeat finds nothing new until the leases expire.
/// `expired_leases` is a read.
#[async_trait]
pub trait StageRunOps {
    /// Creates a stage run in the machine's initial status.
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Versioned<StageRun>, StoreError>;

    /// Reads a stage run.
    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError>;

    /// Compare and swap on the stage run's status and version.
    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
    ) -> Result<Version, StoreError>;

    /// System scope only. Leases ready stage runs to `worker` (`FOR UPDATE SKIP LOCKED` in the
    /// real store) and increments each one's lease epoch.
    async fn claim_ready(
        &mut self,
        worker: &WorkerId,
        limit: u32,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedWork>, StoreError>;

    /// System scope only. The attempts that are still `STARTING` or `RUNNING` whose lease ended at
    /// or before the database time, oldest first, at most `limit`.
    async fn expired_leases(&mut self, limit: u32) -> Result<Vec<AttemptId>, StoreError>;
}

/// Attempts, their heartbeats and the lease fence.
///
/// # Preconditions
/// The caller holds the stage run's lease and sends the epoch it was given. `insert_attempt`
/// needs that epoch to be current.
///
/// # Postconditions
/// `insert_attempt` numbers the attempt one higher than the stage run's last. `heartbeat` moves the
/// lease end to the database time plus the lease's `ttl`. A transition writes `to` and bumps the
/// version.
///
/// # Errors
/// [`StoreError::LeaseFenced`] when the epoch is not the stage run's current epoch or the lease
/// has expired; [`StoreError::Conflict`] when `expected` is stale, the status is not the move's
/// `from`, or `heartbeat` is sent for an attempt that already ended; [`StoreError::NotFound`];
/// [`StoreError::Constraint`] (duplicate id).
///
/// # Idempotency
/// `heartbeat` can be repeated: each call renews the lease. `insert_attempt` is not idempotent.
/// A transition applied twice with the same `expected` succeeds once and conflicts after.
#[async_trait]
pub trait AttemptOps {
    /// Creates an attempt in the machine's initial status.
    async fn insert_attempt(&mut self, new: NewAttempt) -> Result<Versioned<Attempt>, StoreError>;

    /// Reads an attempt.
    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError>;

    /// Renews the lease. Rejects the write when `epoch` is older than the stored epoch (fencing).
    async fn heartbeat(&mut self, id: AttemptId, epoch: LeaseEpoch) -> Result<(), StoreError>;

    /// Compare and swap on the attempt's status and version, fenced by `epoch`.
    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
    ) -> Result<Version, StoreError>;
}

/// Nodes of the task graph.
///
/// # Preconditions
/// Either kind of transaction. The job must exist for the scope.
///
/// # Postconditions
/// As for jobs: a new node starts at the machine's initial status and version one.
///
/// # Errors
/// [`StoreError::NotFound`], [`StoreError::Conflict`], [`StoreError::Constraint`] (duplicate id,
/// or a key already used in the job).
///
/// # Idempotency
/// `insert_task_node` is not idempotent. `transition_task_node` is a compare and swap.
#[async_trait]
pub trait TaskNodeOps {
    /// Creates a node in the machine's initial status.
    async fn insert_task_node(
        &mut self,
        new: NewTaskNode,
    ) -> Result<Versioned<TaskNode>, StoreError>;

    /// Reads a node.
    async fn get_task_node(&mut self, id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError>;

    /// Compare and swap on the node's status and version.
    async fn transition_task_node(
        &mut self,
        id: TaskNodeId,
        expected: Version,
        t: AppliedTransition<TaskNodeStatus>,
    ) -> Result<Version, StoreError>;
}

/// The evidence ledger: one append-only, hash-chained list per job (ADR 0008).
///
/// # Preconditions
/// The job exists for the scope. The entry's hashes were computed by domain code
/// (`EvidenceLedgerEntry::sealed`), and the entry's `prev_entry_hash` is the hash of the entry
/// before it.
///
/// # Postconditions
/// After a successful append the job's head is the new entry. `read_ledger` returns entries in
/// ascending sequence with no gaps, and the list verifies with the domain's `verify_chain`. There
/// is no call that changes or removes an entry.
///
/// # Errors
/// [`StoreError::NotFound`] (no such job for the scope); [`StoreError::Conflict`] when the entry's
/// sequence is already taken (another append won; read the head and retry);
/// [`StoreError::ChainBroken`] when the sequence skips ahead, the previous hash is not the head's
/// hash, the entry's own hash does not match its content, or the entry names another job.
///
/// # Idempotency
/// An append is not idempotent: sending the same entry twice conflicts the second time. Reads are
/// reads.
#[async_trait]
pub trait LedgerOps {
    /// Appends at head + 1. The hashes are computed by domain code and checked here.
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError>;

    /// The last entry's sequence and hash, or `None` for a job with no entries.
    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError>;

    /// Entries of the job from sequence `from` (inclusive), in order, at most `limit`.
    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError>;
}

/// The transactional outbox (ADR 0004).
///
/// # Preconditions
/// The event's job exists for the scope and the event's `tenant_id` is the tenant that owns it.
/// An enqueue is made in the same transaction as the state change it announces.
///
/// # Postconditions
/// An enqueued event is visible only after the transaction commits, and then in every read from a
/// position at or before its own. Events of a job read back in the order they were enqueued, each
/// with a higher position than the one before. An event from a rolled-back transaction is never
/// visible.
///
/// # Errors
/// [`StoreError::NotFound`] (no such job for the scope); [`StoreError::TenantMismatch`] (the event
/// names another tenant); [`StoreError::Constraint`] (an event with this id is already queued).
///
/// # Idempotency
/// `enqueue_event` is not idempotent: the event id is unique. Consumers are idempotent by event
/// id (ADR 0004). Reads are reads.
#[async_trait]
pub trait OutboxOps {
    /// Queues an event for delivery.
    async fn enqueue_event(&mut self, event: DomainEvent) -> Result<(), StoreError>;

    /// Events of the job from position `from` (inclusive), in order, at most `limit`.
    async fn read_events(
        &mut self,
        job: JobId,
        from: OutboxSeq,
        limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError>;
}

/// The audit log: who did what, under which policy. Append only.
///
/// # Preconditions
/// The record's job exists for the scope.
///
/// # Postconditions
/// A recorded event is returned by `read_audit` in the order it was recorded. Nothing changes or
/// removes a record.
///
/// # Errors
/// [`StoreError::NotFound`] (no such job for the scope).
///
/// # Idempotency
/// `record_audit` is not idempotent: each call adds a record.
#[async_trait]
pub trait AuditOps {
    /// Append only. The record names the actor, the policy hash and the correlation id.
    async fn record_audit(&mut self, event: AuditEvent) -> Result<(), StoreError>;

    /// The job's audit records in the order they were recorded, at most `limit`.
    async fn read_audit(&mut self, job: JobId, limit: u32) -> Result<Vec<AuditEvent>, StoreError>;
}

/// The tenant's index of the artifacts it holds (ADR 0008).
///
/// # Preconditions
/// Tenant transaction. A `stage_run_id`, when given, belongs to the tenant.
///
/// # Postconditions
/// After `index_artifact` the tenant can read the artifact's row. Another tenant cannot, even
/// when it holds the same bytes under the same hash.
///
/// # Errors
/// [`StoreError::NotFound`] (no row for this tenant, or the stage run is not the tenant's);
/// [`StoreError::ScopeNotAllowed`] (system transaction).
///
/// # Idempotency
/// `index_artifact` is idempotent by hash: a second call for the same hash returns the first row
/// and changes nothing.
#[async_trait]
pub trait ArtifactIndexOps {
    /// Records that the tenant holds the artifact.
    async fn index_artifact(
        &mut self,
        new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError>;

    /// The tenant's row for the hash.
    async fn get_artifact_index(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError>;
}

/// People and services that act on jobs.
///
/// # Preconditions
/// Tenant transaction for `insert_principal`.
///
/// # Postconditions
/// A stored principal is readable by its own tenant only.
///
/// # Errors
/// [`StoreError::NotFound`]; [`StoreError::Constraint`] (duplicate id, or an external reference
/// already recorded for the tenant); [`StoreError::ScopeNotAllowed`].
///
/// # Idempotency
/// `insert_principal` is not idempotent. `get_principal` is a read.
#[async_trait]
pub trait PrincipalOps {
    /// Records a person or service.
    async fn insert_principal(&mut self, new: NewPrincipal) -> Result<Principal, StoreError>;

    /// Reads a principal.
    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError>;
}
