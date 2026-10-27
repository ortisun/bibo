//! An in-memory `Store` that behaves like the real one where the contract can see it.
//!
//! Transactions are optimistic with read-committed reads, which is how the PostgreSQL adapter
//! behaves for the contract's purposes:
//!
//! * A transaction keeps its own writes in an overlay. A read sees the overlay first and then the
//!   latest committed rows, so it reads its own writes and never sees another transaction's
//!   uncommitted ones.
//! * A write checks the version it was given against the row it can see, so a stale update is a
//!   `Conflict` at once.
//! * A commit re-checks every row the transaction wrote against the committed state. If another
//!   transaction committed a change to one of them in the meantime, the commit fails with
//!   `Conflict` and nothing is applied (first committer wins).
//! * `claim_ready` locks the rows it claims until the transaction ends, and skips rows that
//!   another open transaction has locked, like `FOR UPDATE SKIP LOCKED`.
//! * Dropping a transaction without committing discards the overlay and releases the locks.
//!
//! Lease expiry uses the clock given to the store, which plays the part of the database clock.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::{DomainEvent, EvidenceLedgerEntry};
use factory_domain::ids::{AttemptId, JobId, PrincipalId, StageRunId, TaskNodeId, TenantId};
use factory_domain::ledger::ChainHead;
use factory_domain::scope::TenantScope;
use factory_domain::state::{AttemptStatus, JobStatus, StageRunStatus, Status, TaskNodeStatus};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{Clock, duration_between, timestamp_after};
use factory_ports::store::{
    AppliedTransition, ArtifactIndexEntry, ArtifactIndexOps, Attempt, AttemptOps, AuditEvent,
    AuditOps, ClaimedWork, Job, JobOps, Lease, LeaseEpoch, LedgerOps, NewArtifactIndexEntry,
    NewAttempt, NewJob, NewPrincipal, NewStageRun, NewTaskNode, OutboxOps, OutboxRow, OutboxSeq,
    Principal, PrincipalOps, SchemaVersion, Sequence, StageRun, StageRunOps, Store, StoreError,
    SystemScope, TaskNode, TaskNodeOps, Tx, Version, Versioned, WorkerId,
};

/// The schema version the in-memory store reports.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);

/// A deliberate fault, for proving that the contract suite can fail. Each one makes the store
/// break one rule of the `Store` contract. A store built with a defect is never used for anything
/// but that proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDefect {
    /// `claim_ready` ignores existing leases and row locks, so one stage run goes to two workers.
    DoubleGrantsLease,
    /// Lease epochs are not compared, so a worker that lost its lease can still write.
    IgnoresLeaseEpoch,
    /// The `expected` version of an update is not compared, so there is no compare and swap.
    SkipsVersionCheck,
    /// Commit silently drops the last outbox row the transaction queued.
    LosesLastOutboxRow,
    /// `read_events` returns events newest first.
    ReversesOutboxOrder,
    /// Rows of every tenant are visible to every tenant scope.
    ReadsAcrossTenants,
    /// A ledger append does not check the previous hash or the entry's own hash.
    AcceptsBrokenChain,
    /// A transaction that is dropped without commit keeps its writes.
    KeepsWritesOnDrop,
}

#[derive(Clone)]
struct Row<T> {
    value: T,
    version: Version,
}

#[derive(Clone)]
struct LeaseRow {
    epoch: LeaseEpoch,
    lease: Option<Lease>,
}

#[derive(Clone)]
struct StoredEvent {
    seq: OutboxSeq,
    job: JobId,
    event: DomainEvent,
}

#[derive(Clone, Default)]
struct Tables {
    jobs: BTreeMap<JobId, Row<Job>>,
    stage_runs: BTreeMap<StageRunId, Row<StageRun>>,
    leases: BTreeMap<StageRunId, LeaseRow>,
    attempts: BTreeMap<AttemptId, Row<Attempt>>,
    task_nodes: BTreeMap<TaskNodeId, Row<TaskNode>>,
    principals: BTreeMap<PrincipalId, Principal>,
    artifacts: BTreeMap<(TenantId, String), ArtifactIndexEntry>,
    ledger: BTreeMap<JobId, Vec<EvidenceLedgerEntry>>,
    events: Vec<StoredEvent>,
    audit: Vec<(JobId, AuditEvent)>,
}

/// For each row a transaction wrote, the committed version it saw when it first wrote it
/// (`None` when it created the row). A commit succeeds only if the committed state still agrees.
#[derive(Default)]
struct Bases {
    jobs: BTreeMap<JobId, Option<Version>>,
    stage_runs: BTreeMap<StageRunId, Option<Version>>,
    leases: BTreeMap<StageRunId, LeaseEpoch>,
    attempts: BTreeMap<AttemptId, Option<Version>>,
    task_nodes: BTreeMap<TaskNodeId, Option<Version>>,
    principals: BTreeSet<PrincipalId>,
    ledger: BTreeMap<JobId, usize>,
}

#[derive(Default)]
struct Shared {
    committed: Tables,
    next_outbox: u64,
    next_tx: u64,
    locks: HashMap<StageRunId, u64>,
}

/// An in-memory store. Reports fidelity `fake`.
pub struct InMemoryStore {
    shared: Arc<Mutex<Shared>>,
    clock: Arc<dyn Clock>,
    defect: Option<StoreDefect>,
}

impl InMemoryStore {
    /// An empty store whose database clock is `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
            clock,
            defect: None,
        }
    }

    /// An empty store that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(clock: Arc<dyn Clock>, defect: StoreDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::new(clock)
        }
    }

    fn open(&self, scope: Scope) -> Box<dyn Tx> {
        let mut shared = lock(&self.shared);
        shared.next_tx += 1;
        let id = shared.next_tx;
        drop(shared);
        Box::new(InMemoryTx {
            shared: Arc::clone(&self.shared),
            clock: Arc::clone(&self.clock),
            defect: self.defect,
            id,
            scope,
            over: Tables::default(),
            bases: Bases::default(),
            locked: Vec::new(),
            finished: false,
        })
    }
}

#[async_trait]
impl Store for InMemoryStore {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError> {
        Ok(self.open(Scope::Tenant(scope.tenant_id())))
    }

    async fn begin_system(&self, _scope: SystemScope) -> Result<Box<dyn Tx>, StoreError> {
        Ok(self.open(Scope::System))
    }

    async fn schema_version(&self) -> Result<SchemaVersion, StoreError> {
        Ok(SCHEMA_VERSION)
    }
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().expect("the store lock is never poisoned")
}

#[derive(Clone, Copy)]
enum Scope {
    Tenant(TenantId),
    System,
}

struct InMemoryTx {
    shared: Arc<Mutex<Shared>>,
    clock: Arc<dyn Clock>,
    defect: Option<StoreDefect>,
    id: u64,
    scope: Scope,
    over: Tables,
    bases: Bases,
    locked: Vec<StageRunId>,
    finished: bool,
}

/// The new status and version after a compare and swap, or the reason it was refused.
fn swap<S: Status>(
    stored_status: S,
    stored_version: Version,
    expected: Version,
    t: &AppliedTransition<S>,
    skip_version_check: bool,
) -> Result<(S, Version), StoreError> {
    if !skip_version_check && stored_version != expected {
        return Err(StoreError::Conflict);
    }
    if stored_status != t.from_status() {
        return Err(StoreError::Conflict);
    }
    let next = stored_version
        .next()
        .map_err(|_| StoreError::Constraint("the version counter is exhausted".to_owned()))?;
    Ok((t.to_status(), next))
}

impl InMemoryTx {
    fn has(&self, defect: StoreDefect) -> bool {
        self.defect == Some(defect)
    }

    fn sees(&self, tenant: TenantId) -> bool {
        match self.scope {
            Scope::System => true,
            Scope::Tenant(own) => own == tenant || self.has(StoreDefect::ReadsAcrossTenants),
        }
    }

    fn tenant(&self) -> Result<TenantId, StoreError> {
        match self.scope {
            Scope::Tenant(tenant) => Ok(tenant),
            Scope::System => Err(StoreError::ScopeNotAllowed),
        }
    }

    fn require_system(&self) -> Result<(), StoreError> {
        match self.scope {
            Scope::System => Ok(()),
            Scope::Tenant(_) => Err(StoreError::ScopeNotAllowed),
        }
    }

    // ---- reads: the overlay first, then the latest committed rows -------------------------

    fn job_row(&self, g: &Shared, id: JobId) -> Result<Row<Job>, StoreError> {
        let row = self
            .over
            .jobs
            .get(&id)
            .or_else(|| g.committed.jobs.get(&id))
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if self.sees(row.value.tenant_id) {
            Ok(row)
        } else {
            Err(StoreError::NotFound)
        }
    }

    fn lease_row(&self, g: &Shared, id: StageRunId) -> LeaseRow {
        self.over
            .leases
            .get(&id)
            .or_else(|| g.committed.leases.get(&id))
            .cloned()
            .unwrap_or(LeaseRow {
                epoch: LeaseEpoch::NEVER_CLAIMED,
                lease: None,
            })
    }

    fn stage_run_row(&self, g: &Shared, id: StageRunId) -> Result<Row<StageRun>, StoreError> {
        let mut row = self
            .over
            .stage_runs
            .get(&id)
            .or_else(|| g.committed.stage_runs.get(&id))
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if !self.sees(row.value.tenant_id) {
            return Err(StoreError::NotFound);
        }
        let lease = self.lease_row(g, id);
        row.value.lease_epoch = lease.epoch;
        row.value.lease = lease.lease;
        Ok(row)
    }

    fn attempt_row(&self, g: &Shared, id: AttemptId) -> Result<Row<Attempt>, StoreError> {
        let row = self
            .over
            .attempts
            .get(&id)
            .or_else(|| g.committed.attempts.get(&id))
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if self.sees(row.value.tenant_id) {
            Ok(row)
        } else {
            Err(StoreError::NotFound)
        }
    }

    fn task_node_row(&self, g: &Shared, id: TaskNodeId) -> Result<Row<TaskNode>, StoreError> {
        let row = self
            .over
            .task_nodes
            .get(&id)
            .or_else(|| g.committed.task_nodes.get(&id))
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if self.sees(row.value.tenant_id) {
            Ok(row)
        } else {
            Err(StoreError::NotFound)
        }
    }

    fn principal_row(&self, g: &Shared, id: PrincipalId) -> Result<Principal, StoreError> {
        let row = self
            .over
            .principals
            .get(&id)
            .or_else(|| g.committed.principals.get(&id))
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if self.sees(row.tenant_id) {
            Ok(row)
        } else {
            Err(StoreError::NotFound)
        }
    }

    fn ledger_chain(&self, g: &Shared, job: JobId) -> Vec<EvidenceLedgerEntry> {
        let mut chain = g.committed.ledger.get(&job).cloned().unwrap_or_default();
        if let Some(own) = self.over.ledger.get(&job) {
            chain.extend(own.iter().cloned());
        }
        chain
    }

    // ---- writes: the overlay, with the committed version noted on first touch ------------

    fn put_job(&mut self, g: &Shared, row: Row<Job>) {
        let id = row.value.id;
        self.bases
            .jobs
            .entry(id)
            .or_insert_with(|| g.committed.jobs.get(&id).map(|r| r.version));
        self.over.jobs.insert(id, row);
    }

    fn put_stage_run(&mut self, g: &Shared, row: Row<StageRun>) {
        let id = row.value.id;
        self.bases
            .stage_runs
            .entry(id)
            .or_insert_with(|| g.committed.stage_runs.get(&id).map(|r| r.version));
        self.over.stage_runs.insert(id, row);
    }

    fn put_lease(&mut self, g: &Shared, id: StageRunId, row: LeaseRow) {
        self.bases.leases.entry(id).or_insert_with(|| {
            g.committed
                .leases
                .get(&id)
                .map_or(LeaseEpoch::NEVER_CLAIMED, |l| l.epoch)
        });
        self.over.leases.insert(id, row);
    }

    fn put_attempt(&mut self, g: &Shared, row: Row<Attempt>) {
        let id = row.value.id;
        self.bases
            .attempts
            .entry(id)
            .or_insert_with(|| g.committed.attempts.get(&id).map(|r| r.version));
        self.over.attempts.insert(id, row);
    }

    fn put_task_node(&mut self, g: &Shared, row: Row<TaskNode>) {
        let id = row.value.id;
        self.bases
            .task_nodes
            .entry(id)
            .or_insert_with(|| g.committed.task_nodes.get(&id).map(|r| r.version));
        self.over.task_nodes.insert(id, row);
    }

    fn release_locks(&mut self) {
        if self.locked.is_empty() {
            return;
        }
        let mut g = lock(&self.shared);
        for id in self.locked.drain(..) {
            if g.locks.get(&id) == Some(&self.id) {
                g.locks.remove(&id);
            }
        }
    }

    /// Checks every row this transaction wrote against the committed state.
    fn validate_commit(&self, g: &Shared) -> Result<(), StoreError> {
        macro_rules! unchanged {
            ($bases:expr, $table:ident) => {
                for (id, base) in &$bases {
                    let now = g.committed.$table.get(id).map(|r| r.version);
                    if now != *base {
                        return Err(StoreError::Conflict);
                    }
                }
            };
        }
        unchanged!(self.bases.jobs, jobs);
        unchanged!(self.bases.stage_runs, stage_runs);
        unchanged!(self.bases.attempts, attempts);
        unchanged!(self.bases.task_nodes, task_nodes);
        for (id, base) in &self.bases.leases {
            let now = g
                .committed
                .leases
                .get(id)
                .map_or(LeaseEpoch::NEVER_CLAIMED, |l| l.epoch);
            if now != *base {
                return Err(StoreError::Conflict);
            }
        }
        for id in &self.bases.principals {
            if g.committed.principals.contains_key(id) {
                return Err(StoreError::Conflict);
            }
        }
        for (job, base) in &self.bases.ledger {
            let now = g.committed.ledger.get(job).map_or(0, Vec::len);
            if now != *base {
                return Err(StoreError::Conflict);
            }
        }
        for pending in &self.over.events {
            if g.committed
                .events
                .iter()
                .any(|stored| stored.event.event_id == pending.event.event_id)
            {
                return Err(StoreError::Conflict);
            }
        }
        Ok(())
    }

    /// Makes the overlay the committed state.
    fn apply(&mut self, g: &mut Shared) {
        let over = std::mem::take(&mut self.over);
        g.committed.jobs.extend(over.jobs);
        g.committed.stage_runs.extend(over.stage_runs);
        g.committed.leases.extend(over.leases);
        g.committed.attempts.extend(over.attempts);
        g.committed.task_nodes.extend(over.task_nodes);
        g.committed.principals.extend(over.principals);
        for (key, entry) in over.artifacts {
            g.committed.artifacts.entry(key).or_insert(entry);
        }
        for (job, mut entries) in over.ledger {
            g.committed
                .ledger
                .entry(job)
                .or_default()
                .append(&mut entries);
        }
        let mut events = over.events;
        if self.has(StoreDefect::LosesLastOutboxRow) {
            events.pop();
        }
        g.committed.events.extend(events);
        g.committed.audit.extend(over.audit);
    }
}

impl Drop for InMemoryTx {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.has(StoreDefect::KeepsWritesOnDrop) {
            let arc = Arc::clone(&self.shared);
            let mut g = lock(&arc);
            self.apply(&mut g);
        }
        self.release_locks();
    }
}

#[async_trait]
impl Tx for InMemoryTx {
    async fn database_time(&mut self) -> Result<Timestamp, StoreError> {
        Ok(self.clock.now())
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StoreError> {
        self.finished = true;
        let outcome = {
            let arc = Arc::clone(&self.shared);
            let mut g = lock(&arc);
            match self.validate_commit(&g) {
                Ok(()) => {
                    self.apply(&mut g);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        self.release_locks();
        outcome
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), StoreError> {
        self.finished = true;
        self.release_locks();
        Ok(())
    }
}

#[async_trait]
impl JobOps for InMemoryTx {
    async fn insert_job(&mut self, new: NewJob) -> Result<Versioned<Job>, StoreError> {
        let tenant = self.tenant()?;
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        if self.job_row(&g, new.id).is_ok() || g.committed.jobs.contains_key(&new.id) {
            return Err(StoreError::Constraint(
                "a job with this id exists".to_owned(),
            ));
        }
        match self.principal_row(&g, new.requester) {
            Ok(principal) if principal.tenant_id == tenant => {}
            _ => {
                return Err(StoreError::Constraint(
                    "the requester is not a principal of this tenant".to_owned(),
                ));
            }
        }
        let job = Job {
            id: new.id,
            tenant_id: tenant,
            correlation_id: new.correlation_id,
            requester: new.requester,
            status: JobStatus::INITIAL,
            created_at: new.created_at,
        };
        let row = Row {
            value: job.clone(),
            version: Version::FIRST,
        };
        self.put_job(&g, row);
        Ok(Versioned {
            value: job,
            version: Version::FIRST,
        })
    }

    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let row = self.job_row(&g, id)?;
        Ok(Versioned {
            value: row.value,
            version: row.version,
        })
    }

    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let mut row = self.job_row(&g, id)?;
        let (status, version) = swap(
            row.value.status,
            row.version,
            expected,
            &t,
            self.has(StoreDefect::SkipsVersionCheck),
        )?;
        row.value.status = status;
        row.version = version;
        self.put_job(&g, row);
        Ok(version)
    }
}

#[async_trait]
impl StageRunOps for InMemoryTx {
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Versioned<StageRun>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let job = self.job_row(&g, new.job_id)?;
        if self.stage_run_row(&g, new.id).is_ok() || g.committed.stage_runs.contains_key(&new.id) {
            return Err(StoreError::Constraint(
                "a stage run with this id exists".to_owned(),
            ));
        }
        let run = StageRun {
            id: new.id,
            tenant_id: job.value.tenant_id,
            job_id: new.job_id,
            kind: new.kind,
            status: StageRunStatus::INITIAL,
            lease_epoch: LeaseEpoch::NEVER_CLAIMED,
            lease: None,
            created_at: new.created_at,
        };
        let row = Row {
            value: run.clone(),
            version: Version::FIRST,
        };
        self.put_stage_run(&g, row);
        Ok(Versioned {
            value: run,
            version: Version::FIRST,
        })
    }

    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let row = self.stage_run_row(&g, id)?;
        Ok(Versioned {
            value: row.value,
            version: row.version,
        })
    }

    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
    ) -> Result<Version, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let mut row = self.stage_run_row(&g, id)?;
        let (status, version) = swap(
            row.value.status,
            row.version,
            expected,
            &t,
            self.has(StoreDefect::SkipsVersionCheck),
        )?;
        row.value.status = status;
        row.version = version;
        self.put_stage_run(&g, row);
        Ok(version)
    }

    async fn claim_ready(
        &mut self,
        worker: &WorkerId,
        limit: u32,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedWork>, StoreError> {
        self.require_system()?;
        let now = self.clock.now();
        let arc = Arc::clone(&self.shared);
        let mut g = lock(&arc);
        let double_grant = self.has(StoreDefect::DoubleGrantsLease);

        let mut ids: BTreeSet<StageRunId> = g.committed.stage_runs.keys().copied().collect();
        ids.extend(self.over.stage_runs.keys().copied());
        let mut candidates: Vec<Row<StageRun>> = Vec::new();
        for id in ids {
            let row = self.stage_run_row(&g, id)?;
            if row.value.status != StageRunStatus::Ready {
                continue;
            }
            let lease_is_current = row
                .value
                .lease
                .as_ref()
                .is_some_and(|lease| lease.expires_at > now);
            let locked_by_other = g.locks.get(&id).is_some_and(|owner| *owner != self.id);
            if !double_grant && (lease_is_current || locked_by_other) {
                continue;
            }
            candidates.push(row);
        }
        candidates.sort_by_key(|row| (row.value.created_at, row.value.id));

        let mut claimed = Vec::new();
        let mut updates = Vec::new();
        for row in candidates.into_iter().take(limit as usize) {
            let epoch = row.value.lease_epoch.next();
            let lease = Lease {
                worker: worker.clone(),
                epoch,
                expires_at: timestamp_after(&now, lease_ttl),
                ttl: lease_ttl,
            };
            let mut stage_run = row.value.clone();
            stage_run.lease_epoch = epoch;
            stage_run.lease = Some(lease.clone());
            updates.push((stage_run.id, epoch, lease.clone()));
            claimed.push(ClaimedWork {
                stage_run: Versioned {
                    value: stage_run,
                    version: row.version,
                },
                lease,
            });
        }
        for (id, epoch, lease) in updates {
            self.put_lease(
                &g,
                id,
                LeaseRow {
                    epoch,
                    lease: Some(lease),
                },
            );
            g.locks.insert(id, self.id);
            self.locked.push(id);
        }
        Ok(claimed)
    }

    async fn expired_leases(&mut self, limit: u32) -> Result<Vec<AttemptId>, StoreError> {
        self.require_system()?;
        let now = self.clock.now();
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let mut ids: BTreeSet<AttemptId> = g.committed.attempts.keys().copied().collect();
        ids.extend(self.over.attempts.keys().copied());
        let mut expired: Vec<(Timestamp, AttemptId)> = Vec::new();
        for id in ids {
            let attempt = self.attempt_row(&g, id)?.value;
            if !matches!(
                attempt.status,
                AttemptStatus::Starting | AttemptStatus::Running
            ) {
                continue;
            }
            let lease = self.lease_row(&g, attempt.stage_run_id).lease;
            let ended = lease.is_some_and(|l| l.epoch == attempt.epoch && l.expires_at <= now);
            if ended {
                expired.push((attempt.created_at, attempt.id));
            }
        }
        expired.sort();
        Ok(expired
            .into_iter()
            .take(limit as usize)
            .map(|(_, id)| id)
            .collect())
    }
}

#[async_trait]
impl AttemptOps for InMemoryTx {
    async fn insert_attempt(&mut self, new: NewAttempt) -> Result<Versioned<Attempt>, StoreError> {
        let now = self.clock.now();
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let run = self.stage_run_row(&g, new.stage_run_id)?;
        let lease = self.lease_row(&g, new.stage_run_id);
        let current = lease
            .lease
            .as_ref()
            .is_some_and(|l| l.epoch == new.epoch && l.expires_at > now);
        if !self.has(StoreDefect::IgnoresLeaseEpoch) && !current {
            return Err(StoreError::LeaseFenced);
        }
        if self.attempt_row(&g, new.id).is_ok() || g.committed.attempts.contains_key(&new.id) {
            return Err(StoreError::Constraint(
                "an attempt with this id exists".to_owned(),
            ));
        }
        let mut earlier = 0_u32;
        let mut ids: BTreeSet<AttemptId> = g.committed.attempts.keys().copied().collect();
        ids.extend(self.over.attempts.keys().copied());
        for id in ids {
            if self
                .attempt_row(&g, id)
                .is_ok_and(|row| row.value.stage_run_id == new.stage_run_id)
            {
                earlier += 1;
            }
        }
        let worker = match lease.lease {
            Some(l) => l.worker,
            None => WorkerId::new("unknown")
                .map_err(|_| StoreError::Constraint("worker id".to_owned()))?,
        };
        let attempt = Attempt {
            id: new.id,
            tenant_id: run.value.tenant_id,
            job_id: run.value.job_id,
            stage_run_id: new.stage_run_id,
            number: earlier + 1,
            status: AttemptStatus::INITIAL,
            worker,
            epoch: new.epoch,
            created_at: new.created_at,
        };
        let row = Row {
            value: attempt.clone(),
            version: Version::FIRST,
        };
        self.put_attempt(&g, row);
        Ok(Versioned {
            value: attempt,
            version: Version::FIRST,
        })
    }

    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let row = self.attempt_row(&g, id)?;
        Ok(Versioned {
            value: row.value,
            version: row.version,
        })
    }

    async fn heartbeat(&mut self, id: AttemptId, epoch: LeaseEpoch) -> Result<(), StoreError> {
        let now = self.clock.now();
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let attempt = self.attempt_row(&g, id)?.value;
        if attempt.status.is_terminal() {
            return Err(StoreError::Conflict);
        }
        let mut lease_row = self.lease_row(&g, attempt.stage_run_id);
        let lease_ok = lease_row
            .lease
            .as_ref()
            .is_some_and(|l| l.epoch == epoch && attempt.epoch == epoch && l.expires_at > now);
        if !lease_ok && !self.has(StoreDefect::IgnoresLeaseEpoch) {
            return Err(StoreError::LeaseFenced);
        }
        if let Some(lease) = lease_row.lease.as_mut() {
            lease.expires_at = timestamp_after(&now, lease.ttl);
        }
        self.put_lease(&g, attempt.stage_run_id, lease_row);
        Ok(())
    }

    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
    ) -> Result<Version, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let mut row = self.attempt_row(&g, id)?;
        let current = self.lease_row(&g, row.value.stage_run_id).epoch;
        if !self.has(StoreDefect::IgnoresLeaseEpoch)
            && (row.value.epoch != epoch || current != epoch)
        {
            return Err(StoreError::LeaseFenced);
        }
        let (status, version) = swap(
            row.value.status,
            row.version,
            expected,
            &t,
            self.has(StoreDefect::SkipsVersionCheck),
        )?;
        row.value.status = status;
        row.version = version;
        self.put_attempt(&g, row);
        Ok(version)
    }
}

#[async_trait]
impl TaskNodeOps for InMemoryTx {
    async fn insert_task_node(
        &mut self,
        new: NewTaskNode,
    ) -> Result<Versioned<TaskNode>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let job = self.job_row(&g, new.job_id)?;
        if self.task_node_row(&g, new.id).is_ok() || g.committed.task_nodes.contains_key(&new.id) {
            return Err(StoreError::Constraint(
                "a task node with this id exists".to_owned(),
            ));
        }
        let mut ids: BTreeSet<TaskNodeId> = g.committed.task_nodes.keys().copied().collect();
        ids.extend(self.over.task_nodes.keys().copied());
        let key_taken = ids.into_iter().any(|id| {
            self.task_node_row(&g, id)
                .is_ok_and(|row| row.value.job_id == new.job_id && row.value.key == new.key)
        });
        if key_taken {
            return Err(StoreError::Constraint(
                "the key is already used in this job".to_owned(),
            ));
        }
        let node = TaskNode {
            id: new.id,
            tenant_id: job.value.tenant_id,
            job_id: new.job_id,
            key: new.key,
            status: TaskNodeStatus::INITIAL,
            created_at: new.created_at,
        };
        let row = Row {
            value: node.clone(),
            version: Version::FIRST,
        };
        self.put_task_node(&g, row);
        Ok(Versioned {
            value: node,
            version: Version::FIRST,
        })
    }

    async fn get_task_node(&mut self, id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let row = self.task_node_row(&g, id)?;
        Ok(Versioned {
            value: row.value,
            version: row.version,
        })
    }

    async fn transition_task_node(
        &mut self,
        id: TaskNodeId,
        expected: Version,
        t: AppliedTransition<TaskNodeStatus>,
    ) -> Result<Version, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let mut row = self.task_node_row(&g, id)?;
        let (status, version) = swap(
            row.value.status,
            row.version,
            expected,
            &t,
            self.has(StoreDefect::SkipsVersionCheck),
        )?;
        row.value.status = status;
        row.version = version;
        self.put_task_node(&g, row);
        Ok(version)
    }
}

#[async_trait]
impl LedgerOps for InMemoryTx {
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError> {
        let job = entry.metadata.job_id;
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.job_row(&g, job)?;
        let chain = self.ledger_chain(&g, job);
        let height = chain.len() as u64;
        let sequence = entry.sequence();
        if sequence <= height {
            return Err(StoreError::Conflict);
        }
        if sequence > height + 1 {
            return Err(StoreError::ChainBroken);
        }
        if !self.has(StoreDefect::AcceptsBrokenChain) {
            let head_hash = chain.last().map(|last| &last.entry_hash);
            if entry.prev_entry_hash.as_ref() != head_hash {
                return Err(StoreError::ChainBroken);
            }
            match entry.computed_hash() {
                Ok(computed) if computed == entry.entry_hash => {}
                _ => return Err(StoreError::ChainBroken),
            }
        }
        let head = ChainHead {
            sequence,
            hash: entry.entry_hash.clone(),
        };
        let committed_len = g.committed.ledger.get(&job).map_or(0, Vec::len);
        self.bases.ledger.entry(job).or_insert(committed_len);
        self.over.ledger.entry(job).or_default().push(entry);
        Ok(head)
    }

    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.job_row(&g, job)?;
        Ok(self.ledger_chain(&g, job).last().map(|last| ChainHead {
            sequence: last.sequence(),
            hash: last.entry_hash.clone(),
        }))
    }

    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.job_row(&g, job)?;
        Ok(self
            .ledger_chain(&g, job)
            .into_iter()
            .filter(|entry| entry.sequence() >= from)
            .take(limit as usize)
            .collect())
    }
}

#[async_trait]
impl OutboxOps for InMemoryTx {
    async fn enqueue_event(&mut self, event: DomainEvent) -> Result<(), StoreError> {
        let arc = Arc::clone(&self.shared);
        let mut g = lock(&arc);
        let job = self.job_row(&g, event.job_id)?;
        if event.tenant_id != job.value.tenant_id {
            return Err(StoreError::TenantMismatch);
        }
        let taken = g
            .committed
            .events
            .iter()
            .chain(self.over.events.iter())
            .any(|stored| stored.event.event_id == event.event_id);
        if taken {
            return Err(StoreError::Constraint(
                "an event with this id is queued".to_owned(),
            ));
        }
        g.next_outbox += 1;
        let seq = OutboxSeq::new(g.next_outbox);
        self.over.events.push(StoredEvent {
            seq,
            job: event.job_id,
            event,
        });
        Ok(())
    }

    async fn read_events(
        &mut self,
        job: JobId,
        from: OutboxSeq,
        limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.job_row(&g, job)?;
        let mut rows: Vec<OutboxRow> = g
            .committed
            .events
            .iter()
            .chain(self.over.events.iter())
            .filter(|stored| stored.job == job && stored.seq >= from)
            .map(|stored| OutboxRow {
                seq: stored.seq,
                event: stored.event.clone(),
            })
            .collect();
        rows.sort_by_key(|row| row.seq);
        if self.has(StoreDefect::ReversesOutboxOrder) {
            rows.reverse();
        }
        rows.truncate(limit as usize);
        Ok(rows)
    }
}

#[async_trait]
impl AuditOps for InMemoryTx {
    async fn record_audit(&mut self, event: AuditEvent) -> Result<(), StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.job_row(&g, event.job_id)?;
        let job = event.job_id;
        self.over.audit.push((job, event));
        Ok(())
    }

    async fn read_audit(&mut self, job: JobId, limit: u32) -> Result<Vec<AuditEvent>, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.job_row(&g, job)?;
        Ok(g.committed
            .audit
            .iter()
            .chain(self.over.audit.iter())
            .filter(|(owner, _)| *owner == job)
            .map(|(_, event)| event.clone())
            .take(limit as usize)
            .collect())
    }
}

#[async_trait]
impl ArtifactIndexOps for InMemoryTx {
    async fn index_artifact(
        &mut self,
        new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        let tenant = self.tenant()?;
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        if let Some(run) = new.stage_run_id {
            self.stage_run_row(&g, run)?;
        }
        let key = (tenant, new.artifact.sha256.to_string());
        if let Some(existing) = self
            .over
            .artifacts
            .get(&key)
            .or_else(|| g.committed.artifacts.get(&key))
        {
            return Ok(existing.clone());
        }
        let entry = ArtifactIndexEntry {
            tenant_id: tenant,
            artifact: new.artifact,
            stage_run_id: new.stage_run_id,
            created_at: new.created_at,
        };
        self.over.artifacts.insert(key, entry.clone());
        Ok(entry)
    }

    async fn get_artifact_index(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        let tenant = self.tenant()?;
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        let key = (tenant, sha256.to_string());
        self.over
            .artifacts
            .get(&key)
            .or_else(|| g.committed.artifacts.get(&key))
            .cloned()
            .ok_or(StoreError::NotFound)
    }
}

#[async_trait]
impl PrincipalOps for InMemoryTx {
    async fn insert_principal(&mut self, new: NewPrincipal) -> Result<Principal, StoreError> {
        let tenant = self.tenant()?;
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        if self.principal_row(&g, new.id).is_ok() || g.committed.principals.contains_key(&new.id) {
            return Err(StoreError::Constraint(
                "a principal with this id exists".to_owned(),
            ));
        }
        let reference_taken = g
            .committed
            .principals
            .values()
            .chain(self.over.principals.values())
            .any(|p| p.tenant_id == tenant && p.external_ref == new.external_ref);
        if reference_taken {
            return Err(StoreError::Constraint(
                "the external reference is already recorded for this tenant".to_owned(),
            ));
        }
        let principal = Principal {
            id: new.id,
            tenant_id: tenant,
            external_ref: new.external_ref,
            created_at: new.created_at,
        };
        self.bases.principals.insert(new.id);
        self.over.principals.insert(new.id, principal.clone());
        Ok(principal)
    }

    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        let arc = Arc::clone(&self.shared);
        let g = lock(&arc);
        self.principal_row(&g, id)
    }
}

/// How far a lease has run, for tests that want to read it: the time left at `now`, or `None`
/// when it already ended.
#[must_use]
pub fn time_left(lease: &Lease, now: &Timestamp) -> Option<Duration> {
    duration_between(now, &lease.expires_at)
}

/// The in-memory store packaged as a subject of the store contract suite.
pub struct InMemoryStoreSubject {
    clock: Arc<crate::clock::FakeClock>,
    store: InMemoryStore,
}

impl InMemoryStoreSubject {
    /// A faithful store with its own clock.
    #[must_use]
    pub fn new() -> Self {
        let clock = Arc::new(crate::clock::FakeClock::new());
        let store = InMemoryStore::new(clock.clone());
        Self { clock, store }
    }

    /// A store that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: StoreDefect) -> Self {
        let clock = Arc::new(crate::clock::FakeClock::new());
        let store = InMemoryStore::with_defect(clock.clone(), defect);
        Self { clock, store }
    }
}

impl Default for InMemoryStoreSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::contracts::store::StoreSubject for InMemoryStoreSubject {
    fn store(&self) -> &dyn Store {
        &self.store
    }

    async fn advance_database_time(&self, by: Duration) {
        self.clock.advance(by);
    }
}
