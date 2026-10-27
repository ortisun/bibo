//! `PgTx`: a tenant transaction.
//!
//! A tenant transaction starts like this, in this order, and nothing else comes first:
//!
//! 1. `BEGIN`;
//! 2. `SELECT set_config('factory.tenant_id', $1, true)` with the tenant as a bound parameter.
//!    The third argument `true` ties the setting to the transaction, so it ends at commit or
//!    rollback and cannot reach the next borrower of the connection. The value is never written
//!    into the statement text, so neither `pg_stat_activity` nor the logs carry it.
//!
//! The type has no method that runs raw SQL or changes the setting. After the first database error
//! that PostgreSQL counts as an error of the transaction (for example a constraint violation),
//! PostgreSQL refuses every later statement of that transaction, and the store reports
//! `Unavailable` for them. The caller rolls back. Errors that the store detects before it writes
//! (`Conflict` on a stale version, `NotFound`, `LeaseFenced`, `TenantMismatch`) leave the
//! transaction usable.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Text, Timestamptz};
use diesel_async::{AnsiTransactionManager, AsyncPgConnection, RunQueryDsl, TransactionManager};
use factory_domain::contracts::{DomainEvent, EvidenceLedgerEntry};
use factory_domain::ids::{AttemptId, JobId, PrincipalId, StageRunId, TaskNodeId, TenantId};
use factory_domain::ledger::ChainHead;
use factory_domain::state::{AttemptStatus, JobStatus, StageRunStatus, TaskNodeStatus};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_ports::store::{
    AppliedTransition, ArtifactIndexEntry, ArtifactIndexOps, Attempt, AttemptOps, AuditEvent,
    AuditOps, ClaimedWork, Job, JobOps, LeaseEpoch, LedgerOps, NewArtifactIndexEntry, NewAttempt,
    NewJob, NewPrincipal, NewStageRun, NewTaskNode, OutboxOps, OutboxRow, OutboxSeq, Principal,
    PrincipalOps, Sequence, StageRun, StageRunOps, StoreError, TaskNode, TaskNodeOps, Tx, Version,
    Versioned, WorkerId,
};
use time::OffsetDateTime;

use super::error::{Failure, constraint, generic};
use super::pool::PooledConnection;
use super::store::{Settings, Shared};
use super::{
    artifact_index, attempts, audit, jobs, ledger, outbox, principals, stage_runs, task_nodes,
};

/// An open tenant transaction.
pub struct PgTx {
    connection: Option<PooledConnection>,
    tenant: TenantId,
    shared: Arc<Shared>,
}

/// Starts a transaction on `connection` and makes the tenant setting, in that order.
pub(super) async fn start(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
) -> Result<(), StoreError> {
    <AnsiTransactionManager as TransactionManager<AsyncPgConnection>>::begin_transaction(
        connection,
    )
    .await
    .map_err(|error| generic("begin", &error))?;
    sql_query("SELECT set_config('factory.tenant_id', $1, true)")
        .bind::<Text, _>(tenant.to_string())
        .execute(connection)
        .await
        .map_err(|error| generic("begin", &error))?;
    Ok(())
}

pub(super) async fn finish_commit(connection: &mut AsyncPgConnection) -> Result<(), StoreError> {
    <AnsiTransactionManager as TransactionManager<AsyncPgConnection>>::commit_transaction(
        connection,
    )
    .await
    .map_err(|error| map_commit_error(&error))
}

pub(super) async fn finish_rollback(connection: &mut AsyncPgConnection) -> Result<(), StoreError> {
    <AnsiTransactionManager as TransactionManager<AsyncPgConnection>>::rollback_transaction(
        connection,
    )
    .await
    .map_err(|error| generic("rollback", &error))
}

/// Errors that arrive at commit, because the checks that span rows are deferred.
fn map_commit_error(error: &diesel::result::Error) -> StoreError {
    match Failure::of(error) {
        Failure::Check(Some(name)) if name == "attempts_live_attempt_has_current_epoch" => {
            StoreError::LeaseFenced
        }
        Failure::Check(Some(name)) if name.starts_with("outbox_aggregate_") => {
            constraint("check violation", Some(&name))
        }
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
        Failure::Unique(_) | Failure::Serialization => StoreError::Conflict,
        _ => generic("commit", error),
    }
}

/// Hands a connection with an open transaction back without waiting for the database.
///
/// With a runtime at hand the rollback runs as a task, which the store remembers, and the next
/// `begin` waits for it. Without a runtime the connection is closed, which makes the server end
/// the transaction.
pub(super) fn abandon(shared: &Arc<Shared>, connection: PooledConnection) {
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            let task = runtime.spawn(async move {
                let mut connection = connection;
                if finish_rollback(&mut connection).await.is_err() {
                    drop(PooledConnection::take(connection));
                }
            });
            shared.track_rollback(task);
        }
        Err(_) => drop(PooledConnection::take(connection)),
    }
}

#[derive(QueryableByName)]
struct DatabaseNow {
    #[diesel(sql_type = Timestamptz)]
    now: OffsetDateTime,
}

/// The database clock, read on any connection.
pub(super) async fn database_now(
    connection: &mut AsyncPgConnection,
) -> Result<Timestamp, StoreError> {
    let row = sql_query("SELECT clock_timestamp() AS now")
        .get_result::<DatabaseNow>(connection)
        .await
        .map_err(|error| generic("database_time", &error))?;
    Ok(Timestamp::from_utc(row.now))
}

impl PgTx {
    pub(super) async fn begin(shared: Arc<Shared>, tenant: TenantId) -> Result<Self, StoreError> {
        shared.settle_rollbacks().await;
        let mut connection = shared.tenant_pool.get().await?;
        start(&mut connection, tenant).await?;
        Ok(Self {
            connection: Some(connection),
            tenant,
            shared,
        })
    }

    pub(super) const fn tenant(&self) -> TenantId {
        self.tenant
    }

    fn parts(&mut self) -> Result<(&mut AsyncPgConnection, TenantId, &Settings), StoreError> {
        let connection = self.connection.as_mut().ok_or(StoreError::Unavailable)?;
        Ok((&mut **connection, self.tenant, &self.shared.settings))
    }

    /// Commits and consumes the transaction. The connection is closed after a failed commit, so
    /// a connection in an unknown state never goes back to the pool.
    pub(super) async fn commit_inner(&mut self) -> Result<(), StoreError> {
        let Some(mut connection) = self.connection.take() else {
            return Err(StoreError::Unavailable);
        };
        match finish_commit(&mut connection).await {
            Ok(()) => Ok(()),
            Err(error) => {
                drop(PooledConnection::take(connection));
                Err(error)
            }
        }
    }

    /// Rolls back and consumes the transaction.
    pub(super) async fn rollback_inner(&mut self) -> Result<(), StoreError> {
        let Some(mut connection) = self.connection.take() else {
            return Ok(());
        };
        match finish_rollback(&mut connection).await {
            Ok(()) => Ok(()),
            Err(_) => {
                drop(PooledConnection::take(connection));
                Err(StoreError::Unavailable)
            }
        }
    }

    pub(super) async fn claim_one(
        &mut self,
        stage_run: StageRunId,
        worker: &WorkerId,
        ttl: Duration,
    ) -> Result<Option<ClaimedWork>, StoreError> {
        let (connection, tenant, settings) = self.parts()?;
        stage_runs::claim(connection, tenant, stage_run, worker, ttl, settings).await
    }

    pub(super) async fn take_back_expired(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<bool, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        stage_runs::take_back_expired(connection, tenant, stage_run).await
    }
}

impl Drop for PgTx {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            abandon(&self.shared, connection);
        }
    }
}

#[async_trait]
impl Tx for PgTx {
    async fn database_time(&mut self) -> Result<Timestamp, StoreError> {
        let (connection, _, _) = self.parts()?;
        database_now(connection).await
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StoreError> {
        self.commit_inner().await
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), StoreError> {
        self.rollback_inner().await
    }
}

#[async_trait]
impl JobOps for PgTx {
    async fn insert_job(&mut self, new: NewJob) -> Result<Versioned<Job>, StoreError> {
        let (connection, tenant, settings) = self.parts()?;
        jobs::insert(connection, tenant, settings, new).await
    }

    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        jobs::get(connection, tenant, id).await
    }

    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        jobs::transition(connection, tenant, id, expected, t).await
    }
}

#[async_trait]
impl StageRunOps for PgTx {
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Versioned<StageRun>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        stage_runs::insert(connection, tenant, new).await
    }

    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        stage_runs::get(connection, tenant, id).await
    }

    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
    ) -> Result<Version, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        stage_runs::transition(connection, tenant, id, expected, t).await
    }

    async fn claim_ready(
        &mut self,
        _worker: &WorkerId,
        _limit: u32,
        _lease_ttl: Duration,
    ) -> Result<Vec<ClaimedWork>, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }

    async fn expired_leases(&mut self, _limit: u32) -> Result<Vec<AttemptId>, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }
}

#[async_trait]
impl AttemptOps for PgTx {
    async fn insert_attempt(&mut self, new: NewAttempt) -> Result<Versioned<Attempt>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        attempts::insert(connection, tenant, new).await
    }

    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        attempts::get(connection, tenant, id).await
    }

    async fn heartbeat(&mut self, id: AttemptId, epoch: LeaseEpoch) -> Result<(), StoreError> {
        let (connection, tenant, _) = self.parts()?;
        attempts::heartbeat(connection, tenant, id, epoch).await
    }

    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
    ) -> Result<Version, StoreError> {
        let (connection, tenant, settings) = self.parts()?;
        attempts::transition(connection, tenant, settings, id, expected, epoch, t).await
    }
}

#[async_trait]
impl TaskNodeOps for PgTx {
    async fn insert_task_node(
        &mut self,
        new: NewTaskNode,
    ) -> Result<Versioned<TaskNode>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        task_nodes::insert(connection, tenant, new).await
    }

    async fn get_task_node(&mut self, id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        task_nodes::get(connection, tenant, id).await
    }

    async fn transition_task_node(
        &mut self,
        id: TaskNodeId,
        expected: Version,
        t: AppliedTransition<TaskNodeStatus>,
    ) -> Result<Version, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        task_nodes::transition(connection, tenant, id, expected, t).await
    }
}

#[async_trait]
impl LedgerOps for PgTx {
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        ledger::append(connection, tenant, entry).await
    }

    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        ledger::head(connection, tenant, job).await
    }

    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        ledger::read(connection, tenant, job, from, limit).await
    }
}

#[async_trait]
impl OutboxOps for PgTx {
    async fn enqueue_event(&mut self, event: DomainEvent) -> Result<(), StoreError> {
        let (connection, tenant, _) = self.parts()?;
        outbox::enqueue(connection, tenant, event).await
    }

    async fn read_events(
        &mut self,
        job: JobId,
        from: OutboxSeq,
        limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        outbox::read(connection, tenant, job, from, limit).await
    }
}

#[async_trait]
impl AuditOps for PgTx {
    async fn record_audit(&mut self, event: AuditEvent) -> Result<(), StoreError> {
        let (connection, tenant, _) = self.parts()?;
        audit::record(connection, tenant, event).await
    }

    async fn read_audit(&mut self, job: JobId, limit: u32) -> Result<Vec<AuditEvent>, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        audit::read(connection, tenant, job, limit).await
    }
}

#[async_trait]
impl ArtifactIndexOps for PgTx {
    async fn index_artifact(
        &mut self,
        new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        let (connection, tenant, settings) = self.parts()?;
        artifact_index::index(connection, tenant, settings, new).await
    }

    async fn get_artifact_index(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        artifact_index::get(connection, tenant, sha256).await
    }
}

#[async_trait]
impl PrincipalOps for PgTx {
    async fn insert_principal(&mut self, new: NewPrincipal) -> Result<Principal, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        principals::insert(connection, tenant, new).await
    }

    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        let (connection, tenant, _) = self.parts()?;
        principals::get(connection, tenant, id).await
    }
}
