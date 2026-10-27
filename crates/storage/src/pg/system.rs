//! `SystemTx`: the system scope (ADR 0012, section 3).
//!
//! The system login finds work across tenants and can write nothing. A system transaction
//! therefore does two things:
//!
//! * it **finds** with the system pool: ready stage runs, stage runs whose lease ended, expired
//!   attempts, and the tenant that owns a job, stage run or attempt given by id;
//! * it **changes** only through a tenant transaction for the tenant that was found, taken from the
//!   tenant pool, so every write happens under the tenant policy.
//!
//! The tenant transactions it opens belong to the system transaction. `commit` commits them one
//! after the other, `rollback` and a drop roll them all back. The commit of several tenants is not
//! one atomic step: if the second commit fails, the first has already happened. Claims of
//! different tenants do not depend on each other, so the claim is safe, and a failed commit says
//! so to the caller.
//!
//! The find step cannot hold its locks until the system transaction ends. The tenant transaction
//! that follows must lock the same row, and a lock held by another connection would make it skip
//! the row (`docs/database/for-the-storage-crate.md`, "Claim a stage run"). So the find is a
//! single statement, and the lock that lasts is the one the tenant transaction takes.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
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
use uuid::Uuid;

use super::cas::Machine;
use super::conv::{attempt_from_column, stage_run_from_column, tenant_from_column};
use super::error::generic;
use super::store::Shared;
use super::tx::{PgTx, database_now};
use std::sync::Arc;

/// A system transaction.
pub struct SystemTx {
    shared: Arc<Shared>,
    children: Vec<PgTx>,
}

#[derive(QueryableByName)]
struct Candidate {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run: Uuid,
}

#[derive(QueryableByName)]
struct TenantRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
}

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

impl SystemTx {
    pub(super) fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            children: Vec::new(),
        }
    }

    /// The tenant transaction for `tenant`, opened on first use.
    async fn child(&mut self, tenant: TenantId) -> Result<&mut PgTx, StoreError> {
        if let Some(position) = self
            .children
            .iter()
            .position(|child| child.tenant() == tenant)
        {
            return Ok(&mut self.children[position]);
        }
        let child = PgTx::begin(self.shared.clone(), tenant).await?;
        self.children.push(child);
        let last = self.children.len() - 1;
        Ok(&mut self.children[last])
    }

    /// Finds the tenant that owns the row with this id, with the system login. A row id is a UUID
    /// version 7 and unique in practice. If two tenants hold the same id the row cannot be
    /// routed, and the answer is `NotFound`.
    async fn tenant_of(&self, machine: Machine, id: Uuid) -> Result<TenantId, StoreError> {
        let mut connection = self.shared.system_connection().await?;
        let table = machine.table();
        let rows = sql_query(format!(
            "SELECT tenant_id FROM {table} WHERE id = $1 LIMIT 2"
        ))
        .bind::<SqlUuid, _>(id)
        .load::<TenantRow>(&mut *connection)
        .await
        .map_err(|error| generic("system_route", &error))?;
        match rows.as_slice() {
            [only] => Ok(tenant_from_column(only.tenant_id)),
            _ => Err(StoreError::NotFound),
        }
    }

    async fn job_tx(&mut self, job: JobId) -> Result<&mut PgTx, StoreError> {
        let tenant = self.tenant_of(Machine::Job, job.as_uuid()).await?;
        self.child(tenant).await
    }

    async fn stage_run_tx(&mut self, stage_run: StageRunId) -> Result<&mut PgTx, StoreError> {
        let tenant = self
            .tenant_of(Machine::StageRun, stage_run.as_uuid())
            .await?;
        self.child(tenant).await
    }

    async fn attempt_tx(&mut self, attempt: AttemptId) -> Result<&mut PgTx, StoreError> {
        let tenant = self.tenant_of(Machine::Attempt, attempt.as_uuid()).await?;
        self.child(tenant).await
    }

    /// Stage runs to try, as (tenant, stage run, lease ended): first those whose lease ended,
    /// then the ready ones, oldest first. One statement each, with `SKIP LOCKED`.
    async fn find(&self, want: usize) -> Result<Vec<(TenantId, StageRunId, bool)>, StoreError> {
        let mut connection = self.shared.system_connection().await?;
        let limit = i64::try_from(want).unwrap_or(i64::MAX);
        let mut found = Vec::new();
        let expired = sql_query(
            "SELECT a.tenant_id, a.stage_run_id AS stage_run FROM attempts a \
              WHERE a.status IN ('STARTING', 'RUNNING') AND a.lease_expires_at <= now() \
              ORDER BY a.lease_expires_at LIMIT $1 \
              FOR NO KEY UPDATE OF a SKIP LOCKED",
        )
        .bind::<BigInt, _>(limit)
        .load::<Candidate>(&mut *connection)
        .await
        .map_err(|error| generic("claim_ready", &error))?;
        found.extend(expired.into_iter().map(|row| {
            (
                tenant_from_column(row.tenant_id),
                stage_run_from_column(row.stage_run),
                true,
            )
        }));
        let ready = sql_query(
            "SELECT s.tenant_id, s.id AS stage_run FROM stage_runs s \
              WHERE s.status = 'READY' AND s.not_before <= now() \
                AND (NOT $2 OR EXISTS (SELECT 1 FROM jobs j WHERE j.tenant_id = s.tenant_id \
                                        AND j.id = s.job_id AND j.status = 'ACTIVE')) \
              ORDER BY s.not_before LIMIT $1 \
              FOR NO KEY UPDATE OF s SKIP LOCKED",
        )
        .bind::<BigInt, _>(limit)
        .bind::<Bool, _>(self.shared.settings.claim_only_active_jobs)
        .load::<Candidate>(&mut *connection)
        .await
        .map_err(|error| generic("claim_ready", &error))?;
        found.extend(ready.into_iter().map(|row| {
            (
                tenant_from_column(row.tenant_id),
                stage_run_from_column(row.stage_run),
                false,
            )
        }));
        Ok(found)
    }
}

impl Drop for SystemTx {
    fn drop(&mut self) {
        // Each child rolls itself back when it is dropped.
        self.children.clear();
    }
}

#[async_trait]
impl Tx for SystemTx {
    async fn database_time(&mut self) -> Result<Timestamp, StoreError> {
        let mut connection = self.shared.system_connection().await?;
        database_now(&mut connection).await
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StoreError> {
        let mut children = std::mem::take(&mut self.children);
        let mut outcome = Ok(());
        for child in &mut children {
            if outcome.is_ok() {
                outcome = child.commit_inner().await;
            } else {
                // A child that was not committed is rolled back, so nothing stays open.
                let _ = child.rollback_inner().await;
            }
        }
        outcome
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), StoreError> {
        let mut children = std::mem::take(&mut self.children);
        let mut outcome = Ok(());
        for child in &mut children {
            if let Err(error) = child.rollback_inner().await {
                outcome = Err(error);
            }
        }
        outcome
    }
}

#[async_trait]
impl JobOps for SystemTx {
    async fn insert_job(&mut self, _new: NewJob) -> Result<Versioned<Job>, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }

    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError> {
        self.job_tx(id).await?.get_job(id).await
    }

    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError> {
        self.job_tx(id).await?.transition_job(id, expected, t).await
    }
}

#[async_trait]
impl StageRunOps for SystemTx {
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Versioned<StageRun>, StoreError> {
        let job = new.job_id;
        self.job_tx(job).await?.insert_stage_run(new).await
    }

    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError> {
        self.stage_run_tx(id).await?.get_stage_run(id).await
    }

    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
    ) -> Result<Version, StoreError> {
        self.stage_run_tx(id)
            .await?
            .transition_stage_run(id, expected, t)
            .await
    }

    async fn claim_ready(
        &mut self,
        worker: &WorkerId,
        limit: u32,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedWork>, StoreError> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut claimed: Vec<ClaimedWork> = Vec::new();
        let mut tried: HashSet<(TenantId, StageRunId)> = HashSet::new();
        while claimed.len() < limit {
            let found = self.find(limit - claimed.len()).await?;
            let fresh: Vec<_> = found
                .into_iter()
                .filter(|(tenant, run, _)| !tried.contains(&(*tenant, *run)))
                .collect();
            if fresh.is_empty() {
                break;
            }
            for (tenant, run, lease_ended) in fresh {
                tried.insert((tenant, run));
                let child = self.child(tenant).await?;
                if lease_ended && !child.take_back_expired(run).await? {
                    continue;
                }
                if let Some(work) = child.claim_one(run, worker, lease_ttl).await? {
                    claimed.push(work);
                    if claimed.len() >= limit {
                        break;
                    }
                }
            }
        }
        Ok(claimed)
    }

    async fn expired_leases(&mut self, limit: u32) -> Result<Vec<AttemptId>, StoreError> {
        let mut connection = self.shared.system_connection().await?;
        let rows = sql_query(
            "SELECT id FROM attempts WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at <= now() \
              ORDER BY lease_expires_at LIMIT $1",
        )
        .bind::<BigInt, _>(i64::from(limit))
        .load::<IdRow>(&mut *connection)
        .await
        .map_err(|error| generic("expired_leases", &error))?;
        Ok(rows
            .into_iter()
            .map(|row| attempt_from_column(row.id))
            .collect())
    }
}

#[async_trait]
impl AttemptOps for SystemTx {
    async fn insert_attempt(&mut self, new: NewAttempt) -> Result<Versioned<Attempt>, StoreError> {
        let run = new.stage_run_id;
        self.stage_run_tx(run).await?.insert_attempt(new).await
    }

    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError> {
        self.attempt_tx(id).await?.get_attempt(id).await
    }

    async fn heartbeat(&mut self, id: AttemptId, epoch: LeaseEpoch) -> Result<(), StoreError> {
        self.attempt_tx(id).await?.heartbeat(id, epoch).await
    }

    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
    ) -> Result<Version, StoreError> {
        self.attempt_tx(id)
            .await?
            .transition_attempt(id, expected, epoch, t)
            .await
    }
}

#[async_trait]
impl TaskNodeOps for SystemTx {
    // The system login cannot read `task_nodes`, so a node id cannot be routed to its tenant.
    async fn insert_task_node(
        &mut self,
        _new: NewTaskNode,
    ) -> Result<Versioned<TaskNode>, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }

    async fn get_task_node(&mut self, _id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }

    async fn transition_task_node(
        &mut self,
        _id: TaskNodeId,
        _expected: Version,
        _t: AppliedTransition<TaskNodeStatus>,
    ) -> Result<Version, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }
}

#[async_trait]
impl LedgerOps for SystemTx {
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError> {
        let job = entry.metadata.job_id;
        self.job_tx(job).await?.append_ledger_entry(entry).await
    }

    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError> {
        self.job_tx(job).await?.ledger_head(job).await
    }

    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
        self.job_tx(job).await?.read_ledger(job, from, limit).await
    }
}

#[async_trait]
impl OutboxOps for SystemTx {
    async fn enqueue_event(&mut self, event: DomainEvent) -> Result<(), StoreError> {
        let job = event.job_id;
        self.job_tx(job).await?.enqueue_event(event).await
    }

    async fn read_events(
        &mut self,
        job: JobId,
        from: OutboxSeq,
        limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        self.job_tx(job).await?.read_events(job, from, limit).await
    }
}

#[async_trait]
impl AuditOps for SystemTx {
    async fn record_audit(&mut self, event: AuditEvent) -> Result<(), StoreError> {
        let job = event.job_id;
        self.job_tx(job).await?.record_audit(event).await
    }

    async fn read_audit(&mut self, job: JobId, limit: u32) -> Result<Vec<AuditEvent>, StoreError> {
        self.job_tx(job).await?.read_audit(job, limit).await
    }
}

#[async_trait]
impl ArtifactIndexOps for SystemTx {
    async fn index_artifact(
        &mut self,
        _new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }

    async fn get_artifact_index(
        &mut self,
        _sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }
}

#[async_trait]
impl PrincipalOps for SystemTx {
    async fn insert_principal(&mut self, _new: NewPrincipal) -> Result<Principal, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }

    async fn get_principal(&mut self, _id: PrincipalId) -> Result<Principal, StoreError> {
        Err(StoreError::ScopeNotAllowed)
    }
}
