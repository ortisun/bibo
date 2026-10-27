//! `PgSystemTx`: the cross-tenant, read-only transaction of the engine (ADR 0012, section 3;
//! ADR 0014, rule R3).
//!
//! The system login finds work across tenants and can write nothing. A system transaction
//! therefore does two things:
//!
//! * it **finds**: ready stage runs and attempts that are due, as identifiers and the version they
//!   were read at, with `FOR NO KEY UPDATE SKIP LOCKED` so that two finders mostly see different
//!   rows;
//! * it **finishes**, which ends the transaction and releases the locks.
//!
//! A found row is a hint. The change is made in a tenant transaction (`start_attempt`,
//! `transition_attempt`) for the tenant that was found, on the tenant pool, under the tenant's
//! policy. The system role reads named columns only, so no query here is `SELECT *`.
//!
//! The statements use `now()`, the start of this transaction, so one finding sees one instant.

use std::sync::Arc;

use async_trait::async_trait;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AnsiTransactionManager, AsyncPgConnection, RunQueryDsl, TransactionManager};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::values::Timestamp;
use factory_ports::store::{ClaimCandidate, DueAttempt, DueReason, StoreError, SystemTx};
use time::OffsetDateTime;
use uuid::Uuid;

use super::conv::{from_column, version_from_column};
use super::error::database;
use super::pool::PooledConnection;
use super::store::Shared;
use super::tx::{abandon, database_now, set_limits};

/// An open system transaction.
pub struct PgSystemTx {
    connection: Option<PooledConnection>,
    shared: Arc<Shared>,
    busy: bool,
    poisoned: bool,
}

#[derive(QueryableByName)]
struct CandidateRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Timestamptz)]
    not_before: OffsetDateTime,
}

#[derive(QueryableByName)]
struct DueRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = BigInt)]
    version: i64,
}

/// Ready stage runs of active jobs, oldest start time first.
const CLAIM_CANDIDATES: &str = "\
    SELECT s.tenant_id, s.job_id, s.id, s.version, s.not_before \
      FROM stage_runs s \
      JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE' \
     WHERE s.status = 'READY' AND s.not_before <= now() \
     ORDER BY s.not_before, s.id \
     LIMIT $1 \
     FOR NO KEY UPDATE OF s SKIP LOCKED";

/// A `STARTING` or `RUNNING` attempt whose lease ended (A07). Each of the three queries has an
/// index of its own.
const LEASE_EXPIRED: &str = "\
    SELECT tenant_id, job_id, stage_run_id, id, version FROM attempts \
     WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now() \
     ORDER BY lease_expires_at, id LIMIT $1 \
     FOR NO KEY UPDATE SKIP LOCKED";

/// A `STARTING` or `RUNNING` attempt past its deadline (A06).
const DEADLINE_PASSED: &str = "\
    SELECT tenant_id, job_id, stage_run_id, id, version FROM attempts \
     WHERE status IN ('STARTING', 'RUNNING') AND deadline_at < now() \
     ORDER BY deadline_at, id LIMIT $1 \
     FOR NO KEY UPDATE SKIP LOCKED";

/// A `CANCELLING` attempt past its teardown deadline (A10). A cancelling attempt with a lapsed
/// lease is due only for this reason.
const TEARDOWN_PASSED: &str = "\
    SELECT tenant_id, job_id, stage_run_id, id, version FROM attempts \
     WHERE status = 'CANCELLING' AND teardown_deadline_at < now() \
     ORDER BY teardown_deadline_at, id LIMIT $1 \
     FOR NO KEY UPDATE SKIP LOCKED";

impl PgSystemTx {
    pub(super) async fn begin(shared: Arc<Shared>) -> Result<Self, StoreError> {
        shared.settle_rollbacks().await;
        let (Some(pool), Some(limits)) = (&shared.system_pool, &shared.system_limits) else {
            tracing::error!("a system transaction was asked for, but no system pool is configured");
            return Err(StoreError::Unavailable);
        };
        let mut connection = pool.get().await?;
        // Not READ ONLY: `SELECT ... FOR NO KEY UPDATE` is refused in a read only transaction.
        // The role has no write grant on these tables, which is what makes it read only.
        <AnsiTransactionManager as TransactionManager<AsyncPgConnection>>::begin_transaction(
            &mut connection,
        )
        .await
        .map_err(|error| database("begin_system", &error))?;
        set_limits(
            &mut connection,
            limits.statement_timeout,
            limits.lock_timeout,
        )
        .await?;
        Ok(Self {
            connection: Some(connection),
            shared,
            busy: false,
            poisoned: false,
        })
    }

    /// Marks a call as started; a dropped call leaves the mark and poisons the transaction.
    fn enter(&mut self) -> Result<&mut AsyncPgConnection, StoreError> {
        if self.busy || self.poisoned {
            self.poisoned = true;
            return Err(StoreError::Unavailable);
        }
        let Some(connection) = self.connection.as_mut() else {
            return Err(StoreError::Unavailable);
        };
        self.busy = true;
        Ok(&mut **connection)
    }

    fn leave<T>(&mut self, outcome: &Result<T, StoreError>) {
        self.busy = false;
        if outcome.is_err() {
            self.poisoned = true;
        }
    }

    async fn due(&mut self, query: &'static str, limit: u32) -> Result<Vec<DueRow>, StoreError> {
        let connection = self.enter()?;
        let outcome = sql_query(query)
            .bind::<BigInt, _>(i64::from(limit))
            .load::<DueRow>(connection)
            .await
            .map_err(|error| database("find_due_attempts", &error));
        self.leave(&outcome);
        outcome
    }
}

impl Drop for PgSystemTx {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            abandon(&self.shared, connection);
        }
    }
}

#[async_trait]
impl SystemTx for PgSystemTx {
    async fn database_time(&mut self) -> Result<Timestamp, StoreError> {
        let connection = self.enter()?;
        let outcome = database_now(connection).await;
        self.leave(&outcome);
        outcome
    }

    async fn find_claim_candidates(
        &mut self,
        limit: u32,
    ) -> Result<Vec<ClaimCandidate>, StoreError> {
        let connection = self.enter()?;
        let outcome = sql_query(CLAIM_CANDIDATES)
            .bind::<BigInt, _>(i64::from(limit))
            .load::<CandidateRow>(connection)
            .await
            .map_err(|error| database("find_claim_candidates", &error));
        self.leave(&outcome);
        outcome?
            .into_iter()
            .map(|row| {
                Ok(ClaimCandidate {
                    tenant: TenantId::from_uuid(row.tenant_id),
                    job: JobId::from_uuid(row.job_id),
                    stage_run: StageRunId::from_uuid(row.id),
                    version: version_from_column(row.version)?,
                    not_before: from_column(row.not_before),
                })
            })
            .collect()
    }

    async fn find_due_attempts(
        &mut self,
        reason: DueReason,
        limit: u32,
    ) -> Result<Vec<DueAttempt>, StoreError> {
        let query = match reason {
            DueReason::LeaseExpired => LEASE_EXPIRED,
            DueReason::DeadlinePassed => DEADLINE_PASSED,
            DueReason::TeardownDeadlinePassed => TEARDOWN_PASSED,
        };
        self.due(query, limit)
            .await?
            .into_iter()
            .map(|row| {
                Ok(DueAttempt {
                    tenant: TenantId::from_uuid(row.tenant_id),
                    job: JobId::from_uuid(row.job_id),
                    stage_run: StageRunId::from_uuid(row.stage_run_id),
                    attempt: AttemptId::from_uuid(row.id),
                    version: version_from_column(row.version)?,
                    reason,
                })
            })
            .collect()
    }

    async fn finish(mut self: Box<Self>) -> Result<(), StoreError> {
        let Some(mut connection) = self.connection.take() else {
            return Ok(());
        };
        // Nothing was written, so a commit and a rollback end the same way. The commit is used so
        // the connection leaves a clean transaction state in both outcomes.
        let ended =
            <AnsiTransactionManager as TransactionManager<AsyncPgConnection>>::commit_transaction(
                &mut connection,
            )
            .await;
        match ended {
            Ok(()) => Ok(()),
            Err(error) => {
                let mapped = database("finish", &error);
                drop(PooledConnection::take(connection));
                Err(mapped)
            }
        }
    }
}
