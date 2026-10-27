//! `PgTx`: a tenant transaction.
//!
//! A tenant transaction starts like this, in this order, and nothing else comes first:
//!
//! 1. `BEGIN`;
//! 2. `SELECT set_config('factory.tenant_id', $1, true)` with the tenant as a bound parameter.
//!    The third argument `true` ties the setting to the transaction, so it ends at commit or
//!    rollback and cannot reach the next borrower of the connection. The value is never written
//!    into the statement text, so neither `pg_stat_activity` nor the logs carry it;
//! 3. the statement and lock timeouts of the pool, set the same way, local to the transaction.
//!
//! The type has no method that runs raw SQL or changes the setting.
//!
//! # A call that never returns
//!
//! The port says that a method future dropped before it completes poisons the transaction. Every
//! call marks the transaction busy before it touches the connection and clears the mark when it
//! has an answer. A dropped future never clears it, so the next call finds the transaction busy
//! and answers `Unavailable`, as does every call after it. The only safe step is to drop the
//! transaction, which rolls it back.
//!
//! # After an error of the database
//!
//! PostgreSQL refuses every later statement of a transaction after an error of its own (for
//! example a constraint violation). Errors the store detects before it writes (`Conflict` on a
//! stale version, `NotFound`, `LeaseFenced`, `TenantMismatch`) leave the transaction usable; the
//! others poison it, and the later calls are reported as `Unavailable`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AnsiTransactionManager, AsyncPgConnection, RunQueryDsl, TransactionManager};
use factory_domain::ids::TenantId;
use factory_domain::values::Timestamp;
use factory_ports::store::{StoreError, Tx, Witness};
use time::OffsetDateTime;

use super::conv::from_column;
use super::error::{Failure, at_commit, database};
use super::pool::PooledConnection;
use super::store::Shared;

/// An open tenant transaction.
pub struct PgTx {
    connection: Option<PooledConnection>,
    tenant: TenantId,
    shared: Arc<Shared>,
    /// A call is in flight. A dropped future leaves it set.
    busy: bool,
    /// The transaction can no longer be used.
    poisoned: bool,
}

type Transactions = AnsiTransactionManager;

/// Runs one call on the connection of a transaction. Marks the transaction busy while the call
/// runs, so a call that is dropped poisons it, and clears the mark with the outcome.
///
/// ```text
/// call!(self, connection, tenant => jobs::get(connection, tenant, id))
/// ```
macro_rules! call {
    ($self:ident, $connection:ident, $tenant:ident => $body:expr) => {{
        $self.begin_call().await?;
        let ($connection, $tenant) = $self.parts()?;
        let outcome = $body.await;
        $self.leave(&outcome);
        outcome
    }};
}
pub(super) use call;

/// Starts a transaction on `connection` and makes the tenant setting, in that order, then sets the
/// limits. The setting is made first so that no statement of the transaction runs without it.
pub(super) async fn start(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    statement_timeout: Duration,
    lock_timeout: Duration,
) -> Result<(), StoreError> {
    <Transactions as TransactionManager<AsyncPgConnection>>::begin_transaction(connection)
        .await
        .map_err(|error| database("begin", &error))?;
    sql_query("SELECT set_config('factory.tenant_id', $1, true)")
        .bind::<Text, _>(tenant.to_string())
        .execute(connection)
        .await
        .map_err(|error| database("begin", &error))?;
    set_limits(connection, statement_timeout, lock_timeout).await
}

/// Sets the statement and lock timeouts for this transaction only.
pub(super) async fn set_limits(
    connection: &mut AsyncPgConnection,
    statement_timeout: Duration,
    lock_timeout: Duration,
) -> Result<(), StoreError> {
    sql_query(
        "SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true)",
    )
    .bind::<Text, _>(format!("{}ms", statement_timeout.as_millis()))
    .bind::<Text, _>(format!("{}ms", lock_timeout.as_millis()))
    .execute(connection)
    .await
    .map_err(|error| database("begin", &error))?;
    Ok(())
}

pub(super) async fn finish_rollback(connection: &mut AsyncPgConnection) -> Result<(), StoreError> {
    <Transactions as TransactionManager<AsyncPgConnection>>::rollback_transaction(connection)
        .await
        .map_err(|error| database("rollback", &error))
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

/// The database clock, read on any connection. It is the clock of the moment of the call, not the
/// start of the transaction, so a transaction that stays open still sees time pass.
pub(super) async fn database_now(
    connection: &mut AsyncPgConnection,
) -> Result<Timestamp, StoreError> {
    let row = sql_query("SELECT clock_timestamp() AS now")
        .get_result::<DatabaseNow>(connection)
        .await
        .map_err(|error| database("database_time", &error))?;
    Ok(from_column(row.now))
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = Bool)]
    found: bool,
}

impl PgTx {
    pub(super) async fn begin(shared: Arc<Shared>, tenant: TenantId) -> Result<Self, StoreError> {
        shared.settle_rollbacks().await;
        let mut connection = shared.tenant_pool.get().await?;
        let limits = &shared.tenant_limits;
        start(
            &mut connection,
            tenant,
            limits.statement_timeout,
            limits.lock_timeout,
        )
        .await?;
        Ok(Self {
            connection: Some(connection),
            tenant,
            shared,
            busy: false,
            poisoned: false,
        })
    }

    /// Marks a call as started. The transaction is busy until [`PgTx::leave`] clears the mark, so
    /// a call whose future is dropped leaves it busy, and the next call finds it poisoned. A test
    /// can ask the store to stall here, to show exactly that.
    pub(super) async fn begin_call(&mut self) -> Result<(), StoreError> {
        if self.busy || self.poisoned || self.connection.is_none() {
            self.poisoned = true;
            return Err(StoreError::Unavailable);
        }
        self.busy = true;
        if self.shared.faults.take_stall() {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    /// The connection and the tenant of a call that [`PgTx::begin_call`] accepted.
    pub(super) fn parts(&mut self) -> Result<(&mut AsyncPgConnection, TenantId), StoreError> {
        match self.connection.as_mut() {
            Some(connection) => Ok((&mut **connection, self.tenant)),
            None => Err(StoreError::Unavailable),
        }
    }

    /// Clears the busy mark. An answer that says the database or the connection failed poisons
    /// the transaction: PostgreSQL refuses what follows.
    pub(super) fn leave<T>(&mut self, outcome: &Result<T, StoreError>) {
        self.busy = false;
        if matches!(
            outcome,
            Err(StoreError::Unavailable | StoreError::Internal(_))
        ) {
            self.poisoned = true;
        }
    }

    /// Whether the witnessed write is stored for this transaction's tenant.
    pub(super) async fn witnessed(&mut self, witness: Witness) -> Result<bool, StoreError> {
        call!(self, connection, tenant => async {
            let (sql, key) = match witness {
                Witness::OutboxEvent(id) => (
                    "SELECT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND event_id = $2) AS found",
                    id.as_uuid(),
                ),
                Witness::Audit(id) => (
                    "SELECT EXISTS (SELECT 1 FROM audit_events WHERE tenant_id = $1 AND event_id = $2) AS found",
                    id.as_uuid(),
                ),
            };
            let row = sql_query(sql)
                .bind::<SqlUuid, _>(tenant.as_uuid())
                .bind::<SqlUuid, _>(key)
                .get_result::<Found>(connection)
                .await
                .map_err(|error| database("committed", &error))?;
            Ok(row.found)
        })
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
        call!(self, connection, tenant => async {
            let _ = tenant;
            database_now(connection).await
        })
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StoreError> {
        if self.busy || self.poisoned {
            return Err(StoreError::Unavailable);
        }
        let Some(mut connection) = self.connection.take() else {
            return Err(StoreError::Unavailable);
        };
        let sent = <Transactions as TransactionManager<AsyncPgConnection>>::commit_transaction(
            &mut connection,
        )
        .await;
        match sent {
            Ok(()) => {
                if self.shared.faults.take_lost_commit() {
                    // The database applied the commit and the answer is lost: the connection is
                    // no longer trusted and the caller must ask `Store::committed`.
                    drop(PooledConnection::take(connection));
                    return Err(StoreError::CommitOutcomeUnknown);
                }
                Ok(())
            }
            Err(error) => {
                // A connection that failed while the commit was in flight may or may not have
                // applied it. Everything else (a deferred check, a lost race) is a refusal, and
                // the database rolled the transaction back.
                let lost = matches!(Failure::of(&error), Failure::Connection);
                drop(PooledConnection::take(connection));
                if lost {
                    Err(StoreError::CommitOutcomeUnknown)
                } else {
                    Err(at_commit(&error))
                }
            }
        }
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), StoreError> {
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
}
