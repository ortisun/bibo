//! Attempts, their leases and the fence (ADR 0014, rules R1 to R3).
//!
//! # The claim, step two: `start_attempt`
//!
//! The first step is a system transaction that only finds candidates (see [`super::system`]). This
//! is the second: one tenant transaction that takes the locks in the order the schema expects
//! (job, stage run, attempt, task node), decides from what it read under the locks, and then
//! writes both rows:
//!
//! 1. the job is share-locked (`FOR SHARE`), so a pause or a cancel of the job waits for this
//!    decision, or this decision sees the new status;
//! 2. the stage run is locked with `FOR NO KEY UPDATE` and read;
//! 3. the decision, in this order: the run is `READY` at the version the candidate was read at
//!    (else `Conflict`), the job is `ACTIVE`, the back-off has passed, no attempt is live, the
//!    attempts used since the last human answer are below the limit, and the epoch can rise;
//! 4. the run moves to `RUNNING` with `lease_epoch + 1`, and the attempt is created in `STARTING`
//!    at that epoch, with its lease and deadline taken from `now()`.
//!
//! `FOR NO KEY UPDATE` and never `FOR UPDATE`: a ledger, audit or outbox insert takes a `KEY SHARE`
//! lock on the rows it points at, and `FOR UPDATE` conflicts with that.
//!
//! The lease lives on the attempt. The epoch rises only here, only for `READY` to `RUNNING`. A
//! write that carries a fence is current only for a live attempt whose epoch is the one it holds;
//! the database keeps a live attempt at the run's epoch (`attempts_live_attempt_has_current_epoch`),
//! so the attempt's own epoch is the fence.
//!
//! # Times
//!
//! `lease_expires_at`, `deadline_at`, `teardown_deadline_at`, `last_heartbeat_at` and `ended_at`
//! come from `now()` plus a duration the caller gave. A time computed in Rust never reaches the
//! database.

use std::time::Duration;

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Bool, Integer, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::state::{AttemptStatus, Status};
use factory_ports::sandbox::SandboxId;
use factory_ports::store::{
    AppliedTransition, Attempt, AttemptEnd, AttemptOps, ConstraintRule, Fence, LeaseEpoch,
    LeaseRenewal, NotReady, SandboxRecord, StartAttempt, StartedAttempt, StoreError, Version,
    Versioned, WorkerId, attempt_end_rule,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists};
use super::conv::{
    corrupt, digest_from_column, epoch_from_column, epoch_to_column, from_column, micros,
    status_from_column, version_from_column,
};
use super::error::database;
use super::stage_runs::{StageRunRow, stage_run_from_row};
use super::tx::{PgTx, call};

const COLUMNS: &str = "tenant_id, id, job_id, stage_run_id, attempt_number, status, version, \
    lease_owner, lease_epoch, lease_expires_at, last_heartbeat_at, deadline_at, \
    teardown_deadline_at, failure_class, output_sha256, sandbox_id, sandbox_leaked, created_at, \
    ended_at";

const STAGE_RUN_COLUMNS: &str = "tenant_id, id, job_id, stage_kind, run_number, status, version, \
    lease_epoch, max_attempts, not_before, rework_of_stage_run_id, stage_contract_sha256, \
    gate_outcome, gate_report_sha256, failing_set_sha256, created_at, finished_at, superseded_at";

#[derive(QueryableByName)]
struct AttemptRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
    #[diesel(sql_type = Integer)]
    attempt_number: i32,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Nullable<Text>)]
    lease_owner: Option<String>,
    #[diesel(sql_type = BigInt)]
    lease_epoch: i64,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    lease_expires_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_heartbeat_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Timestamptz)]
    deadline_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    teardown_deadline_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    failure_class: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    output_sha256: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    sandbox_id: Option<String>,
    #[diesel(sql_type = Bool)]
    sandbox_leaked: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    ended_at: Option<OffsetDateTime>,
}

fn attempt_from_row(row: AttemptRow) -> Result<Versioned<Attempt>, StoreError> {
    let worker = row
        .lease_owner
        .as_deref()
        .and_then(|name| WorkerId::new(name).ok())
        .ok_or_else(|| corrupt("lease owner"))?;
    Ok(Versioned {
        value: Attempt {
            id: AttemptId::from_uuid(row.id),
            tenant_id: TenantId::from_uuid(row.tenant_id),
            job_id: JobId::from_uuid(row.job_id),
            stage_run_id: StageRunId::from_uuid(row.stage_run_id),
            number: u32::try_from(row.attempt_number).map_err(|_| corrupt("attempt number"))?,
            status: status_from_column::<AttemptStatus>(&row.status)?,
            worker,
            epoch: epoch_from_column(row.lease_epoch)?,
            lease_expires_at: from_column(
                row.lease_expires_at
                    .ok_or_else(|| corrupt("lease expiry"))?,
            ),
            last_heartbeat_at: row.last_heartbeat_at.map(from_column),
            deadline_at: from_column(row.deadline_at),
            teardown_deadline_at: row.teardown_deadline_at.map(from_column),
            failure_class: row
                .failure_class
                .as_deref()
                .map(|name| FailureClass::parse(name).map_err(|_| corrupt("failure class")))
                .transpose()?,
            output: row
                .output_sha256
                .as_deref()
                .map(digest_from_column)
                .transpose()?,
            sandbox: row.sandbox_id.map(|name| SandboxRecord {
                sandbox: SandboxId::new(name),
                leaked: row.sandbox_leaked,
            }),
            created_at: from_column(row.created_at),
            ended_at: row.ended_at.map(from_column),
        },
        version: version_from_column(row.version)?,
    })
}

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Text)]
    status: String,
}

#[derive(QueryableByName)]
struct RunLock {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = BigInt)]
    lease_epoch: i64,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    max_attempts: i16,
    #[diesel(sql_type = Integer)]
    attempts_before_last_answer: i32,
    #[diesel(sql_type = Bool)]
    due: bool,
}

#[derive(QueryableByName)]
struct Used {
    #[diesel(sql_type = Integer)]
    last_number: i32,
    #[diesel(sql_type = Bool)]
    live: bool,
    #[diesel(sql_type = Bool)]
    id_taken: bool,
}

async fn start_attempt(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    start: StartAttempt,
) -> Result<StartedAttempt, StoreError> {
    let run_id = start.stage_run.as_uuid();
    let operation = "start_attempt";
    // The job of a stage run never changes, so it can be read before the locks.
    let job = sql_query("SELECT job_id AS id FROM stage_runs WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant.as_uuid())
        .bind::<SqlUuid, _>(run_id)
        .get_result::<IdRow>(connection)
        .await
        .optional()
        .map_err(|error| database(operation, &error))?
        .ok_or(StoreError::NotFound)?
        .id;
    if start.transition.transition_id() != "S03" {
        return Err(StoreError::Constraint(ConstraintRule::IllegalStatusMove));
    }

    // 1. The job, share-locked.
    let job_status =
        sql_query("SELECT status FROM jobs WHERE tenant_id = $1 AND id = $2 FOR SHARE")
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(job)
            .get_result::<TextRow>(connection)
            .await
            .optional()
            .map_err(|error| database(operation, &error))?
            .ok_or(StoreError::NotFound)?;

    // 2. The stage run, locked, and read as it is now.
    let run = sql_query(
        "SELECT status, version, lease_epoch, max_attempts, attempts_before_last_answer, \
                (not_before <= now()) AS due \
           FROM stage_runs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(run_id)
    .get_result::<RunLock>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?
    .ok_or(StoreError::NotFound)?;
    // What the attempts say, read after the lock so it is read under a fresh snapshot.
    let used = sql_query(
        "SELECT coalesce(max(attempt_number), 0) AS last_number, \
                coalesce(bool_or(status IN ('STARTING', 'RUNNING', 'CANCELLING')), false) AS live, \
                coalesce(bool_or(id = $3), false) AS id_taken \
           FROM attempts WHERE tenant_id = $1 AND stage_run_id = $2",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(run_id)
    .bind::<SqlUuid, _>(start.attempt.as_uuid())
    .get_result::<Used>(connection)
    .await
    .map_err(|error| database(operation, &error))?;

    // 3. The decision.
    if run.version != start.expected.get() || run.status != "READY" {
        return Err(StoreError::Conflict);
    }
    if job_status.status != "ACTIVE" {
        return Err(StoreError::NotReady(NotReady::JobNotActive));
    }
    if !run.due {
        return Err(StoreError::NotReady(NotReady::BackingOff));
    }
    if used.live {
        return Err(StoreError::Constraint(ConstraintRule::OneLiveAttempt));
    }
    // Attempts are numbered without a gap, and the limit counts those made since the last human
    // answer (INV-10): `attempts_before_last_answer` is the number that came before it.
    let next_number = used.last_number + 1;
    if next_number - run.attempts_before_last_answer > i32::from(run.max_attempts) {
        return Err(StoreError::Constraint(ConstraintRule::AttemptLimit));
    }
    if used.id_taken {
        return Err(StoreError::Conflict);
    }
    let epoch = epoch_from_column(run.lease_epoch)?;
    let Some(granted) = epoch.checked_next() else {
        return Err(StoreError::Constraint(ConstraintRule::LeaseEpochExhausted));
    };

    // 4. Both rows, in this order: the run, then the attempt at the epoch the run now holds.
    let moved = sql_query(format!(
        "UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, \
                version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'READY' \
          RETURNING {STAGE_RUN_COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(run_id)
    .bind::<BigInt, _>(start.expected.get())
    .get_result::<StageRunRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?
    .ok_or(StoreError::Conflict)?;
    let attempt = sql_query(format!(
        "INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, status, \
                lease_owner, lease_epoch, lease_expires_at, deadline_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                 now() + $9 * interval '1 microsecond', now() + $10 * interval '1 microsecond') \
         RETURNING {COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(start.attempt.as_uuid())
    .bind::<SqlUuid, _>(job)
    .bind::<SqlUuid, _>(run_id)
    .bind::<Integer, _>(next_number)
    .bind::<Text, _>(AttemptStatus::INITIAL.to_string())
    .bind::<Text, _>(start.worker.as_str())
    .bind::<BigInt, _>(epoch_to_column(granted))
    .bind::<BigInt, _>(micros(start.lease_ttl))
    .bind::<BigInt, _>(micros(start.attempt_timeout))
    .get_result::<AttemptRow>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    Ok(StartedAttempt {
        stage_run: stage_run_from_row(moved)?,
        attempt: attempt_from_row(attempt)?,
    })
}

async fn find(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AttemptId,
) -> Result<Option<Versioned<Attempt>>, StoreError> {
    sql_query(format!(
        "SELECT {COLUMNS} FROM attempts WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<AttemptRow>(connection)
    .await
    .optional()
    .map_err(|error| database("get_attempt", &error))?
    .map(attempt_from_row)
    .transpose()
}

async fn list(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    stage_run: StageRunId,
) -> Result<Vec<Versioned<Attempt>>, StoreError> {
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM attempts WHERE tenant_id = $1 AND stage_run_id = $2 \
          ORDER BY attempt_number"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(stage_run.as_uuid())
    .load::<AttemptRow>(connection)
    .await
    .map_err(|error| database("list_attempts", &error))?;
    if rows.is_empty()
        && !exists(
            connection,
            Table::StageRuns,
            tenant,
            stage_run.as_uuid(),
            "list_attempts",
        )
        .await?
    {
        return Err(StoreError::NotFound);
    }
    rows.into_iter().map(attempt_from_row).collect()
}

#[derive(QueryableByName)]
struct Renewal {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Timestamptz)]
    lease_expires_at: OffsetDateTime,
    #[diesel(sql_type = Timestamptz)]
    deadline_at: OffsetDateTime,
}

async fn heartbeat(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    fence: Fence,
    ttl: Duration,
) -> Result<LeaseRenewal, StoreError> {
    // Renewed only while the lease has not lapsed: a lapsed lease is the sweeper's.
    let renewed = sql_query(
        "UPDATE attempts SET lease_expires_at = now() + $5 * interval '1 microsecond', \
                last_heartbeat_at = now(), version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND lease_epoch = $4 \
            AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now() \
          RETURNING status, lease_expires_at, deadline_at",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(fence.attempt.as_uuid())
    .bind::<Text, _>(fence.worker.as_str())
    .bind::<BigInt, _>(epoch_to_column(fence.epoch))
    .bind::<BigInt, _>(micros(ttl))
    .get_result::<Renewal>(connection)
    .await
    .optional()
    .map_err(|error| database("heartbeat", &error))?;
    if let Some(row) = renewed {
        return Ok(LeaseRenewal {
            status: status_from_column::<AttemptStatus>(&row.status)?,
            lease_expires_at: from_column(row.lease_expires_at),
            deadline_at: from_column(row.deadline_at),
        });
    }
    // Refused. An attempt that ended is a `Conflict`; any other reason (an unknown attempt, the
    // wrong worker, the wrong epoch, a lapsed lease) is a fence that is not current.
    let found = find(connection, tenant, fence.attempt).await?;
    Err(match found {
        Some(row) if row.value.status.is_terminal() => StoreError::Conflict,
        _ => StoreError::LeaseFenced,
    })
}

#[derive(QueryableByName)]
struct AttemptState {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = BigInt)]
    lease_epoch: i64,
}

#[derive(QueryableByName)]
struct NewVersion {
    #[diesel(sql_type = BigInt)]
    version: i64,
}

/// Why a transition changed no row: no such attempt, the attempt moved since it was read, the
/// epoch is not the attempt's, the status is not the one the move starts from, or the end record
/// breaks the rule of the transition. The order is the order the port lists them in.
async fn refusal(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AttemptId,
    expected: Version,
    epoch: LeaseEpoch,
    from: &str,
    rule: Option<StoreError>,
) -> Result<StoreError, StoreError> {
    let state = sql_query(
        "SELECT status, version, lease_epoch FROM attempts WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<AttemptState>(connection)
    .await
    .optional()
    .map_err(|error| database("transition_attempt", &error))?;
    Ok(match state {
        None => StoreError::NotFound,
        Some(row) if row.version != expected.get() => StoreError::Conflict,
        Some(row) if row.lease_epoch != epoch_to_column(epoch) => StoreError::LeaseFenced,
        Some(row) if row.status != from => StoreError::Conflict,
        Some(_) => rule.unwrap_or(StoreError::Conflict),
    })
}

/// The end record must be the one the transition requires, and no other.
fn check_end(transition_id: &str, end: &AttemptEnd) -> Result<(), StoreError> {
    let rule = attempt_end_rule(transition_id);
    if rule.failure_class == end.failure_class.is_some()
        && rule.output == end.output.is_some()
        && rule.teardown_grace == end.teardown_grace.is_some()
    {
        Ok(())
    } else {
        Err(StoreError::Constraint(ConstraintRule::AttemptEndRule))
    }
}

async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AttemptId,
    expected: Version,
    epoch: LeaseEpoch,
    t: AppliedTransition<AttemptStatus>,
    end: AttemptEnd,
) -> Result<Version, StoreError> {
    let from = t.from_status().to_string();
    if let Err(rule) = check_end(t.transition_id(), &end) {
        return Err(refusal(connection, tenant, id, expected, epoch, &from, Some(rule)).await?);
    }
    let to = t.to_status();
    let transition_id = t.transition_id();
    let sandbox = end.sandbox.as_ref();
    let updated = sql_query(
        "UPDATE attempts SET status = $5, version = version + 1, \
                ended_at = CASE WHEN $6 THEN now() ELSE ended_at END, \
                failure_class = coalesce($7, failure_class), \
                output_sha256 = coalesce($8, output_sha256), \
                teardown_deadline_at = CASE WHEN $9::bigint IS NOT NULL \
                    THEN now() + $9 * interval '1 microsecond' ELSE teardown_deadline_at END, \
                sandbox_id = coalesce($10, sandbox_id), \
                sandbox_leaked = sandbox_leaked OR $11 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND lease_epoch = $4 \
            AND status = $12 \
            AND ($13 IS FALSE OR lease_expires_at < now()) \
            AND ($14 IS FALSE OR deadline_at < now()) \
            AND ($15 IS FALSE OR teardown_deadline_at < now()) \
          RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<BigInt, _>(epoch_to_column(epoch))
    .bind::<Text, _>(to.to_string())
    .bind::<Bool, _>(to.is_terminal())
    .bind::<Nullable<Text>, _>(end.failure_class.map(|class| class.as_str().to_owned()))
    .bind::<Nullable<Text>, _>(end.output.as_ref().map(|hash| hash.as_str().to_owned()))
    .bind::<Nullable<BigInt>, _>(end.teardown_grace.map(micros))
    .bind::<Nullable<Text>, _>(sandbox.map(|record| record.sandbox.as_str().to_owned()))
    .bind::<Bool, _>(sandbox.is_some_and(|record| record.leaked))
    .bind::<Text, _>(from.clone())
    // The sweeper's moves are allowed only once the database clock says the time has passed.
    .bind::<Bool, _>(transition_id == "A07")
    .bind::<Bool, _>(transition_id == "A06")
    .bind::<Bool, _>(transition_id == "A10")
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("transition_attempt", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(refusal(connection, tenant, id, expected, epoch, &from, None).await?),
    }
}

async fn record_sandbox(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AttemptId,
    record: SandboxRecord,
) -> Result<(), StoreError> {
    // Allowed in any status, including after the attempt ended. `leaked` only rises.
    let changed = sql_query(
        "UPDATE attempts SET sandbox_id = $3, sandbox_leaked = sandbox_leaked OR $4, \
                version = version + 1 \
          WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<Text, _>(record.sandbox.as_str())
    .bind::<Bool, _>(record.leaked)
    .execute(connection)
    .await
    .map_err(|error| database("record_sandbox", &error))?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

#[async_trait]
impl AttemptOps for PgTx {
    async fn start_attempt(&mut self, start: StartAttempt) -> Result<StartedAttempt, StoreError> {
        call!(self, connection, tenant => start_attempt(connection, tenant, start))
    }

    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError> {
        call!(self, connection, tenant => async {
            find(connection, tenant, id).await?.ok_or(StoreError::NotFound)
        })
    }

    async fn list_attempts(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<Versioned<Attempt>>, StoreError> {
        call!(self, connection, tenant => list(connection, tenant, stage_run))
    }

    async fn heartbeat(&mut self, fence: Fence, ttl: Duration) -> Result<LeaseRenewal, StoreError> {
        call!(self, connection, tenant => heartbeat(connection, tenant, fence, ttl))
    }

    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
        end: AttemptEnd,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            transition(connection, tenant, id, expected, epoch, t, end)
        })
    }

    async fn record_sandbox(
        &mut self,
        id: AttemptId,
        record: SandboxRecord,
    ) -> Result<(), StoreError> {
        call!(self, connection, tenant => record_sandbox(connection, tenant, id, record))
    }
}
