//! Attempts, their heartbeats and the lease fence.
//!
//! The fence has two layers. This module checks the epoch in the code and answers `LeaseFenced`
//! before it writes. The database checks it again at commit (`attempts_live_attempt_has_current_epoch`),
//! so a write that skipped the code check still cannot leave a live attempt at a stale epoch.
//!
//! Lease expiry is judged by the database clock: every comparison and every new expiry is written
//! as `now()` plus an interval inside the statement. A worker clock never enters.

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{AttemptId, TenantId};
use factory_domain::state::{AttemptStatus, Status};
use factory_ports::store::{
    AppliedTransition, Attempt, LeaseEpoch, NewAttempt, StoreError, Version, Versioned, WorkerId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Machine, exists};
use super::conv::{
    attempt_from_column, attempt_to_column, corrupt, from_column, job_from_column, micros,
    stage_run_from_column, stage_run_to_column, status_from_column, tenant_from_column,
    tenant_to_column, to_column, version_from_column,
};
use super::error::{Failure, constraint, generic};
use super::store::Settings;
use crate::schema::attempts;

type AttemptRow = (
    Uuid,
    Uuid,
    Uuid,
    Uuid,
    i32,
    String,
    i64,
    Option<String>,
    i64,
    OffsetDateTime,
);

const ATTEMPT_COLUMNS: (
    attempts::tenant_id,
    attempts::id,
    attempts::job_id,
    attempts::stage_run_id,
    attempts::attempt_number,
    attempts::status,
    attempts::version,
    attempts::lease_owner,
    attempts::lease_epoch,
    attempts::created_at,
) = (
    attempts::tenant_id,
    attempts::id,
    attempts::job_id,
    attempts::stage_run_id,
    attempts::attempt_number,
    attempts::status,
    attempts::version,
    attempts::lease_owner,
    attempts::lease_epoch,
    attempts::created_at,
);

fn attempt_from_row(row: AttemptRow) -> Result<Versioned<Attempt>, StoreError> {
    let (tenant, id, job, stage_run, number, status, version, owner, epoch, created_at) = row;
    let owner = owner.ok_or_else(|| corrupt("attempt without a lease owner"))?;
    Ok(Versioned {
        value: Attempt {
            id: attempt_from_column(id),
            tenant_id: tenant_from_column(tenant),
            job_id: job_from_column(job),
            stage_run_id: stage_run_from_column(stage_run),
            number: u32::try_from(number).map_err(|_| corrupt("attempt number"))?,
            status: status_from_column::<AttemptStatus>(&status)?,
            worker: WorkerId::new(&owner).map_err(|_| corrupt("lease owner"))?,
            epoch: LeaseEpoch::new(u64::try_from(epoch).map_err(|_| corrupt("lease epoch"))?),
            created_at: from_column(created_at),
        },
        version: version_from_column(version)?,
    })
}

pub(super) async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AttemptId,
) -> Result<Versioned<Attempt>, StoreError> {
    let row: Option<AttemptRow> = attempts::table
        .filter(attempts::tenant_id.eq(tenant_to_column(tenant)))
        .filter(attempts::id.eq(attempt_to_column(id)))
        .select(ATTEMPT_COLUMNS)
        .first(connection)
        .await
        .optional()
        .map_err(|error| generic("get_attempt", &error))?;
    row.map_or(Err(StoreError::NotFound), attempt_from_row)
}

#[derive(QueryableByName)]
struct RunFacts {
    #[diesel(sql_type = BigInt)]
    run_epoch: i64,
    #[diesel(sql_type = Text)]
    run_status: String,
    #[diesel(sql_type = BigInt)]
    max_attempts_left: i64,
}

#[derive(QueryableByName)]
struct LiveAttempt {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

/// Registers the attempt of a claim.
///
/// A claim already created the attempt that carries the lease (see [`super::stage_runs`]). So this
/// call checks the epoch, and then either returns that attempt when its id is the one given, or
/// refuses with `Constraint` when another live attempt holds the lease. A stage run with no live
/// attempt has no lease to register against, which is `LeaseFenced`.
pub(super) async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewAttempt,
) -> Result<Versioned<Attempt>, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let run_raw = stage_run_to_column(new.stage_run_id);
    let facts = sql_query(
        "SELECT s.lease_epoch AS run_epoch, s.status AS run_status, \
                (s.max_attempts - coalesce((SELECT max(a.attempt_number) FROM attempts a \
                    WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id), 0))::bigint AS max_attempts_left \
           FROM stage_runs s WHERE s.tenant_id = $1 AND s.id = $2 \
          FOR NO KEY UPDATE OF s SKIP LOCKED",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(run_raw)
    .get_result::<RunFacts>(connection)
    .await
    .optional()
    .map_err(|error| generic("insert_attempt", &error))?;
    let Some(facts) = facts else {
        return Err(
            if exists(
                connection,
                Machine::StageRun,
                tenant_raw,
                run_raw,
                "insert_attempt",
            )
            .await?
            {
                StoreError::Conflict
            } else {
                StoreError::NotFound
            },
        );
    };
    let current_epoch = u64::try_from(facts.run_epoch).map_err(|_| corrupt("lease epoch"))?;
    if new.epoch.get() != current_epoch {
        return Err(StoreError::LeaseFenced);
    }
    let live = sql_query(
        "SELECT id FROM attempts WHERE tenant_id = $1 AND stage_run_id = $2 AND lease_epoch = $3 \
            AND status IN ('STARTING', 'RUNNING', 'CANCELLING') ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(run_raw)
    .bind::<BigInt, _>(facts.run_epoch)
    .get_result::<LiveAttempt>(connection)
    .await
    .optional()
    .map_err(|error| generic("insert_attempt", &error))?;
    let Some(live) = live else {
        // The run's status and attempts left are read only to explain a refusal in the log.
        tracing::debug!(
            run_status = facts.run_status.as_str(),
            attempts_left = facts.max_attempts_left,
            "insert_attempt found no lease to register against"
        );
        return Err(StoreError::LeaseFenced);
    };
    if live.id == attempt_to_column(new.id) {
        return get(connection, tenant, new.id).await;
    }
    Err(constraint("the stage run already has a live attempt", None))
}

/// The locked facts that decide a heartbeat or a transition of an attempt.
#[derive(QueryableByName)]
struct AttemptFacts {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = BigInt)]
    attempt_epoch: i64,
    #[diesel(sql_type = BigInt)]
    run_epoch: i64,
    #[diesel(sql_type = Bool)]
    lease_live: bool,
}

async fn lock_with_run(
    connection: &mut AsyncPgConnection,
    tenant: Uuid,
    id: Uuid,
    operation: &'static str,
) -> Result<AttemptFacts, StoreError> {
    let facts = sql_query(
        "SELECT a.status AS status, a.version AS version, a.lease_epoch AS attempt_epoch, \
                s.lease_epoch AS run_epoch, \
                coalesce(a.lease_expires_at > now(), false) AS lease_live \
           FROM attempts a \
           JOIN stage_runs s ON s.tenant_id = a.tenant_id AND s.id = a.stage_run_id \
          WHERE a.tenant_id = $1 AND a.id = $2 \
          FOR NO KEY UPDATE OF a SKIP LOCKED",
    )
    .bind::<SqlUuid, _>(tenant)
    .bind::<SqlUuid, _>(id)
    .get_result::<AttemptFacts>(connection)
    .await
    .optional()
    .map_err(|error| generic(operation, &error))?;
    match facts {
        Some(facts) => Ok(facts),
        None => {
            if exists(connection, Machine::Attempt, tenant, id, operation).await? {
                Err(StoreError::Conflict)
            } else {
                Err(StoreError::NotFound)
            }
        }
    }
}

const LIVE: [&str; 3] = ["STARTING", "RUNNING", "CANCELLING"];

fn is_live(status: &str) -> bool {
    LIVE.contains(&status)
}

fn epoch_matches(facts: &AttemptFacts, epoch: LeaseEpoch) -> bool {
    let given = i64::try_from(epoch.get()).unwrap_or(i64::MAX);
    facts.run_epoch == given && facts.attempt_epoch == given
}

pub(super) async fn heartbeat(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AttemptId,
    epoch: LeaseEpoch,
) -> Result<(), StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let id_raw = attempt_to_column(id);
    let facts = lock_with_run(connection, tenant_raw, id_raw, "heartbeat").await?;
    if !epoch_matches(&facts, epoch) {
        return Err(StoreError::LeaseFenced);
    }
    if !is_live(&facts.status) {
        return Err(StoreError::Conflict);
    }
    if !facts.lease_live {
        return Err(StoreError::LeaseFenced);
    }
    // The new expiry keeps the length of the lease: the time between the last renewal and the
    // current expiry. Both come from the database clock, so the sum is exact.
    let changed = sql_query(
        "UPDATE attempts SET lease_expires_at = now() + (lease_expires_at - coalesce(last_heartbeat_at, created_at)), \
                last_heartbeat_at = now(), version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND lease_epoch = $4 \
            AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now()",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .bind::<BigInt, _>(facts.version)
    .bind::<BigInt, _>(facts.attempt_epoch)
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("heartbeat", &error),
    })?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::Conflict)
    }
}

/// Events of the worker. A worker whose lease has ended may not send them. The sweeper's and the
/// canceller's events (A06 to A10) are not the worker's and are not refused for an ended lease.
fn is_worker_event(transition_id: &str) -> bool {
    matches!(transition_id, "A01" | "A02" | "A03" | "A04" | "A05")
}

/// The failure class a move to `FAILED` records. The port carries none, so it follows the
/// transition.
fn failure_class_for(transition_id: &str) -> Option<&'static str> {
    match transition_id {
        "A02" => Some("SANDBOX_ERROR"),
        "A05" => Some("TOOL_ERROR"),
        _ => None,
    }
}

pub(super) async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    settings: &Settings,
    id: AttemptId,
    expected: Version,
    epoch: LeaseEpoch,
    plan: AppliedTransition<AttemptStatus>,
) -> Result<Version, StoreError> {
    if plan.transition_id() == "A04" {
        // A succeeded attempt must name its output artifact (`attempts_succeeded_has_output`).
        // The port gives the store no output, so the move cannot be written.
        return Err(constraint(
            "a succeeded attempt needs an output artifact",
            None,
        ));
    }
    let tenant_raw = tenant_to_column(tenant);
    let id_raw = attempt_to_column(id);
    let facts = lock_with_run(connection, tenant_raw, id_raw, "transition_attempt").await?;
    if !epoch_matches(&facts, epoch) {
        return Err(StoreError::LeaseFenced);
    }
    if is_worker_event(plan.transition_id()) && is_live(&facts.status) && !facts.lease_live {
        return Err(StoreError::LeaseFenced);
    }
    if facts.version != expected.get() || facts.status != plan.from_status().to_string() {
        return Err(StoreError::Conflict);
    }
    let next = expected.next().map_err(|_| corrupt("version"))?;
    let ends = plan.to_status().is_terminal();
    let cancels = plan.transition_id() == "A08";
    let changed = sql_query(
        "UPDATE attempts SET status = $4, version = $5, \
                ended_at = CASE WHEN $6 THEN $7 ELSE ended_at END, \
                failure_class = coalesce($8, failure_class), \
                teardown_deadline_at = CASE WHEN $9 THEN now() + $10 * interval '1 microsecond' ELSE teardown_deadline_at END \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $11 AND lease_epoch = $12",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(plan.to_status().to_string())
    .bind::<BigInt, _>(next.get())
    .bind::<Bool, _>(ends)
    .bind::<Timestamptz, _>(to_column(&plan.at()))
    .bind::<Nullable<Text>, _>(failure_class_for(plan.transition_id()))
    .bind::<Bool, _>(cancels)
    .bind::<BigInt, _>(micros(settings.attempt_timings.teardown_grace))
    .bind::<Text, _>(plan.from_status().to_string())
    .bind::<BigInt, _>(facts.attempt_epoch)
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("transition_attempt", &error),
    })?;
    if changed == 1 {
        Ok(next)
    } else {
        Err(StoreError::Conflict)
    }
}
