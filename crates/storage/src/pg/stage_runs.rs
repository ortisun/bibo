//! Stage runs, and the claim of ready work.
//!
//! # Where the lease lives
//!
//! The port gives a stage run a lease (worker, epoch, expiry, ttl) and says a claim leaves the run
//! `READY`. The schema keeps no lease on `stage_runs`. The lease owner and expiry are columns of
//! `attempts`, and `lease_epoch` of a stage run may rise only together with `READY` to `RUNNING`
//! (trigger `stage_runs_lease_epoch_moves_with_claim`). So a claim here does what the reference
//! SQL of `docs/database/tests/lease.sql` does: in one tenant transaction it moves the run to
//! `RUNNING` with `lease_epoch + 1` and creates the attempt that carries the lease. The lease of a
//! stage run is read back from its newest attempt at the current epoch. The handover report lists
//! what this means for the port.

use std::time::Duration;

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{StageRunId, TenantId};
use factory_domain::state::{StageRunStatus, Status};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{
    AppliedTransition, ClaimedWork, Lease, LeaseEpoch, NewStageRun, StageRun, StoreError, Version,
    Versioned, WorkerId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Locked, Machine, lock};
use super::conv::{
    corrupt, from_column, job_from_column, job_to_column, micros, stage_run_from_column,
    stage_run_to_column, status_from_column, tenant_from_column, tenant_to_column, to_column,
    version_from_column,
};
use super::error::{Failure, constraint, generic};
use super::jobs::job_exists;
use super::store::Settings;
use crate::schema::stage_runs;

type StageRunRow = (Uuid, Uuid, Uuid, String, String, i64, i64, OffsetDateTime);

const STAGE_RUN_COLUMNS: (
    stage_runs::tenant_id,
    stage_runs::id,
    stage_runs::job_id,
    stage_runs::stage_kind,
    stage_runs::status,
    stage_runs::version,
    stage_runs::lease_epoch,
    stage_runs::created_at,
) = (
    stage_runs::tenant_id,
    stage_runs::id,
    stage_runs::job_id,
    stage_runs::stage_kind,
    stage_runs::status,
    stage_runs::version,
    stage_runs::lease_epoch,
    stage_runs::created_at,
);

#[derive(QueryableByName)]
struct LeaseRow {
    #[diesel(sql_type = Nullable<Text>)]
    owner: Option<String>,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<BigInt>)]
    ttl_micros: Option<i64>,
}

/// Reads a stage run, with the lease of its newest attempt at the current epoch.
pub(super) async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
) -> Result<Versioned<StageRun>, StoreError> {
    let row: Option<StageRunRow> = stage_runs::table
        .filter(stage_runs::tenant_id.eq(tenant_to_column(tenant)))
        .filter(stage_runs::id.eq(stage_run_to_column(id)))
        .select(STAGE_RUN_COLUMNS)
        .first(connection)
        .await
        .optional()
        .map_err(|error| generic("get_stage_run", &error))?;
    let Some((tenant_id, id, job_id, kind, status, version, epoch, created_at)) = row else {
        return Err(StoreError::NotFound);
    };
    let epoch = u64::try_from(epoch).map_err(|_| corrupt("lease epoch"))?;
    let lease = read_lease(connection, tenant_id, id, epoch).await?;
    Ok(Versioned {
        value: StageRun {
            id: stage_run_from_column(id),
            tenant_id: tenant_from_column(tenant_id),
            job_id: job_from_column(job_id),
            kind: StageKind::parse(&kind).map_err(|_| corrupt("stage kind"))?,
            status: status_from_column::<StageRunStatus>(&status)?,
            lease_epoch: LeaseEpoch::new(epoch),
            lease,
            created_at: from_column(created_at),
        },
        version: version_from_column(version)?,
    })
}

async fn read_lease(
    connection: &mut AsyncPgConnection,
    tenant: Uuid,
    stage_run: Uuid,
    epoch: u64,
) -> Result<Option<Lease>, StoreError> {
    if epoch == 0 {
        return Ok(None);
    }
    let row = sql_query(
        "SELECT lease_owner AS owner, lease_epoch AS epoch, lease_expires_at AS expires_at, \
                (extract(epoch FROM (lease_expires_at - coalesce(last_heartbeat_at, created_at))) \
                 * 1000000)::bigint AS ttl_micros \
           FROM attempts \
          WHERE tenant_id = $1 AND stage_run_id = $2 AND lease_epoch = $3 \
          ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind::<SqlUuid, _>(tenant)
    .bind::<SqlUuid, _>(stage_run)
    .bind::<BigInt, _>(i64::try_from(epoch).map_err(|_| corrupt("lease epoch"))?)
    .get_result::<LeaseRow>(connection)
    .await
    .optional()
    .map_err(|error| generic("get_stage_run", &error))?;
    let Some(row) = row else { return Ok(None) };
    let (Some(owner), Some(expires_at)) = (row.owner, row.expires_at) else {
        return Ok(None);
    };
    let ttl = row
        .ttl_micros
        .and_then(|micros| u64::try_from(micros).ok())
        .map_or(Duration::ZERO, Duration::from_micros);
    Ok(Some(Lease {
        worker: WorkerId::new(&owner).map_err(|_| corrupt("lease owner"))?,
        epoch: LeaseEpoch::new(u64::try_from(row.epoch).map_err(|_| corrupt("lease epoch"))?),
        expires_at: from_column(expires_at),
        ttl,
    }))
}

pub(super) async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewStageRun,
) -> Result<Versioned<StageRun>, StoreError> {
    if !job_exists(connection, tenant, new.job_id, "insert_stage_run").await? {
        return Err(StoreError::NotFound);
    }
    let inserted = sql_query(
        "INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status, created_at) \
         SELECT $1, $2, $3, $4, \
                coalesce((SELECT max(run_number) FROM stage_runs \
                           WHERE tenant_id = $1 AND job_id = $3 AND stage_kind = $4), 0) + 1, \
                $5, $6",
    )
    .bind::<SqlUuid, _>(tenant_to_column(tenant))
    .bind::<SqlUuid, _>(stage_run_to_column(new.id))
    .bind::<SqlUuid, _>(job_to_column(new.job_id))
    .bind::<Text, _>(new.kind.as_str())
    .bind::<Text, _>(StageRunStatus::INITIAL.to_string())
    .bind::<Timestamptz, _>(to_column(&new.created_at))
    .execute(connection)
    .await;
    if let Err(error) = inserted {
        return Err(match Failure::of(&error) {
            Failure::Unique(Some(name)) if name.contains("run_number") => StoreError::Conflict,
            Failure::Unique(name) => constraint("unique violation", name.as_deref()),
            Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
            _ => generic("insert_stage_run", &error),
        });
    }
    get(connection, tenant, new.id).await
}

/// The gate outcome that a move to `PASSED` or `SKIPPED` must record (`stage_runs_passed_has_outcome`
/// and `stage_runs_skipped_has_outcome`). The port carries no gate report, so the outcome follows
/// the transition: a gate that passed, a human approval and an accepted override.
fn gate_outcome_for(transition_id: &str) -> Option<&'static str> {
    match transition_id {
        "S08" | "S14" => Some("PASSED"),
        "S18" => Some("BLOCKED"),
        "S02" => Some("NOT_APPLICABLE"),
        _ => None,
    }
}

pub(super) async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
    expected: Version,
    plan: AppliedTransition<StageRunStatus>,
) -> Result<Version, StoreError> {
    let current = match lock(
        connection,
        Machine::StageRun,
        tenant_to_column(tenant),
        stage_run_to_column(id),
        "transition_stage_run",
    )
    .await?
    {
        Locked::Missing => return Err(StoreError::NotFound),
        Locked::Busy => return Err(StoreError::Conflict),
        Locked::Row { status, version } => (status, version),
    };
    if current.1 != expected.get() || current.0 != plan.from_status().to_string() {
        return Err(StoreError::Conflict);
    }
    let next = expected.next().map_err(|_| corrupt("version"))?;
    let finishes = plan.to_status().is_terminal() && !plan.from_status().is_terminal();
    // A move to RUNNING from READY is the claim of the schema: the epoch must rise with it.
    let epoch_step = i64::from(plan.transition_id() == "S03");
    let changed = sql_query(
        "UPDATE stage_runs SET status = $4, version = $5, \
                lease_epoch = lease_epoch + $6, \
                finished_at = CASE WHEN $7 THEN $8 ELSE finished_at END, \
                superseded_at = CASE WHEN $4 = 'SUPERSEDED' THEN $8 ELSE superseded_at END, \
                gate_outcome = coalesce($9, gate_outcome) \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $10",
    )
    .bind::<SqlUuid, _>(tenant_to_column(tenant))
    .bind::<SqlUuid, _>(stage_run_to_column(id))
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(plan.to_status().to_string())
    .bind::<BigInt, _>(next.get())
    .bind::<BigInt, _>(epoch_step)
    .bind::<Bool, _>(finishes)
    .bind::<Timestamptz, _>(to_column(&plan.at()))
    .bind::<Nullable<Text>, _>(gate_outcome_for(plan.transition_id()))
    .bind::<Text, _>(plan.from_status().to_string())
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("transition_stage_run", &error),
    })?;
    if changed == 1 {
        Ok(next)
    } else {
        Err(StoreError::Conflict)
    }
}

#[derive(QueryableByName)]
struct Claimable {
    #[diesel(sql_type = BigInt)]
    version: i64,
}

/// Claims one stage run for `worker` inside a tenant transaction.
///
/// Returns `None` when the run is no longer claimable: someone else holds or won it, it is not
/// `READY`, it is not yet due, its job is not active, or it has used every attempt it may make.
pub(super) async fn claim(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
    worker: &WorkerId,
    ttl: Duration,
    settings: &Settings,
) -> Result<Option<ClaimedWork>, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let id_raw = stage_run_to_column(id);
    let candidate = sql_query(
        "SELECT s.version FROM stage_runs s \
          WHERE s.tenant_id = $1 AND s.id = $2 AND s.status = 'READY' AND s.not_before <= now() \
            AND (NOT $3 OR EXISTS (SELECT 1 FROM jobs j WHERE j.tenant_id = s.tenant_id \
                                    AND j.id = s.job_id AND j.status = 'ACTIVE')) \
            AND (SELECT coalesce(max(a.attempt_number), 0) FROM attempts a \
                  WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id) < s.max_attempts \
          FOR NO KEY UPDATE OF s SKIP LOCKED",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .bind::<Bool, _>(settings.claim_only_active_jobs)
    .get_result::<Claimable>(connection)
    .await
    .optional()
    .map_err(|error| generic("claim_ready", &error))?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };

    let moved = sql_query(
        "UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'READY'",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .bind::<BigInt, _>(candidate.version)
    .execute(connection)
    .await
    .map_err(|error| generic("claim_ready", &error))?;
    if moved != 1 {
        return Ok(None);
    }

    // The lease is written in SQL from the database clock, never from a worker clock.
    sql_query(
        "INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, \
                               lease_epoch, lease_expires_at, last_heartbeat_at, deadline_at) \
         SELECT s.tenant_id, uuidv7(), s.job_id, s.id, \
                coalesce((SELECT max(a.attempt_number) FROM attempts a \
                           WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id), 0) + 1, \
                $3, s.lease_epoch, \
                now() + $4 * interval '1 microsecond', now(), \
                now() + $5 * interval '1 microsecond' \
           FROM stage_runs s WHERE s.tenant_id = $1 AND s.id = $2",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .bind::<Text, _>(worker.as_str())
    .bind::<BigInt, _>(micros(ttl))
    .bind::<BigInt, _>(micros(settings.attempt_timings.deadline))
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Unique(name) => constraint("unique violation", name.as_deref()),
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("claim_ready", &error),
    })?;

    let stage_run = get(connection, tenant, id).await?;
    let Some(lease) = stage_run.value.lease.clone() else {
        return Err(corrupt("claimed stage run without a lease"));
    };
    Ok(Some(ClaimedWork { stage_run, lease }))
}

/// Takes a stage run back from a worker whose lease ended, so it can be claimed again.
///
/// Inside one tenant transaction: the live attempts whose lease ended become `LEASE_LOST`
/// (transition A07), and the run goes back to `READY` (S05). Returns `false` when the run has no
/// live attempt with an ended lease, so nothing was changed.
pub(super) async fn take_back_expired(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
) -> Result<bool, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let id_raw = stage_run_to_column(id);
    let run = sql_query(
        "SELECT s.version FROM stage_runs s \
          WHERE s.tenant_id = $1 AND s.id = $2 AND s.status = 'RUNNING' \
            AND EXISTS (SELECT 1 FROM attempts a WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id \
                         AND a.status IN ('STARTING', 'RUNNING') AND a.lease_expires_at <= now()) \
          FOR NO KEY UPDATE OF s SKIP LOCKED",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .get_result::<Claimable>(connection)
    .await
    .optional()
    .map_err(|error| generic("claim_ready", &error))?;
    let Some(run) = run else { return Ok(false) };
    let lost = sql_query(
        "UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1 \
          WHERE tenant_id = $1 AND stage_run_id = $2 AND status IN ('STARTING', 'RUNNING') \
            AND lease_expires_at <= now()",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .execute(connection)
    .await
    .map_err(|error| generic("claim_ready", &error))?;
    if lost == 0 {
        return Ok(false);
    }
    let ready = sql_query(
        "UPDATE stage_runs SET status = 'READY', version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'RUNNING'",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(id_raw)
    .bind::<BigInt, _>(run.version)
    .execute(connection)
    .await
    .map_err(|error| generic("claim_ready", &error))?;
    Ok(ready == 1)
}
