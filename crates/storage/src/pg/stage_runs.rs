//! Stage runs.
//!
//! A stage run holds no lease: it holds `lease_epoch`, a counter that rises by one only when the
//! run goes from `READY` to `RUNNING`, and only inside `start_attempt` (see [`super::attempts`]).
//! `transition_stage_run` therefore refuses `S03`, and never writes the epoch.
//!
//! # Rules that ride on a transition
//!
//! The gate record, the contract hash and the back-off are checked here against
//! [`stage_run_effects_rule`] before any statement runs, so a refusal leaves the transaction
//! usable. The database enforces the same rules (`stage_runs_*_has_outcome`,
//! `stage_runs_failing_set_*`, `stage_runs_not_before_only_when_ready`) as the last line.
//!
//! # Times
//!
//! `finished_at`, `superseded_at` and `not_before` come from `now()` in the statement. A move into
//! `READY` sets `not_before` to `now()` plus the delay of the effects (zero when absent).

use std::time::Duration;

use async_trait::async_trait;
use diesel::sql_types::{
    BigInt, Bool, Integer, Nullable, SmallInt, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::state::{StageRunStatus, Status};
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::store::{
    AppliedTransition, ConstraintRule, GateRecord, Inserted, NewStageRun, StageRun,
    StageRunEffects, StageRunOps, StoreError, Version, Versioned, stage_run_effects_rule,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists, no_row_changed};
use super::conv::{
    corrupt, digest_from_column, epoch_from_column, from_column, micros, status_from_column,
    version_from_column,
};
use super::error::database;
use super::tx::{PgTx, call};

const COLUMNS: &str = "tenant_id, id, job_id, stage_kind, run_number, status, version, \
    lease_epoch, max_attempts, not_before, rework_of_stage_run_id, stage_contract_sha256, \
    gate_outcome, gate_report_sha256, failing_set_sha256, created_at, finished_at, superseded_at";

#[derive(QueryableByName)]
pub(super) struct StageRunRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = Text)]
    stage_kind: String,
    #[diesel(sql_type = Integer)]
    run_number: i32,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = BigInt)]
    lease_epoch: i64,
    #[diesel(sql_type = SmallInt)]
    max_attempts: i16,
    #[diesel(sql_type = Timestamptz)]
    not_before: OffsetDateTime,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    rework_of_stage_run_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    stage_contract_sha256: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    gate_outcome: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    gate_report_sha256: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    failing_set_sha256: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    finished_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    superseded_at: Option<OffsetDateTime>,
}

pub(super) fn stage_run_from_row(row: StageRunRow) -> Result<Versioned<StageRun>, StoreError> {
    let gate = match row.gate_outcome.as_deref() {
        Some(name) => Some(GateRecord {
            outcome: GateOutcome::parse(name).map_err(|_| corrupt("gate outcome"))?,
            report_sha256: row
                .gate_report_sha256
                .as_deref()
                .map(digest_from_column)
                .transpose()?,
            failing_set_sha256: row
                .failing_set_sha256
                .as_deref()
                .map(digest_from_column)
                .transpose()?,
        }),
        None => None,
    };
    Ok(Versioned {
        value: StageRun {
            id: StageRunId::from_uuid(row.id),
            tenant_id: TenantId::from_uuid(row.tenant_id),
            job_id: JobId::from_uuid(row.job_id),
            kind: StageKind::parse(&row.stage_kind).map_err(|_| corrupt("stage kind"))?,
            run_number: u32::try_from(row.run_number).map_err(|_| corrupt("run number"))?,
            status: status_from_column::<StageRunStatus>(&row.status)?,
            lease_epoch: epoch_from_column(row.lease_epoch)?,
            max_attempts: u8::try_from(row.max_attempts).map_err(|_| corrupt("max attempts"))?,
            not_before: from_column(row.not_before),
            rework_of: row.rework_of_stage_run_id.map(StageRunId::from_uuid),
            contract_sha256: row
                .stage_contract_sha256
                .as_deref()
                .map(digest_from_column)
                .transpose()?,
            gate,
            created_at: from_column(row.created_at),
            finished_at: row.finished_at.map(from_column),
            superseded_at: row.superseded_at.map(from_column),
        },
        version: version_from_column(row.version)?,
    })
}

pub(super) async fn find(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
) -> Result<Option<Versioned<StageRun>>, StoreError> {
    sql_query(format!(
        "SELECT {COLUMNS} FROM stage_runs WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<StageRunRow>(connection)
    .await
    .optional()
    .map_err(|error| database("get_stage_run", &error))?
    .map(stage_run_from_row)
    .transpose()
}

fn same_run(stored: &StageRun, new: &NewStageRun) -> bool {
    stored.job_id == new.job_id
        && stored.kind == new.kind
        && stored.run_number == new.run_number
        && stored.max_attempts == new.max_attempts
        && stored.rework_of == new.rework_of
}

async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewStageRun,
) -> Result<Inserted<StageRun>, StoreError> {
    let run_number = i32::try_from(new.run_number)
        .map_err(|_| StoreError::Constraint(ConstraintRule::TextBounds))?;
    // No conflict target: a clash on the run number of the job, with another id, is absorbed too.
    let inserted = sql_query(format!(
        "INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status, \
                max_attempts, rework_of_stage_run_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT DO NOTHING RETURNING {COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .bind::<SqlUuid, _>(new.job_id.as_uuid())
    .bind::<Text, _>(new.kind.as_str())
    .bind::<Integer, _>(run_number)
    .bind::<Text, _>(StageRunStatus::INITIAL.to_string())
    .bind::<SmallInt, _>(i16::from(new.max_attempts))
    .bind::<Nullable<SqlUuid>, _>(new.rework_of.map(|run| run.as_uuid()))
    .get_result::<StageRunRow>(connection)
    .await
    .optional()
    .map_err(|error| database("insert_stage_run", &error))?;
    if let Some(row) = inserted {
        return Ok(Inserted {
            row: stage_run_from_row(row)?,
            created: true,
        });
    }
    match find(connection, tenant, new.id).await? {
        Some(found) if same_run(&found.value, &new) => Ok(Inserted {
            row: found,
            created: false,
        }),
        // The id holds other content, or the position of the run is taken by another id.
        _ => Err(StoreError::Constraint(
            ConstraintRule::IdReusedWithDifferentContent,
        )),
    }
}

async fn list(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
) -> Result<Vec<Versioned<StageRun>>, StoreError> {
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM stage_runs WHERE tenant_id = $1 AND job_id = $2 \
          ORDER BY created_at, run_number, id"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .load::<StageRunRow>(connection)
    .await
    .map_err(|error| database("list_stage_runs", &error))?;
    if rows.is_empty()
        && !exists(
            connection,
            Table::Jobs,
            tenant,
            job.as_uuid(),
            "list_stage_runs",
        )
        .await?
    {
        return Err(StoreError::NotFound);
    }
    rows.into_iter().map(stage_run_from_row).collect()
}

#[derive(QueryableByName)]
struct NewVersion {
    #[diesel(sql_type = BigInt)]
    version: i64,
}

#[derive(QueryableByName)]
struct Current {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
}

/// Why a transition or a postponement cannot go ahead, when its own rules held: no such row, the
/// row moved since it was read, or (when `rule` is given) the rule of the effects was broken.
async fn refusal(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
    expected: Version,
    from: &str,
    rule: Option<StoreError>,
) -> Result<StoreError, StoreError> {
    let current =
        sql_query("SELECT status, version FROM stage_runs WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(id.as_uuid())
            .get_result::<Current>(connection)
            .await
            .optional()
            .map_err(|error| database("transition_stage_run", &error))?;
    Ok(match current {
        None => StoreError::NotFound,
        Some(row) if row.version != expected.get() || row.status != from => StoreError::Conflict,
        Some(_) => rule.unwrap_or(StoreError::Conflict),
    })
}

/// The effects must be the ones the transition requires, and no others.
fn check_effects(transition_id: &str, effects: &StageRunEffects) -> Result<(), StoreError> {
    let broken = || StoreError::Constraint(ConstraintRule::GateRecordRule);
    let rule = stage_run_effects_rule(transition_id);
    match (rule.gate, &effects.gate) {
        (Some(want), Some(have)) if have.outcome == want => {
            // A report is stored for every outcome but NOT_APPLICABLE; a failing set belongs to
            // FAILED only (`stage_runs_failing_set_needs_failed_outcome`).
            if have.report_sha256.is_none() && want != GateOutcome::NotApplicable {
                return Err(broken());
            }
            if have.failing_set_sha256.is_some() && want != GateOutcome::Failed {
                return Err(broken());
            }
        }
        (None, None) => {}
        _ => return Err(broken()),
    }
    if rule.contract != effects.contract_sha256.is_some() {
        return Err(broken());
    }
    Ok(())
}

async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
    expected: Version,
    t: AppliedTransition<StageRunStatus>,
    effects: StageRunEffects,
) -> Result<Version, StoreError> {
    let from = t.from_status().to_string();
    // `S03` creates the attempt that carries the epoch, so it is made by `start_attempt` only.
    let rule = if t.transition_id() == "S03" {
        Some(StoreError::Constraint(ConstraintRule::IllegalStatusMove))
    } else {
        check_effects(t.transition_id(), &effects).err()
    };
    if rule.is_some() {
        return Err(refusal(connection, tenant, id, expected, &from, rule).await?);
    }
    let to = t.to_status();
    let delay = effects.not_before_after.map_or(0, micros);
    let gate = effects.gate.as_ref();
    let updated = sql_query(
        "UPDATE stage_runs SET status = $4, version = version + 1, \
                finished_at = CASE WHEN $5 THEN coalesce(finished_at, now()) ELSE finished_at END, \
                superseded_at = CASE WHEN $6 THEN now() ELSE superseded_at END, \
                not_before = CASE WHEN $7 THEN now() + $8 * interval '1 microsecond' \
                                  ELSE not_before END, \
                stage_contract_sha256 = coalesce($9, stage_contract_sha256), \
                gate_outcome = coalesce($10, gate_outcome), \
                gate_report_sha256 = coalesce($11, gate_report_sha256), \
                failing_set_sha256 = coalesce($12, failing_set_sha256) \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $13 \
          RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(to.to_string())
    .bind::<Bool, _>(to.is_terminal())
    .bind::<Bool, _>(to == StageRunStatus::Superseded)
    .bind::<Bool, _>(to == StageRunStatus::Ready)
    .bind::<BigInt, _>(delay)
    .bind::<Nullable<Text>, _>(
        effects
            .contract_sha256
            .as_ref()
            .map(|hash| hash.as_str().to_owned()),
    )
    .bind::<Nullable<Text>, _>(gate.map(|gate| gate.outcome.as_str().to_owned()))
    .bind::<Nullable<Text>, _>(
        gate.and_then(|gate| gate.report_sha256.as_ref())
            .map(|hash| hash.as_str().to_owned()),
    )
    .bind::<Nullable<Text>, _>(
        gate.and_then(|gate| gate.failing_set_sha256.as_ref())
            .map(|hash| hash.as_str().to_owned()),
    )
    .bind::<Text, _>(from)
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("transition_stage_run", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(no_row_changed(
            connection,
            Table::StageRuns,
            tenant,
            id.as_uuid(),
            "transition_stage_run",
        )
        .await?),
    }
}

async fn postpone(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: StageRunId,
    expected: Version,
    delay: Duration,
) -> Result<Version, StoreError> {
    let current =
        sql_query("SELECT status, version FROM stage_runs WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(id.as_uuid())
            .get_result::<Current>(connection)
            .await
            .optional()
            .map_err(|error| database("postpone_stage_run", &error))?
            .ok_or(StoreError::NotFound)?;
    if current.version != expected.get() {
        return Err(StoreError::Conflict);
    }
    let status = status_from_column::<StageRunStatus>(&current.status)?;
    if status.is_terminal() {
        return Err(StoreError::Constraint(ConstraintRule::TerminalRowImmutable));
    }
    // The only update of a stage run that is not a transition, and only while it waits to start.
    let updated = sql_query(
        "UPDATE stage_runs SET not_before = now() + $4 * interval '1 microsecond', \
                version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'READY' \
          RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<BigInt, _>(micros(delay))
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("postpone_stage_run", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(StoreError::Conflict),
    }
}

#[async_trait]
impl StageRunOps for PgTx {
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Inserted<StageRun>, StoreError> {
        call!(self, connection, tenant => insert(connection, tenant, new))
    }

    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError> {
        call!(self, connection, tenant => async {
            find(connection, tenant, id).await?.ok_or(StoreError::NotFound)
        })
    }

    async fn list_stage_runs(
        &mut self,
        job: JobId,
    ) -> Result<Vec<Versioned<StageRun>>, StoreError> {
        call!(self, connection, tenant => list(connection, tenant, job))
    }

    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
        effects: StageRunEffects,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            transition(connection, tenant, id, expected, t, effects)
        })
    }

    async fn postpone_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        delay: Duration,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => postpone(connection, tenant, id, expected, delay))
    }
}
