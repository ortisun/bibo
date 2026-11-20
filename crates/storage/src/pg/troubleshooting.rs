//! The troubleshooter's own rows (ADR 0021): its runs, the state of each probe, the map from a
//! finding's fingerprint to its triage issue, and the counters of one UTC day
//! (migration `2026-11-20-003000_troubleshooting_runs`).
//!
//! # Why a concrete store and no port
//!
//! A port is what an inner ring needs from the outside (ADR 0002, ring 1). No use case of the
//! pipeline reads these rows: only `apps/troubleshooter`, a composition root, does, and a root may
//! use an adapter directly. Putting these calls on the `Tx` of the `Store` port would make every
//! store implementation (the in-memory fake included) carry the troubleshooter's tables, and the
//! engine would gain methods it never calls. So [`TroubleshootingStore`] is a type of this crate,
//! with the conventions of the rest of it: a pool per login, a tenant transaction that starts with
//! the tenant setting and the pool's limits, closed errors that never carry a database message,
//! and the start-up checks of the login (a member of `factory_app` only) and of the schema.
//!
//! # One troubleshooter at a time
//!
//! [`TroubleshooterLock`] is a PostgreSQL session-level advisory lock held on a connection of its
//! own, outside the pool. It was chosen over a lease row:
//!
//! * the database ends it when the holder's session ends, so a process that dies or loses its
//!   connection gives the lock up without a lease length to tune or a clock to trust;
//! * a second instance asks with `pg_try_advisory_lock`, gets `false` and idles, and nothing is
//!   written to decide it;
//! * the holder asks [`TroubleshooterLock::still_held`] before each pass, so a connection that was
//!   cut (and with it the lock) stops the holder's work before another instance can take over.
//!
//! The lock is per database (PostgreSQL scopes advisory locks to the current database), which is
//! the scope of one factory deployment.

use std::time::Duration;

use diesel::sql_types::{Array, BigInt, Bool, Integer, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{
    AnsiTransactionManager, AsyncConnection, AsyncPgConnection, RunQueryDsl, TransactionManager,
};
use factory_domain::ids::TenantId;
use factory_domain::troubleshooting::{GatewayCallId, TroubleshootingRunId};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_ports::store::StoreError;
use time::OffsetDateTime;

use super::config::{DatabaseUrl, PoolSettings};
use super::conv::{corrupt, digest_from_column, from_column, unsigned_from_column};
use super::error::{StartupError, database};
use super::pool::{PgPool, PooledConnection};
use super::readiness::{self, Expected};
use super::tx::{finish_rollback, start};

/// The key of the advisory lock that one active troubleshooter holds: "FAC" and ADR 0021.
pub const TROUBLESHOOTER_LOCK_KEY: i64 = 0x0FAC_0021_0001;

/// Why a troubleshooting run started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunTrigger {
    /// One or more probes tripped, or a probe's source was unavailable.
    Probe,
    /// The slow sweep came due.
    Sweep,
}

impl RunTrigger {
    /// The column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Sweep => "sweep",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "probe" => Ok(Self::Probe),
            "sweep" => Ok(Self::Sweep),
            _ => Err(corrupt("run trigger")),
        }
    }
}

/// How a run ended. The set is the CHECK constraint of the column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// The agent reported that nothing is wrong.
    Healthy,
    /// The agent reported findings, and they were accepted.
    Findings,
    /// The agent asked a person a question.
    NeedsHuman,
    /// The agent could not investigate.
    Blocked,
    /// Only `source_unavailable` findings, raised without the model.
    SourceUnavailable,
    /// An observation cited a call the gateway did not record for the run; the report was
    /// refused and no issue was written from it.
    EvidenceMismatch,
    /// The report did not pass the `health-findings` schema.
    ReportInvalid,
    /// The agent did not produce a report (timeout, process failure, no output).
    AgentFailed,
    /// The day's cap of agent runs was reached; the agent did not run.
    CapReached,
    /// The day's spend ceiling of the role was reached; the agent did not run.
    SpendCeiling,
    /// Something of the troubleshooter's own failed (a gateway run, the sandbox, the store).
    Failed,
}

impl RunOutcome {
    /// The column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Findings => "findings",
            Self::NeedsHuman => "needs_human",
            Self::Blocked => "blocked",
            Self::SourceUnavailable => "source_unavailable",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::ReportInvalid => "report_invalid",
            Self::AgentFailed => "agent_failed",
            Self::CapReached => "cap_reached",
            Self::SpendCeiling => "spend_ceiling",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        [
            Self::Healthy,
            Self::Findings,
            Self::NeedsHuman,
            Self::Blocked,
            Self::SourceUnavailable,
            Self::EvidenceMismatch,
            Self::ReportInvalid,
            Self::AgentFailed,
            Self::CapReached,
            Self::SpendCeiling,
            Self::Failed,
        ]
        .into_iter()
        .find(|outcome| outcome.as_str() == text)
        .ok_or_else(|| corrupt("run outcome"))
    }
}

/// A run to record when it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRun {
    /// The run.
    pub id: TroubleshootingRunId,
    /// Why it started.
    pub trigger: RunTrigger,
    /// When, by the troubleshooter's clock.
    pub started_at: Timestamp,
    /// Nothing is written to GitHub in this run.
    pub dry_run: bool,
    /// Datadog is configured, so its probes and tools are on.
    pub datadog_enabled: bool,
}

/// What a run left, written when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEnd {
    /// The run.
    pub id: TroubleshootingRunId,
    /// When it ended.
    pub ended_at: Timestamp,
    /// How it ended.
    pub outcome: RunOutcome,
    /// The model spend of the run, in millionths of a dollar.
    pub spend_micro_usd: u64,
    /// The SHA-256 of the report bytes, when the agent returned any.
    pub report_sha256: Option<Sha256Digest>,
    /// The digest of the gateway's run record (canonical JSON).
    pub gateway_record_sha256: Option<Sha256Digest>,
    /// The agent ran in this run.
    pub agent_ran: bool,
    /// New issues opened.
    pub issues_opened: u32,
    /// "Seen again" comments posted.
    pub comments_posted: u32,
    /// The fingerprints of findings the day's cap of new issues kept back. At most 20.
    pub deferred: Vec<Sha256Digest>,
}

/// A run as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    /// The run.
    pub id: TroubleshootingRunId,
    /// Why it started.
    pub trigger: RunTrigger,
    /// When it started.
    pub started_at: Timestamp,
    /// When it ended, once it has.
    pub ended_at: Option<Timestamp>,
    /// How it ended, once it has.
    pub outcome: Option<RunOutcome>,
    /// The model spend, in millionths of a dollar.
    pub spend_micro_usd: u64,
    /// The digest of the report bytes.
    pub report_sha256: Option<Sha256Digest>,
    /// The digest of the gateway's run record.
    pub gateway_record_sha256: Option<Sha256Digest>,
    /// The agent ran.
    pub agent_ran: bool,
    /// Nothing was written to GitHub.
    pub dry_run: bool,
    /// Datadog was on.
    pub datadog_enabled: bool,
    /// New issues opened.
    pub issues_opened: u32,
    /// Comments posted.
    pub comments_posted: u32,
    /// Findings kept back by the cap.
    pub deferred: Vec<Sha256Digest>,
}

/// What a probe found the last time it ran. The set is the CHECK constraint of the column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe ran and did not trip.
    Ok,
    /// The probe tripped.
    Tripped,
    /// The source answered with no value.
    NoData,
    /// The source did not answer.
    SourceUnavailable,
    /// The probe's source is not configured (Datadog absent, VictoriaMetrics absent).
    Disabled,
}

impl ProbeOutcome {
    /// The column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Tripped => "tripped",
            Self::NoData => "no_data",
            Self::SourceUnavailable => "source_unavailable",
            Self::Disabled => "disabled",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        [
            Self::Ok,
            Self::Tripped,
            Self::NoData,
            Self::SourceUnavailable,
            Self::Disabled,
        ]
        .into_iter()
        .find(|outcome| outcome.as_str() == text)
        .ok_or_else(|| corrupt("probe outcome"))
    }
}

/// One probe result to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// The probe id of the policy.
    pub probe_id: String,
    /// What it found.
    pub outcome: ProbeOutcome,
    /// The observed value, as the exact decimal text it was compared in.
    pub value: Option<String>,
    /// The gateway call it ran under, when it ran through the gateway.
    pub call_id: Option<GatewayCallId>,
    /// The gateway run of the pass.
    pub run: Option<TroubleshootingRunId>,
    /// When it ran.
    pub checked_at: Timestamp,
}

/// The stored state of one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeState {
    /// The probe id.
    pub probe_id: String,
    /// What it found the last time.
    pub last_outcome: ProbeOutcome,
    /// The value it saw the last time.
    pub last_value: Option<String>,
    /// The call it ran under the last time.
    pub last_call_id: Option<GatewayCallId>,
    /// When it last ran.
    pub last_checked_at: Timestamp,
    /// When it last tripped.
    pub last_tripped_at: Option<Timestamp>,
    /// Until when a trip of it starts no agent run.
    pub cooldown_until: Option<Timestamp>,
}

/// The triage issue of a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueEntry {
    /// The fingerprint, `sha256:` and 64 hex characters.
    pub fingerprint: Sha256Digest,
    /// The finding's category, as the schema names it.
    pub category: String,
    /// The finding's component.
    pub component: String,
    /// The issue title as code rendered it.
    pub title: String,
    /// The repository, `owner/name`.
    pub repository: String,
    /// The issue number.
    pub issue_number: u64,
    /// When the troubleshooter opened it.
    pub opened_at: Timestamp,
    /// The last UTC day a "seen again" comment was posted, `YYYY-MM-DD`.
    pub last_comment_day: Option<String>,
    /// How many comments were posted on that day.
    pub comments_on_last_day: u32,
}

/// An issue to record for a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewIssue<'a> {
    /// The fingerprint.
    pub fingerprint: &'a Sha256Digest,
    /// The finding's category.
    pub category: &'a str,
    /// The finding's component.
    pub component: &'a str,
    /// The issue title as code rendered it, at most 200 characters.
    pub title: &'a str,
    /// The repository, `owner/name`.
    pub repository: &'a str,
    /// The issue number.
    pub issue_number: u64,
    /// When it was opened.
    pub opened_at: &'a Timestamp,
}

/// The counters of one UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DayCounters {
    /// Agent runs started.
    pub agent_runs: u32,
    /// New issues opened.
    pub new_issues: u32,
    /// "Seen again" comments posted.
    pub comments: u32,
    /// Model spend, in millionths of a dollar.
    pub spend_micro_usd: u64,
}

/// What to add to the counters of a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DayIncrement {
    /// Agent runs.
    pub agent_runs: u32,
    /// New issues.
    pub new_issues: u32,
    /// Comments.
    pub comments: u32,
    /// Spend, in millionths of a dollar.
    pub spend_micro_usd: u64,
}

/// The UTC calendar day of an instant, `YYYY-MM-DD`.
#[must_use]
pub fn utc_day(at: &Timestamp) -> String {
    let date = at.to_utc().date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The store of the troubleshooter's rows, for one tenant.
#[derive(Debug, Clone)]
pub struct TroubleshootingStore {
    pool: PgPool,
    tenant: TenantId,
    statement_timeout: Duration,
    lock_timeout: Duration,
}

#[derive(QueryableByName)]
struct RunRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    trigger: String,
    #[diesel(sql_type = Timestamptz)]
    started_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    ended_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    outcome: Option<String>,
    #[diesel(sql_type = BigInt)]
    spend_micro_usd: i64,
    #[diesel(sql_type = Nullable<Text>)]
    report_sha256: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    gateway_record_sha256: Option<String>,
    #[diesel(sql_type = Bool)]
    agent_ran: bool,
    #[diesel(sql_type = Bool)]
    dry_run: bool,
    #[diesel(sql_type = Bool)]
    datadog_enabled: bool,
    #[diesel(sql_type = Integer)]
    issues_opened: i32,
    #[diesel(sql_type = Integer)]
    comments_posted: i32,
    #[diesel(sql_type = Array<Text>)]
    deferred_fingerprints: Vec<String>,
}

const RUN_COLUMNS: &str = "id, trigger, started_at, ended_at, outcome, spend_micro_usd, report_sha256, \
     gateway_record_sha256, agent_ran, dry_run, datadog_enabled, issues_opened, comments_posted, \
     deferred_fingerprints";

#[derive(QueryableByName)]
struct ProbeRow {
    #[diesel(sql_type = Text)]
    probe_id: String,
    #[diesel(sql_type = Text)]
    last_outcome: String,
    #[diesel(sql_type = Nullable<Text>)]
    last_value: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_call_id: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    last_checked_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_tripped_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    cooldown_until: Option<OffsetDateTime>,
}

#[derive(QueryableByName)]
struct IssueRow {
    #[diesel(sql_type = Text)]
    fingerprint: String,
    #[diesel(sql_type = Text)]
    category: String,
    #[diesel(sql_type = Text)]
    component: String,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Text)]
    repository: String,
    #[diesel(sql_type = BigInt)]
    issue_number: i64,
    #[diesel(sql_type = Timestamptz)]
    opened_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Text>)]
    last_comment_day: Option<String>,
    #[diesel(sql_type = Integer)]
    comments_on_last_day: i32,
}

#[derive(QueryableByName)]
struct CounterRow {
    #[diesel(sql_type = Integer)]
    agent_runs: i32,
    #[diesel(sql_type = Integer)]
    new_issues: i32,
    #[diesel(sql_type = Integer)]
    comments: i32,
    #[diesel(sql_type = BigInt)]
    spend_micro_usd: i64,
}

#[derive(QueryableByName)]
struct Held {
    #[diesel(sql_type = Bool)]
    held: bool,
}

fn small(value: i32, what: &'static str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| corrupt(what))
}

fn big(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn count(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn instant(at: &Timestamp) -> OffsetDateTime {
    at.to_utc()
}

fn run_from_row(row: RunRow) -> Result<RunRecord, StoreError> {
    Ok(RunRecord {
        id: TroubleshootingRunId::parse(&row.id).map_err(|_| corrupt("run id"))?,
        trigger: RunTrigger::parse(&row.trigger)?,
        started_at: from_column(row.started_at),
        ended_at: row.ended_at.map(from_column),
        outcome: row.outcome.as_deref().map(RunOutcome::parse).transpose()?,
        spend_micro_usd: unsigned_from_column(row.spend_micro_usd, "spend")?,
        report_sha256: row
            .report_sha256
            .as_deref()
            .map(digest_from_column)
            .transpose()?,
        gateway_record_sha256: row
            .gateway_record_sha256
            .as_deref()
            .map(digest_from_column)
            .transpose()?,
        agent_ran: row.agent_ran,
        dry_run: row.dry_run,
        datadog_enabled: row.datadog_enabled,
        issues_opened: small(row.issues_opened, "issues opened")?,
        comments_posted: small(row.comments_posted, "comments posted")?,
        deferred: row
            .deferred_fingerprints
            .iter()
            .map(|text| digest_from_column(text))
            .collect::<Result<_, _>>()?,
    })
}

fn probe_from_row(row: ProbeRow) -> Result<ProbeState, StoreError> {
    Ok(ProbeState {
        probe_id: row.probe_id,
        last_outcome: ProbeOutcome::parse(&row.last_outcome)?,
        last_value: row.last_value,
        last_call_id: row
            .last_call_id
            .as_deref()
            .map(|text| GatewayCallId::parse(text).map_err(|_| corrupt("call id")))
            .transpose()?,
        last_checked_at: from_column(row.last_checked_at),
        last_tripped_at: row.last_tripped_at.map(from_column),
        cooldown_until: row.cooldown_until.map(from_column),
    })
}

fn issue_from_row(row: IssueRow) -> Result<IssueEntry, StoreError> {
    Ok(IssueEntry {
        fingerprint: digest_from_column(&row.fingerprint)?,
        category: row.category,
        component: row.component,
        title: row.title,
        repository: row.repository,
        issue_number: unsigned_from_column(row.issue_number, "issue number")?,
        opened_at: from_column(row.opened_at),
        last_comment_day: row.last_comment_day,
        comments_on_last_day: small(row.comments_on_last_day, "comments on the last day")?,
    })
}

impl TroubleshootingStore {
    /// Builds the pool, checks that its login is a member of `factory_app` and nothing that would
    /// widen it, and that the database has every migration the code expects (this one included).
    ///
    /// # Errors
    /// [`StartupError`], as `PgStore::connect` reports it.
    pub async fn connect(settings: &PoolSettings, tenant: TenantId) -> Result<Self, StartupError> {
        let pool = PgPool::new("troubleshooter", settings)?;
        let mut connection = pool.get().await.map_err(|_| StartupError::Unreachable {
            pool: "troubleshooter",
        })?;
        readiness::check_role(&mut connection, "troubleshooter", Expected::Worker).await?;
        readiness::check_schema(&mut connection).await?;
        drop(connection);
        Ok(Self {
            pool,
            tenant,
            statement_timeout: settings.statement_timeout,
            lock_timeout: settings.lock_timeout,
        })
    }

    /// The tenant this store writes for.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    async fn begin(&self) -> Result<PooledConnection, StoreError> {
        let mut connection = self.pool.get().await?;
        start(
            &mut connection,
            self.tenant,
            self.statement_timeout,
            self.lock_timeout,
        )
        .await?;
        Ok(connection)
    }

    async fn end<T>(
        mut connection: PooledConnection,
        outcome: Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        match outcome {
            Ok(value) => {
                <AnsiTransactionManager as TransactionManager<AsyncPgConnection>>::commit_transaction(
                    &mut connection,
                )
                .await
                .map_err(|error| database("commit", &error))?;
                Ok(value)
            }
            Err(error) => {
                if finish_rollback(&mut connection).await.is_err() {
                    drop(PooledConnection::take(connection));
                }
                Err(error)
            }
        }
    }

    /// Records a run that starts. A second call with the same id is refused by the key.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn begin_run(&self, run: &NewRun) -> Result<(), StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "INSERT INTO troubleshooting_runs (tenant_id, id, trigger, started_at, dry_run, datadog_enabled) \
             VALUES ($1::uuid, $2, $3, $4, $5, $6)",
        )
        .bind::<Text, _>(self.tenant.to_string())
        .bind::<Text, _>(run.id.as_str())
        .bind::<Text, _>(run.trigger.as_str())
        .bind::<Timestamptz, _>(instant(&run.started_at))
        .bind::<Bool, _>(run.dry_run)
        .bind::<Bool, _>(run.datadog_enabled)
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| database("troubleshooting.begin_run", &error));
        Self::end(connection, outcome).await
    }

    /// Records how a run ended. A run that already ended is not changed again
    /// (`StoreError::NotFound`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn finish_run(&self, end: &RunEnd) -> Result<(), StoreError> {
        let deferred: Vec<String> = end
            .deferred
            .iter()
            .take(20)
            .map(|digest| digest.as_str().to_owned())
            .collect();
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "UPDATE troubleshooting_runs SET state = 'finished', ended_at = $2, outcome = $3, \
                    spend_micro_usd = $4, report_sha256 = $5, gateway_record_sha256 = $6, agent_ran = $7, \
                    issues_opened = $8, comments_posted = $9, deferred_fingerprints = $10 \
              WHERE id = $1 AND state = 'running'",
        )
        .bind::<Text, _>(end.id.as_str())
        .bind::<Timestamptz, _>(instant(&end.ended_at))
        .bind::<Text, _>(end.outcome.as_str())
        .bind::<BigInt, _>(big(end.spend_micro_usd))
        .bind::<Nullable<Text>, _>(end.report_sha256.as_ref().map(|d| d.as_str().to_owned()))
        .bind::<Nullable<Text>, _>(
            end.gateway_record_sha256
                .as_ref()
                .map(|d| d.as_str().to_owned()),
        )
        .bind::<Bool, _>(end.agent_ran)
        .bind::<Integer, _>(count(end.issues_opened))
        .bind::<Integer, _>(count(end.comments_posted))
        .bind::<Array<Text>, _>(deferred)
        .execute(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.finish_run", &error))
        .and_then(|rows| {
            if rows == 1 {
                Ok(())
            } else {
                Err(StoreError::NotFound)
            }
        });
        Self::end(connection, outcome).await
    }

    /// One run.
    ///
    /// # Errors
    /// [`StoreError`]; `NotFound` for a run this tenant does not have.
    pub async fn run(&self, id: &TroubleshootingRunId) -> Result<RunRecord, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(format!(
            "SELECT {RUN_COLUMNS} FROM troubleshooting_runs WHERE id = $1"
        ))
        .bind::<Text, _>(id.as_str())
        .get_result::<RunRow>(&mut connection)
        .await
        .optional()
        .map_err(|error| database("troubleshooting.run", &error))
        .and_then(|row| row.ok_or(StoreError::NotFound))
        .and_then(run_from_row);
        Self::end(connection, outcome).await
    }

    /// The runs that started at or after `since`, oldest first, at most `limit`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn runs_since(
        &self,
        since: &Timestamp,
        limit: u32,
    ) -> Result<Vec<RunRecord>, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(format!(
            "SELECT {RUN_COLUMNS} FROM troubleshooting_runs WHERE started_at >= $1 \
              ORDER BY started_at, id LIMIT $2"
        ))
        .bind::<Timestamptz, _>(instant(since))
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RunRow>(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.runs_since", &error))
        .and_then(|rows| rows.into_iter().map(run_from_row).collect());
        Self::end(connection, outcome).await
    }

    /// When the last sweep started, if one ever did.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn last_sweep_started(&self) -> Result<Option<Timestamp>, StoreError> {
        #[derive(QueryableByName)]
        struct Last {
            #[diesel(sql_type = Nullable<Timestamptz>)]
            at: Option<OffsetDateTime>,
        }
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "SELECT max(started_at) AS at FROM troubleshooting_runs WHERE trigger = 'sweep'",
        )
        .get_result::<Last>(&mut connection)
        .await
        .map(|row| row.at.map(from_column))
        .map_err(|error| database("troubleshooting.last_sweep", &error));
        Self::end(connection, outcome).await
    }

    /// The runs that never ended, such as one whose process died. The caller closes them.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn unfinished_runs(&self) -> Result<Vec<RunRecord>, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(format!(
            "SELECT {RUN_COLUMNS} FROM troubleshooting_runs WHERE state = 'running' ORDER BY started_at"
        ))
        .load::<RunRow>(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.unfinished", &error))
        .and_then(|rows| rows.into_iter().map(run_from_row).collect());
        Self::end(connection, outcome).await
    }

    /// The state of every probe that ever ran.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn probe_states(&self) -> Result<Vec<ProbeState>, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "SELECT probe_id, last_outcome, last_value, last_call_id, last_checked_at, last_tripped_at, \
                    cooldown_until FROM troubleshooting_probe_state ORDER BY probe_id",
        )
        .load::<ProbeRow>(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.probe_states", &error))
        .and_then(|rows| rows.into_iter().map(probe_from_row).collect());
        Self::end(connection, outcome).await
    }

    /// Records the result of one probe. A tripped probe gets `last_tripped_at`; the cool-down is
    /// left alone (it is set when an agent run investigates the probe).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_probe(&self, result: &ProbeResult) -> Result<(), StoreError> {
        let tripped = result.outcome == ProbeOutcome::Tripped;
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "INSERT INTO troubleshooting_probe_state AS p \
                    (tenant_id, probe_id, last_outcome, last_value, last_call_id, last_run_id, last_checked_at, last_tripped_at) \
             VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, CASE WHEN $8 THEN $7 END) \
             ON CONFLICT (tenant_id, probe_id) DO UPDATE SET \
                    last_outcome = EXCLUDED.last_outcome, last_value = EXCLUDED.last_value, \
                    last_call_id = EXCLUDED.last_call_id, last_run_id = EXCLUDED.last_run_id, \
                    last_checked_at = EXCLUDED.last_checked_at, \
                    last_tripped_at = coalesce(EXCLUDED.last_tripped_at, p.last_tripped_at)",
        )
        .bind::<Text, _>(self.tenant.to_string())
        .bind::<Text, _>(result.probe_id.as_str())
        .bind::<Text, _>(result.outcome.as_str())
        .bind::<Nullable<Text>, _>(result.value.as_deref())
        .bind::<Nullable<Text>, _>(result.call_id.as_ref().map(GatewayCallId::as_str))
        .bind::<Nullable<Text>, _>(result.run.as_ref().map(TroubleshootingRunId::as_str))
        .bind::<Timestamptz, _>(instant(&result.checked_at))
        .bind::<Bool, _>(tripped)
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| database("troubleshooting.record_probe", &error));
        Self::end(connection, outcome).await
    }

    /// Starts the cool-down of probes an agent run investigated: until `until`, a trip of any of
    /// them starts no agent run.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn start_cooldown(
        &self,
        probe_ids: &[String],
        until: &Timestamp,
    ) -> Result<(), StoreError> {
        if probe_ids.is_empty() {
            return Ok(());
        }
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "UPDATE troubleshooting_probe_state SET cooldown_until = $2 WHERE probe_id = ANY($1)",
        )
        .bind::<Array<Text>, _>(probe_ids.to_vec())
        .bind::<Timestamptz, _>(instant(until))
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| database("troubleshooting.cooldown", &error));
        Self::end(connection, outcome).await
    }

    /// The counters of a UTC day. Zero for a day with no row.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn day_counters(&self, day: &Timestamp) -> Result<DayCounters, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "SELECT agent_runs, new_issues, comments, spend_micro_usd \
               FROM troubleshooting_daily_counters WHERE day = $1::date",
        )
        .bind::<Text, _>(utc_day(day))
        .get_result::<CounterRow>(&mut connection)
        .await
        .optional()
        .map_err(|error| database("troubleshooting.day_counters", &error))
        .and_then(|row| match row {
            None => Ok(DayCounters::default()),
            Some(row) => Ok(DayCounters {
                agent_runs: small(row.agent_runs, "agent runs")?,
                new_issues: small(row.new_issues, "new issues")?,
                comments: small(row.comments, "comments")?,
                spend_micro_usd: unsigned_from_column(row.spend_micro_usd, "spend")?,
            }),
        });
        Self::end(connection, outcome).await
    }

    /// Adds to the counters of the UTC day of `at`, and returns the new counters.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn add_to_day(
        &self,
        at: &Timestamp,
        add: DayIncrement,
    ) -> Result<DayCounters, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "INSERT INTO troubleshooting_daily_counters AS c \
                    (tenant_id, day, agent_runs, new_issues, comments, spend_micro_usd) \
             VALUES ($1::uuid, $2::date, $3, $4, $5, $6) \
             ON CONFLICT (tenant_id, day) DO UPDATE SET \
                    agent_runs = c.agent_runs + EXCLUDED.agent_runs, \
                    new_issues = c.new_issues + EXCLUDED.new_issues, \
                    comments = c.comments + EXCLUDED.comments, \
                    spend_micro_usd = c.spend_micro_usd + EXCLUDED.spend_micro_usd \
             RETURNING c.agent_runs, c.new_issues, c.comments, c.spend_micro_usd",
        )
        .bind::<Text, _>(self.tenant.to_string())
        .bind::<Text, _>(utc_day(at))
        .bind::<Integer, _>(count(add.agent_runs))
        .bind::<Integer, _>(count(add.new_issues))
        .bind::<Integer, _>(count(add.comments))
        .bind::<BigInt, _>(big(add.spend_micro_usd))
        .get_result::<CounterRow>(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.add_to_day", &error))
        .and_then(|row| {
            Ok(DayCounters {
                agent_runs: small(row.agent_runs, "agent runs")?,
                new_issues: small(row.new_issues, "new issues")?,
                comments: small(row.comments, "comments")?,
                spend_micro_usd: unsigned_from_column(row.spend_micro_usd, "spend")?,
            })
        });
        Self::end(connection, outcome).await
    }

    /// The issue of a fingerprint, if the troubleshooter ever opened one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn issue_for(
        &self,
        fingerprint: &Sha256Digest,
    ) -> Result<Option<IssueEntry>, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "SELECT fingerprint, category, component, title, repository, issue_number, opened_at, last_comment_day::text AS last_comment_day, \
                    comments_on_last_day FROM troubleshooting_issues WHERE fingerprint = $1",
        )
        .bind::<Text, _>(fingerprint.as_str())
        .get_result::<IssueRow>(&mut connection)
        .await
        .optional()
        .map_err(|error| database("troubleshooting.issue_for", &error))
        .and_then(|row| row.map(issue_from_row).transpose());
        Self::end(connection, outcome).await
    }

    /// Every issue the troubleshooter opened, newest first, at most `limit`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn issues(&self, limit: u32) -> Result<Vec<IssueEntry>, StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "SELECT fingerprint, category, component, title, repository, issue_number, opened_at, last_comment_day::text AS last_comment_day, \
                    comments_on_last_day FROM troubleshooting_issues ORDER BY opened_at DESC, fingerprint LIMIT $1",
        )
        .bind::<BigInt, _>(i64::from(limit))
        .load::<IssueRow>(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.issues", &error))
        .and_then(|rows| rows.into_iter().map(issue_from_row).collect());
        Self::end(connection, outcome).await
    }

    /// Records the issue of a fingerprint: a new one, or a new issue that replaces one a person
    /// closed. The comment count starts again.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_issue(&self, issue: &NewIssue<'_>) -> Result<(), StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "INSERT INTO troubleshooting_issues \
                    (tenant_id, fingerprint, category, component, title, repository, issue_number, opened_at) \
             VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET category = EXCLUDED.category, \
                    component = EXCLUDED.component, title = EXCLUDED.title, repository = EXCLUDED.repository, \
                    issue_number = EXCLUDED.issue_number, opened_at = EXCLUDED.opened_at, \
                    last_comment_day = NULL, comments_on_last_day = 0",
        )
        .bind::<Text, _>(self.tenant.to_string())
        .bind::<Text, _>(issue.fingerprint.as_str())
        .bind::<Text, _>(issue.category)
        .bind::<Text, _>(issue.component)
        .bind::<Text, _>(issue.title)
        .bind::<Text, _>(issue.repository)
        .bind::<BigInt, _>(big(issue.issue_number))
        .bind::<Timestamptz, _>(instant(issue.opened_at))
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| database("troubleshooting.record_issue", &error));
        Self::end(connection, outcome).await
    }

    /// Counts a "seen again" comment on the issue of a fingerprint, on the UTC day of `at`.
    ///
    /// # Errors
    /// [`StoreError`]; `NotFound` when the fingerprint has no issue.
    pub async fn record_comment(
        &self,
        fingerprint: &Sha256Digest,
        at: &Timestamp,
    ) -> Result<(), StoreError> {
        let mut connection = self.begin().await?;
        let outcome = sql_query(
            "UPDATE troubleshooting_issues SET \
                    comments_on_last_day = CASE WHEN last_comment_day = $2::date THEN comments_on_last_day + 1 ELSE 1 END, \
                    last_comment_day = $2::date \
              WHERE fingerprint = $1",
        )
        .bind::<Text, _>(fingerprint.as_str())
        .bind::<Text, _>(utc_day(at))
        .execute(&mut connection)
        .await
        .map_err(|error| database("troubleshooting.record_comment", &error))
        .and_then(|rows| {
            if rows == 1 {
                Ok(())
            } else {
                Err(StoreError::NotFound)
            }
        });
        Self::end(connection, outcome).await
    }
}

/// The advisory lock of the one active troubleshooter, on a connection of its own. Dropping it
/// closes the connection, which ends the lock.
pub struct TroubleshooterLock {
    connection: AsyncPgConnection,
}

impl std::fmt::Debug for TroubleshooterLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TroubleshooterLock").finish_non_exhaustive()
    }
}

impl TroubleshooterLock {
    /// Opens a connection as the login of `url` and asks for the lock without waiting. `None`
    /// when another session holds it: another troubleshooter is active.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] when the database cannot be reached.
    pub async fn try_acquire(url: &DatabaseUrl) -> Result<Option<Self>, StoreError> {
        let mut connection = AsyncPgConnection::establish(url.expose())
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let row = sql_query("SELECT pg_try_advisory_lock($1) AS held")
            .bind::<BigInt, _>(TROUBLESHOOTER_LOCK_KEY)
            .get_result::<Held>(&mut connection)
            .await
            .map_err(|error| database("troubleshooting.lock", &error))?;
        Ok(row.held.then_some(Self { connection }))
    }

    /// Whether this session still holds the lock. `false` when the connection was lost, which
    /// ended the lock: the holder must stop.
    pub async fn still_held(&mut self) -> bool {
        sql_query(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE locktype = 'advisory' \
                AND pid = pg_backend_pid() AND granted \
                AND ((classid::bigint << 32) | objid::bigint) = $1) AS held",
        )
        .bind::<BigInt, _>(TROUBLESHOOTER_LOCK_KEY)
        .get_result::<Held>(&mut self.connection)
        .await
        .is_ok_and(|row| row.held)
    }

    /// Gives the lock up and closes the connection.
    pub async fn release(mut self) {
        let _ = sql_query("SELECT pg_advisory_unlock($1) AS held")
            .bind::<BigInt, _>(TROUBLESHOOTER_LOCK_KEY)
            .get_result::<Held>(&mut self.connection)
            .await;
    }
}
