//! The contract suite for the `Store` port (ports-v1.1): the two-step claim with the lease on the
//! attempt, fencing, idempotent inserts, tenant scope, the evidence ledger chain, the outbox, the
//! audit log, the commit witness and the poisoning of a transaction whose call was dropped.
//!
//! The fake in this crate and the PostgreSQL store in `factory-storage` both run it. Every check
//! is named by at least one deliberate defect of the fake (`store::DEFECTS`) or carries a waiver
//! (`WAIVERS`), and `contract_register` fails otherwise.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, StageRunId, TenantId};
use factory_domain::ledger::{head_of, verify_chain};
use factory_domain::machines::failure::FailureClass;
use factory_domain::scope::{PlatformScope, ResolvedPrincipal, TenantScope};
use factory_domain::state::{
    AttemptEvent, AttemptStatus, Guard, JobEvent, JobStatus, StageRunEvent, StageRunStatus, Status,
    TaskNodeEvent, TaskNodeStatus,
};
use factory_domain::values::{GitSha, MediaType, NonNegativeInt, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::store::*;

use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};
use crate::fixtures::{Ids, cleared, domain_event, ledger_entry};

/// What the suite needs beyond the `Store` port itself. For the fake, each lever is a method call.
/// For a real adapter it is a SQL statement, a sleep or a fault injected into the connection.
#[async_trait]
pub trait StoreSubject: Send + Sync {
    /// The store under test. It starts empty and is used by one check only.
    fn store(&self) -> &dyn Store;

    /// Moves the database clock forward by at least `by`.
    async fn advance_database_time(&self, by: Duration);

    /// Registers a repository for the tenant, as an administrator does. The port has no insert.
    async fn seed_repository(&self, tenant: TenantId) -> RepositoryId;

    /// Registers an API token for a principal.
    async fn seed_token(&self, hash: TokenHash, audience: Audience, who: ResolvedPrincipal);

    /// Switches the repository off, which also switches off its installation.
    async fn disable_repository(&self, repository: RepositoryId);

    /// The next call of any transaction never completes (a stalled connection). The check drops
    /// that call and expects the transaction to be poisoned.
    async fn stall_next_call(&self);

    /// The next commit is applied, and its answer is lost: it reports `CommitOutcomeUnknown`.
    async fn lose_next_commit_answer(&self);

    /// The audit records stored under the platform tenant.
    async fn platform_audit(&self) -> Vec<AuditRecord>;

    /// The audit records stored under the tenant, read outside the port.
    async fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord>;

    /// Sets the stage run's fencing counter to `epoch`, to reach the maximum without 2^63 starts.
    /// A fake edits the row. A real adapter uses a privileged `UPDATE` in the test database.
    async fn force_lease_epoch(&self, tenant: TenantId, stage_run: StageRunId, epoch: LeaseEpoch);
}

/// A check of the store contract.
pub type StoreCheck = Check<dyn StoreSubject>;

/// Runs the whole suite. `make` builds a fresh, empty subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: StoreSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn StoreSubject>
    })
    .await
}

/// Checks that no deliberate defect can fail, each with why and what would remove the waiver.
pub const WAIVERS: &[Waiver] = &[
    Waiver {
        check: "a_new_store_reports_a_schema_version",
        reason: "The fake reports a constant. The value it reports is not a rule it can break.",
        trigger: "s1-storage-postgres runs this check against the migrated database, where the number is read from it.",
    },
    Waiver {
        check: "a_lease_has_no_owner_on_the_stage_run",
        reason: "A type fact: StageRun has no lease field, so there is no value to get wrong.",
        trigger: "None: the check is the compiler. It stays to name the rule.",
    },
];

/// Every check of the store contract.
#[must_use]
pub fn checks() -> Vec<StoreCheck> {
    check_list![dyn StoreSubject;
        a_new_store_reports_a_schema_version,
        a_stale_version_conflicts_and_changes_nothing,
        writes_are_invisible_until_commit_and_vanish_on_drop,
        status_ledger_and_outbox_commit_together_or_not_at_all,
        two_open_transactions_cannot_both_extend_the_chain,
        a_row_of_another_tenant_looks_like_a_missing_row,
        an_event_naming_the_wrong_tenant_is_refused,
        a_tenant_cannot_read_another_tenants_row_through_any_new_method,
        a_system_transaction_finds_work_in_every_tenant,
        a_candidate_is_found_only_for_an_active_job,
        a_candidate_is_found_only_after_not_before,
        candidates_go_oldest_first_and_honour_the_limit,
        two_workers_find_one_candidate_and_one_start_wins,
        a_rolled_back_start_leaves_the_stage_run_startable,
        start_attempt_raises_the_epoch_by_one_and_creates_the_attempt_together,
        start_attempt_refuses_a_job_that_is_not_active,
        start_attempt_refuses_a_second_live_attempt,
        start_attempt_refuses_past_the_attempt_limit,
        start_attempt_fails_at_the_largest_epoch,
        a_retry_is_findable_after_its_back_off_and_not_before,
        a_lease_has_no_owner_on_the_stage_run,
        a_heartbeat_cannot_revive_a_lapsed_lease,
        a_fence_from_another_worker_name_is_refused,
        a_zombie_worker_is_fenced_after_another_worker_takes_over,
        a_zombie_cannot_change_its_attempt,
        due_attempts_cover_lease_deadline_and_teardown,
        an_insert_is_idempotent_by_id_and_content,
        the_same_id_with_other_content_is_refused,
        a_job_is_found_by_its_origin,
        an_unknown_commit_outcome_is_resolved_by_the_witness,
        a_dropped_call_poisons_the_transaction,
        the_gate_record_is_required_where_the_table_says,
        the_attempt_end_is_required_where_the_table_says,
        a_terminal_row_is_not_edited,
        a_duplicate_task_key_is_refused,
        a_task_graph_cycle_is_refused,
        a_task_move_needs_a_current_fence,
        a_ledger_entry_that_does_not_extend_the_chain_is_refused,
        a_ledger_position_can_be_taken_only_once,
        events_read_back_in_the_order_they_were_queued,
        the_audit_limit_is_honoured,
        an_audit_event_with_no_job_is_stored_and_read,
        the_platform_audit_event_lands_under_the_platform_tenant_only,
        a_delivery_repeat_is_a_duplicate_not_an_error,
        an_original_request_revision_is_immutable,
        an_approval_counts_only_for_its_head_and_until_it_expires,
        a_lookup_miss_is_none_for_every_reason,
        database_time_follows_the_subjects_clock,
    ]
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

const TTL: Duration = Duration::from_secs(60);
const TIMEOUT: Duration = Duration::from_secs(600);

struct World<'a> {
    subject: &'a dyn StoreSubject,
    ids: Ids,
    a: TenantId,
    b: TenantId,
}

/// A job that is `ACTIVE` with one `READY` stage run.
#[derive(Clone, Copy)]
struct Ready {
    tenant: TenantId,
    job: JobId,
    run: StageRunId,
}

impl<'a> World<'a> {
    fn new(subject: &'a dyn StoreSubject) -> Self {
        let ids = Ids::new();
        let (a, b) = (ids.tenant(), ids.tenant());
        Self { subject, ids, a, b }
    }

    async fn tx(&self, tenant: TenantId) -> Result<Box<dyn Tx>, String> {
        self.subject
            .store()
            .begin(TenantScope::new(tenant))
            .await
            .ctx("begin a transaction")
    }

    async fn sys(&self) -> Result<Box<dyn SystemTx>, String> {
        self.subject
            .store()
            .begin_system(SystemScope::engine())
            .await
            .ctx("begin a system transaction")
    }

    async fn principal(&self, tenant: TenantId) -> Result<PrincipalId, String> {
        let id = self.ids.principal();
        let mut tx = self.tx(tenant).await?;
        // The counter of the sequential generator sits in the first 48 bits, so those bytes differ.
        let github = u64::from_be_bytes(id.as_uuid().as_bytes()[0..8].try_into().expect("8 bytes"));
        tx.insert_principal(NewPrincipal {
            id,
            kind: PrincipalKind::Human {
                github_user_id: github,
            },
            login: Some("octocat".to_owned()),
        })
        .await
        .ctx("insert a principal")?;
        tx.commit().await.ctx("commit the principal")?;
        Ok(id)
    }

    fn new_job(
        &self,
        repository: RepositoryId,
        requester: PrincipalId,
        origin: Option<JobOrigin>,
    ) -> NewJob {
        NewJob {
            id: self.ids.job(),
            correlation_id: self.ids.correlation(),
            repository,
            requester,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L1,
            pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).expect("a scope"),
            origin,
        }
    }

    /// A job in `RECEIVED`.
    async fn job(&self, tenant: TenantId) -> Result<JobId, String> {
        let repository = self.subject.seed_repository(tenant).await;
        let requester = self.principal(tenant).await?;
        let new = self.new_job(repository, requester, None);
        let id = new.id;
        let mut tx = self.tx(tenant).await?;
        tx.insert_job(new).await.ctx("insert a job")?;
        tx.commit().await.ctx("commit the job")?;
        Ok(id)
    }

    /// A job in `ACTIVE`.
    async fn active_job(&self, tenant: TenantId) -> Result<JobId, String> {
        let job = self.job(tenant).await?;
        self.activate(tenant, job).await?;
        Ok(job)
    }

    async fn activate(&self, tenant: TenantId, job: JobId) -> Result<(), String> {
        let mut tx = self.tx(tenant).await?;
        let row = tx.get_job(job).await.ctx("read the job")?;
        let plan = plan(JobStatus::Received, JobEvent::Admit, Guard::AdmissionOk)?;
        tx.transition_job(job, row.version, plan)
            .await
            .ctx("admit the job")?;
        tx.commit().await.ctx("commit the admission")
    }

    /// An `ACTIVE` job with one `READY` stage run that may use `max_attempts`.
    async fn ready(&self, tenant: TenantId, max_attempts: u8) -> Result<Ready, String> {
        let job = self.active_job(tenant).await?;
        let run = self.stage_run(tenant, job, max_attempts).await?;
        Ok(Ready { tenant, job, run })
    }

    /// A stage run moved to `READY`.
    async fn stage_run(
        &self,
        tenant: TenantId,
        job: JobId,
        max_attempts: u8,
    ) -> Result<StageRunId, String> {
        let id = self.ids.stage_run();
        let mut tx = self.tx(tenant).await?;
        let row = tx
            .insert_stage_run(NewStageRun {
                id,
                job_id: job,
                kind: StageKind::Intake,
                run_number: 1,
                max_attempts,
                rework_of: None,
            })
            .await
            .ctx("insert a stage run")?
            .row;
        let effects = StageRunEffects {
            contract_sha256: Some(Sha256Digest::of(b"contract")),
            ..StageRunEffects::default()
        };
        let plan = plan(
            StageRunStatus::Pending,
            StageRunEvent::PreconditionsMet,
            Guard::UpstreamPassed,
        )?;
        tx.transition_stage_run(id, row.version, plan, effects)
            .await
            .ctx("make the stage run ready")?;
        tx.commit().await.ctx("commit the stage run")?;
        Ok(id)
    }

    /// Starts an attempt for `run` in a fresh transaction and commits it.
    async fn start(&self, r: Ready, worker: &str) -> Result<StartedAttempt, StoreError> {
        let mut tx = self
            .tx(r.tenant)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let started = self.start_in(&mut *tx, r.run, worker).await?;
        tx.commit().await?;
        Ok(started)
    }

    async fn start_in(
        &self,
        tx: &mut dyn Tx,
        run: StageRunId,
        worker: &str,
    ) -> Result<StartedAttempt, StoreError> {
        let row = tx.get_stage_run(run).await?;
        self.start_at(tx, run, row.version, worker).await
    }

    async fn start_at(
        &self,
        tx: &mut dyn Tx,
        run: StageRunId,
        version: Version,
        worker: &str,
    ) -> Result<StartedAttempt, StoreError> {
        let transition = plan(
            StageRunStatus::Ready,
            StageRunEvent::Start,
            Guard::LeaseAcquired,
        )
        .map_err(|_| StoreError::Internal(FaultCode::Unmapped))?;
        tx.start_attempt(StartAttempt {
            attempt: self.ids.attempt(),
            stage_run: run,
            expected: version,
            worker: WorkerId::new(worker).expect("a worker name"),
            lease_ttl: TTL,
            attempt_timeout: TIMEOUT,
            transition,
        })
        .await
    }
}

/// Indexes `bytes` as an artifact of the transaction's tenant, through the port, and returns the
/// hash that names them. A row that names a hash (a stage contract, a gate report, an attempt
/// output, a task plan) needs the artifact to be indexed first.
async fn index_bytes(tx: &mut dyn Tx, bytes: &[u8]) -> Result<Sha256Digest, String> {
    let sha256 = Sha256Digest::of(bytes);
    let size = i64::try_from(bytes.len()).map_err(|_| "the artifact is too long".to_owned())?;
    tx.index_artifact(NewArtifactIndexEntry {
        sha256: sha256.clone(),
        media_type: MediaType::parse("application/octet-stream").ctx("a media type")?,
        size_bytes: NonNegativeInt::new(size).ctx("a size")?,
        origin: None,
    })
    .await
    .ctx("index an artifact")?;
    Ok(sha256)
}

fn plan<S: Status>(from: S, event: S::Event, guard: Guard) -> Result<AppliedTransition<S>, String> {
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("a valid time");
    AppliedTransition::plan(from, event, at, cleared(guard)).ctx("plan a transition")
}

fn fence(started: &StartedAttempt, worker: &str) -> Fence {
    Fence {
        attempt: started.attempt.value.id,
        epoch: started.attempt.value.epoch,
        worker: WorkerId::new(worker).expect("a worker name"),
    }
}

fn effects_for_failure() -> AttemptEnd {
    AttemptEnd {
        failure_class: Some(FailureClass::SandboxError),
        ..AttemptEnd::default()
    }
}

// ---------------------------------------------------------------------------------------------
// Basics: versions, commit, drop, witness
// ---------------------------------------------------------------------------------------------

async fn a_new_store_reports_a_schema_version(subject: &dyn StoreSubject) -> Result<(), String> {
    subject
        .store()
        .schema_version()
        .await
        .ctx("read the schema version")?;
    Ok(())
}

async fn a_stale_version_conflicts_and_changes_nothing(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let mut tx = w.tx(w.a).await?;
    let row = tx.get_job(job).await.ctx("read")?;
    ensure_eq!(
        row.version,
        Version::FIRST,
        "a new row starts at the first version"
    );
    let admit = plan(JobStatus::Received, JobEvent::Admit, Guard::AdmissionOk)?;
    let v2 = tx
        .transition_job(job, row.version, admit.clone())
        .await
        .ctx("transition")?;
    ensure!(v2 > row.version, "a transition bumps the version");
    ensure_eq!(
        tx.get_job(job).await.ctx("read")?.value.status,
        JobStatus::Active,
        "the status moved"
    );
    tx.commit().await.ctx("commit")?;

    // A valid move from the current status, made with the version that was current before the
    // last write. Only the version can refuse it: the status is the one the move starts from.
    let mut tx = w.tx(w.a).await?;
    let pause = plan(JobStatus::Active, JobEvent::Pause, Guard::ActorMayPause)?;
    let v3 = tx.transition_job(job, v2, pause).await.ctx("pause")?;
    tx.commit().await.ctx("commit")?;

    let mut tx = w.tx(w.a).await?;
    let resume = plan(JobStatus::Paused, JobEvent::Resume, Guard::ActorMayPause)?;
    ensure_err!(
        tx.transition_job(job, v2, resume.clone()).await,
        StoreError::Conflict,
        "a stale version"
    );
    ensure_eq!(
        tx.get_job(job).await.ctx("read")?.version,
        v3,
        "a refused move changes nothing"
    );
    ensure_eq!(
        tx.get_job(job).await.ctx("read")?.value.status,
        JobStatus::Paused,
        "the status stayed"
    );
    // The same move from the wrong status, with the current version: the status check refuses it.
    ensure_err!(
        tx.transition_job(
            job,
            v3,
            plan(JobStatus::Received, JobEvent::Admit, Guard::AdmissionOk)?
        )
        .await,
        StoreError::Conflict,
        "a move from another status"
    );
    // And the move with the current version works.
    tx.transition_job(job, v3, resume)
        .await
        .ctx("the current version is accepted")?;
    Ok(())
}

async fn writes_are_invisible_until_commit_and_vanish_on_drop(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let repository = subject.seed_repository(w.a).await;
    let requester = w.principal(w.a).await?;

    // Visible to its own transaction, invisible to another, until commit.
    let new = w.new_job(repository, requester, None);
    let id = new.id;
    let mut writer = w.tx(w.a).await?;
    writer.insert_job(new).await.ctx("insert")?;
    ensure!(
        writer.get_job(id).await.is_ok(),
        "a transaction reads its own writes"
    );
    let mut reader = w.tx(w.a).await?;
    ensure_err!(
        reader.get_job(id).await,
        StoreError::NotFound,
        "before commit"
    );
    writer.commit().await.ctx("commit")?;
    let mut after = w.tx(w.a).await?;
    ensure!(after.get_job(id).await.is_ok(), "after commit");

    // Dropped without commit: nothing stays.
    let dropped = w.new_job(repository, requester, None);
    let dropped_id = dropped.id;
    {
        let mut tx = w.tx(w.a).await?;
        tx.insert_job(dropped).await.ctx("insert")?;
    }
    let mut check = w.tx(w.a).await?;
    ensure_err!(
        check.get_job(dropped_id).await,
        StoreError::NotFound,
        "after a drop"
    );

    // Rolled back: nothing stays either.
    let rolled = w.new_job(repository, requester, None);
    let rolled_id = rolled.id;
    let mut tx = w.tx(w.a).await?;
    tx.insert_job(rolled).await.ctx("insert")?;
    tx.rollback().await.ctx("roll back")?;
    let mut check = w.tx(w.a).await?;
    ensure_err!(
        check.get_job(rolled_id).await,
        StoreError::NotFound,
        "after a rollback"
    );
    Ok(())
}

async fn status_ledger_and_outbox_commit_together_or_not_at_all(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let run = w.ids.stage_run();
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");

    // All three, rolled back: none remains.
    let mut tx = w.tx(w.a).await?;
    let row = tx.get_job(job).await.ctx("read")?;
    tx.transition_job(
        job,
        row.version,
        plan(JobStatus::Received, JobEvent::Admit, Guard::AdmissionOk)?,
    )
    .await
    .ctx("transition")?;
    tx.append_ledger_entry(ledger_entry(&w.ids, job, run, 1, None, &at, "First."))
        .await
        .ctx("append")?;
    tx.enqueue_event(domain_event(&w.ids, w.a, job, 2, &at))
        .await
        .ctx("enqueue")?;
    tx.enqueue_event(domain_event(&w.ids, w.a, job, 3, &at))
        .await
        .ctx("enqueue")?;
    tx.rollback().await.ctx("roll back")?;
    let mut check = w.tx(w.a).await?;
    ensure_eq!(
        check.get_job(job).await.ctx("read")?.value.status,
        JobStatus::Received,
        "status"
    );
    ensure_eq!(check.ledger_head(job).await.ctx("head")?, None, "ledger");
    ensure!(
        check
            .read_events(job, OutboxSeq::START, 10)
            .await
            .ctx("read")?
            .is_empty(),
        "outbox"
    );

    // All three, committed: all are there, and every queued event.
    let mut tx = w.tx(w.a).await?;
    let row = tx.get_job(job).await.ctx("read")?;
    tx.transition_job(
        job,
        row.version,
        plan(JobStatus::Received, JobEvent::Admit, Guard::AdmissionOk)?,
    )
    .await
    .ctx("transition")?;
    tx.append_ledger_entry(ledger_entry(&w.ids, job, run, 1, None, &at, "First."))
        .await
        .ctx("append")?;
    tx.enqueue_event(domain_event(&w.ids, w.a, job, 2, &at))
        .await
        .ctx("enqueue")?;
    tx.enqueue_event(domain_event(&w.ids, w.a, job, 3, &at))
        .await
        .ctx("enqueue")?;
    tx.commit().await.ctx("commit")?;
    let mut check = w.tx(w.a).await?;
    ensure_eq!(
        check.get_job(job).await.ctx("read")?.value.status,
        JobStatus::Active,
        "status"
    );
    ensure!(
        check.ledger_head(job).await.ctx("head")?.is_some(),
        "ledger"
    );
    ensure_eq!(
        check
            .read_events(job, OutboxSeq::START, 10)
            .await
            .ctx("read")?
            .len(),
        2,
        "both events"
    );
    Ok(())
}

/// Two writers cannot both extend one job's chain.
///
/// How the second writer loses depends on the store, and every way is allowed: a store that locks
/// the job makes the second append wait and then find its position taken (`Conflict`), or give up
/// at the lock timeout (`Unavailable`); a store that merges at commit refuses the second commit
/// with `Conflict`. What no store may do is let both entries into the chain. So the check does
/// not ask how the second writer lost, only that it did, and that the chain holds the first
/// writer's entry and no other.
async fn two_open_transactions_cannot_both_extend_the_chain(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let run = w.stage_run(w.a, job, 3).await?;
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let from_one = ledger_entry(&w.ids, job, run, 1, None, &at, "From one.");
    let from_two = ledger_entry(&w.ids, job, run, 1, None, &at, "From two.");
    let mut one = w.tx(w.a).await?;
    let mut two = w.tx(w.a).await?;
    one.append_ledger_entry(from_one.clone())
        .await
        .ctx("append in one")?;
    // The second writer appends while the first holds the job and commits meanwhile, so a store
    // that makes the second append wait lets it go on once the first has committed.
    let (appended, committed) = tokio::join!(two.append_ledger_entry(from_two), one.commit());
    committed.ctx("the first writer commits")?;
    let second_extended = match appended {
        Err(StoreError::Conflict | StoreError::ChainBroken | StoreError::Unavailable) => false,
        Err(other) => return Err(format!("the second append failed another way: {other:?}")),
        Ok(_) => match two.commit().await {
            Ok(()) => true,
            Err(StoreError::Conflict) => false,
            Err(other) => return Err(format!("the second commit failed another way: {other:?}")),
        },
    };
    ensure!(
        !second_extended,
        "both writers extended the chain: the second append and the second commit both succeeded"
    );
    let mut check = w.tx(w.a).await?;
    let entries = check.read_ledger(job, 1, 10).await.ctx("read")?;
    ensure_eq!(entries.len(), 1, "one entry: the chain did not fork");
    ensure_eq!(
        entries[0].entry_hash,
        from_one.entry_hash,
        "and it is the first writer's"
    );
    verify_chain(&entries).map_err(|e| format!("the chain should verify: {e:?}"))?;
    Ok(())
}

async fn an_unknown_commit_outcome_is_resolved_by_the_witness(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let event = domain_event(&w.ids, w.a, job, 2, &at);
    let witness = Witness::OutboxEvent(event.event_id);
    ensure!(
        !subject
            .store()
            .committed(TenantScope::new(w.a), witness)
            .await
            .ctx("ask")?,
        "nothing is committed yet"
    );
    let mut tx = w.tx(w.a).await?;
    tx.enqueue_event(event).await.ctx("enqueue")?;
    subject.lose_next_commit_answer().await;
    ensure_err!(
        tx.commit().await,
        StoreError::CommitOutcomeUnknown,
        "the answer was lost"
    );
    ensure!(
        subject
            .store()
            .committed(TenantScope::new(w.a), witness)
            .await
            .ctx("ask")?,
        "the witness says the commit was applied"
    );
    ensure!(
        !subject
            .store()
            .committed(TenantScope::new(w.b), witness)
            .await
            .ctx("ask")?,
        "another tenant cannot see the witness"
    );
    Ok(())
}

async fn a_dropped_call_poisons_the_transaction(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let mut tx = w.tx(w.a).await?;
    subject.stall_next_call().await;
    let stalled = tokio::time::timeout(Duration::from_millis(20), tx.get_job(job)).await;
    ensure!(
        stalled.is_err(),
        "the stalled call should not have completed"
    );
    ensure_err!(
        tx.get_job(job).await,
        StoreError::Unavailable,
        "a call after a dropped one"
    );
    ensure_err!(
        tx.database_time().await,
        StoreError::Unavailable,
        "every later call"
    );
    // A fresh transaction is not affected.
    let mut fresh = w.tx(w.a).await?;
    ensure!(fresh.get_job(job).await.is_ok(), "a new transaction works");
    Ok(())
}

async fn database_time_follows_the_subjects_clock(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    // A short step: a subject on a real server can move the reading of its own clock only by
    // waiting, and the property does not depend on how large the step is. A frozen reading fails
    // at any step.
    const STEP: Duration = Duration::from_secs(2);
    let w = World::new(subject);
    let mut tx = w.tx(w.a).await?;
    let before = tx.database_time().await.ctx("time")?;
    subject.advance_database_time(STEP).await;
    let after = tx.database_time().await.ctx("time")?;
    let gap = after.duration_since(&before).unwrap_or_default();
    ensure!(
        gap >= STEP,
        "the clock moved by at least {STEP:?}, moved {gap:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Tenant scope
// ---------------------------------------------------------------------------------------------

async fn a_row_of_another_tenant_looks_like_a_missing_row(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let mut other = w.tx(w.b).await?;
    ensure_err!(
        other.get_job(r.job).await,
        StoreError::NotFound,
        "a job of another tenant"
    );
    ensure_err!(
        other.get_stage_run(r.run).await,
        StoreError::NotFound,
        "a stage run of another tenant"
    );
    ensure_err!(
        other.list_stage_runs(r.job).await,
        StoreError::NotFound,
        "the stage runs of a job of another tenant"
    );
    let missing = w.ids.job();
    let same = other.get_job(missing).await.expect_err("a missing job");
    let foreign = other.get_job(r.job).await.expect_err("a foreign job");
    ensure_eq!(
        same,
        foreign,
        "a foreign row and a missing row give the same error"
    );
    // The artifact index is per tenant.
    let mut mine = w.tx(w.a).await?;
    let sha256 = index_bytes(&mut *mine, b"blob").await?;
    let row = mine.get_artifact_index(&sha256).await.ctx("read the row")?;
    ensure_eq!(row.tenant_id, w.a, "the row is the tenant's");
    ensure_eq!(
        row.artifact.size_bytes.map(NonNegativeInt::get),
        Some(4),
        "the row keeps the size the entry gave"
    );
    mine.commit().await.ctx("commit")?;
    let mut other = w.tx(w.b).await?;
    ensure_err!(
        other.get_artifact_index(&sha256).await,
        StoreError::NotFound,
        "another tenant's artifact index row"
    );
    Ok(())
}

async fn an_event_naming_the_wrong_tenant_is_refused(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let mut tx = w.tx(w.a).await?;
    ensure_err!(
        tx.enqueue_event(domain_event(&w.ids, w.b, job, 2, &at))
            .await,
        StoreError::TenantMismatch,
        "an event that names another tenant"
    );
    Ok(())
}

async fn a_tenant_cannot_read_another_tenants_row_through_any_new_method(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let started = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let mut mine = w.tx(w.a).await?;
    let request = mine
        .record_original_request(NewOriginalRequest {
            id: w.ids.uuid7(),
            job: r.job,
            revision: 1,
            source: RequestSource::Api,
            source_ref: None,
            author_github_user_id: Some(7),
            text: "Add a word count command.".to_owned(),
        })
        .await
        .ctx("record a request")?;
    ensure!(request.created, "the first request is new");
    mine.append_ledger_entry(ledger_entry(&w.ids, r.job, r.run, 1, None, &at, "Mine."))
        .await
        .ctx("append")?;
    mine.record_audit(audit_event(&w, Some(r.job), "job.admitted"))
        .await
        .ctx("audit")?;
    mine.commit().await.ctx("commit")?;

    let mut other = w.tx(w.b).await?;
    ensure_err!(
        other.get_original_request(r.job, None).await,
        StoreError::NotFound,
        "original request"
    );
    ensure_err!(
        other.list_attempts(r.run).await,
        StoreError::NotFound,
        "attempts"
    );
    ensure_err!(
        other.get_attempt(started.attempt.value.id).await,
        StoreError::NotFound,
        "an attempt"
    );
    ensure_err!(
        other.list_task_nodes(r.run).await,
        StoreError::NotFound,
        "task nodes"
    );
    ensure_err!(
        other.task_dependencies(r.run).await,
        StoreError::NotFound,
        "task dependencies"
    );
    ensure_err!(
        other.list_stage_run_artifacts(r.run).await,
        StoreError::NotFound,
        "stage run artifacts"
    );
    ensure_err!(
        other.list_approvals(r.job).await,
        StoreError::NotFound,
        "approvals"
    );
    ensure_err!(
        other.read_ledger(r.job, 1, 10).await,
        StoreError::NotFound,
        "the ledger"
    );
    ensure_err!(
        other.read_audit(AuditFilter::Job(r.job), 0, 10).await,
        StoreError::NotFound,
        "the job's audit"
    );
    ensure!(
        other
            .read_audit(AuditFilter::Tenant, 0, 10)
            .await
            .ctx("read the tenant's audit")?
            .is_empty(),
        "another tenant's audit log shows none of the first tenant's records"
    );
    ensure!(
        other
            .find_principal_by_github_user(1)
            .await
            .ctx("find")?
            .is_none(),
        "a principal of another tenant is not found"
    );
    let page = other
        .list_jobs(JobFilter::default(), None, 10)
        .await
        .ctx("list jobs")?;
    ensure!(
        page.rows.is_empty(),
        "the job listing of another tenant is empty"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------------------------

async fn a_system_transaction_finds_work_in_every_tenant(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let a = w.ready(w.a, 3).await?;
    let b = w.ready(w.b, 3).await?;
    let mut sys = w.sys().await?;
    let found = sys.find_claim_candidates(10).await.ctx("find")?;
    let tenants: Vec<TenantId> = found.iter().map(|c| c.tenant).collect();
    ensure!(
        tenants.contains(&a.tenant) && tenants.contains(&b.tenant),
        "both tenants' stage runs are found, found {found:?}"
    );
    sys.finish().await.ctx("finish")
}

async fn a_candidate_is_found_only_for_an_active_job(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    // A READY stage run of a job that is not ACTIVE (still RECEIVED).
    let job = w.job(w.a).await?;
    let run = w.stage_run(w.a, job, 3).await?;
    let mut sys = w.sys().await?;
    let found = sys.find_claim_candidates(10).await.ctx("find")?;
    ensure!(
        found.iter().all(|c| c.stage_run != run),
        "a stage run of an inactive job is not a candidate"
    );
    sys.finish().await.ctx("finish")?;

    w.activate(w.a, job).await?;
    let mut sys = w.sys().await?;
    let found = sys.find_claim_candidates(10).await.ctx("find")?;
    ensure!(
        found.iter().any(|c| c.stage_run == run),
        "it is a candidate once the job is active"
    );
    sys.finish().await.ctx("finish")
}

async fn a_candidate_is_found_only_after_not_before(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let mut tx = w.tx(w.a).await?;
    let row = tx.get_stage_run(r.run).await.ctx("read")?;
    tx.postpone_stage_run(r.run, row.version, Duration::from_secs(120))
        .await
        .ctx("postpone")?;
    tx.commit().await.ctx("commit")?;
    let mut sys = w.sys().await?;
    ensure!(
        sys.find_claim_candidates(10).await.ctx("find")?.is_empty(),
        "a postponed stage run is not a candidate before not_before"
    );
    sys.finish().await.ctx("finish")?;
    subject
        .advance_database_time(Duration::from_secs(121))
        .await;
    let mut sys = w.sys().await?;
    ensure_eq!(
        sys.find_claim_candidates(10).await.ctx("find")?.len(),
        1,
        "after not_before"
    );
    sys.finish().await.ctx("finish")
}

async fn candidates_go_oldest_first_and_honour_the_limit(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let first = w.ready(w.a, 3).await?;
    subject.advance_database_time(Duration::from_secs(5)).await;
    let second = w.ready(w.a, 3).await?;
    subject.advance_database_time(Duration::from_secs(5)).await;
    let third = w.ready(w.a, 3).await?;
    let mut sys = w.sys().await?;
    let found = sys.find_claim_candidates(2).await.ctx("find")?;
    ensure_eq!(found.len(), 2, "the limit is honoured");
    ensure_eq!(found[0].stage_run, first.run, "oldest first");
    ensure_eq!(found[1].stage_run, second.run, "then the next");
    ensure!(
        found.iter().all(|c| c.stage_run != third.run),
        "the third is cut off"
    );
    sys.finish().await.ctx("finish")
}

/// Two workers find the same stage run, and exactly one of their starts wins.
///
/// A candidate is a hint (ADR 0014), and the finder of a real store takes the row with
/// `FOR NO KEY UPDATE SKIP LOCKED`. So a second finder that runs while the first still holds the
/// row may skip it, and a store with no row locks may show it again; both are allowed here. What no
/// store may do is hide the row for good (the first finder holds no lock after `finish`), or let
/// both starts of the one candidate win. The start decides, and the loser gets `Conflict`.
async fn two_workers_find_one_candidate_and_one_start_wins(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let mut s1 = w.sys().await?;
    let mut s2 = w.sys().await?;
    let first = s1.find_claim_candidates(1).await.ctx("find")?;
    ensure!(
        first.len() == 1 && first[0].stage_run == r.run,
        "the first finder sees the one candidate, saw {first:?}"
    );
    let candidate = first[0].clone();
    let meanwhile = s2.find_claim_candidates(1).await.ctx("find meanwhile")?;
    ensure!(
        meanwhile.is_empty() || meanwhile == first,
        "a finder that runs while another holds the row skips it or sees the same candidate, saw {meanwhile:?}"
    );
    s1.finish().await.ctx("finish")?;
    let after = s2.find_claim_candidates(1).await.ctx("find after")?;
    ensure_eq!(
        after,
        first,
        "once the first finder is done the row is free for the second"
    );
    s2.finish().await.ctx("finish")?;

    let mut t1 = w.tx(w.a).await?;
    let mut t2 = w.tx(w.a).await?;
    let won = w
        .start_at(&mut *t1, r.run, candidate.version, "worker-1")
        .await
        .ctx("the first start")?;
    t1.commit().await.ctx("commit the winner")?;
    let lost = w
        .start_at(&mut *t2, r.run, candidate.version, "worker-2")
        .await;
    ensure_err!(
        lost,
        StoreError::Conflict,
        "the second start of the same candidate"
    );
    let mut check = w.tx(w.a).await?;
    let attempts = check.list_attempts(r.run).await.ctx("list")?;
    ensure_eq!(attempts.len(), 1, "exactly one attempt");
    ensure_eq!(
        attempts[0].value.id,
        won.attempt.value.id,
        "the winner's attempt"
    );
    let mut sys = w.sys().await?;
    ensure!(
        sys.find_claim_candidates(10).await.ctx("find")?.is_empty(),
        "a started stage run is no longer a candidate"
    );
    sys.finish().await.ctx("finish")
}

async fn a_rolled_back_start_leaves_the_stage_run_startable(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    {
        let mut tx = w.tx(w.a).await?;
        w.start_in(&mut *tx, r.run, "worker-1").await.ctx("start")?;
        // Dropped without commit.
    }
    let started = w
        .start(r, "worker-2")
        .await
        .map_err(|e| format!("start after a rollback: {e:?}"))?;
    ensure_eq!(
        started.attempt.value.number,
        1,
        "the rolled back start left no attempt behind"
    );
    ensure_eq!(
        started.attempt.value.epoch,
        LeaseEpoch::new(1),
        "or a raised epoch"
    );
    Ok(())
}

async fn start_attempt_raises_the_epoch_by_one_and_creates_the_attempt_together(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let started = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    ensure_eq!(
        started.stage_run.value.status,
        StageRunStatus::Running,
        "the run moved to RUNNING"
    );
    ensure_eq!(
        started.stage_run.value.lease_epoch,
        LeaseEpoch::new(1),
        "the epoch rose by one"
    );
    ensure_eq!(
        started.attempt.value.status,
        AttemptStatus::Starting,
        "the attempt starts in STARTING"
    );
    ensure_eq!(started.attempt.value.number, 1, "attempt number one");
    ensure_eq!(
        started.attempt.value.epoch,
        started.stage_run.value.lease_epoch,
        "the attempt carries the epoch"
    );
    let mut tx = w.tx(w.a).await?;
    let stored = tx
        .get_attempt(started.attempt.value.id)
        .await
        .ctx("the attempt is stored")?;
    ensure_eq!(
        stored.value.worker.as_str(),
        "worker-1",
        "the worker holds the lease"
    );
    let run = tx.get_stage_run(r.run).await.ctx("read the run")?;
    ensure_eq!(
        run.value.lease_epoch,
        LeaseEpoch::new(1),
        "the stored epoch"
    );
    Ok(())
}

async fn start_attempt_refuses_a_job_that_is_not_active(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    // Pause the job after the candidate was found.
    let mut tx = w.tx(w.a).await?;
    let row = tx.get_job(r.job).await.ctx("read")?;
    let pause = plan(JobStatus::Active, JobEvent::Pause, Guard::ActorMayPause)?;
    tx.transition_job(r.job, row.version, pause)
        .await
        .ctx("pause")?;
    tx.commit().await.ctx("commit")?;
    let result = w.start(r, "worker-1").await;
    ensure_err!(
        result,
        StoreError::NotReady(NotReady::JobNotActive),
        "a paused job"
    );
    Ok(())
}

/// A second attempt cannot start while the first one is live.
///
/// Two refusals stand between a second start and the table. A run that is `RUNNING` is not
/// `READY`, so the start conflicts. A run that reads `READY` while its attempt is live is a bug
/// the engine must not have, and the start must still refuse it with `OneLiveAttempt`. The
/// database never commits that state (a run that leaves `RUNNING` ends its attempt in the same
/// transaction), so the check builds it inside one transaction and drops the transaction: the
/// store must refuse the start there, and nothing of it may stay.
async fn start_attempt_refuses_a_second_live_attempt(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 5).await?;
    let first = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    ensure_err!(
        w.start(r, "worker-2").await,
        StoreError::Conflict,
        "a start of a run that is running"
    );
    {
        let mut tx = w.tx(w.a).await?;
        let row = tx.get_stage_run(r.run).await.ctx("read")?;
        let retry = plan(
            StageRunStatus::Running,
            StageRunEvent::AttemptFailedRetryable,
            Guard::RetryAllowed,
        )?;
        tx.transition_stage_run(r.run, row.version, retry, StageRunEffects::default())
            .await
            .ctx("move back to READY with the attempt still live")?;
        ensure_err!(
            w.start_in(&mut *tx, r.run, "worker-2").await,
            StoreError::Constraint(ConstraintRule::OneLiveAttempt),
            "a second live attempt"
        );
        // Dropped without commit: the state above never reaches the table.
    }
    let mut check = w.tx(w.a).await?;
    let attempts = check.list_attempts(r.run).await.ctx("list")?;
    ensure_eq!(attempts.len(), 1, "one attempt");
    ensure_eq!(
        attempts[0].value.id,
        first.attempt.value.id,
        "the first attempt"
    );
    ensure_eq!(
        check
            .get_stage_run(r.run)
            .await
            .ctx("read the run")?
            .value
            .status,
        StageRunStatus::Running,
        "the run is still running"
    );
    Ok(())
}

/// Ends the live attempt of `run` as failed and moves the run back to `READY` after `delay`.
async fn fail_and_retry(
    w: &World<'_>,
    r: Ready,
    started: &StartedAttempt,
    delay: Duration,
) -> Result<(), String> {
    let mut tx = w.tx(r.tenant).await?;
    let attempt = tx
        .get_attempt(started.attempt.value.id)
        .await
        .ctx("read the attempt")?;
    let fail = plan(
        AttemptStatus::Starting,
        AttemptEvent::ProvisionFailed,
        Guard::EpochCurrent,
    )?;
    tx.transition_attempt(
        attempt.value.id,
        attempt.version,
        attempt.value.epoch,
        fail,
        effects_for_failure(),
    )
    .await
    .ctx("end the attempt")?;
    let row = tx.get_stage_run(r.run).await.ctx("read the run")?;
    let retry = plan(
        StageRunStatus::Running,
        StageRunEvent::AttemptFailedRetryable,
        Guard::RetryAllowed,
    )?;
    tx.transition_stage_run(
        r.run,
        row.version,
        retry,
        StageRunEffects {
            not_before_after: Some(delay),
            ..StageRunEffects::default()
        },
    )
    .await
    .ctx("schedule the retry")?;
    tx.commit().await.ctx("commit")
}

async fn start_attempt_refuses_past_the_attempt_limit(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 1).await?;
    let first = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    fail_and_retry(&w, r, &first, Duration::ZERO).await?;
    let second = w.start(r, "worker-2").await;
    ensure_err!(
        second,
        StoreError::Constraint(ConstraintRule::AttemptLimit),
        "a second attempt for a run that may use one"
    );
    Ok(())
}

async fn start_attempt_fails_at_the_largest_epoch(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    subject
        .force_lease_epoch(r.tenant, r.run, LeaseEpoch::MAX)
        .await;
    let result = w.start(r, "worker-1").await;
    ensure_err!(
        result,
        StoreError::Constraint(ConstraintRule::LeaseEpochExhausted),
        "a start at the largest epoch"
    );
    let mut tx = w.tx(w.a).await?;
    ensure_eq!(
        tx.get_stage_run(r.run).await.ctx("read")?.value.lease_epoch,
        LeaseEpoch::MAX,
        "the epoch did not wrap"
    );
    Ok(())
}

async fn a_retry_is_findable_after_its_back_off_and_not_before(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let first = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    fail_and_retry(&w, r, &first, Duration::from_secs(30)).await?;
    let mut sys = w.sys().await?;
    ensure!(
        sys.find_claim_candidates(10).await.ctx("find")?.is_empty(),
        "not found during the back-off"
    );
    sys.finish().await.ctx("finish")?;
    ensure_err!(
        w.start(r, "worker-2").await,
        StoreError::NotReady(NotReady::BackingOff),
        "a start during the back-off"
    );
    subject.advance_database_time(Duration::from_secs(31)).await;
    let mut sys = w.sys().await?;
    ensure_eq!(
        sys.find_claim_candidates(10).await.ctx("find")?.len(),
        1,
        "found after the back-off"
    );
    sys.finish().await.ctx("finish")?;
    let second = w
        .start(r, "worker-2")
        .await
        .map_err(|e| format!("start after the back-off: {e:?}"))?;
    ensure_eq!(second.attempt.value.number, 2, "the retry is attempt two");
    ensure_eq!(
        second.attempt.value.epoch,
        LeaseEpoch::new(2),
        "at the next epoch"
    );
    Ok(())
}

async fn a_lease_has_no_owner_on_the_stage_run(subject: &dyn StoreSubject) -> Result<(), String> {
    // `StageRun` has no worker and no lease expiry field: this function only compiles if so.
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let mut tx = w.tx(w.a).await?;
    let StageRun { lease_epoch, .. } = tx.get_stage_run(r.run).await.ctx("read")?.value;
    ensure_eq!(
        lease_epoch,
        LeaseEpoch::NEVER_CLAIMED,
        "a stage run never started has no epoch"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Leases and fences
// ---------------------------------------------------------------------------------------------

async fn a_heartbeat_cannot_revive_a_lapsed_lease(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let started = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let f = fence(&started, "worker-1");
    let mut tx = w.tx(w.a).await?;
    // A heartbeat inside the lease renews it.
    subject.advance_database_time(Duration::from_secs(30)).await;
    let renewal = tx
        .heartbeat(f.clone(), TTL)
        .await
        .ctx("a heartbeat inside the lease")?;
    ensure_eq!(
        renewal.status,
        AttemptStatus::Starting,
        "the renewal reports the status"
    );
    tx.commit().await.ctx("commit")?;
    // Past the renewed lease: fenced.
    subject.advance_database_time(Duration::from_secs(61)).await;
    let mut tx = w.tx(w.a).await?;
    ensure_err!(
        tx.heartbeat(f, TTL).await,
        StoreError::LeaseFenced,
        "a heartbeat after the lease lapsed"
    );
    Ok(())
}

async fn a_fence_from_another_worker_name_is_refused(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let started = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let mut tx = w.tx(w.a).await?;
    ensure_err!(
        tx.heartbeat(fence(&started, "worker-2"), TTL).await,
        StoreError::LeaseFenced,
        "a fence with the right epoch and another worker"
    );
    tx.heartbeat(fence(&started, "worker-1"), TTL)
        .await
        .ctx("the holder's heartbeat")?;
    Ok(())
}

async fn a_zombie_worker_is_fenced_after_another_worker_takes_over(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let first = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    fail_and_retry(&w, r, &first, Duration::ZERO).await?;
    let second = w
        .start(r, "worker-2")
        .await
        .map_err(|e| format!("second start: {e:?}"))?;
    ensure!(
        second.attempt.value.epoch > first.attempt.value.epoch,
        "the epoch rose"
    );
    let mut tx = w.tx(w.a).await?;
    // The first attempt ended. The port text says `Conflict` for the heartbeat of an ended attempt
    // and `LeaseFenced` for any fenced write that is not current, so either refusal is correct;
    // success is not.
    let ended = tx.heartbeat(fence(&first, "worker-1"), TTL).await;
    ensure!(
        matches!(ended, Err(StoreError::LeaseFenced | StoreError::Conflict)),
        "the heartbeat of an ended attempt must be refused, but it returned {ended:?}"
    );
    // The same old epoch against the live attempt is plainly fenced.
    let stale = Fence {
        attempt: second.attempt.value.id,
        epoch: first.attempt.value.epoch,
        worker: WorkerId::new("worker-2").expect("a worker name"),
    };
    ensure_err!(
        tx.heartbeat(stale, TTL).await,
        StoreError::LeaseFenced,
        "the live attempt with an old epoch"
    );
    let other_worker = Fence {
        worker: WorkerId::new("worker-1").expect("a worker name"),
        ..fence(&second, "worker-2")
    };
    ensure_err!(
        tx.heartbeat(other_worker, TTL).await,
        StoreError::LeaseFenced,
        "the live attempt held by another worker name"
    );
    tx.heartbeat(fence(&second, "worker-2"), TTL)
        .await
        .ctx("the current holder")?;
    Ok(())
}

async fn a_zombie_cannot_change_its_attempt(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let first = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    // The lease lapses; the sweeper ends the attempt (A07) and the run is retried.
    subject
        .advance_database_time(Duration::from_secs(120))
        .await;
    let mut tx = w.tx(w.a).await?;
    let attempt = tx.get_attempt(first.attempt.value.id).await.ctx("read")?;
    let lost = plan(
        AttemptStatus::Starting,
        AttemptEvent::LeaseExpired,
        Guard::LeaseExpired,
    )?;
    tx.transition_attempt(
        attempt.value.id,
        attempt.version,
        attempt.value.epoch,
        lost,
        AttemptEnd::default(),
    )
    .await
    .ctx("the sweeper ends the attempt")?;
    let row = tx.get_stage_run(r.run).await.ctx("read the run")?;
    let retry = plan(
        StageRunStatus::Running,
        StageRunEvent::AttemptFailedRetryable,
        Guard::RetryAllowed,
    )?;
    tx.transition_stage_run(r.run, row.version, retry, StageRunEffects::default())
        .await
        .ctx("retry")?;
    tx.commit().await.ctx("commit")?;
    let second = w
        .start(r, "worker-2")
        .await
        .map_err(|e| format!("second start: {e:?}"))?;
    // The first worker, still alive, tries to report with its old epoch against the new attempt.
    let mut tx = w.tx(w.a).await?;
    let current = tx.get_attempt(second.attempt.value.id).await.ctx("read")?;
    let ready = plan(
        AttemptStatus::Starting,
        AttemptEvent::SandboxReady,
        Guard::SandboxProvisioned,
    )?;
    ensure_err!(
        tx.transition_attempt(
            current.value.id,
            current.version,
            first.attempt.value.epoch,
            ready.clone(),
            AttemptEnd::default()
        )
        .await,
        StoreError::LeaseFenced,
        "a transition under an old epoch"
    );
    tx.transition_attempt(
        current.value.id,
        current.version,
        current.value.epoch,
        ready,
        AttemptEnd::default(),
    )
    .await
    .ctx("the current epoch is accepted")?;
    Ok(())
}

async fn due_attempts_cover_lease_deadline_and_teardown(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    // One attempt per reason, each in its own job, none due yet.
    let lease = w.ready(w.a, 3).await?;
    let started_lease = w
        .start(lease, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let deadline = w.ready(w.a, 3).await?;
    let started_deadline = w
        .start(deadline, "worker-2")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let teardown = w.ready(w.a, 3).await?;
    let started_teardown = w
        .start(teardown, "worker-3")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    // Put the third into CANCELLING with a 30 second grace.
    let mut tx = w.tx(w.a).await?;
    let attempt = tx
        .get_attempt(started_teardown.attempt.value.id)
        .await
        .ctx("read")?;
    let cancel = plan(
        AttemptStatus::Starting,
        AttemptEvent::RequestCancel,
        Guard::CancelAllowed,
    )?;
    tx.transition_attempt(
        attempt.value.id,
        attempt.version,
        attempt.value.epoch,
        cancel,
        AttemptEnd {
            teardown_grace: Some(Duration::from_secs(30)),
            ..AttemptEnd::default()
        },
    )
    .await
    .ctx("request cancel")?;
    tx.commit().await.ctx("commit")?;
    // Keep the first two leases alive by heartbeating, so only the intended reason is due.
    let mut sys = w.sys().await?;
    for reason in [
        DueReason::LeaseExpired,
        DueReason::DeadlinePassed,
        DueReason::TeardownDeadlinePassed,
    ] {
        ensure!(
            sys.find_due_attempts(reason, 10)
                .await
                .ctx("find")?
                .is_empty(),
            "nothing is due at the start ({reason:?})"
        );
    }
    sys.finish().await.ctx("finish")?;

    // After 100 seconds: leases (60 s) have lapsed and the teardown grace (30 s) too; the
    // 600 second deadline has not.
    subject
        .advance_database_time(Duration::from_secs(100))
        .await;
    let mut sys = w.sys().await?;
    let leases = sys
        .find_due_attempts(DueReason::LeaseExpired, 10)
        .await
        .ctx("find")?;
    let ids: Vec<_> = leases.iter().map(|d| d.attempt).collect();
    ensure!(
        ids.contains(&started_lease.attempt.value.id)
            && ids.contains(&started_deadline.attempt.value.id),
        "both live attempts have a lapsed lease, found {ids:?}"
    );
    let teardowns = sys
        .find_due_attempts(DueReason::TeardownDeadlinePassed, 10)
        .await
        .ctx("find")?;
    ensure_eq!(
        teardowns.len(),
        1,
        "one attempt is past its teardown deadline"
    );
    ensure_eq!(
        teardowns[0].attempt,
        started_teardown.attempt.value.id,
        "the cancelling attempt"
    );
    ensure!(
        sys.find_due_attempts(DueReason::DeadlinePassed, 10)
            .await
            .ctx("find")?
            .is_empty(),
        "no deadline has passed yet"
    );
    sys.finish().await.ctx("finish")?;

    subject
        .advance_database_time(Duration::from_secs(600))
        .await;
    let mut sys = w.sys().await?;
    let past = sys
        .find_due_attempts(DueReason::DeadlinePassed, 10)
        .await
        .ctx("find")?;
    ensure!(
        past.iter()
            .any(|d| d.attempt == started_lease.attempt.value.id)
            && past
                .iter()
                .any(|d| d.attempt == started_deadline.attempt.value.id),
        "both live attempts are past their deadline, found {past:?}"
    );
    ensure!(
        past.iter().all(|d| d.reason == DueReason::DeadlinePassed),
        "each answer carries its reason"
    );
    let limited = sys
        .find_due_attempts(DueReason::DeadlinePassed, 1)
        .await
        .ctx("find")?;
    ensure_eq!(limited.len(), 1, "the limit is honoured");
    sys.finish().await.ctx("finish")
}

// ---------------------------------------------------------------------------------------------
// Idempotent inserts, origins, requests, deliveries
// ---------------------------------------------------------------------------------------------

async fn an_insert_is_idempotent_by_id_and_content(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let repository = subject.seed_repository(w.a).await;
    let requester = w.principal(w.a).await?;
    let new = w.new_job(repository, requester, None);
    let mut tx = w.tx(w.a).await?;
    let first = tx.insert_job(new.clone()).await.ctx("insert")?;
    ensure!(first.created, "the first insert creates");
    tx.commit().await.ctx("commit")?;

    let mut tx = w.tx(w.a).await?;
    let again = tx.insert_job(new.clone()).await.ctx("a replay")?;
    ensure!(!again.created, "a replay creates nothing");
    ensure_eq!(again.row, first.row, "and returns the first row");

    // The same holds for a stage run, an event and a principal.
    let run = NewStageRun {
        id: w.ids.stage_run(),
        job_id: new.id,
        kind: StageKind::Intake,
        run_number: 1,
        max_attempts: 3,
        rework_of: None,
    };
    let created = tx.insert_stage_run(run.clone()).await.ctx("insert a run")?;
    let replayed = tx.insert_stage_run(run).await.ctx("replay a run")?;
    ensure!(
        created.created && !replayed.created,
        "a stage run insert is idempotent too"
    );
    ensure_eq!(
        tx.list_stage_runs(new.id).await.ctx("list")?.len(),
        1,
        "one stage run"
    );
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let event = domain_event(&w.ids, w.a, new.id, 2, &at);
    tx.enqueue_event(event.clone()).await.ctx("enqueue")?;
    tx.enqueue_event(event).await.ctx("a replayed event")?;
    ensure_eq!(
        tx.read_events(new.id, OutboxSeq::START, 10)
            .await
            .ctx("read")?
            .len(),
        1,
        "one event"
    );
    let principal = NewPrincipal {
        id: w.ids.principal(),
        kind: PrincipalKind::Service,
        login: None,
    };
    let created = tx
        .insert_principal(principal.clone())
        .await
        .ctx("principal")?;
    let replayed = tx
        .insert_principal(principal)
        .await
        .ctx("replay a principal")?;
    ensure!(
        created.created && !replayed.created,
        "a principal insert is idempotent too"
    );
    Ok(())
}

async fn the_same_id_with_other_content_is_refused(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let repository = subject.seed_repository(w.a).await;
    let requester = w.principal(w.a).await?;
    let new = w.new_job(repository, requester, None);
    let mut tx = w.tx(w.a).await?;
    tx.insert_job(new.clone()).await.ctx("insert")?;
    let other = NewJob {
        autonomy_level: AutonomyLevel::L0,
        ..new.clone()
    };
    ensure_err!(
        tx.insert_job(other).await,
        StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent),
        "the same id with other content"
    );
    ensure_eq!(
        tx.get_job(new.id).await.ctx("read")?.value.autonomy_level,
        AutonomyLevel::L1,
        "the first row is unchanged"
    );
    let job = new.id;
    let run = NewStageRun {
        id: w.ids.stage_run(),
        job_id: job,
        kind: StageKind::Intake,
        run_number: 1,
        max_attempts: 3,
        rework_of: None,
    };
    tx.insert_stage_run(run.clone()).await.ctx("run")?;
    ensure_err!(
        tx.insert_stage_run(NewStageRun {
            max_attempts: 9,
            ..run
        })
        .await,
        StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent),
        "a stage run id reused with other content"
    );
    Ok(())
}

async fn a_job_is_found_by_its_origin(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let repository = subject.seed_repository(w.a).await;
    let requester = w.principal(w.a).await?;
    let key = JobOrigin::Request(IdempotencyKey::new("create-1").expect("a key"));
    let first = w.new_job(repository, requester, Some(key.clone()));
    let second = w.new_job(repository, requester, Some(key));
    ensure!(first.id != second.id, "two different ids");
    let mut tx = w.tx(w.a).await?;
    let one = tx.insert_job(first.clone()).await.ctx("insert")?;
    let two = tx
        .insert_job(second)
        .await
        .ctx("insert with the same origin")?;
    ensure!(
        one.created && !two.created,
        "the second insert finds the first job"
    );
    ensure_eq!(two.row.value.id, first.id, "it returns the first job");
    tx.commit().await.ctx("commit")?;
    // Another tenant with the same key has its own job.
    let repository_b = subject.seed_repository(w.b).await;
    let requester_b = w.principal(w.b).await?;
    let mut tx = w.tx(w.b).await?;
    let key = JobOrigin::Request(IdempotencyKey::new("create-1").expect("a key"));
    let theirs = tx
        .insert_job(w.new_job(repository_b, requester_b, Some(key)))
        .await
        .ctx("insert")?;
    ensure!(theirs.created, "an origin is unique per tenant");
    Ok(())
}

async fn an_original_request_revision_is_immutable(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let first = NewOriginalRequest {
        id: w.ids.uuid7(),
        job,
        revision: 1,
        source: RequestSource::GithubIssue,
        source_ref: Some("https://github.com/acme/widgets/issues/12".to_owned()),
        author_github_user_id: Some(42),
        text: "Add a word count command.".to_owned(),
    };
    let mut tx = w.tx(w.a).await?;
    let stored = tx
        .record_original_request(first.clone())
        .await
        .ctx("record")?;
    ensure_eq!(
        stored.row.value.content_sha256,
        Sha256Digest::of(first.text.as_bytes()),
        "the hash is of the exact text"
    );
    let replay = tx
        .record_original_request(first.clone())
        .await
        .ctx("a replay")?;
    ensure!(!replay.created, "a replay creates nothing");
    ensure_err!(
        tx.record_original_request(NewOriginalRequest {
            text: "Edited.".to_owned(),
            ..first.clone()
        })
        .await,
        StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent),
        "an edit of revision one"
    );
    let second = NewOriginalRequest {
        id: w.ids.uuid7(),
        revision: 2,
        text: "Add a word count command, with a --lines flag.".to_owned(),
        ..first.clone()
    };
    tx.record_original_request(second)
        .await
        .ctx("a new revision")?;
    ensure_eq!(
        tx.get_original_request(job, Some(1))
            .await
            .ctx("read")?
            .text,
        first.text,
        "revision one is unchanged"
    );
    ensure_eq!(
        tx.get_original_request(job, None)
            .await
            .ctx("read")?
            .revision,
        2,
        "the latest revision"
    );
    Ok(())
}

fn delivery(w: &World<'_>, id: &str, body: &str, semantic: Option<&str>) -> NewWebhookDelivery {
    NewWebhookDelivery {
        id: factory_domain::ids::WebhookDeliveryId::from_uuid(w.ids.job().as_uuid()),
        delivery_id: id.to_owned(),
        event_name: Slug::parse("issues").expect("slug"),
        action: Some(Slug::parse("labeled").expect("slug")),
        installation: InstallationId(1),
        repository: Some(GithubRepositoryId(2)),
        sender_github_user_id: Some(3),
        body_sha256: Sha256Digest::of(body.as_bytes()),
        semantic_key: semantic.map(|s| Sha256Digest::of(s.as_bytes())),
    }
}

async fn a_delivery_repeat_is_a_duplicate_not_an_error(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let mut tx = w.tx(w.a).await?;
    let first = tx
        .record_delivery(delivery(
            &w,
            "delivery-0001",
            "body one",
            Some("semantic one"),
        ))
        .await
        .ctx("record")?;
    ensure!(
        matches!(first, DeliveryOutcome::Recorded(_)),
        "the first delivery is recorded"
    );
    ensure_eq!(
        tx.record_delivery(delivery(&w, "delivery-0001", "body two", None))
            .await
            .ctx("same id")?,
        DeliveryOutcome::Duplicate(DuplicateOf::DeliveryId),
        "the same delivery id"
    );
    ensure_eq!(
        tx.record_delivery(delivery(&w, "delivery-0002", "body one", None))
            .await
            .ctx("same body")?,
        DeliveryOutcome::Duplicate(DuplicateOf::Body),
        "the same body"
    );
    ensure_eq!(
        tx.record_delivery(delivery(
            &w,
            "delivery-0003",
            "body three",
            Some("semantic one")
        ))
        .await
        .ctx("same key")?,
        DeliveryOutcome::Duplicate(DuplicateOf::Semantic),
        "the same semantic key"
    );
    ensure!(
        matches!(
            tx.record_delivery(delivery(
                &w,
                "delivery-0004",
                "body four",
                Some("semantic two")
            ))
            .await
            .ctx("new")?,
            DeliveryOutcome::Recorded(_)
        ),
        "a different delivery is recorded"
    );
    ensure_err!(
        tx.record_delivery(delivery(&w, "short", "body five", None))
            .await,
        StoreError::Constraint(ConstraintRule::TextBounds),
        "a delivery id under eight bytes"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Rules that ride on transitions
// ---------------------------------------------------------------------------------------------

async fn the_gate_record_is_required_where_the_table_says(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    w.start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    // RUNNING -> GATING needs no gate record; GATING -> PASSED needs one.
    let mut tx = w.tx(w.a).await?;
    let row = tx.get_stage_run(r.run).await.ctx("read")?;
    let gating = plan(
        StageRunStatus::Running,
        StageRunEvent::AttemptSucceeded,
        Guard::OutputSchemaValid,
    )?;
    let v = tx
        .transition_stage_run(r.run, row.version, gating, StageRunEffects::default())
        .await
        .ctx("to gating")?;
    let pass = plan(
        StageRunStatus::Gating,
        StageRunEvent::GatePassed,
        Guard::GatePassEvidenced,
    )?;
    ensure_err!(
        tx.transition_stage_run(r.run, v, pass.clone(), StageRunEffects::default())
            .await,
        StoreError::Constraint(ConstraintRule::GateRecordRule),
        "PASSED with no gate record"
    );
    let wrong = StageRunEffects {
        gate: Some(GateRecord {
            outcome: factory_domain::vocabulary::GateOutcome::Failed,
            report_sha256: Some(Sha256Digest::of(b"r")),
            failing_set_sha256: Some(Sha256Digest::of(b"f")),
        }),
        ..StageRunEffects::default()
    };
    ensure_err!(
        tx.transition_stage_run(r.run, v, pass.clone(), wrong).await,
        StoreError::Constraint(ConstraintRule::GateRecordRule),
        "PASSED with a FAILED record"
    );
    let right = StageRunEffects {
        gate: Some(GateRecord {
            outcome: factory_domain::vocabulary::GateOutcome::Passed,
            report_sha256: Some(Sha256Digest::of(b"r")),
            failing_set_sha256: None,
        }),
        ..StageRunEffects::default()
    };
    tx.transition_stage_run(r.run, v, pass, right)
        .await
        .ctx("PASSED with the record")?;
    let stored = tx.get_stage_run(r.run).await.ctx("read")?;
    ensure!(
        stored.value.gate.is_some() && stored.value.finished_at.is_some(),
        "the record and the end are stored"
    );
    Ok(())
}

async fn the_attempt_end_is_required_where_the_table_says(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let started = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let mut tx = w.tx(w.a).await?;
    let attempt = tx.get_attempt(started.attempt.value.id).await.ctx("read")?;
    let fail = plan(
        AttemptStatus::Starting,
        AttemptEvent::ProvisionFailed,
        Guard::EpochCurrent,
    )?;
    ensure_err!(
        tx.transition_attempt(
            attempt.value.id,
            attempt.version,
            attempt.value.epoch,
            fail.clone(),
            AttemptEnd::default()
        )
        .await,
        StoreError::Constraint(ConstraintRule::AttemptEndRule),
        "a failed attempt with no failure class"
    );
    let extra = AttemptEnd {
        output: Some(Sha256Digest::of(b"o")),
        ..effects_for_failure()
    };
    ensure_err!(
        tx.transition_attempt(
            attempt.value.id,
            attempt.version,
            attempt.value.epoch,
            fail.clone(),
            extra
        )
        .await,
        StoreError::Constraint(ConstraintRule::AttemptEndRule),
        "an output on a failure"
    );
    tx.transition_attempt(
        attempt.value.id,
        attempt.version,
        attempt.value.epoch,
        fail,
        effects_for_failure(),
    )
    .await
    .ctx("the failure with its class")?;
    let stored = tx.get_attempt(attempt.value.id).await.ctx("read")?;
    ensure_eq!(
        stored.value.failure_class,
        Some(FailureClass::SandboxError),
        "the class is stored"
    );
    ensure!(stored.value.ended_at.is_some(), "the end time is stored");
    Ok(())
}

async fn a_terminal_row_is_not_edited(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.active_job(w.a).await?;
    let run = w.stage_run(w.a, job, 3).await?;
    let mut tx = w.tx(w.a).await?;
    // A cancelled stage run cannot be postponed.
    let row = tx.get_stage_run(run).await.ctx("read")?;
    let cancel = plan(
        StageRunStatus::Ready,
        StageRunEvent::Cancel,
        Guard::NoActiveAttempt,
    )?;
    let v = tx
        .transition_stage_run(run, row.version, cancel, StageRunEffects::default())
        .await
        .ctx("cancel")?;
    ensure_err!(
        tx.postpone_stage_run(run, v, Duration::from_secs(5)).await,
        StoreError::Constraint(ConstraintRule::TerminalRowImmutable),
        "postponing a cancelled stage run"
    );
    // A failed job takes no new facts.
    let job_row = tx.get_job(job).await.ctx("read")?;
    let fail = plan(JobStatus::Active, JobEvent::FailJob, Guard::Unrecoverable)?;
    let jv = tx
        .transition_job(job, job_row.version, fail)
        .await
        .ctx("fail the job")?;
    ensure_err!(
        tx.update_job_facts(
            job,
            jv,
            JobFacts {
                policy_hash: Some(Sha256Digest::of(b"p")),
                ..JobFacts::default()
            }
        )
        .await,
        StoreError::Constraint(ConstraintRule::TerminalRowImmutable),
        "new facts on a failed job"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Task graph
// ---------------------------------------------------------------------------------------------

fn node(w: &World<'_>, key: &str, depends_on: &[&str]) -> NewTaskNode {
    NewTaskNode {
        id: w.ids.task_node(),
        key: Slug::parse(key).expect("slug"),
        depends_on: depends_on
            .iter()
            .map(|k| Slug::parse(k).expect("slug"))
            .collect(),
    }
}

async fn a_duplicate_task_key_is_refused(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let mut tx = w.tx(w.a).await?;
    let graph = NewTaskGraph {
        stage_run: r.run,
        plan_sha256: Sha256Digest::of(b"plan"),
        nodes: vec![node(&w, "t-001", &[]), node(&w, "t-001", &[])],
    };
    ensure_err!(
        tx.insert_task_graph(graph).await,
        StoreError::Constraint(ConstraintRule::DuplicateTaskKey),
        "two nodes with one key"
    );
    ensure!(
        tx.list_task_nodes(r.run).await.ctx("list")?.is_empty(),
        "nothing was stored"
    );
    // A good plan is idempotent by plan hash; another plan for the same run is refused.
    let good = NewTaskGraph {
        stage_run: r.run,
        plan_sha256: Sha256Digest::of(b"plan"),
        nodes: vec![node(&w, "t-001", &[]), node(&w, "t-002", &["t-001"])],
    };
    let stored = tx
        .insert_task_graph(good.clone())
        .await
        .ctx("insert the graph")?;
    ensure_eq!(stored.len(), 2, "two nodes");
    let again = tx.insert_task_graph(good.clone()).await.ctx("a replay")?;
    ensure_eq!(again.len(), 2, "a replay returns the stored nodes");
    ensure_eq!(
        tx.task_dependencies(r.run).await.ctx("edges")?.len(),
        1,
        "one edge"
    );
    ensure_err!(
        tx.insert_task_graph(NewTaskGraph {
            plan_sha256: Sha256Digest::of(b"other"),
            ..good
        })
        .await,
        StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent),
        "another plan for the same stage run"
    );
    Ok(())
}

async fn a_task_graph_cycle_is_refused(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let mut tx = w.tx(w.a).await?;
    let graph = NewTaskGraph {
        stage_run: r.run,
        plan_sha256: Sha256Digest::of(b"plan"),
        nodes: vec![node(&w, "t-001", &["t-002"]), node(&w, "t-002", &["t-001"])],
    };
    ensure_err!(
        tx.insert_task_graph(graph).await,
        StoreError::Constraint(ConstraintRule::DependencyCycle),
        "a graph with a cycle"
    );
    ensure!(
        tx.list_task_nodes(r.run).await.ctx("list")?.is_empty(),
        "nothing was stored"
    );
    Ok(())
}

async fn a_task_move_needs_a_current_fence(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let started = w
        .start(r, "worker-1")
        .await
        .map_err(|e| format!("start: {e:?}"))?;
    let mut tx = w.tx(w.a).await?;
    let nodes = tx
        .insert_task_graph(NewTaskGraph {
            stage_run: r.run,
            plan_sha256: Sha256Digest::of(b"plan"),
            nodes: vec![node(&w, "t-001", &[])],
        })
        .await
        .ctx("graph")?;
    let id = nodes[0].value.id;
    let ready = plan(
        TaskNodeStatus::Pending,
        TaskNodeEvent::DependenciesSatisfied,
        Guard::TaskDepsSucceeded,
    )?;
    let v = tx
        .transition_task_node(
            id,
            nodes[0].version,
            None,
            ready,
            TaskNodeEffects::default(),
        )
        .await
        .ctx("T01 needs no fence")?;
    let start = plan(
        TaskNodeStatus::Ready,
        TaskNodeEvent::Start,
        Guard::TaskStartedByAttempt,
    )?;
    let effects = TaskNodeEffects {
        attempt: Some(started.attempt.value.id),
        commit: None,
    };
    ensure_err!(
        tx.transition_task_node(id, v, None, start.clone(), effects.clone())
            .await,
        StoreError::LeaseFenced,
        "T02 with no fence"
    );
    ensure_err!(
        tx.transition_task_node(
            id,
            v,
            Some(fence(&started, "worker-9")),
            start.clone(),
            effects.clone()
        )
        .await,
        StoreError::LeaseFenced,
        "T02 with another worker's fence"
    );
    let v = tx
        .transition_task_node(id, v, Some(fence(&started, "worker-1")), start, effects)
        .await
        .ctx("T02 with the current fence")?;
    let node = tx.get_task_node(id).await.ctx("read")?;
    ensure_eq!(node.version, v, "the version");
    ensure_eq!(
        node.value.current_attempt,
        Some(started.attempt.value.id),
        "the attempt that took the node"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Ledger, outbox, audit
// ---------------------------------------------------------------------------------------------

async fn a_ledger_entry_that_does_not_extend_the_chain_is_refused(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let run = w.ids.stage_run();
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let mut tx = w.tx(w.a).await?;
    let first = ledger_entry(&w.ids, job, run, 1, None, &at, "First.");
    let head = tx.append_ledger_entry(first.clone()).await.ctx("first")?;
    ensure_eq!(head.sequence, 1, "the head after the first entry");
    // A position skipped.
    let third = ledger_entry(&w.ids, job, run, 3, Some(&first.entry_hash), &at, "Third.");
    ensure_err!(
        tx.append_ledger_entry(third).await,
        StoreError::ChainBroken,
        "a skipped position"
    );
    // The wrong previous hash.
    let wrong = Sha256Digest::of(b"not the head");
    let bad_prev = ledger_entry(&w.ids, job, run, 2, Some(&wrong), &at, "Second.");
    ensure_err!(
        tx.append_ledger_entry(bad_prev).await,
        StoreError::ChainBroken,
        "the wrong previous hash"
    );
    // A wrong own hash.
    let mut bad_own = ledger_entry(&w.ids, job, run, 2, Some(&first.entry_hash), &at, "Second.");
    bad_own.entry_hash = Sha256Digest::of(b"forged");
    ensure_err!(
        tx.append_ledger_entry(bad_own).await,
        StoreError::ChainBroken,
        "a wrong own hash"
    );
    // A good second entry; the chain verifies and reads back in order.
    let second = ledger_entry(&w.ids, job, run, 2, Some(&first.entry_hash), &at, "Second.");
    tx.append_ledger_entry(second).await.ctx("second")?;
    let entries = tx.read_ledger(job, 1, 10).await.ctx("read")?;
    ensure_eq!(entries.len(), 2, "two entries");
    verify_chain(&entries).map_err(|e| format!("the chain should verify: {e:?}"))?;
    ensure_eq!(
        tx.ledger_head(job).await.ctx("head")?,
        head_of(&entries),
        "the head"
    );
    Ok(())
}

async fn a_ledger_position_can_be_taken_only_once(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let run = w.ids.stage_run();
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let mut tx = w.tx(w.a).await?;
    tx.append_ledger_entry(ledger_entry(&w.ids, job, run, 1, None, &at, "First."))
        .await
        .ctx("first")?;
    ensure_err!(
        tx.append_ledger_entry(ledger_entry(
            &w.ids,
            job,
            run,
            1,
            None,
            &at,
            "Another first."
        ))
        .await,
        StoreError::Conflict,
        "a position already taken"
    );
    Ok(())
}

async fn events_read_back_in_the_order_they_were_queued(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let other = w.job(w.a).await?;
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("time");
    let mut tx = w.tx(w.a).await?;
    let mut queued = Vec::new();
    // Another job's event goes first, so that the last row of the transaction is this job's.
    tx.enqueue_event(domain_event(&w.ids, w.a, other, 2, &at))
        .await
        .ctx("another job's event")?;
    for version in 2..=4 {
        let event = domain_event(&w.ids, w.a, job, version, &at);
        queued.push(event.event_id);
        tx.enqueue_event(event).await.ctx("enqueue")?;
    }
    tx.commit().await.ctx("commit")?;
    let mut tx = w.tx(w.a).await?;
    let rows = tx
        .read_events(job, OutboxSeq::START, 10)
        .await
        .ctx("read")?;
    let ids: Vec<_> = rows.iter().map(|row| row.event.event_id).collect();
    ensure_eq!(
        ids,
        queued,
        "events come back in the order they were queued, and only this job's"
    );
    ensure!(
        rows.windows(2).all(|pair| pair[0].seq < pair[1].seq),
        "positions grow"
    );
    let resumed = tx
        .read_events(job, OutboxSeq::new(rows[0].seq.get() + 1), 10)
        .await
        .ctx("resume")?;
    ensure_eq!(
        resumed.len(),
        2,
        "reading resumes after the last position seen"
    );
    ensure_eq!(
        tx.read_events(job, OutboxSeq::START, 2)
            .await
            .ctx("limit")?
            .len(),
        2,
        "the limit"
    );
    Ok(())
}

fn audit_event(w: &World<'_>, job: Option<JobId>, action: &str) -> NewAuditEvent {
    NewAuditEvent {
        id: factory_domain::ids::AuditEventId::from_uuid(w.ids.job().as_uuid()),
        actor: AuditActor::System(Slug::parse("workflow-engine").expect("slug")),
        action: AuditAction::new(action).expect("an action"),
        subject: "job".to_owned(),
        decision: AuditDecision::Record,
        reason: "a test record".to_owned(),
        policy_hash: Sha256Digest::of(b"policy"),
        job,
        stage_run: None,
        correlation_id: w.ids.correlation(),
    }
}

async fn the_audit_limit_is_honoured(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let mut tx = w.tx(w.a).await?;
    for n in 0..5 {
        tx.record_audit(audit_event(&w, Some(job), &format!("test.step{n}")))
            .await
            .ctx("record")?;
    }
    let limited = tx
        .read_audit(AuditFilter::Job(job), 0, 2)
        .await
        .ctx("read")?;
    ensure_eq!(limited.len(), 2, "the limit is honoured");
    ensure_eq!(limited[0].sequence, 1, "oldest first");
    let rest = tx
        .read_audit(AuditFilter::Job(job), 2, 10)
        .await
        .ctx("read")?;
    ensure_eq!(rest.len(), 3, "reading resumes after a sequence");
    ensure_eq!(rest[0].sequence, 3, "at the next one");
    Ok(())
}

async fn an_audit_event_with_no_job_is_stored_and_read(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let job = w.job(w.a).await?;
    let mut tx = w.tx(w.a).await?;
    let record = tx
        .record_audit(audit_event(&w, None, "issue.rejected"))
        .await
        .ctx("an event with no job")?;
    tx.record_audit(audit_event(&w, Some(job), "job.admitted"))
        .await
        .ctx("an event with a job")?;
    let again = tx
        .record_audit(record.event.clone())
        .await
        .ctx("a replay")?;
    ensure_eq!(
        again.sequence,
        record.sequence,
        "an event is idempotent by id"
    );
    let tenant = tx
        .read_audit(AuditFilter::Tenant, 0, 10)
        .await
        .ctx("read")?;
    ensure_eq!(tenant.len(), 2, "the tenant's log holds both");
    let job_only = tx
        .read_audit(AuditFilter::Job(job), 0, 10)
        .await
        .ctx("read")?;
    ensure_eq!(job_only.len(), 1, "the job's log holds its own");
    tx.commit().await.ctx("commit")?;
    ensure_eq!(
        subject.tenant_audit(w.a).await.len(),
        2,
        "both records are stored for the tenant"
    );
    Ok(())
}

async fn the_platform_audit_event_lands_under_the_platform_tenant_only(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let event = audit_event(&w, None, "webhook.rejected");
    let record = subject
        .store()
        .record_platform_audit(PlatformScope::receiver(), event.clone())
        .await
        .ctx("record")?;
    let again = subject
        .store()
        .record_platform_audit(PlatformScope::receiver(), event)
        .await
        .ctx("a replay")?;
    ensure_eq!(again.sequence, record.sequence, "idempotent by event id");
    ensure_eq!(
        subject.platform_audit().await.len(),
        1,
        "stored under the platform tenant"
    );
    ensure!(
        subject.tenant_audit(w.a).await.is_empty(),
        "no tenant has it"
    );
    let mut tx = w.tx(w.a).await?;
    ensure!(
        tx.read_audit(AuditFilter::Tenant, 0, 10)
            .await
            .ctx("read")?
            .is_empty(),
        "no tenant transaction can read it"
    );
    ensure_err!(
        subject
            .store()
            .record_platform_audit(
                PlatformScope::receiver(),
                audit_event(&w, Some(w.ids.job()), "webhook.rejected")
            )
            .await,
        StoreError::NotFound,
        "a platform event that names a job"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Approvals and lookups
// ---------------------------------------------------------------------------------------------

async fn an_approval_counts_only_for_its_head_and_until_it_expires(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let w = World::new(subject);
    let r = w.ready(w.a, 3).await?;
    let approver = w.principal(w.a).await?;
    let head = GitSha::parse(&"a".repeat(40)).expect("sha");
    let other_head = GitSha::parse(&"b".repeat(40)).expect("sha");
    let binding = ApprovalBinding {
        pr_head: head.clone(),
        tree: head.clone(),
        base: head.clone(),
        evidence_manifest: Sha256Digest::of(b"manifest"),
        spec_version: 1,
    };
    let new = NewApproval {
        id: factory_domain::ids::ApprovalId::from_uuid(w.ids.job().as_uuid()),
        job: r.job,
        stage_run: r.run,
        decision: ApprovalDecision::Approve,
        approver,
        designation: Slug::parse("approver").expect("slug"),
        allowlist_version: Sha256Digest::of(b"allowlist"),
        binding: Some(binding),
        policy_hash: Sha256Digest::of(b"policy"),
        reason: "Looks right.".to_owned(),
        channel: ApprovalChannel::Cli,
        valid_for: Duration::from_secs(3600),
    };
    let mut tx = w.tx(w.a).await?;
    let stored = tx.record_approval(new.clone()).await.ctx("record")?;
    ensure!(stored.created, "the first record is new");
    ensure!(
        !tx.record_approval(new.clone())
            .await
            .ctx("a replay")?
            .created,
        "a replay creates nothing"
    );
    ensure_eq!(
        tx.valid_approvals(r.job, &head).await.ctx("valid")?.len(),
        1,
        "valid for its head"
    );
    ensure!(
        tx.valid_approvals(r.job, &other_head)
            .await
            .ctx("valid")?
            .is_empty(),
        "not valid for another head"
    );
    tx.commit().await.ctx("commit")?;

    subject
        .advance_database_time(Duration::from_secs(3601))
        .await;
    let mut tx = w.tx(w.a).await?;
    ensure!(
        tx.valid_approvals(r.job, &head)
            .await
            .ctx("valid")?
            .is_empty(),
        "not valid after it expired"
    );
    ensure_eq!(
        tx.list_approvals(r.job).await.ctx("list")?.len(),
        1,
        "but still listed"
    );

    // Invalidation: a fresh approval stops counting when the head moves.
    let fresh = NewApproval {
        id: factory_domain::ids::ApprovalId::from_uuid(w.ids.job().as_uuid()),
        reason: "Looks right again.".to_owned(),
        ..new
    };
    let fresh = NewApproval {
        binding: fresh.binding.clone().map(|b| ApprovalBinding {
            spec_version: 2,
            ..b
        }),
        ..fresh
    };
    let approver_two = w.principal(w.a).await?;
    let mut tx = w.tx(w.a).await?;
    tx.record_approval(NewApproval {
        approver: approver_two,
        ..fresh
    })
    .await
    .ctx("record again")?;
    ensure_eq!(
        tx.valid_approvals(r.job, &head).await.ctx("valid")?.len(),
        1,
        "one valid approval"
    );
    ensure_eq!(
        tx.invalidate_approvals(r.job, ApprovalInvalidation::NewCommit)
            .await
            .ctx("invalidate")?,
        1,
        "one changed"
    );
    ensure!(
        tx.valid_approvals(r.job, &head)
            .await
            .ctx("valid")?
            .is_empty(),
        "none counts after"
    );
    ensure_eq!(
        tx.invalidate_approvals(r.job, ApprovalInvalidation::NewCommit)
            .await
            .ctx("again")?,
        0,
        "repeatable"
    );
    Ok(())
}

async fn a_lookup_miss_is_none_for_every_reason(subject: &dyn StoreSubject) -> Result<(), String> {
    let w = World::new(subject);
    let repository = subject.seed_repository(w.a).await;
    let principal = w.principal(w.a).await?;
    let audience = Audience(Slug::parse("factory-api").expect("slug"));
    let hash = TokenHash([1; 32]);
    subject
        .seed_token(
            hash.clone(),
            audience.clone(),
            ResolvedPrincipal {
                tenant: w.a,
                principal,
            },
        )
        .await;
    let store = subject.store();
    let found = store.resolve_token(&hash, &audience).await.ctx("resolve")?;
    ensure_eq!(
        found.map(|who| who.tenant),
        Some(w.a),
        "a known token resolves"
    );
    let unknown = store
        .resolve_token(&TokenHash([2; 32]), &audience)
        .await
        .ctx("unknown token")?;
    ensure!(unknown.is_none(), "an unknown token is none");
    let wrong_audience = Audience(Slug::parse("other-api").expect("slug"));
    let wrong = store
        .resolve_token(&hash, &wrong_audience)
        .await
        .ctx("wrong audience")?;
    ensure!(wrong.is_none(), "a token for another audience is none");

    let mut tx = w.tx(w.a).await?;
    let repo = tx
        .get_repository(repository)
        .await
        .ctx("read the repository")?;
    ensure_eq!(
        repo.value.tenant_id,
        w.a,
        "the repository belongs to the tenant"
    );
    drop(tx);
    let installation = repo.value.installation;
    let github = repo.value.github_repository_id;
    let known = store
        .resolve_installation(installation, github)
        .await
        .ctx("resolve")?;
    ensure_eq!(
        known.map(|r| r.repository),
        Some(repository),
        "a known pair resolves"
    );
    let unknown = store
        .resolve_installation(InstallationId(9999), github)
        .await
        .ctx("unknown")?;
    ensure!(unknown.is_none(), "an unknown installation is none");
    let mismatched = store
        .resolve_installation(installation, GithubRepositoryId(9999))
        .await
        .ctx("mismatch")?;
    ensure!(
        mismatched.is_none(),
        "a repository that does not belong to the installation is none"
    );
    subject.disable_repository(repository).await;
    let disabled = store
        .resolve_installation(installation, github)
        .await
        .ctx("disabled")?;
    ensure!(
        disabled.is_none(),
        "a disabled repository is none, the same as every other miss"
    );
    Ok(())
}
