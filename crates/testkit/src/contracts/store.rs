//! The contract suite for the `Store` port: compare and swap, tenant scope, lease fencing, the
//! evidence ledger chain, the outbox, and atomic commit.
//!
//! The fakes in this crate and the PostgreSQL store in `factory-storage` both run it.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::ledger::{head_of, verify_chain};
use factory_domain::scope::TenantScope;
use factory_domain::state::{
    AttemptEvent, AttemptStatus, JobStatus, StageRunEvent, StageRunStatus, Status, TaskNodeStatus,
};
use factory_domain::values::{HumanText, NonEmptyString, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::{duration_between, timestamp_after};
use factory_ports::store::{
    AppliedTransition, AuditActor, AuditEvent, LeaseEpoch, NewArtifactIndexEntry, NewAttempt,
    NewJob, NewPrincipal, NewStageRun, NewTaskNode, OutboxSeq, Store, StoreError, SystemScope, Tx,
    Version, WorkerId,
};

use super::{Check, Context, Report, check_list, ensure, ensure_eq, ensure_err, run_checks};
use crate::fixtures::{Ids, domain_event, ledger_entry};

/// What the suite needs beyond the `Store` port itself.
#[async_trait]
pub trait StoreSubject: Send + Sync {
    /// The store under test. It starts empty and is used by one check only.
    fn store(&self) -> &dyn Store;

    /// Moves the database clock forward by at least `by`. A fake moves its clock. A real store
    /// waits, or shifts a test clock in the database.
    async fn advance_database_time(&self, by: Duration);
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

/// Every check of the store contract.
#[must_use]
pub fn checks() -> Vec<StoreCheck> {
    check_list![dyn StoreSubject;
        a_new_store_reports_a_schema_version,
        inserted_rows_read_back_at_the_first_version,
        inserting_a_duplicate_id_is_a_constraint_error,
        a_job_needs_a_principal_of_its_own_tenant,
        a_transition_moves_the_status_and_bumps_the_version,
        a_stale_version_conflicts_and_changes_nothing,
        a_transition_from_the_wrong_status_conflicts,
        writes_are_invisible_until_commit_and_vanish_on_drop,
        an_explicit_rollback_discards_every_write,
        a_transaction_reads_its_own_writes,
        status_ledger_and_outbox_commit_together_or_not_at_all,
        a_failed_commit_leaves_nothing_behind,
        a_row_of_another_tenant_looks_like_a_missing_row,
        an_event_naming_the_wrong_tenant_is_refused,
        the_artifact_index_is_per_tenant_and_idempotent,
        a_system_transaction_sees_every_tenant,
        a_system_transaction_cannot_create_a_tenant_row,
        claiming_needs_a_system_transaction,
        a_ready_stage_run_is_claimed_by_exactly_one_worker,
        claiming_sets_the_lease_and_raises_the_epoch,
        claims_go_oldest_first_and_honour_the_limit,
        a_stage_run_that_is_not_ready_is_never_claimed,
        a_rolled_back_claim_leaves_the_stage_run_claimable,
        an_expired_lease_is_claimed_again_with_a_higher_epoch,
        an_attempt_needs_the_current_lease,
        a_heartbeat_with_the_current_epoch_renews_the_lease,
        a_heartbeat_after_the_lease_expired_is_fenced,
        a_zombie_worker_is_fenced_after_another_worker_takes_over,
        a_zombie_cannot_change_its_attempt,
        an_attempt_that_ended_cannot_be_heartbeated,
        expired_leases_lists_only_attempts_past_their_lease,
        the_first_ledger_entry_starts_the_chain,
        ledger_entries_read_back_in_order_and_verify,
        a_ledger_entry_that_skips_a_position_breaks_the_chain,
        a_ledger_entry_with_the_wrong_previous_hash_breaks_the_chain,
        a_ledger_entry_with_a_wrong_own_hash_is_refused,
        a_ledger_position_can_be_taken_only_once,
        two_open_transactions_cannot_both_extend_the_chain,
        a_rolled_back_ledger_append_leaves_no_trace,
        events_read_back_in_the_order_they_were_queued,
        reading_resumes_after_the_last_position_seen,
        events_are_kept_per_job,
        an_event_id_can_be_queued_only_once,
        audit_records_read_back_in_order_and_stay_with_their_tenant,
        database_time_follows_the_subjects_clock,
    ]
}

// ---------------------------------------------------------------------------------------------
// Helpers

const TTL: Duration = Duration::from_secs(60);

struct World<'a> {
    subject: &'a dyn StoreSubject,
    ids: Ids,
    a: TenantId,
    b: TenantId,
}

impl<'a> World<'a> {
    fn new(subject: &'a dyn StoreSubject) -> Self {
        let ids = Ids::new();
        let (a, b) = (ids.tenant(), ids.tenant());
        Self { subject, ids, a, b }
    }

    fn store(&self) -> &dyn Store {
        self.subject.store()
    }

    async fn tenant_tx(&self, tenant: TenantId) -> Result<Box<dyn Tx>, String> {
        self.store()
            .begin(TenantScope::new(tenant))
            .await
            .ctx("begin a tenant transaction")
    }

    async fn system_tx(&self) -> Result<Box<dyn Tx>, String> {
        self.store()
            .begin_system(SystemScope::engine())
            .await
            .ctx("begin a system transaction")
    }

    async fn now(&self) -> Result<Timestamp, String> {
        let mut tx = self.system_tx().await?;
        tx.database_time().await.ctx("read the database time")
    }

    async fn principal(&self, tenant: TenantId) -> Result<PrincipalId, String> {
        let now = self.now().await?;
        let id = self.ids.principal();
        let mut tx = self.tenant_tx(tenant).await?;
        tx.insert_principal(NewPrincipal {
            id,
            external_ref: NonEmptyString::parse(&format!("user-{id}")).ctx("external ref")?,
            created_at: now,
        })
        .await
        .ctx("insert a principal")?;
        tx.commit().await.ctx("commit a principal")?;
        Ok(id)
    }

    async fn job(&self, tenant: TenantId) -> Result<JobId, String> {
        let requester = self.principal(tenant).await?;
        let now = self.now().await?;
        let id = self.ids.job();
        let mut tx = self.tenant_tx(tenant).await?;
        tx.insert_job(NewJob {
            id,
            correlation_id: self.ids.correlation(),
            requester,
            created_at: now,
        })
        .await
        .ctx("insert a job")?;
        tx.commit().await.ctx("commit a job")?;
        Ok(id)
    }

    /// A stage run in `READY`, committed.
    async fn ready_stage_run(&self, tenant: TenantId, job: JobId) -> Result<StageRunId, String> {
        let now = self.now().await?;
        let id = self.ids.stage_run();
        let mut tx = self.tenant_tx(tenant).await?;
        let inserted = tx
            .insert_stage_run(NewStageRun {
                id,
                job_id: job,
                kind: StageKind::Intake,
                created_at: now,
            })
            .await
            .ctx("insert a stage run")?;
        let plan = AppliedTransition::plan(
            StageRunStatus::INITIAL,
            StageRunEvent::PreconditionsMet,
            now,
        )
        .ctx("plan preconditions_met")?;
        tx.transition_stage_run(id, inserted.version, plan)
            .await
            .ctx("move the stage run to READY")?;
        tx.commit().await.ctx("commit a stage run")?;
        Ok(id)
    }

    /// Claims `stage_run` for `worker` in a committed system transaction and returns the epoch.
    async fn claim(&self, worker: &str) -> Result<Vec<factory_ports::store::ClaimedWork>, String> {
        let mut tx = self.system_tx().await?;
        let claimed = tx
            .claim_ready(&WorkerId::new(worker).ctx("worker id")?, 10, TTL)
            .await
            .ctx("claim ready work")?;
        tx.commit().await.ctx("commit a claim")?;
        Ok(claimed)
    }

    async fn new_attempt(
        &self,
        tenant: TenantId,
        stage_run: StageRunId,
        epoch: LeaseEpoch,
    ) -> Result<factory_domain::ids::AttemptId, String> {
        let now = self.now().await?;
        let id = self.ids.attempt();
        let mut tx = self.tenant_tx(tenant).await?;
        tx.insert_attempt(NewAttempt {
            id,
            stage_run_id: stage_run,
            epoch,
            created_at: now,
        })
        .await
        .ctx("insert an attempt")?;
        tx.commit().await.ctx("commit an attempt")?;
        Ok(id)
    }
}

fn first_legal_job_event() -> Result<factory_domain::state::JobEvent, String> {
    JobStatus::INITIAL
        .legal_events()
        .into_iter()
        .next()
        .ok_or_else(|| "the job machine has no move from its initial status".to_owned())
}

// ---------------------------------------------------------------------------------------------
// Checks

async fn a_new_store_reports_a_schema_version(subject: &dyn StoreSubject) -> Result<(), String> {
    subject
        .store()
        .schema_version()
        .await
        .ctx("read the schema version")?;
    Ok(())
}

async fn inserted_rows_read_back_at_the_first_version(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let tenant = world.a;
    let job = world.job(tenant).await?;
    let stage_run = world.ready_stage_run(tenant, job).await?;
    let now = world.now().await?;
    let node = world.ids.task_node();
    let mut tx = world.tenant_tx(tenant).await?;
    tx.insert_task_node(NewTaskNode {
        id: node,
        job_id: job,
        key: Slug::parse("t-001").ctx("slug")?,
        created_at: now,
    })
    .await
    .ctx("insert a task node")?;
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(tenant).await?;
    let read_job = tx.get_job(job).await.ctx("get the job")?;
    ensure_eq!(read_job.version, Version::FIRST, "a new job's version");
    ensure_eq!(
        read_job.value.status,
        JobStatus::INITIAL,
        "a new job's status"
    );
    ensure_eq!(read_job.value.tenant_id, tenant, "the job's tenant");

    let read_run = tx.get_stage_run(stage_run).await.ctx("get the stage run")?;
    ensure_eq!(read_run.value.job_id, job, "the stage run's job");
    ensure_eq!(
        read_run.value.kind,
        StageKind::Intake,
        "the stage run's kind"
    );
    ensure_eq!(
        read_run.value.lease,
        None,
        "a stage run nobody claimed has no lease"
    );
    ensure_eq!(
        read_run.value.lease_epoch,
        LeaseEpoch::NEVER_CLAIMED,
        "a stage run nobody claimed has epoch zero"
    );

    let read_node = tx.get_task_node(node).await.ctx("get the task node")?;
    ensure_eq!(
        read_node.version,
        Version::FIRST,
        "a new task node's version"
    );
    ensure_eq!(
        read_node.value.status,
        TaskNodeStatus::INITIAL,
        "a new task node's status"
    );
    Ok(())
}

async fn inserting_a_duplicate_id_is_a_constraint_error(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let tenant = world.a;
    let job = world.job(tenant).await?;
    let requester = world.principal(tenant).await?;
    let now = world.now().await?;

    let mut tx = world.tenant_tx(tenant).await?;
    ensure_err!(
        tx.insert_job(NewJob {
            id: job,
            correlation_id: world.ids.correlation(),
            requester,
            created_at: now,
        })
        .await,
        StoreError::Constraint(_),
        "a second job with the same id"
    );
    Ok(())
}

async fn a_job_needs_a_principal_of_its_own_tenant(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let stranger = world.principal(world.b).await?;
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.insert_job(NewJob {
            id: world.ids.job(),
            correlation_id: world.ids.correlation(),
            requester: stranger,
            created_at: now,
        })
        .await,
        StoreError::Constraint(_),
        "a job whose requester belongs to another tenant"
    );
    Ok(())
}

async fn a_transition_moves_the_status_and_bumps_the_version(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let event = first_legal_job_event()?;
    let plan = AppliedTransition::plan(JobStatus::INITIAL, event, now).ctx("plan")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let version = tx
        .transition_job(job, Version::FIRST, plan)
        .await
        .ctx("transition the job")?;
    ensure_eq!(
        version,
        Version::FIRST.next().ctx("next version")?,
        "the version after one change"
    );
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.get_job(job).await.ctx("get")?;
    ensure_eq!(read.value.status, plan.to_status(), "the stored status");
    ensure_eq!(read.version, version, "the stored version");
    Ok(())
}

async fn a_stale_version_conflicts_and_changes_nothing(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let event = first_legal_job_event()?;
    let plan = AppliedTransition::plan(JobStatus::INITIAL, event, now).ctx("plan")?;
    let second = Version::FIRST.next().ctx("next version")?;

    // A version that was never current.
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.transition_job(job, second, plan).await,
        StoreError::Conflict,
        "an update that says it read version 2 of a row at version 1"
    );
    drop(tx);

    // A version that was current and has been replaced.
    let mut tx = world.tenant_tx(world.a).await?;
    tx.transition_job(job, Version::FIRST, plan)
        .await
        .ctx("the first update")?;
    tx.commit().await.ctx("commit")?;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.transition_job(job, Version::FIRST, plan).await,
        StoreError::Conflict,
        "a second update that still says it read version 1"
    );
    let read = tx.get_job(job).await.ctx("get")?;
    ensure_eq!(
        read.version,
        second,
        "a refused update must not change the version"
    );
    Ok(())
}

async fn a_transition_from_the_wrong_status_conflicts(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    // A move that is legal in the machine, but from a status the row is not in.
    let other = JobStatus::STATES
        .iter()
        .copied()
        .find(|status| *status != JobStatus::INITIAL && !status.legal_events().is_empty())
        .ok_or("the job machine has no second status with a legal move")?;
    let event = other
        .legal_events()
        .into_iter()
        .next()
        .ok_or("no legal event")?;
    let plan = AppliedTransition::plan(other, event, now).ctx("plan")?;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.transition_job(job, Version::FIRST, plan).await,
        StoreError::Conflict,
        "a move that starts from a status the row is not in, with the right version"
    );
    Ok(())
}

async fn writes_are_invisible_until_commit_and_vanish_on_drop(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let requester = world.principal(world.a).await?;
    let now = world.now().await?;
    let job = world.ids.job();

    let mut writer = world.tenant_tx(world.a).await?;
    writer
        .insert_job(NewJob {
            id: job,
            correlation_id: world.ids.correlation(),
            requester,
            created_at: now,
        })
        .await
        .ctx("insert in the writer")?;

    let mut reader = world.tenant_tx(world.a).await?;
    ensure_err!(
        reader.get_job(job).await,
        StoreError::NotFound,
        "another transaction reading an uncommitted insert"
    );
    drop(reader);

    drop(writer);
    let mut after = world.tenant_tx(world.a).await?;
    ensure_err!(
        after.get_job(job).await,
        StoreError::NotFound,
        "a transaction that was dropped without commit must leave nothing"
    );
    Ok(())
}

async fn an_explicit_rollback_discards_every_write(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let requester = world.principal(world.a).await?;
    let now = world.now().await?;
    let job = world.ids.job();
    let mut tx = world.tenant_tx(world.a).await?;
    tx.insert_job(NewJob {
        id: job,
        correlation_id: world.ids.correlation(),
        requester,
        created_at: now,
    })
    .await
    .ctx("insert")?;
    tx.rollback().await.ctx("roll back")?;
    let mut after = world.tenant_tx(world.a).await?;
    ensure_err!(
        after.get_job(job).await,
        StoreError::NotFound,
        "a job after its transaction was rolled back"
    );
    Ok(())
}

async fn a_transaction_reads_its_own_writes(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let requester = world.principal(world.a).await?;
    let now = world.now().await?;
    let job = world.ids.job();
    let mut tx = world.tenant_tx(world.a).await?;
    tx.insert_job(NewJob {
        id: job,
        correlation_id: world.ids.correlation(),
        requester,
        created_at: now,
    })
    .await
    .ctx("insert")?;
    let read = tx.get_job(job).await.ctx("read its own insert")?;
    ensure_eq!(
        read.value.id,
        job,
        "the job read inside the writing transaction"
    );
    Ok(())
}

async fn status_ledger_and_outbox_commit_together_or_not_at_all(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ids.stage_run();
    let now = world.now().await?;
    let plan =
        AppliedTransition::plan(JobStatus::INITIAL, first_legal_job_event()?, now).ctx("plan")?;

    // One transaction does all three writes and is dropped.
    let mut tx = world.tenant_tx(world.a).await?;
    tx.transition_job(job, Version::FIRST, plan)
        .await
        .ctx("transition")?;
    let entry = ledger_entry(&world.ids, job, stage_run, 1, None, &now, "A claim.");
    tx.append_ledger_entry(entry.clone()).await.ctx("append")?;
    tx.enqueue_event(domain_event(&world.ids, world.a, job, 2, &now))
        .await
        .ctx("enqueue")?;
    drop(tx);

    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.get_job(job).await.ctx("get")?;
    ensure_eq!(
        read.version,
        Version::FIRST,
        "the job after a dropped transaction"
    );
    ensure_eq!(
        tx.ledger_head(job).await.ctx("head")?,
        None,
        "the ledger after a dropped transaction"
    );
    ensure_eq!(
        tx.read_events(job, OutboxSeq::START, 10)
            .await
            .ctx("events")?
            .len(),
        0,
        "the outbox after a dropped transaction"
    );
    drop(tx);

    // The same three writes, committed.
    let mut tx = world.tenant_tx(world.a).await?;
    tx.transition_job(job, Version::FIRST, plan)
        .await
        .ctx("transition")?;
    tx.append_ledger_entry(entry).await.ctx("append")?;
    tx.enqueue_event(domain_event(&world.ids, world.a, job, 2, &now))
        .await
        .ctx("enqueue")?;
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.get_job(job).await.ctx("get")?;
    ensure_eq!(read.value.status, plan.to_status(), "the job after commit");
    ensure!(
        tx.ledger_head(job).await.ctx("head")?.is_some(),
        "the ledger entry must be visible after commit"
    );
    ensure_eq!(
        tx.read_events(job, OutboxSeq::START, 10)
            .await
            .ctx("events")?
            .len(),
        1,
        "the outbox after commit"
    );
    Ok(())
}

async fn a_failed_commit_leaves_nothing_behind(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let plan =
        AppliedTransition::plan(JobStatus::INITIAL, first_legal_job_event()?, now).ctx("plan")?;

    let mut winner = world.tenant_tx(world.a).await?;
    let mut loser = world.tenant_tx(world.a).await?;
    winner
        .transition_job(job, Version::FIRST, plan)
        .await
        .ctx("the winner's update")?;
    // The loser reads the same version, writes an outbox row too, and commits second.
    let loser_update = loser.transition_job(job, Version::FIRST, plan).await;
    let loser_event = domain_event(&world.ids, world.a, job, 2, &now);
    let loser_event_id = loser_event.event_id;
    loser
        .enqueue_event(loser_event)
        .await
        .ctx("the loser's event")?;
    winner.commit().await.ctx("the winner's commit")?;

    let commit = match loser_update {
        Err(StoreError::Conflict) => {
            // The store noticed at the write. Nothing more to prove about the commit.
            drop(loser);
            Ok(())
        }
        Err(other) => Err(format!("the loser's update failed with {other:?}")),
        Ok(_) => match loser.commit().await {
            Err(StoreError::Conflict) => Ok(()),
            Err(other) => Err(format!("the loser's commit failed with {other:?}")),
            Ok(()) => Err(
                "both transactions changed the same row from the same version and both committed"
                    .to_owned(),
            ),
        },
    };
    commit?;

    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.get_job(job).await.ctx("get")?;
    ensure_eq!(
        read.version,
        Version::FIRST.next().ctx("next")?,
        "the job must hold exactly one change"
    );
    let events = tx
        .read_events(job, OutboxSeq::START, 10)
        .await
        .ctx("events")?;
    ensure!(
        events
            .iter()
            .all(|row| row.event.event_id != loser_event_id),
        "an event queued by a transaction that did not commit must not be visible"
    );
    Ok(())
}

async fn a_row_of_another_tenant_looks_like_a_missing_row(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let principal = world.principal(world.a).await?;
    let now = world.now().await?;
    let plan =
        AppliedTransition::plan(JobStatus::INITIAL, first_legal_job_event()?, now).ctx("plan")?;
    let entry = ledger_entry(&world.ids, job, stage_run, 1, None, &now, "A claim.");

    let mut other = world.tenant_tx(world.b).await?;
    ensure_err!(
        other.get_job(job).await,
        StoreError::NotFound,
        "get_job of another tenant's job"
    );
    ensure_err!(
        other.get_stage_run(stage_run).await,
        StoreError::NotFound,
        "get_stage_run of another tenant's stage run"
    );
    ensure_err!(
        other.get_principal(principal).await,
        StoreError::NotFound,
        "get_principal of another tenant's principal"
    );
    ensure_err!(
        other.transition_job(job, Version::FIRST, plan).await,
        StoreError::NotFound,
        "transition_job of another tenant's job"
    );
    ensure_err!(
        other
            .insert_stage_run(NewStageRun {
                id: world.ids.stage_run(),
                job_id: job,
                kind: StageKind::Intake,
                created_at: now,
            })
            .await,
        StoreError::NotFound,
        "insert_stage_run under another tenant's job"
    );
    ensure_err!(
        other.append_ledger_entry(entry).await,
        StoreError::NotFound,
        "append_ledger_entry to another tenant's job"
    );
    ensure_err!(
        other.ledger_head(job).await,
        StoreError::NotFound,
        "ledger_head of another tenant's job"
    );
    ensure_err!(
        other.read_ledger(job, 1, 10).await,
        StoreError::NotFound,
        "read_ledger of another tenant's job"
    );
    ensure_err!(
        other.read_events(job, OutboxSeq::START, 10).await,
        StoreError::NotFound,
        "read_events of another tenant's job"
    );
    ensure_err!(
        other.read_audit(job, 10).await,
        StoreError::NotFound,
        "read_audit of another tenant's job"
    );

    // The owner's row is untouched.
    let mut owner = world.tenant_tx(world.a).await?;
    let read = owner.get_job(job).await.ctx("the owner's get")?;
    ensure_eq!(
        read.version,
        Version::FIRST,
        "the owner's job after the refused calls"
    );
    Ok(())
}

async fn an_event_naming_the_wrong_tenant_is_refused(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.enqueue_event(domain_event(&world.ids, world.b, job, 2, &now))
            .await,
        StoreError::TenantMismatch,
        "an event of tenant B for a job of tenant A"
    );
    Ok(())
}

async fn the_artifact_index_is_per_tenant_and_idempotent(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let now = world.now().await?;
    let artifact = factory_domain::contracts::ArtifactRef {
        sha256: Sha256Digest::of(b"shared bytes"),
        media_type: factory_domain::values::MediaType::parse("text/plain").ctx("media type")?,
        size_bytes: None,
    };
    let entry = || NewArtifactIndexEntry {
        artifact: artifact.clone(),
        stage_run_id: None,
        created_at: now,
    };

    let mut a = world.tenant_tx(world.a).await?;
    let first = a.index_artifact(entry()).await.ctx("index for A")?;
    let again = a.index_artifact(entry()).await.ctx("index for A again")?;
    ensure_eq!(again, first, "a second index call for the same hash");
    a.commit().await.ctx("commit")?;

    let mut b = world.tenant_tx(world.b).await?;
    ensure_err!(
        b.get_artifact_index(&artifact.sha256).await,
        StoreError::NotFound,
        "tenant B asking for a hash only tenant A indexed"
    );
    let own = b.index_artifact(entry()).await.ctx("index for B")?;
    ensure_eq!(own.tenant_id, world.b, "B's own row");
    drop(b);

    let mut system = world.system_tx().await?;
    ensure_err!(
        system.index_artifact(entry()).await,
        StoreError::ScopeNotAllowed,
        "a system transaction indexing an artifact"
    );
    Ok(())
}

async fn a_system_transaction_sees_every_tenant(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job_a = world.job(world.a).await?;
    let job_b = world.job(world.b).await?;
    let mut system = world.system_tx().await?;
    ensure_eq!(
        system.get_job(job_a).await.ctx("job A")?.value.tenant_id,
        world.a,
        "tenant of job A"
    );
    ensure_eq!(
        system.get_job(job_b).await.ctx("job B")?.value.tenant_id,
        world.b,
        "tenant of job B"
    );
    Ok(())
}

async fn a_system_transaction_cannot_create_a_tenant_row(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let requester = world.principal(world.a).await?;
    let now = world.now().await?;
    let mut system = world.system_tx().await?;
    ensure_err!(
        system
            .insert_job(NewJob {
                id: world.ids.job(),
                correlation_id: world.ids.correlation(),
                requester,
                created_at: now,
            })
            .await,
        StoreError::ScopeNotAllowed,
        "a system transaction creating a job"
    );
    ensure_err!(
        system
            .insert_principal(NewPrincipal {
                id: world.ids.principal(),
                external_ref: NonEmptyString::parse("someone").ctx("ref")?,
                created_at: now,
            })
            .await,
        StoreError::ScopeNotAllowed,
        "a system transaction creating a principal"
    );
    Ok(())
}

async fn claiming_needs_a_system_transaction(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    world.ready_stage_run(world.a, job).await?;
    let mut tenant = world.tenant_tx(world.a).await?;
    let worker = WorkerId::new("worker-1").ctx("worker id")?;
    ensure_err!(
        tenant.claim_ready(&worker, 10, TTL).await,
        StoreError::ScopeNotAllowed,
        "a tenant transaction claiming work"
    );
    ensure_err!(
        tenant.expired_leases(10).await,
        StoreError::ScopeNotAllowed,
        "a tenant transaction listing expired leases"
    );
    Ok(())
}

async fn a_ready_stage_run_is_claimed_by_exactly_one_worker(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    world.ready_stage_run(world.a, job).await?;
    let one = WorkerId::new("worker-1").ctx("worker id")?;
    let two = WorkerId::new("worker-2").ctx("worker id")?;

    let mut first = world.system_tx().await?;
    let mut second = world.system_tx().await?;
    let got = first.claim_ready(&one, 10, TTL).await.ctx("first claim")?;
    ensure_eq!(got.len(), 1, "the first worker's claim");
    // The first transaction has not committed. The second must skip the locked row.
    let skipped = second
        .claim_ready(&two, 10, TTL)
        .await
        .ctx("second claim")?;
    ensure_eq!(
        skipped.len(),
        0,
        "a claim while another open transaction holds the row"
    );
    first.commit().await.ctx("commit the first claim")?;
    drop(second);

    // After the commit the lease is current, so a third claim finds nothing.
    let third = world.claim("worker-2").await?;
    ensure_eq!(
        third.len(),
        0,
        "a claim on a stage run whose lease has not expired"
    );
    Ok(())
}

async fn claiming_sets_the_lease_and_raises_the_epoch(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let before = world.now().await?;
    let claimed = world.claim("worker-1").await?;
    ensure_eq!(claimed.len(), 1, "claimed stage runs");
    let work = &claimed[0];
    ensure_eq!(work.stage_run.value.id, stage_run, "the claimed stage run");
    ensure_eq!(
        work.stage_run.value.status,
        StageRunStatus::Ready,
        "a claim leaves the status READY"
    );
    ensure_eq!(
        work.lease.epoch,
        LeaseEpoch::new(1),
        "the first claim's epoch"
    );
    ensure_eq!(work.lease.worker.as_str(), "worker-1", "the lease holder");
    ensure_eq!(work.lease.ttl, TTL, "the lease ttl");
    let expires_in = duration_between(&before, &work.lease.expires_at)
        .ok_or("the lease ends before the claim happened")?;
    ensure!(
        expires_in >= TTL && expires_in <= TTL + Duration::from_secs(1),
        "the lease should end one ttl after the database time, but ends {expires_in:?} later"
    );

    let mut tx = world.tenant_tx(world.a).await?;
    let stored = tx.get_stage_run(stage_run).await.ctx("get")?;
    ensure_eq!(
        stored.value.lease_epoch,
        LeaseEpoch::new(1),
        "the stored epoch"
    );
    ensure_eq!(
        stored.value.lease.as_ref(),
        Some(&work.lease),
        "the stored lease"
    );
    Ok(())
}

async fn claims_go_oldest_first_and_honour_the_limit(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let first = world.ready_stage_run(world.a, job).await?;
    subject.advance_database_time(Duration::from_secs(1)).await;
    let second = world.ready_stage_run(world.a, job).await?;
    subject.advance_database_time(Duration::from_secs(1)).await;
    let third = world.ready_stage_run(world.a, job).await?;

    let mut tx = world.system_tx().await?;
    let worker = WorkerId::new("worker-1").ctx("worker id")?;
    let got = tx.claim_ready(&worker, 2, TTL).await.ctx("claim two")?;
    let ids: Vec<StageRunId> = got.iter().map(|work| work.stage_run.value.id).collect();
    ensure_eq!(ids, vec![first, second], "the two oldest, in order");
    tx.commit().await.ctx("commit")?;

    let rest = world.claim("worker-1").await?;
    let ids: Vec<StageRunId> = rest.iter().map(|work| work.stage_run.value.id).collect();
    ensure_eq!(ids, vec![third], "what is left");
    Ok(())
}

async fn a_stage_run_that_is_not_ready_is_never_claimed(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    tx.insert_stage_run(NewStageRun {
        id: world.ids.stage_run(),
        job_id: job,
        kind: StageKind::Intake,
        created_at: now,
    })
    .await
    .ctx("insert a PENDING stage run")?;
    tx.commit().await.ctx("commit")?;
    ensure_eq!(
        world.claim("worker-1").await?.len(),
        0,
        "a claim with only a PENDING stage run"
    );
    Ok(())
}

async fn a_rolled_back_claim_leaves_the_stage_run_claimable(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    world.ready_stage_run(world.a, job).await?;
    let worker = WorkerId::new("worker-1").ctx("worker id")?;
    let mut tx = world.system_tx().await?;
    ensure_eq!(
        tx.claim_ready(&worker, 10, TTL).await.ctx("claim")?.len(),
        1,
        "the first claim"
    );
    drop(tx);
    let again = world.claim("worker-2").await?;
    ensure_eq!(
        again.len(),
        1,
        "a claim after the first transaction was dropped"
    );
    ensure_eq!(
        again[0].lease.epoch,
        LeaseEpoch::new(1),
        "the epoch of a claim whose predecessor rolled back"
    );
    Ok(())
}

async fn an_expired_lease_is_claimed_again_with_a_higher_epoch(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    world.ready_stage_run(world.a, job).await?;
    let first = world.claim("worker-1").await?;
    ensure_eq!(first.len(), 1, "the first claim");
    subject
        .advance_database_time(TTL + Duration::from_secs(1))
        .await;
    let second = world.claim("worker-2").await?;
    ensure_eq!(second.len(), 1, "a claim after the lease expired");
    ensure_eq!(
        second[0].lease.epoch,
        LeaseEpoch::new(2),
        "the epoch of the second claim"
    );
    ensure_eq!(
        second[0].lease.worker.as_str(),
        "worker-2",
        "the new lease holder"
    );
    Ok(())
}

async fn an_attempt_needs_the_current_lease(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let claimed = world.claim("worker-1").await?;
    let epoch = claimed.first().ok_or("nothing was claimed")?.lease.epoch;
    let now = world.now().await?;

    let mut tx = world.tenant_tx(world.a).await?;
    for wrong in [LeaseEpoch::NEVER_CLAIMED, epoch.next()] {
        ensure_err!(
            tx.insert_attempt(NewAttempt {
                id: world.ids.attempt(),
                stage_run_id: stage_run,
                epoch: wrong,
                created_at: now,
            })
            .await,
            StoreError::LeaseFenced,
            "an attempt that carries an epoch the lease does not have"
        );
    }
    let id = world.ids.attempt();
    let attempt = tx
        .insert_attempt(NewAttempt {
            id,
            stage_run_id: stage_run,
            epoch,
            created_at: now,
        })
        .await
        .ctx("insert with the current epoch")?;
    ensure_eq!(attempt.value.number, 1, "the first attempt's number");
    ensure_eq!(
        attempt.value.status,
        AttemptStatus::INITIAL,
        "a new attempt's status"
    );
    ensure_eq!(
        attempt.value.worker.as_str(),
        "worker-1",
        "the attempt's worker"
    );
    ensure_err!(
        tx.insert_attempt(NewAttempt {
            id,
            stage_run_id: stage_run,
            epoch,
            created_at: now,
        })
        .await,
        StoreError::Constraint(_),
        "a second attempt with the same id"
    );
    Ok(())
}

async fn a_heartbeat_with_the_current_epoch_renews_the_lease(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let epoch = world
        .claim("worker-1")
        .await?
        .first()
        .ok_or("nothing was claimed")?
        .lease
        .epoch;
    let attempt = world.new_attempt(world.a, stage_run, epoch).await?;
    subject.advance_database_time(TTL / 2).await;

    let mut tx = world.system_tx().await?;
    let now = tx.database_time().await.ctx("time")?;
    tx.heartbeat(attempt, epoch).await.ctx("heartbeat")?;
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let lease = tx
        .get_stage_run(stage_run)
        .await
        .ctx("get")?
        .value
        .lease
        .ok_or("the lease vanished")?;
    let renewed_for =
        duration_between(&now, &lease.expires_at).ok_or("the renewed lease already ended")?;
    ensure!(
        renewed_for >= TTL && renewed_for <= TTL + Duration::from_secs(1),
        "a heartbeat should extend the lease to one ttl from the database time, but it ends {renewed_for:?} later"
    );
    Ok(())
}

async fn a_heartbeat_after_the_lease_expired_is_fenced(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let epoch = world
        .claim("worker-1")
        .await?
        .first()
        .ok_or("nothing was claimed")?
        .lease
        .epoch;
    let attempt = world.new_attempt(world.a, stage_run, epoch).await?;
    subject
        .advance_database_time(TTL + Duration::from_secs(1))
        .await;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.heartbeat(attempt, epoch).await,
        StoreError::LeaseFenced,
        "a heartbeat after the lease ended"
    );
    Ok(())
}

async fn a_zombie_worker_is_fenced_after_another_worker_takes_over(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let old_epoch = world
        .claim("worker-1")
        .await?
        .first()
        .ok_or("no first claim")?
        .lease
        .epoch;
    let old_attempt = world.new_attempt(world.a, stage_run, old_epoch).await?;
    subject
        .advance_database_time(TTL + Duration::from_secs(1))
        .await;
    let new_epoch = world
        .claim("worker-2")
        .await?
        .first()
        .ok_or("no second claim")?
        .lease
        .epoch;
    let new_attempt = world.new_attempt(world.a, stage_run, new_epoch).await?;
    ensure!(
        new_epoch > old_epoch,
        "the epoch must rise: {old_epoch:?} then {new_epoch:?}"
    );

    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.heartbeat(old_attempt, old_epoch).await,
        StoreError::LeaseFenced,
        "a heartbeat from the worker that lost its lease"
    );
    tx.heartbeat(new_attempt, new_epoch)
        .await
        .ctx("the new worker's heartbeat")?;
    Ok(())
}

async fn a_zombie_cannot_change_its_attempt(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let old_epoch = world
        .claim("worker-1")
        .await?
        .first()
        .ok_or("no first claim")?
        .lease
        .epoch;
    let old_attempt = world.new_attempt(world.a, stage_run, old_epoch).await?;
    subject
        .advance_database_time(TTL + Duration::from_secs(1))
        .await;
    world.claim("worker-2").await?;
    let now = world.now().await?;
    let ready = AppliedTransition::plan(AttemptStatus::INITIAL, AttemptEvent::SandboxReady, now)
        .ctx("plan")?;

    let mut tx = world.tenant_tx(world.a).await?;
    ensure_err!(
        tx.transition_attempt(old_attempt, Version::FIRST, old_epoch, ready)
            .await,
        StoreError::LeaseFenced,
        "a status change from a worker that lost its lease"
    );
    let read = tx.get_attempt(old_attempt).await.ctx("get")?;
    ensure_eq!(
        read.value.status,
        AttemptStatus::INITIAL,
        "the attempt after the refused change"
    );
    ensure_eq!(
        read.version,
        Version::FIRST,
        "the attempt's version after the refused change"
    );
    Ok(())
}

async fn an_attempt_that_ended_cannot_be_heartbeated(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let stage_run = world.ready_stage_run(world.a, job).await?;
    let epoch = world
        .claim("worker-1")
        .await?
        .first()
        .ok_or("nothing was claimed")?
        .lease
        .epoch;
    let attempt = world.new_attempt(world.a, stage_run, epoch).await?;
    let now = world.now().await?;
    let failed = AttemptStatus::INITIAL
        .legal_events()
        .into_iter()
        .find_map(|event| {
            AppliedTransition::plan(AttemptStatus::INITIAL, event, now)
                .ok()
                .filter(|plan| plan.to_status().is_terminal())
        });
    let failed = failed.ok_or("no move from the initial attempt status reaches an end state")?;
    let mut tx = world.tenant_tx(world.a).await?;
    tx.transition_attempt(attempt, Version::FIRST, epoch, failed)
        .await
        .ctx("end the attempt")?;
    ensure_err!(
        tx.heartbeat(attempt, epoch).await,
        StoreError::Conflict,
        "a heartbeat for an attempt that already ended"
    );
    Ok(())
}

async fn expired_leases_lists_only_attempts_past_their_lease(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run_one = world.ready_stage_run(world.a, job).await?;
    let run_two = world.ready_stage_run(world.a, job).await?;
    let claims = world.claim("worker-1").await?;
    ensure_eq!(claims.len(), 2, "both stage runs are claimed");
    let epoch_of = |run: StageRunId| {
        claims
            .iter()
            .find(|work| work.stage_run.value.id == run)
            .map(|work| work.lease.epoch)
            .ok_or_else(|| "a stage run was not claimed".to_owned())
    };
    let attempt_one = world
        .new_attempt(world.a, run_one, epoch_of(run_one)?)
        .await?;
    let attempt_two = world
        .new_attempt(world.a, run_two, epoch_of(run_two)?)
        .await?;

    // Keep the second lease alive, then let the first one run out.
    subject.advance_database_time(TTL / 2).await;
    let mut tx = world.system_tx().await?;
    tx.heartbeat(attempt_two, epoch_of(run_two)?)
        .await
        .ctx("heartbeat")?;
    ensure_eq!(
        tx.expired_leases(10)
            .await
            .ctx("expired before any lease ended")?
            .len(),
        0,
        "expired leases while every lease is current"
    );
    tx.commit().await.ctx("commit")?;
    subject
        .advance_database_time(TTL / 2 + Duration::from_secs(1))
        .await;

    let mut tx = world.system_tx().await?;
    let expired = tx.expired_leases(10).await.ctx("expired leases")?;
    ensure_eq!(
        expired,
        vec![attempt_one],
        "the attempts whose lease has ended"
    );
    Ok(())
}

async fn the_first_ledger_entry_starts_the_chain(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_eq!(
        tx.ledger_head(job).await.ctx("head")?,
        None,
        "the head of an empty ledger"
    );
    let entry = ledger_entry(&world.ids, job, run, 1, None, &now, "First.");
    let head = tx.append_ledger_entry(entry.clone()).await.ctx("append")?;
    ensure_eq!(head.sequence, 1, "the head after the first append");
    ensure_eq!(head.hash, entry.entry_hash.clone(), "the head hash");
    ensure_eq!(
        tx.ledger_head(job).await.ctx("head")?,
        Some(head),
        "ledger_head"
    );
    Ok(())
}

async fn ledger_entries_read_back_in_order_and_verify(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    let mut previous: Option<Sha256Digest> = None;
    let mut written = Vec::new();
    for sequence in 1..=3 {
        let entry = ledger_entry(
            &world.ids,
            job,
            run,
            sequence,
            previous.as_ref(),
            &now,
            "A claim.",
        );
        previous = Some(entry.entry_hash.clone());
        tx.append_ledger_entry(entry.clone()).await.ctx("append")?;
        written.push(entry);
    }
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.read_ledger(job, 1, 100).await.ctx("read")?;
    ensure_eq!(read, written.clone(), "the entries read back");
    ensure!(
        verify_chain(&read).is_ok(),
        "the chain that was read back must verify"
    );
    ensure_eq!(
        head_of(&read).map(|h| h.sequence),
        Some(3),
        "the head of the chain read"
    );
    let tail = tx.read_ledger(job, 2, 1).await.ctx("read a page")?;
    ensure_eq!(
        tail,
        vec![written[1].clone()],
        "a page that starts at position 2 and holds one entry"
    );
    Ok(())
}

async fn a_ledger_entry_that_skips_a_position_breaks_the_chain(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    let first = ledger_entry(&world.ids, job, run, 1, None, &now, "First.");
    tx.append_ledger_entry(first.clone()).await.ctx("append")?;
    let skipping = ledger_entry(
        &world.ids,
        job,
        run,
        3,
        Some(&first.entry_hash),
        &now,
        "Third.",
    );
    ensure_err!(
        tx.append_ledger_entry(skipping).await,
        StoreError::ChainBroken,
        "an entry at position 3 after position 1"
    );
    Ok(())
}

async fn a_ledger_entry_with_the_wrong_previous_hash_breaks_the_chain(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    let first = ledger_entry(&world.ids, job, run, 1, None, &now, "First.");
    tx.append_ledger_entry(first).await.ctx("append")?;
    let elsewhere = Sha256Digest::of(b"some other history");
    let forged = ledger_entry(&world.ids, job, run, 2, Some(&elsewhere), &now, "Second.");
    ensure_err!(
        tx.append_ledger_entry(forged).await,
        StoreError::ChainBroken,
        "an entry that points at a hash other than the head's"
    );
    Ok(())
}

async fn a_ledger_entry_with_a_wrong_own_hash_is_refused(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    let first = ledger_entry(&world.ids, job, run, 1, None, &now, "First.");
    tx.append_ledger_entry(first.clone()).await.ctx("append")?;
    let mut tampered = ledger_entry(
        &world.ids,
        job,
        run,
        2,
        Some(&first.entry_hash),
        &now,
        "Second.",
    );
    tampered.claim.statement = HumanText::parse("Changed after sealing.").ctx("text")?;
    ensure_err!(
        tx.append_ledger_entry(tampered).await,
        StoreError::ChainBroken,
        "an entry whose content no longer matches its hash"
    );
    Ok(())
}

async fn a_ledger_position_can_be_taken_only_once(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    tx.append_ledger_entry(ledger_entry(&world.ids, job, run, 1, None, &now, "First."))
        .await
        .ctx("append")?;
    ensure_err!(
        tx.append_ledger_entry(ledger_entry(&world.ids, job, run, 1, None, &now, "Rival."))
            .await,
        StoreError::Conflict,
        "a second entry at position 1"
    );
    Ok(())
}

async fn two_open_transactions_cannot_both_extend_the_chain(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    let first = ledger_entry(&world.ids, job, run, 1, None, &now, "First.");
    tx.append_ledger_entry(first.clone()).await.ctx("append")?;
    tx.commit().await.ctx("commit")?;

    let mut one = world.tenant_tx(world.a).await?;
    let mut two = world.tenant_tx(world.a).await?;
    let second_one = ledger_entry(
        &world.ids,
        job,
        run,
        2,
        Some(&first.entry_hash),
        &now,
        "One.",
    );
    let second_two = ledger_entry(
        &world.ids,
        job,
        run,
        2,
        Some(&first.entry_hash),
        &now,
        "Two.",
    );
    one.append_ledger_entry(second_one)
        .await
        .ctx("the first writer's append")?;
    let append_two = two.append_ledger_entry(second_two).await;
    one.commit().await.ctx("the first writer's commit")?;
    match append_two {
        Err(StoreError::Conflict) => {}
        Err(other) => return Err(format!("the second writer's append failed with {other:?}")),
        Ok(_) => match two.commit().await {
            Err(StoreError::Conflict) => {}
            Err(other) => return Err(format!("the second writer's commit failed with {other:?}")),
            Ok(()) => {
                return Err(
                    "two transactions both extended the chain at position 2 and both committed"
                        .to_owned(),
                );
            }
        },
    }
    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.read_ledger(job, 1, 10).await.ctx("read")?;
    ensure_eq!(read.len(), 2, "entries in the chain");
    ensure!(verify_chain(&read).is_ok(), "the chain must still verify");
    Ok(())
}

async fn a_rolled_back_ledger_append_leaves_no_trace(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let run = world.ids.stage_run();
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    tx.append_ledger_entry(ledger_entry(&world.ids, job, run, 1, None, &now, "First."))
        .await
        .ctx("append")?;
    tx.rollback().await.ctx("roll back")?;
    let mut tx = world.tenant_tx(world.a).await?;
    ensure_eq!(
        tx.ledger_head(job).await.ctx("head")?,
        None,
        "the head after a rolled-back append"
    );
    // The position is free again.
    tx.append_ledger_entry(ledger_entry(&world.ids, job, run, 1, None, &now, "Again."))
        .await
        .ctx("append at the freed position")?;
    Ok(())
}

async fn events_read_back_in_the_order_they_were_queued(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    let mut queued = Vec::new();
    for version in 2..=4 {
        let event = domain_event(&world.ids, world.a, job, version, &now);
        queued.push(event.event_id);
        tx.enqueue_event(event).await.ctx("enqueue")?;
    }
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let rows = tx
        .read_events(job, OutboxSeq::START, 100)
        .await
        .ctx("read")?;
    let read: Vec<_> = rows.iter().map(|row| row.event.event_id).collect();
    ensure_eq!(read, queued, "the event ids in read order");
    ensure!(
        rows.windows(2).all(|pair| pair[0].seq < pair[1].seq),
        "positions must rise with every event"
    );
    Ok(())
}

async fn reading_resumes_after_the_last_position_seen(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    for version in 2..=4 {
        tx.enqueue_event(domain_event(&world.ids, world.a, job, version, &now))
            .await
            .ctx("enqueue")?;
    }
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let page = tx
        .read_events(job, OutboxSeq::START, 2)
        .await
        .ctx("first page")?;
    ensure_eq!(page.len(), 2, "events in a page of two");
    let last = page.last().ok_or("empty page")?.seq;
    // `from` is inclusive: reading from the last position seen returns that event again.
    let again = tx.read_events(job, last, 10).await.ctx("resume at last")?;
    ensure_eq!(
        again.first().map(|row| row.seq),
        Some(last),
        "from is inclusive"
    );
    ensure_eq!(
        again.len(),
        2,
        "events from the last position seen to the end"
    );
    let after = tx
        .read_events(job, OutboxSeq::new(last.get() + 1), 10)
        .await
        .ctx("resume after")?;
    ensure_eq!(after.len(), 1, "events after the last position seen");
    Ok(())
}

async fn events_are_kept_per_job(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job_one = world.job(world.a).await?;
    let job_two = world.job(world.a).await?;
    let now = world.now().await?;
    let mut tx = world.tenant_tx(world.a).await?;
    tx.enqueue_event(domain_event(&world.ids, world.a, job_one, 2, &now))
        .await
        .ctx("one")?;
    tx.enqueue_event(domain_event(&world.ids, world.a, job_two, 2, &now))
        .await
        .ctx("two")?;
    tx.enqueue_event(domain_event(&world.ids, world.a, job_two, 3, &now))
        .await
        .ctx("three")?;
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    ensure_eq!(
        tx.read_events(job_one, OutboxSeq::START, 10)
            .await
            .ctx("one")?
            .len(),
        1,
        "events of job one"
    );
    ensure_eq!(
        tx.read_events(job_two, OutboxSeq::START, 10)
            .await
            .ctx("two")?
            .len(),
        2,
        "events of job two"
    );
    Ok(())
}

async fn an_event_id_can_be_queued_only_once(subject: &dyn StoreSubject) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let event = domain_event(&world.ids, world.a, job, 2, &now);
    let mut tx = world.tenant_tx(world.a).await?;
    tx.enqueue_event(event.clone()).await.ctx("enqueue")?;
    ensure_err!(
        tx.enqueue_event(event).await,
        StoreError::Constraint(_),
        "the same event id queued twice"
    );
    Ok(())
}

async fn audit_records_read_back_in_order_and_stay_with_their_tenant(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let job = world.job(world.a).await?;
    let now = world.now().await?;
    let correlation = world.ids.correlation();
    let record = |action: &str| -> Result<AuditEvent, String> {
        Ok(AuditEvent {
            job_id: job,
            actor: AuditActor::Component(Slug::parse("workflow.engine").ctx("slug")?),
            action: Slug::parse(action).ctx("slug")?,
            policy_hash: Sha256Digest::of(b"policy"),
            correlation_id: correlation,
            occurred_at: now,
        })
    };
    let mut tx = world.tenant_tx(world.a).await?;
    tx.record_audit(record("job.admitted")?)
        .await
        .ctx("record")?;
    tx.record_audit(record("approval.recorded")?)
        .await
        .ctx("record")?;
    tx.commit().await.ctx("commit")?;

    let mut tx = world.tenant_tx(world.a).await?;
    let read = tx.read_audit(job, 10).await.ctx("read")?;
    let actions: Vec<&str> = read.iter().map(|e| e.action.as_str()).collect();
    ensure_eq!(
        actions,
        vec!["job.admitted", "approval.recorded"],
        "audit actions in order"
    );
    drop(tx);

    let mut other = world.tenant_tx(world.b).await?;
    ensure_err!(
        other.record_audit(record("job.admitted")?).await,
        StoreError::NotFound,
        "recording an audit event for another tenant's job"
    );
    Ok(())
}

async fn database_time_follows_the_subjects_clock(
    subject: &dyn StoreSubject,
) -> Result<(), String> {
    let world = World::new(subject);
    let before = world.now().await?;
    subject.advance_database_time(Duration::from_secs(30)).await;
    let after = world.now().await?;
    let gap = duration_between(&before, &after).ok_or("the database time went backwards")?;
    ensure!(
        gap >= Duration::from_secs(30),
        "after the clock moved 30 seconds the database time moved only {gap:?}"
    );
    ensure!(
        timestamp_after(&before, Duration::from_secs(30)) <= after,
        "the database time must be at least 30 seconds later"
    );
    Ok(())
}
