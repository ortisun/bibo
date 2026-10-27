//! The claim loop: handing a ready stage run to one worker, with a lease.
//!
//! A claim has two halves, in two transactions, because the system scope only finds work and the
//! tenant scope applies it (ADR 0012):
//!
//! 1. A system transaction leases ready stage runs to the worker (`Store::claim_ready`). The
//!    store gives each stage run to at most one claimer, skips one that is already claimed, and
//!    raises its lease epoch. The engine commits at once.
//! 2. For each stage run, a tenant transaction checks the guard `G_LEASE_ACQUIRED`, creates the
//!    attempt and moves the stage run to `RUNNING` (`S03`) in one commit.
//!
//! If the engine stops between the two, the stage run is `READY` with a lease that lapses by
//! itself, and the next claim takes it with a higher epoch. Nothing is lost and nothing runs
//! twice: the attempt that did not start has no worker, and a worker that did start holds an
//! epoch that the store checks on every write (INV-05).

use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::machines::guards::{GuardFacts, LeaseGrantFacts, evaluate};
use factory_domain::state::{Guard, StageRunEvent, StageRunStatus};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::timestamp_after;
use factory_ports::store::{ClaimedWork, LeaseEpoch, NewAttempt, StoreError, WorkerId};
use std::time::Duration;

use crate::engine::payload::attempt_started;
use crate::engine::progress::{Board, upstream_runs};
use crate::engine::record::Cx;
use crate::engine::timeline::Timeline;
use crate::engine::{Engine, EngineError};
use crate::handlers::ContractContext;

/// A stage run that was claimed and whose attempt has started. The worker runs the attempt with
/// this and sends every write under its epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedAttempt {
    /// The tenant that owns the job.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// Which stage it is a run of.
    pub kind: StageKind,
    /// The attempt, in `STARTING`.
    pub attempt: AttemptId,
    /// Which try this is for the stage run, from 1.
    pub attempt_number: u32,
    /// The fencing epoch of the lease. Every write of the worker carries it.
    pub epoch: LeaseEpoch,
    /// The worker that holds the lease.
    pub worker: WorkerId,
    /// When the lease ends unless a heartbeat renews it, by the database clock.
    pub lease_expires_at: Timestamp,
    /// When the attempt times out.
    pub deadline_at: Timestamp,
}

/// Why a claimed stage run did not start. The lease lapses by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deferral {
    /// The job is not `ACTIVE`: paused, waiting, blocked, cancelling or finished.
    JobNotActive,
    /// A retry back-off has not ended.
    BackingOff,
    /// The concurrency quota does not allow another attempt.
    QuotaExceeded,
    /// The router has no route for what the stage needs.
    NoRuntime,
    /// The contract of the stage could not be resolved.
    NoContract,
    /// Another writer got there first, or the lease had already ended.
    Superseded,
}

/// The result of one call to [`Engine::claim_next`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claimed {
    /// The attempts that started.
    pub started: Vec<ClaimedAttempt>,
    /// The stage runs that were claimed and did not start, with the reason.
    pub deferred: Vec<(StageRunId, Deferral)>,
}

impl Engine {
    /// Leases ready stage runs to `worker` and starts an attempt for each one that may start.
    ///
    /// # Errors
    /// The store errors of the claim itself. A stage run that cannot start is reported in
    /// [`Claimed::deferred`], not as an error, so one bad run does not hold back the others.
    pub async fn claim_next(&self, worker: &WorkerId) -> Result<Claimed, EngineError> {
        let work = {
            let mut tx = self.system_tx().await?;
            let work = tx
                .claim_ready(worker, self.config.claim_batch, self.config.lease_ttl)
                .await?;
            match tx.commit().await {
                Ok(()) => work,
                // Another claimer committed first: its claim stands and this one is dropped.
                Err(StoreError::Conflict) => return Ok(Claimed::default()),
                Err(other) => return Err(other.into()),
            }
        };
        let mut claimed = Claimed::default();
        for item in work {
            let run = item.stage_run.value.id;
            match self.start_attempt(worker, item).await {
                Ok(Ok(started)) => claimed.started.push(started),
                Ok(Err(reason)) => claimed.deferred.push((run, reason)),
                Err(EngineError::Conflict | EngineError::LeaseFenced | EngineError::NotFound) => {
                    claimed.deferred.push((run, Deferral::Superseded));
                }
                Err(other) => return Err(other),
            }
        }
        Ok(claimed)
    }

    /// Applies one claim: checks `G_LEASE_ACQUIRED`, creates the attempt and takes `S03`.
    async fn start_attempt(
        &self,
        worker: &WorkerId,
        work: ClaimedWork,
    ) -> Result<Result<ClaimedAttempt, Deferral>, EngineError> {
        let (tenant, job_id, run_id) = (
            work.stage_run.value.tenant_id,
            work.stage_run.value.job_id,
            work.stage_run.value.id,
        );
        // The quota is asked before the transaction opens: a transaction awaits the store only.
        let quota_allows = self
            .deps
            .authority
            .concurrency_allows(tenant, job_id)
            .await
            .unwrap_or(false);

        let mut tx = self.tenant_tx(tenant).await?;
        let job = tx.get_job(job_id).await?;
        let run = tx.get_stage_run(run_id).await?;
        if run.value.status != StageRunStatus::Ready || run.value.lease_epoch != work.lease.epoch {
            return Ok(Err(Deferral::Superseded));
        }
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        let timeline = Timeline::load(&mut *tx, job_id).await?;
        let Some(record) = timeline.run(run_id) else {
            return Err(EngineError::Corrupt(
                "a claimed stage run is not in the job's timeline",
            ));
        };
        let handler = self
            .handlers
            .get(run.value.kind)
            .ok_or(EngineError::NoHandler(run.value.kind))?;
        let board = Board::load(&mut *tx, &timeline).await?;
        let upstream = upstream_runs(&timeline, &board);
        let ccx = ContractContext {
            identity: Engine::identity(&cx, &run.value),
            mode: self.config.mode,
            policy_hash: &self.config.policy_hash,
            now: cx.now,
            upstream: &upstream,
            human_inputs: &record.human_inputs,
        };
        let Ok(contract) = handler.contract(&ccx) else {
            return Ok(Err(Deferral::NoContract));
        };
        let capability_ok = handler
            .routing_need(&ccx)
            .is_none_or(|need| self.deps.router.route(&need).is_ok());

        let now = tx.database_time().await?;
        let facts = GuardFacts::LeaseGrant(LeaseGrantFacts {
            lease_compare_and_swap_succeeded: work.lease.expires_at > now,
            job_status: job.value.status,
            now,
            not_before: record.not_before,
            concurrency_quota_allows: quota_allows,
            runtime_capability_check_passed: capability_ok,
        });
        if let Err(error) = evaluate(Guard::LeaseAcquired, &facts) {
            tracing::debug!(
                stage_run = %run_id,
                guard = %Guard::LeaseAcquired,
                "a claimed stage run does not start: {error}"
            );
            return Ok(Err(deferral_for(
                job.value.status,
                record.not_before.is_some_and(|not_before| now < not_before),
                quota_allows,
                capability_ok,
            )));
        }

        let attempt_id = self.new_attempt_id();
        let attempt = tx
            .insert_attempt(NewAttempt {
                id: attempt_id,
                stage_run_id: run_id,
                epoch: work.lease.epoch,
                created_at: cx.now,
            })
            .await?;
        let timeout = Duration::from_secs(
            u64::try_from(contract.timeout_and_retries.attempt_timeout_seconds.get())
                .unwrap_or(u64::MAX),
        );
        let deadline_at = timestamp_after(&now, timeout);
        let payload = attempt_started(
            run.value.kind,
            run_id,
            attempt_id,
            attempt.value.number,
            deadline_at,
        );
        cx.move_stage_run(&mut *tx, &run, StageRunEvent::Start, None, payload)
            .await?;
        tx.commit().await?;
        Ok(Ok(ClaimedAttempt {
            tenant,
            job: job_id,
            stage_run: run_id,
            kind: run.value.kind,
            attempt: attempt_id,
            attempt_number: attempt.value.number,
            epoch: work.lease.epoch,
            worker: worker.clone(),
            lease_expires_at: work.lease.expires_at,
            deadline_at,
        }))
    }
}

/// The reason a guard-checked claim did not start, in the order a person would look for it.
fn deferral_for(
    job_status: factory_domain::state::JobStatus,
    backing_off: bool,
    quota_allows: bool,
    capability_ok: bool,
) -> Deferral {
    if job_status != factory_domain::state::JobStatus::Active {
        Deferral::JobNotActive
    } else if backing_off {
        Deferral::BackingOff
    } else if !quota_allows {
        Deferral::QuotaExceeded
    } else if !capability_ok {
        Deferral::NoRuntime
    } else {
        Deferral::Superseded
    }
}
