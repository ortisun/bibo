//! The claim loop: handing a ready stage run to one worker, with a lease.
//!
//! A claim has two halves, in two transactions, because the system scope only finds work and the
//! tenant scope applies it (ADR 0012, ADR 0014):
//!
//! 1. A system transaction finds ready stage runs of active jobs whose back-off is over
//!    (`SystemTx::find_claim_candidates`). It writes nothing and holds no lock once it ends. What
//!    it returns is a hint, not a grant.
//! 2. For each candidate, a tenant transaction reads the job and the stage run, checks the guard
//!    `G_LEASE_ACQUIRED` and calls `AttemptOps::start_attempt`. The store checks that the stage run
//!    is still `READY` at the version the candidate was read at, raises the epoch, moves the run
//!    to `RUNNING` (`S03`) and creates the attempt with its lease, as one step. Two workers that
//!    found the same candidate cannot both start it: one gets `Conflict`.
//!
//! If the engine stops between the two halves nothing was written, and the next claim finds the
//! same candidate again. If it stops after the start, the attempt holds a lease that lapses by
//! itself and the sweeper ends it (`A07`). A worker that did start holds an epoch that the store
//! checks on every write (INV-05).

use factory_domain::ids::{AttemptId, CorrelationId, JobId, StageRunId, TenantId};
use factory_domain::machines::guards::{GuardFacts, LeaseGrantFacts, evaluate};
use factory_domain::state::Guard;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{
    ClaimCandidate, ConstraintRule, LeaseEpoch, NotReady, StoreError, WorkerId,
};
use std::time::Duration;

use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::engine::progress::{Board, upstream_runs};
use crate::engine::record::{Cx, Launch};
use crate::engine::timeline::Timeline;
use crate::engine::{Engine, EngineError};

/// A stage run that was claimed and whose attempt has started. The worker runs the attempt with
/// this and sends every write under its epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedAttempt {
    /// The tenant that owns the job.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// Shared by every event, log line and span of the job.
    pub correlation: CorrelationId,
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

/// Why a candidate did not start. Nothing was claimed, so there is no lease to wait out.
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
    /// The job has spent its budget. A person raises it or ends the job.
    BudgetExhausted,
    /// The contract of the stage could not be resolved.
    NoContract,
    /// The stage run has used all the attempts the store allows it.
    AttemptLimit,
    /// Another worker started it first, or it changed since it was found.
    Superseded,
    /// Starting it raised an error that is about this stage run or its job and not about the
    /// worker (a damaged record, a stage with no handler here). It was set aside for a while, so
    /// that the stage runs behind it get their turn, and the error was logged.
    Faulted,
}

impl Deferral {
    /// True when the stage run stays `READY` and would be found again at once, so the engine moves
    /// its `not_before` forward to keep one stage run from holding up the others.
    const fn is_postponed(self) -> bool {
        matches!(
            self,
            Self::QuotaExceeded | Self::NoRuntime | Self::BudgetExhausted | Self::NoContract
        )
    }
}

/// The result of one call to [`Engine::claim_next`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claimed {
    /// The attempts that started.
    pub started: Vec<ClaimedAttempt>,
    /// The stage runs that were found and did not start, with the reason.
    pub deferred: Vec<(StageRunId, Deferral)>,
}

impl Engine {
    /// Finds ready stage runs and starts an attempt, with a lease for `worker`, for each one that
    /// may start.
    ///
    /// # Errors
    /// The store errors of the lookup, and an error of a start that is about the process
    /// ([`EngineError::is_about_the_process`]). A stage run that cannot start is reported in
    /// [`Claimed::deferred`], not as an error, so one bad run does not hold back the others. That
    /// includes a stage run whose start raises an error about itself: it is set aside for one
    /// lease time ([`Deferral::Faulted`]). Without that it would stay the oldest ready run, be
    /// found first by every claim of every worker, and stop them all.
    pub async fn claim_next(&self, worker: &WorkerId) -> Result<Claimed, EngineError> {
        let candidates = {
            let mut tx = self.system_tx().await?;
            let found = tx.find_claim_candidates(self.config.claim_batch).await;
            // The transaction ends whether or not the lookup worked, so no lock outlives it.
            tx.finish().await?;
            found?
        };
        // The depth of the queue as the lookup saw it: stage runs that are ready, of active jobs,
        // with their back-off over, waiting for a worker. It is recorded on every call, zero
        // included, so an idle queue reads as zero and not as a gap. The lookup returns at most
        // `claim_batch` of them, so this is the depth up to that bound; the store port has no
        // count that would see past it.
        tracing::info!(
            gauge.factory_queue_depth = i64::try_from(candidates.len()).unwrap_or(i64::MAX),
            queue = "ready_stage_runs"
        );
        let mut claimed = Claimed::default();
        for candidate in candidates {
            let run = candidate.stage_run;
            match self.start_candidate(worker, &candidate).await {
                Ok(Ok(started)) => claimed.started.push(started),
                Ok(Err(reason)) => claimed.deferred.push((run, reason)),
                Err(EngineError::Conflict | EngineError::LeaseFenced | EngineError::NotFound) => {
                    claimed.deferred.push((run, Deferral::Superseded));
                }
                Err(error) if error.is_about_the_process() => return Err(error),
                Err(error) => {
                    tracing::error!(
                        stage_run = %run,
                        %error,
                        "a ready stage run cannot be started; it is set aside so the others run"
                    );
                    self.set_aside(&candidate).await?;
                    claimed.deferred.push((run, Deferral::Faulted));
                }
            }
        }
        Ok(claimed)
    }

    /// Moves the `not_before` of a candidate that raised an error forward by one lease time, in a
    /// transaction of its own, because the one that raised the error is gone.
    ///
    /// Nothing else is written: the stage run stays `READY` and is tried again after the wait, so
    /// a fault that passes (a handler that a new release registers, a record that is repaired)
    /// needs no command to recover from. The engine has no way to fail a stage run that has no
    /// attempt, and this adds none.
    async fn set_aside(&self, candidate: &ClaimCandidate) -> Result<(), EngineError> {
        let mut tx = self.tenant_tx(candidate.tenant).await?;
        match tx
            .postpone_stage_run(
                candidate.stage_run,
                candidate.version,
                self.config.lease_ttl,
            )
            .await
        {
            Ok(_) => Ok(tx.commit().await?),
            // It changed since it was found, so it is not the same candidate any more.
            Err(StoreError::Conflict | StoreError::NotFound) => Ok(tx.rollback().await?),
            Err(other) => {
                let _ = tx.rollback().await;
                Err(other.into())
            }
        }
    }

    /// Applies one candidate: checks `G_LEASE_ACQUIRED`, then starts the attempt (`S03`).
    async fn start_candidate(
        &self,
        worker: &WorkerId,
        candidate: &ClaimCandidate,
    ) -> Result<Result<ClaimedAttempt, Deferral>, EngineError> {
        let (tenant, job_id, run_id) = (candidate.tenant, candidate.job, candidate.stage_run);
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
        let board = Board::of(&timeline);
        let upstream = upstream_runs(&timeline, &board);
        let ccx = self.contract_context(&cx, &run.value, record, &upstream);
        let contract = handler.contract(&ccx);
        // The need is asked without the author of the work under review, on purpose. A review
        // with no model independent of its author must start, so that the attempt can send it to
        // a person (`S07`, cause `independent-reviewer-unavailable`). Asked with the author here,
        // the check would defer the stage run, and it would sit `READY` with nobody told.
        let capability_ok = handler
            .routing_need(&ccx)
            .is_none_or(|need| self.deps.router.route(&need).is_ok());
        let now = tx.database_time().await?;

        let facts = GuardFacts::LeaseGrant(LeaseGrantFacts {
            claim_candidate_current: run.value.status
                == factory_domain::state::StageRunStatus::Ready
                && run.version == candidate.version,
            job_status: job.value.status,
            now,
            not_before: Some(run.value.not_before),
            concurrency_quota_allows: quota_allows,
            runtime_capability_check_passed: capability_ok,
        });
        let verdict = match (
            &contract,
            timeline.spent_micro_usd >= self.config.job_budget_micro_usd,
        ) {
            (Err(_), _) => Err(Deferral::NoContract),
            (Ok(_), true) => Err(Deferral::BudgetExhausted),
            (Ok(_), false) => match evaluate(Guard::LeaseAcquired, &facts) {
                Ok(cleared) => Ok(cleared),
                Err(error) => {
                    tracing::debug!(
                        stage_run = %run_id,
                        guard = %Guard::LeaseAcquired,
                        "a stage run does not start: {error}"
                    );
                    Err(deferral_for(
                        job.value.status,
                        run.value.not_before > now,
                        quota_allows,
                        capability_ok,
                        run.value.status == factory_domain::state::StageRunStatus::Ready
                            && run.version == candidate.version,
                    ))
                }
            },
        };
        let cleared = match verdict {
            Ok(cleared) => cleared,
            Err(reason) => return self.defer(tx, &run, reason).await,
        };
        let Ok(contract) = contract else {
            return Ok(Err(Deferral::NoContract));
        };

        let attempt_id = self.new_attempt_id();
        let timeout = Duration::from_secs(
            u64::try_from(contract.timeout_and_retries.attempt_timeout_seconds.get())
                .unwrap_or(u64::MAX),
        );
        let started = match cx
            .start_stage_run(
                &mut *tx,
                &run,
                cleared,
                Launch {
                    attempt: attempt_id,
                    worker: worker.clone(),
                    lease_ttl: self.config.lease_ttl,
                    attempt_timeout: timeout,
                },
            )
            .await
        {
            Ok(started) => started,
            // The store judged it by its own clock and its own rows, and its answer is final.
            Err(EngineError::Store(StoreError::NotReady(NotReady::JobNotActive))) => {
                return Ok(Err(Deferral::JobNotActive));
            }
            Err(EngineError::Store(StoreError::NotReady(NotReady::BackingOff))) => {
                return Ok(Err(Deferral::BackingOff));
            }
            Err(EngineError::Store(StoreError::Constraint(ConstraintRule::AttemptLimit))) => {
                return Ok(Err(Deferral::AttemptLimit));
            }
            Err(other) => return Err(other),
        };
        // The tools that policy granted to this run are the ones in its contract.
        cx.audit_engine(
            &mut *tx,
            AuditAction::new(AuditKind::ToolGrantIssued, AuditDecision::Granted),
        )
        .await?;
        cx.commit(tx).await?;
        let attempt = started.attempt.value;
        Ok(Ok(ClaimedAttempt {
            tenant,
            job: job_id,
            correlation: job.value.correlation_id,
            stage_run: run_id,
            kind: run.value.kind,
            attempt: attempt_id,
            attempt_number: attempt.number,
            epoch: attempt.epoch,
            worker: worker.clone(),
            lease_expires_at: attempt.lease_expires_at,
            deadline_at: attempt.deadline_at,
        }))
    }

    /// Ends a transaction for a candidate that does not start. A reason that would make the same
    /// candidate come back at once moves the stage run's `not_before` forward first
    /// (`postpone_stage_run`), so other stage runs get their turn.
    async fn defer(
        &self,
        mut tx: Box<dyn factory_ports::store::Tx>,
        run: &factory_ports::store::Versioned<factory_ports::store::StageRun>,
        reason: Deferral,
    ) -> Result<Result<ClaimedAttempt, Deferral>, EngineError> {
        if reason.is_postponed() {
            tx.postpone_stage_run(run.value.id, run.version, self.config.lease_ttl)
                .await?;
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        Ok(Err(reason))
    }
}

/// The reason a guard-checked claim did not start, in the order a person would look for it.
fn deferral_for(
    job_status: factory_domain::state::JobStatus,
    backing_off: bool,
    quota_allows: bool,
    capability_ok: bool,
    candidate_current: bool,
) -> Deferral {
    if !candidate_current {
        Deferral::Superseded
    } else if job_status != factory_domain::state::JobStatus::Active {
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
