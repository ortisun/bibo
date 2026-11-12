//! The worker loop: claim, run, sweep, wait, until told to stop.
//!
//! The loop runs on one thread (the engine's futures are not `Send`) and runs one attempt at a
//! time, which is the Slice 1 concurrency (`apps` entry `worker` of the rules file). It holds no
//! state about any job: everything it knows is in the store, so a loop that dies is replaced by a
//! new one that starts from the rows.
//!
//! # One pass
//!
//! 1. If a sweep is due, `Engine::sweep`: end attempts whose lease lapsed, whose deadline passed
//!    or whose teardown ran out of time. Another worker's lapsed lease is recovered here. A sweep
//!    is due when the sweep interval has passed since the last one, by the loop's ticker, whether
//!    or not the loop found work in between: a queue that never empties does not put it off.
//! 2. `Engine::claim_next`, which takes at most one attempt (the loop sets `claim_batch` to 1, so
//!    it never holds a lease it is not running).
//! 3. Each started attempt runs inside a `factory.job` span with `Engine::run_attempt`.
//!    While it runs, the loop asks at the poll interval for a cancel of that job and gives it to
//!    the engine, so a person who cancels a job does not wait for its stage to end. Admissions,
//!    approvals and every other decision are still applied between attempts only.
//! 4. With nothing to do the loop waits for the poll interval or for the stop request, whichever
//!    comes first.
//!
//! # Stopping
//!
//! A stop request (SIGTERM or SIGINT, through [`Shutdown`]) is checked before each claim and
//! while waiting. It never interrupts an attempt at once: the attempt gets the **drain budget**
//! to finish and commit its result. If it does not finish in time, the loop stops waiting for it
//! and reports it in [`LoopSummary::abandoned`] with an error-level log line. Its lease is not
//! released by the loop, because the attempt is still in flight in the store; it expires, and the
//! sweeper of the next worker moves the attempt to `LEASE_LOST` and the stage run to a retry.
//! So a lease is never abandoned silently: it is logged, counted, and the exit code says so.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use factory_ports::store::WorkerId;
use factory_workflow::engine::{AttemptOutcome, Engine, EngineError};
use factory_workflow::scheduler::{ClaimedAttempt, Deferral, Ticker};
use tracing::Instrument;

use factory_composition::config::LoopConfig;
use factory_composition::drift::DriftPump;
use factory_composition::hooks::{BeforeClaim, WhileRunning};
use factory_composition::indexing::ActiveJobs;
use factory_composition::system::Shutdown;
use factory_composition::telemetry::job_stretch;

/// What to do after an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Go on.
    Continue,
    /// Leave the loop now, as if the process had been told to stop. Tests use it to stop at an
    /// exact boundary.
    Stop,
}

/// Looks at each finished attempt. Production runs without one.
pub trait Observer: Send + Sync {
    /// Called after the engine committed the result of `attempt`.
    fn after_attempt(&self, attempt: &ClaimedAttempt, outcome: &AttemptOutcome) -> Flow;
}

/// What the loop did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoopSummary {
    /// Attempts that ran to a recorded result.
    pub attempts_run: u32,
    /// Sweeps made.
    pub sweeps: u32,
    /// Ready stage runs the claim set aside because starting them raised an error about the
    /// stage run itself (`Deferral::Faulted`). One stage run is counted each time it is set aside.
    pub set_aside: u32,
    /// Attempts whose run raised an error about the job and that the loop then failed as a fault
    /// of the factory, or left for the sweeper when that could not be recorded.
    pub faulted: u32,
    /// Attempts the loop stopped waiting for at the end of the drain budget.
    pub abandoned: Vec<ClaimedAttempt>,
    /// True when the loop ended because of the stop request or an observer, not an error.
    pub stopped_cleanly: bool,
    /// The error that ended the loop, when one did. Plain text, no secret.
    pub failure: Option<String>,
}

/// The loop.
pub struct WorkerLoop {
    engine: Arc<Engine>,
    ticker: Arc<dyn Ticker>,
    worker: WorkerId,
    settings: LoopConfig,
    shutdown: Shutdown,
    observer: Option<Arc<dyn Observer>>,
    jobs: Option<Arc<ActiveJobs>>,
    before_claim: Vec<Arc<dyn BeforeClaim>>,
    while_running: Vec<Arc<dyn WhileRunning>>,
    drift: Option<Arc<DriftPump>>,
}

impl WorkerLoop {
    /// A loop over an engine that was built with `claim_batch` of 1.
    #[must_use]
    pub fn new(
        engine: Engine,
        ticker: Arc<dyn Ticker>,
        worker: WorkerId,
        settings: LoopConfig,
        shutdown: Shutdown,
    ) -> Self {
        Self::shared(Arc::new(engine), ticker, worker, settings, shutdown)
    }

    /// A loop over an engine that something else holds too: the hook that applies decisions
    /// (`factory_composition::decisions::ClaimWork`) and the approval service call the same engine.
    #[must_use]
    pub fn shared(
        engine: Arc<Engine>,
        ticker: Arc<dyn Ticker>,
        worker: WorkerId,
        settings: LoopConfig,
        shutdown: Shutdown,
    ) -> Self {
        Self {
            engine,
            ticker,
            worker,
            settings,
            shutdown,
            observer: None,
            jobs: None,
            before_claim: Vec::new(),
            while_running: Vec::new(),
            drift: None,
        }
    }

    /// Adds an observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Runs `hook` before each claim, after the hooks added before it. The request cache of
    /// `factory_composition::seams::StoreRequests` is filled this way, because
    /// `RequestSource::recorded` must answer without waiting while the claim runs. It is filled
    /// first, before `factory_composition::decisions::ClaimWork`, which admits jobs and so
    /// resolves their contracts.
    #[must_use]
    pub fn with_before_claim(mut self, hook: Arc<dyn BeforeClaim>) -> Self {
        self.before_claim.push(hook);
        self
    }

    /// Asks `hook`, at the poll interval while an attempt runs, to apply the cancel requests of
    /// the job of that attempt. `factory_composition::decisions::ClaimWork` is the one: without
    /// it a cancel is read between attempts only, so with one worker it waits for the stage to
    /// end.
    #[must_use]
    pub fn with_cancel_watch(mut self, hook: Arc<dyn WhileRunning>) -> Self {
        self.while_running.push(hook);
        self
    }

    /// Applies the cancel requests of the job of `attempt`, at the poll interval, for as long as
    /// it is polled. It never completes: the loop selects on it next to the attempt and drops it
    /// when the attempt ends.
    ///
    /// The hook gives the cancel to the engine. The attempt learns of it from its next heartbeat,
    /// which raises its cancel signal, so the handler and its sandbox run are told to stop within
    /// one poll interval plus one heartbeat interval of the request.
    async fn watch_for_cancel(&self, attempt: &ClaimedAttempt) {
        if self.while_running.is_empty() {
            return std::future::pending().await;
        }
        loop {
            self.ticker.sleep(self.settings.poll_interval()).await;
            for hook in &self.while_running {
                hook.apply_cancels(attempt.tenant, attempt.job).await;
            }
        }
    }

    /// Tells the loop to note, while an attempt runs, which tenant owns its job. The indexing
    /// sandbox reads it (`factory_composition::indexing`).
    #[must_use]
    pub fn with_active_jobs(mut self, jobs: Arc<ActiveJobs>) -> Self {
        self.jobs = Some(jobs);
        self
    }

    /// Serves the evidence-drift requests of the stage handlers while an attempt runs. The
    /// handlers' futures are `Send` and the engine's are not, so the delivery stage reports a
    /// changed binding through a channel and this loop, which owns the engine, makes the call
    /// (`factory_composition::drift`).
    #[must_use]
    pub fn with_drift_pump(mut self, pump: Arc<DriftPump>) -> Self {
        self.drift = Some(pump);
        self
    }

    /// Serves one drift request, or never completes when there is no pump or it has no sender
    /// left. The loop selects on it next to the attempt.
    async fn serve_drift(&self) {
        if let Some(pump) = &self.drift
            && pump.serve_next(&self.engine).await
        {
            return;
        }
        std::future::pending::<()>().await;
    }

    /// The engine, for a caller that needs to read a job between runs.
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Runs until stopped or until an error the loop cannot ride out.
    pub async fn run(&self) -> LoopSummary {
        let mut summary = LoopSummary::default();
        let mut sweep_due = true;
        // The wait until the next sweep. It is made once per sweep and looked at on every pass, so
        // the time an attempt took counts towards it exactly as the time spent idle does.
        let mut next_sweep = self.ticker.sleep(self.settings.sweep_interval());
        tracing::info!(worker = self.worker.as_str(), "worker loop started");
        loop {
            if self.shutdown.is_raised() {
                summary.stopped_cleanly = true;
                break;
            }
            if sweep_due || has_ended(&mut next_sweep).await {
                match self.engine.sweep().await {
                    Ok(swept) => {
                        summary.sweeps += 1;
                        let recovered = swept.lease_lost.len() + swept.timed_out.len();
                        if recovered > 0 {
                            tracing::warn!(
                                lease_lost = swept.lease_lost.len(),
                                timed_out = swept.timed_out.len(),
                                "the sweep recovered attempts"
                            );
                        }
                    }
                    Err(error) if is_transient(&error) => {
                        tracing::warn!(%error, "the sweep failed and will be tried again");
                    }
                    Err(error) => {
                        return self.fail(summary, &error);
                    }
                }
                sweep_due = false;
                next_sweep = self.ticker.sleep(self.settings.sweep_interval());
            }
            for hook in &self.before_claim {
                hook.before_claim().await;
            }
            let claimed = match self.engine.claim_next(&self.worker).await {
                Ok(claimed) => claimed,
                Err(error) if is_transient(&error) => {
                    tracing::warn!(%error, "the claim failed and will be tried again");
                    self.idle().await;
                    continue;
                }
                Err(error) => return self.fail(summary, &error),
            };
            let set_aside = claimed
                .deferred
                .iter()
                .filter(|(_, reason)| *reason == Deferral::Faulted)
                .count();
            summary.set_aside = summary
                .set_aside
                .saturating_add(u32::try_from(set_aside).unwrap_or(u32::MAX));
            if claimed.started.is_empty() {
                self.idle().await;
                continue;
            }
            for attempt in claimed.started {
                match self.run_one(&attempt).await {
                    Ran::Done(outcome) => {
                        summary.attempts_run += 1;
                        if let Some(observer) = &self.observer
                            && observer.after_attempt(&attempt, &outcome) == Flow::Stop
                        {
                            summary.stopped_cleanly = true;
                            return summary;
                        }
                    }
                    Ran::Abandoned => {
                        summary.abandoned.push(attempt);
                        summary.stopped_cleanly = false;
                        return summary;
                    }
                    Ran::Error(error) => {
                        if is_transient(&error) {
                            tracing::warn!(%error, "an attempt could not record its result; the lease will lapse");
                        } else if error.is_about_the_process() {
                            return self.fail(summary, &error);
                        } else {
                            summary.faulted += 1;
                            if let Err(worse) = self.fail_faulted(&attempt, &error).await {
                                return self.fail(summary, &worse);
                            }
                        }
                    }
                }
            }
        }
        tracing::info!(attempts = summary.attempts_run, "worker loop stopped");
        summary
    }

    /// Deals with an attempt whose run raised `error`, an error about the job and not about this
    /// process. The loop used to end here, and the worker that replaced it met the same job again.
    ///
    /// The failure is recorded against the attempt through the engine (`Engine::fail_attempt`), as
    /// a fault of the factory, which is never retried: the stage run ends or asks a person, and
    /// the jobs behind it run. When even that cannot be recorded because of the job (its records
    /// are damaged), the attempt is left as it is: its lease lapses, the sweeper ends it, and the
    /// retry rules of the stage bound how often it comes back.
    ///
    /// # Errors
    /// The error of the recording when it is about this process, which ends the loop.
    async fn fail_faulted(
        &self,
        attempt: &ClaimedAttempt,
        error: &EngineError,
    ) -> Result<(), EngineError> {
        tracing::error!(
            attempt = %attempt.attempt,
            stage = attempt.kind.as_str(),
            %error,
            detail = ?error,
            "an attempt raised an error about its job; it is failed and the loop goes on"
        );
        match self.engine.fail_attempt(attempt).await {
            Ok(outcome) => {
                tracing::warn!(attempt = %attempt.attempt, outcome = ?outcome, "the faulted attempt was ended");
                Ok(())
            }
            Err(worse) if worse.is_about_the_process() && !is_transient(&worse) => Err(worse),
            Err(worse) => {
                tracing::error!(
                    attempt = %attempt.attempt,
                    error = %worse,
                    "the failure of a faulted attempt could not be recorded; its lease is left to lapse and the sweeper will end it"
                );
                Ok(())
            }
        }
    }

    fn fail(&self, mut summary: LoopSummary, error: &EngineError) -> LoopSummary {
        tracing::error!(%error, detail = ?error, "worker loop ended with an error");
        summary.failure = Some(format!("{error} ({error:?})"));
        summary
    }

    /// Runs one attempt inside a job span, honouring the drain budget on a stop request.
    async fn run_one(&self, attempt: &ClaimedAttempt) -> Ran {
        let _active = self
            .jobs
            .as_ref()
            .map(|jobs| ActiveGuard::enter(Arc::clone(jobs), attempt));
        let span = job_stretch(
            &attempt.correlation.to_string(),
            &attempt.job.to_string(),
            &attempt.tenant.to_string(),
        );
        let work = async {
            let result = self.engine.run_attempt(attempt).await;
            match &result {
                Ok(outcome) => tracing::info!(
                    stage = attempt.kind.as_str(),
                    outcome = ?outcome,
                    "attempt finished"
                ),
                Err(error) => tracing::warn!(
                    stage = attempt.kind.as_str(),
                    %error,
                    "attempt ended with an engine error"
                ),
            }
            result
        }
        .instrument(span);
        tokio::pin!(work);
        // The watch is made once and kept through both phases. It never completes, so it never
        // ends a `select!` and so never drops a drift request that is being served.
        let cancel_watch = self.watch_for_cancel(attempt);
        tokio::pin!(cancel_watch);
        // Phase 1: no stop request yet. The attempt runs; a stop request starts the drain clock.
        let stop = self.shutdown.raised();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                result = &mut work => return Ran::from(result),
                () = &mut cancel_watch => {}
                () = &mut stop => {
                    tracing::info!(attempt = %attempt.attempt, drain_s = self.settings.drain_s, "stop requested; letting the running attempt finish");
                    break;
                }
                () = self.serve_drift() => {}
            }
        }
        // Phase 2: drain.
        let drain = self.ticker.sleep(self.settings.drain());
        tokio::pin!(drain);
        loop {
            tokio::select! {
                result = &mut work => return Ran::from(result),
                () = &mut cancel_watch => {}
                () = self.serve_drift() => {}
                () = &mut drain => {
                    tracing::error!(
                        attempt = %attempt.attempt,
                        stage_run = %attempt.stage_run,
                        "the drain budget ended before the attempt did; its lease is left to expire and the sweeper will recover it"
                    );
                    return Ran::Abandoned;
                }
            }
        }
    }

    async fn idle(&self) {
        tokio::select! {
            () = self.ticker.sleep(self.settings.poll_interval()) => {}
            () = self.shutdown.raised() => {}
        }
    }
}

/// A wait of the loop's ticker.
type Wait<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// True when `wait` has ended. It looks once and does not wait. The caller replaces a wait that
/// has ended before it asks again.
async fn has_ended(wait: &mut Wait<'_>) -> bool {
    tokio::select! {
        biased;
        () = wait.as_mut() => true,
        () = std::future::ready(()) => false,
    }
}

/// Notes the tenant of a job while an attempt runs, and forgets it on every way out.
struct ActiveGuard {
    jobs: Arc<ActiveJobs>,
    job: factory_domain::ids::JobId,
    attempt: factory_domain::ids::AttemptId,
}

impl ActiveGuard {
    fn enter(jobs: Arc<ActiveJobs>, attempt: &ClaimedAttempt) -> Self {
        jobs.enter(attempt.job, attempt.tenant);
        jobs.enter_attempt(attempt.attempt, attempt.tenant);
        Self {
            jobs,
            job: attempt.job,
            attempt: attempt.attempt,
        }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.jobs.leave(self.job);
        self.jobs.leave_attempt(self.attempt);
    }
}

enum Ran {
    Done(AttemptOutcome),
    Abandoned,
    Error(EngineError),
}

impl From<Result<AttemptOutcome, EngineError>> for Ran {
    fn from(result: Result<AttemptOutcome, EngineError>) -> Self {
        match result {
            Ok(outcome) => Self::Done(outcome),
            Err(error) => Self::Error(error),
        }
    }
}

/// An error the loop rides out: the store was busy or a race was lost.
///
/// Of the others, an error about this process (`EngineError::is_about_the_process`: the
/// configuration, a store that is broken) ends the loop, because a worker that keeps going after
/// such a defect hides it. An error about one job does not: it is logged at the error level,
/// counted in [`LoopSummary`], the attempt is failed, and the other jobs run. Ending the loop for
/// it stopped every tenant, and the same job was the first thing the next worker met.
fn is_transient(error: &EngineError) -> bool {
    error.is_retryable()
        || matches!(
            error,
            EngineError::Conflict | EngineError::LeaseFenced | EngineError::NotFound
        )
}

/// The process exit code for a loop that ended: 0 for a clean stop, 1 for an engine error, and 4
/// when an attempt had to be abandoned.
#[must_use]
pub fn exit_code(summary: &LoopSummary) -> u8 {
    if !summary.abandoned.is_empty() {
        4
    } else if summary.failure.is_some() {
        1
    } else {
        0
    }
}
