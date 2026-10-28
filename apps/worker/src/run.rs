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
//!    or whose teardown ran out of time. Another worker's lapsed lease is recovered here.
//! 2. `Engine::claim_next`, which takes at most one attempt (the loop sets `claim_batch` to 1, so
//!    it never holds a lease it is not running).
//! 3. Each started attempt runs inside a `factory.job` span with `Engine::run_attempt`.
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

use std::sync::Arc;
use std::time::Duration;

use factory_ports::store::WorkerId;
use factory_workflow::engine::{AttemptOutcome, Engine, EngineError};
use factory_workflow::scheduler::{ClaimedAttempt, Ticker};
use tracing::Instrument;

use crate::config::LoopConfig;
use crate::system::Shutdown;
use crate::telemetry::job_stretch;

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
    /// Attempts the loop stopped waiting for at the end of the drain budget.
    pub abandoned: Vec<ClaimedAttempt>,
    /// True when the loop ended because of the stop request or an observer, not an error.
    pub stopped_cleanly: bool,
    /// The error that ended the loop, when one did. Plain text, no secret.
    pub failure: Option<String>,
}

/// The loop.
pub struct WorkerLoop {
    engine: Engine,
    ticker: Arc<dyn Ticker>,
    worker: WorkerId,
    settings: LoopConfig,
    shutdown: Shutdown,
    observer: Option<Arc<dyn Observer>>,
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
        Self {
            engine,
            ticker,
            worker,
            settings,
            shutdown,
            observer: None,
        }
    }

    /// Adds an observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
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
        let mut since_sweep = Duration::ZERO;
        tracing::info!(worker = self.worker.as_str(), "worker loop started");
        loop {
            if self.shutdown.is_raised() {
                summary.stopped_cleanly = true;
                break;
            }
            if sweep_due {
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
                since_sweep = Duration::ZERO;
            }
            let claimed = match self.engine.claim_next(&self.worker).await {
                Ok(claimed) => claimed,
                Err(error) if is_transient(&error) => {
                    tracing::warn!(%error, "the claim failed and will be tried again");
                    self.idle(&mut since_sweep, &mut sweep_due).await;
                    continue;
                }
                Err(error) => return self.fail(summary, &error),
            };
            if claimed.started.is_empty() {
                self.idle(&mut since_sweep, &mut sweep_due).await;
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
                        } else {
                            return self.fail(summary, &error);
                        }
                    }
                }
            }
        }
        tracing::info!(attempts = summary.attempts_run, "worker loop stopped");
        summary
    }

    fn fail(&self, mut summary: LoopSummary, error: &EngineError) -> LoopSummary {
        tracing::error!(%error, detail = ?error, "worker loop ended with an error");
        summary.failure = Some(format!("{error} ({error:?})"));
        summary
    }

    /// Runs one attempt inside a job span, honouring the drain budget on a stop request.
    async fn run_one(&self, attempt: &ClaimedAttempt) -> Ran {
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
        // Phase 1: no stop request yet. The attempt runs; a stop request starts the drain clock.
        let stop = self.shutdown.raised();
        tokio::pin!(stop);
        tokio::select! {
            result = &mut work => return Ran::from(result),
            () = &mut stop => {
                tracing::info!(attempt = %attempt.attempt, drain_s = self.settings.drain_s, "stop requested; letting the running attempt finish");
            }
        }
        // Phase 2: drain.
        tokio::select! {
            result = &mut work => Ran::from(result),
            () = self.ticker.sleep(self.settings.drain()) => {
                tracing::error!(
                    attempt = %attempt.attempt,
                    stage_run = %attempt.stage_run,
                    "the drain budget ended before the attempt did; its lease is left to expire and the sweeper will recover it"
                );
                Ran::Abandoned
            }
        }
    }

    async fn idle(&self, since_sweep: &mut Duration, sweep_due: &mut bool) {
        let wait = self.settings.poll_interval();
        tokio::select! {
            () = self.ticker.sleep(wait) => {}
            () = self.shutdown.raised() => {}
        }
        *since_sweep += wait;
        if *since_sweep >= self.settings.sweep_interval() {
            *sweep_due = true;
        }
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

/// An error the loop rides out: the store was busy or a race was lost. Anything else ends the
/// loop, because a worker that keeps going after a defect hides it.
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
