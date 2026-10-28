//! Running a claimed attempt and recording its result.
//!
//! [`Engine::run_attempt`] is what a worker calls after [`Engine::claim_next`]. It resolves the
//! stage contract, runs the stage handler next to the lease heartbeat, and then records what
//! happened in one transaction:
//!
//! * a valid output is stored by its content hash and the attempt succeeds (`A04`), then the stage
//!   run moves to `GATING` (`S04`);
//! * a failure is classified, the attempt fails (`A05`, or `A02` before the sandbox was up, or
//!   `A06` for a timeout), and the stage run retries, asks a person or fails (see
//!   [`failure`](super::failure));
//! * a lost lease writes nothing at all. The sweeper ends the attempt, and every write the worker
//!   would make is refused by the epoch check (INV-05).
//!
//! The handler reports and the engine decides. Nothing the handler returns is trusted: the output
//! is validated against its schema, an undeclared document is refused, and a required deliverable
//! that is missing makes the output invalid.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use factory_domain::contracts::stage_contract::Placement;
use factory_domain::contracts::{ArtifactRef, StageContract};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{
    DeadlineFacts, EnvironmentCause, EpochFacts, GuardFacts, OutputFacts, SandboxProvisionFacts,
};
use factory_domain::machines::retry::AttemptDisposition;
use factory_domain::scope::TenantScope;
use factory_domain::state::{AttemptEvent, AttemptStatus, Guard, Status};
use factory_domain::values::Slug;
use factory_ports::agent::{
    CostMicroUsd, IssuedJobToken, JobTokenId, JobTokenRef, JobTokenRequest,
};
use factory_ports::store::{AttemptEnd, AuditActor, Tx};
use serde_json::{Value, json};
use tracing::Instrument;

use super::Engine;
use super::agent_span::ObservedRuntime;
use super::cancel::AttemptCancel;
use super::error::EngineError;
use super::failure::HumanReason;
use super::gate::Judged;
use super::payload;
use super::progress::{Board, clear, upstream_runs};
use super::record::{Cx, Step, index_entry};
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::framework::{Expectation, GateDecision, check_evidence, resolve};
use crate::handlers::{
    GateContext, NamedArtifact, Notes, OutputDocument, SandboxReady, StageContext, StageError,
    StageHandler, StageOutput, UpstreamRun,
};
use crate::scheduler::{ClaimedAttempt, Pulse};

/// How a run of an attempt ended, for the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The output was valid and stored, and the stage run moved on.
    Succeeded,
    /// The agent asked for a person. The stage run waits for an answer.
    NeedsHuman,
    /// The attempt failed. The stage run retries, waits for a person or fails, as `then` says.
    Failed {
        /// How the attempt failed.
        class: FailureClass,
        /// What happened to the stage run.
        then: AttemptDisposition,
    },
    /// The lease was lost. Nothing was written, and the sweeper owns the attempt.
    LeaseLost,
    /// The engine cancelled the attempt (the job is cancelling, or the stage run was replaced).
    Cancelled,
}

/// Everything the handler needs, read before the handler runs.
struct Prepared {
    contract: StageContract,
    need: Option<factory_ports::agent::RoutingNeed>,
    upstream: Vec<UpstreamRun>,
    human_inputs: Vec<ArtifactRef>,
    handler: std::sync::Arc<dyn StageHandler>,
    identity: crate::handlers::RunIdentity,
}

/// What the work before the result transaction produced.
enum Produced {
    /// The agent asked for a person. The request is stored.
    AgentAsked {
        request: NamedArtifact,
        output: StageOutput,
    },
    /// The output is valid and stored, and the gate collected its evidence.
    Judged {
        outputs: Vec<NamedArtifact>,
        /// The document that lists every output by name and hash. Its hash is the attempt's
        /// output (`AttemptEnd::output`).
        manifest: ArtifactRef,
        judged: Box<Judged>,
        output: StageOutput,
    },
}

/// Why the work before the result transaction did not produce a result.
enum PipelineError {
    /// The stage handler failed, or the output was invalid.
    Stage(StageError),
    /// The engine could not store a document. The attempt is left to its lease.
    Engine(EngineError),
}

impl From<StageError> for PipelineError {
    fn from(error: StageError) -> Self {
        Self::Stage(error)
    }
}

impl From<EngineError> for PipelineError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

/// What watching the handler found.
#[derive(Default)]
struct Watched {
    result: Option<Result<Produced, PipelineError>>,
    lease_lost: bool,
    deadline_passed: bool,
    cancel_requested: bool,
}

impl Engine {
    /// Runs the attempt a worker holds, and records the result.
    ///
    /// The heartbeat of the lease and the teardown grace period wait through the engine's
    /// [`Ticker`](crate::scheduler::Ticker), so the composition root decides how the wait is made.
    /// The lease itself is judged by the database clock, not by these waits.
    ///
    /// # Errors
    /// The store errors. A handler failure is an [`AttemptOutcome`], not an error.
    pub async fn run_attempt(
        &self,
        claimed: &ClaimedAttempt,
    ) -> Result<AttemptOutcome, EngineError> {
        // The stage run outlives a process, and an attempt is one stretch of work on it, so each
        // attempt opens a stage run span of its own under the job stretch. Two attempts of one
        // stage run give two spans with the same `factory.stage_run_id`, and a search for that
        // identifier finds them all. The attempt hangs from this span, and the gate from the
        // attempt.
        let stage_run = tracing::info_span!(
            "factory.stage_run",
            factory.correlation_id = %claimed.correlation,
            factory.job_id = %claimed.job,
            factory.stage_run_id = %claimed.stage_run,
            factory.stage_kind = claimed.kind.as_str(),
            factory.outcome = tracing::field::Empty,
        );
        let span = tracing::info_span!(
            parent: &stage_run,
            "factory.attempt",
            factory.correlation_id = %claimed.correlation,
            factory.job_id = %claimed.job,
            factory.stage_run_id = %claimed.stage_run,
            factory.attempt_id = %claimed.attempt,
            factory.attempt_number = i64::from(claimed.attempt_number),
            factory.stage_kind = claimed.kind.as_str(),
            factory.outcome = tracing::field::Empty,
            factory.error_class = tracing::field::Empty,
        );
        let outcome = self
            .run_attempt_inner(claimed)
            .instrument(span.clone())
            .await?;
        span.record("factory.outcome", outcome_label(&outcome));
        if let AttemptOutcome::Failed { class, .. } = &outcome {
            // The wire spelling of the failure class, such as `TOOL_ERROR`: a closed set.
            span.record("factory.error_class", class.as_str());
        }
        if let Some(ended) = self.stage_run_outcome(claimed, &outcome).await {
            stage_run.record("factory.outcome", ended);
        }
        Ok(outcome)
    }

    /// The outcome the stage run ended in, when this attempt ended it: `passed`, `failed`,
    /// `blocked` or `rework_requested`. `None` when the run goes on (a retry, a question to a
    /// person) or when it cannot be read; telemetry never fails an attempt.
    ///
    /// Only a result that was committed can have ended the run, so a lost lease and a cancel are
    /// not read. The status is read from the store after the commit, so the span says what the
    /// run holds and not what the branch of the code expected.
    async fn stage_run_outcome(
        &self,
        claimed: &ClaimedAttempt,
        outcome: &AttemptOutcome,
    ) -> Option<&'static str> {
        let may_have_ended = matches!(
            outcome,
            AttemptOutcome::Succeeded
                | AttemptOutcome::Failed {
                    then: AttemptDisposition::Fail | AttemptDisposition::Block(_),
                    ..
                }
        );
        if !may_have_ended {
            return None;
        }
        let mut tx = self.tenant_tx(claimed.tenant).await.ok()?;
        let run = tx.get_stage_run(claimed.stage_run).await.ok();
        let _ = tx.rollback().await;
        run.and_then(|run| super::ended::outcome_of(run.value.status))
    }

    async fn run_attempt_inner(
        &self,
        claimed: &ClaimedAttempt,
    ) -> Result<AttemptOutcome, EngineError> {
        let prepared = self.prepare(claimed).await?;
        let notes = Notes::default();
        let token = match self.issue_token(claimed, &prepared).await? {
            Ok(token) => token,
            Err(class) => {
                return self.commit_failure(claimed, class, &notes).await;
            }
        };
        let reference = token.as_ref().map(|issued| JobTokenRef { id: issued.id });
        let outcome = self
            .run_prepared(claimed, &prepared, reference, &notes)
            .await;
        // The token ends with the attempt, whatever happened to it. Revoking is idempotent.
        if let Some(issued) = &token {
            self.end_token(claimed, issued.id, &notes).await?;
        }
        outcome
    }

    async fn run_prepared(
        &self,
        claimed: &ClaimedAttempt,
        prepared: &Prepared,
        job_token: Option<JobTokenRef>,
        notes: &Notes,
    ) -> Result<AttemptOutcome, EngineError> {
        let needs_sandbox = matches!(
            prepared.contract.capabilities.placement,
            Some(Placement::Sandbox | Placement::HostToolBridge)
        );
        if !needs_sandbox {
            // No sandbox to wait for: the engine's own preconditions are the whole of the guard.
            let ready = SandboxReady {
                posture_verified: true,
                tool_grants_recorded: true,
                probe_satisfies_stage: true,
            };
            if let Err(outcome) = lease_outcome(self.mark_running(claimed, ready).await)? {
                return Ok(outcome);
            }
        }

        let cancel = AttemptCancel::new();
        let notes = notes.clone();
        // The handler runs its agents through this wrapper, so each run is a `factory.agent` span.
        let observed =
            ObservedRuntime::new(self.deps.runtime.as_ref(), claimed.correlation, claimed.job);
        let mut ctx = StageContext::new(
            prepared.identity,
            claimed.attempt,
            claimed.attempt_number,
            claimed.epoch,
            self.config.mode,
            &prepared.contract,
            self.stage_ports(&observed),
            &cancel,
            job_token,
            &prepared.human_inputs,
            &prepared.upstream,
        )
        .with_notes(notes.clone());
        let watched = self
            .watch(
                claimed,
                &cancel,
                &notes,
                self.produce(claimed, prepared, &mut ctx),
            )
            .await;
        drop(ctx);
        // What the model cost is read once the handler has stopped, so the events of this attempt
        // can carry it.
        if let Some(token) = job_token {
            let cost = self.token_cost(token.id).await;
            notes.set_cost(cost);
            // Money was spent whether or not the attempt is later recorded, so the spend is
            // counted here and not with the result: an attempt that lost its lease still cost it.
            self.record_spend(claimed, prepared, cost);
        }

        if watched.lease_lost {
            return Ok(AttemptOutcome::LeaseLost);
        }
        if watched.deadline_passed {
            return self
                .commit_failure(claimed, FailureClass::TimedOut, &notes)
                .await;
        }
        if watched.cancel_requested {
            self.teardown_complete(claimed).await?;
            return Ok(AttemptOutcome::Cancelled);
        }
        // The handler may have finished before the first heartbeat noticed that its sandbox was
        // ready, so the attempt becomes `RUNNING` no later than its result.
        if needs_sandbox && let Some(ready) = notes.sandbox_ready() {
            match self.mark_running(claimed, ready).await {
                Ok(_) => {}
                Err(EngineError::GuardUnmet(_)) => {
                    return self
                        .commit_failure(claimed, FailureClass::SandboxError, &notes)
                        .await;
                }
                Err(other) => {
                    if let Err(outcome) = lease_outcome::<bool>(Err(other))? {
                        return Ok(outcome);
                    }
                }
            }
        }
        // A stage that needed a sandbox and never said it was ready cannot have run its work
        // inside one. It fails closed instead of reporting a success it cannot back.
        if needs_sandbox && notes.sandbox_ready().is_none() && matches!(watched.result, Some(Ok(_)))
        {
            return self
                .commit_failure(claimed, FailureClass::SandboxError, &notes)
                .await;
        }
        match watched.result {
            Some(Ok(Produced::AgentAsked { request, output })) => {
                self.commit_asked(claimed, request, &output, &notes).await
            }
            Some(Ok(Produced::Judged {
                outputs,
                manifest,
                judged,
                output,
            })) => {
                self.commit_judged(
                    claimed,
                    &prepared.contract,
                    outputs,
                    &manifest,
                    &judged,
                    &output,
                    &notes,
                )
                .await
            }
            Some(Err(PipelineError::Engine(error))) => Err(error),
            Some(Err(PipelineError::Stage(StageError::Cancelled))) => {
                self.teardown_complete(claimed).await?;
                Ok(AttemptOutcome::Cancelled)
            }
            Some(Err(PipelineError::Stage(error))) => {
                // A stage that cannot run because its environment is missing or unsafe carries
                // the cause, and the stage run is blocked (`S21`) instead of retried.
                let class = error.failure_class().unwrap_or(FailureClass::Internal);
                self.commit_failure_for(claimed, class, error.environment(), &notes)
                    .await
            }
            None => {
                self.commit_failure(claimed, FailureClass::Internal, &notes)
                    .await
            }
        }
    }

    /// Reads what the handler needs, in a read-only transaction.
    async fn prepare(&self, claimed: &ClaimedAttempt) -> Result<Prepared, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let job = tx.get_job(claimed.job).await?;
        let timeline = Timeline::load(&mut *tx, claimed.job).await?;
        let board = Board::of(&timeline);
        tx.rollback().await?;
        let run = board.run(claimed.stage_run).ok_or(EngineError::NotFound)?;
        let record = timeline
            .run(claimed.stage_run)
            .ok_or(EngineError::NotFound)?;
        let handler = self
            .handlers
            .get(run.value.kind)
            .ok_or(EngineError::NoHandler(run.value.kind))?
            .clone();
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        let upstream = upstream_runs(&timeline, &board);
        let ccx = self.contract_context(&cx, &run.value, record, &upstream);
        let contract = handler
            .contract(&ccx)
            .map_err(|_| EngineError::Corrupt("the stage contract no longer resolves"))?;
        let identity = Self::identity(&cx, &run.value);
        let need = handler.routing_need(&ccx);
        self.ensure_contract_stored(claimed.tenant, &run.value, &contract)
            .await?;
        Ok(Prepared {
            contract,
            need,
            upstream,
            human_inputs: record.human_inputs.clone(),
            handler,
            identity,
        })
    }

    /// Stores the contract the stage run recorded at `S01` when the artifact store does not hold it.
    ///
    /// The bytes of the contract are written after the commit that recorded its hash
    /// ([`Cx::defer_blob`]), so a process that stopped in between, or a write that failed, leaves
    /// a record that names a blob not stored yet. An attempt does not start until the blob is
    /// there. The contract is resolved again, and it is stored only when it is the one recorded:
    /// a contract that now resolves to another document is not the one the record names, and the
    /// write would not repair it. Storing is idempotent by hash.
    ///
    /// # Errors
    /// [`EngineError::Artifacts`] when the artifact store cannot be asked or cannot store the blob.
    async fn ensure_contract_stored(
        &self,
        tenant: factory_domain::ids::TenantId,
        run: &factory_ports::store::StageRun,
        contract: &StageContract,
    ) -> Result<(), EngineError> {
        let Some(recorded) = &run.contract_sha256 else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(contract)
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        if factory_domain::values::Sha256Digest::of(&bytes) != *recorded {
            return Ok(());
        }
        let media_type = factory_domain::values::MediaType::parse("application/json")?;
        let reference = ArtifactRef {
            sha256: recorded.clone(),
            media_type: media_type.clone(),
            size_bytes: None,
        };
        let stored = self
            .deps
            .artifacts
            .exists(&TenantScope::new(tenant), &reference)
            .await
            .map_err(|error| EngineError::Artifacts(error.to_string()))?;
        if !stored {
            self.deps
                .artifacts
                .put(bytes, media_type)
                .await
                .map_err(|error| EngineError::Artifacts(error.to_string()))?;
        }
        Ok(())
    }

    /// Polls the handler and renews the lease while it runs. A heartbeat that finds the lease
    /// lost, the deadline passed or a cancel requested trips the signal. A handler that does not
    /// stop within the teardown grace period is abandoned.
    async fn watch<F>(
        &self,
        claimed: &ClaimedAttempt,
        cancel: &AttemptCancel,
        notes: &Notes,
        work: F,
    ) -> Watched
    where
        F: Future<Output = Result<Produced, PipelineError>>,
    {
        let mut work = std::pin::pin!(work);
        let mut watched = Watched::default();
        let mut grace: Option<Pin<Box<dyn Future<Output = ()> + Send + '_>>> = None;
        loop {
            tokio::select! {
                outcome = &mut work => {
                    watched.result = Some(outcome);
                    break;
                }
                () = self.deps.ticker.sleep(self.config.heartbeat_interval) => {
                    match self.heartbeat(claimed).await {
                        Ok(Pulse::Alive) => {
                            if let Some(ready) = notes.sandbox_ready() {
                                // Best effort: the result path applies it again if this fails.
                                let _ = self.mark_running(claimed, ready).await;
                            }
                        }
                        Ok(Pulse::CancelRequested) => {
                            watched.cancel_requested = true;
                            cancel.trip();
                            grace.get_or_insert_with(|| self.teardown_timer());
                        }
                        Ok(Pulse::DeadlinePassed) => {
                            watched.deadline_passed = true;
                            cancel.trip();
                            grace.get_or_insert_with(|| self.teardown_timer());
                        }
                        Err(EngineError::LeaseFenced | EngineError::NotFound) => {
                            // The lease is gone. Anything the handler returns now is refused, so
                            // it is dropped here.
                            watched.lease_lost = true;
                            cancel.trip();
                            break;
                        }
                        // A passing fault of the store: the next beat tries again, and the lease
                        // lapses if the outage lasts.
                        Err(_) => {}
                    }
                }
                () = async {
                    match grace.as_mut() {
                        Some(timer) => timer.as_mut().await,
                        None => std::future::pending().await,
                    }
                } => {
                    break;
                }
            }
        }
        watched
    }

    /// Issues the job token for a stage that runs an agent, bound to this tenant, job and stage,
    /// with the stage's cost ceiling and only the model the router chose. A stage that runs no
    /// agent gets none. The inner error is the failure class when the token cannot be issued: the
    /// stage fails closed and never runs without a token it needs.
    async fn issue_token(
        &self,
        claimed: &ClaimedAttempt,
        prepared: &Prepared,
    ) -> Result<Result<Option<IssuedJobToken>, FailureClass>, EngineError> {
        let Some(need) = &prepared.need else {
            return Ok(Ok(None));
        };
        let Ok(decision) = self.deps.router.route(need) else {
            return Ok(Err(FailureClass::PolicyDenied));
        };
        let micro = (prepared.contract.budget.max_cost_usd.as_f64() * 1_000_000.0).round();
        let ceiling = CostMicroUsd(if micro.is_finite() && micro > 0.0 {
            micro as u64
        } else {
            0
        });
        let attempt_seconds = u64::try_from(
            prepared
                .contract
                .timeout_and_retries
                .attempt_timeout_seconds
                .get(),
        )
        .unwrap_or(u64::MAX);
        let request = JobTokenRequest {
            tenant: claimed.tenant,
            job: claimed.job,
            stage: claimed.kind,
            cost_ceiling: ceiling,
            allowed_models: vec![decision.model],
            ttl: Duration::from_secs(attempt_seconds.saturating_add(300)),
        };
        match self.deps.broker.issue(request).await {
            Ok(token) => {
                self.audit_job(
                    claimed,
                    AuditAction::new(
                        AuditKind::CredentialMintedAndRevoked,
                        AuditDecision::Granted,
                    ),
                )
                .await?;
                Ok(Ok(Some(token)))
            }
            Err(factory_ports::agent::BrokerError::Unavailable) => {
                Ok(Err(FailureClass::ProviderError))
            }
            Err(_) => Ok(Err(FailureClass::Internal)),
        }
    }

    /// Adds what an attempt spent to `factory_spend_usd_total`, in dollars, by provider and stage.
    ///
    /// Each attempt has a token of its own, read once when the handler has stopped, so the whole
    /// reading is this attempt's spend and none of it is counted twice. The provider label is the
    /// name of the runtime the router chose for the stage, because the broker does not report a
    /// provider; the router is a pure function of the stage's need, so asking it again gives the
    /// answer the token was issued under. The label comes from the routing policy and the
    /// registered adapters, a closed set, and never from anything a tool printed. Nothing is
    /// recorded for a stage that spent nothing, or whose route cannot be found.
    fn record_spend(&self, claimed: &ClaimedAttempt, prepared: &Prepared, micro_usd: u64) {
        if micro_usd == 0 {
            return;
        }
        let Some(decision) = prepared
            .need
            .as_ref()
            .and_then(|need| self.deps.router.route(need).ok())
        else {
            return;
        };
        tracing::info!(
            monotonic_counter.factory_spend_usd_total = micro_usd as f64 / 1_000_000.0,
            provider = decision.model.runtime.as_str(),
            stage = claimed.kind.as_str()
        );
    }

    /// What the token has spent, in millionths of a US dollar. A broker that cannot be reached
    /// reads as no spend, and the broker's own ceiling still holds.
    async fn token_cost(&self, token: JobTokenId) -> u64 {
        match self.deps.broker.usage(&token).await {
            Ok(usage) => usage.usage.cost.0,
            Err(_) => 0,
        }
    }

    /// Revokes the token, and records the revocation and, when a threshold was crossed, the
    /// threshold. The token cannot spend after this.
    async fn end_token(
        &self,
        claimed: &ClaimedAttempt,
        token: JobTokenId,
        notes: &Notes,
    ) -> Result<(), EngineError> {
        let ceiling = match self.deps.broker.usage(&token).await {
            Ok(usage) => usage.ceiling.0,
            Err(_) => 0,
        };
        // A broker that cannot be reached cannot revoke, and the token's own expiry ends it.
        let _ = self.deps.broker.revoke(&token).await;
        let cost = notes.cost();
        let warn = self.config.budget_warn_percent;
        let crossed = ceiling > 0 && cost.saturating_mul(100) >= ceiling.saturating_mul(warn);
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        cx.audit_engine(
            &mut *tx,
            AuditAction::new(AuditKind::CredentialMintedAndRevoked, AuditDecision::Ended),
        )
        .await?;
        let timeline = Timeline::load(&mut *tx, claimed.job).await?;
        let job_crossed = timeline.spent_micro_usd.saturating_mul(100)
            >= self.config.job_budget_micro_usd.saturating_mul(warn);
        if crossed || job_crossed {
            cx.audit_engine(
                &mut *tx,
                AuditAction::new(AuditKind::BudgetThresholdCrossed, AuditDecision::Noted),
            )
            .await?;
        }
        cx.commit(tx).await?;
        Ok(())
    }

    /// Records one audit event of the engine for the job of a claimed attempt.
    async fn audit_job(
        &self,
        claimed: &ClaimedAttempt,
        action: AuditAction,
    ) -> Result<(), EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        cx.audit_engine(&mut *tx, action).await?;
        cx.commit(tx).await?;
        Ok(())
    }

    /// The wait for a cancelled handler to stop, asked of the ticker. The store's own teardown
    /// deadline (`A10`) is what ends a teardown that never finishes; this wait only stops the
    /// worker from holding on to a handler that ignores the cancel.
    fn teardown_timer(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.deps.ticker.sleep(self.config.teardown_grace)
    }

    /// Moves the attempt from `STARTING` to `RUNNING` (`A01`) once the sandbox is ready. Does
    /// nothing, and returns `false`, when the attempt is already past `STARTING`.
    ///
    /// # Errors
    /// [`EngineError::GuardUnmet`] when the handler reported that its sandbox is not ready.
    async fn mark_running(
        &self,
        claimed: &ClaimedAttempt,
        ready: SandboxReady,
    ) -> Result<bool, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let attempt = tx.get_attempt(claimed.attempt).await?;
        if attempt.value.status != AttemptStatus::Starting {
            return Ok(false);
        }
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        let facts = GuardFacts::SandboxProvision(SandboxProvisionFacts {
            posture_verified: ready.posture_verified,
            tool_grants_recorded: ready.tool_grants_recorded,
            probe_satisfies_stage: ready.probe_satisfies_stage,
            epoch: EpochFacts {
                sent_epoch: claimed.epoch.get(),
                stored_epoch: attempt.value.epoch.get(),
            },
        });
        let cleared = clear(Guard::SandboxProvisioned, &facts)?;
        let payload = payload::attempt_event(
            claimed.kind,
            claimed.stage_run,
            claimed.attempt_number,
            None,
        );
        cx.move_attempt(
            &mut *tx,
            &attempt,
            claimed.epoch,
            Step::new(AttemptEvent::SandboxReady, cleared).payload(payload),
            AttemptEnd::default(),
        )
        .await?;
        cx.commit(tx).await?;
        Ok(true)
    }

    // ---- producing the output and its gate evidence --------------------------------------------

    /// Everything that happens before the result transaction: the handler runs, its output is
    /// checked and stored, and the gate collects its evidence. All of it can take minutes, so no
    /// transaction is open, and the lease heartbeat runs beside it.
    async fn produce(
        &self,
        claimed: &ClaimedAttempt,
        prepared: &Prepared,
        ctx: &mut StageContext<'_>,
    ) -> Result<Produced, PipelineError> {
        let cancel = ctx.cancel;
        let output = prepared.handler.execute(ctx).await?;
        if let Some(request) = &output.needs_human {
            let document = json!({ "needs_human": request.reason.as_str() });
            let stored = self
                .store_document("needs-human-request", "application/json", &document)
                .await?;
            return Ok(Produced::AgentAsked {
                request: stored,
                output,
            });
        }
        let documents = self
            .check_output(claimed, &prepared.contract, &output)
            .await
            .map_err(|()| StageError::InvalidOutput)?;
        let mut outputs = Vec::with_capacity(documents.len() + output.artifacts.len());
        for (name, media_type, value) in &documents {
            outputs.push(self.store_document(name, media_type, value).await?);
        }
        outputs.extend(output.artifacts.iter().cloned());
        // The attempt's output is one document that names every output, so the record of the
        // attempt points at exactly what it produced.
        let listed: Vec<Value> = outputs
            .iter()
            .map(|named| {
                json!({
                    "name": named.name.as_str(),
                    "sha256": named.artifact.sha256.as_str(),
                    "media_type": named.artifact.media_type.as_str(),
                })
            })
            .collect();
        let manifest = self
            .store_document(
                "attempt-output",
                "application/json",
                &json!({ "outputs": listed }),
            )
            .await?
            .artifact;
        // The gate reads these documents through the artifact store, which answers only for a hash
        // the tenant has indexed. The result transaction indexes them too, but it comes after the
        // gate, so they are indexed here first (idempotent by hash). Without this a gate gets
        // `NotFound` for a document the engine itself stored.
        let produced: Vec<ArtifactRef> = outputs
            .iter()
            .map(|named| named.artifact.clone())
            .chain(std::iter::once(manifest.clone()))
            .collect();
        self.index_declared(claimed, &produced).await?;

        let gate = GateContext {
            identity: prepared.identity,
            attempt: claimed.attempt,
            mode: self.config.mode,
            contract: &prepared.contract,
            // The gate gets the same ports as `execute`, so an agent that judges the output is
            // also a `factory.agent` span.
            ports: ctx.ports,
            cancel,
            outputs: &outputs,
            human_inputs: &prepared.human_inputs,
            upstream: &prepared.upstream,
        };
        // The gate is a span of its own, so its time is visible apart from the stage's. The
        // outcome is set once the evidence has been read.
        let span = tracing::info_span!(
            "factory.gate",
            factory.correlation_id = %claimed.correlation,
            factory.job_id = %claimed.job,
            factory.stage_run_id = %claimed.stage_run,
            factory.gate_id = super::gate::gate_label(&prepared.contract),
            factory.outcome = tracing::field::Empty,
        );
        let evaluated = prepared
            .handler
            .evaluate(&gate)
            .instrument(span.clone())
            .await;
        let (decision, could_not_run) = match evaluated {
            Ok(decision) => (decision, false),
            // The gate could not run. That blocks the stage run, and it is not a failure of the
            // attempt: the output itself was valid.
            Err(StageError::Blocked(_)) => (GateDecision::default(), true),
            Err(other) => return Err(other.into()),
        };
        let expectation = Expectation {
            job: claimed.job,
            stage_run: claimed.stage_run,
            attempt: claimed.attempt,
            mode: self.config.mode,
        };
        let problem = check_evidence(&decision, &expectation).err();
        let seen = if could_not_run || problem.is_some() {
            "blocked"
        } else {
            super::gate::outcome_label(&resolve(&prepared.contract, &decision))
        };
        span.record("factory.outcome", seen);
        let mut reports = Vec::new();
        let mut review = None;
        if problem.is_none() && !could_not_run {
            for report in &decision.reports {
                reports.push(self.store_json(report, "application/json").await?);
            }
            if let Some(verdict) = &decision.review {
                review = Some(self.store_json(verdict, "application/json").await?);
            }
        }
        Ok(Produced::Judged {
            outputs,
            manifest,
            judged: Box::new(Judged {
                decision,
                reports,
                review,
                problem,
                could_not_run,
                attempt: claimed.attempt,
            }),
            output,
        })
    }

    /// Stores any serializable document by its content hash.
    async fn store_json<T: serde::Serialize>(
        &self,
        value: &T,
        media_type: &str,
    ) -> Result<ArtifactRef, EngineError> {
        let bytes =
            serde_json::to_vec(value).map_err(|error| EngineError::Invalid(error.to_string()))?;
        self.deps
            .artifacts
            .put(bytes, factory_domain::values::MediaType::parse(media_type)?)
            .await
            .map_err(|error| EngineError::Artifacts(error.to_string()))
    }

    /// Checks an output against the contract, before anything is stored. Returns the documents
    /// to store, or `Err(())` when the output is invalid: a document the contract does not
    /// declare, a document that breaks its schema, an artifact that is not stored, or a required
    /// deliverable that is missing. The reasons are not returned: an agent's output never goes
    /// back into a message.
    async fn check_output(
        &self,
        claimed: &ClaimedAttempt,
        contract: &StageContract,
        output: &StageOutput,
    ) -> Result<Vec<(String, String, Value)>, ()> {
        let tenant = claimed.tenant;
        let declared = |name: &Slug| contract.deliverables.iter().any(|d| &d.name == name);
        let mut documents = Vec::with_capacity(output.documents.len());
        for OutputDocument {
            name,
            contract: schema,
            media_type,
            value,
        } in &output.documents
        {
            if !declared(name) {
                return Err(());
            }
            if let Some((kind, version)) = schema
                && self
                    .deps
                    .validator
                    .validate_value(*kind, *version, value)
                    .is_err()
            {
                return Err(());
            }
            documents.push((
                name.as_str().to_owned(),
                media_type.as_str().to_owned(),
                value.clone(),
            ));
        }
        for artifact in &output.artifacts {
            if !declared(&artifact.name) {
                return Err(());
            }
            // The artifact store answers only for a hash the tenant has indexed, and a handler
            // stores a blob without indexing it. The tenant's row is written first, so that the
            // question "is the blob there" can be asked.
            if self
                .index_declared(claimed, std::slice::from_ref(&artifact.artifact))
                .await
                .is_err()
            {
                return Err(());
            }
            match self
                .deps
                .artifacts
                .exists(&TenantScope::new(tenant), &artifact.artifact)
                .await
            {
                Ok(true) => {}
                Ok(false) | Err(_) => return Err(()),
            }
        }
        let produced = |name: &Slug| {
            output.documents.iter().any(|d| &d.name == name)
                || output.artifacts.iter().any(|a| &a.name == name)
        };
        for deliverable in contract.deliverables.iter() {
            if deliverable.required && !produced(&deliverable.name) {
                return Err(());
            }
        }
        Ok(documents)
    }

    /// Records in the tenant's artifact index, in a short transaction of its own, that it holds
    /// artifacts a handler declared. Indexing is idempotent by hash.
    async fn index_declared(
        &self,
        claimed: &ClaimedAttempt,
        artifacts: &[ArtifactRef],
    ) -> Result<(), EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        for artifact in artifacts {
            tx.index_artifact(index_entry(artifact, claimed.job, claimed.stage_run)?)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Stores one document by its content hash, before the transaction opens.
    async fn store_document(
        &self,
        name: &str,
        media_type: &str,
        value: &Value,
    ) -> Result<NamedArtifact, EngineError> {
        let bytes =
            serde_json::to_vec(value).map_err(|error| EngineError::Invalid(error.to_string()))?;
        let media = factory_domain::values::MediaType::parse(media_type)?;
        let artifact = self
            .deps
            .artifacts
            .put(bytes, media)
            .await
            .map_err(|error| EngineError::Artifacts(error.to_string()))?;
        Ok(NamedArtifact {
            name: Slug::parse(name)?,
            artifact,
        })
    }

    /// The agent asked for a person: the attempt succeeds with the request as its output, and the
    /// stage run waits for an answer instead of going to its gate.
    async fn commit_asked(
        &self,
        claimed: &ClaimedAttempt,
        request: NamedArtifact,
        output: &StageOutput,
        notes: &Notes,
    ) -> Result<AttemptOutcome, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let attempt = tx.get_attempt(claimed.attempt).await?;
        if attempt.value.status.is_terminal() {
            return Ok(AttemptOutcome::LeaseLost);
        }
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id()).with_cost(notes.cost());
        let recorded = async {
            let facts = GuardFacts::Output(OutputFacts {
                attempt_succeeded: true,
                output_validates_against_outputs_schema: true,
                output_artifact_hash_stored: true,
            });
            let cleared = clear(Guard::OutputSchemaValid, &facts)?;
            self.index(
                &mut *tx,
                &cx,
                claimed,
                std::slice::from_ref(&request.artifact),
            )
            .await?;
            cx.move_attempt(
                &mut *tx,
                &attempt,
                claimed.epoch,
                Step::new(AttemptEvent::ReportSuccess, cleared).payload(payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    None,
                )),
                // The request for a person is this attempt's output.
                AttemptEnd {
                    output: Some(request.artifact.sha256.clone()),
                    ..AttemptEnd::default()
                },
            )
            .await?;
            self.escalate_running(
                &mut *tx,
                &cx,
                claimed.stage_run,
                HumanReason::AgentRequested,
            )
            .await?;
            self.record_handler_notes(&mut *tx, &cx, claimed, notes, output)
                .await
        }
        .await;
        Ok(match self.conclude(tx, &cx, recorded).await? {
            Ok(()) => AttemptOutcome::NeedsHuman,
            Err(outcome) => outcome,
        })
    }

    /// Records a valid output and the gate that judged it, in one transaction: the attempt
    /// succeeds (`A04`), the stage run goes through `GATING` and takes the move that the evidence
    /// calls for, and the ledger entries that justify the move are appended with it (INV-03).
    #[allow(clippy::too_many_arguments)]
    async fn commit_judged(
        &self,
        claimed: &ClaimedAttempt,
        contract: &StageContract,
        outputs: Vec<NamedArtifact>,
        manifest: &ArtifactRef,
        judged: &Judged,
        output: &StageOutput,
        notes: &Notes,
    ) -> Result<AttemptOutcome, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let attempt = tx.get_attempt(claimed.attempt).await?;
        if attempt.value.status.is_terminal() {
            // The sweeper or a cancel ended the attempt while the handler ran. Its result is
            // not recorded.
            return Ok(AttemptOutcome::LeaseLost);
        }
        let run = tx.get_stage_run(claimed.stage_run).await?;
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id()).with_cost(notes.cost());
        let recorded = async {
            let facts = GuardFacts::Output(OutputFacts {
                attempt_succeeded: true,
                output_validates_against_outputs_schema: true,
                output_artifact_hash_stored: !outputs.is_empty(),
            });
            let cleared = clear(Guard::OutputSchemaValid, &facts)?;
            let mut stored: Vec<ArtifactRef> =
                outputs.iter().map(|named| named.artifact.clone()).collect();
            stored.push(manifest.clone());
            stored.extend(judged.reports.iter().cloned());
            stored.extend(judged.review.iter().cloned());
            self.index(&mut *tx, &cx, claimed, &stored).await?;
            cx.move_attempt(
                &mut *tx,
                &attempt,
                claimed.epoch,
                Step::new(AttemptEvent::ReportSuccess, cleared).payload(payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    None,
                )),
                AttemptEnd {
                    output: Some(manifest.sha256.clone()),
                    ..AttemptEnd::default()
                },
            )
            .await?;
            self.gate_stage(
                &mut *tx,
                &cx,
                &run,
                contract,
                judged,
                &outputs,
                claimed.attempt_number,
            )
            .await?;
            self.record_handler_notes(&mut *tx, &cx, claimed, notes, output)
                .await
        }
        .await;
        Ok(match self.conclude(tx, &cx, recorded).await? {
            Ok(()) => AttemptOutcome::Succeeded,
            Err(outcome) => outcome,
        })
    }

    /// Records in the tenant's artifact index that it holds these artifacts.
    async fn index(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        claimed: &ClaimedAttempt,
        artifacts: &[ArtifactRef],
    ) -> Result<(), EngineError> {
        for artifact in artifacts {
            tx.index_artifact(index_entry(artifact, cx.job, claimed.stage_run)?)
                .await?;
        }
        Ok(())
    }

    /// Commits when `recorded` succeeded. A write that loses a race or is fenced means the
    /// attempt ended under the worker, and the outcome is a lost lease. Anything else is an
    /// error, and the transaction is dropped.
    async fn conclude<T>(
        &self,
        tx: Box<dyn Tx>,
        cx: &Cx<'_>,
        recorded: Result<T, EngineError>,
    ) -> Result<Result<T, AttemptOutcome>, EngineError> {
        match recorded {
            Ok(value) => match cx.commit(tx).await {
                Ok(()) => Ok(Ok(value)),
                Err(EngineError::Conflict | EngineError::LeaseFenced) => {
                    Ok(Err(AttemptOutcome::LeaseLost))
                }
                Err(other) => Err(other),
            },
            Err(EngineError::LeaseFenced | EngineError::Conflict) => {
                Ok(Err(AttemptOutcome::LeaseLost))
            }
            Err(other) => Err(other),
        }
    }

    // ---- recording a failure ----------------------------------------------------------------------

    /// Fails the attempt with `class` and lets the stage run decide what that means.
    async fn commit_failure(
        &self,
        claimed: &ClaimedAttempt,
        class: FailureClass,
        notes: &Notes,
    ) -> Result<AttemptOutcome, EngineError> {
        self.commit_failure_for(claimed, class, None, notes).await
    }

    /// Fails the attempt with `class`. When `environment` names a cause, the stage run is blocked
    /// before a retry or a person is considered (`S21`); otherwise the stage run retries, asks a
    /// person or fails by the retry rules.
    async fn commit_failure_for(
        &self,
        claimed: &ClaimedAttempt,
        class: FailureClass,
        environment: Option<EnvironmentCause>,
        notes: &Notes,
    ) -> Result<AttemptOutcome, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let attempt = tx.get_attempt(claimed.attempt).await?;
        if attempt.value.status.is_terminal() {
            return Ok(AttemptOutcome::LeaseLost);
        }
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id()).with_cost(notes.cost());
        let from = attempt.value.status;
        let recorded = async {
            let now = tx.database_time().await?;
            let (event, cleared, end) = match class {
                FailureClass::TimedOut => {
                    let facts = GuardFacts::Deadline(DeadlineFacts {
                        now,
                        attempt_deadline: attempt.value.deadline_at,
                    });
                    let cleared = clear(Guard::DeadlinePassed, &facts)?;
                    // A timeout is a status of the attempt, not a failure class in its row.
                    (
                        AttemptEvent::DeadlineExceeded,
                        cleared,
                        AttemptEnd::default(),
                    )
                }
                _ => {
                    let facts = GuardFacts::Epoch(EpochFacts {
                        sent_epoch: claimed.epoch.get(),
                        stored_epoch: attempt.value.epoch.get(),
                    });
                    let cleared = clear(Guard::EpochCurrent, &facts)?;
                    // Before the sandbox was up, the only failure the attempt machine has is
                    // `provision_failed`. The class is in the row and in the event.
                    (
                        class
                            .attempt_event(from)
                            .unwrap_or(AttemptEvent::ProvisionFailed),
                        cleared,
                        AttemptEnd {
                            failure_class: Some(class),
                            ..AttemptEnd::default()
                        },
                    )
                }
            };
            let cause = class.as_str().to_ascii_lowercase().replace('_', "-");
            cx.move_attempt(
                &mut *tx,
                &attempt,
                claimed.epoch,
                Step::new(event, cleared)
                    .cause(&cause)
                    .payload(payload::attempt_event(
                        claimed.kind,
                        claimed.stage_run,
                        claimed.attempt_number,
                        Some(class),
                    )),
                end,
            )
            .await?;
            self.record_handler_notes(&mut *tx, &cx, claimed, notes, &StageOutput::default())
                .await?;
            let disposition = self
                .after_attempt_failed(
                    &mut *tx,
                    &cx,
                    claimed.stage_run,
                    claimed.attempt,
                    class,
                    environment,
                )
                .await?;
            Ok::<Option<AttemptDisposition>, EngineError>(disposition)
        }
        .await;
        Ok(match self.conclude(tx, &cx, recorded).await? {
            Ok(Some(then)) => AttemptOutcome::Failed { class, then },
            Ok(None) => AttemptOutcome::Cancelled,
            Err(outcome) => outcome,
        })
    }

    /// Writes what the handler noted and what the output reported: the audit actions the
    /// handler asked for, and a record of each tool call that policy denied.
    async fn record_handler_notes(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        claimed: &ClaimedAttempt,
        notes: &Notes,
        output: &StageOutput,
    ) -> Result<(), EngineError> {
        let actor = AuditActor::System(Slug::parse(&format!(
            "stage-handler.{}",
            claimed.kind.as_str().to_ascii_lowercase()
        ))?);
        for action in notes.take_audit() {
            cx.audit(tx, actor.clone(), action).await?;
        }
        // A run that failed still reports the tool calls policy denied and its transcript.
        for _ in 0..notes.take_denials() {
            cx.audit(
                tx,
                actor.clone(),
                AuditAction::new(AuditKind::ToolCallDenied, AuditDecision::Denied),
            )
            .await?;
        }
        if let Some(transcript) = notes.take_transcript() {
            self.index(tx, cx, claimed, std::slice::from_ref(&transcript))
                .await?;
        }
        for _ in &output.permission_denials {
            cx.audit(
                tx,
                actor.clone(),
                AuditAction::new(AuditKind::ToolCallDenied, AuditDecision::Denied),
            )
            .await?;
        }
        Ok(())
    }
}

/// Reads a write that was refused because the lease is gone as the outcome "lease lost". Any
/// other error is a real fault and is returned.
fn lease_outcome<T>(
    result: Result<T, EngineError>,
) -> Result<Result<T, AttemptOutcome>, EngineError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(EngineError::LeaseFenced | EngineError::Conflict) => Ok(Err(AttemptOutcome::LeaseLost)),
        Err(other) => Err(other),
    }
}

fn outcome_label(outcome: &AttemptOutcome) -> &'static str {
    match outcome {
        AttemptOutcome::Succeeded | AttemptOutcome::NeedsHuman => "succeeded",
        AttemptOutcome::Failed { class, .. } => match class {
            FailureClass::TimedOut => "timed_out",
            FailureClass::LeaseLost => "lease_lost",
            _ => "failed",
        },
        AttemptOutcome::LeaseLost => "lease_lost",
        AttemptOutcome::Cancelled => "cancelled",
    }
}
