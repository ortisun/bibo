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

use factory_domain::contracts::evidence_ledger_entry::Evidence;
use factory_domain::contracts::stage_contract::Placement;
use factory_domain::contracts::{ArtifactRef, StageContract};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{
    DeadlineFacts, EpochFacts, GuardFacts, OutputFacts, SandboxProvisionFacts, evaluate,
};
use factory_domain::machines::retry::AttemptDisposition;
use factory_domain::state::{AttemptEvent, AttemptStatus, Guard, Status};
use factory_domain::values::Slug;
use factory_ports::agent::{
    CostMicroUsd, IssuedJobToken, JobTokenId, JobTokenRef, JobTokenRequest,
};
use factory_ports::store::{AuditActor, NewArtifactIndexEntry, StoreError, Tx};
use serde_json::{Value, json};
use tracing::Instrument;

use super::Engine;
use super::cancel::AttemptCancel;
use super::error::EngineError;
use super::failure::HumanReason;
use super::gate::Judged;
use super::payload;
use super::progress::{Board, upstream_runs};
use super::record::Cx;
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::framework::{Expectation, GateDecision, check_evidence};
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
    /// # Errors
    /// The store errors. A handler failure is an [`AttemptOutcome`], not an error.
    pub async fn run_attempt(
        &self,
        claimed: &ClaimedAttempt,
    ) -> Result<AttemptOutcome, EngineError> {
        let span = tracing::info_span!(
            "factory.attempt",
            factory.job_id = %claimed.job,
            factory.stage_run_id = %claimed.stage_run,
            factory.attempt_id = %claimed.attempt,
            factory.attempt_number = i64::from(claimed.attempt_number),
            factory.stage_kind = claimed.kind.as_str(),
            factory.outcome = tracing::field::Empty,
        );
        let outcome = self
            .run_attempt_inner(claimed)
            .instrument(span.clone())
            .await?;
        span.record("factory.outcome", outcome_label(&outcome));
        Ok(outcome)
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
                started_within_limits: true,
                tool_grants_in_place: true,
                capability_probe_satisfied: true,
            };
            if let Err(outcome) = lease_outcome(self.mark_running(claimed, ready).await)? {
                return Ok(outcome);
            }
        }

        let cancel = AttemptCancel::new();
        let notes = notes.clone();
        let mut ctx = StageContext::new(
            prepared.identity,
            claimed.attempt,
            claimed.attempt_number,
            claimed.epoch,
            self.config.mode,
            &prepared.contract,
            self.stage_ports(),
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
            notes.set_cost(self.token_cost(token.id).await);
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
                judged,
                output,
            })) => {
                self.commit_judged(
                    claimed,
                    &prepared.contract,
                    outputs,
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
            Some(Err(PipelineError::Stage(StageError::Blocked(_)))) => {
                self.commit_blocked(claimed, &notes).await
            }
            Some(Err(PipelineError::Stage(error))) => {
                let class = error.failure_class().unwrap_or(FailureClass::Internal);
                self.commit_failure(claimed, class, &notes).await
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
        let board = Board::load(&mut *tx, &timeline).await?;
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
        Ok(Prepared {
            contract,
            need,
            upstream,
            human_inputs: record.human_inputs.clone(),
            handler,
            identity,
        })
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
        let mut grace: Option<Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            tokio::select! {
                outcome = &mut work => {
                    watched.result = Some(outcome);
                    break;
                }
                () = tokio::time::sleep(self.config.heartbeat_interval) => {
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
        tx.commit().await?;
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
        tx.commit().await?;
        Ok(())
    }

    fn teardown_timer(&self) -> Pin<Box<tokio::time::Sleep>> {
        let grace: Duration = self.config.teardown_grace;
        Box::pin(tokio::time::sleep(grace))
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
            sandbox_started_within_limits: ready.started_within_limits,
            policy_tool_grants_in_place: ready.tool_grants_in_place,
            runtime_capability_probe_satisfied: ready.capability_probe_satisfied,
            epoch: EpochFacts {
                sent_epoch: claimed.epoch.get(),
                stored_epoch: attempt.value.epoch.get(),
            },
        });
        evaluate(Guard::SandboxProvisioned, &facts).map_err(super::progress::guard_error)?;
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
            AttemptEvent::SandboxReady,
            None,
            payload,
        )
        .await?;
        tx.commit().await?;
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
            .check_output(&prepared.contract, &output)
            .await
            .map_err(|()| StageError::InvalidOutput)?;
        let mut outputs = Vec::with_capacity(documents.len() + output.artifacts.len());
        for (name, media_type, value) in &documents {
            outputs.push(self.store_document(name, media_type, value).await?);
        }
        outputs.extend(output.artifacts.iter().cloned());

        let gate = GateContext {
            identity: prepared.identity,
            attempt: claimed.attempt,
            mode: self.config.mode,
            contract: &prepared.contract,
            ports: self.stage_ports(),
            cancel,
            outputs: &outputs,
            human_inputs: &prepared.human_inputs,
            upstream: &prepared.upstream,
        };
        let (decision, could_not_run) = match prepared.handler.evaluate(&gate).await {
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
            judged: Box::new(Judged {
                decision,
                reports,
                review,
                problem,
                could_not_run,
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
        contract: &StageContract,
        output: &StageOutput,
    ) -> Result<Vec<(String, String, Value)>, ()> {
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
                    .validate(*kind, *version, value)
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
            match self.deps.artifacts.exists(&artifact.artifact).await {
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
            evaluate(Guard::OutputSchemaValid, &facts).map_err(super::progress::guard_error)?;
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
                AttemptEvent::ReportSuccess,
                None,
                payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    None,
                ),
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
        Ok(match self.conclude(tx, recorded).await? {
            Ok(()) => AttemptOutcome::NeedsHuman,
            Err(outcome) => outcome,
        })
    }

    /// Records a valid output and the gate that judged it, in one transaction: the attempt
    /// succeeds (`A04`), the stage run goes through `GATING` and takes the move that the evidence
    /// calls for, and the ledger entries that justify the move are appended with it (INV-03).
    async fn commit_judged(
        &self,
        claimed: &ClaimedAttempt,
        contract: &StageContract,
        outputs: Vec<NamedArtifact>,
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
            evaluate(Guard::OutputSchemaValid, &facts).map_err(super::progress::guard_error)?;
            let mut stored: Vec<ArtifactRef> =
                outputs.iter().map(|named| named.artifact.clone()).collect();
            stored.extend(judged.reports.iter().cloned());
            stored.extend(judged.review.iter().cloned());
            self.index(&mut *tx, &cx, claimed, &stored).await?;
            cx.move_attempt(
                &mut *tx,
                &attempt,
                claimed.epoch,
                AttemptEvent::ReportSuccess,
                None,
                payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    None,
                ),
            )
            .await?;
            self.gate_stage(&mut *tx, &cx, &run, contract, judged, &outputs)
                .await?;
            self.record_handler_notes(&mut *tx, &cx, claimed, notes, output)
                .await
        }
        .await;
        Ok(match self.conclude(tx, recorded).await? {
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
            tx.index_artifact(NewArtifactIndexEntry {
                artifact: artifact.clone(),
                stage_run_id: Some(claimed.stage_run),
                created_at: cx.now,
            })
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
        recorded: Result<T, EngineError>,
    ) -> Result<Result<T, AttemptOutcome>, EngineError> {
        match recorded {
            Ok(value) => match tx.commit().await {
                Ok(()) => Ok(Ok(value)),
                Err(StoreError::Conflict | StoreError::LeaseFenced) => {
                    Ok(Err(AttemptOutcome::LeaseLost))
                }
                Err(other) => Err(other.into()),
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
            let event = match class {
                FailureClass::TimedOut => {
                    let facts = GuardFacts::Deadline(DeadlineFacts {
                        now,
                        attempt_deadline: claimed.deadline_at,
                    });
                    evaluate(Guard::DeadlinePassed, &facts)
                        .map_err(super::progress::guard_error)?;
                    AttemptEvent::DeadlineExceeded
                }
                _ => {
                    let facts = GuardFacts::Epoch(EpochFacts {
                        sent_epoch: claimed.epoch.get(),
                        stored_epoch: attempt.value.epoch.get(),
                    });
                    evaluate(Guard::EpochCurrent, &facts).map_err(super::progress::guard_error)?;
                    // Before the sandbox was up, the only failure the attempt machine has is
                    // `provision_failed`. The class is in the event.
                    class
                        .attempt_event(from)
                        .unwrap_or(AttemptEvent::ProvisionFailed)
                }
            };
            cx.move_attempt(
                &mut *tx,
                &attempt,
                claimed.epoch,
                event,
                Some(&class.as_str().to_ascii_lowercase().replace('_', "-")),
                payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    Some(class),
                ),
            )
            .await?;
            self.record_handler_notes(&mut *tx, &cx, claimed, notes, &StageOutput::default())
                .await?;
            let disposition = self
                .after_attempt_failed(&mut *tx, &cx, claimed.stage_run, claimed.attempt, class)
                .await?;
            Ok::<Option<AttemptDisposition>, EngineError>(disposition)
        }
        .await;
        Ok(match self.conclude(tx, recorded).await? {
            Ok(Some(then)) => AttemptOutcome::Failed { class, then },
            Ok(None) => AttemptOutcome::Cancelled,
            Err(outcome) => outcome,
        })
    }

    /// A stage that cannot run because something it needs is missing fails closed: the attempt
    /// fails and the stage run waits for a person. It is never retried with other settings.
    async fn commit_blocked(
        &self,
        claimed: &ClaimedAttempt,
        notes: &Notes,
    ) -> Result<AttemptOutcome, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let attempt = tx.get_attempt(claimed.attempt).await?;
        if attempt.value.status.is_terminal() {
            return Ok(AttemptOutcome::LeaseLost);
        }
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id()).with_cost(notes.cost());
        let class = FailureClass::PolicyDenied;
        let from = attempt.value.status;
        let recorded = async {
            cx.move_attempt(
                &mut *tx,
                &attempt,
                claimed.epoch,
                class
                    .attempt_event(from)
                    .unwrap_or(AttemptEvent::ProvisionFailed),
                Some("stage-blocked"),
                payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    Some(class),
                ),
            )
            .await?;
            self.record_handler_notes(&mut *tx, &cx, claimed, notes, &StageOutput::default())
                .await?;
            self.escalate_running(&mut *tx, &cx, claimed.stage_run, HumanReason::Blocked)
                .await
        }
        .await;
        Ok(match self.conclude(tx, recorded).await? {
            Ok(()) => AttemptOutcome::Failed {
                class,
                then: AttemptDisposition::Escalate(
                    factory_domain::machines::retry::EscalationCause::AttemptLimit,
                ),
            },
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
        let actor = AuditActor::Component(Slug::parse(&format!(
            "stage-handler.{}",
            claimed.kind.as_str().to_ascii_lowercase()
        ))?);
        for action in notes.take_audit() {
            cx.audit(tx, actor.clone(), action).await?;
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

/// The ledger evidence that cites a stored artifact. Used by the gate increment.
#[allow(dead_code)]
fn artifact_evidence(artifact: &ArtifactRef, what: &str) -> Result<Evidence, EngineError> {
    Ok(Evidence::Artifact(
        factory_domain::contracts::evidence_ledger_entry::ArtifactEvidence {
            sha256: artifact.sha256.clone(),
            media_type: artifact.media_type.clone(),
            description: Some(factory_domain::values::HumanText::parse(what)?),
        },
    ))
}
