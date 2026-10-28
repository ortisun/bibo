//! What a failed attempt does to its stage run: retry after a back-off, ask a person, or fail.
//!
//! A limit never fails a stage run. Reaching the attempt limit, the repair cap or a budget limit
//! asks a person, and only a failure that retrying cannot fix fails the run (ADR 0010, decision 1).
//! The choice is made by `decide_after_failure` of the domain, and the engine then evaluates the
//! guard of the move that the choice names, so the two cannot disagree.
//!
//! Attempts and repairs are counted from the last human answer. A person who answers a stage run
//! that stopped at its limit therefore gets a new window of attempts, and the total stays bounded
//! because a person is in the loop each time.

use factory_domain::ids::{AttemptId, StageRunId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{
    EnvironmentCause, EnvironmentFacts, EscalationFacts, GuardFacts, RetryFacts,
};
use factory_domain::machines::retry::{AttemptDisposition, EscalationCause, decide_after_failure};
use factory_domain::state::{Guard, StageRunEvent, StageRunStatus};
use factory_domain::vocabulary::GateOutcome;
use factory_ports::store::{GateRecord, StageRunEffects, Tx};
use serde_json::json;

use super::Engine;
use super::decision::{DecisionKind, DecisionReport};
use super::error::EngineError;
use super::payload::{self, key};
use super::progress::{Board, clear, upstream_runs};
use super::record::{Cx, Step};
use super::timeline::Timeline;
use crate::scheduler::retry_delay;

/// Why a running stage run goes to a person when no failure class decides it. The only reason
/// left is that the agent asked: a stage that cannot run because its environment is missing no
/// longer goes to a person, it is blocked (`S21`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HumanReason {
    /// The agent returned a structured request for a person.
    AgentRequested,
}

impl HumanReason {
    const fn code(self) -> &'static str {
        match self {
            Self::AgentRequested => "agent-requested-a-human",
        }
    }

    const fn facts(self) -> EscalationFacts {
        EscalationFacts {
            budget_limit_hit: false,
            attempt_limit_reached: false,
            agent_requested_a_human: true,
            stagnation_detected: false,
            policy_requires_human_decision: false,
        }
    }
}

impl Engine {
    /// Decides and applies what the failure of an attempt means for its stage run, then settles
    /// the job. The attempt has already moved to its failed state in this transaction.
    ///
    /// Returns `None` when the stage run is no longer `RUNNING`: it was cancelled or superseded
    /// while the attempt ran, and there is nothing to decide.
    ///
    /// # Errors
    /// Any error of a guard, a move or a read. The caller drops the transaction.
    pub(crate) async fn after_attempt_failed(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run_id: StageRunId,
        attempt: AttemptId,
        class: FailureClass,
        environment: Option<EnvironmentCause>,
    ) -> Result<Option<AttemptDisposition>, EngineError> {
        let timeline = Timeline::load(tx, cx.job).await?;
        let board = Board::of(&timeline);
        let (Some(run), Some(record)) = (board.run(run_id), timeline.run(run_id)) else {
            return Err(EngineError::NotFound);
        };
        if run.value.status != StageRunStatus::Running {
            return Ok(None);
        }
        let handler = self
            .handlers
            .get(run.value.kind)
            .ok_or(EngineError::NoHandler(run.value.kind))?;
        let upstream = upstream_runs(&timeline, &board);
        let ccx = self.contract_context(cx, &run.value, record, &upstream);
        let contract = handler
            .contract(&ccx)
            .map_err(|_| EngineError::Corrupt("the stage contract no longer resolves"))?;

        let window = record.window();
        let facts = RetryFacts {
            class,
            retry_on: contract.timeout_and_retries.retry_on.as_slice(),
            attempts_used: window.attempts_used(),
            max_attempts: u32::try_from(contract.timeout_and_retries.max_attempts.get())
                .unwrap_or(1),
            budget_has_room: timeline.spent_micro_usd < self.config.job_budget_micro_usd,
            invalid_output_failures: window.invalid_output_failures(),
            repair_cap: self.config.repair_cap,
            environment,
        };
        let disposition = decide_after_failure(&facts);
        let base = payload::attempt_event(
            run.value.kind,
            run_id,
            record.attempt(attempt).map_or(0, |a| a.number),
            Some(class),
        );
        match disposition {
            AttemptDisposition::Retry => {
                let cleared = clear(Guard::RetryAllowed, &GuardFacts::Retry(facts))?;
                let delay = retry_delay(
                    &contract.timeout_and_retries.backoff,
                    window.attempts_used(),
                    seed_of(attempt),
                );
                // The store sets `not_before` from its own clock, so the back-off needs no wait
                // for an old lease: the stage run is findable again once the delay has passed.
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::AttemptFailedRetryable, cleared)
                        .cause("retry-scheduled")
                        .payload(base),
                    StageRunEffects {
                        not_before_after: Some(delay),
                        ..StageRunEffects::default()
                    },
                )
                .await?;
                tracing::info!(
                    monotonic_counter.factory_retries_total = 1_u64,
                    stage = run.value.kind.as_str()
                );
            }
            AttemptDisposition::Escalate(cause) => {
                let cleared = clear(
                    Guard::EscalationRequired,
                    &GuardFacts::Escalation(cause.facts()),
                )?;
                let code = match cause {
                    EscalationCause::BudgetLimit => "budget-limit",
                    EscalationCause::AttemptLimit => "attempt-limit",
                };
                let payload = payload::with(base, key::CAUSE, json!(code));
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::EscalateToHuman, cleared)
                        .cause(code)
                        .payload(payload),
                    StageRunEffects::default(),
                )
                .await?;
            }
            AttemptDisposition::Fail => {
                let cleared = clear(Guard::FailureNonretryable, &GuardFacts::Retry(facts))?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::AttemptFailedFinal, cleared)
                        .cause("failure-not-retryable")
                        .payload(base),
                    StageRunEffects::default(),
                )
                .await?;
            }
            AttemptDisposition::Block(cause) => {
                // The environment is missing or unsafe, so the stage run is blocked before any
                // retry or person is considered (`S21`). The attempt was ended as failed in
                // this transaction, which is what the guard asks.
                let cleared = clear(
                    Guard::EnvironmentBlocked,
                    &GuardFacts::Environment(EnvironmentFacts {
                        cause,
                        attempt_ended_failed: true,
                    }),
                )?;
                let code = cause.as_str();
                let payload = payload::with(base, key::CAUSE, json!(code));
                // No gate ran. The block still rests on a document that names the cause, so the
                // reason is not lost with the failed attempt.
                let mut details = serde_json::Map::new();
                details.insert("attempt_id".to_owned(), json!(attempt.to_string()));
                details.insert("failure_class".to_owned(), json!(class.as_str()));
                let report = cx
                    .record_decision(
                        tx,
                        &DecisionReport {
                            kind: DecisionKind::EnvironmentBlock,
                            outcome: GateOutcome::Blocked,
                            stage_run: run_id,
                            stage: run.value.kind,
                            cause: code,
                            details,
                        },
                    )
                    .await?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::AttemptBlocked, cleared)
                        .cause(code)
                        .payload(payload),
                    StageRunEffects {
                        gate: Some(GateRecord {
                            outcome: GateOutcome::Blocked,
                            report_sha256: Some(report),
                            failing_set_sha256: None,
                        }),
                        ..StageRunEffects::default()
                    },
                )
                .await?;
            }
        }
        self.settle(tx, cx).await?;
        Ok(Some(disposition))
    }

    /// Sends a running stage run to a person for a reason that is not a failure class: the agent
    /// asked, or the stage fails closed.
    ///
    /// # Errors
    /// Any error of a guard, a move or a read.
    pub(crate) async fn escalate_running(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run_id: StageRunId,
        reason: HumanReason,
    ) -> Result<(), EngineError> {
        let timeline = Timeline::load(tx, cx.job).await?;
        let board = Board::of(&timeline);
        let run = board.run(run_id).ok_or(EngineError::NotFound)?;
        let cleared = clear(
            Guard::EscalationRequired,
            &GuardFacts::Escalation(reason.facts()),
        )?;
        let payload = payload::with(
            payload::for_run(run.value.kind, run_id),
            key::CAUSE,
            json!(reason.code()),
        );
        cx.move_stage_run(
            tx,
            run,
            Step::new(StageRunEvent::EscalateToHuman, cleared)
                .cause(reason.code())
                .payload(payload),
            StageRunEffects::default(),
        )
        .await?;
        self.settle(tx, cx).await
    }
}

/// The jitter seed of an attempt: the low 64 bits of its identifier.
fn seed_of(attempt: AttemptId) -> u64 {
    let bits = attempt.as_uuid().as_u128();
    u64::try_from(bits & u128::from(u64::MAX)).unwrap_or(0)
}
