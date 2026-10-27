//! Moving a job forward after something changed: promoting stage runs whose upstream is done,
//! skipping stages that do not apply, and following the job status after its stage runs.
//!
//! [`Engine::settle`] runs at the end of every decision, in the same transaction. That is what
//! makes a restart safe: there is never a stage run that passed while the next one waits for
//! somebody to notice, because noticing is part of the commit that made it pass.
//!
//! `settle` makes one move at a time and reads the state again before the next, so each guard
//! sees the effect of the moves before it. The number of rounds is bounded by the size of the
//! job, so a bug cannot make it loop.

use factory_domain::contracts::Contract;
use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence, SourceEvidence};
use factory_domain::ids::StageRunId;
use factory_domain::machines::guards::stage_run::satisfies_dependants;
use factory_domain::machines::guards::{
    GuardFacts, NotApplicableBasis, NotApplicableFacts, PipelineScopeFacts, RejectionFacts,
    StageBoardFacts, UnrecoverableFacts, UpstreamFacts, evaluate,
};
use factory_domain::machines::snapshot::StageRunSnapshot;
use factory_domain::state::{Guard, JobEvent, JobStatus, StageRunEvent, StageRunStatus};
use factory_domain::values::{HumanText, Sha256Digest};
use factory_domain::vocabulary::{ConfidenceLevel, StageKind};
use factory_ports::store::{Job, StageRun, Tx, Versioned};

use super::Engine;
use super::error::EngineError;
use super::ledger::{ClaimSpec, ledger_verifies};
use super::payload;
use super::record::Cx;
use super::timeline::{RunRecord, Timeline};
use crate::handlers::{
    Applicability, ContractContext, RunIdentity, SkipBasis, SkipRule, UpstreamRun,
};

/// The stage runs of a job with their rows, in the order they were created.
pub(crate) struct Board {
    pub(crate) runs: Vec<Versioned<StageRun>>,
}

impl Board {
    /// Reads the row of every stage run in the timeline.
    pub(crate) async fn load(tx: &mut dyn Tx, timeline: &Timeline) -> Result<Self, EngineError> {
        let mut runs = Vec::with_capacity(timeline.runs.len());
        for record in &timeline.runs {
            runs.push(tx.get_stage_run(record.id).await?);
        }
        Ok(Self { runs })
    }

    /// The read-only views the guards take.
    pub(crate) fn snapshots(&self) -> Vec<StageRunSnapshot> {
        self.runs
            .iter()
            .map(|run| StageRunSnapshot::new(run.value.id, run.value.kind, run.value.status))
            .collect()
    }

    /// The row of one stage run.
    pub(crate) fn run(&self, id: StageRunId) -> Option<&Versioned<StageRun>> {
        self.runs.iter().find(|run| run.value.id == id)
    }

    /// The newest run of a stage kind.
    fn newest(&self, kind: StageKind) -> Option<&Versioned<StageRun>> {
        self.runs.iter().rev().find(|run| run.value.kind == kind)
    }

    /// True when some run has this status.
    fn any(&self, status: StageRunStatus) -> bool {
        self.runs.iter().any(|run| run.value.status == status)
    }
}

/// The runs that a new run can build on: for each stage kind, the newest run, when it passed or
/// was skipped by rule. A superseded or dead run is not one.
pub(crate) fn upstream_runs(timeline: &Timeline, board: &Board) -> Vec<UpstreamRun> {
    let mut kinds: Vec<StageKind> = Vec::new();
    for run in &board.runs {
        if !kinds.contains(&run.value.kind) {
            kinds.push(run.value.kind);
        }
    }
    kinds.sort_by_key(|kind| super::config::position(*kind));
    kinds
        .into_iter()
        .filter_map(|kind| board.newest(kind))
        .filter(|run| satisfies_dependants(run.value.status))
        .map(|run| UpstreamRun {
            id: run.value.id,
            kind: run.value.kind,
            status: run.value.status,
            outputs: timeline
                .run(run.value.id)
                .map(|record| record.outputs.clone())
                .unwrap_or_default(),
        })
        .collect()
}

/// What `settle` found to do in one round.
enum Round {
    /// Nothing more to do.
    Settled,
    /// One move was made; read the state again.
    Moved,
}

impl Engine {
    /// The identity of a run, for a handler.
    pub(crate) fn identity(cx: &Cx<'_>, run: &StageRun) -> RunIdentity {
        RunIdentity {
            tenant: cx.tenant,
            job: cx.job,
            correlation: cx.correlation,
            stage_run: run.id,
            kind: run.kind,
        }
    }

    /// What a handler needs to resolve the contract of a run.
    pub(crate) fn contract_context<'a>(
        &'a self,
        cx: &Cx<'_>,
        run: &StageRun,
        record: &'a RunRecord,
        upstream: &'a [UpstreamRun],
    ) -> ContractContext<'a> {
        ContractContext {
            identity: Self::identity(cx, run),
            mode: self.config.mode,
            policy_hash: &self.config.policy_hash,
            now: cx.now,
            upstream,
            human_inputs: &record.human_inputs,
            request_edited: record.reauthorize,
        }
    }

    /// Moves the job forward until nothing more can move, in the transaction of the decision that
    /// changed something.
    ///
    /// # Errors
    /// Any error of a move or a read. The caller drops the transaction, so nothing is written.
    pub(crate) async fn settle(&self, tx: &mut dyn Tx, cx: &Cx<'_>) -> Result<(), EngineError> {
        // Each round makes one move. A job has a bounded number of stage runs and each run moves
        // a bounded number of times, so this limit is far above what a real job needs.
        const MAX_ROUNDS: usize = 512;
        for _ in 0..MAX_ROUNDS {
            let job = tx.get_job(cx.job).await?;
            let timeline = Timeline::load(tx, cx.job).await?;
            let board = Board::load(tx, &timeline).await?;
            match self.settle_round(tx, cx, &job, &timeline, &board).await? {
                Round::Settled => return Ok(()),
                Round::Moved => {}
            }
        }
        Err(EngineError::Corrupt(
            "the job did not settle within the bound; the state machine looped",
        ))
    }

    async fn settle_round(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        job: &Versioned<Job>,
        timeline: &Timeline,
        board: &Board,
    ) -> Result<Round, EngineError> {
        let status = job.value.status;
        if !matches!(status, JobStatus::Active | JobStatus::WaitingForHuman) {
            return Ok(Round::Settled);
        }
        let snaps = board.snapshots();
        let board_facts = GuardFacts::StageBoard(StageBoardFacts { stage_runs: &snaps });

        // A person rejected a stage run: the job ends as rejected, not failed (state-machine.md).
        let rejected = timeline.runs.iter().any(|record| {
            record.rejected
                && board
                    .run(record.id)
                    .is_some_and(|run| run.value.status == StageRunStatus::Failed)
        });
        if rejected {
            let facts = GuardFacts::Rejection(RejectionFacts {
                intake_decision_is_decline: false,
                reject_decision_recorded: true,
                decider_is_authorized_approver: true,
            });
            evaluate(Guard::RejectionRecorded, &facts).map_err(guard_error)?;
            cx.move_job(
                tx,
                job,
                JobEvent::RejectJob,
                Some("approver-rejected"),
                Default::default(),
            )
            .await?;
            return Ok(Round::Moved);
        }

        if status == JobStatus::Active {
            let failed = timeline.runs.iter().any(|record| {
                !record.rejected
                    && board
                        .run(record.id)
                        .is_some_and(|run| run.value.status == StageRunStatus::Failed)
            });
            if failed {
                let facts = GuardFacts::Unrecoverable(UnrecoverableFacts {
                    stage_run_failed: true,
                    rework_route_remains: false,
                    retry_budget_remains: false,
                    hard_limit_reached: false,
                    policy_says_fail: false,
                });
                evaluate(Guard::Unrecoverable, &facts).map_err(guard_error)?;
                cx.move_job(
                    tx,
                    job,
                    JobEvent::FailJob,
                    Some("stage-failed"),
                    Default::default(),
                )
                .await?;
                return Ok(Round::Moved);
            }
            if board.any(StageRunStatus::WaitingForHuman)
                && evaluate(Guard::AnyStageWaiting, &board_facts).is_ok()
            {
                cx.move_job(tx, job, JobEvent::StageNeedsHuman, None, Default::default())
                    .await?;
                return Ok(Round::Moved);
            }
            if board.any(StageRunStatus::Blocked)
                && evaluate(Guard::AnyStageBlocked, &board_facts).is_ok()
            {
                cx.move_job(tx, job, JobEvent::Block, None, Default::default())
                    .await?;
                return Ok(Round::Moved);
            }
        } else if evaluate(Guard::NoStageWaiting, &board_facts).is_ok() {
            // The job was waiting and no stage run waits for a person any more.
            cx.move_job(
                tx,
                job,
                JobEvent::HumanWaitResolved,
                None,
                Default::default(),
            )
            .await?;
            return Ok(Round::Moved);
        }

        if status != JobStatus::Active {
            return Ok(Round::Settled);
        }

        if self
            .pipeline_complete(tx, cx, timeline, board, &snaps)
            .await?
        {
            cx.move_job(tx, job, JobEvent::Complete, None, Default::default())
                .await?;
            return Ok(Round::Moved);
        }

        self.promote_one(tx, cx, timeline, board, &snaps).await
    }

    /// True when guard `G_PIPELINE_SCOPE_COMPLETE` holds for the job.
    async fn pipeline_complete(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        timeline: &Timeline,
        board: &Board,
        snaps: &[StageRunSnapshot],
    ) -> Result<bool, EngineError> {
        // Cheap checks first: the ledger is read only when the stages are done.
        let scope = &self.config.scope;
        let every_stage_done = scope.iter().all(|kind| {
            board
                .newest(*kind)
                .is_some_and(|run| satisfies_dependants(run.value.status))
        });
        if !every_stage_done {
            return Ok(false);
        }
        let approved = !scope.contains(&StageKind::Approval)
            || timeline.runs_of(StageKind::Approval).any(|record| {
                record.approved
                    && board
                        .run(record.id)
                        .is_some_and(|run| run.value.status == StageRunStatus::Passed)
            });
        let chain = ledger_verifies(tx, cx.job).await?;
        let facts = GuardFacts::PipelineScope(PipelineScopeFacts {
            scope,
            stage_runs: snaps,
            approval_decision_is_approve: approved,
            ledger_chain_verifies: chain,
        });
        Ok(evaluate(Guard::PipelineScopeComplete, &facts).is_ok())
    }

    /// Promotes the first `PENDING` run whose upstream is done: to `READY` (`S01`), or to
    /// `SKIPPED` (`S02`) when its handler says a rule makes the stage not apply.
    async fn promote_one(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        timeline: &Timeline,
        board: &Board,
        snaps: &[StageRunSnapshot],
    ) -> Result<Round, EngineError> {
        let upstream = upstream_runs(timeline, board);
        for run in &board.runs {
            if run.value.status != StageRunStatus::Pending {
                continue;
            }
            let Some(record) = timeline.run(run.value.id) else {
                continue;
            };
            let Some(handler) = self.handlers.get(run.value.kind) else {
                continue;
            };
            let ccx = self.contract_context(cx, &run.value, record, &upstream);
            let contract_ok = handler
                .contract(&ccx)
                .is_ok_and(|contract| contract.validate().is_ok());
            let facts = GuardFacts::Upstream(UpstreamFacts {
                stage: run.value.kind,
                stage_runs: snaps,
                consumed_artifact_hashes_current: self.upstream_is_current(board, run.value.kind),
                stage_contract_resolved_and_valid: contract_ok,
            });
            if evaluate(Guard::UpstreamPassed, &facts).is_err() {
                continue;
            }
            match handler.applicability(&ccx) {
                Applicability::Applies => {
                    let payload = payload::for_run(run.value.kind, run.value.id);
                    cx.move_stage_run(tx, run, StageRunEvent::PreconditionsMet, None, payload)
                        .await?;
                }
                Applicability::NotApplicable(rule) => {
                    self.skip_run(tx, cx, run, record, &rule).await?;
                }
            }
            return Ok(Round::Moved);
        }
        Ok(Round::Settled)
    }

    /// True when, for every stage that `kind` requires, the newest run is the one that satisfies
    /// the requirement. An older passed run next to a newer live run means a change was not
    /// followed through, and the artifacts the older run produced are not current.
    fn upstream_is_current(&self, board: &Board, kind: StageKind) -> bool {
        kind.requires().iter().all(|required| {
            board
                .newest(*required)
                .is_some_and(|run| satisfies_dependants(run.value.status))
        })
    }

    /// Marks a run `SKIPPED` by a recorded rule, and writes the rule and what it saw to the
    /// ledger (`S02`, `G_NOT_APPLICABLE_DECIDED`). The skip is never evidence for an assurance
    /// level.
    async fn skip_run(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: &Versioned<StageRun>,
        _record: &RunRecord,
        rule: &SkipRule,
    ) -> Result<(), EngineError> {
        let basis = match rule.basis {
            SkipBasis::DeterministicRule => NotApplicableBasis::DeterministicRule,
            SkipBasis::DomainProfile => NotApplicableBasis::DomainProfile,
            SkipBasis::Policy => NotApplicableBasis::Policy,
        };
        let facts = GuardFacts::NotApplicable(NotApplicableFacts {
            basis: Some(basis),
            rule_and_inputs_recorded: true,
        });
        evaluate(Guard::NotApplicableDecided, &facts).map_err(guard_error)?;
        let citation = HumanText::parse(&format!(
            "Skip rule {} states that the {} stage does not apply: {}",
            rule.rule,
            run.value.kind,
            rule.inputs.as_str()
        ))?;
        let evidence = Evidence::Source(SourceEvidence {
            citation,
            url: None,
            version: None,
            retrieved_at: cx.now,
            sha256: Some(Sha256Digest::of(rule.inputs.as_str().as_bytes())),
        });
        let claim = ClaimSpec {
            statement: format!(
                "The {} stage was skipped because the rule {} states that it does not apply.",
                run.value.kind, rule.rule
            ),
            kind: ClaimKind::MeasuredFact,
            assurance_level: None,
            confidence: ConfidenceLevel::High,
            rationale: "The rule is deterministic and its inputs are recorded in this entry."
                .to_owned(),
        };
        cx.record_claim(tx, run.value.id, None, &claim, &[evidence])
            .await?;
        let payload = payload::with(
            payload::for_run(run.value.kind, run.value.id),
            payload::key::CAUSE,
            serde_json::json!(rule.rule.as_str()),
        );
        cx.move_stage_run(
            tx,
            run,
            StageRunEvent::MarkNotApplicable,
            Some("not-applicable"),
            payload,
        )
        .await?;
        Ok(())
    }
}

/// A guard that did not hold, as an engine error.
pub(crate) fn guard_error(error: factory_domain::machines::guards::GuardError) -> EngineError {
    match error {
        factory_domain::machines::guards::GuardError::Unmet(failure) => {
            EngineError::GuardUnmet(failure)
        }
        factory_domain::machines::guards::GuardError::WrongFacts { .. } => {
            EngineError::Corrupt("the engine passed facts of the wrong kind to a guard")
        }
    }
}
