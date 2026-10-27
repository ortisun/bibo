//! Replacing stage runs: supersession after a change, and the new runs that rework needs.
//!
//! When something that later work was built on changes, every live run that consumed it becomes
//! `SUPERSEDED` (`S20`) and a new run of the same stage starts from `PENDING`. Which runs those
//! are comes from the invalidation table in `state-machine.json`, through the domain functions
//! `plan_for_change` and `plan_for_rework`. This module only applies the plan:
//!
//! * a run that still has a live attempt gets that attempt cancelled first (`A08`), so no worker
//!   goes on working for a run that no longer counts;
//! * a run is never edited back: the old run stays `SUPERSEDED` and a new one is created;
//! * the new runs are listed in the events, so a restarted engine finds them.

use factory_domain::ids::StageRunId;
use factory_domain::machines::guards::{GuardFacts, SupersedeFacts, evaluate};
use factory_domain::state::{AttemptEvent, AttemptStatus, Guard, StageRunEvent};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{NewStageRun, Tx};
use serde_json::json;

use super::Engine;
use super::error::EngineError;
use super::payload::{self, key};
use super::progress::{Board, guard_error};
use super::record::Cx;
use super::timeline::Timeline;
use factory_domain::machines::guards::CancelFacts;

/// Why runs are being replaced. It decides which condition of `G_UPSTREAM_INVALIDATED` holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// A stage sent the work back to an earlier stage.
    Rework,
    /// An artifact that later stages consumed has a newer version.
    ArtifactChanged,
    /// A change from outside the pipeline: the source request, or a value the gate evidence is
    /// bound to.
    External,
}

impl Why {
    const fn facts(self) -> SupersedeFacts {
        SupersedeFacts {
            consumed_artifact_superseded_by_newer_version: matches!(self, Self::ArtifactChanged),
            upstream_stage_run_was_reworked: matches!(self, Self::Rework),
            external_change_recorded: matches!(self, Self::External),
        }
    }
}

impl Engine {
    /// Supersedes `runs` and creates one new run for each kind in `kinds`. Returns the new runs
    /// in the order of `kinds`.
    ///
    /// # Errors
    /// Any error of a guard, a move or a read. The caller drops the transaction.
    pub(crate) async fn supersede_and_replace(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        runs: &[StageRunId],
        kinds: &[StageKind],
        why: Why,
        cause: &'static str,
    ) -> Result<Vec<(StageKind, StageRunId)>, EngineError> {
        let mut created = Vec::with_capacity(kinds.len());
        for kind in kinds {
            let id = self.new_stage_run_id();
            tx.insert_stage_run(NewStageRun {
                id,
                job_id: cx.job,
                kind: *kind,
                created_at: cx.now,
            })
            .await?;
            created.push((*kind, id));
        }
        let timeline = Timeline::load(tx, cx.job).await?;
        for id in runs {
            self.cancel_live_attempts(tx, cx, &timeline, *id).await?;
            let run = tx.get_stage_run(*id).await?;
            evaluate(
                Guard::UpstreamInvalidated,
                &GuardFacts::Supersede(why.facts()),
            )
            .map_err(guard_error)?;
            let mut payload = payload::for_run(run.value.kind, *id);
            payload = payload::with(payload, key::CAUSE, json!(cause));
            if let Some((_, replacement)) = created.iter().find(|(kind, _)| *kind == run.value.kind)
            {
                payload = payload::with(
                    payload,
                    key::REPLACED_BY,
                    payload::run_ref(*replacement, run.value.kind),
                );
            }
            cx.move_stage_run(tx, &run, StageRunEvent::Supersede, Some(cause), payload)
                .await?;
        }
        Ok(created)
    }

    /// Asks every live attempt of a stage run to cancel (`A08`). The worker learns of it from its
    /// next heartbeat, stops its handler, and tears the sandbox down.
    async fn cancel_live_attempts(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        timeline: &Timeline,
        run_id: StageRunId,
    ) -> Result<(), EngineError> {
        let Some(record) = timeline.run(run_id) else {
            return Ok(());
        };
        let job = tx.get_job(cx.job).await?;
        for attempt in record.attempts.iter().filter(|a| a.end.is_none()) {
            let row = tx.get_attempt(attempt.id).await?;
            if !matches!(
                row.value.status,
                AttemptStatus::Starting | AttemptStatus::Running
            ) {
                continue;
            }
            let facts = GuardFacts::Cancel(CancelFacts {
                attempt: row.value.status,
                job: job.value.status,
                stage_run_is_being_superseded: true,
            });
            evaluate(Guard::CancelAllowed, &facts).map_err(guard_error)?;
            let payload = payload::attempt_event(record.kind, run_id, row.value.number, None);
            cx.move_attempt(
                tx,
                &row,
                row.value.epoch,
                AttemptEvent::RequestCancel,
                Some("run-superseded"),
                payload,
            )
            .await?;
        }
        Ok(())
    }

    /// The live runs that `plan_for_change` and friends read: every run of the job with its
    /// current status.
    pub(crate) async fn snapshots_of(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
    ) -> Result<Vec<factory_domain::machines::snapshot::StageRunSnapshot>, EngineError> {
        let timeline = Timeline::load(tx, cx.job).await?;
        let board = Board::load(tx, &timeline).await?;
        Ok(board.snapshots())
    }
}
