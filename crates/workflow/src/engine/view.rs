//! A read model of one job: its status, its stage runs, their attempts and the counts the engine
//! keeps. For the API, the dashboard and the tests. It writes nothing.

use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::machines::limits::ReworkTrack;
use factory_domain::state::{AttemptStatus, JobStatus, StageRunStatus};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::LeaseEpoch;

use super::timeline::Timeline;
use super::{Engine, EngineError};

/// One attempt of a stage run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptView {
    /// The attempt.
    pub id: AttemptId,
    /// Which try this is for its stage run, from 1.
    pub number: u32,
    /// Where it stands.
    pub status: AttemptStatus,
    /// The lease epoch it was granted at.
    pub epoch: LeaseEpoch,
}

/// One stage run of the job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRunView {
    /// The stage run.
    pub id: StageRunId,
    /// Which stage it is a run of.
    pub kind: StageKind,
    /// Where it stands.
    pub status: StageRunStatus,
    /// The highest lease epoch ever granted on it.
    pub lease_epoch: LeaseEpoch,
    /// Its attempts, oldest first.
    pub attempts: Vec<AttemptView>,
    /// The earliest instant it may start again, while a retry back-off runs.
    pub not_before: Option<Timestamp>,
    /// How many answers people gave it.
    pub human_answers: usize,
    /// The run that replaced it after a supersession: the next run of the same stage.
    pub replaced_by: Option<StageRunId>,
}

/// A job and its stage runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobView {
    /// The job.
    pub job: JobId,
    /// Where it stands.
    pub status: JobStatus,
    /// Its stage runs, in the order they were created.
    pub stage_runs: Vec<StageRunView>,
    /// Rework rounds used on the specification count (re-runs of `SPECIFICATION`).
    pub specification_rework_rounds: u8,
    /// Rework rounds used on the design count (re-runs of `ARCHITECTURE` and `TASK_PLANNING`).
    pub design_rework_rounds: u8,
    /// Rework rounds used on the code count (re-runs of `IMPLEMENTATION`).
    pub code_rework_rounds: u8,
    /// Rework rounds used on the documentation count.
    pub documentation_rework_rounds: u8,
}

impl JobView {
    /// The runs of one stage kind, oldest first.
    pub fn runs_of(&self, kind: StageKind) -> impl Iterator<Item = &StageRunView> {
        self.stage_runs.iter().filter(move |run| run.kind == kind)
    }

    /// The newest run of one stage kind.
    #[must_use]
    pub fn newest(&self, kind: StageKind) -> Option<&StageRunView> {
        self.runs_of(kind).last()
    }
}

impl Engine {
    /// Whether the engine already applied the command with this id to the job.
    ///
    /// A decision the engine applies leaves events that carry the command id as their cause, and
    /// a repeat of the command is answered `Duplicate`. A caller that applies decisions from a
    /// queue and may stop between the engine's commit and its own record of it asks this first,
    /// so that the repeat is a no-op and not a second application.
    ///
    /// # Errors
    /// [`EngineError::NotFound`] when the job does not exist for the tenant, and the store errors.
    pub async fn command_applied(
        &self,
        tenant: TenantId,
        job: JobId,
        command: factory_domain::ids::CausationId,
    ) -> Result<bool, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let loaded = async {
            tx.get_job(job).await?;
            Timeline::load(&mut *tx, job).await
        }
        .await;
        tx.rollback().await?;
        Ok(loaded?.has_applied(command))
    }

    /// When the stage run moved into `status` the last time, if it is in that state now: the
    /// `occurred_at` of the newest `stage_run.waiting_for_human` or `stage_run.blocked` event of
    /// the run. `Ok(None)` when the run is in another state, when `status` is neither of the two,
    /// or when the event is not readable (old events archived): a caller that measures a wait from
    /// here then refuses (ADR 0022).
    ///
    /// # Errors
    /// [`EngineError::NotFound`] when the job does not exist for the tenant, and the store errors.
    pub async fn state_entered_at(
        &self,
        tenant: TenantId,
        job: JobId,
        stage_run: StageRunId,
        status: StageRunStatus,
    ) -> Result<Option<Timestamp>, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let loaded = async {
            tx.get_job(job).await?;
            Timeline::load(&mut *tx, job).await
        }
        .await;
        tx.rollback().await?;
        let timeline = loaded?;
        let Some(record) = timeline.run(stage_run) else {
            return Ok(None);
        };
        if record.row.value.status != status {
            return Ok(None);
        }
        Ok(match status {
            StageRunStatus::WaitingForHuman => record.waiting_for_human_at,
            StageRunStatus::Blocked => record.blocked_at,
            _ => None,
        })
    }

    /// Reads a job with its stage runs and attempts.
    ///
    /// # Errors
    /// [`EngineError::NotFound`] when the job does not exist for the tenant, and the store errors.
    pub async fn job_view(&self, tenant: TenantId, job: JobId) -> Result<JobView, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let stored = tx.get_job(job).await?;
        let timeline = Timeline::load(&mut *tx, job).await?;
        let mut stage_runs = Vec::with_capacity(timeline.runs.len());
        for record in &timeline.runs {
            let run = &record.row;
            let mut attempts = Vec::with_capacity(record.attempts.len());
            for attempt in &record.attempts {
                let row = tx.get_attempt(attempt.id).await?;
                attempts.push(AttemptView {
                    id: row.value.id,
                    number: row.value.number,
                    status: row.value.status,
                    epoch: row.value.epoch,
                });
            }
            // The back-off is a column of the stage run. It shows while the run waits to be tried
            // again after an attempt that ended badly.
            let backing_off = run.value.status == StageRunStatus::Ready
                && attempts.last().is_some_and(|last| {
                    matches!(
                        last.status,
                        AttemptStatus::Failed | AttemptStatus::TimedOut | AttemptStatus::LeaseLost
                    )
                });
            stage_runs.push(StageRunView {
                id: run.value.id,
                kind: run.value.kind,
                status: run.value.status,
                lease_epoch: run.value.lease_epoch,
                attempts,
                not_before: backing_off.then_some(run.value.not_before),
                human_answers: record.human_inputs.len(),
                replaced_by: timeline.replacement_of(record),
            });
        }
        tx.rollback().await?;
        Ok(JobView {
            job,
            status: stored.value.status,
            stage_runs,
            specification_rework_rounds: timeline.rework.used(ReworkTrack::Specification),
            design_rework_rounds: timeline.rework.used(ReworkTrack::Design),
            code_rework_rounds: timeline.rework.used(ReworkTrack::Code),
            documentation_rework_rounds: timeline.rework.used(ReworkTrack::Documentation),
        })
    }
}
