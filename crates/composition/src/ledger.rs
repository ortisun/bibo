//! The `TaskLedger` seam of the implementation stage, over `TaskNodeOps` of the real store.
//!
//! A node of the plan is a row of `task_nodes`. This type is the only code that moves one. Each
//! call opens a tenant transaction, applies the moves of the task machine (`T01` to `T06`) with
//! the guard that clears each, and commits, so a crash between two calls leaves the rows in a
//! state the next attempt can read and continue from.
//!
//! # The fence
//!
//! A move of a node that an attempt makes (`T02` to `T05`) carries a [`Fence`]: the attempt, the
//! epoch of its lease and the worker that holds it. The stage hands over a [`Hold`], which is the
//! attempt and the epoch, and the worker is read from the attempt row. Two checks refuse a worker
//! that lost its lease:
//!
//! 1. before any write, the guard `G_EPOCH_CURRENT` compares the epoch in the hold with the epoch
//!    stored on the attempt, and an older epoch is [`LedgerError::Fenced`];
//! 2. the store applies the move only if the fence names a live attempt of the same worker and
//!    epoch, and answers `LeaseFenced` otherwise, which is mapped to the same error.
//!
//! The ledger never passes `None` for a move that needs a fence. The deliberate break in
//! `tests/ledger.rs` shows the store refusing exactly that.
//!
//! # What the ledger does not decide
//!
//! `G_TASK_EVIDENCE_RECORDED` (`T03`) asks whether the commit exists, whether every changed path is
//! inside the task's owned files, whether a protected path changed and whether the per-task checks
//! passed. The stage checks all four before it calls [`TaskLedger::finish`] (it has the workspace
//! and the plan), and the ledger writes down that it was told so. The per-task retry limit is not
//! in any policy file, so it is a setting of this type (see the README, "Decisions that need
//! review").

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::TaskNodeId;
use factory_domain::machines::guards::{
    EpochFacts, GuardCleared, GuardFacts, TaskDepsFacts, TaskEvidenceFacts, TaskRetryFacts,
    TaskStartFacts, evaluate,
};
use factory_domain::scope::TenantScope;
use factory_domain::state::{AttemptStatus, Guard, TaskNodeEvent, TaskNodeStatus};
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::paths::CommitSha;
use factory_ports::store::{
    AppliedTransition, Fence, NewTaskGraph, NewTaskNode, NewTaskRun, Store, StoreError, TaskNode,
    TaskNodeEffects, Tx, Versioned,
};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::implementation::seams::{
    Hold, LedgerError, PlannedTask, TaskLedger, TaskRecord, TaskRunRecord,
};

/// The default number of times a failed task is retried.
///
/// The policy files name no per-task limit. Two matches the rework cap of ADR 0009 item 6. A
/// person who wants another number passes it to [`StoreTaskLedger::with_retry_limit`].
pub const DEFAULT_TASK_RETRIES: u32 = 2;

/// The task ledger over the store.
pub struct StoreTaskLedger {
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    retry_limit: u32,
}

impl StoreTaskLedger {
    /// A ledger over `store`, with the default retry limit.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self {
            store,
            clock,
            ids,
            retry_limit: DEFAULT_TASK_RETRIES,
        }
    }

    /// The same ledger with another per-task retry limit.
    #[must_use]
    pub fn with_retry_limit(mut self, retries: u32) -> Self {
        self.retry_limit = retries;
        self
    }

    async fn begin(&self, run: &RunIdentity) -> Result<Box<dyn Tx>, LedgerError> {
        self.store
            .begin(TenantScope::new(run.tenant))
            .await
            .map_err(map)
    }

    /// Commits when `outcome` is `Ok` and rolls back when it is not.
    async fn settle<T>(tx: Box<dyn Tx>, outcome: Result<T, LedgerError>) -> Result<T, LedgerError> {
        match outcome {
            Ok(value) => {
                tx.commit().await.map_err(map)?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    /// The fence for a hold, with the proof that the guard compared the epoch of the hold with the
    /// one stored on the attempt and found them equal.
    async fn fence(tx: &mut dyn Tx, hold: &Hold) -> Result<(Fence, GuardCleared), LedgerError> {
        let attempt = tx.get_attempt(hold.attempt).await.map_err(map)?.value;
        let facts = EpochFacts {
            sent_epoch: hold.epoch.get(),
            stored_epoch: attempt.epoch.get(),
        };
        let cleared = evaluate(Guard::EpochCurrent, &GuardFacts::Epoch(facts))
            .map_err(|_| LedgerError::Fenced)?;
        if !matches!(
            attempt.status,
            AttemptStatus::Starting | AttemptStatus::Running
        ) {
            return Err(LedgerError::Fenced);
        }
        let fence = Fence {
            attempt: hold.attempt,
            epoch: hold.epoch,
            worker: attempt.worker,
        };
        Ok((fence, cleared))
    }

    async fn node(
        tx: &mut dyn Tx,
        run: &RunIdentity,
        task: &Slug,
    ) -> Result<Versioned<TaskNode>, LedgerError> {
        tx.list_task_nodes(run.stage_run)
            .await
            .map_err(map)?
            .into_iter()
            .find(|node| &node.value.key == task)
            .ok_or(LedgerError::Illegal)
    }

    async fn apply(
        &self,
        tx: &mut dyn Tx,
        node: &Versioned<TaskNode>,
        event: TaskNodeEvent,
        cleared: GuardCleared,
        fence: Option<Fence>,
        effects: TaskNodeEffects,
    ) -> Result<Versioned<TaskNode>, LedgerError> {
        let planned = AppliedTransition::plan(node.value.status, event, self.clock.now(), cleared)
            .map_err(|_| LedgerError::Illegal)?;
        let to = planned.to_status();
        let version = tx
            .transition_task_node(node.value.id, node.version, fence, planned, effects)
            .await
            .map_err(map)?;
        Ok(Versioned {
            value: TaskNode {
                status: to,
                ..node.value.clone()
            },
            version,
        })
    }

    async fn start_in(
        &self,
        tx: &mut dyn Tx,
        run: &RunIdentity,
        task: &Slug,
        hold: &Hold,
    ) -> Result<(), LedgerError> {
        let (fence, epoch_cleared) = Self::fence(tx, hold).await?;
        let mut node = Self::node(tx, run, task).await?;
        // Bring the node to READY: first `T01` for a node that waited for its dependencies, `T06`
        // for one that failed, `T05` for one that an earlier attempt left RUNNING.
        match node.value.status {
            TaskNodeStatus::Pending => {
                let statuses = Self::dependency_statuses(tx, run, &node).await?;
                let cleared = evaluate(
                    Guard::TaskDepsSucceeded,
                    &GuardFacts::TaskDeps(TaskDepsFacts {
                        dependencies: &statuses,
                    }),
                )
                .map_err(|_| LedgerError::Illegal)?;
                node = self
                    .apply(
                        tx,
                        &node,
                        TaskNodeEvent::DependenciesSatisfied,
                        cleared,
                        None,
                        TaskNodeEffects::default(),
                    )
                    .await?;
            }
            TaskNodeStatus::Failed => {
                let cleared = evaluate(
                    Guard::TaskRetryAllowed,
                    &GuardFacts::TaskRetry(TaskRetryFacts {
                        retries_used: node.value.retry_count,
                        per_task_limit: self.retry_limit,
                        stage_budget_has_room: true,
                    }),
                )
                .map_err(|_| LedgerError::Illegal)?;
                node = self
                    .apply(
                        tx,
                        &node,
                        TaskNodeEvent::RetryTask,
                        cleared,
                        None,
                        TaskNodeEffects::default(),
                    )
                    .await?;
            }
            TaskNodeStatus::Running => {
                node = self
                    .apply(
                        tx,
                        &node,
                        TaskNodeEvent::AttemptInterrupted,
                        epoch_cleared,
                        Some(fence.clone()),
                        TaskNodeEffects::default(),
                    )
                    .await?;
            }
            TaskNodeStatus::Ready => {}
            TaskNodeStatus::Succeeded | TaskNodeStatus::Cancelled => {
                return Err(LedgerError::Illegal);
            }
        }
        // `T02`. The stage picks the next task in topological order, so this node is the one.
        let cleared = evaluate(
            Guard::TaskStartedByAttempt,
            &GuardFacts::TaskStart(TaskStartFacts {
                this_task: node.value.id,
                next_in_topological_order: Some(node.value.id),
            }),
        )
        .map_err(|_| LedgerError::Illegal)?;
        self.apply(
            tx,
            &node,
            TaskNodeEvent::Start,
            cleared,
            Some(fence),
            TaskNodeEffects {
                attempt: Some(hold.attempt),
                commit: None,
            },
        )
        .await?;
        Ok(())
    }

    async fn dependency_statuses(
        tx: &mut dyn Tx,
        run: &RunIdentity,
        node: &Versioned<TaskNode>,
    ) -> Result<Vec<TaskNodeStatus>, LedgerError> {
        let nodes = tx.list_task_nodes(run.stage_run).await.map_err(map)?;
        let edges = tx.task_dependencies(run.stage_run).await.map_err(map)?;
        let status_of = |id: TaskNodeId| {
            nodes
                .iter()
                .find(|other| other.value.id == id)
                .map(|other| other.value.status)
        };
        edges
            .into_iter()
            .filter(|(from, _)| *from == node.value.id)
            .map(|(_, on)| status_of(on).ok_or(LedgerError::Unavailable))
            .collect()
    }
}

/// A store error as the closed set of the ledger.
fn map(error: StoreError) -> LedgerError {
    match error {
        StoreError::LeaseFenced => LedgerError::Fenced,
        StoreError::Constraint(_) | StoreError::NotFound => LedgerError::Illegal,
        _ => LedgerError::Unavailable,
    }
}

fn record(node: &TaskNode) -> TaskRecord {
    TaskRecord {
        key: node.key.clone(),
        status: node.status,
        commit: node.commit.clone(),
    }
}

#[async_trait]
impl TaskLedger for StoreTaskLedger {
    fn fidelity(&self) -> Fidelity {
        self.store.fidelity()
    }

    async fn open(
        &self,
        run: &RunIdentity,
        plan: &Sha256Digest,
        tasks: &[PlannedTask],
    ) -> Result<Vec<TaskRecord>, LedgerError> {
        let mut tx = self.begin(run).await?;
        let graph = NewTaskGraph {
            stage_run: run.stage_run,
            plan_sha256: plan.clone(),
            nodes: tasks
                .iter()
                .map(|task| NewTaskNode {
                    id: TaskNodeId::from_uuid(self.ids.new_uuid()),
                    key: task.key.clone(),
                    depends_on: task.depends_on.clone(),
                })
                .collect(),
        };
        let stored = tx.insert_task_graph(graph).await.map_err(map);
        let outcome = stored.and_then(|nodes| {
            // The order of `tasks`, whatever order the store returned them in.
            tasks
                .iter()
                .map(|task| {
                    nodes
                        .iter()
                        .find(|node| node.value.key == task.key)
                        .map(|node| record(&node.value))
                        .ok_or(LedgerError::Unavailable)
                })
                .collect::<Result<Vec<_>, _>>()
        });
        Self::settle(tx, outcome).await
    }

    async fn start(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError> {
        let mut tx = self.begin(run).await?;
        let outcome = self.start_in(&mut *tx, run, task, hold).await;
        Self::settle(tx, outcome).await
    }

    async fn confirm(&self, run: &RunIdentity, hold: &Hold) -> Result<(), LedgerError> {
        let mut tx = self.begin(run).await?;
        let outcome = async {
            let _ = Self::fence(&mut *tx, hold).await?;
            let stage_run = tx.get_stage_run(run.stage_run).await.map_err(map)?.value;
            if stage_run.lease_epoch == hold.epoch {
                Ok(())
            } else {
                Err(LedgerError::Fenced)
            }
        }
        .await;
        // A read: nothing to commit.
        let _ = tx.rollback().await;
        outcome
    }

    async fn record_run(
        &self,
        run: &RunIdentity,
        task: &Slug,
        hold: &Hold,
        ran: &TaskRunRecord,
    ) -> Result<(), LedgerError> {
        let mut tx = self.begin(run).await?;
        let outcome = async {
            let (fence, _) = Self::fence(&mut *tx, hold).await?;
            let node = Self::node(&mut *tx, run, task).await?;
            tx.record_task_run(
                fence,
                NewTaskRun {
                    task_node: node.value.id,
                    runtime: ran.runtime.clone(),
                    model: ran.model.clone(),
                    tier: ran.tier,
                    metered: ran.metered,
                },
            )
            .await
            .map_err(map)
        }
        .await;
        Self::settle(tx, outcome).await
    }

    async fn finish(
        &self,
        run: &RunIdentity,
        task: &Slug,
        commit: &CommitSha,
        hold: &Hold,
    ) -> Result<(), LedgerError> {
        let mut tx = self.begin(run).await?;
        let outcome = async {
            let (fence, _) = Self::fence(&mut *tx, hold).await?;
            let node = Self::node(&mut *tx, run, task).await?;
            // The stage checked these before it called: see the module note.
            let cleared = evaluate(
                Guard::TaskEvidenceRecorded,
                &GuardFacts::TaskEvidence(TaskEvidenceFacts {
                    commit_exists_for_task: true,
                    changed_paths_inside_owned_files: true,
                    protected_path_changed: false,
                    per_task_checks_passed: true,
                }),
            )
            .map_err(|_| LedgerError::Illegal)?;
            self.apply(
                &mut *tx,
                &node,
                TaskNodeEvent::TaskSucceeded,
                cleared,
                Some(fence),
                TaskNodeEffects {
                    attempt: None,
                    commit: Some(commit.clone()),
                },
            )
            .await
            .map(|_| ())
        }
        .await;
        Self::settle(tx, outcome).await
    }

    async fn fail(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError> {
        let mut tx = self.begin(run).await?;
        let outcome = async {
            let (fence, cleared) = Self::fence(&mut *tx, hold).await?;
            let node = Self::node(&mut *tx, run, task).await?;
            self.apply(
                &mut *tx,
                &node,
                TaskNodeEvent::TaskFailed,
                cleared,
                Some(fence),
                TaskNodeEffects::default(),
            )
            .await
            .map(|_| ())
        }
        .await;
        Self::settle(tx, outcome).await
    }
}
