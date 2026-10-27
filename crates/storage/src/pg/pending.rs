//! TEMPORARY: the aggregates that are not adapted to ports v1.1 yet answer `Unavailable`.
//!
//! This file shrinks with every commit of the work package `s1-storage-postgres` and is deleted
//! by the last one. Nothing outside this work package may rely on it.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::{DomainEvent, EvidenceLedgerEntry};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TaskNodeId};
use factory_domain::ledger::ChainHead;
use factory_domain::state::{AttemptStatus, StageRunStatus, TaskNodeStatus};
use factory_domain::values::{GitSha, Sha256Digest, Slug};
use factory_ports::store::{
    AppliedTransition, Approval, ApprovalInvalidation, ApprovalOps, ArtifactDirection,
    ArtifactIndexEntry, ArtifactIndexOps, Attempt, AttemptEnd, AttemptOps, AuditFilter, AuditOps,
    AuditRecord, Fence, Inserted, LeaseEpoch, LeaseRenewal, LedgerOps, NewApproval,
    NewArtifactIndexEntry, NewAuditEvent, NewStageRun, NewTaskGraph, OutboxOps, OutboxRow,
    OutboxSeq, SandboxRecord, Sequence, StageArtifactOps, StageRun, StageRunArtifact,
    StageRunEffects, StageRunOps, StartAttempt, StartedAttempt, StoreError, TaskNode,
    TaskNodeEffects, TaskNodeOps, Version, Versioned,
};

use super::tx::PgTx;

#[async_trait]
impl TaskNodeOps for PgTx {
    async fn insert_task_graph(
        &mut self,
        _graph: NewTaskGraph,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn get_task_node(&mut self, _id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn list_task_nodes(
        &mut self,
        _stage_run: StageRunId,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn task_dependencies(
        &mut self,
        _stage_run: StageRunId,
    ) -> Result<Vec<(TaskNodeId, TaskNodeId)>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn transition_task_node(
        &mut self,
        _id: TaskNodeId,
        _expected: Version,
        _by: Option<Fence>,
        _t: AppliedTransition<TaskNodeStatus>,
        _effects: TaskNodeEffects,
    ) -> Result<Version, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[async_trait]
impl StageArtifactOps for PgTx {
    async fn link_stage_run_artifact(
        &mut self,
        _stage_run: StageRunId,
        _direction: ArtifactDirection,
        _role: Slug,
        _sha256: Sha256Digest,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn list_stage_run_artifacts(
        &mut self,
        _stage_run: StageRunId,
    ) -> Result<Vec<StageRunArtifact>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn stage_runs_consuming(
        &mut self,
        _job: JobId,
        _sha256: &Sha256Digest,
    ) -> Result<Vec<StageRunId>, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[async_trait]
impl ApprovalOps for PgTx {
    async fn record_approval(
        &mut self,
        _new: NewApproval,
    ) -> Result<Inserted<Approval>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn list_approvals(&mut self, _job: JobId) -> Result<Vec<Approval>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn valid_approvals(
        &mut self,
        _job: JobId,
        _head: &GitSha,
    ) -> Result<Vec<Approval>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn invalidate_approvals(
        &mut self,
        _job: JobId,
        _reason: ApprovalInvalidation,
    ) -> Result<u32, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[async_trait]
impl LedgerOps for PgTx {
    async fn append_ledger_entry(
        &mut self,
        _entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn ledger_head(&mut self, _job: JobId) -> Result<Option<ChainHead>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn read_ledger(
        &mut self,
        _job: JobId,
        _from: Sequence,
        _limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[async_trait]
impl OutboxOps for PgTx {
    async fn enqueue_event(&mut self, _event: DomainEvent) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn read_events(
        &mut self,
        _job: JobId,
        _from: OutboxSeq,
        _limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[async_trait]
impl AuditOps for PgTx {
    async fn record_audit(&mut self, _event: NewAuditEvent) -> Result<AuditRecord, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn read_audit(
        &mut self,
        _filter: AuditFilter,
        _after_sequence: u64,
        _limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[async_trait]
impl ArtifactIndexOps for PgTx {
    async fn index_artifact(
        &mut self,
        _new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn get_artifact_index(
        &mut self,
        _sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        Err(StoreError::Unavailable)
    }
}
