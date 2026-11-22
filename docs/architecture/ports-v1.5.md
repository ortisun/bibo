# Ports v1.5: the facts of the process metrics

- Status: proposed on 2026-11-21, **pending confirmation by the architect**. Specifies an addition to `ports-v1.1`, `ports-v1.2`, the troubleshooter's v1.3 (the section "Ports v1.3" of `ports-v1.2.md`) and `ports-v1.4`. The reasons, and the options that were weighed, are in the section "Where the facts of query version 2 are stored" of [process metrics and the improvement loop](process-metrics-and-improvement.md); the decision to measure is [ADR 0029](../adr/0029-process-metrics-and-improvement-loop.md).
- Form: reference. Read the design first for why, this file for what.
- What this does not change: every operation of the earlier revisions and its contract, the state machine and the schemas of `schemas/`. Two structures of the `Store` port gain one optional field each, and the transaction gains two groups of operations.
- Verified against: PostgreSQL 18 through the store contract suite, the in-memory store, and the fake GitHub server of the test kit (FX-GH, whose pull request route gained two times). **Not verified against the real GitHub.**

## 1. What changes, and where

| Item | Where | Notes |
|---|---|---|
| `MeteredUsage`, `MAX_METERED`, `AttemptEnd::metered`, `Attempt::metered` | `crates/ports/src/store.rs` | What the broker metered for an attempt, written by the move that ends it. |
| `TaskRunOps`, `NewTaskRun`, `TaskRun` | `crates/ports/src/store.rs` | One row for each run of the builder on a task. |
| `PullRequestOps`, `NewPullRequest`, `PullRequestRecord`, `StoredFate`, `PullRequestSighting` | `crates/ports/src/store.rs` | The pull requests the factory opened and what became of them. |
| `PullRequestFateSource`, `FateScope`, `ObservedPullRequest` | `crates/ports/src/pull_request_fate.rs` (new) | The read of GitHub that does not belong to a job. One operation. |
| Migration `2026-11-21-003200_process_metric_facts` | `migrations/` | Four columns of `attempts`, the tables `task_runs` and `pull_requests`, and the right of the API login to read the four tables the process snapshot is computed from. |
| The PostgreSQL adapter | `crates/storage/src/pg/attempts.rs`, `task_runs.rs` (new), `pull_requests.rs` (new) | |
| The in-memory store and the store contract suite | `crates/testkit/src/store.rs`, `contracts/store.rs` | |
| `GithubPullRequestFates`, `PermissionSet::pull_request_reader`, `TokenClass::PullRequestFate` | `crates/github/src/pull_request_fate.rs` (new), `permissions.rs`, `token.rs`, `adapter.rs` | The adapter and its credential. |
| `FakePullRequestFates`, the contract suite | `crates/testkit/src/pull_request_fate.rs`, `contracts/pull_request_fate.rs` | The fake and the suite. |
| `StageOutput::pull_request`, `OpenedPullRequest` | `crates/workflow/src/handlers/output.rs` | How the delivery stage tells the engine which pull request it opened. Not a port change; listed for completeness. |
| `TaskLedger::record_run`, `TaskRunRecord` | `crates/workflow/src/stages/implementation/seams.rs`, `crates/composition/src/ledger.rs` | The seam of the implementation stage: it records each run of the builder when the builder has stopped. Not a port change. |
| `PullRequestFateSync` | `crates/composition/src/pull_request_fates.rs` (new), `apps/worker/src/pipeline.rs`, `main.rs` | The worker step. |
| `github.follow_pull_requests` | `crates/composition/src/config.rs` | The switch. Default true. |

## 2. The store

```rust
/// The largest count or amount the store keeps: 2^53 - 1.
pub const MAX_METERED: u64 = 9_007_199_254_740_991;

/// What the model broker metered. Each value is at most `MAX_METERED`.
pub struct MeteredUsage { /* input_tokens, output_tokens, cost_micro_usd, requests */ }

pub struct AttemptEnd {
    // ... the fields of v1.1 ...
    /// What the broker metered for the attempt's token. Allowed only on a move into a terminal
    /// status. `None` when the meter was not read.
    pub metered: Option<MeteredUsage>,
}

pub struct Attempt {
    // ... the fields of v1.1 ...
    /// What the attempt used, or `None` when it has not ended or the meter was not read.
    pub metered: Option<MeteredUsage>,
}

/// One run of the builder on a task, to record.
pub struct NewTaskRun {
    pub task_node: TaskNodeId,
    pub runtime: RuntimeId,
    pub model: NonEmptyString,
    pub tier: RecommendedTier,
    /// What the broker metered for this run, or `None` when it could not be read.
    pub metered: Option<MeteredUsage>,
}

pub struct TaskRun {
    pub tenant_id: TenantId,
    pub job_id: JobId,
    pub stage_run_id: StageRunId,
    pub task_node_id: TaskNodeId,
    pub attempt_id: AttemptId,
    pub runtime: RuntimeId,
    pub model: NonEmptyString,
    pub tier: RecommendedTier,
    pub metered: Option<MeteredUsage>,
    pub recorded_at: Timestamp,
}

#[async_trait]
pub trait TaskRunOps {
    /// Records the run of the attempt of `by` on a task node.
    async fn record_task_run(&mut self, by: Fence, run: NewTaskRun) -> Result<(), StoreError>;
    /// The task runs of a stage run, in the order they were recorded.
    async fn list_task_runs(&mut self, stage_run: StageRunId) -> Result<Vec<TaskRun>, StoreError>;
}

/// A pull request a delivery stage opened.
pub struct NewPullRequest {
    pub job: JobId,
    pub repository: RepositoryId,
    pub number: u64,
}

/// What became of a pull request, as the store holds it.
pub enum StoredFate {
    Open,
    Merged { decided_at: Timestamp, recorded_at: Timestamp },
    Closed { decided_at: Timestamp, recorded_at: Timestamp },
}

pub struct PullRequestRecord {
    pub tenant_id: TenantId,
    pub job_id: JobId,
    pub repository: RepositoryId,
    pub number: u64,
    /// When the factory recorded that it was opened, by the database clock.
    pub opened_at: Timestamp,
    pub fate: StoredFate,
    /// When the factory last asked the code host about it, whatever the answer.
    pub last_checked_at: Option<Timestamp>,
}

/// What one look at the code host found.
pub enum PullRequestSighting {
    /// Still open.
    Open,
    /// Merged, at the time the code host gives.
    Merged(Timestamp),
    /// Closed without a merge, at the time the code host gives.
    Closed(Timestamp),
    /// The code host could not be read.
    Unread,
}

#[async_trait]
pub trait PullRequestOps {
    async fn record_pull_request_opened(&mut self, new: NewPullRequest) -> Result<(), StoreError>;
    /// The pull requests of a job, oldest first.
    async fn list_pull_requests(&mut self, job: JobId) -> Result<Vec<PullRequestRecord>, StoreError>;
    /// The open pull requests never looked at, or last looked at before `before`, the longest
    /// wait first, at most `limit`.
    async fn list_pull_requests_to_check(
        &mut self,
        before: Timestamp,
        limit: u32,
    ) -> Result<Vec<PullRequestRecord>, StoreError>;
    async fn record_pull_request_sighting(
        &mut self,
        repository: RepositoryId,
        number: u64,
        sighting: PullRequestSighting,
    ) -> Result<PullRequestRecord, StoreError>;
}
```

`Tx` gains `TaskRunOps` and `PullRequestOps` among its parts.

### 2.1 The contract of the metered use of an attempt

- `AttemptEnd::metered` may be set on a move into a terminal status of the attempt (`SUCCEEDED`, `FAILED`, `TIMED_OUT`, `LEASE_LOST`, `CANCELLED`) and on no other. On another move it is `Constraint(AttemptEndRule)` and nothing is written.
- It is written in the same statement as the status. An attempt that has ended keeps the value for ever: the row of a terminal attempt is not edited.
- `None` stores "not known". The store never turns it into zero, and `Attempt::metered` reads it back as `None`.
- `MeteredUsage::new` refuses a value above `MAX_METERED`, so a value the store cannot keep exactly is never offered to it.

### 2.2 The contract of a task run

**Preconditions.** A tenant transaction. The task node belongs to the stage run of the attempt of the fence.

**Postconditions.** One row for the task node and the attempt of the fence, with the job and the stage run of the node. `recorded_at` is the database's clock. `list_task_runs` returns the rows of a stage run by `recorded_at`, then by attempt.

**Errors.** `LeaseFenced` when the attempt of the fence is not live, is held by another worker or has another epoch. `NotFound` for a task node the tenant does not hold, or one of another stage run than the attempt's. `Constraint(IdReusedWithDifferentContent)` when the task node and the attempt already have a row with other content. `Constraint(TextBounds)` for a model name of more than 200 characters.

**Idempotency.** The same run a second time, with the same content, writes nothing and succeeds. A row is never changed or deleted.

**Cancellation and timeouts.** As every operation of the transaction: a dropped call poisons it.

### 2.3 The contract of a pull request

**Preconditions.** A tenant transaction. The job and the repository belong to the tenant, and the repository is the job's.

**Postconditions.**

- `record_pull_request_opened` makes one row with the fate `Open`, `opened_at` at the database's clock and no look yet.
- `record_pull_request_sighting` sets `last_checked_at` to the database's clock for every sighting. `Merged` and `Closed` also set the fate, with `recorded_at` at the database's clock, **when the row is still open**. A row that already has a fate keeps it: the first decision is final, and a later sighting changes nothing but the time of the look. The row comes back as it stands after the call.
- `list_pull_requests_to_check` never returns a row with a fate.

**Errors.** `NotFound` for a job or a pull request the tenant does not hold, and for a repository that is not the job's. `Constraint(IdReusedWithDifferentContent)` when the same repository and number are recorded for another job. `Constraint(TextBounds)` for a number of zero or above `MAX_METERED`.

**Idempotency.** `record_pull_request_opened` with the same job, repository and number a second time writes nothing and succeeds, whatever the fate of the row is by then. A sighting may be repeated.

## 3. The read of the code host

```rust
/// What a look may touch. A credential is minted for exactly this. No stage and no job.
pub struct FateScope {
    pub tenant: TenantId,
    /// The identifier the credential is kept under and ended by (`revoke_job_tokens`).
    /// Not a job: a fresh identifier for each pass.
    pub session: JobId,
    pub repo: RepoRef,
}

/// What the code host says about a pull request now. Built only by `OPEN`, `merged(at)` and
/// `closed(at)`, so it has a time exactly when the pull request was decided.
pub struct ObservedPullRequest { /* lifecycle, decided_at */ }

#[async_trait]
pub trait PullRequestFateSource: Send + Sync {
    fn fidelity(&self) -> Fidelity;

    /// Reads one pull request. It writes nothing.
    async fn observe(
        &self,
        scope: &FateScope,
        pr: &PullRequestRef,
    ) -> Result<ObservedPullRequest, GitHostError>;
}
```

**Preconditions.** The scope names the tenant and the repository of the pull request.

**Postconditions.** A merged pull request is `Merged` with the time of the merge; a pull request closed without a merge is `Closed` with the time of the close; an open one is `Open` with no time. A merged or closed pull request for which the code host gives no time, or a time that cannot be read, is an error and not a fate without a time.

**Errors.** `GitHostError`: `NotFound` for a pull request or a repository the scope does not cover, `Forbidden` when the credential lacks the permission, `RateLimited` and `Unavailable` for the host, and `Unavailable` for an answer that cannot be read.

**Idempotency.** A read.

**Cancellation and timeouts.** Safe to drop. The adapter sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.

### 3.1 The credential

`PermissionSet::pull_request_reader`: `metadata: read` and `pull_requests: read`, for one repository, minted under `TokenClass::PullRequestFate`, which does not depend on a stage. The minter checks the answer of GitHub against the request as for every token. The GitHub App already holds `pull_requests: write` for the delivery stage, so it needs no new permission. No stage holds this set and nothing a sandbox sees carries it.

## 4. The worker step

`PullRequestFateSync` (composition) runs before each claim, for each tenant the worker serves, and at most once every five minutes for a tenant:

1. It lists up to 20 open pull requests that were never looked at or were last looked at more than an hour ago (`list_pull_requests_to_check`).
2. For each, it reads the repository's name from its row, asks the code host (`observe`) and records the sighting. A look that fails is recorded as `Unread`.
3. It ends the credential of the pass.

It never fails a claim or a job: a failure is logged and the next pass tries again. It writes no audit record: it reads the code host and records a fact, and decides nothing. `github.follow_pull_requests: false` turns it off; the pull requests then stay open in the store and the metrics MT-0011 and MT-0012 show too few samples.
