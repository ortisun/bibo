//! An in-memory `Store` that keeps the rules the database keeps (ports-v1.1, ADR 0014).
//!
//! A fake that is easier than the real thing teaches the engine habits the database then punishes,
//! so this one enforces what the migrations enforce and what the port documents:
//!
//! * **Snapshot transactions.** A transaction works on a copy of the committed rows. Commit is a
//!   three-way merge: a row that changed in the transaction must still be, in the committed state,
//!   what it was when the transaction began, or the commit is a `Conflict` (first committer wins).
//! * **The claim.** `SystemTx::find_claim_candidates` only reads. `AttemptOps::start_attempt` is
//!   the one operation that creates an attempt and raises the epoch. It re-reads the *committed*
//!   stage run, so two workers that found the same candidate get one winner and one `Conflict`.
//! * **Tenant scope.** A row of another tenant looks like a missing row.
//! * **Idempotent inserts.** A repeat with the same id and content returns the first row.
//! * **A dropped call poisons its transaction.** The next call returns `Unavailable`.
//! * **An unknown commit outcome** can be provoked with a lever and resolved with
//!   `Store::committed`.
//!
//! Every deliberate defect is listed in [`StoreDefect`], with the checks that must catch it in
//! [`DEFECTS`]. The tests in `crates/testkit/tests/` and `contract_register` use that table.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, DomainEvent, EvidenceLedgerEntry};
use factory_domain::ids::{
    ApprovalId, AttemptId, JobId, PrincipalId, RepositoryId, StageRunId, TaskNodeId, TenantId,
};
use factory_domain::ledger::ChainHead;
use factory_domain::scope::{PlatformScope, ResolvedPrincipal, ResolvedRepository, TenantScope};
use factory_domain::state::{AttemptStatus, JobStatus, StageRunStatus, Status, TaskNodeStatus};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_ports::store::*;

/// The schema version the fake reports.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(14);

/// The tenant under which `record_platform_audit` writes. No transaction can be opened for it.
#[must_use]
pub fn platform_tenant() -> TenantId {
    TenantId::parse("ffffffff-ffff-7fff-bfff-ffffffffffff").expect("a valid tenant id")
}

/// A deliberate defect of the fake. Each one breaks one documented rule, so the contract suite
/// can be shown to fail when the rule is broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreDefect {
    /// `find_claim_candidates` returns stage runs of jobs that are not `ACTIVE`.
    ClaimsForInactiveJob,
    /// `find_claim_candidates` ignores `not_before`.
    IgnoresNotBefore,
    /// `start_attempt` trusts its own snapshot, so two workers can both start the same run.
    DoubleStartsAttempt,
    /// `start_attempt` raises the epoch and moves the run but creates no attempt.
    SplitsStart,
    /// `start_attempt` starts work for a job that is not `ACTIVE`.
    StartsForInactiveJob,
    /// `start_attempt` allows a second live attempt of one stage run.
    AllowsTwoLiveAttempts,
    /// `start_attempt` ignores the attempt limit.
    IgnoresAttemptLimit,
    /// `start_attempt` wraps the epoch at its maximum instead of failing.
    WrapsTheEpoch,
    /// `start_attempt` ignores `not_before` after a retry back-off.
    IgnoresBackOff,
    /// `heartbeat` renews a lease that already lapsed.
    RevivesLapsedLease,
    /// A fence from another worker name is accepted.
    IgnoresWorkerName,
    /// A write with an old epoch is accepted.
    IgnoresLeaseEpoch,
    /// `find_due_attempts` misses attempts past their deadline.
    MissesDeadline,
    /// `find_due_attempts` misses attempts past their teardown deadline.
    MissesTeardown,
    /// `find_due_attempts` misses attempts whose lease ended.
    MissesLeaseExpiry,
    /// An insert of an existing id and content makes a second row.
    DuplicatesOnReplay,
    /// An insert of an existing id with other content overwrites the row.
    OverwritesOnReplay,
    /// A second job with the same origin is created instead of returning the first.
    IgnoresOrigin,
    /// `committed` always says no, although the commit was applied.
    LosesWitness,
    /// A transaction keeps working after one of its calls was dropped.
    ContinuesAfterDrop,
    /// A move to `PASSED` is accepted with no gate record.
    AcceptsPassedWithoutOutcome,
    /// A failed attempt is accepted with no failure class.
    AcceptsFailedWithoutClass,
    /// A terminal row can be edited.
    EditsTerminalRows,
    /// Two task nodes of one plan may share a key.
    AllowsDuplicateTaskKey,
    /// A task graph with a cycle is accepted.
    AllowsCycle,
    /// A task node moves without a current fence.
    IgnoresTaskFence,
    /// `read_audit` ignores its limit.
    IgnoresAuditLimit,
    /// An audit event with no job is refused.
    RequiresJobForAudit,
    /// The platform audit event is written under the caller's tenant instead.
    WritesToCallerTenant,
    /// A repeated delivery is an error instead of a `Duplicate`.
    ErrorsOnRepeat,
    /// A stored original request revision can be edited.
    EditsRequest,
    /// An approval counts for any head.
    IgnoresHead,
    /// An approval counts after it expired.
    IgnoresExpiry,
    /// A lookup that finds nothing says why through the error.
    RevealsReason,
    /// A tenant sees the rows of other tenants.
    ReadsAcrossTenants,
    /// A write with a stale version is accepted.
    SkipsVersionCheck,
    /// The last outbox row of a transaction is lost.
    LosesLastOutboxRow,
    /// Events read back in reverse order.
    ReversesOutboxOrder,
    /// A ledger entry that does not extend the chain is accepted.
    AcceptsBrokenChain,
    /// Writes of a transaction that was dropped stay.
    KeepsWritesOnDrop,
    /// An event that names another tenant is accepted.
    AcceptsForeignTenantEvent,
    /// `find_claim_candidates` sees only the first tenant's stage runs.
    FindsOnlyFirstTenant,
    /// `find_claim_candidates` ignores its limit.
    IgnoresCandidateLimit,
    /// The claim lock of a dropped transaction is never released.
    KeepsClaimLockOnRollback,
    /// A ledger position that is taken is reported as a broken chain, not a conflict.
    ReusesLedgerPosition,
    /// Commit does not check that the rows it writes are still what the transaction saw.
    SkipsCommitMerge,
    /// `database_time` does not move.
    FrozenDatabaseTime,
}

/// Each defect and the checks of `contracts::store` that must fail when the fake has it.
pub const DEFECTS: &[(StoreDefect, &[&str])] = &[
    (
        StoreDefect::ClaimsForInactiveJob,
        &["a_candidate_is_found_only_for_an_active_job"],
    ),
    (
        StoreDefect::IgnoresNotBefore,
        &["a_candidate_is_found_only_after_not_before"],
    ),
    (
        StoreDefect::DoubleStartsAttempt,
        &["two_workers_find_one_candidate_and_one_start_wins"],
    ),
    (
        StoreDefect::SplitsStart,
        &["start_attempt_raises_the_epoch_by_one_and_creates_the_attempt_together"],
    ),
    (
        StoreDefect::StartsForInactiveJob,
        &["start_attempt_refuses_a_job_that_is_not_active"],
    ),
    (
        StoreDefect::AllowsTwoLiveAttempts,
        &["start_attempt_refuses_a_second_live_attempt"],
    ),
    (
        StoreDefect::IgnoresAttemptLimit,
        &["start_attempt_refuses_past_the_attempt_limit"],
    ),
    (
        StoreDefect::WrapsTheEpoch,
        &["start_attempt_fails_at_the_largest_epoch"],
    ),
    (
        StoreDefect::IgnoresBackOff,
        &["a_retry_is_findable_after_its_back_off_and_not_before"],
    ),
    (
        StoreDefect::RevivesLapsedLease,
        &["a_heartbeat_cannot_revive_a_lapsed_lease"],
    ),
    (
        StoreDefect::IgnoresWorkerName,
        &["a_fence_from_another_worker_name_is_refused"],
    ),
    (
        StoreDefect::IgnoresLeaseEpoch,
        &[
            "a_zombie_worker_is_fenced_after_another_worker_takes_over",
            "a_zombie_cannot_change_its_attempt",
        ],
    ),
    (
        StoreDefect::MissesDeadline,
        &["due_attempts_cover_lease_deadline_and_teardown"],
    ),
    (
        StoreDefect::MissesTeardown,
        &["due_attempts_cover_lease_deadline_and_teardown"],
    ),
    (
        StoreDefect::MissesLeaseExpiry,
        &["due_attempts_cover_lease_deadline_and_teardown"],
    ),
    (
        StoreDefect::DuplicatesOnReplay,
        &["an_insert_is_idempotent_by_id_and_content"],
    ),
    (
        StoreDefect::OverwritesOnReplay,
        &["the_same_id_with_other_content_is_refused"],
    ),
    (
        StoreDefect::IgnoresOrigin,
        &["a_job_is_found_by_its_origin"],
    ),
    (
        StoreDefect::LosesWitness,
        &["an_unknown_commit_outcome_is_resolved_by_the_witness"],
    ),
    (
        StoreDefect::ContinuesAfterDrop,
        &["a_dropped_call_poisons_the_transaction"],
    ),
    (
        StoreDefect::AcceptsPassedWithoutOutcome,
        &["the_gate_record_is_required_where_the_table_says"],
    ),
    (
        StoreDefect::AcceptsFailedWithoutClass,
        &["the_attempt_end_is_required_where_the_table_says"],
    ),
    (
        StoreDefect::EditsTerminalRows,
        &["a_terminal_row_is_not_edited"],
    ),
    (
        StoreDefect::AllowsDuplicateTaskKey,
        &["a_duplicate_task_key_is_refused"],
    ),
    (StoreDefect::AllowsCycle, &["a_task_graph_cycle_is_refused"]),
    (
        StoreDefect::IgnoresTaskFence,
        &["a_task_move_needs_a_current_fence"],
    ),
    (
        StoreDefect::IgnoresAuditLimit,
        &["the_audit_limit_is_honoured"],
    ),
    (
        StoreDefect::RequiresJobForAudit,
        &["an_audit_event_with_no_job_is_stored_and_read"],
    ),
    (
        StoreDefect::WritesToCallerTenant,
        &["the_platform_audit_event_lands_under_the_platform_tenant_only"],
    ),
    (
        StoreDefect::ErrorsOnRepeat,
        &["a_delivery_repeat_is_a_duplicate_not_an_error"],
    ),
    (
        StoreDefect::EditsRequest,
        &["an_original_request_revision_is_immutable"],
    ),
    (
        StoreDefect::IgnoresHead,
        &["an_approval_counts_only_for_its_head_and_until_it_expires"],
    ),
    (
        StoreDefect::IgnoresExpiry,
        &["an_approval_counts_only_for_its_head_and_until_it_expires"],
    ),
    (
        StoreDefect::RevealsReason,
        &["a_lookup_miss_is_none_for_every_reason"],
    ),
    (
        StoreDefect::ReadsAcrossTenants,
        &[
            "a_row_of_another_tenant_looks_like_a_missing_row",
            "a_tenant_cannot_read_another_tenants_row_through_any_new_method",
        ],
    ),
    (
        StoreDefect::SkipsVersionCheck,
        &["a_stale_version_conflicts_and_changes_nothing"],
    ),
    (
        StoreDefect::LosesLastOutboxRow,
        &[
            "events_read_back_in_the_order_they_were_queued",
            "status_ledger_and_outbox_commit_together_or_not_at_all",
        ],
    ),
    (
        StoreDefect::ReversesOutboxOrder,
        &["events_read_back_in_the_order_they_were_queued"],
    ),
    (
        StoreDefect::AcceptsBrokenChain,
        &["a_ledger_entry_that_does_not_extend_the_chain_is_refused"],
    ),
    (
        StoreDefect::KeepsWritesOnDrop,
        &["writes_are_invisible_until_commit_and_vanish_on_drop"],
    ),
    (
        StoreDefect::AcceptsForeignTenantEvent,
        &["an_event_naming_the_wrong_tenant_is_refused"],
    ),
    (
        StoreDefect::FindsOnlyFirstTenant,
        &["a_system_transaction_finds_work_in_every_tenant"],
    ),
    (
        StoreDefect::IgnoresCandidateLimit,
        &["candidates_go_oldest_first_and_honour_the_limit"],
    ),
    (
        StoreDefect::KeepsClaimLockOnRollback,
        &["a_rolled_back_start_leaves_the_stage_run_startable"],
    ),
    (
        StoreDefect::ReusesLedgerPosition,
        &["a_ledger_position_can_be_taken_only_once"],
    ),
    (
        StoreDefect::SkipsCommitMerge,
        &["two_open_transactions_cannot_both_extend_the_chain"],
    ),
    (
        StoreDefect::FrozenDatabaseTime,
        &["database_time_follows_the_subjects_clock"],
    ),
];

// ---------------------------------------------------------------------------------------------
// Rows and tables
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
struct Row<T> {
    value: T,
    version: Version,
}

impl<T: Clone> Row<T> {
    fn versioned(&self) -> Versioned<T> {
        Versioned {
            value: self.value.clone(),
            version: self.version,
        }
    }
}

/// A recorded webhook delivery, with the tenant that owns it.
#[derive(Clone, Debug, PartialEq)]
struct Delivery {
    tenant: TenantId,
    row: NewWebhookDelivery,
}

#[derive(Clone, Debug, PartialEq)]
struct StoredEvent {
    seq: OutboxSeq,
    tenant: TenantId,
    event: DomainEvent,
}

#[derive(Clone, Default, Debug)]
struct Tables {
    jobs: BTreeMap<JobId, Row<Job>>,
    requests: BTreeMap<(JobId, u32), (TenantId, OriginalRequest)>,
    deliveries: Vec<Delivery>,
    repositories: BTreeMap<RepositoryId, Row<Repository>>,
    stage_runs: BTreeMap<StageRunId, Row<StageRun>>,
    attempts: BTreeMap<AttemptId, Row<Attempt>>,
    task_nodes: BTreeMap<TaskNodeId, Row<TaskNode>>,
    task_deps: BTreeMap<StageRunId, Vec<(TaskNodeId, TaskNodeId)>>,
    stage_artifacts: Vec<(TenantId, StageRunArtifact)>,
    approvals: BTreeMap<ApprovalId, (TenantId, Approval)>,
    principals: BTreeMap<PrincipalId, Principal>,
    ledger: BTreeMap<JobId, Vec<EvidenceLedgerEntry>>,
    outbox: Vec<StoredEvent>,
    audit: BTreeMap<TenantId, Vec<AuditRecord>>,
    index: BTreeMap<(TenantId, Sha256Digest), ArtifactIndexEntry>,
}

/// Checks that every changed or new entry of `work` is still, in `committed`, what it was in
/// `base`; returns the entries to write.
fn changed<K: Ord + Clone, V: PartialEq + Clone>(
    committed: &BTreeMap<K, V>,
    base: &BTreeMap<K, V>,
    work: &BTreeMap<K, V>,
    check: bool,
) -> Result<Vec<(K, V)>, StoreError> {
    let mut out = Vec::new();
    for (key, value) in work {
        if base.get(key) == Some(value) {
            continue;
        }
        let now = committed.get(key);
        if check && now != base.get(key) && now != Some(value) {
            return Err(StoreError::Conflict);
        }
        out.push((key.clone(), value.clone()));
    }
    Ok(out)
}

#[derive(Default)]
struct Shared {
    committed: Tables,
    next_outbox: u64,
    next_tx: u64,
    /// Stage runs that an open transaction has started an attempt for.
    claims: BTreeMap<StageRunId, u64>,
    tokens: Vec<(TokenHash, Audience, ResolvedPrincipal)>,
    installations: Vec<(InstallationId, GithubRepositoryId, ResolvedRepository)>,
    stall_next: bool,
    lose_commit_answer: bool,
}

struct Inner {
    clock: Arc<dyn Clock>,
    defect: Option<StoreDefect>,
    shared: Mutex<Shared>,
}

/// The in-memory store.
#[derive(Clone)]
pub struct InMemoryStore {
    inner: Arc<Inner>,
}

fn lock(inner: &Inner) -> MutexGuard<'_, Shared> {
    inner
        .shared
        .lock()
        .expect("the store lock is never poisoned")
}

impl InMemoryStore {
    /// A store whose database time is the given clock's time.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::build(clock, None)
    }

    /// A store with one deliberate defect.
    #[must_use]
    pub fn with_defect(clock: Arc<dyn Clock>, defect: StoreDefect) -> Self {
        Self::build(clock, Some(defect))
    }

    fn build(clock: Arc<dyn Clock>, defect: Option<StoreDefect>) -> Self {
        Self {
            inner: Arc::new(Inner {
                clock,
                defect,
                shared: Mutex::new(Shared::default()),
            }),
        }
    }

    /// Registers a repository for a tenant, as an administrator would. The port has no insert.
    pub fn seed_repository(&self, tenant: TenantId) -> RepositoryId {
        let mut g = lock(&self.inner);
        let n = u128::try_from(g.committed.repositories.len()).unwrap_or(0) + 1;
        let id = RepositoryId::parse(&format!("00000000-0000-7000-8000-{n:012x}"))
            .expect("a valid repository id");
        let installation = InstallationId(n as u64);
        let github = GithubRepositoryId(1000 + n as u64);
        let row = Repository {
            id,
            tenant_id: tenant,
            installation,
            github_repository_id: github,
            full_name: "acme/widgets".to_owned(),
            default_branch: "main".to_owned(),
            enabled: true,
            protection_preflight_passed: false,
            autonomy_ceiling: factory_domain::vocabulary::AutonomyLevel::L1,
        };
        g.committed.repositories.insert(
            id,
            Row {
                value: row,
                version: Version::FIRST,
            },
        );
        g.installations.push((
            installation,
            github,
            ResolvedRepository {
                tenant,
                repository: id,
            },
        ));
        id
    }

    /// Registers an API token for a principal.
    pub fn seed_token(&self, hash: TokenHash, audience: Audience, who: ResolvedPrincipal) {
        lock(&self.inner).tokens.push((hash, audience, who));
    }

    /// Switches off the installation registered for a repository.
    pub fn disable_repository(&self, repository: RepositoryId) {
        let mut g = lock(&self.inner);
        if let Some(row) = g.committed.repositories.get_mut(&repository) {
            row.value.enabled = false;
        }
    }

    /// Sets a stage run's fencing counter, to reach the largest epoch without 2^63 starts.
    pub fn force_lease_epoch(&self, stage_run: StageRunId, epoch: LeaseEpoch) {
        let mut g = lock(&self.inner);
        if let Some(row) = g.committed.stage_runs.get_mut(&stage_run) {
            row.value.lease_epoch = epoch;
        }
    }

    /// The next call of any transaction never completes. Dropping it poisons the transaction.
    pub fn stall_next_call(&self) {
        lock(&self.inner).stall_next = true;
    }

    /// The next commit is applied and then reports `CommitOutcomeUnknown`.
    pub fn lose_next_commit_answer(&self) {
        lock(&self.inner).lose_commit_answer = true;
    }

    /// The audit records stored under the platform tenant.
    #[must_use]
    pub fn platform_audit(&self) -> Vec<AuditRecord> {
        lock(&self.inner)
            .committed
            .audit
            .get(&platform_tenant())
            .cloned()
            .unwrap_or_default()
    }

    /// The audit records stored under a tenant, for a test that checks where an event landed.
    #[must_use]
    pub fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord> {
        lock(&self.inner)
            .committed
            .audit
            .get(&tenant)
            .cloned()
            .unwrap_or_default()
    }

    fn has(&self, defect: StoreDefect) -> bool {
        self.inner.defect == Some(defect)
    }

    fn now(&self) -> Timestamp {
        self.inner.clock.now()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError> {
        let mut g = lock(&self.inner);
        g.next_tx += 1;
        let id = g.next_tx;
        let base = g.committed.clone();
        drop(g);
        Ok(Box::new(InMemoryTx {
            store: self.clone(),
            tenant: scope.tenant_id(),
            id,
            work: base.clone(),
            base,
            poisoned: Arc::new(AtomicBool::new(false)),
            claimed: BTreeSet::new(),
            finished: false,
        }))
    }

    async fn begin_system(&self, _scope: SystemScope) -> Result<Box<dyn SystemTx>, StoreError> {
        let snapshot = lock(&self.inner).committed.clone();
        Ok(Box::new(InMemorySystemTx {
            store: self.clone(),
            snapshot,
        }))
    }

    async fn resolve_token(
        &self,
        hash: &TokenHash,
        audience: &Audience,
    ) -> Result<Option<ResolvedPrincipal>, StoreError> {
        let g = lock(&self.inner);
        let found = g
            .tokens
            .iter()
            .find(|(h, a, _)| h == hash && a == audience)
            .map(|(_, _, who)| *who);
        let Some(who) = found else {
            return self.miss();
        };
        let owner_ok = g
            .committed
            .principals
            .get(&who.principal)
            .is_none_or(|p| p.disabled_at.is_none());
        if owner_ok { Ok(Some(who)) } else { self.miss() }
    }

    async fn resolve_installation(
        &self,
        installation: InstallationId,
        repository: GithubRepositoryId,
    ) -> Result<Option<ResolvedRepository>, StoreError> {
        let g = lock(&self.inner);
        let found = g
            .installations
            .iter()
            .find(|(i, r, _)| *i == installation && *r == repository)
            .map(|(_, _, who)| *who);
        match found {
            Some(who)
                if g.committed
                    .repositories
                    .get(&who.repository)
                    .is_some_and(|row| row.value.enabled) =>
            {
                Ok(Some(who))
            }
            _ => self.miss(),
        }
    }

    async fn record_platform_audit(
        &self,
        _scope: PlatformScope,
        event: NewAuditEvent,
    ) -> Result<AuditRecord, StoreError> {
        if event.job.is_some() || event.stage_run.is_some() {
            return Err(StoreError::NotFound);
        }
        let now = self.now();
        let mut g = lock(&self.inner);
        let tenant = if self.has(StoreDefect::WritesToCallerTenant) {
            TenantId::parse("00000000-0000-7000-8000-000000000001").expect("a valid tenant id")
        } else {
            platform_tenant()
        };
        append_audit(&mut g.committed.audit, tenant, event, now)
    }

    async fn committed(&self, scope: TenantScope, witness: Witness) -> Result<bool, StoreError> {
        if self.has(StoreDefect::LosesWitness) {
            return Ok(false);
        }
        let g = lock(&self.inner);
        let tenant = scope.tenant_id();
        Ok(match witness {
            Witness::OutboxEvent(id) => g
                .committed
                .outbox
                .iter()
                .any(|e| e.tenant == tenant && e.event.event_id == id),
            Witness::Audit(id) => g
                .committed
                .audit
                .get(&tenant)
                .is_some_and(|list| list.iter().any(|r| r.event.id == id)),
        })
    }

    async fn schema_version(&self) -> Result<SchemaVersion, StoreError> {
        Ok(SCHEMA_VERSION)
    }
}

impl InMemoryStore {
    /// A lookup that finds nothing. The defect `RevealsReason` makes it say why.
    fn miss<T>(&self) -> Result<Option<T>, StoreError> {
        if self.has(StoreDefect::RevealsReason) {
            Err(StoreError::NotFound)
        } else {
            Ok(None)
        }
    }
}

fn append_audit(
    audit: &mut BTreeMap<TenantId, Vec<AuditRecord>>,
    tenant: TenantId,
    event: NewAuditEvent,
    now: Timestamp,
) -> Result<AuditRecord, StoreError> {
    check_text(&event.subject, 1, 500)?;
    check_text(&event.reason, 1, 1000)?;
    let list = audit.entry(tenant).or_default();
    if let Some(existing) = list.iter().find(|r| r.event.id == event.id) {
        return if existing.event == event {
            Ok(existing.clone())
        } else {
            Err(StoreError::Constraint(
                ConstraintRule::IdReusedWithDifferentContent,
            ))
        };
    }
    let sequence = list.len() as u64 + 1;
    let previous = list
        .last()
        .map(|r| r.hash.as_str().to_owned())
        .unwrap_or_default();
    let hash = Sha256Digest::of(format!("{previous}|{sequence}|{}", event.id).as_bytes());
    let record = AuditRecord {
        sequence,
        event,
        created_at: now,
        hash,
    };
    list.push(record.clone());
    Ok(record)
}

fn check_text(text: &str, min: usize, max: usize) -> Result<(), StoreError> {
    if (min..=max).contains(&text.len()) {
        Ok(())
    } else {
        Err(StoreError::Constraint(ConstraintRule::TextBounds))
    }
}

// ---------------------------------------------------------------------------------------------
// The system transaction
// ---------------------------------------------------------------------------------------------

struct InMemorySystemTx {
    store: InMemoryStore,
    snapshot: Tables,
}

#[async_trait]
impl SystemTx for InMemorySystemTx {
    async fn database_time(&mut self) -> Result<Timestamp, StoreError> {
        Ok(self.store.now())
    }

    async fn find_claim_candidates(
        &mut self,
        limit: u32,
    ) -> Result<Vec<ClaimCandidate>, StoreError> {
        let now = self.store.now();
        let locked: BTreeSet<StageRunId> = lock(&self.store.inner).claims.keys().copied().collect();
        let mut found: Vec<ClaimCandidate> = self
            .snapshot
            .stage_runs
            .values()
            .filter(|row| row.value.status == StageRunStatus::Ready)
            .filter(|row| !locked.contains(&row.value.id))
            .filter(|row| {
                self.store.has(StoreDefect::IgnoresNotBefore) || row.value.not_before <= now
            })
            .filter(|row| {
                self.store.has(StoreDefect::ClaimsForInactiveJob)
                    || self
                        .snapshot
                        .jobs
                        .get(&row.value.job_id)
                        .is_some_and(|job| job.value.status == JobStatus::Active)
            })
            .map(|row| ClaimCandidate {
                tenant: row.value.tenant_id,
                job: row.value.job_id,
                stage_run: row.value.id,
                version: row.version,
                not_before: row.value.not_before,
            })
            .collect();
        found.sort_by_key(|c| (c.not_before, c.stage_run));
        if self.store.has(StoreDefect::FindsOnlyFirstTenant)
            && let Some(first) = found.first().map(|c| c.tenant)
        {
            found.retain(|c| c.tenant == first);
        }
        if !self.store.has(StoreDefect::IgnoresCandidateLimit) {
            found.truncate(limit as usize);
        }
        Ok(found)
    }

    async fn find_due_attempts(
        &mut self,
        reason: DueReason,
        limit: u32,
    ) -> Result<Vec<DueAttempt>, StoreError> {
        let now = self.store.now();
        let defect = |d| self.store.has(d);
        let mut due: Vec<(Timestamp, DueAttempt)> = Vec::new();
        for row in self.snapshot.attempts.values() {
            let a = &row.value;
            let live = matches!(a.status, AttemptStatus::Starting | AttemptStatus::Running);
            let when = match reason {
                DueReason::LeaseExpired if live && !defect(StoreDefect::MissesLeaseExpiry) => {
                    Some(a.lease_expires_at)
                }
                DueReason::DeadlinePassed if live && !defect(StoreDefect::MissesDeadline) => {
                    Some(a.deadline_at)
                }
                DueReason::TeardownDeadlinePassed
                    if a.status == AttemptStatus::Cancelling
                        && !defect(StoreDefect::MissesTeardown) =>
                {
                    a.teardown_deadline_at
                }
                _ => None,
            };
            if let Some(when) = when
                && when < now
            {
                due.push((
                    when,
                    DueAttempt {
                        tenant: a.tenant_id,
                        job: a.job_id,
                        stage_run: a.stage_run_id,
                        attempt: a.id,
                        version: row.version,
                        reason,
                    },
                ));
            }
        }
        due.sort_by_key(|d| (d.0, d.1.attempt));
        Ok(due
            .into_iter()
            .map(|(_, d)| d)
            .take(limit as usize)
            .collect())
    }

    async fn finish(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// The tenant transaction
// ---------------------------------------------------------------------------------------------

struct InMemoryTx {
    store: InMemoryStore,
    tenant: TenantId,
    id: u64,
    base: Tables,
    work: Tables,
    poisoned: Arc<AtomicBool>,
    claimed: BTreeSet<StageRunId>,
    finished: bool,
}

/// Marks a call as in flight. If the future is dropped before the call finishes, the transaction
/// is poisoned.
struct Flight {
    poisoned: Arc<AtomicBool>,
    done: bool,
}

impl Flight {
    fn finish(mut self) {
        self.done = true;
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        if !self.done {
            self.poisoned.store(true, Ordering::SeqCst);
        }
    }
}

impl Drop for InMemoryTx {
    fn drop(&mut self) {
        let mut g = lock(&self.store.inner);
        for id in &self.claimed {
            if g.claims.get(id) == Some(&self.id)
                && !self.store.has(StoreDefect::KeepsClaimLockOnRollback)
            {
                g.claims.remove(id);
            }
        }
        if self.store.has(StoreDefect::KeepsWritesOnDrop) && !self.finished {
            // The defect: a dropped transaction applies its writes anyway.
            drop(g);
            let _ = self.apply();
        }
    }
}

/// Runs the body of a call. A poisoned transaction answers `Unavailable`. A future dropped before
/// the body ends poisons the transaction.
macro_rules! call {
    ($self:ident, $body:block) => {{
        if $self.poisoned.load(Ordering::SeqCst)
            && !$self.store.has(StoreDefect::ContinuesAfterDrop)
        {
            return Err(StoreError::Unavailable);
        }
        let flight = Flight {
            poisoned: Arc::clone(&$self.poisoned),
            done: false,
        };
        let stall = std::mem::take(&mut lock(&$self.store.inner).stall_next);
        if stall {
            std::future::pending::<()>().await;
        }
        // The closure keeps the early `return` and `?` of the body inside this one call.
        #[allow(clippy::redundant_closure_call)]
        let result = (|| -> Result<_, StoreError> { $body })();
        flight.finish();
        result
    }};
}

impl InMemoryTx {
    fn has(&self, defect: StoreDefect) -> bool {
        self.store.has(defect)
    }

    fn now(&self) -> Timestamp {
        self.store.now()
    }

    /// True when a row of `owner` is visible to this transaction.
    fn sees(&self, owner: TenantId) -> bool {
        owner == self.tenant || self.has(StoreDefect::ReadsAcrossTenants)
    }

    fn job(&self, id: JobId) -> Result<&Row<Job>, StoreError> {
        self.work
            .jobs
            .get(&id)
            .filter(|row| self.sees(row.value.tenant_id))
            .ok_or(StoreError::NotFound)
    }

    fn stage_run(&self, id: StageRunId) -> Result<&Row<StageRun>, StoreError> {
        self.work
            .stage_runs
            .get(&id)
            .filter(|row| self.sees(row.value.tenant_id))
            .ok_or(StoreError::NotFound)
    }

    fn attempt(&self, id: AttemptId) -> Result<&Row<Attempt>, StoreError> {
        self.work
            .attempts
            .get(&id)
            .filter(|row| self.sees(row.value.tenant_id))
            .ok_or(StoreError::NotFound)
    }

    fn task_node(&self, id: TaskNodeId) -> Result<&Row<TaskNode>, StoreError> {
        self.work
            .task_nodes
            .get(&id)
            .filter(|row| self.sees(row.value.tenant_id))
            .ok_or(StoreError::NotFound)
    }

    fn check_version(&self, current: Version, expected: Version) -> Result<(), StoreError> {
        if current != expected && !self.has(StoreDefect::SkipsVersionCheck) {
            Err(StoreError::Conflict)
        } else {
            Ok(())
        }
    }

    /// Whether a fence is the current one for its attempt.
    fn fence_is_current(&self, fence: &Fence) -> Result<(), StoreError> {
        let attempt = self
            .attempt(fence.attempt)
            .map_err(|_| StoreError::LeaseFenced)?;
        let run = self
            .stage_run(attempt.value.stage_run_id)
            .map_err(|_| StoreError::LeaseFenced)?;
        let live = matches!(
            attempt.value.status,
            AttemptStatus::Starting | AttemptStatus::Running | AttemptStatus::Cancelling
        );
        let epoch_ok = (attempt.value.epoch == fence.epoch && run.value.lease_epoch == fence.epoch)
            || self.has(StoreDefect::IgnoresLeaseEpoch);
        let worker_ok =
            attempt.value.worker == fence.worker || self.has(StoreDefect::IgnoresWorkerName);
        if live && epoch_ok && worker_ok {
            Ok(())
        } else {
            Err(StoreError::LeaseFenced)
        }
    }

    /// Validates the three-way merge and writes the transaction's changes. Returns the error
    /// without writing anything when a row moved under the transaction.
    fn apply(&mut self) -> Result<(), StoreError> {
        let mut g = lock(&self.store.inner);
        let merge = !self.store.has(StoreDefect::SkipsCommitMerge);
        let c = &g.committed;
        let (b, w) = (&self.base, &self.work);
        let jobs = changed(&c.jobs, &b.jobs, &w.jobs, merge)?;
        let requests = changed(&c.requests, &b.requests, &w.requests, merge)?;
        let repos = changed(&c.repositories, &b.repositories, &w.repositories, merge)?;
        let runs = changed(&c.stage_runs, &b.stage_runs, &w.stage_runs, merge)?;
        let attempts = changed(&c.attempts, &b.attempts, &w.attempts, merge)?;
        let nodes = changed(&c.task_nodes, &b.task_nodes, &w.task_nodes, merge)?;
        let deps = changed(&c.task_deps, &b.task_deps, &w.task_deps, merge)?;
        let approvals = changed(&c.approvals, &b.approvals, &w.approvals, merge)?;
        let principals = changed(&c.principals, &b.principals, &w.principals, merge)?;
        let index = changed(&c.index, &b.index, &w.index, merge)?;
        // Append-only tables: the position must still be the one the transaction saw.
        for (job, entries) in &w.ledger {
            let base_len = b.ledger.get(job).map_or(0, Vec::len);
            if merge
                && entries.len() > base_len
                && c.ledger.get(job).map_or(0, Vec::len) != base_len
            {
                return Err(StoreError::Conflict);
            }
        }
        for (tenant, records) in &w.audit {
            let base_len = b.audit.get(tenant).map_or(0, Vec::len);
            if merge
                && records.len() > base_len
                && c.audit.get(tenant).map_or(0, Vec::len) != base_len
            {
                return Err(StoreError::Conflict);
            }
        }
        let new_deliveries: Vec<Delivery> = w.deliveries[b.deliveries.len()..].to_vec();
        for delivery in &new_deliveries {
            if c.deliveries
                .iter()
                .any(|d| same_delivery(&d.row, &delivery.row))
            {
                return Err(StoreError::Conflict);
            }
        }
        let new_artifacts: Vec<(TenantId, StageRunArtifact)> =
            w.stage_artifacts[b.stage_artifacts.len()..].to_vec();
        let new_events: Vec<StoredEvent> = w.outbox[b.outbox.len()..].to_vec();
        let ledger: Vec<(JobId, Vec<EvidenceLedgerEntry>)> = w
            .ledger
            .iter()
            .filter(|(job, entries)| entries.len() > b.ledger.get(job).map_or(0, Vec::len))
            .map(|(job, entries)| (*job, entries.clone()))
            .collect();
        let audit: Vec<(TenantId, Vec<AuditRecord>)> = w
            .audit
            .iter()
            .filter(|(tenant, records)| records.len() > b.audit.get(tenant).map_or(0, Vec::len))
            .map(|(tenant, records)| (*tenant, records.clone()))
            .collect();

        let c = &mut g.committed;
        c.jobs.extend(jobs);
        c.requests.extend(requests);
        c.repositories.extend(repos);
        c.stage_runs.extend(runs);
        c.attempts.extend(attempts);
        c.task_nodes.extend(nodes);
        c.task_deps.extend(deps);
        c.approvals.extend(approvals);
        c.principals.extend(principals);
        c.index.extend(index);
        c.deliveries.extend(new_deliveries);
        c.stage_artifacts.extend(new_artifacts);
        c.outbox.extend(new_events);
        c.ledger.extend(ledger);
        c.audit.extend(audit);
        Ok(())
    }
}

fn same_delivery(a: &NewWebhookDelivery, b: &NewWebhookDelivery) -> bool {
    a.delivery_id == b.delivery_id
        || a.body_sha256 == b.body_sha256
        || (a.semantic_key.is_some() && a.semantic_key == b.semantic_key)
}

#[async_trait]
impl Tx for InMemoryTx {
    async fn database_time(&mut self) -> Result<Timestamp, StoreError> {
        call!(self, {
            if self.has(StoreDefect::FrozenDatabaseTime) {
                return Ok(Timestamp::parse("2026-01-01T00:00:00Z").expect("a valid time"));
            }
            Ok(self.now())
        })
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StoreError> {
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.finished = true;
        if self.has(StoreDefect::LosesLastOutboxRow)
            && let Some(last) = self.work.outbox.last().cloned()
            && self.work.outbox.len() > self.base.outbox.len()
        {
            self.work.outbox.retain(|e| e != &last);
        }
        self.apply()?;
        if std::mem::take(&mut lock(&self.store.inner).lose_commit_answer) {
            return Err(StoreError::CommitOutcomeUnknown);
        }
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), StoreError> {
        self.finished = true;
        Ok(())
    }
}

// ---- jobs ------------------------------------------------------------------------------------

#[async_trait]
impl JobOps for InMemoryTx {
    async fn insert_job(&mut self, new: NewJob) -> Result<Inserted<Job>, StoreError> {
        call!(self, {
            if let Some(existing) = self
                .work
                .jobs
                .get(&new.id)
                .filter(|r| self.sees(r.value.tenant_id))
            {
                let same = existing.value.repository == new.repository
                    && existing.value.requester == new.requester
                    && existing.value.execution_mode == new.execution_mode
                    && existing.value.autonomy_level == new.autonomy_level
                    && existing.value.pipeline_scope == new.pipeline_scope
                    && existing.value.origin == new.origin
                    && existing.value.correlation_id == new.correlation_id;
                if self.has(StoreDefect::DuplicatesOnReplay) {
                    // The defect: a replay is a second row with the same content.
                    return Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ));
                }
                return if same {
                    Ok(Inserted {
                        row: existing.versioned(),
                        created: false,
                    })
                } else if self.has(StoreDefect::OverwritesOnReplay) {
                    self.work.jobs.remove(&new.id);
                    self.store_new_job(new)
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            if let Some(origin) = &new.origin
                && !self.has(StoreDefect::IgnoresOrigin)
                && let Some(first) = self.work.jobs.values().find(|r| {
                    r.value.tenant_id == self.tenant && r.value.origin.as_ref() == Some(origin)
                })
            {
                return Ok(Inserted {
                    row: first.versioned(),
                    created: false,
                });
            }
            self.store_new_job(new)
        })
    }

    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError> {
        call!(self, { Ok(self.job(id)?.versioned()) })
    }

    async fn list_jobs(
        &mut self,
        filter: JobFilter,
        after: Option<PageCursor>,
        limit: u32,
    ) -> Result<Page<Versioned<Job>>, StoreError> {
        call!(self, {
            let mut rows: Vec<&Row<Job>> = self
                .work
                .jobs
                .values()
                .filter(|r| self.sees(r.value.tenant_id))
                .filter(|r| filter.statuses.is_empty() || filter.statuses.contains(&r.value.status))
                .filter(|r| {
                    filter
                        .repository
                        .is_none_or(|repo| repo == r.value.repository)
                })
                .collect();
            rows.sort_by(|a, b| {
                (b.value.created_at, b.value.id).cmp(&(a.value.created_at, a.value.id))
            });
            let start: usize = after
                .as_ref()
                .and_then(|c| c.as_str().parse().ok())
                .unwrap_or(0);
            let limit = limit as usize;
            let page: Vec<Versioned<Job>> = rows
                .iter()
                .skip(start)
                .take(limit)
                .map(|r| r.versioned())
                .collect();
            let next =
                (start + limit < rows.len()).then(|| PageCursor::new((start + limit).to_string()));
            Ok(Page { rows: page, next })
        })
    }

    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let now = self.now();
            let row = self.job(id)?.clone();
            self.check_version(row.version, expected)?;
            if row.value.status != t.from_status() {
                return Err(StoreError::Conflict);
            }
            let mut next = row;
            next.value.status = t.to_status();
            if t.to_status().is_terminal() {
                next.value.terminal_at = Some(now);
            }
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.jobs.insert(id, next);
            Ok(version)
        })
    }

    async fn update_job_facts(
        &mut self,
        id: JobId,
        expected: Version,
        facts: JobFacts,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let row = self.job(id)?.clone();
            self.check_version(row.version, expected)?;
            if row.value.status.is_terminal() && !self.has(StoreDefect::EditsTerminalRows) {
                return Err(StoreError::Constraint(ConstraintRule::TerminalRowImmutable));
            }
            let mut next = row.clone();
            let mut changed = false;
            for (current, new) in [
                (&mut next.value.policy_hash, facts.policy_hash),
                (&mut next.value.normalized_request, facts.normalized_request),
            ] {
                match (current.as_ref(), new) {
                    (_, None) => {}
                    (None, Some(value)) => {
                        *current = Some(value);
                        changed = true;
                    }
                    (Some(have), Some(value)) if *have == value => {}
                    (Some(_), Some(_)) => {
                        return Err(StoreError::Constraint(
                            ConstraintRule::IdReusedWithDifferentContent,
                        ));
                    }
                }
            }
            if !changed {
                return Ok(row.version);
            }
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.jobs.insert(id, next);
            Ok(version)
        })
    }
}

fn bump(version: Version) -> Result<Version, StoreError> {
    version
        .next()
        .map_err(|_| StoreError::Internal(FaultCode::Unmapped))
}

impl InMemoryTx {
    fn store_new_job(&mut self, new: NewJob) -> Result<Inserted<Job>, StoreError> {
        let repo = self
            .work
            .repositories
            .get(&new.repository)
            .filter(|r| self.sees(r.value.tenant_id))
            .ok_or(StoreError::NotFound)?;
        let _ = repo;
        let requester = self
            .work
            .principals
            .get(&new.requester)
            .filter(|p| self.sees(p.tenant_id))
            .ok_or(StoreError::NotFound)?;
        let _ = requester;
        if let Some(JobOrigin::Webhook(delivery)) = &new.origin {
            let _ = delivery;
        }
        let job = Job {
            id: new.id,
            tenant_id: self.tenant,
            correlation_id: new.correlation_id,
            repository: new.repository,
            requester: new.requester,
            status: JobStatus::INITIAL,
            execution_mode: new.execution_mode,
            autonomy_level: new.autonomy_level,
            pipeline_scope: new.pipeline_scope,
            origin: new.origin,
            policy_hash: None,
            normalized_request: None,
            created_at: self.now(),
            terminal_at: None,
        };
        let row = Row {
            value: job,
            version: Version::FIRST,
        };
        self.work.jobs.insert(new.id, row.clone());
        Ok(Inserted {
            row: row.versioned(),
            created: true,
        })
    }
}

// ---- requests, deliveries, repositories -----------------------------------------------------

#[async_trait]
impl RequestOps for InMemoryTx {
    async fn record_original_request(
        &mut self,
        new: NewOriginalRequest,
    ) -> Result<Inserted<OriginalRequest>, StoreError> {
        call!(self, {
            self.job(new.job)?;
            check_text(&new.text, 1, 1 << 20)?;
            if let Some(source_ref) = &new.source_ref {
                check_text(source_ref, 0, 2048)?;
            }
            let stored = OriginalRequest {
                id: new.id,
                job: new.job,
                revision: new.revision,
                source: new.source,
                source_ref: new.source_ref.clone(),
                author_github_user_id: new.author_github_user_id,
                text: new.text.clone(),
                content_sha256: Sha256Digest::of(new.text.as_bytes()),
                captured_at: self.now(),
            };
            let key = (new.job, new.revision);
            if let Some((_, existing)) = self.work.requests.get(&key) {
                let same = existing.id == stored.id
                    && existing.text == stored.text
                    && existing.source == stored.source
                    && existing.source_ref == stored.source_ref
                    && existing.author_github_user_id == stored.author_github_user_id;
                if same {
                    return Ok(Inserted {
                        row: Versioned {
                            value: existing.clone(),
                            version: Version::FIRST,
                        },
                        created: false,
                    });
                }
                if !self.has(StoreDefect::EditsRequest) {
                    return Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ));
                }
            }
            self.work
                .requests
                .insert(key, (self.tenant, stored.clone()));
            Ok(Inserted {
                row: Versioned {
                    value: stored,
                    version: Version::FIRST,
                },
                created: true,
            })
        })
    }

    async fn get_original_request(
        &mut self,
        job: JobId,
        revision: Option<u32>,
    ) -> Result<OriginalRequest, StoreError> {
        call!(self, {
            self.job(job)?;
            let found = match revision {
                Some(r) => self.work.requests.get(&(job, r)),
                None => self
                    .work
                    .requests
                    .range((job, 0)..=(job, u32::MAX))
                    .next_back()
                    .map(|(_, v)| v),
            };
            found.map(|(_, r)| r.clone()).ok_or(StoreError::NotFound)
        })
    }
}

#[async_trait]
impl DeliveryOps for InMemoryTx {
    async fn record_delivery(
        &mut self,
        new: NewWebhookDelivery,
    ) -> Result<DeliveryOutcome, StoreError> {
        call!(self, {
            check_text(&new.delivery_id, 8, 128)?;
            let tenant_deliveries = self.work.deliveries.iter().filter(|d| self.sees(d.tenant));
            for old in tenant_deliveries {
                let kind = if old.row.delivery_id == new.delivery_id {
                    Some(DuplicateOf::DeliveryId)
                } else if old.row.body_sha256 == new.body_sha256 {
                    Some(DuplicateOf::Body)
                } else if new.semantic_key.is_some() && old.row.semantic_key == new.semantic_key {
                    Some(DuplicateOf::Semantic)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    return if self.has(StoreDefect::ErrorsOnRepeat) {
                        Err(StoreError::Conflict)
                    } else {
                        Ok(DeliveryOutcome::Duplicate(kind))
                    };
                }
            }
            let id = new.id;
            self.work.deliveries.push(Delivery {
                tenant: self.tenant,
                row: new,
            });
            Ok(DeliveryOutcome::Recorded(id))
        })
    }
}

#[async_trait]
impl RepositoryOps for InMemoryTx {
    async fn get_repository(
        &mut self,
        id: RepositoryId,
    ) -> Result<Versioned<Repository>, StoreError> {
        call!(self, {
            self.work
                .repositories
                .get(&id)
                .filter(|r| self.sees(r.value.tenant_id))
                .map(Row::versioned)
                .ok_or(StoreError::NotFound)
        })
    }

    async fn record_protection_preflight(
        &mut self,
        id: RepositoryId,
        expected: Version,
        passed: bool,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let row = self
                .work
                .repositories
                .get(&id)
                .filter(|r| self.sees(r.value.tenant_id))
                .cloned()
                .ok_or(StoreError::NotFound)?;
            self.check_version(row.version, expected)?;
            let mut next = row;
            next.value.protection_preflight_passed = passed;
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.repositories.insert(id, next);
            Ok(version)
        })
    }
}

// ---- stage runs ------------------------------------------------------------------------------

#[async_trait]
impl StageRunOps for InMemoryTx {
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Inserted<StageRun>, StoreError> {
        call!(self, {
            self.job(new.job_id)?;
            if let Some(existing) = self
                .work
                .stage_runs
                .get(&new.id)
                .filter(|r| self.sees(r.value.tenant_id))
            {
                let same = existing.value.job_id == new.job_id
                    && existing.value.kind == new.kind
                    && existing.value.run_number == new.run_number
                    && existing.value.max_attempts == new.max_attempts
                    && existing.value.rework_of == new.rework_of;
                return if same && !self.has(StoreDefect::DuplicatesOnReplay) {
                    Ok(Inserted {
                        row: existing.versioned(),
                        created: false,
                    })
                } else if self.has(StoreDefect::OverwritesOnReplay) && !same {
                    self.work.stage_runs.remove(&new.id);
                    self.new_stage_run(new)
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            self.new_stage_run(new)
        })
    }

    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError> {
        call!(self, { Ok(self.stage_run(id)?.versioned()) })
    }

    async fn list_stage_runs(
        &mut self,
        job: JobId,
    ) -> Result<Vec<Versioned<StageRun>>, StoreError> {
        call!(self, {
            self.job(job)?;
            let mut rows: Vec<&Row<StageRun>> = self
                .work
                .stage_runs
                .values()
                .filter(|r| r.value.job_id == job && self.sees(r.value.tenant_id))
                .collect();
            rows.sort_by_key(|r| (r.value.created_at, r.value.run_number, r.value.id));
            Ok(rows.into_iter().map(Row::versioned).collect())
        })
    }

    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
        effects: StageRunEffects,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let now = self.now();
            let row = self.stage_run(id)?.clone();
            self.check_version(row.version, expected)?;
            if row.value.status != t.from_status() {
                return Err(StoreError::Conflict);
            }
            if t.transition_id() == "S03" {
                return Err(StoreError::Constraint(ConstraintRule::IllegalStatusMove));
            }
            let rule = stage_run_effects_rule(t.transition_id());
            match (rule.gate, &effects.gate) {
                (Some(want), Some(have)) if have.outcome == want => {}
                (Some(GateOutcome::Passed), None)
                    if self.has(StoreDefect::AcceptsPassedWithoutOutcome) => {}
                (None, None) => {}
                _ => return Err(StoreError::Constraint(ConstraintRule::GateRecordRule)),
            }
            if rule.contract != effects.contract_sha256.is_some() {
                return Err(StoreError::Constraint(ConstraintRule::GateRecordRule));
            }
            let mut next = row;
            next.value.status = t.to_status();
            if effects.gate.is_some() {
                next.value.gate = effects.gate.clone();
            }
            if effects.contract_sha256.is_some() {
                next.value.contract_sha256 = effects.contract_sha256.clone();
            }
            if t.to_status() == StageRunStatus::Ready {
                next.value.not_before = match effects.not_before_after {
                    Some(delay) => timestamp_after(&now, delay),
                    None => now,
                };
            }
            if t.to_status().is_terminal() && next.value.finished_at.is_none() {
                next.value.finished_at = Some(now);
            }
            if t.to_status() == StageRunStatus::Superseded {
                next.value.superseded_at = Some(now);
            }
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.stage_runs.insert(id, next);
            Ok(version)
        })
    }

    async fn postpone_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        delay: Duration,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let now = self.now();
            let row = self.stage_run(id)?.clone();
            self.check_version(row.version, expected)?;
            if row.value.status != StageRunStatus::Ready {
                return if row.value.status.is_terminal()
                    && !self.has(StoreDefect::EditsTerminalRows)
                {
                    Err(StoreError::Constraint(ConstraintRule::TerminalRowImmutable))
                } else if row.value.status.is_terminal() {
                    let mut next = row;
                    next.value.not_before = timestamp_after(&now, delay);
                    next.version = bump(next.version)?;
                    let version = next.version;
                    self.work.stage_runs.insert(id, next);
                    Ok(version)
                } else {
                    Err(StoreError::Conflict)
                };
            }
            let mut next = row;
            next.value.not_before = timestamp_after(&now, delay);
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.stage_runs.insert(id, next);
            Ok(version)
        })
    }
}

use factory_domain::vocabulary::GateOutcome;
use factory_ports::clock::timestamp_after;

impl InMemoryTx {
    fn new_stage_run(&mut self, new: NewStageRun) -> Result<Inserted<StageRun>, StoreError> {
        let run = StageRun {
            id: new.id,
            tenant_id: self.tenant,
            job_id: new.job_id,
            kind: new.kind,
            run_number: new.run_number,
            status: StageRunStatus::INITIAL,
            lease_epoch: LeaseEpoch::NEVER_CLAIMED,
            max_attempts: new.max_attempts,
            not_before: self.now(),
            rework_of: new.rework_of,
            contract_sha256: None,
            gate: None,
            created_at: self.now(),
            finished_at: None,
            superseded_at: None,
        };
        let row = Row {
            value: run,
            version: Version::FIRST,
        };
        self.work.stage_runs.insert(new.id, row.clone());
        Ok(Inserted {
            row: row.versioned(),
            created: true,
        })
    }
}

// ---- attempts --------------------------------------------------------------------------------

#[async_trait]
impl AttemptOps for InMemoryTx {
    async fn start_attempt(&mut self, start: StartAttempt) -> Result<StartedAttempt, StoreError> {
        call!(self, {
            let now = self.now();
            let run = self.stage_run(start.stage_run)?.clone();
            if start.transition.transition_id() != "S03" {
                return Err(StoreError::Constraint(ConstraintRule::IllegalStatusMove));
            }
            // The statement waits for the row lock and re-evaluates against the committed row.
            if !self.has(StoreDefect::DoubleStartsAttempt) {
                let g = lock(&self.store.inner);
                if let Some(committed) = g.committed.stage_runs.get(&start.stage_run)
                    && (committed.version != start.expected
                        || committed.value.status != StageRunStatus::Ready)
                    && !self.claimed.contains(&start.stage_run)
                {
                    return Err(StoreError::Conflict);
                }
                if g.claims
                    .get(&start.stage_run)
                    .is_some_and(|owner| *owner != self.id)
                {
                    return Err(StoreError::Conflict);
                }
            }
            if run.version != start.expected || run.value.status != StageRunStatus::Ready {
                return Err(StoreError::Conflict);
            }
            let job = self.job(run.value.job_id)?.clone();
            if job.value.status != JobStatus::Active && !self.has(StoreDefect::StartsForInactiveJob)
            {
                return Err(StoreError::NotReady(NotReady::JobNotActive));
            }
            if run.value.not_before > now && !self.has(StoreDefect::IgnoresBackOff) {
                return Err(StoreError::NotReady(NotReady::BackingOff));
            }
            let attempts: Vec<&Row<Attempt>> = self
                .work
                .attempts
                .values()
                .filter(|a| a.value.stage_run_id == start.stage_run)
                .collect();
            let live = attempts.iter().any(|a| {
                matches!(
                    a.value.status,
                    AttemptStatus::Starting | AttemptStatus::Running | AttemptStatus::Cancelling
                )
            });
            if live && !self.has(StoreDefect::AllowsTwoLiveAttempts) {
                return Err(StoreError::Constraint(ConstraintRule::OneLiveAttempt));
            }
            if attempts.len() >= usize::from(run.value.max_attempts)
                && !self.has(StoreDefect::IgnoresAttemptLimit)
            {
                return Err(StoreError::Constraint(ConstraintRule::AttemptLimit));
            }
            if self.work.attempts.contains_key(&start.attempt) {
                return Err(StoreError::Conflict);
            }
            let epoch = match run.value.lease_epoch.checked_next() {
                Some(epoch) => epoch,
                None if self.has(StoreDefect::WrapsTheEpoch) => LeaseEpoch::NEVER_CLAIMED,
                None => return Err(StoreError::Constraint(ConstraintRule::LeaseEpochExhausted)),
            };
            let number = attempts.iter().map(|a| a.value.number).max().unwrap_or(0) + 1;
            let mut next = run;
            next.value.status = start.transition.to_status();
            next.value.lease_epoch = epoch;
            next.version = bump(next.version)?;
            self.work.stage_runs.insert(start.stage_run, next.clone());
            let attempt = Attempt {
                id: start.attempt,
                tenant_id: self.tenant,
                job_id: next.value.job_id,
                stage_run_id: start.stage_run,
                number,
                status: AttemptStatus::INITIAL,
                worker: start.worker,
                epoch,
                lease_expires_at: timestamp_after(&now, start.lease_ttl),
                last_heartbeat_at: None,
                deadline_at: timestamp_after(&now, start.attempt_timeout),
                teardown_deadline_at: None,
                failure_class: None,
                output: None,
                sandbox: None,
                created_at: now,
                ended_at: None,
            };
            let row = Row {
                value: attempt,
                version: Version::FIRST,
            };
            if !self.has(StoreDefect::SplitsStart) {
                self.work.attempts.insert(start.attempt, row.clone());
            }
            self.claimed.insert(start.stage_run);
            lock(&self.store.inner)
                .claims
                .insert(start.stage_run, self.id);
            Ok(StartedAttempt {
                stage_run: next.versioned(),
                attempt: row.versioned(),
            })
        })
    }

    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError> {
        call!(self, { Ok(self.attempt(id)?.versioned()) })
    }

    async fn list_attempts(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<Versioned<Attempt>>, StoreError> {
        call!(self, {
            self.stage_run(stage_run)?;
            let mut rows: Vec<&Row<Attempt>> = self
                .work
                .attempts
                .values()
                .filter(|a| a.value.stage_run_id == stage_run && self.sees(a.value.tenant_id))
                .collect();
            rows.sort_by_key(|a| a.value.number);
            Ok(rows.into_iter().map(Row::versioned).collect())
        })
    }

    async fn heartbeat(&mut self, fence: Fence, ttl: Duration) -> Result<LeaseRenewal, StoreError> {
        call!(self, {
            let now = self.now();
            let row = self
                .attempt(fence.attempt)
                .map_err(|_| StoreError::LeaseFenced)?
                .clone();
            if row.value.status.is_terminal() {
                return Err(StoreError::Conflict);
            }
            self.fence_is_current(&fence)?;
            if row.value.lease_expires_at < now && !self.has(StoreDefect::RevivesLapsedLease) {
                return Err(StoreError::LeaseFenced);
            }
            let mut next = row;
            next.value.lease_expires_at = timestamp_after(&now, ttl);
            next.value.last_heartbeat_at = Some(now);
            let renewal = LeaseRenewal {
                status: next.value.status,
                lease_expires_at: next.value.lease_expires_at,
                deadline_at: next.value.deadline_at,
            };
            self.work.attempts.insert(fence.attempt, next);
            Ok(renewal)
        })
    }

    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
        end: AttemptEnd,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let now = self.now();
            let row = self.attempt(id)?.clone();
            self.check_version(row.version, expected)?;
            let run = self.stage_run(row.value.stage_run_id)?;
            let epoch_ok = (row.value.epoch == epoch && run.value.lease_epoch == epoch)
                || self.has(StoreDefect::IgnoresLeaseEpoch);
            if !epoch_ok {
                return Err(StoreError::LeaseFenced);
            }
            if row.value.status != t.from_status() {
                return Err(StoreError::Conflict);
            }
            let rule = attempt_end_rule(t.transition_id());
            let class_ok = rule.failure_class == end.failure_class.is_some()
                || (self.has(StoreDefect::AcceptsFailedWithoutClass) && rule.failure_class);
            if !class_ok
                || rule.output != end.output.is_some()
                || rule.teardown_grace != end.teardown_grace.is_some()
            {
                return Err(StoreError::Constraint(ConstraintRule::AttemptEndRule));
            }
            let mut next = row;
            next.value.status = t.to_status();
            if t.to_status().is_terminal() {
                next.value.ended_at = Some(now);
            }
            next.value.failure_class = end.failure_class.or(next.value.failure_class);
            next.value.output = end.output.clone().or(next.value.output.take());
            if let Some(record) = end.sandbox {
                next.value.sandbox = Some(merge_sandbox(next.value.sandbox.as_ref(), record));
            }
            if let Some(grace) = end.teardown_grace {
                next.value.teardown_deadline_at = Some(timestamp_after(&now, grace));
            }
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.attempts.insert(id, next);
            Ok(version)
        })
    }

    async fn record_sandbox(
        &mut self,
        id: AttemptId,
        record: SandboxRecord,
    ) -> Result<(), StoreError> {
        call!(self, {
            let mut next = self.attempt(id)?.clone();
            next.value.sandbox = Some(merge_sandbox(next.value.sandbox.as_ref(), record));
            self.work.attempts.insert(id, next);
            Ok(())
        })
    }
}

/// `leaked` only rises.
fn merge_sandbox(old: Option<&SandboxRecord>, new: SandboxRecord) -> SandboxRecord {
    SandboxRecord {
        leaked: new.leaked || old.is_some_and(|o| o.leaked),
        sandbox: new.sandbox,
    }
}

// ---- task nodes ------------------------------------------------------------------------------

#[async_trait]
impl TaskNodeOps for InMemoryTx {
    async fn insert_task_graph(
        &mut self,
        graph: NewTaskGraph,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
        call!(self, {
            let run = self.stage_run(graph.stage_run)?.clone();
            let existing: Vec<&Row<TaskNode>> = self
                .work
                .task_nodes
                .values()
                .filter(|n| n.value.stage_run_id == graph.stage_run)
                .collect();
            if let Some(first) = existing.first() {
                return if first.value.plan_sha256 == graph.plan_sha256 {
                    let mut rows: Vec<Versioned<TaskNode>> =
                        existing.iter().map(|r| r.versioned()).collect();
                    rows.sort_by(|a, b| a.value.key.as_str().cmp(b.value.key.as_str()));
                    Ok(rows)
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            let mut keys = BTreeMap::new();
            for node in &graph.nodes {
                if self.work.task_nodes.contains_key(&node.id) {
                    return Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ));
                }
                let first = keys.insert(node.key.as_str().to_owned(), node.id);
                if first.is_some() && !self.has(StoreDefect::AllowsDuplicateTaskKey) {
                    return Err(StoreError::Constraint(ConstraintRule::DuplicateTaskKey));
                }
            }
            let mut edges = Vec::new();
            for node in &graph.nodes {
                for dep in &node.depends_on {
                    let target = keys.get(dep.as_str()).ok_or(StoreError::NotFound)?;
                    edges.push((node.id, *target));
                }
            }
            if has_cycle(&edges) && !self.has(StoreDefect::AllowsCycle) {
                return Err(StoreError::Constraint(ConstraintRule::DependencyCycle));
            }
            let now = self.now();
            let mut out = Vec::new();
            for node in graph.nodes {
                let row = Row {
                    value: TaskNode {
                        id: node.id,
                        tenant_id: self.tenant,
                        job_id: run.value.job_id,
                        stage_run_id: graph.stage_run,
                        key: node.key,
                        plan_sha256: graph.plan_sha256.clone(),
                        status: TaskNodeStatus::INITIAL,
                        retry_count: 0,
                        current_attempt: None,
                        commit: None,
                        created_at: now,
                    },
                    version: Version::FIRST,
                };
                self.work.task_nodes.insert(row.value.id, row.clone());
                out.push(row.versioned());
            }
            self.work.task_deps.insert(graph.stage_run, edges);
            out.sort_by(|a, b| a.value.key.as_str().cmp(b.value.key.as_str()));
            Ok(out)
        })
    }

    async fn get_task_node(&mut self, id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError> {
        call!(self, { Ok(self.task_node(id)?.versioned()) })
    }

    async fn list_task_nodes(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
        call!(self, {
            self.stage_run(stage_run)?;
            let mut rows: Vec<Versioned<TaskNode>> = self
                .work
                .task_nodes
                .values()
                .filter(|n| n.value.stage_run_id == stage_run && self.sees(n.value.tenant_id))
                .map(Row::versioned)
                .collect();
            rows.sort_by(|a, b| a.value.key.as_str().cmp(b.value.key.as_str()));
            Ok(rows)
        })
    }

    async fn task_dependencies(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<(TaskNodeId, TaskNodeId)>, StoreError> {
        call!(self, {
            self.stage_run(stage_run)?;
            Ok(self
                .work
                .task_deps
                .get(&stage_run)
                .cloned()
                .unwrap_or_default())
        })
    }

    async fn transition_task_node(
        &mut self,
        id: TaskNodeId,
        expected: Version,
        by: Option<Fence>,
        t: AppliedTransition<TaskNodeStatus>,
        effects: TaskNodeEffects,
    ) -> Result<Version, StoreError> {
        call!(self, {
            let row = self.task_node(id)?.clone();
            self.check_version(row.version, expected)?;
            if row.value.status != t.from_status() {
                return Err(StoreError::Conflict);
            }
            let fenced = matches!(t.transition_id(), "T02" | "T03" | "T04" | "T05");
            if fenced && !self.has(StoreDefect::IgnoresTaskFence) {
                match &by {
                    Some(fence) => self.fence_is_current(fence)?,
                    None => return Err(StoreError::LeaseFenced),
                }
            }
            if t.transition_id() == "T03" && effects.commit.is_none() {
                return Err(StoreError::Constraint(ConstraintRule::AttemptEndRule));
            }
            let mut next = row;
            next.value.status = t.to_status();
            match t.transition_id() {
                "T02" => next.value.current_attempt = effects.attempt,
                "T03" => {
                    next.value.current_attempt = None;
                    next.value.commit = effects.commit;
                }
                "T04" | "T05" => next.value.current_attempt = None,
                "T06" => next.value.retry_count += 1,
                _ => {}
            }
            next.version = bump(next.version)?;
            let version = next.version;
            self.work.task_nodes.insert(id, next);
            Ok(version)
        })
    }
}

/// True when the edges `(node, depends_on)` contain a cycle.
fn has_cycle(edges: &[(TaskNodeId, TaskNodeId)]) -> bool {
    let mut incoming: BTreeMap<TaskNodeId, usize> = BTreeMap::new();
    for (from, to) in edges {
        incoming.entry(*from).or_insert(0);
        incoming.entry(*to).or_insert(0);
    }
    for (from, _) in edges {
        *incoming.entry(*from).or_insert(0) += 1;
    }
    let mut ready: Vec<TaskNodeId> = incoming
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(k, _)| *k)
        .collect();
    let mut removed = 0;
    while let Some(done) = ready.pop() {
        removed += 1;
        for (from, to) in edges {
            if *to == done {
                let count = incoming.entry(*from).or_insert(0);
                *count -= 1;
                if *count == 0 {
                    ready.push(*from);
                }
            }
        }
    }
    removed != incoming.len()
}

// ---- stage run artifacts ---------------------------------------------------------------------

#[async_trait]
impl StageArtifactOps for InMemoryTx {
    async fn link_stage_run_artifact(
        &mut self,
        stage_run: StageRunId,
        direction: ArtifactDirection,
        role: factory_domain::values::Slug,
        sha256: Sha256Digest,
    ) -> Result<(), StoreError> {
        call!(self, {
            self.stage_run(stage_run)?;
            if !self.work.index.contains_key(&(self.tenant, sha256.clone())) {
                return Err(StoreError::NotFound);
            }
            let existing = self.work.stage_artifacts.iter().find(|(tenant, a)| {
                *tenant == self.tenant
                    && a.stage_run == stage_run
                    && a.direction == direction
                    && a.role == role
            });
            if let Some((_, old)) = existing {
                return if old.sha256 == sha256 {
                    Ok(())
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            let created_at = self.now();
            self.work.stage_artifacts.push((
                self.tenant,
                StageRunArtifact {
                    stage_run,
                    direction,
                    role,
                    sha256,
                    created_at,
                },
            ));
            Ok(())
        })
    }

    async fn list_stage_run_artifacts(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<StageRunArtifact>, StoreError> {
        call!(self, {
            self.stage_run(stage_run)?;
            Ok(self
                .work
                .stage_artifacts
                .iter()
                .filter(|(tenant, a)| self.sees(*tenant) && a.stage_run == stage_run)
                .map(|(_, a)| a.clone())
                .collect())
        })
    }

    async fn stage_runs_consuming(
        &mut self,
        job: JobId,
        sha256: &Sha256Digest,
    ) -> Result<Vec<StageRunId>, StoreError> {
        call!(self, {
            self.job(job)?;
            let mut out: Vec<StageRunId> = Vec::new();
            for (tenant, link) in &self.work.stage_artifacts {
                let in_job = self
                    .work
                    .stage_runs
                    .get(&link.stage_run)
                    .is_some_and(|r| r.value.job_id == job);
                if self.sees(*tenant)
                    && in_job
                    && link.direction == ArtifactDirection::Input
                    && link.sha256 == *sha256
                    && !out.contains(&link.stage_run)
                {
                    out.push(link.stage_run);
                }
            }
            Ok(out)
        })
    }
}

// ---- approvals -------------------------------------------------------------------------------

#[async_trait]
impl ApprovalOps for InMemoryTx {
    async fn record_approval(
        &mut self,
        new: NewApproval,
    ) -> Result<Inserted<Approval>, StoreError> {
        call!(self, {
            self.job(new.job)?;
            let run = self.stage_run(new.stage_run)?;
            if run.value.job_id != new.job {
                return Err(StoreError::NotFound);
            }
            let approver = self
                .work
                .principals
                .get(&new.approver)
                .ok_or(StoreError::NotFound)?;
            if !self.sees(approver.tenant_id) {
                return Err(StoreError::TenantMismatch);
            }
            let PrincipalKind::Human { github_user_id } = approver.kind else {
                return Err(StoreError::TenantMismatch);
            };
            check_text(&new.reason, 1, 2000)?;
            if new.decision == ApprovalDecision::Approve && new.binding.is_none() {
                return Err(StoreError::Constraint(ConstraintRule::GateRecordRule));
            }
            if let Some((_, old)) = self.work.approvals.get(&new.id) {
                let same = old.job == new.job
                    && old.decision == new.decision
                    && old.approver == new.approver
                    && old.binding == new.binding
                    && old.reason == new.reason;
                return if same {
                    Ok(Inserted {
                        row: Versioned {
                            value: old.clone(),
                            version: Version::FIRST,
                        },
                        created: false,
                    })
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            let head = new.binding.as_ref().map(|b| b.pr_head.clone());
            let repeated = self.work.approvals.values().any(|(_, a)| {
                a.job == new.job
                    && a.approver == new.approver
                    && a.decision == new.decision
                    && a.binding.as_ref().map(|b| b.pr_head.clone()) == head
            });
            if repeated {
                return Err(StoreError::Constraint(
                    ConstraintRule::IdReusedWithDifferentContent,
                ));
            }
            let now = self.now();
            let approval = Approval {
                id: new.id,
                job: new.job,
                stage_run: new.stage_run,
                decision: new.decision,
                approver: new.approver,
                approver_github_user_id: github_user_id,
                designation: new.designation,
                binding: new.binding,
                reason: new.reason,
                channel: new.channel,
                created_at: now,
                expires_at: timestamp_after(&now, new.valid_for),
                invalidated: None,
            };
            self.work
                .approvals
                .insert(new.id, (self.tenant, approval.clone()));
            Ok(Inserted {
                row: Versioned {
                    value: approval,
                    version: Version::FIRST,
                },
                created: true,
            })
        })
    }

    async fn list_approvals(&mut self, job: JobId) -> Result<Vec<Approval>, StoreError> {
        call!(self, {
            self.job(job)?;
            let mut out: Vec<Approval> = self
                .work
                .approvals
                .values()
                .filter(|(tenant, a)| self.sees(*tenant) && a.job == job)
                .map(|(_, a)| a.clone())
                .collect();
            out.sort_by_key(|a| (a.created_at, a.id));
            Ok(out)
        })
    }

    async fn valid_approvals(
        &mut self,
        job: JobId,
        head: &factory_domain::values::GitSha,
    ) -> Result<Vec<Approval>, StoreError> {
        call!(self, {
            self.job(job)?;
            let now = self.now();
            let mut out: Vec<Approval> = self
                .work
                .approvals
                .values()
                .filter(|(tenant, _)| self.sees(*tenant))
                .map(|(_, a)| a)
                .filter(|a| a.job == job && a.decision == ApprovalDecision::Approve)
                .filter(|a| a.invalidated.is_none())
                .filter(|a| self.has(StoreDefect::IgnoresExpiry) || a.expires_at > now)
                .filter(|a| {
                    self.has(StoreDefect::IgnoresHead)
                        || a.binding.as_ref().is_some_and(|b| b.pr_head == *head)
                })
                .cloned()
                .collect();
            out.sort_by_key(|a| (a.created_at, a.id));
            Ok(out)
        })
    }

    async fn invalidate_approvals(
        &mut self,
        job: JobId,
        reason: ApprovalInvalidation,
    ) -> Result<u32, StoreError> {
        call!(self, {
            self.job(job)?;
            let now = self.now();
            let mut count = 0;
            for (tenant, approval) in self.work.approvals.values_mut() {
                if *tenant == self.tenant
                    && approval.job == job
                    && approval.decision == ApprovalDecision::Approve
                    && approval.invalidated.is_none()
                    && approval.expires_at > now
                {
                    approval.invalidated = Some((now, reason));
                    count += 1;
                }
            }
            Ok(count)
        })
    }
}

// ---- ledger, outbox, audit, artifact index, principals --------------------------------------

#[async_trait]
impl LedgerOps for InMemoryTx {
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError> {
        call!(self, {
            let job = entry.metadata.job_id;
            self.job(job)?;
            let chain = self.work.ledger.get(&job).cloned().unwrap_or_default();
            let height = chain.len() as u64;
            let sequence = entry.sequence();
            if sequence <= height {
                return Err(if self.has(StoreDefect::ReusesLedgerPosition) {
                    StoreError::ChainBroken
                } else {
                    StoreError::Conflict
                });
            }
            if sequence > height + 1 {
                return Err(StoreError::ChainBroken);
            }
            if !self.has(StoreDefect::AcceptsBrokenChain) {
                let head_hash = chain.last().map(|last| &last.entry_hash);
                if entry.prev_entry_hash.as_ref() != head_hash {
                    return Err(StoreError::ChainBroken);
                }
                match entry.computed_hash() {
                    Ok(computed) if computed == entry.entry_hash => {}
                    _ => return Err(StoreError::ChainBroken),
                }
            }
            let head = ChainHead {
                sequence,
                hash: entry.entry_hash.clone(),
            };
            self.work.ledger.entry(job).or_default().push(entry);
            Ok(head)
        })
    }

    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError> {
        call!(self, {
            self.job(job)?;
            Ok(self
                .work
                .ledger
                .get(&job)
                .and_then(|chain| chain.last())
                .map(|last| ChainHead {
                    sequence: last.sequence(),
                    hash: last.entry_hash.clone(),
                }))
        })
    }

    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
        call!(self, {
            self.job(job)?;
            Ok(self
                .work
                .ledger
                .get(&job)
                .into_iter()
                .flatten()
                .filter(|entry| entry.sequence() >= from)
                .take(limit as usize)
                .cloned()
                .collect())
        })
    }
}

#[async_trait]
impl OutboxOps for InMemoryTx {
    async fn enqueue_event(&mut self, event: DomainEvent) -> Result<(), StoreError> {
        call!(self, {
            let job = self.job(event.job_id)?;
            if event.tenant_id != job.value.tenant_id
                && !self.has(StoreDefect::AcceptsForeignTenantEvent)
            {
                return Err(StoreError::TenantMismatch);
            }
            if let Some(old) = self
                .work
                .outbox
                .iter()
                .find(|e| e.event.event_id == event.event_id)
            {
                return if old.event == event {
                    Ok(())
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            let committed_has = lock(&self.store.inner)
                .committed
                .outbox
                .iter()
                .any(|e| e.event.event_id == event.event_id);
            if committed_has {
                return Err(StoreError::Constraint(
                    ConstraintRule::IdReusedWithDifferentContent,
                ));
            }
            let seq = {
                let mut g = lock(&self.store.inner);
                g.next_outbox += 1;
                OutboxSeq::new(g.next_outbox)
            };
            self.work.outbox.push(StoredEvent {
                seq,
                tenant: self.tenant,
                event,
            });
            Ok(())
        })
    }

    async fn read_events(
        &mut self,
        job: JobId,
        from: OutboxSeq,
        limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        call!(self, {
            self.job(job)?;
            let mut rows: Vec<OutboxRow> = self
                .work
                .outbox
                .iter()
                .filter(|e| e.event.job_id == job && e.seq >= from)
                .map(|e| OutboxRow {
                    seq: e.seq,
                    event: e.event.clone(),
                })
                .collect();
            rows.sort_by_key(|row| row.seq);
            if self.has(StoreDefect::ReversesOutboxOrder) {
                rows.reverse();
            }
            rows.truncate(limit as usize);
            Ok(rows)
        })
    }
}

#[async_trait]
impl AuditOps for InMemoryTx {
    async fn record_audit(&mut self, event: NewAuditEvent) -> Result<AuditRecord, StoreError> {
        call!(self, {
            if event.job.is_none() && self.has(StoreDefect::RequiresJobForAudit) {
                return Err(StoreError::NotFound);
            }
            if let Some(job) = event.job {
                self.job(job)?;
            }
            if let Some(run) = event.stage_run {
                if event.job.is_none() {
                    return Err(StoreError::NotFound);
                }
                self.stage_run(run)?;
            }
            let now = self.now();
            append_audit(&mut self.work.audit, self.tenant, event, now)
        })
    }

    async fn read_audit(
        &mut self,
        filter: AuditFilter,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        call!(self, {
            if let AuditFilter::Job(job) = filter {
                self.job(job)?;
            }
            let records = self.work.audit.get(&self.tenant).into_iter().flatten();
            let mut out: Vec<AuditRecord> = records
                .filter(|r| r.sequence > after_sequence)
                .filter(|r| match filter {
                    AuditFilter::Tenant => true,
                    AuditFilter::Job(job) => r.event.job == Some(job),
                })
                .cloned()
                .collect();
            if !self.has(StoreDefect::IgnoresAuditLimit) {
                out.truncate(limit as usize);
            }
            Ok(out)
        })
    }
}

#[async_trait]
impl ArtifactIndexOps for InMemoryTx {
    async fn index_artifact(
        &mut self,
        new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        call!(self, {
            if let Some((job, run)) = new.origin {
                self.job(job)?;
                self.stage_run(run)?;
            }
            let key = (self.tenant, new.sha256.clone());
            if let Some(first) = self.work.index.get(&key) {
                return Ok(first.clone());
            }
            let entry = ArtifactIndexEntry {
                tenant_id: self.tenant,
                artifact: ArtifactRef {
                    sha256: new.sha256,
                    media_type: new.media_type,
                    size_bytes: Some(new.size_bytes),
                },
                origin: new.origin,
                created_at: self.now(),
            };
            self.work.index.insert(key, entry.clone());
            Ok(entry)
        })
    }

    async fn get_artifact_index(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        call!(self, {
            self.work
                .index
                .iter()
                .find(|((tenant, hash), _)| hash == sha256 && self.sees(*tenant))
                .map(|(_, entry)| entry.clone())
                .ok_or(StoreError::NotFound)
        })
    }
}

#[async_trait]
impl PrincipalOps for InMemoryTx {
    async fn insert_principal(
        &mut self,
        new: NewPrincipal,
    ) -> Result<Inserted<Principal>, StoreError> {
        call!(self, {
            if let Some(old) = self
                .work
                .principals
                .get(&new.id)
                .filter(|p| self.sees(p.tenant_id))
            {
                return if old.kind == new.kind && old.login == new.login {
                    Ok(Inserted {
                        row: Versioned {
                            value: old.clone(),
                            version: Version::FIRST,
                        },
                        created: false,
                    })
                } else {
                    Err(StoreError::Constraint(
                        ConstraintRule::IdReusedWithDifferentContent,
                    ))
                };
            }
            if let PrincipalKind::Human { github_user_id } = new.kind {
                let taken = self.work.principals.values().any(|p| {
                    self.sees(p.tenant_id)
                        && matches!(p.kind, PrincipalKind::Human { github_user_id: other } if other == github_user_id)
                });
                if taken {
                    return Err(StoreError::Constraint(
                        ConstraintRule::ExternalReferenceTaken,
                    ));
                }
            }
            let principal = Principal {
                id: new.id,
                tenant_id: self.tenant,
                kind: new.kind,
                login: new.login,
                created_at: self.now(),
                disabled_at: None,
            };
            self.work.principals.insert(new.id, principal.clone());
            Ok(Inserted {
                row: Versioned {
                    value: principal,
                    version: Version::FIRST,
                },
                created: true,
            })
        })
    }

    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        call!(self, {
            self.work
                .principals
                .get(&id)
                .filter(|p| self.sees(p.tenant_id))
                .cloned()
                .ok_or(StoreError::NotFound)
        })
    }

    async fn find_principal_by_github_user(
        &mut self,
        github_user_id: u64,
    ) -> Result<Option<Principal>, StoreError> {
        call!(self, {
            Ok(self
                .work
                .principals
                .values()
                .find(|p| {
                    self.sees(p.tenant_id)
                        && matches!(p.kind, PrincipalKind::Human { github_user_id: id } if id == github_user_id)
                })
                .cloned())
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The subject for the contract suite
// ---------------------------------------------------------------------------------------------

/// An [`InMemoryStore`] with the levers the contract suite needs.
pub struct InMemoryStoreSubject {
    store: InMemoryStore,
    clock: Arc<crate::clock::FakeClock>,
}

impl InMemoryStoreSubject {
    /// A fresh, correct store.
    #[must_use]
    pub fn new() -> Self {
        let clock = Arc::new(crate::clock::FakeClock::new());
        Self {
            store: InMemoryStore::new(clock.clone()),
            clock,
        }
    }

    /// A fresh store with one deliberate defect.
    #[must_use]
    pub fn with_defect(defect: StoreDefect) -> Self {
        let clock = Arc::new(crate::clock::FakeClock::new());
        Self {
            store: InMemoryStore::with_defect(clock.clone(), defect),
            clock,
        }
    }
}

impl Default for InMemoryStoreSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::contracts::store::StoreSubject for InMemoryStoreSubject {
    fn store(&self) -> &dyn Store {
        &self.store
    }

    async fn advance_database_time(&self, by: Duration) {
        self.clock.advance(by);
    }

    async fn seed_repository(&self, tenant: TenantId) -> RepositoryId {
        self.store.seed_repository(tenant)
    }

    async fn seed_token(&self, hash: TokenHash, audience: Audience, who: ResolvedPrincipal) {
        self.store.seed_token(hash, audience, who);
    }

    async fn disable_repository(&self, repository: RepositoryId) {
        self.store.disable_repository(repository);
    }

    async fn stall_next_call(&self) {
        self.store.stall_next_call();
    }

    async fn lose_next_commit_answer(&self) {
        self.store.lose_next_commit_answer();
    }

    async fn platform_audit(&self) -> Vec<AuditRecord> {
        self.store.platform_audit()
    }

    async fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord> {
        self.store.tenant_audit(tenant)
    }

    async fn force_lease_epoch(&self, _tenant: TenantId, stage_run: StageRunId, epoch: LeaseEpoch) {
        self.store.force_lease_epoch(stage_run, epoch);
    }
}
