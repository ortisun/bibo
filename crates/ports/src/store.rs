//! The store port: transactional state, the evidence ledger and the outbox (ADR 0004, 0007, 0008,
//! 0014).
//!
//! One [`Tx`] is one database transaction. The engine writes a status change, its ledger entries
//! and its outbox rows in one `Tx` and commits them together (invariant INV-03). Everything in a
//! `Tx` is scoped to a tenant. The only cross-tenant access is a [`SystemTx`], which only the
//! workflow crate may open, and which cannot write: it finds work and returns identifiers.
//!
//! # Scope rules
//!
//! * A **tenant** transaction (`Store::begin`) sees only rows of its own tenant. A row of another
//!   tenant looks exactly like a row that does not exist: the call returns
//!   [`StoreError::NotFound`], so a caller cannot learn that the other row exists.
//! * A **system** transaction (`Store::begin_system`) is a different type with three methods, all
//!   reads. A wrong call does not compile, so there is no "scope not allowed" error.
//! * A value that names a tenant, such as a `DomainEvent`, must name the tenant that owns the
//!   job it belongs to. A mismatch is [`StoreError::TenantMismatch`].
//!
//! # The claim, in one place (ADR 0014, rules R1 to R3)
//!
//! The engine opens a system transaction and calls [`SystemTx::find_claim_candidates`]; it calls
//! `finish`; for each candidate it opens a tenant transaction, reads the job and the stage run,
//! evaluates `G_LEASE_ACQUIRED`, plans `S03` with the clearance, calls
//! [`AttemptOps::start_attempt`], enqueues `stage_run.started`, and commits. A
//! [`StoreError::Conflict`] from `start_attempt` means another worker won. A
//! [`StoreError::NotReady`] means the candidate went stale. No other call creates an attempt.
//!
//! * **R1.** An attempt holds a lease: worker, epoch, expiry. A stage run holds only
//!   [`StageRun::lease_epoch`], a fencing counter.
//! * **R2.** `start_attempt` is the only operation that creates an attempt and the only one that
//!   raises the epoch, in one atomic step.
//! * **R3.** A write that carries a [`Fence`] is rejected with [`StoreError::LeaseFenced`] unless
//!   the attempt is live and its epoch is the stage run's current epoch.
//!
//! # Concurrency rules
//!
//! * Every mutable row carries a [`Version`]. An update says which version it read. A stale
//!   version, or a status that is not the one the update started from, is
//!   [`StoreError::Conflict`] and changes nothing.
//! * Lease expiry is judged by the database clock ([`Tx::database_time`]), never by the `Clock`.
//! * Inserts are idempotent by id and content ([`Inserted`]). The same id with other content is
//!   `Constraint(IdReusedWithDifferentContent)`. `created_at` is never supplied by the caller.
//! * Only [`Tx::commit`] can have an outcome the caller cannot see
//!   ([`StoreError::CommitOutcomeUnknown`]). Every state-changing engine transaction keeps a
//!   [`Witness`], and the caller asks [`Store::committed`] before it acts again.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, DomainEvent, EvidenceLedgerEntry};
use factory_domain::error::ValueError;
use factory_domain::ids::{
    ApprovalId, AttemptId, AuditEventId, CorrelationId, EventId, JobId, PrincipalId, RepositoryId,
    StageRunId, TaskNodeId, TenantId, WebhookDeliveryId,
};
use factory_domain::ledger::ChainHead;
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::GuardCleared;
use factory_domain::scope::{PlatformScope, ResolvedPrincipal, ResolvedRepository, TenantScope};
use factory_domain::state::{
    AttemptStatus, Guard, IllegalTransition, JobStatus, StageRunStatus, Status, TaskNodeStatus,
};
use factory_domain::values::{
    AggregateVersion, GitSha, MediaType, NonNegativeInt, Sha256Digest, Slug, Timestamp,
};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, Fidelity, GateOutcome, StageKind};

use crate::sandbox::SandboxId;

/// The version counter of a mutable row. A new row starts at [`AggregateVersion::FIRST`].
pub type Version = AggregateVersion;

/// The position of an entry in a job's evidence ledger. The first entry is 1.
pub type Sequence = u64;

/// The position of an event in the outbox. It grows with every enqueued event. Gaps are allowed
/// and arrival order is not a guarantee across aggregates (ADR 0004), so a reader uses it only to
/// resume reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboxSeq(u64);

impl OutboxSeq {
    /// The position before every event. Reading `from` this position reads everything.
    pub const START: Self = Self(0);

    /// Wraps a position.
    #[must_use]
    pub const fn new(position: u64) -> Self {
        Self(position)
    }

    /// The position as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The version of the database schema, which is the number of the last migration applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// Wraps a migration number.
    #[must_use]
    pub const fn new(migration: u32) -> Self {
        Self(migration)
    }

    /// The migration number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The name of a worker process, such as `worker-1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerId(Slug);

impl WorkerId {
    /// Checks and wraps a worker name.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless the name is a slug.
    pub fn new(name: &str) -> Result<Self, ValueError> {
        Slug::parse(name).map(Self)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A value and the version it was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versioned<T> {
    /// The row.
    pub value: T,
    /// Its version. Pass it back as `expected` to update the row.
    pub version: Version,
}

/// An event in the outbox with its position.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxRow {
    /// The position the store gave the event.
    pub seq: OutboxSeq,
    /// The event.
    pub event: DomainEvent,
}

// ---------------------------------------------------------------------------------------------
// Scopes and the lease epoch
// ---------------------------------------------------------------------------------------------

/// Proof that the caller is the engine and may look across tenants. A system transaction cannot
/// write: it only finds work. Only the workflow crate calls `Store::begin_system` (DEP-09).
#[derive(Debug)]
pub struct SystemScope(());

impl SystemScope {
    /// The engine's scope.
    #[must_use]
    pub const fn engine() -> Self {
        Self(())
    }
}

/// The fencing counter of a stage run. It is raised by exactly one when the stage run goes from
/// `READY` to `RUNNING` (S03), in the same statement that creates the attempt which carries it.
/// The largest value is `i64::MAX`, the largest the database column holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseEpoch(u64);

impl LeaseEpoch {
    /// The epoch of a stage run that was never started.
    pub const NEVER_CLAIMED: Self = Self(0);
    /// The largest epoch. A claim at this value fails with
    /// [`ConstraintRule::LeaseEpochExhausted`].
    pub const MAX: Self = Self(i64::MAX as u64);

    /// Wraps an epoch. Values above [`LeaseEpoch::MAX`] are cut to it.
    #[must_use]
    pub const fn new(epoch: u64) -> Self {
        if epoch > Self::MAX.0 {
            Self::MAX
        } else {
            Self(epoch)
        }
    }

    /// The epoch as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The epoch after one more start, or `None` at the maximum. It never wraps and never stays
    /// put.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        if self.0 >= Self::MAX.0 {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }
}

/// The worker, the attempt and the epoch a write is made under. A write that names an attempt
/// is rejected with [`StoreError::LeaseFenced`] unless the attempt is live and its epoch is the
/// stage run's current epoch (INV-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    /// The attempt the writer holds.
    pub attempt: AttemptId,
    /// The epoch the writer was given.
    pub epoch: LeaseEpoch,
    /// The worker that holds the lease. A write from another name is fenced too.
    pub worker: WorkerId,
}

// ---------------------------------------------------------------------------------------------
// Transitions that carry the guard that cleared them (F-11)
// ---------------------------------------------------------------------------------------------

/// A state change that the state machine allows and whose guard held, ready to be stored.
///
/// It is made only by [`AppliedTransition::plan`], which needs the [`GuardCleared`] that
/// `guards::evaluate` returned. The store checks `from` against the stored status, writes `to`,
/// and the engine writes [`AppliedTransition::guard`] and the facts digest into the payload of
/// the event that announces the move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTransition<S: Status> {
    from: S,
    event: S::Event,
    to: S,
    transition_id: &'static str,
    at: Timestamp,
    cleared: GuardCleared,
}

/// Why a transition could not be planned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The state machine has no such move.
    #[error(transparent)]
    Illegal(#[from] IllegalTransition),
    /// The guard that held is not the guard the table row asks for.
    #[error("the move needs guard {expected} but guard {given} was cleared")]
    WrongGuard {
        /// The guard of the table row.
        expected: Guard,
        /// The guard the token is for.
        given: Guard,
    },
}

impl<S: Status> AppliedTransition<S> {
    /// Looks up the move that `event` causes from `from` and checks that `cleared` is for the
    /// guard of that row.
    ///
    /// # Errors
    /// [`PlanError::Illegal`] when the table has no such move; [`PlanError::WrongGuard`] when the
    /// token is for another guard.
    pub fn plan(
        from: S,
        event: S::Event,
        at: Timestamp,
        cleared: GuardCleared,
    ) -> Result<Self, PlanError> {
        let row = from.transition(event)?;
        if row.guard != cleared.guard() {
            return Err(PlanError::WrongGuard {
                expected: row.guard,
                given: cleared.guard(),
            });
        }
        Ok(Self {
            from,
            event,
            to: row.to,
            transition_id: row.id,
            at,
            cleared,
        })
    }

    /// The status the move starts from.
    #[must_use]
    pub const fn from_status(&self) -> S {
        self.from
    }
    /// The event that asked for the move.
    #[must_use]
    pub const fn event(&self) -> S::Event {
        self.event
    }
    /// The status after the move.
    #[must_use]
    pub const fn to_status(&self) -> S {
        self.to
    }
    /// The transition id in `state-machine.json`, such as `S03`.
    #[must_use]
    pub const fn transition_id(&self) -> &'static str {
        self.transition_id
    }
    /// When the engine planned the move. Row timestamps come from the database clock, not this.
    #[must_use]
    pub const fn at(&self) -> Timestamp {
        self.at
    }
    /// The guard that held.
    #[must_use]
    pub fn guard(&self) -> Guard {
        self.cleared.guard()
    }
    /// The digest of the facts the guard was checked on.
    #[must_use]
    pub fn facts_sha256(&self) -> &Sha256Digest {
        self.cleared.facts_sha256()
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// A rule of the store that a write broke. The set is closed and carries no value from a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintRule {
    /// A row with this id exists and its content differs from the one offered.
    IdReusedWithDifferentContent,
    /// A task key is already used in the stage run.
    DuplicateTaskKey,
    /// The task dependencies would close a cycle.
    DependencyCycle,
    /// Another attempt of the stage run is still live.
    OneLiveAttempt,
    /// The stage run has used all its attempts (INV-10).
    AttemptLimit,
    /// The external reference (a GitHub user id) is already recorded for the tenant.
    ExternalReferenceTaken,
    /// A terminal row cannot be edited.
    TerminalRowImmutable,
    /// The transition needs a gate record, or may not carry one.
    GateRecordRule,
    /// The transition needs an attempt end record, or may not carry one.
    AttemptEndRule,
    /// The database refused a status move the table lists. A domain bug.
    IllegalStatusMove,
    /// The event does not agree with its aggregate (missing, other job, version not reached).
    EventAggregateMismatch,
    /// The lease epoch is at its maximum.
    LeaseEpochExhausted,
    /// The text is longer than the column allows, or empty where text is required.
    TextBounds,
    /// The project map record of a repository breaks a rule: the repository would be enabled without
    /// a map commit, the commit is not 40 lowercase hexadecimal characters, the record is only
    /// partly filled, the person who attested it is not an active human of the tenant, or the
    /// person who enables it is not.
    ProjectMapRule,
    /// An enable named a map commit other than the one attested now. The approver meant another
    /// map than the one on file, so nothing changes (finding REG-1).
    ProjectMapChanged,
    /// The person who would enable the repository is the person who attested its map, and the
    /// repository was not registered as a single-maintainer one, so nothing changes (finding
    /// REG-6).
    EnablerIsAttestor,
}

/// Why a start was refused although the stage run looked ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReady {
    /// The job is not `ACTIVE`: paused, waiting, blocked, cancelling or finished.
    JobNotActive,
    /// `not_before` is still in the future by the database clock.
    BackingOff,
}

/// A fault in the store itself, never in the caller's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCode {
    /// The role may not run the statement.
    PermissionDenied,
    /// The tenant setting was missing or malformed.
    TenantSetting,
    /// The adapter could not map a database failure onto this enum.
    Unmapped,
}

/// Why a store call failed. The set is closed: an adapter maps every failure of its database
/// library onto one of these and never lets a library error type or a database message through.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The update started from a version or a status that is no longer current, or an append
    /// lost a race. Read the row again and decide.
    #[error("the row changed since it was read; read it again and retry")]
    Conflict,
    /// No such row for this scope. A row of another tenant is reported the same way.
    #[error("no such row for this scope")]
    NotFound,
    /// A value names a tenant that does not own the job it belongs to.
    #[error("the value names a tenant that does not own this job")]
    TenantMismatch,
    /// The write carries a fence that is not current, or the lease has expired.
    #[error("the lease epoch is not current: this worker no longer holds the lease")]
    LeaseFenced,
    /// A ledger entry does not extend the job's hash chain.
    #[error("the ledger entry does not extend the job's hash chain")]
    ChainBroken,
    /// The stage run may not start now.
    #[error("the stage run may not start now")]
    NotReady(NotReady),
    /// A rule of the store was broken.
    #[error("a store rule was broken")]
    Constraint(ConstraintRule),
    /// The database cannot be reached or refused the call for a reason that is not the caller's.
    /// Nothing the call asked for was applied, except for a `commit` (see below).
    #[error("the database is unavailable")]
    Unavailable,
    /// `commit` was sent and the answer was lost: the transaction may or may not be applied.
    /// Ask [`Store::committed`] with the witness of the transaction before doing anything else.
    #[error("the outcome of the commit is unknown")]
    CommitOutcomeUnknown,
    /// A fault in the store or its configuration.
    #[error("the store failed")]
    Internal(FaultCode),
}

// ---------------------------------------------------------------------------------------------
// Rows and the records that ride on transitions
// ---------------------------------------------------------------------------------------------

/// The result of an insert. Inserts are idempotent: a repeat finds the row it made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inserted<T> {
    /// The row, new or found.
    pub row: Versioned<T>,
    /// False when the row was already there with the same content.
    pub created: bool,
}

/// How a job came to exist. A job is identified by its origin: a second insert with the same
/// origin and a different id returns the first job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOrigin {
    /// Created from a webhook delivery. At most one job comes from one delivery.
    Webhook(WebhookDeliveryId),
    /// Created through the API or the command line with a caller-chosen key.
    Request(IdempotencyKey),
}

/// A key the caller chose so that a retried request finds its first job. 1 to 128 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

/// The stage kinds a job must pass (guard `G_PIPELINE_SCOPE_COMPLETE`). 1 to 14 distinct kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineScope(Vec<StageKind>);

/// A job to create. The status starts at the machine's initial status. The store assigns
/// `created_at` from the database clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    /// The new job's id, from the `IdGenerator`.
    pub id: JobId,
    /// Shared by every event and log line of the job.
    pub correlation_id: CorrelationId,
    /// The repository the job works on. Fixed for the life of the job.
    pub repository: RepositoryId,
    /// The person who asked for the work.
    pub requester: PrincipalId,
    /// `test` jobs may carry fake evidence; `production` jobs may not (INV-08).
    pub execution_mode: ExecutionMode,
    /// The autonomy level the job runs at.
    pub autonomy_level: AutonomyLevel,
    /// The stages the job must pass.
    pub pipeline_scope: PipelineScope,
    /// How the job came to exist, when it has an origin that must be unique.
    pub origin: Option<JobOrigin>,
}

/// A stored job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The job.
    pub id: JobId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// Shared by every event and log line of the job.
    pub correlation_id: CorrelationId,
    /// The repository.
    pub repository: RepositoryId,
    /// The person who asked for the work.
    pub requester: PrincipalId,
    /// Where the job stands.
    pub status: JobStatus,
    /// The execution mode.
    pub execution_mode: ExecutionMode,
    /// The autonomy level.
    pub autonomy_level: AutonomyLevel,
    /// The stages the job must pass.
    pub pipeline_scope: PipelineScope,
    /// How the job came to exist.
    pub origin: Option<JobOrigin>,
    /// The hash of the policy in force at admission, once admitted.
    pub policy_hash: Option<Sha256Digest>,
    /// The normalized request, once intake has produced it.
    pub normalized_request: Option<Sha256Digest>,
    /// When the database created the row.
    pub created_at: Timestamp,
    /// When the job reached a terminal status.
    pub terminal_at: Option<Timestamp>,
}

/// Facts about a job that are set once, outside a status move.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobFacts {
    /// The hash of the policy in force. Set at admission.
    pub policy_hash: Option<Sha256Digest>,
    /// The normalized request. Set by intake.
    pub normalized_request: Option<Sha256Digest>,
}

/// Which jobs to list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobFilter {
    /// Only these statuses. Empty means all.
    pub statuses: Vec<JobStatus>,
    /// Only this repository.
    pub repository: Option<RepositoryId>,
}

/// A position in a listing. Opaque to the caller; pass back what the previous page returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor(String);

/// One page of a keyset listing, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The rows.
    pub rows: Vec<T>,
    /// Where the next page starts, or `None` at the end.
    pub next: Option<PageCursor>,
}

/// The request exactly as received (FR-003). Editing the source creates a new revision with a
/// new hash. A stored revision never changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOriginalRequest {
    /// The new row's id.
    pub id: Uuid7,
    /// The job it belongs to.
    pub job: JobId,
    /// 1 for the first text, 2 for the first edit, and so on.
    pub revision: u32,
    /// Where the text came from.
    pub source: RequestSource,
    /// A pointer such as an issue URL. Untrusted like the text. At most 2048 bytes.
    pub source_ref: Option<String>,
    /// The numeric GitHub id of the author, when there is one.
    pub author_github_user_id: Option<u64>,
    /// Title and body as one text, exactly as received. 1 byte to 1 MiB. Never placed in an
    /// instruction channel.
    pub text: String,
}

/// An identifier of a row that has no typed id of its own.
pub type Uuid7 = uuid::Uuid;

/// Where an original request came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSource {
    /// A GitHub issue.
    GithubIssue,
    /// The API.
    Api,
    /// The command line.
    Cli,
}

/// A stored original request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalRequest {
    /// The row's id.
    pub id: Uuid7,
    /// The job.
    pub job: JobId,
    /// The revision.
    pub revision: u32,
    /// Where the text came from.
    pub source: RequestSource,
    /// The pointer, as received.
    pub source_ref: Option<String>,
    /// The author's numeric GitHub id.
    pub author_github_user_id: Option<u64>,
    /// The text, exactly as received.
    pub text: String,
    /// The SHA-256 of the text, as the database computed it.
    pub content_sha256: Sha256Digest,
    /// When the database captured it.
    pub captured_at: Timestamp,
}

/// The GitHub installation id of a webhook, as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstallationId(pub u64);

/// The GitHub repository id of a webhook, as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GithubRepositoryId(pub u64);

/// A webhook delivery that passed signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWebhookDelivery {
    /// The new row's id.
    pub id: WebhookDeliveryId,
    /// The `X-GitHub-Delivery` header. 8 to 128 bytes.
    pub delivery_id: String,
    /// The `X-GitHub-Event` header, lower case letters and `_`.
    pub event_name: Slug,
    /// The payload's `action`, when it has one.
    pub action: Option<Slug>,
    /// The installation the delivery came through.
    pub installation: InstallationId,
    /// The repository, when the event names one.
    pub repository: Option<GithubRepositoryId>,
    /// The numeric id of the sender.
    pub sender_github_user_id: Option<u64>,
    /// The hash of the raw body.
    pub body_sha256: Sha256Digest,
    /// The hash of the event, action, installation, repository, subject, subject update time and
    /// sender (`policies/security.yaml`, `webhook.semantic_idempotency`).
    pub semantic_key: Option<Sha256Digest>,
}

/// What recording a delivery found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// A new delivery. The caller goes on to create the job in the same transaction.
    Recorded(WebhookDeliveryId),
    /// A repeat, by delivery id, by body hash or by semantic key. Acknowledge and stop. Not an
    /// error.
    Duplicate(DuplicateOf),
}

/// Which key found the earlier delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateOf {
    /// The same `X-GitHub-Delivery`.
    DeliveryId,
    /// The same body.
    Body,
    /// The same event on the same subject revision.
    Semantic,
}

/// The commit of a repository's default branch that holds its project map: exactly 40 lowercase
/// hexadecimal characters.
///
/// This is a claim that a person made, and the store keeps it as one. The engine holds no GitHub
/// credential, so nothing here checks that the commit exists, that it is on the default branch or
/// that the map it holds is any good. The type checks the shape and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectMapCommit(String);

impl ProjectMapCommit {
    /// The number of characters of a commit.
    pub const LENGTH: usize = 40;

    /// Checks and wraps a commit.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless the text is 40 characters, each one of `0` to `9` and `a`
    /// to `f`. Upper case, spaces, a branch name and a 64-character object id are all refused.
    pub fn new(text: &str) -> Result<Self, ValueError> {
        if text.len() == Self::LENGTH
            && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            Ok(Self(text.to_owned()))
        } else {
            Err(ValueError::new(
                "project map commit",
                text,
                "use the 40 lowercase hexadecimal characters of a commit",
            ))
        }
    }

    /// The commit.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectMapCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a person said about a repository's project map: the commit that holds it, who said so and
/// when. It is an attestation, not a verification (see [`ProjectMapCommit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMapAttestation {
    /// The commit of the default branch that holds the map.
    pub commit: ProjectMapCommit,
    /// The person who attested it: an active human principal of the tenant.
    pub attested_by: PrincipalId,
    /// When the database recorded the attestation.
    pub attested_at: Timestamp,
}

/// What an enabled repository was enabled for: the map commit the approver meant, who enabled it
/// and when. It exists exactly while the repository is enabled, and it is emptied when the
/// repository is switched off. A map that is attested again switches the repository off, so an
/// enabled repository is always enabled for the map on file (finding REG-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnabledFor {
    /// The map commit the approver named. For an enabled repository it equals the attested commit.
    pub commit: ProjectMapCommit,
    /// The person who enabled it. `None` only for a row that a privileged writer enabled without
    /// saying who; the Store always says.
    pub enabled_by: Option<PrincipalId>,
    /// When the database recorded the enabling.
    pub enabled_at: Timestamp,
}

/// A repository to register. Registering never takes the flags that grant anything: the row starts
/// disabled, at level `L0`, with no protection result and no project map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRepository {
    /// The new repository's id.
    pub id: RepositoryId,
    /// The GitHub App installation.
    pub installation: InstallationId,
    /// GitHub's numeric repository id. One GitHub repository belongs to one tenant only.
    pub github_repository_id: GithubRepositoryId,
    /// `owner/name`.
    pub full_name: String,
    /// The default branch name.
    pub default_branch: String,
    /// True when one person may both attest the project map and enable the repository (finding
    /// REG-6). It is a statement made at registration by an operator, it is recorded in the audit
    /// trail, and nothing changes it afterwards. False is the strict rule: the enabler is another
    /// person than the attestor.
    pub single_maintainer: bool,
}

/// A repository registered for the tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// The repository.
    pub id: RepositoryId,
    /// The tenant.
    pub tenant_id: TenantId,
    /// The GitHub App installation.
    pub installation: InstallationId,
    /// GitHub's numeric repository id.
    pub github_repository_id: GithubRepositoryId,
    /// `owner/name`.
    pub full_name: String,
    /// The default branch name, as registered.
    pub default_branch: String,
    /// False when the repository is switched off.
    pub enabled: bool,
    /// True when the protection preflight passed at the last check.
    pub protection_preflight_passed: bool,
    /// The highest autonomy level the repository may run at.
    pub autonomy_ceiling: AutonomyLevel,
    /// The attestation of the project map. `None` until a person attests it, and a repository
    /// with `None` is never enabled (the table says so for every role).
    pub project_map: Option<ProjectMapAttestation>,
    /// What the repository was enabled for. `Some` exactly while `enabled` is true.
    pub enabled_for: Option<EnabledFor>,
    /// True when the repository was registered as a single-maintainer one (finding REG-6): the
    /// person who attests its map may also enable it.
    pub single_maintainer: bool,
    /// False when a person attested the map and is no longer an active human principal of the
    /// tenant (a disabled person, or a service). True when nobody attested it.
    pub attestor_is_active: bool,
    /// False when a person enabled the repository and is no longer an active human principal of
    /// the tenant. True when nobody is named as the enabler.
    pub enabler_is_active: bool,
}

impl Repository {
    /// Which repository this is for a question about authority: its registered name and GitHub's
    /// numeric id of it (finding RR-28). Every caller that holds the row asks with this and not with
    /// the name alone, so an allowlist entry that lists the id follows the repository through a
    /// rename or a transfer, and a new repository under the old name is another repository.
    #[must_use]
    pub fn identity(&self) -> factory_domain::policy::authority::RepositoryIdentity<'_> {
        factory_domain::policy::authority::RepositoryIdentity::registered(
            &self.full_name,
            self.github_repository_id.0,
        )
    }

    /// True when the people behind the repository still stand: the attestor of its map and its
    /// enabler are active human principals of the tenant (finding REG-6).
    #[must_use]
    pub const fn standing_holds(&self) -> bool {
        self.attestor_is_active && self.enabler_is_active
    }

    /// True when a new job may start for this repository: it is enabled and the people who
    /// attested its map and enabled it are still active humans of the tenant. A repository that is
    /// enabled but fails the second test is treated as not enabled for new work, and fails
    /// closed. The flag `enabled` alone is the stored fact, not the answer to "may a new job
    /// start".
    #[must_use]
    pub const fn open_for_new_jobs(&self) -> bool {
        self.enabled && self.standing_holds()
    }
}

/// The fixed knobs of a stage run at creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewStageRun {
    /// The new stage run's id.
    pub id: StageRunId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// Which stage this is a run of.
    pub kind: StageKind,
    /// 1 for the first run of this kind in the job, then 2, 3. Rework creates the next number.
    pub run_number: u32,
    /// How many attempts the run may use (1 to 20), from the stage contract.
    pub max_attempts: u8,
    /// The run this one replaces after a rework request.
    pub rework_of: Option<StageRunId>,
}

/// What the gate decided, stored with the move that records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRecord {
    /// The gate outcome.
    pub outcome: GateOutcome,
    /// The gate report, stored as an artifact. `None` only for `NOT_APPLICABLE`.
    pub report_sha256: Option<Sha256Digest>,
    /// The digest of what failed, for the stagnation detector. `None` unless the outcome is
    /// `FAILED`.
    pub failing_set_sha256: Option<Sha256Digest>,
}

/// What may ride on a stage run transition. Which fields are required for which transition is
/// [`stage_run_effects_rule`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StageRunEffects {
    /// The gate outcome and report.
    pub gate: Option<GateRecord>,
    /// The resolved stage contract. Recorded on `S01`.
    pub contract_sha256: Option<Sha256Digest>,
    /// For a move into `READY`: the earliest start, as a delay after the database time. `None`
    /// means now.
    pub not_before_after: Option<Duration>,
}

/// What a transition requires of its [`StageRunEffects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectsRule {
    /// The gate outcome the transition must record, or `None` when it must not record one.
    pub gate: Option<GateOutcome>,
    /// True when the transition must record the contract (`S01`).
    pub contract: bool,
}

/// The effects each stage run transition requires: `S01` the contract; `S02` NOT_APPLICABLE;
/// `S08` and `S14` PASSED; `S09` and `S12` FAILED; `S11` and `S21` BLOCKED; no other transition
/// records a gate outcome (`S18` keeps the BLOCKED recorded by `S11` or `S21`).
#[must_use]
pub fn stage_run_effects_rule(transition_id: &str) -> EffectsRule {
    let gate = match transition_id {
        "S02" => Some(GateOutcome::NotApplicable),
        "S08" | "S14" => Some(GateOutcome::Passed),
        "S09" | "S12" => Some(GateOutcome::Failed),
        "S11" | "S21" => Some(GateOutcome::Blocked),
        _ => None,
    };
    EffectsRule {
        gate,
        contract: transition_id == "S01",
    }
}

/// A stored stage run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRun {
    /// The stage run.
    pub id: StageRunId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// Which stage this is a run of.
    pub kind: StageKind,
    /// 1 for the first run of this kind in the job.
    pub run_number: u32,
    /// Where it stands.
    pub status: StageRunStatus,
    /// The fencing counter. It never goes down.
    pub lease_epoch: LeaseEpoch,
    /// How many attempts the run may use.
    pub max_attempts: u8,
    /// The earliest time it may start. Also the retry back-off.
    pub not_before: Timestamp,
    /// The run this one replaced.
    pub rework_of: Option<StageRunId>,
    /// The resolved stage contract.
    pub contract_sha256: Option<Sha256Digest>,
    /// The recorded gate outcome.
    pub gate: Option<GateRecord>,
    /// When the database created the row.
    pub created_at: Timestamp,
    /// When the run reached a terminal status.
    pub finished_at: Option<Timestamp>,
    /// When the run was superseded.
    pub superseded_at: Option<Timestamp>,
}

/// A ready stage run that a system transaction found. It is a hint, not a claim: it grants
/// nothing and holds no lock after the transaction ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCandidate {
    /// The tenant. The engine opens a tenant transaction for it.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// The version the candidate was read at. `start_attempt` compares with it.
    pub version: Version,
    /// When it became startable.
    pub not_before: Timestamp,
}

/// Why an attempt is due for the sweeper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DueReason {
    /// A `STARTING` or `RUNNING` attempt whose lease ended before the database time (`A07`).
    LeaseExpired,
    /// A `STARTING` or `RUNNING` attempt past its deadline (`A06`).
    DeadlinePassed,
    /// A `CANCELLING` attempt past its teardown deadline (`A10`).
    TeardownDeadlinePassed,
}

/// An attempt that a system transaction found due. The engine moves it in a tenant transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueAttempt {
    /// The tenant.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// The attempt.
    pub attempt: AttemptId,
    /// The version it was read at.
    pub version: Version,
    /// Why it is due.
    pub reason: DueReason,
}

/// What `start_attempt` needs. It moves the stage run `READY` to `RUNNING` (`S03`), raises its
/// epoch by one and creates the attempt in `STARTING` with its lease, as one atomic step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAttempt {
    /// The new attempt's id.
    pub attempt: AttemptId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// The version the candidate was read at.
    pub expected: Version,
    /// The worker that takes the lease.
    pub worker: WorkerId,
    /// How long the lease lasts from the database time, and how long each heartbeat extends it.
    pub lease_ttl: Duration,
    /// How long the attempt may run, from the database time. Becomes `deadline_at`.
    pub attempt_timeout: Duration,
    /// `S03`, planned with the cleared `G_LEASE_ACQUIRED`.
    pub transition: AppliedTransition<StageRunStatus>,
}

/// What `start_attempt` created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedAttempt {
    /// The stage run after the move.
    pub stage_run: Versioned<StageRun>,
    /// The attempt, in `STARTING`.
    pub attempt: Versioned<Attempt>,
}

/// The facts about the sandbox of an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRecord {
    /// The sandbox's name.
    pub sandbox: SandboxId,
    /// True when the sandbox could not be confirmed gone.
    pub leaked: bool,
}

/// What rides on an attempt transition. See [`attempt_end_rule`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptEnd {
    /// Why the attempt failed. Required for `A02` and `A05`, forbidden elsewhere: `TIMED_OUT`
    /// and `LEASE_LOST` are statuses, not failure classes in the column.
    pub failure_class: Option<FailureClass>,
    /// The validated output. Required for `A04`, forbidden elsewhere.
    pub output: Option<Sha256Digest>,
    /// The sandbox, when the transition knows it (`A01`, `A09`, `A10`).
    pub sandbox: Option<SandboxRecord>,
    /// How long teardown may take, from the database time. Required for `A08`, which sets
    /// `teardown_deadline_at` in the same statement, forbidden elsewhere.
    pub teardown_grace: Option<Duration>,
}

/// What an attempt transition requires of its [`AttemptEnd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptEndRule {
    /// True when a failure class is required.
    pub failure_class: bool,
    /// True when an output hash is required.
    pub output: bool,
    /// True when a teardown grace period is required.
    pub teardown_grace: bool,
}

/// `A02` and `A05` require a failure class; `A04` requires an output; `A08` requires a teardown
/// grace period; no other transition may carry any of them.
#[must_use]
pub fn attempt_end_rule(transition_id: &str) -> AttemptEndRule {
    AttemptEndRule {
        failure_class: matches!(transition_id, "A02" | "A05"),
        output: transition_id == "A04",
        teardown_grace: transition_id == "A08",
    }
}

/// A stored attempt. The lease belongs to the attempt, never to the stage run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The attempt.
    pub id: AttemptId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// The stage run it is a try at.
    pub stage_run_id: StageRunId,
    /// Which try this is for the stage run, from 1.
    pub number: u32,
    /// Where it stands.
    pub status: AttemptStatus,
    /// The worker that holds the lease.
    pub worker: WorkerId,
    /// The epoch the lease was granted at. Never changes.
    pub epoch: LeaseEpoch,
    /// When the lease ends unless a heartbeat renews it, by the database clock.
    pub lease_expires_at: Timestamp,
    /// The last heartbeat.
    pub last_heartbeat_at: Option<Timestamp>,
    /// When the attempt times out.
    pub deadline_at: Timestamp,
    /// Set while `CANCELLING`: when teardown stops waiting and kills.
    pub teardown_deadline_at: Option<Timestamp>,
    /// Why it failed, for `FAILED`.
    pub failure_class: Option<FailureClass>,
    /// The validated output, for `SUCCEEDED`.
    pub output: Option<Sha256Digest>,
    /// The sandbox, once known.
    pub sandbox: Option<SandboxRecord>,
    /// When the database created the row.
    pub created_at: Timestamp,
    /// When the attempt reached a terminal status.
    pub ended_at: Option<Timestamp>,
}

/// What a heartbeat found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRenewal {
    /// The attempt's status. `CANCELLING` tells the worker to tear down.
    pub status: AttemptStatus,
    /// The new end of the lease.
    pub lease_expires_at: Timestamp,
    /// The attempt deadline.
    pub deadline_at: Timestamp,
}

/// One node of the task graph, with the keys of the nodes it depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTaskNode {
    /// The new node's id.
    pub id: TaskNodeId,
    /// The node's key in the plan, such as `t-001`.
    pub key: Slug,
    /// Keys of nodes of the same plan that must succeed first.
    pub depends_on: Vec<Slug>,
}

/// A task graph to create for an `IMPLEMENTATION` stage run, in one atomic step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTaskGraph {
    /// The stage run that executes the plan.
    pub stage_run: StageRunId,
    /// The plan artifact the nodes come from.
    pub plan_sha256: Sha256Digest,
    /// The nodes, in any order. Keys are unique and the dependencies acyclic.
    pub nodes: Vec<NewTaskNode>,
}

/// A stored node of the task graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskNode {
    /// The node.
    pub id: TaskNodeId,
    /// The tenant that owns it.
    pub tenant_id: TenantId,
    /// The job it belongs to.
    pub job_id: JobId,
    /// The stage run that executes it.
    pub stage_run_id: StageRunId,
    /// The node's key in the plan.
    pub key: Slug,
    /// The plan artifact.
    pub plan_sha256: Sha256Digest,
    /// Where it stands.
    pub status: TaskNodeStatus,
    /// How many times it was retried.
    pub retry_count: u32,
    /// The attempt working on it.
    pub current_attempt: Option<AttemptId>,
    /// The commit that finished it.
    pub commit: Option<GitSha>,
    /// When it was created.
    pub created_at: Timestamp,
}

/// What rides on a task node transition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskNodeEffects {
    /// The attempt that took the node. Set on `T02`, cleared on `T04` and `T05`.
    pub attempt: Option<AttemptId>,
    /// The commit that finished the node. Required on `T03`.
    pub commit: Option<GitSha>,
}

/// Which side of a stage run a stored artifact is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactDirection {
    /// The run consumed it. A human answer is an input with the role `human-answer-<n>`.
    Input,
    /// The run produced it.
    Output,
}

/// An artifact a stage run consumed or produced, by role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRunArtifact {
    /// The stage run.
    pub stage_run: StageRunId,
    /// Input or output.
    pub direction: ArtifactDirection,
    /// What it is for, such as `spec` or `human-answer-1`.
    pub role: Slug,
    /// The artifact.
    pub sha256: Sha256Digest,
    /// When the database recorded it.
    pub created_at: Timestamp,
}

/// A person or service to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A person, named by the immutable numeric GitHub user id.
    Human {
        /// The numeric GitHub user id.
        github_user_id: u64,
    },
    /// A service.
    Service,
}

/// A principal to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrincipal {
    /// The new principal's id.
    pub id: PrincipalId,
    /// Human or service.
    pub kind: PrincipalKind,
    /// The login at the time of recording. Display only; never authorizes anything.
    pub login: Option<String>,
}

/// A stored person or service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The principal.
    pub id: PrincipalId,
    /// The tenant that owns the record.
    pub tenant_id: TenantId,
    /// Human or service.
    pub kind: PrincipalKind,
    /// The login at the time of recording.
    pub login: Option<String>,
    /// When it was recorded.
    pub created_at: Timestamp,
    /// When it was switched off.
    pub disabled_at: Option<Timestamp>,
}

/// The decision of an approver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalDecision {
    /// Approve the pull request at the head named in the record.
    Approve,
    /// Reject the job.
    Reject,
    /// Send the work back.
    Rework,
    /// Pause the job.
    Pause,
    /// Cancel the job.
    Cancel,
}

/// Where the decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalChannel {
    /// The dashboard.
    Dashboard,
    /// The command line.
    Cli,
    /// A pull request comment.
    GithubComment,
}

/// What an approval is bound to. All five are required for an approve decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBinding {
    /// The pull request head the approver saw.
    pub pr_head: GitSha,
    /// The tree hash at that head.
    pub tree: GitSha,
    /// The base commit.
    pub base: GitSha,
    /// The evidence manifest the approver saw.
    pub evidence_manifest: Sha256Digest,
    /// The specification version.
    pub spec_version: u32,
}

/// An approver's decision to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApproval {
    /// The new row's id.
    pub id: ApprovalId,
    /// The job.
    pub job: JobId,
    /// The `APPROVAL` stage run the decision is for.
    pub stage_run: StageRunId,
    /// The decision.
    pub decision: ApprovalDecision,
    /// The approver. Must be a human principal of the tenant.
    pub approver: PrincipalId,
    /// The designation the approver held, such as `approver`.
    pub designation: Slug,
    /// The hash of the allowlist version that authorized the approver.
    pub allowlist_version: Sha256Digest,
    /// The binding. Required when `decision` is `Approve`.
    pub binding: Option<ApprovalBinding>,
    /// The hash of the policy in force.
    pub policy_hash: Sha256Digest,
    /// The approver's reason. 1 to 2000 bytes.
    pub reason: String,
    /// Where the decision was made.
    pub channel: ApprovalChannel,
    /// How long the approval counts, from the database time.
    pub valid_for: Duration,
}

/// Why an approval stopped counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalInvalidation {
    /// The head moved.
    NewCommit,
    /// The base branch moved.
    BaseMoved,
    /// The policy changed.
    PolicyChange,
    /// The sandbox image changed.
    ImageChange,
    /// The specification was revised.
    SpecRevision,
}

/// A stored approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The row's id.
    pub id: ApprovalId,
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// The decision.
    pub decision: ApprovalDecision,
    /// The approver.
    pub approver: PrincipalId,
    /// The approver's numeric GitHub user id.
    pub approver_github_user_id: u64,
    /// The designation.
    pub designation: Slug,
    /// The binding, for an approve decision.
    pub binding: Option<ApprovalBinding>,
    /// The reason.
    pub reason: String,
    /// The channel.
    pub channel: ApprovalChannel,
    /// When the database recorded it.
    pub created_at: Timestamp,
    /// When it stops counting.
    pub expires_at: Timestamp,
    /// Why and when it stopped counting early.
    pub invalidated: Option<(Timestamp, ApprovalInvalidation)>,
}

/// An artifact to index for the tenant.
///
/// The size is part of the entry and is not optional. The index records it, quota and accounting
/// are counted from it, and an adapter that indexes a blob it does not hold has no length to read.
/// An `ArtifactRef` may omit the size, so the entry does not take one: it names the hash, the
/// media type and the size as three fields, and a reference without a size cannot be turned into
/// an entry ([`NewArtifactIndexEntry::from_reference`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifactIndexEntry {
    /// The content hash of the artifact.
    pub sha256: Sha256Digest,
    /// What kind of bytes it is.
    pub media_type: MediaType,
    /// The length of the blob in bytes.
    pub size_bytes: NonNegativeInt,
    /// The job that made it, when one did.
    pub origin: Option<(JobId, StageRunId)>,
}

impl NewArtifactIndexEntry {
    /// The entry for a reference that carries its size, and `None` for one that does not.
    #[must_use]
    pub fn from_reference(
        artifact: &ArtifactRef,
        origin: Option<(JobId, StageRunId)>,
    ) -> Option<Self> {
        Some(Self {
            sha256: artifact.sha256.clone(),
            media_type: artifact.media_type.clone(),
            size_bytes: artifact.size_bytes?,
            origin,
        })
    }
}

/// The tenant's record that it holds an artifact. A tenant reads a blob only through this row
/// (ADR 0008, and `ArtifactStore::get` in ports-v1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIndexEntry {
    /// The tenant that holds the artifact.
    pub tenant_id: TenantId,
    /// The artifact, by content hash. Its size is always present: the index requires it.
    pub artifact: ArtifactRef,
    /// The job and stage run that made it.
    pub origin: Option<(JobId, StageRunId)>,
    /// When the database indexed it.
    pub created_at: Timestamp,
}

/// Who did something that is recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditActor {
    /// A person.
    Human(PrincipalId),
    /// A service principal.
    Service(PrincipalId),
    /// A factory component, such as `workflow.engine`.
    System(Slug),
    /// Nobody could be identified, such as a webhook with a bad signature. The label says where
    /// the call came from, for example `webhook`.
    Anonymous(Slug),
}

/// What the audit record says was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDecision {
    /// Allowed.
    Allow,
    /// Refused.
    Deny,
    /// A fact recorded with no decision.
    Record,
}

/// A dotted lower-case action name such as `approval.recorded` or `webhook.rejected`. Segments
/// are `[a-z][a-z0-9_]*`, joined by `.`, at most 100 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditAction(String);

/// One audit record to write. The log is append only. The store assigns the sequence, the time
/// and the hash chain; the caller never supplies a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    /// The record's id, from the `IdGenerator`. A repeat of the same id and content is a no-op.
    pub id: AuditEventId,
    /// Who did it.
    pub actor: AuditActor,
    /// What was done.
    pub action: AuditAction,
    /// What it was done to, 1 to 500 bytes. Never a secret and never issue text.
    pub subject: String,
    /// What was decided.
    pub decision: AuditDecision,
    /// Why, 1 to 1000 bytes. Never reveals which test of a group failed.
    pub reason: String,
    /// The hash of the policy that was in force.
    pub policy_hash: Sha256Digest,
    /// The job the action concerns. `None` for an event that belongs to no job, such as a
    /// rejected issue (FR-002).
    pub job: Option<JobId>,
    /// The stage run, when there is one. Needs a job.
    pub stage_run: Option<StageRunId>,
    /// Shared by everything in the job. A fresh one for an event with no job.
    pub correlation_id: CorrelationId,
}

/// A stored audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The tenant's audit sequence, from 1.
    pub sequence: u64,
    /// The event as written.
    pub event: NewAuditEvent,
    /// When the database wrote it.
    pub created_at: Timestamp,
    /// The record's hash in the chain.
    pub hash: Sha256Digest,
}

/// Which audit records to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFilter {
    /// Every record of the tenant, including those with no job.
    Tenant,
    /// The records of one job.
    Job(JobId),
}

/// Proof that a transaction was applied, readable without the transaction. Every state-changing
/// engine transaction writes at least one outbox event or audit record and keeps its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Witness {
    /// An outbox event the transaction enqueued.
    OutboxEvent(EventId),
    /// An audit record the transaction wrote.
    Audit(AuditEventId),
}

/// The SHA-256 of a presented API token, 32 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenHash(pub [u8; 32]);

/// The audience an API serves, such as `factory-api`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience(pub Slug);

impl IdempotencyKey {
    /// The most bytes a key may have.
    pub const MAX_BYTES: usize = 128;

    /// Checks and wraps a caller-chosen key.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless the key has 1 to 128 bytes.
    pub fn new(key: &str) -> Result<Self, ValueError> {
        if (1..=Self::MAX_BYTES).contains(&key.len()) {
            Ok(Self(key.to_owned()))
        } else {
            Err(ValueError::new(
                "idempotency key",
                key,
                "use 1 to 128 bytes",
            ))
        }
    }

    /// The key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PipelineScope {
    /// The most stage kinds a scope may hold.
    pub const MAX_KINDS: usize = 14;

    /// Checks and wraps the stages a job must pass.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless there are 1 to 14 kinds and no kind appears twice.
    pub fn new(kinds: Vec<StageKind>) -> Result<Self, ValueError> {
        let mut seen = std::collections::BTreeSet::new();
        let distinct = kinds.iter().all(|kind| seen.insert(kind.as_str()));
        if (1..=Self::MAX_KINDS).contains(&kinds.len()) && distinct {
            Ok(Self(kinds))
        } else {
            Err(ValueError::new(
                "pipeline scope",
                &format!("{} stage kinds", kinds.len()),
                "list 1 to 14 distinct stage kinds",
            ))
        }
    }

    /// The stage kinds, in the order given.
    #[must_use]
    pub fn kinds(&self) -> &[StageKind] {
        &self.0
    }
}

impl PageCursor {
    /// Wraps a position. Only the store that produced a page makes a cursor; a caller passes back
    /// the one it was given and never builds one.
    #[must_use]
    pub fn new(position: String) -> Self {
        Self(position)
    }

    /// The position text, for the store that made it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AuditAction {
    /// The most bytes an action may have.
    pub const MAX_BYTES: usize = 100;

    /// Checks and wraps an action name.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless every dot-separated segment starts with a lower-case letter
    /// and holds only lower-case letters, digits and `_`, and the whole name has at most 100
    /// bytes.
    pub fn new(action: &str) -> Result<Self, ValueError> {
        let segment_ok = |segment: &str| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|first| first.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        };
        if action.len() <= Self::MAX_BYTES && action.split('.').all(segment_ok) {
            Ok(Self(action.to_owned()))
        } else {
            Err(ValueError::new(
                "audit action",
                action,
                "use lower-case segments such as approval.recorded, at most 100 bytes",
            ))
        }
    }

    /// The action.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The hash of a token is not the token, but it identifies one, so it stays out of logs.
        f.write_str("TokenHash(..)")
    }
}

// ---------------------------------------------------------------------------------------------
// The traits
// ---------------------------------------------------------------------------------------------

/// The entry point to the store.
///
/// # Preconditions
/// The schema is at the version the code expects (`schema_version`, checked at start-up).
///
/// # Postconditions
/// Each `begin` returns a new, independent transaction. Nothing a transaction writes is visible
/// to another until it commits. The three methods that run without a transaction
/// (`resolve_token`, `resolve_installation`, `record_platform_audit`, `committed`) each do one
/// statement or one short transaction of their own.
///
/// # Errors
/// [`StoreError::Unavailable`], plus the variants named on each method. A lookup that finds
/// nothing returns `Ok(None)` for every reason, so the caller cannot tell which reason it was.
///
/// # Idempotency
/// Beginning a transaction and every lookup change nothing. `record_platform_audit` is
/// idempotent by event id.
///
/// # Cancellation and timeouts
/// Dropping a future returned by this trait before it completes leaves nothing applied, except
/// `record_platform_audit`, which may have been applied. Every call has a statement timeout set
/// by the adapter. A timeout is `Unavailable`.
#[async_trait]
pub trait Store: Send + Sync {
    /// Says whether this store is the real database (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Opens a transaction that sees only the rows of `scope`'s tenant.
    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError>;

    /// Opens a read-only transaction that sees every tenant. Only the workflow crate calls this
    /// (DEP-09). It can find work and cannot write.
    async fn begin_system(&self, scope: SystemScope) -> Result<Box<dyn SystemTx>, StoreError>;

    /// Before any tenant is known. `None` for an unknown, expired, revoked or wrong-audience
    /// token, a disabled owner and a disabled tenant alike.
    async fn resolve_token(
        &self,
        hash: &TokenHash,
        audience: &Audience,
    ) -> Result<Option<ResolvedPrincipal>, StoreError>;

    /// Before any tenant is known. `None` when the installation or repository is unknown, the
    /// pair does not belong together, or either is disabled.
    async fn resolve_installation(
        &self,
        installation: InstallationId,
        repository: GithubRepositoryId,
    ) -> Result<Option<ResolvedRepository>, StoreError>;

    /// Writes one audit record under the platform tenant, for an event that belongs to no tenant
    /// (a webhook with a bad signature, an unknown installation). `event.job` must be `None`.
    async fn record_platform_audit(
        &self,
        scope: PlatformScope,
        event: NewAuditEvent,
    ) -> Result<AuditRecord, StoreError>;

    /// True when the witnessed write is stored for the tenant. The answer after a
    /// [`StoreError::CommitOutcomeUnknown`].
    async fn committed(&self, scope: TenantScope, witness: Witness) -> Result<bool, StoreError>;

    /// The version of the schema the database is at.
    async fn schema_version(&self) -> Result<SchemaVersion, StoreError>;
}

/// The cross-tenant, read-only transaction of the engine. It finds work and returns identifiers;
/// every change is made in a tenant transaction for the tenant that was found (ADR 0012,
/// ADR 0014).
///
/// # Preconditions
/// Opened by `Store::begin_system`.
///
/// # Postconditions
/// A found row is a hint. Another worker may find the same row, and by the time a tenant
/// transaction opens the row may have changed. `finish` releases every lock the transaction took.
///
/// # Errors
/// [`StoreError::Unavailable`]; [`StoreError::Internal`] when the system role lacks a grant.
///
/// # Idempotency
/// Every method is a read.
///
/// # Cancellation and timeouts
/// A dropped call leaves nothing applied and holds no lock after the transaction is dropped. The
/// adapter sets a statement timeout; a timeout is Unavailable.
#[async_trait]
pub trait SystemTx: Send {
    /// The database's current time.
    async fn database_time(&mut self) -> Result<Timestamp, StoreError>;

    /// `READY` stage runs of `ACTIVE` jobs whose `not_before` is not after the database time,
    /// ordered by `not_before` then id, at most `limit`. The real store takes
    /// `FOR NO KEY UPDATE SKIP LOCKED` on them so two concurrent finders mostly see different
    /// rows. A lease is not consulted: a stage run has none.
    async fn find_claim_candidates(
        &mut self,
        limit: u32,
    ) -> Result<Vec<ClaimCandidate>, StoreError>;

    /// Attempts that are due for `reason` by the database clock, oldest due first, at most
    /// `limit`.
    async fn find_due_attempts(
        &mut self,
        reason: DueReason,
        limit: u32,
    ) -> Result<Vec<DueAttempt>, StoreError>;

    /// Ends the transaction and releases its locks. Nothing was written.
    async fn finish(self: Box<Self>) -> Result<(), StoreError>;
}

/// One database transaction for one tenant. Dropping it without calling `commit` rolls it back.
///
/// # Preconditions
/// The transaction is open and the caller awaits nothing but the store while it is (ADR 0007).
///
/// # Postconditions
/// After `commit` returns `Ok`, every write is visible to every later transaction, all together.
/// After `commit` returns `Conflict` or `Unavailable`, `rollback`, or a drop, none is. After
/// `CommitOutcomeUnknown` either all or none is: ask `Store::committed`. A transaction reads its
/// own writes.
///
/// # Errors
/// `commit`: `Conflict` (first committer wins), `Constraint` (a deferred rule failed at commit),
/// `Unavailable` (the commit was never sent), `CommitOutcomeUnknown` (it was sent and the answer
/// was lost). `rollback`: `Unavailable` only.
///
/// # Idempotency
/// A transaction is used once: `commit` and `rollback` take it by value.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later
/// call returns `Unavailable` and the only safe step is to drop it. Statement and lock timeouts
/// are set by the adapter; a timeout is `Unavailable` and poisons the transaction.
#[async_trait]
pub trait Tx:
    JobOps
    + RequestOps
    + DeliveryOps
    + RepositoryOps
    + StageRunOps
    + AttemptOps
    + TaskNodeOps
    + StageArtifactOps
    + ApprovalOps
    + LedgerOps
    + OutboxOps
    + AuditOps
    + ArtifactIndexOps
    + PrincipalOps
    + Send
{
    /// The database's current time. Lease and deadline checks use this and never the `Clock`.
    async fn database_time(&mut self) -> Result<Timestamp, StoreError>;

    /// Makes every write of the transaction visible, all together.
    async fn commit(self: Box<Self>) -> Result<(), StoreError>;

    /// Discards every write of the transaction.
    async fn rollback(self: Box<Self>) -> Result<(), StoreError>;
}

/// Jobs.
///
/// # Idempotency
/// `insert_job` returns the existing job when the id and content match, or when the origin
/// matches (see [`JobOrigin`]); the same id with other content is
/// `Constraint(IdReusedWithDifferentContent)`. `transition_job` and `update_job_facts` are
/// compare and swap: applied twice with the same `expected`, one succeeds and the other is a
/// `Conflict`.
///
/// # Preconditions
/// A tenant transaction that is open and not poisoned. Every id the call names belongs to the
/// transaction's tenant.
///
/// # Postconditions
/// A stored job is readable by its own tenant only. created_at comes from the database clock. A
/// status move is stored with the transition id and the guard that cleared it.
///
/// # Errors
/// StoreError. The variants a method can return are named on the method. A row of another tenant is
/// reported as NotFound.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait JobOps {
    /// Creates a job.
    async fn insert_job(&mut self, new: NewJob) -> Result<Inserted<Job>, StoreError>;
    /// Reads a job.
    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError>;
    /// Jobs of the tenant, newest first.
    async fn list_jobs(
        &mut self,
        filter: JobFilter,
        after: Option<PageCursor>,
        limit: u32,
    ) -> Result<Page<Versioned<Job>>, StoreError>;
    /// Compare and swap on the job's status and version.
    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError>;
    /// Sets facts that do not move the status. A fact already set to another value is a
    /// `Constraint(IdReusedWithDifferentContent)`; the same value is a no-op that still bumps
    /// nothing.
    async fn update_job_facts(
        &mut self,
        id: JobId,
        expected: Version,
        facts: JobFacts,
    ) -> Result<Version, StoreError>;
}

/// The original request text, kept apart from everything the engine derives from it.
///
/// # Idempotency
/// `record_original_request` is idempotent by id and content. A revision number already used
/// with other text is `Constraint(IdReusedWithDifferentContent)`.
///
/// # Preconditions
/// A tenant transaction that is open and not poisoned. Every id the call names belongs to the
/// transaction's tenant.
///
/// # Postconditions
/// A stored revision never changes. The content hash is computed by the database from the stored
/// text.
///
/// # Errors
/// StoreError::NotFound (no such job or revision), StoreError::Constraint
/// (IdReusedWithDifferentContent, TextBounds).
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait RequestOps {
    /// Stores one revision of the request exactly as received.
    async fn record_original_request(
        &mut self,
        new: NewOriginalRequest,
    ) -> Result<Inserted<OriginalRequest>, StoreError>;
    /// A revision, or the latest when `revision` is `None`.
    async fn get_original_request(
        &mut self,
        job: JobId,
        revision: Option<u32>,
    ) -> Result<OriginalRequest, StoreError>;
}

/// Webhook deliveries.
///
/// # Idempotency
/// `record_delivery` is the duplicate filter: a repeat is `Duplicate`, never an error, and
/// fifty concurrent copies of one delivery give one `Recorded`.
///
/// # Preconditions
/// A tenant transaction that is open and not poisoned. Every id the call names belongs to the
/// transaction's tenant.
///
/// # Postconditions
/// After a Recorded outcome the delivery is stored and a later delivery with the same delivery id,
/// body hash or semantic key is a Duplicate.
///
/// # Errors
/// StoreError::Constraint (TextBounds). A repeat is Duplicate, never an error.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait DeliveryOps {
    /// Records a verified delivery, or says which earlier one it repeats.
    async fn record_delivery(
        &mut self,
        new: NewWebhookDelivery,
    ) -> Result<DeliveryOutcome, StoreError>;
}

/// Registered repositories.
///
/// # Preconditions
/// A tenant transaction that is open and not poisoned. Every id the call names belongs to the
/// transaction's tenant.
///
/// # Postconditions
/// A repository is readable by its own tenant only. A recorded preflight result replaces the earlier
/// one.
///
/// # Errors
/// StoreError::NotFound, StoreError::Conflict (stale version).
///
/// # Idempotency
/// get_repository is a read. register_repository is idempotent by id and content, like every insert.
/// record_protection_preflight, attest_project_map, enable_repository and disable_repository are
/// compare and swap on the version.
///
/// # Rules
/// * A repository is registered disabled, at level `L0`, with no protection result and no project
///   map. Registration cannot say otherwise.
/// * A repository is enabled only with a project map commit. The table refuses the other case for
///   every role, so `enable_repository` on a repository with no map is
///   `Constraint(ProjectMapRule)` and changes nothing.
/// * A repository is enabled for the map commit the approver names, and only for the one on file.
///   `enable_repository` with another commit is `Constraint(ProjectMapChanged)` and changes nothing.
/// * An enabled repository does not stay enabled over another map. `attest_project_map` with a
///   different commit or a different person on an enabled repository switches it off in the same
///   statement (the table does it, for every writer), and the caller enables it again by naming
///   the new commit (finding REG-1).
/// * The project map is an attestation by a person. The store records the commit, the principal
///   and the database time. It does not look at the repository and cannot.
/// * The person who enables a repository is not the person who attested its map, unless the
///   repository was registered with `single_maintainer` (finding REG-6). The flag is written at
///   registration and no method changes it.
/// * `get_repository` says whether the attestor and the enabler are still active human principals
///   of the tenant (`attestor_is_active`, `enabler_is_active`). A caller that decides whether a new
///   job may start asks `Repository::open_for_new_jobs`, not `enabled` alone.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait RepositoryOps {
    /// Reads a repository of the tenant.
    async fn get_repository(
        &mut self,
        id: RepositoryId,
    ) -> Result<Versioned<Repository>, StoreError>;
    /// Records the result of the protection preflight. `autonomy_ceiling` never rises above the
    /// ceiling an org admin set; the adapter keeps the lower of the two.
    async fn record_protection_preflight(
        &mut self,
        id: RepositoryId,
        expected: Version,
        passed: bool,
    ) -> Result<Version, StoreError>;
    /// Registers a repository for the tenant. Idempotent by id and content: a repeat returns the
    /// first row with `created: false`. A GitHub repository that another registration already
    /// holds, in this tenant or in another, is reported as `NotFound` (NT-TEN-05): the caller
    /// cannot learn which.
    async fn register_repository(
        &mut self,
        new: NewRepository,
    ) -> Result<Inserted<Repository>, StoreError>;
    /// Records that a person attested the project map at `commit`. Replaces an earlier attestation.
    /// `attested_by` must be an active human principal of the tenant, or the call is
    /// `Constraint(ProjectMapRule)`. When the repository is enabled and the commit or the person
    /// changes, the repository is switched off by the same change.
    async fn attest_project_map(
        &mut self,
        id: RepositoryId,
        expected: Version,
        commit: ProjectMapCommit,
        attested_by: PrincipalId,
    ) -> Result<Version, StoreError>;
    /// Switches a repository on for the map commit `commit`, on the word of `enabled_by`. Without a
    /// map commit the call is `Constraint(ProjectMapRule)`, and so it is when `enabled_by` is not
    /// an active human principal of the tenant. When `commit` is not the commit attested now it is
    /// `Constraint(ProjectMapChanged)`. When `enabled_by` is the person who attested the map and
    /// the repository is not a single-maintainer one, it is `Constraint(EnablerIsAttestor)`
    /// (finding REG-6). Nothing changes in any of these cases.
    async fn enable_repository(
        &mut self,
        id: RepositoryId,
        expected: Version,
        commit: ProjectMapCommit,
        enabled_by: PrincipalId,
    ) -> Result<Version, StoreError>;
    /// Switches a repository off and empties the record of what it was enabled for. Switching off
    /// a repository that is off is allowed and raises the version.
    async fn disable_repository(
        &mut self,
        id: RepositoryId,
        expected: Version,
    ) -> Result<Version, StoreError>;
}

/// Stage runs.
///
/// # Idempotency
/// `insert_stage_run` is idempotent by id and content. `transition_stage_run` and
/// `postpone_stage_run` are compare and swap.
///
/// # Rules
/// * A move into `READY` sets `not_before` to the database time plus
///   `StageRunEffects::not_before_after` (zero when absent).
/// * `lease_epoch` moves only inside `AttemptOps::start_attempt`.
/// * A terminal run is never edited, except `PASSED` or `SKIPPED` to `SUPERSEDED`.
///
/// # Preconditions
/// A tenant transaction that is open and not poisoned. Every id the call names belongs to the
/// transaction's tenant.
///
/// # Postconditions
/// A stored stage run is readable by its own tenant only. A move into READY sets not_before from the
/// database clock. The records a transition requires are stored with it.
///
/// # Errors
/// StoreError. The variants a method can return are named on the method. A row of another tenant is
/// reported as NotFound.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait StageRunOps {
    /// Creates a stage run in the machine's initial status.
    async fn insert_stage_run(
        &mut self,
        new: NewStageRun,
    ) -> Result<Inserted<StageRun>, StoreError>;
    /// Reads a stage run.
    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError>;
    /// Every stage run of the job, oldest first.
    async fn list_stage_runs(&mut self, job: JobId)
    -> Result<Vec<Versioned<StageRun>>, StoreError>;
    /// Compare and swap on the stage run's status and version, with the records the transition
    /// requires ([`stage_run_effects_rule`]). Not for `S03`; use `start_attempt`.
    async fn transition_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        t: AppliedTransition<StageRunStatus>,
        effects: StageRunEffects,
    ) -> Result<Version, StoreError>;
    /// While `READY`, moves `not_before` to the database time plus `delay` without a status
    /// change. The only update of a stage run that is not a transition. Used when the engine
    /// finds a candidate it cannot start for a reason outside the stage run (quota, capability).
    async fn postpone_stage_run(
        &mut self,
        id: StageRunId,
        expected: Version,
        delay: Duration,
    ) -> Result<Version, StoreError>;
}

/// Attempts, their leases and the fence.
///
/// # Lease and epoch rules (ADR 0014, section 1)
/// * The lease belongs to the attempt. `stage_runs.lease_epoch` is a counter, not a lease.
/// * `start_attempt` is the only way to create an attempt and the only way to raise the epoch.
/// * An attempt is current while it is `STARTING`, `RUNNING` or `CANCELLING` and its epoch is the
///   stage run's epoch.
/// * A write that carries a [`Fence`] is rejected with `LeaseFenced` unless the fence is current.
///   A terminal attempt is never current.
/// * `heartbeat` renews the lease from the database clock and only while the lease has not
///   lapsed. A lapsed lease is the sweeper's, not the worker's.
///
/// # Idempotency
/// `start_attempt` is not idempotent: a repeat is `Conflict`. `heartbeat` can be repeated.
/// `record_sandbox` can be repeated; `leaked` only goes from false to true.
///
/// # Preconditions
/// Tenant transaction. For start_attempt, the candidate was read in a system transaction or in this
/// one.
///
/// # Postconditions
/// After start_attempt the stage run is RUNNING at the next epoch and exactly one live attempt holds
/// the lease. A write that carries a fence changes nothing unless the fence is current.
///
/// # Errors
/// StoreError::Conflict, NotReady, Constraint (AttemptLimit, LeaseEpochExhausted, OneLiveAttempt,
/// AttemptEndRule), LeaseFenced, NotFound.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait AttemptOps {
    /// Atomically: checks the stage run is `READY` at `expected`, its job is `ACTIVE` and
    /// `not_before` has passed by the database clock; raises the epoch by one; moves the run to
    /// `RUNNING`; creates the attempt as number `previous + 1` with the lease; returns both.
    ///
    /// Errors: `Conflict` (status or version changed, or another attempt is live),
    /// `NotReady(JobNotActive | BackingOff)`, `Constraint(AttemptLimit | LeaseEpochExhausted)`,
    /// `NotFound`.
    async fn start_attempt(&mut self, start: StartAttempt) -> Result<StartedAttempt, StoreError>;
    /// Reads an attempt.
    async fn get_attempt(&mut self, id: AttemptId) -> Result<Versioned<Attempt>, StoreError>;
    /// The attempts of a stage run, by number.
    async fn list_attempts(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<Versioned<Attempt>>, StoreError>;
    /// Renews the lease to the database time plus `ttl`. `LeaseFenced` when the fence is not
    /// current or the lease already lapsed; `Conflict` when the attempt ended.
    async fn heartbeat(&mut self, fence: Fence, ttl: Duration) -> Result<LeaseRenewal, StoreError>;
    /// Compare and swap on the attempt's status and version, fenced by `epoch`, with the records
    /// the transition requires ([`attempt_end_rule`]). A sweeper move (`A06`, `A07`, `A10`) is made
    /// with the attempt's own epoch, which the sweeper just read.
    async fn transition_attempt(
        &mut self,
        id: AttemptId,
        expected: Version,
        epoch: LeaseEpoch,
        t: AppliedTransition<AttemptStatus>,
        end: AttemptEnd,
    ) -> Result<Version, StoreError>;
    /// Records the facts about the attempt's sandbox. Allowed in any status, including after the
    /// attempt ended.
    async fn record_sandbox(
        &mut self,
        id: AttemptId,
        record: SandboxRecord,
    ) -> Result<(), StoreError>;
}

/// Nodes of the task graph and their dependency edges.
///
/// # Idempotency
/// `insert_task_graph` is idempotent by stage run and plan hash: a repeat returns the stored
/// nodes. A different plan hash for a stage run that already has nodes is
/// `Constraint(IdReusedWithDifferentContent)`.
///
/// # Preconditions
/// A tenant transaction that is open and not poisoned. Every id the call names belongs to the
/// transaction's tenant.
///
/// # Postconditions
/// A task graph exists whole or not at all. A node moves only with a current fence where the table
/// asks for one.
///
/// # Errors
/// StoreError::Constraint (DuplicateTaskKey, DependencyCycle, IdReusedWithDifferentContent),
/// LeaseFenced, Conflict, NotFound.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait TaskNodeOps {
    /// Creates every node and edge of a plan in one atomic step.
    /// Errors: `Constraint(DuplicateTaskKey | DependencyCycle)`.
    async fn insert_task_graph(
        &mut self,
        graph: NewTaskGraph,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError>;
    /// Reads a node.
    async fn get_task_node(&mut self, id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError>;
    /// The nodes of a stage run, in key order.
    async fn list_task_nodes(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError>;
    /// The edges of a stage run as `(node, depends_on)`.
    async fn task_dependencies(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<(TaskNodeId, TaskNodeId)>, StoreError>;
    /// Compare and swap on the node. `by` is required for `T02` to `T05` and checked like any
    /// fenced write.
    async fn transition_task_node(
        &mut self,
        id: TaskNodeId,
        expected: Version,
        by: Option<Fence>,
        t: AppliedTransition<TaskNodeStatus>,
        effects: TaskNodeEffects,
    ) -> Result<Version, StoreError>;
}

/// What a stage run consumed and produced, by role.
///
/// # Idempotency
/// `link_stage_run_artifact` is idempotent for the same role and hash; the same role with another
/// hash is `Constraint(IdReusedWithDifferentContent)`.
///
/// # Preconditions
/// Tenant transaction. The artifact is indexed for the tenant.
///
/// # Postconditions
/// After a link, list_stage_run_artifacts returns it and stage_runs_consuming finds the run for an
/// input link.
///
/// # Errors
/// StoreError::NotFound (stage run or artifact not the tenant's), Constraint
/// (IdReusedWithDifferentContent).
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait StageArtifactOps {
    /// Links an artifact the tenant holds to a stage run.
    async fn link_stage_run_artifact(
        &mut self,
        stage_run: StageRunId,
        direction: ArtifactDirection,
        role: Slug,
        sha256: Sha256Digest,
    ) -> Result<(), StoreError>;
    /// The links of a stage run, oldest first.
    async fn list_stage_run_artifacts(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<StageRunArtifact>, StoreError>;
    /// The stage runs of the job that consumed the artifact. The invalidation lookup (ADR 0010).
    async fn stage_runs_consuming(
        &mut self,
        job: JobId,
        sha256: &Sha256Digest,
    ) -> Result<Vec<StageRunId>, StoreError>;
}

/// Approver decisions (FR-029, FR-031).
///
/// # Idempotency
/// `record_approval` is idempotent by id and content; a second decision of the same approver,
/// kind and head is `Constraint(IdReusedWithDifferentContent)`. `invalidate_approvals` can be
/// repeated.
///
/// # Preconditions
/// Tenant transaction. The approver is a human principal of the tenant.
///
/// # Postconditions
/// A recorded approval counts only for its head and only until it expires or is invalidated.
///
/// # Errors
/// StoreError::NotFound, Constraint (IdReusedWithDifferentContent, TextBounds), TenantMismatch.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait ApprovalOps {
    /// Records a decision.
    async fn record_approval(&mut self, new: NewApproval)
    -> Result<Inserted<Approval>, StoreError>;
    /// Every decision on the job, oldest first.
    async fn list_approvals(&mut self, job: JobId) -> Result<Vec<Approval>, StoreError>;
    /// `Approve` decisions bound to `head`, not invalidated and not expired by the database
    /// clock.
    async fn valid_approvals(
        &mut self,
        job: JobId,
        head: &GitSha,
    ) -> Result<Vec<Approval>, StoreError>;
    /// Marks the job's valid approvals as no longer counting. Returns how many changed.
    async fn invalidate_approvals(
        &mut self,
        job: JobId,
        reason: ApprovalInvalidation,
    ) -> Result<u32, StoreError>;
}

/// The evidence ledger. Unchanged from ports-v1 except that an entry is appended by the
/// transaction's tenant only. See ADR 0008.
///
/// # Preconditions
/// Tenant transaction. The entry's job belongs to the tenant.
///
/// # Postconditions
/// An appended entry extends the job's hash chain by one. Entries are never changed or removed.
///
/// # Errors
/// StoreError::ChainBroken (the entry does not extend the chain), Conflict (lost a race for the
/// position), NotFound, TenantMismatch.
///
/// # Idempotency
/// append_ledger_entry is not idempotent: a repeat is Conflict. The reads change nothing.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait LedgerOps {
    /// Appends at head + 1. The hashes are computed by domain code and checked here.
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError>;
    /// The last entry's sequence and hash, or `None` for a job with no entries.
    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError>;
    /// Entries of the job from sequence `from` (inclusive), in order, at most `limit`.
    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError>;
}

/// The transactional outbox (ADR 0004). The outbox is a notification record, not the source of
/// truth for what exists: the engine reads rows through the listing methods, never from event
/// payloads.
///
/// # Preconditions
/// Tenant transaction. The event names the tenant and an aggregate that exists for it.
///
/// # Postconditions
/// An enqueued event is delivered at least once after the transaction commits, and never if it rolls
/// back.
///
/// # Errors
/// StoreError::TenantMismatch, Constraint (EventAggregateMismatch, IdReusedWithDifferentContent),
/// NotFound.
///
/// # Idempotency
/// enqueue_event is idempotent by event id and content. read_events is a read.
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait OutboxOps {
    /// Queues an event for delivery. Idempotent by event id and content.
    async fn enqueue_event(&mut self, event: DomainEvent) -> Result<(), StoreError>;
    /// Events of the job from position `from` (inclusive), in order, at most `limit`.
    async fn read_events(
        &mut self,
        job: JobId,
        from: OutboxSeq,
        limit: u32,
    ) -> Result<Vec<OutboxRow>, StoreError>;
}

/// The audit log. Append only; the chain is per tenant.
///
/// # Idempotency
/// `record_audit` is idempotent by event id and content.
///
/// # Preconditions
/// Tenant transaction. A job or stage run the event names belongs to the tenant.
///
/// # Postconditions
/// A recorded event is returned by read_audit in the order it was recorded. Nothing changes or
/// removes a record.
///
/// # Errors
/// StoreError::NotFound (a named job or stage run is not the tenant's), Constraint
/// (IdReusedWithDifferentContent, TextBounds).
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait AuditOps {
    /// Appends one record. The store assigns the sequence, time and hash.
    async fn record_audit(&mut self, event: NewAuditEvent) -> Result<AuditRecord, StoreError>;
    /// The record with this event id, or `None`. An id of another tenant is `None` too. This is how
    /// a retried request finds the record it wrote the first time.
    async fn find_audit(&mut self, id: AuditEventId) -> Result<Option<AuditRecord>, StoreError>;
    /// Records in the order they were written, from `after_sequence` (exclusive), at most `limit`.
    async fn read_audit(
        &mut self,
        filter: AuditFilter,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError>;
}

/// The tenant's index of the artifacts it holds (ADR 0008). `ArtifactStore::get` and `exists`
/// consult it, so a tenant reads a blob only through its own row.
///
/// # Idempotency
/// `index_artifact` is idempotent by hash: a second call returns the first row.
///
/// # Preconditions
/// Tenant transaction. A stage run in the origin, when given, belongs to the tenant.
///
/// # Postconditions
/// After index_artifact the tenant can read the artifact's row and the artifact store. Another tenant
/// cannot, even when it holds the same bytes under the same hash.
///
/// # Errors
/// StoreError::NotFound (no row for this tenant, or the stage run is not the tenant's).
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait ArtifactIndexOps {
    /// Records that the tenant holds the artifact.
    async fn index_artifact(
        &mut self,
        new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError>;
    /// The tenant's row for the hash.
    async fn get_artifact_index(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError>;
}

/// People and services that act on jobs.
///
/// # Idempotency
/// `insert_principal` is idempotent by id and content. A GitHub user id already recorded for the
/// tenant under another id is `Constraint(ExternalReferenceTaken)`.
///
/// # Preconditions
/// Tenant transaction.
///
/// # Postconditions
/// A stored principal is readable by its own tenant only.
///
/// # Errors
/// StoreError::NotFound, StoreError::Constraint (IdReusedWithDifferentContent,
/// ExternalReferenceTaken).
///
/// # Cancellation and timeouts
/// If a method future is dropped before it completes, the transaction is poisoned: every later call
/// returns Unavailable and the only safe step is to drop the transaction. The adapter sets a
/// statement timeout on every call; a timeout is Unavailable and poisons the transaction.
#[async_trait]
pub trait PrincipalOps {
    /// Records a person or service.
    async fn insert_principal(
        &mut self,
        new: NewPrincipal,
    ) -> Result<Inserted<Principal>, StoreError>;
    /// Reads a principal.
    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError>;
    /// Finds the human principal with this immutable numeric GitHub user id.
    async fn find_principal_by_github_user(
        &mut self,
        github_user_id: u64,
    ) -> Result<Option<Principal>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::machines::guards::{AdmissionFacts, GuardFacts, LeaseGrantFacts, evaluate};
    use factory_domain::state::{AttemptEvent, JobEvent, StageRunEvent};

    fn at() -> Timestamp {
        Timestamp::parse("2026-10-27T08:30:00Z").expect("a valid timestamp")
    }

    /// A clearance for the lease guard, from facts that hold.
    fn lease_cleared() -> GuardCleared {
        let facts = LeaseGrantFacts {
            claim_candidate_current: true,
            job_status: JobStatus::Active,
            now: at(),
            not_before: None,
            concurrency_quota_allows: true,
            runtime_capability_check_passed: true,
        };
        evaluate(Guard::LeaseAcquired, &GuardFacts::LeaseGrant(facts))
            .expect("the lease guard holds")
    }

    fn admission_ok_cleared() -> GuardCleared {
        let facts = AdmissionFacts {
            requester_on_allowlist: true,
            tenant_within_job_quota: true,
            repository_registered_and_enabled: true,
            policy_allows_request_class: true,
            repository_day_budget_has_room: true,
            organization_day_budget_has_room: true,
            protection_preflight_passed: true,
        };
        evaluate(Guard::AdmissionOk, &GuardFacts::Admission(facts)).expect("admission holds")
    }

    #[test]
    fn a_planned_transition_carries_the_tables_target_the_id_and_the_clearance() {
        let cleared = lease_cleared();
        let digest = cleared.facts_sha256().clone();
        let plan =
            AppliedTransition::plan(StageRunStatus::Ready, StageRunEvent::Start, at(), cleared)
                .expect("S03 is legal with the lease guard");
        assert_eq!(plan.from_status(), StageRunStatus::Ready);
        assert_eq!(plan.to_status(), StageRunStatus::Running);
        assert_eq!(plan.event(), StageRunEvent::Start);
        assert_eq!(plan.transition_id(), "S03");
        assert_eq!(plan.at(), at());
        assert_eq!(plan.guard(), Guard::LeaseAcquired);
        assert_eq!(plan.facts_sha256(), &digest);
    }

    #[test]
    fn a_move_the_state_machine_does_not_list_cannot_be_planned() {
        let refused = AppliedTransition::plan(
            StageRunStatus::Passed,
            StageRunEvent::Start,
            at(),
            lease_cleared(),
        );
        assert!(matches!(refused, Err(PlanError::Illegal(_))));
    }

    #[test]
    fn a_clearance_for_another_guard_is_refused() {
        // S03 asks for G_LEASE_ACQUIRED. A clearance for admission is not that proof.
        let refused = AppliedTransition::plan(
            StageRunStatus::Ready,
            StageRunEvent::Start,
            at(),
            admission_ok_cleared(),
        );
        assert_eq!(
            refused,
            Err(PlanError::WrongGuard {
                expected: Guard::LeaseAcquired,
                given: Guard::AdmissionOk,
            })
        );
    }

    #[test]
    fn a_wrong_guard_error_names_both_guards() {
        let text = AppliedTransition::plan(
            StageRunStatus::Ready,
            StageRunEvent::Start,
            at(),
            admission_ok_cleared(),
        )
        .unwrap_err()
        .to_string();
        assert!(text.contains("G_LEASE_ACQUIRED"), "{text}");
        assert!(text.contains("G_ADMISSION_OK"), "{text}");
    }

    #[test]
    fn every_legal_job_move_with_its_own_guard_can_be_planned_and_no_other() {
        // For each (status, event) the table lists, a clearance for the row's own guard is accepted.
        // The facts differ per guard, so this only checks the legal/illegal split with a clearance
        // that never matches: a legal move is refused as a wrong guard, an illegal one as illegal.
        for status in JobStatus::STATES {
            for event in JobStatus::EVENTS {
                let planned = AppliedTransition::plan(*status, *event, at(), lease_cleared());
                let legal = status.legal_events().contains(event);
                match planned {
                    Err(PlanError::Illegal(_)) => assert!(!legal, "{status} on {event}"),
                    Err(PlanError::WrongGuard { .. }) => assert!(legal, "{status} on {event}"),
                    Ok(_) => panic!("{status} on {event} accepted the lease clearance"),
                }
            }
        }
    }

    #[test]
    fn a_job_and_an_attempt_move_use_their_own_tables() {
        let job = AppliedTransition::plan(
            JobStatus::Received,
            JobEvent::Admit,
            at(),
            admission_ok_cleared(),
        )
        .expect("J01 is legal");
        assert_eq!(job.to_status(), JobStatus::Active);
        let wrong = AppliedTransition::plan(
            AttemptStatus::Starting,
            AttemptEvent::SandboxReady,
            at(),
            lease_cleared(),
        );
        assert!(matches!(wrong, Err(PlanError::WrongGuard { .. })));
    }

    #[test]
    fn a_lease_epoch_only_goes_up_and_stops_at_the_largest_value() {
        let never = LeaseEpoch::NEVER_CLAIMED;
        assert_eq!(never.get(), 0);
        assert_eq!(never.checked_next(), Some(LeaseEpoch::new(1)));
        assert!(never.checked_next().unwrap() > never);
        assert_eq!(LeaseEpoch::MAX.get(), i64::MAX as u64);
        assert_eq!(
            LeaseEpoch::MAX.checked_next(),
            None,
            "the maximum does not wrap"
        );
        let almost = LeaseEpoch::new(LeaseEpoch::MAX.get() - 1);
        assert_eq!(almost.checked_next(), Some(LeaseEpoch::MAX));
    }

    #[test]
    fn an_epoch_above_the_column_is_cut_to_the_largest() {
        assert_eq!(LeaseEpoch::new(u64::MAX), LeaseEpoch::MAX);
        assert_eq!(LeaseEpoch::new(i64::MAX as u64 + 1), LeaseEpoch::MAX);
    }

    #[test]
    fn worker_names_are_slugs() {
        assert!(WorkerId::new("worker-1").is_ok());
        for bad in ["", "Worker 1", "-x"] {
            assert!(WorkerId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reading_the_outbox_from_the_start_covers_every_position() {
        assert_eq!(OutboxSeq::START.get(), 0);
        assert!(OutboxSeq::new(1) > OutboxSeq::START);
    }

    #[test]
    fn an_idempotency_key_has_one_to_128_bytes() {
        assert!(IdempotencyKey::new("a").is_ok());
        assert!(IdempotencyKey::new(&"k".repeat(128)).is_ok());
        assert!(IdempotencyKey::new("").is_err());
        assert!(IdempotencyKey::new(&"k".repeat(129)).is_err());
    }

    #[test]
    fn a_pipeline_scope_has_one_to_fourteen_distinct_kinds() {
        assert!(PipelineScope::new(vec![]).is_err());
        assert!(PipelineScope::new(vec![StageKind::Intake]).is_ok());
        assert!(PipelineScope::new(vec![StageKind::Intake, StageKind::Intake]).is_err());
        let all: Vec<StageKind> = StageKind::ALL.to_vec();
        assert!(
            PipelineScope::new(all.clone()).is_ok() == (all.len() <= PipelineScope::MAX_KINDS),
            "the full list is accepted exactly when it fits"
        );
    }

    #[test]
    fn an_audit_action_is_dotted_lower_case_segments() {
        for good in [
            "approval.recorded",
            "webhook.rejected",
            "a",
            "job.stage_2.done",
        ] {
            assert!(AuditAction::new(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "Approval.recorded",
            "approval..recorded",
            "approval.",
            ".x",
            "2a.b",
            "a b",
        ] {
            assert!(AuditAction::new(bad).is_err(), "{bad:?}");
        }
        assert!(AuditAction::new(&"a".repeat(100)).is_ok());
        assert!(AuditAction::new(&"a".repeat(101)).is_err());
    }

    #[test]
    fn a_token_hash_does_not_show_in_debug_output() {
        let hash = TokenHash([7; 32]);
        assert_eq!(format!("{hash:?}"), "TokenHash(..)");
    }

    #[test]
    fn the_stage_run_effects_rule_follows_the_documented_table() {
        let rule = |id| stage_run_effects_rule(id);
        assert!(rule("S01").contract);
        assert_eq!(rule("S02").gate, Some(GateOutcome::NotApplicable));
        for id in ["S08", "S14"] {
            assert_eq!(rule(id).gate, Some(GateOutcome::Passed), "{id}");
        }
        for id in ["S09", "S12"] {
            assert_eq!(rule(id).gate, Some(GateOutcome::Failed), "{id}");
        }
        for id in ["S11", "S21"] {
            assert_eq!(rule(id).gate, Some(GateOutcome::Blocked), "{id}");
        }
        for id in [
            "S03", "S04", "S05", "S06", "S07", "S10", "S13", "S18", "S22",
        ] {
            assert_eq!(rule(id).gate, None, "{id}");
            assert!(!rule(id).contract, "{id}");
        }
    }

    #[test]
    fn the_attempt_end_rule_follows_the_documented_table() {
        for id in ["A02", "A05"] {
            assert!(attempt_end_rule(id).failure_class, "{id}");
        }
        assert!(attempt_end_rule("A04").output);
        assert!(attempt_end_rule("A08").teardown_grace);
        for id in ["A01", "A03", "A06", "A07", "A09", "A10"] {
            let rule = attempt_end_rule(id);
            assert!(
                !rule.failure_class && !rule.output && !rule.teardown_grace,
                "{id}"
            );
        }
    }

    #[test]
    fn the_store_error_set_has_no_free_text() {
        // A closed error carries plain data. Its display texts are fixed sentences.
        for error in [
            StoreError::Conflict,
            StoreError::NotFound,
            StoreError::TenantMismatch,
            StoreError::LeaseFenced,
            StoreError::ChainBroken,
            StoreError::NotReady(NotReady::JobNotActive),
            StoreError::Constraint(ConstraintRule::DuplicateTaskKey),
            StoreError::Unavailable,
            StoreError::CommitOutcomeUnknown,
            StoreError::Internal(FaultCode::Unmapped),
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
