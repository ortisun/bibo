# Ports v1.1: signatures, rules and change tables

- Status: Accepted by the architect on 2026-10-27. Specifies the work package `s1-ports-revision`. The decisions and the reasons are in [ADR 0014](../adr/0014-ports-v1-1-claim-protocol-and-port-revision.md). Defaults that need a person are listed at the end of that record and marked here with **(pending)**.
- Form: reference. Read the ADR first for why, this file for what.
- Source of the code below: the Rust blocks were compiled in a scratch crate against `factory-domain` and `factory-ports` at commit `4e5a5b6` (`cargo check --offline`, Rust 1.98). They compile; none was run. Bodies of pure functions are `todo!()` and belong to the TDD work of the package. The new domain items (identifiers, `PlatformScope`, `ResolvedPrincipal`, `GuardCleared`, `AutonomyLevel`) are imported from `crate::dom` in the scratch crate only because that crate cannot edit `factory-domain`; in the real code they live in `factory-domain` at the paths in section 4 and the `use` lines change accordingly. Items the blocks do not repeat are unchanged from `ports-v1`. A `use factory_ports::...` line in a block names an item of ports-v1 that sits in the same module (or another module of the same crate) in the real code, so it becomes `use super::...` or `use crate::...` there.
- What this does not change: the domain state machine other than `S21` and `S22`, the ledger and chain rules, the telemetry, and every port not named here (`Clock`, `IdGenerator`, `CancelSignal`, `AgentRegistry`, `ModelRouter`'s purity).

## 1. Finding to decision to place

"Accepted" means the finding is right and the fix is as proposed. "Changed" means the finding is right and the fix differs; the reason is in the ADR section named. Package ids: **rev** is `s1-ports-revision`, **db** is `s1-database-port-alignment`, **stor** `s1-storage-postgres`, **sbx** `s1-sandbox-adapter`, **ws** `s1-workspace-ingestion`, **gh** `s1-github-adapter`, **rt** `s1-agent-runtime-adapters`, **egr** `s1-egress-and-broker`, **xt** `s1-xtask-extensions`, **spec** `s1-spec-adapter-and-stage`, **rev-stage** `s1-stage-implementation-and-review`.

| Id | Verified by me | Decision | Where it lands |
|---|---|---|---|
| F-01 | Read both sides. Also found: the claim cannot work as the port says even in principle, because the system role cannot write | **Changed.** Two-step claim; lease on the attempt; records on transitions (ADR 0014 d1, d2) | Section 5.2 (`NewJob`, `NewStageRun`, `GateRecord`, `AttemptEnd`, `StartAttempt`); rev, stor, db |
| F-02 | `grep` of `crates/ports` and the tables | **Accepted.** `RequestOps`, `DeliveryOps`, `RepositoryOps`, `ApprovalOps`, `StageArtifactOps`, lookups, listings, due-work queries, audit shape (d2) | Section 5.2; rev, stor |
| F-03 | Read `workspace.rs`, `spec.rs`, the fake | **Changed.** `JobRepo::read_file_at` after `commit`, `export_patch`; the Spec Kit port splits into `run` and a pure `assemble`. `read_changed_file` rejected (d4) | Sections 5.4, 5.8; rev, ws, spec |
| F-04 | Read the port's push precondition and the fake's per-instance `made` set (`testkit/src/workspace.rs:269`) | **Changed.** The job owns the object store; the attempt owns the worktree; `fetch` returns the tip; `push` is on `JobRepo`. `WorkspaceId` and `open` rejected as unneeded (d4) | Section 5.4; rev, ws, gh (`fetch_target`) |
| F-05 | Read `registry.rs`, `agent.rs`, `validator.rs` | **Accepted.** `RawOutput`, `validate_bytes`, `ValidatedOutput` (d6) | Sections 5.6, 5.7; rev, contracts |
| F-06 | Read `Tx` docs | **Accepted, extended.** `CommitOutcomeUnknown`, `Store::committed(witness)`, idempotent inserts, the poison rule (d2) | Section 5.2; rev, stor |
| F-07 | Read the trait and the check | **Accepted.** `exclude` and `probed` in `RoutingNeed`; `AllExcluded` (d6) | Section 5.6; rev, contracts (`PolicyModelRouter`), engine |
| F-08 | Read | **Accepted.** `AgentRunReport` always carries usage, transcript, denials (d6) | Section 5.6; rev, rt |
| F-09 | Read `validate` and `check_limits`; the reproduction values are the review's | **Accepted, changed.** Typed mounts (allow list by construction), non-zero limits, full `PostureReport` compared by a pure function in ports (d5) | Section 5.5; rev, sbx |
| F-10 | Read `paths.rs` and the policy | **Accepted.** `PathRules`, `PathMode`, folded matching, `.git` aliases, `WorkspacePurpose::Verify` (d4) | Sections 5.3, 5.4; rev, ws |
| F-11 | Read `plan` and `evaluate` | **Accepted.** `GuardCleared`; `plan` takes it; the clearance is written into the event payload (d3) | Sections 4, 5.2; rev (domain and engine) |
| F-12 | Read `scan.rs` (the test-file skip), the `clippy.toml` of `ports` and `workflow` (the same ban list, with none of the entries the review lists) and the domain manifest comment about `now_utc`. The alias, feature-unification and `allow` mutations are the review's and I did not rerun them | **Accepted, extended** (d11) | Section 12; xt, rev (`ProcessRunner`, ST-03 wording) |
| F-13 | Read the ports; read the GitHub documentation (ADR 0014 "What was checked") | **Changed.** Check runs, rulesets with an admin attestation, `fetch_comment`, `WebhookVerifier`, no ready-for-review (d7). Two items **(pending)** | Sections 5.9, 11; rev, gh; security text edits in section 11 |
| F-14 | Read `JobTokenFile` and the `workflow` clippy ban on `std::fs::write` and `File` | **Accepted.** `JobTokenMount { secret }`; the sandbox adapter writes and removes the file (d5) | Section 5.5; rev, sbx |
| F-15 | Read `artifact.rs` | **Accepted.** `get` and `exists` take a `TenantScope` (d9) | Section 5.1; rev, stor |
| F-16 | Read the fake's `claim_ready` (it never reads the job), the first half of `insert_attempt`, the fake `open_draft_pull_request` (no pushed-head check) and the store defect table. The mutation survivors and the 65 of 132 count are the review's | **Accepted, extended** with the `contract_register` rule and new suites (d10) | Section 9; rev |
| F-17 | Read the schema, examples and the domain mirror | **Accepted.** Schema rule applied; domain rule and the diff check follow (d8) | Section 10; rev (domain), rev-stage (gate) |
| F-18 | Counted the pipeline rows: 13 in Slice 1 plus `MERGE` | **Accepted.** Exact edits for the specification in section 13; the end-to-end assertion reads the list from `state-machine.json` | Section 13; human; qa |
| F-19 | Read each statement | **Accepted.** Corrected in this change: lock mode in the new store docs, `state-machine.md` status line, ADR 0011 and 0002 statements, `crate-dependency-rules.json` | ADR 0002, 0011 revision notes; this change |
| F-20 | Read the schema and `retry.rs` | **Accepted.** Schema rule applied (d8). Tightening in place is **(pending)** | Section 10; rev (domain) |
| F-21 | Read `Confinement` and `Namespace` | **Accepted.** `Confinement::NotAvailable` (policy flag), `Namespace::None` (d5) | Section 5.5; rev, sbx |
| F-22 | Read the schemas | **Changed.** `source.url` gets a `pattern`. No `\d` appears in any schema, so there is nothing to change there; `\S` and `\s` stay, because the trim rule wants Unicode space | Section 10; schema applied |
| F-23 | Read the test; did not rerun | **Accepted.** `env_remove("CARGO_TARGET_DIR")` and a scratch target per crate | Section 12; xt |
| F-24 | Grepped for the ids | **Accepted.** An `invariant_register` check reads the table from `state-machine.json`; INV-01, INV-09, INV-11 tests are named | Section 12; xt, rev (engine tests), db |
| F-25 | Read the constructors | **Changed.** Scans name the crates allowed to call each constructor (ST-13); error enums carry closed rule codes (done in section 5) | Sections 5, 12; rev, xt |
| F-26 | Judgment confirmed by reading the schema | **Accepted, schema not applied.** Outline in section 10.3; needs a new `ContractKind` | Section 10.3; rev |
| F-27 | Not rerun | **Accepted.** No action. One cosmetic fix: the policy header says "block style" and the files use flow style; the security specialist corrects the header | human (security) |
| F-28 | Not rerun | **Accepted.** No action beyond F-22 | none |
| F-29 | Not rerun; the conformance tests passed in the review | **Accepted.** No action. The weaknesses it names are F-11, F-12, F-24 | none |
| F-30 | Read | **Accepted.** `LeaseEpoch::checked_next`, maximum `i64::MAX`, the claim fails at the maximum (d1) | Section 5.2; rev |
| F-31 | Not rerun | **Accepted.** No action. The untried case, a path or git dependency under an allowed crate name, becomes a fixture (section 12) | xt |

Findings the review did not list:

| Id | What | Decision |
|---|---|---|
| E-1 | `IssueSource::label_actor` and `Issue::author` return a login. The policy authorizes by the numeric GitHub user id, so nobody could be authorized | `GithubActor { id, login }` everywhere (section 5.9) |
| E-2 | `SpecError::ForbiddenOperation` can never be produced (the review's answer to question 1) | Removed (section 5.8) |
| E-3 | The slice plan sketches (`claim_ready`, `AgentRuntime::run(req, cancel)` with no session, `resolve_installation(installation)`, `set_status`) are stale | Replaced in `slice-plan.md` section 7 in this change |
| E-4 | The system transaction can find work and cannot write, but the type let it call `insert_job` and return `ScopeNotAllowed` | `SystemTx` is a separate read-only type (section 5.2) |

Observations from implementers that I checked against the code and found already fixed: `SandboxError::Cancelled` exists (`sandbox.rs:739`); `AgentRuntime::run` takes `session` (`agent.rs:430`). The spawner abstraction, the `ModelBroker` metering seam, timestamp arithmetic and the platform scope are new and are specified below.

## 2. Rules that hold for every method

These apply to every port in this file. Each trait's documentation repeats the part that applies to it, and a test in `crates/ports/tests/trait_docs.rs` fails if a trait lacks the headings Preconditions, Postconditions, Errors, Idempotency, and, new in v1.1, **Cancellation and timeouts**.

1. **Closed errors.** One error enum per port. A variant carries plain data, a closed rule code or a name of a step. It never carries a library error, text from a row, text from git or Docker, or a secret. An adapter maps every failure onto the enum, and a failure it cannot map becomes the port's `Internal` or `Unavailable` variant, not a new variant.
2. **Idempotency is stated per method.** A write is one of: idempotent by id and content; a compare and swap (applied twice, one succeeds and the other conflicts); or not idempotent, with the reason.
3. **Cancellation.** A method that can take longer than a second takes `&dyn CancelSignal` (`fetch`, `create`, `ingest`, `export_patch`, `push`, `create_verified`, `run`, `exec`, `ProcessRunner::run`). The signal only asks; the method stops within one second and leaves nothing partial that the next call cannot reuse or remove. A method without a signal is cancel-safe by dropping its future, except for the store, where dropping poisons the transaction (rule 5).
4. **Timeouts.** Every adapter sets a timeout on every external call (statement and lock timeouts for the store, 30 seconds for the code host, a fixed deadline for each git and Docker call) and reports it as the port's `Timeout` or `Unavailable`. A timeout never reports success.
5. **Unknown outcome.** Only `Tx::commit` can have an outcome the caller cannot see (`CommitOutcomeUnknown`). A dropped store method poisons its transaction. Everything else that talks to a remote system (a push, a comment, a check run) can have been applied when the call reports a failure; each of those is idempotent or at least once, so repeating it is safe.
6. **Fidelity.** Every port with a stand-in has `fidelity()`, and the composition root calls `require_permitted` for each one it wires. A new test in `apps/*` composition checks that the root does so for every port in the registry (the review noted that nothing forces it).
7. **No secrets in `Debug`.** `FetchCredential`, `PushCredential`, `JobTokenSecret`, `RawOutput` and `EnvValue::Secret` show a placeholder. A test per type checks it.

## 3. Method rules at a glance

Idempotency (I), cancellation (C) and timeout (T). "Dp" means dropping the future is safe. "Poison" means dropping poisons the transaction. "CAS" means compare and swap. "Id+c" means idempotent by id and content.

| Port and method | I | C | T |
|---|---|---|---|
| `Store::begin`, `begin_system` | read | Dp | `Unavailable` |
| `Store::resolve_token`, `resolve_installation`, `committed`, `schema_version` | read | Dp | `Unavailable` |
| `Store::record_platform_audit` | Id+c by event id | Dp, may have applied | `Unavailable` |
| `SystemTx::find_claim_candidates`, `find_due_attempts`, `database_time` | read | Dp | `Unavailable` |
| `Tx::commit` | once | n/a | `Unavailable` (not sent) or `CommitOutcomeUnknown` (sent) |
| `Tx::rollback`, `database_time` | read/once | Dp | `Unavailable` |
| `JobOps::insert_job` and the other `insert_*`, `record_*` | Id+c | Poison | `Unavailable`, poison |
| `transition_*`, `update_job_facts`, `postpone_stage_run` | CAS | Poison | `Unavailable`, poison |
| `AttemptOps::start_attempt` | no: a repeat is `Conflict` | Poison | `Unavailable`, poison |
| `AttemptOps::heartbeat` | repeatable | Poison | `Unavailable`, poison |
| `AttemptOps::record_sandbox` | repeatable; `leaked` only rises | Poison | `Unavailable`, poison |
| `ApprovalOps::invalidate_approvals` | repeatable | Poison | `Unavailable`, poison |
| `LedgerOps::append_ledger_entry` | no: a repeat is `Conflict` | Poison | `Unavailable`, poison |
| `OutboxOps::enqueue_event` | Id+c by event id | Poison | `Unavailable`, poison |
| all `get_*`, `list_*`, `read_*`, `find_*` | read | Poison (a read in a transaction) | `Unavailable`, poison |
| `ArtifactStore::put` | idempotent by bytes | Dp, may have stored | `Io(Write)` |
| `ArtifactStore::get`, `exists` | read | Dp | `Io(Read)` |
| `WorkspaceProvider::fetch` | idempotent | signal; drop = cancel | `Timeout` |
| `WorkspaceProvider::create` | no | signal | `Timeout` |
| `WorkspaceProvider::repo`, `dispose_job`, `sweep_orphans` | read / idempotent | Dp | `Timeout` |
| `JobRepo::read_file_at`, `list_at` | read | Dp | `Timeout` |
| `JobRepo::export_patch` | idempotent | signal | `Timeout` |
| `JobRepo::push` | idempotent per commit | signal; may have applied | `Timeout` |
| `Workspace::ingest` | read | signal | `Timeout` |
| `Workspace::commit` | idempotent per `IngestedChange` | Dp (a ref update) | `Timeout` |
| `Workspace::dispose` | idempotent | Dp | `Timeout` |
| `SandboxProvider::create_verified` | no | signal; removes what it made | `ProvisionFailed` |
| `SandboxProvider::sweep_orphans` | idempotent | Dp | `DaemonUnavailable` |
| `SandboxSession::exec` | no | signal | `Timeout` (command) |
| `SandboxSession::stop_and_remove` | once | n/a | `TeardownFailed` |
| `AgentRuntime::probe` | read | Dp | `ProbeFailed(Trial)` |
| `AgentRuntime::run` | no; may cost money | signal; drop kills the tool and loses the report | `Timeout` in the report |
| `ModelRouter::route` | pure | n/a | n/a |
| `ModelBroker::issue` | no | Dp, may have issued | `Unavailable` |
| `ModelBroker::revoke`, `revoke_for_job` | idempotent | Dp | `Unavailable` |
| `ModelBroker::usage` | read | Dp | `Unavailable` |
| `MeteringOps::record_usage` | no: each call adds | Dp | `Unavailable` |
| `OutputValidator::validate_bytes`, `validate_value` | pure | n/a | n/a |
| `SpecificationProvider::run` | no | signal in the context | `Runtime(Timeout)` |
| `SpecificationProvider::assemble` | pure | n/a | n/a |
| `IssueSource::*` | read | Dp | `Unavailable` (30 s) |
| `ChangeHost::fetch_target`, `push_target`, `resolve_branch`, `pull_request_state` | read | Dp | `Unavailable` (30 s) |
| `ChangeHost::open_draft_pull_request` | idempotent per open head | Dp, may have applied | `Unavailable` |
| `ChangeHost::update_pull_request_body` | CAS by tag | Dp | `Unavailable` |
| `ChangeHost::post_comment` | at least once by key | Dp, may have applied | `Unavailable` |
| `ChangeHost::publish_check` | idempotent by `(commit, name, external_id)` | Dp, may have applied | `Unavailable` |
| `ChangeHost::revoke_job_tokens` | idempotent | Dp | `Unavailable` |
| `WebhookVerifier::verify` | pure | n/a | n/a |
| `ProcessRunner::run` | no | signal; drop kills the group | `Timeout` |

## 4. Domain additions

These are changes in `crates/domain`, owned for this purpose by the revision package (it depends on `s1-domain-revision`).

```rust
// crates/domain/src/ids.rs: three identifiers, with the existing `uuid_id!` macro.
uuid_id! { /// A repository registered for a tenant.            pub struct RepositoryId("repository id") }
uuid_id! { /// One approver decision.                            pub struct ApprovalId("approval id") }
uuid_id! { /// One recorded webhook delivery (the row, not GitHub's header). pub struct WebhookDeliveryId("webhook delivery id") }
uuid_id! { /// One audit record.                                 pub struct AuditEventId("audit event id") }

// crates/domain/src/vocabulary/mod.rs: with the existing `string_enum!` macro. Values `L0` to `L3`.
string_enum! { /// How much the factory may do on its own in a repository.
    pub enum AutonomyLevel("autonomy level") { L0 = "L0", L1 = "L1", L2 = "L2", L3 = "L3" } }

// crates/domain/src/values/timestamp.rs: arithmetic. No clock is read. All return `None` on overflow.
impl Timestamp {
    pub fn checked_add(&self, d: std::time::Duration) -> Option<Timestamp>;
    pub fn checked_sub(&self, d: std::time::Duration) -> Option<Timestamp>;
    /// The gap from `earlier` to `self`, or `None` when `earlier` is later.
    pub fn duration_since(&self, earlier: &Timestamp) -> Option<std::time::Duration>;
}

// crates/domain/src/scope.rs
/// The scope of the webhook receiver for an event that belongs to no tenant. Used only with
/// `Store::record_platform_audit`. Callers: the `api` binary's webhook handler (ST-13).
pub struct PlatformScope(());
impl PlatformScope { pub const fn receiver() -> Self; }
/// What `Store::resolve_token` returns. `TenantScope::new` stays public; ST-13 names its callers.
pub struct ResolvedPrincipal { pub tenant: TenantId, pub principal: PrincipalId }
/// What `Store::resolve_installation` returns.
pub struct ResolvedRepository { pub tenant: TenantId, pub repository: RepositoryId }

// crates/domain/src/machines/guards.rs
/// Proof that `guard` held on facts whose digest is `facts_sha256`. The only constructor is in
/// this module and is called by `evaluate`.
pub struct GuardCleared { /* private */ }
impl GuardCleared { pub fn guard(&self) -> Guard; pub fn facts_sha256(&self) -> &Sha256Digest; }
/// Was `Result<(), GuardError>`. A caller that ignored the value still compiles with a warning
/// (`#[must_use]`); one that wants to plan a transition needs it.
pub fn evaluate(guard: Guard, facts: &GuardFacts<'_>) -> Result<GuardCleared, GuardError>;
```

The facts digest: SHA-256 of the facts rendered as `name=value\n` lines in field order, booleans as `true` or `false`, timestamps with `Timestamp::as_text`, digests as their text, absent options as `-`. One macro implements it for each facts struct, so a new field cannot be left out of the digest.

## 5. The ports

### 5.1 Artifacts

```rust
// crates/ports/src/artifact.rs (ports-v1.1): `get` and `exists` take the tenant's scope.
// `ArtifactBackend` is unchanged.

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactBackend;

/// What the adapter was doing when the backend failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendStep {
    /// Writing a blob.
    Write,
    /// Reading a blob.
    Read,
    /// Reading the tenant's index row.
    Index,
}

/// Why an artifact call failed. The set is closed. `Io` names the step instead of carrying text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    /// No blob has this hash, or the tenant has no index row for it. The two look the same.
    #[error("no artifact has this content hash")]
    NotFound,
    /// The stored bytes no longer hash to the address they are stored under.
    #[error("the stored bytes do not match their content hash")]
    HashMismatch {
        /// The hash the blob is stored under.
        expected: Sha256Digest,
        /// The hash the stored bytes actually have.
        actual: Sha256Digest,
    },
    /// The bytes are larger than the store accepts.
    #[error("the artifact is larger than the limit of {limit} bytes")]
    TooLarge {
        /// The largest size the store accepts, in bytes.
        limit: u64,
    },
    /// The backend failed.
    #[error("the artifact backend failed at {0:?}")]
    Io(BackendStep),
}

/// Content-addressed storage for immutable blobs.
///
/// # Preconditions
/// For `put`, the bytes are no larger than the store's limit. Secrets have already been redacted
/// from logs and transcripts; this port stores exactly what it is given.
///
/// # Postconditions
/// After `put` returns a reference, the blob is stored once, whoever else holds the same bytes.
/// `get` and `exists` answer only for a tenant whose index row (`ArtifactIndexOps`) names the
/// hash: for any other tenant `get` is `NotFound` and `exists` is `false`, so a hash held by
/// another tenant cannot be read and its existence cannot be tested. `get` never returns bytes
/// whose hash differs from the address. The implementation of this port lives with the database
/// adapter and reads the index through the same store.
///
/// # Errors
/// [`ArtifactError`].
///
/// # Idempotency
/// `put` is idempotent: the same bytes always give the same hash, a second `put` stores nothing
/// new, and an earlier blob is never replaced. `get` and `exists` are reads.
///
/// # Cancellation and timeouts
/// Every call is safe to drop. A `put` that was dropped may have stored the blob; the next `put`
/// of the same bytes is a no-op.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Where the bytes live.
    fn backend(&self) -> ArtifactBackend;

    /// Says whether this store is the real backend (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Stores the bytes and returns their reference. Never overwrites. Makes no index row: the
    /// caller indexes the artifact for its tenant in the transaction that uses it.
    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError>;

    /// Returns the bytes if the tenant's index row names the hash. Re-hashes them on the way out.
    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError>;

    /// True when the tenant's index row names the hash and the blob is stored.
    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError>;
}
```

### 5.2 Store

The trait `Store` has two new lookups, two new methods that run without a transaction, and a system transaction that cannot write. The sub-traits of `Tx` are listed in the order of the tables they serve. `OutboxRow`, `Versioned`, `Version`, `Sequence`, `OutboxSeq`, `SchemaVersion` and `WorkerId` are unchanged.

The claim, in one place (R1 to R3 of ADR 0014): the engine opens a system transaction and calls `find_claim_candidates`; it calls `finish`; for each candidate it opens a tenant transaction, reads the job and the stage run, evaluates `G_LEASE_ACQUIRED`, plans `S03` with the clearance, calls `start_attempt`, enqueues `stage_run.started`, and commits. A `Conflict` from `start_attempt` means another worker won. A `NotReady` means the candidate went stale. No other call creates an attempt.

```rust
// crates/ports/src/store.rs (ports-v1.1). Unchanged and not repeated: `Version`, `Sequence`,
// `OutboxSeq`, `SchemaVersion`, `WorkerId`, `Versioned<T>`, `OutboxRow`.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, DomainEvent, EvidenceLedgerEntry};
use factory_domain::ids::{
    AttemptId, CorrelationId, EventId, JobId, PrincipalId, StageRunId, TaskNodeId, TenantId,
};
use factory_domain::ledger::ChainHead;
use factory_domain::machines::failure::FailureClass;
use factory_domain::scope::TenantScope;
use factory_domain::state::{
    AttemptStatus, Guard, IllegalTransition, JobStatus, StageRunStatus, Status, TaskNodeStatus,
};
use factory_domain::values::{GitSha, NonEmptyString, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{
    Fidelity, ExecutionMode, GateOutcome, StageKind,
};

use crate::dom::{
    ApprovalId, AuditEventId, AutonomyLevel, GuardCleared, PlatformScope, RepositoryId,
    ResolvedPrincipal, ResolvedRepository, WebhookDeliveryId,
};
use factory_ports::sandbox::SandboxId;
use factory_ports::store::{
    OutboxRow, OutboxSeq, SchemaVersion, Sequence, Version, Versioned, WorkerId,
};

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
        if epoch > Self::MAX.0 { Self::MAX } else { Self(epoch) }
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
        if self.0 >= Self::MAX.0 { None } else { Some(Self(self.0 + 1)) }
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
        Ok(Self { from, event, to: row.to, transition_id: row.id, at, cleared })
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
    EffectsRule { gate, contract: transition_id == "S01" }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifactIndexEntry {
    /// The artifact, by content hash.
    pub artifact: ArtifactRef,
    /// The job that made it, when one did.
    pub origin: Option<(JobId, StageRunId)>,
}

/// The tenant's record that it holds an artifact. A tenant reads a blob only through this row
/// (ADR 0008, and `ArtifactStore::get` in ports-v1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIndexEntry {
    /// The tenant that holds the artifact.
    pub tenant_id: TenantId,
    /// The artifact, by content hash.
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
#[async_trait]
pub trait SystemTx: Send {
    /// The database's current time.
    async fn database_time(&mut self) -> Result<Timestamp, StoreError>;

    /// `READY` stage runs of `ACTIVE` jobs whose `not_before` is not after the database time,
    /// ordered by `not_before` then id, at most `limit`. The real store takes
    /// `FOR NO KEY UPDATE SKIP LOCKED` on them so two concurrent finders mostly see different
    /// rows. A lease is not consulted: a stage run has none.
    async fn find_claim_candidates(&mut self, limit: u32)
    -> Result<Vec<ClaimCandidate>, StoreError>;

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
#[async_trait]
pub trait DeliveryOps {
    /// Records a verified delivery, or says which earlier one it repeats.
    async fn record_delivery(
        &mut self,
        new: NewWebhookDelivery,
    ) -> Result<DeliveryOutcome, StoreError>;
}

/// Registered repositories.
#[async_trait]
pub trait RepositoryOps {
    /// Reads a repository of the tenant.
    async fn get_repository(&mut self, id: RepositoryId) -> Result<Versioned<Repository>, StoreError>;
    /// Records the result of the protection preflight. `autonomy_ceiling` never rises above the
    /// ceiling an org admin set; the adapter keeps the lower of the two.
    async fn record_protection_preflight(
        &mut self,
        id: RepositoryId,
        expected: Version,
        passed: bool,
    ) -> Result<Version, StoreError>;
    // Added on 2026-11-02 (ADR 0016, item 1), after this document was written. `Repository` also
    // gained `project_map: Option<ProjectMapAttestation>`. The code in `crates/ports/src/store.rs`
    // is the source for the details.
    /// Registers a repository: disabled, level L0, no protection result, no project map.
    /// Idempotent by id and content. A GitHub repository that is taken is `NotFound`.
    async fn register_repository(
        &mut self,
        new: NewRepository,
    ) -> Result<Inserted<Repository>, StoreError>;
    /// Records that a person attested the commit that holds the project map. The attestor is an
    /// active human principal of the tenant. The engine does not look at the repository.
    async fn attest_project_map(
        &mut self,
        id: RepositoryId,
        expected: Version,
        commit: ProjectMapCommit,
        attested_by: PrincipalId,
    ) -> Result<Version, StoreError>;
    // Changed on 2026-11-02 (review finding REG-1): `set_repository_enabled(id, expected, enabled)`
    // became the two methods below, and `Repository` gained `enabled_for: Option<EnabledFor>`.
    // Enabling names the map commit the approver read and the person who enables. Attesting another
    // commit, or the same commit by another person, switches an enabled repository off.
    /// Enables a repository for the map commit `commit`. Without a map commit the call is
    /// `Constraint(ProjectMapRule)`, as it is for an enabler who is not an active human of the
    /// tenant. A commit that is not the one attested now is `Constraint(ProjectMapChanged)`.
    async fn enable_repository(
        &mut self,
        id: RepositoryId,
        expected: Version,
        commit: ProjectMapCommit,
        enabled_by: PrincipalId,
    ) -> Result<Version, StoreError>;
    /// Disables a repository and empties the record of what it was enabled for.
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
#[async_trait]
pub trait StageRunOps {
    /// Creates a stage run in the machine's initial status.
    async fn insert_stage_run(&mut self, new: NewStageRun)
    -> Result<Inserted<StageRun>, StoreError>;
    /// Reads a stage run.
    async fn get_stage_run(&mut self, id: StageRunId) -> Result<Versioned<StageRun>, StoreError>;
    /// Every stage run of the job, oldest first.
    async fn list_stage_runs(&mut self, job: JobId) -> Result<Vec<Versioned<StageRun>>, StoreError>;
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
#[async_trait]
pub trait ApprovalOps {
    /// Records a decision.
    async fn record_approval(&mut self, new: NewApproval) -> Result<Inserted<Approval>, StoreError>;
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
#[async_trait]
pub trait AuditOps {
    /// Appends one record. The store assigns the sequence, time and hash.
    async fn record_audit(&mut self, event: NewAuditEvent) -> Result<AuditRecord, StoreError>;
    /// The record with this event id, or `None`. Added on 2026-11-02 (ADR 0016, item 1): a retried
    /// request finds the record it wrote the first time.
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
#[async_trait]
pub trait PrincipalOps {
    /// Records a person or service.
    async fn insert_principal(&mut self, new: NewPrincipal) -> Result<Inserted<Principal>, StoreError>;
    /// Reads a principal.
    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError>;
    /// Finds the human principal with this immutable numeric GitHub user id.
    async fn find_principal_by_github_user(
        &mut self,
        github_user_id: u64,
    ) -> Result<Option<Principal>, StoreError>;
}
```

Which effects each transition carries, as a table (the code is `stage_run_effects_rule` and `attempt_end_rule`):

| Transition | `StageRunEffects` | `AttemptEnd` |
|---|---|---|
| `S01` | `contract_sha256` required | n/a |
| `S02` | `gate` = `NOT_APPLICABLE`, no report | n/a |
| `S03` | not allowed; use `start_attempt` | n/a |
| `S04` | none | n/a |
| `S05`, `S13`, `S17` | `not_before_after` optional (the back-off for `S05`) | n/a |
| `S08`, `S14` | `gate` = `PASSED` with the report | n/a |
| `S09`, `S12` | `gate` = `FAILED` with the report and `failing_set_sha256` | n/a |
| `S11`, `S21` | `gate` = `BLOCKED` with the report | n/a |
| `S06`, `S07`, `S10`, `S15`, `S16`, `S18`, `S19`, `S20`, `S22` | none | n/a |
| `A02`, `A05` | n/a | `failure_class` required |
| `A04` | n/a | `output` required |
| `A08` | n/a | `teardown_grace` required |
| `A01`, `A03`, `A06`, `A07`, `A09`, `A10` | n/a | none (`A01`, `A09`, `A10` may carry `sandbox`) |

"With the report" is a rule of the port and not a hint: every store refuses a gate record that has an outcome other than `NOT_APPLICABLE` and no report, and refuses a report that is not an artifact the tenant holds (the Store contract suite checks both). A decision that no gate reported (a person's approval, an environment block, a gate that could not run) is still recorded on a document: the engine stores a small decision record and passes its hash (ADR 0014, amendment 1).

### 5.3 Paths

`RepoPath::new` also refuses the aliases of `.git` listed in `is_git_directory_alias`. `RepoGlob` keeps `matches` (exact) and gains `matches_folded`. Nothing outside `PathRules::classify` decides what a path is.

```rust
// crates/ports/src/paths.rs (ports-v1.1): additions. `RepoPath`, `RepoGlob`, `BranchName`,
// `RepoRef`, `CommitSha`, `Finding` and `NameError` stay. `RepoPath::new` changes (see below).

use factory_ports::paths::{NameError, RepoGlob, RepoPath};

/// What the policy does with a path (`policies/security.yaml`, section `protected_paths`). When
/// several rules match one path, the most restrictive wins, in this order: `Hidden`,
/// `DenyWrite`, `AppendOnly`, `AdditionsOnly`, `Sensitive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathMode {
    /// Not in the checkout at all, and not readable.
    Hidden,
    /// Any add, modify, delete, rename or mode change is refused.
    DenyWrite,
    /// New files are allowed; modifying, deleting or renaming an existing file is refused.
    AppendOnly,
    /// New files are allowed; an existing file may only gain lines. Deleting or renaming it is
    /// refused.
    AdditionsOnly,
    /// The change is allowed and is reported for the semantic checks and extra review.
    Sensitive,
}

/// One rule of a [`PathRules`] list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRule {
    /// Paths that match the glob get the mode.
    Mode {
        /// The pattern.
        glob: RepoGlob,
        /// What the policy does with a matching path.
        mode: PathMode,
    },
    /// A policy entry written with a leading `!`: a path that matches the glob is taken out of
    /// the matching rules *of the same group* that come before it.
    Reinclude {
        /// The pattern, without the `!`.
        glob: RepoGlob,
        /// The group the re-inclusion belongs to (the policy group id), so that it cannot lift
        /// a protection from another group.
        group: String,
    },
}

/// The ordered path rules for a job, built from the central policy and the project's
/// tighten-only overrides. This is the **only** place that decides what a path is: every adapter
/// and every fake calls [`PathRules::classify`], and none matches globs by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRules {
    rules: Vec<(String, PathRule)>,
}

impl PathRules {
    /// Builds the rules from `(group id, rule)` pairs in policy order.
    #[must_use]
    pub fn new(rules: Vec<(String, PathRule)>) -> Self {
        Self { rules }
    }

    /// The mode that applies to `path`, or `None` for a free path. The path is folded the way
    /// the policy says (Unicode NFC, then case-insensitive) before any glob is tried, and a
    /// `Reinclude` is applied after the `Mode` rules of its own group.
    #[must_use]
    pub fn classify(&self, path: &RepoPath) -> Option<PathMode> {
        let _ = path;
        todo!("ports-v1.1: implemented by the port revision package, test first")
    }

    /// The rules, for adapters that must show them in a report.
    #[must_use]
    pub fn rules(&self) -> &[(String, PathRule)] {
        &self.rules
    }
}

impl RepoGlob {
    /// True when the whole of `path` matches, after both are folded the way the policy says:
    /// Unicode NFC, then simple case folding. `matches` (exact, case-sensitive) stays for tests.
    #[must_use]
    pub fn matches_folded(&self, path: &RepoPath) -> bool {
        let _ = path;
        todo!("ports-v1.1")
    }
}

/// The check `RepoPath::new` makes for the `.git` component, replacing the ASCII-only
/// comparison. A component is refused when, after removing the characters git's own HFS and NTFS
/// protections ignore (U+200C to U+200F, U+202A to U+202E, U+206A to U+206F, U+FEFF), trimming
/// trailing dots and spaces, applying NFC and folding case, it equals `.git`, or it equals the
/// short name `git~1` followed by nothing or by a digit.
#[must_use]
pub fn is_git_directory_alias(component: &str) -> bool {
    let _ = component;
    todo!("ports-v1.1")
}
```

### 5.4 Workspace and job repository

The sequence of a job, to show how the pieces fit:

1. `ChangeHost::fetch_target` gives a read credential. `WorkspaceProvider::fetch` puts the default branch tip into the job's store and returns it as `FetchedBase`.
2. For each stage that needs files: `create` a workspace of the latest job commit, build the sandbox from `mounts()`, run, stop the sandbox, `ingest`, `commit`. The commit lands in the job's store.
3. Any stage reads committed files with `repo(job).read_file_at(commit, path, ...)`, the reviewer gets `export_patch(base, head)`, and the verify stage creates a `Verify` workspace of the candidate commit.
4. Delivery calls `repo(job).push(target, commit)`. It works after any number of restarts because the commit is in the store.

```rust
// crates/ports/src/workspace.rs (ports-v1.1). Replaces the file. `CommitRequest`, `ChangeKind`,
// `ChangedPath` and `PushCredential` are unchanged and not repeated.

use std::path::PathBuf;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{BranchName, CommitSha, Finding, RepoGlob, RepoPath, RepoRef};
use factory_ports::workspace::{ChangedPath, CommitRequest, PushCredential, PushTarget};

use crate::paths::{PathMode, PathRules};

/// An opaque credential for one fetch. Short-lived, read-only and narrowed to one repository. Its
/// text never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchCredential(String);

impl FetchCredential {
    /// Wraps a credential issued by the code host adapter.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }
    /// The credential text. Pass it to git through the environment, never on a command line.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for FetchCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FetchCredential(<redacted>)")
    }
}

/// Where to fetch from and with what credential. `ChangeHost::fetch_target` makes one. The
/// mirror of `PushTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchTarget {
    /// The repository.
    pub repo: RepoRef,
    /// The read credential for this fetch.
    pub credential: FetchCredential,
}

/// What `fetch` brought in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedBase {
    /// The branch that was fetched.
    pub branch: BranchName,
    /// The commit the branch pointed at when it was fetched. Now in the job's object store.
    pub commit: CommitSha,
}

/// What a workspace is for. It decides which paths exist in the checkout and whether the sandbox
/// may write to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacePurpose {
    /// A checkout for an `agent` sandbox. Every path the rules classify as `Hidden` is absent.
    /// The checkout is writable.
    Agent,
    /// A checkout for a `verify` sandbox. It is read-only. Paths the rules classify as `Hidden`
    /// are absent, except those that match `holdouts`, which are present so the trusted gates
    /// can run held-out tests. The builder never had them.
    Verify {
        /// The held-out test globs from the policy (`evaluation_holdouts`).
        holdouts: Vec<RepoGlob>,
    },
}

/// What to check out and what to keep out of the sandbox's sight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRequest {
    /// The job. Its object store must exist (`WorkspaceProvider::fetch`).
    pub job: JobId,
    /// The attempt the workspace belongs to. A workspace whose attempt is not live is an orphan.
    pub attempt: AttemptId,
    /// The commit to check out, detached. It is the fetched base or a commit the factory made
    /// earlier in this job.
    pub base: CommitSha,
    /// The path rules from the policy. Adapters take every decision about a path from here.
    pub rules: PathRules,
    /// What the workspace is for.
    pub purpose: WorkspacePurpose,
}

/// The host directories and masks the sandbox is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMounts {
    /// The checkout, mounted at `/workspace`.
    pub workspace: PathBuf,
    /// True for a `verify` workspace: `/workspace` is mounted read-only.
    pub workspace_read_only: bool,
    /// The output directory, mounted read-write at `/out`. Build output goes here.
    pub out: PathBuf,
    /// Paths the rules classify as `DenyWrite` or `AppendOnly`, re-mounted read-only over the
    /// checkout (`protected_overlay_readonly`).
    pub protected_overlays: Vec<RepoPath>,
    /// True when `/dev/null` is bound over `/workspace/.git`, so the sandbox sees no git data.
    pub git_masked: bool,
}

/// A protected path that changed, and the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathViolation {
    /// The path. A rename reports both ends.
    pub path: RepoPath,
    /// The mode that applies to it.
    pub mode: PathMode,
}

/// Why a workspace call failed. The set is closed and carries no file content, no credential and
/// no text from git.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceError {
    /// A hidden path exists in the sandbox's tree.
    #[error("a hidden path exists in the sandbox tree: {0}")]
    HiddenPathPresent(RepoPath),
    /// A symbolic link points outside the workspace.
    #[error("a symbolic link points outside the workspace: {0}")]
    EscapingSymlink(RepoPath),
    /// A gitlink (a submodule entry) was found.
    #[error("a gitlink (submodule entry) was found: {0}")]
    Gitlink(RepoPath),
    /// A nested git directory was found.
    #[error("a nested git directory was found: {0}")]
    NestedGit(RepoPath),
    /// One or more paths broke their mode.
    #[error("{} protected path(s) changed", .0.len())]
    ProtectedPathChanged(Vec<PathViolation>),
    /// The changed files hold something that looks like a secret.
    #[error("{} possible secret(s) found in the change", .0.len())]
    SecretFound(Vec<Finding>),
    /// A file or the whole change is larger than the limit.
    #[error("the file or change is larger than the limit")]
    TooLarge,
    /// The path does not exist at the commit, or it is hidden in this view.
    #[error("no such path at the commit: {0}")]
    PathNotFound(RepoPath),
    /// The commit is not in the job's object store.
    #[error("the commit is not in the job's object store")]
    UnknownCommit,
    /// The job has no object store yet. Call `fetch` first.
    #[error("the job has no object store; fetch the repository first")]
    NotFetched,
    /// The branch moved while it was being fetched, or the remote no longer has the commit.
    #[error("the remote branch moved while it was fetched")]
    BaseMoved,
    /// The remote branch has commits the push would drop. The factory never forces.
    #[error("the remote branch has commits that the push would drop")]
    NonFastForward,
    /// The commit was not made by the factory in this job, so it is not pushed.
    #[error("the commit was not made by the factory in this job")]
    NotMadeHere,
    /// A push target is not under `factory/`. The factory pushes nowhere else.
    #[error("the factory may push only to branches under `factory/`")]
    BranchNotAllowed,
    /// The remote refused the credential.
    #[error("the remote refused the credential")]
    Unauthorized,
    /// The caller cancelled the call. Nothing partial remains.
    #[error("the call was cancelled")]
    Cancelled,
    /// The call took longer than its limit. Nothing partial remains.
    #[error("the call timed out")]
    Timeout,
    /// A git command failed. Names the operation and the exit code, never git's text.
    #[error("git failed during {operation:?} (exit code {exit:?})")]
    Git {
        /// What the adapter was doing.
        operation: GitOperation,
        /// The exit code, when the process exited by itself.
        exit: Option<i32>,
    },
    /// Reading or writing the host directories failed.
    #[error("the host file system failed during {0:?}")]
    Io(IoOperation),
}

/// What the adapter was doing when git failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitOperation {
    /// Fetching objects.
    Fetch,
    /// Making the sparse worktree.
    Checkout,
    /// Computing the tree difference.
    Diff,
    /// Writing a commit.
    Commit,
    /// Pushing.
    Push,
    /// Reading an object.
    Read,
}

/// What the adapter was doing when a host file operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    /// Making a directory.
    CreateDirectory,
    /// Walking the checkout.
    Walk,
    /// Removing a directory.
    Remove,
}

/// The sandbox's work after it was audited: the tree difference from the workspace's base commit.
///
/// Only [`Workspace::ingest`] makes one, so a value of this type is proof that the audit walk,
/// the path rules and the secret scan passed. `new` is for workspace adapters and the testkit
/// only; the static check ST-13 fails a call from anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedChange {
    base: CommitSha,
    changes: Vec<ChangedPath>,
    sensitive: Vec<RepoPath>,
    tree: Sha256Digest,
}

impl IngestedChange {
    /// Called by a workspace adapter when ingestion succeeded.
    #[must_use]
    pub fn new(
        base: CommitSha,
        mut changes: Vec<ChangedPath>,
        sensitive: Vec<RepoPath>,
        tree: Sha256Digest,
    ) -> Self {
        changes.sort();
        Self { base, changes, sensitive, tree }
    }
    /// The commit the change is relative to.
    #[must_use]
    pub fn base(&self) -> &CommitSha {
        &self.base
    }
    /// The changed paths, sorted by path.
    #[must_use]
    pub fn changes(&self) -> &[ChangedPath] {
        &self.changes
    }
    /// The changed paths the rules classify as `Sensitive`. They feed the semantic checks.
    #[must_use]
    pub fn sensitive(&self) -> &[RepoPath] {
        &self.sensitive
    }
    /// The hash of the resulting tree.
    #[must_use]
    pub fn tree(&self) -> &Sha256Digest {
        &self.tree
    }
    /// True when nothing differs from the base commit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Which paths a read may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadView {
    /// What an agent may see. A path the rules classify as `Hidden` is `PathNotFound`.
    Agent,
    /// What the trusted control plane may see: everything in the commit.
    Trusted,
}

/// The diff between two commits, stored as an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchExport {
    /// The unified diff, `text/x-diff`. Generated on the host from the object store, with a fixed
    /// context size of 3 lines and no external diff driver or textconv.
    pub patch: ArtifactRef,
    /// The changed paths, sorted. A rename is a deletion and an addition.
    pub changes: Vec<ChangedPath>,
}

/// Makes the job's object store and the workspaces over it.
///
/// # Preconditions
/// Path rules come from the project configuration at the protected base, not from the
/// repository under work.
///
/// # Postconditions
/// The job's object store is a directory outside every mount. `fetch` puts the remote branch tip
/// into it and nothing else. `create` returns a sparse, detached worktree of a commit in that
/// store, and the store, not the worktree, keeps every commit `Workspace::commit` makes. A new
/// provider value over the same host directory sees the same store, so a restart loses no
/// commit.
///
/// # Errors
/// [`WorkspaceError`].
///
/// # Idempotency
/// `fetch` is idempotent: a repeat fetches what is missing and returns the tip it found.
/// `create` is not idempotent. `dispose_job` and `sweep_orphans` are.
///
/// # Cancellation and timeouts
/// `fetch` and `create` take a cancel signal and stop within a second. A cancelled or timed-out
/// call leaves the store as it was, or with extra objects that the next call reuses. Dropping the
/// future is equivalent to cancelling and is safe.
#[async_trait]
pub trait WorkspaceProvider: Send + Sync {
    /// Says whether this provider runs real git (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Fetches the branch into the job's object store, making the store when it does not exist,
    /// and returns the commit the branch pointed at. If the tip moved during the fetch the call
    /// returns `BaseMoved`.
    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<FetchedBase, WorkspaceError>;

    /// A sparse, detached worktree of `req.base`. Paths the rules classify as `Hidden` are not in
    /// it, except in a `Verify` workspace for the holdout globs.
    async fn create(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn Workspace>, WorkspaceError>;

    /// The job's object store, for reads, patches and pushes.
    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError>;

    /// Removes the job's object store and every workspace of the job.
    async fn dispose_job(&self, job: JobId) -> Result<(), WorkspaceError>;

    /// Removes the workspaces whose attempt is not in `live`, and the stores of jobs not in
    /// `live_jobs`. Returns the attempts whose workspace it removed.
    async fn sweep_orphans(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError>;
}

/// The trusted object store of one job. Everything here reads or writes the store, never the
/// sandbox-writable tree.
///
/// # Postconditions
/// `read_file_at` and `list_at` return what the commit holds. `export_patch` is the difference
/// between two commits in the store. `push` sends a commit that `Workspace::commit` made in this
/// job, recorded durably in the store, so it works after a restart and in a workspace other than
/// the one that made it.
///
/// # Errors
/// [`WorkspaceError`]: `UnknownCommit`, `PathNotFound`, `TooLarge`, `NotMadeHere`, `NonFastForward`,
/// `BranchNotAllowed`, `Unauthorized`, `Cancelled`, `Timeout`, `Git`, `Io`.
///
/// # Idempotency
/// Every read is a read. `push` of a commit already on the remote branch succeeds without
/// change. `export_patch` of the same two commits gives the same artifact.
///
/// # Cancellation and timeouts
/// `push` and `export_patch` take a cancel signal. A cancelled push has either updated the remote
/// branch or not; the next `push` of the same commit settles it.
#[async_trait]
pub trait JobRepo: Send + Sync {
    /// The bytes of a file at a commit, at most `max_bytes`.
    async fn read_file_at(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> Result<Vec<u8>, WorkspaceError>;

    /// The paths at a commit that match the glob, sorted, at most `limit`.
    async fn list_at(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError>;

    /// The diff from `base` to `head` as a stored artifact. The caller indexes it for its tenant.
    async fn export_patch(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<PatchExport, WorkspaceError>;

    /// Pushes a commit the factory made in this job to the target branch.
    async fn push(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError>;
}

/// The host side of one attempt's checkout. All git runs here with a fixed environment.
///
/// # Preconditions
/// `ingest` is called only after the sandbox container is gone, because a running container could
/// still change the tree. `commit` needs a change that `ingest` returned for this workspace.
///
/// # Postconditions
/// A successful `ingest` means the no-follow audit walk found no hidden path, no escaping
/// symlink, no gitlink and no nested git directory; the tree difference from the base commit,
/// computed on the host with a temporary index, passed every path rule; and no secret was found.
/// `commit` commits exactly the tree that `ingest` audited, with the base commit as its only
/// parent, and records the commit as made by the factory in this job. It refuses a change this
/// workspace never ingested.
///
/// # Errors
/// [`WorkspaceError`]: `HiddenPathPresent`, `EscapingSymlink`, `Gitlink`, `NestedGit`,
/// `ProtectedPathChanged`, `SecretFound`, `TooLarge`, `Cancelled`, `Timeout`, `Git`, `Io`.
///
/// # Idempotency
/// `ingest` gives the same answer for the same tree. `commit` of the same `IngestedChange` with
/// the same `CommitRequest` returns the same commit id and makes no second commit. `dispose`
/// removes the workspace's directories and can be followed by `sweep_orphans` safely.
///
/// # Cancellation and timeouts
/// `ingest` takes a cancel signal. Dropping `commit` is safe: it is atomic (a ref update).
#[async_trait]
pub trait Workspace: Send + Sync {
    /// The host directories and masks to build the sandbox from.
    fn mounts(&self) -> WorkspaceMounts;

    /// The commit the workspace was made from.
    fn base(&self) -> &CommitSha;

    /// Call after the container is gone. No-follow audit walk, temporary-index tree diff against
    /// `base()`, path rules, rejection of gitlinks and escaping symlinks, secret scan.
    async fn ingest(&self, cancel: &dyn CancelSignal) -> Result<IngestedChange, WorkspaceError>;

    /// Commits the audited change on top of the base commit, in the job's object store.
    async fn commit(
        &self,
        change: &IngestedChange,
        req: CommitRequest,
    ) -> Result<CommitSha, WorkspaceError>;

    /// Ends the workspace and removes its directories. The commits it made stay in the store.
    async fn dispose(self: Box<Self>) -> Result<(), WorkspaceError>;
}
```

### 5.5 Sandbox

```rust
// crates/ports/src/sandbox.rs (ports-v1.1): the items that change or are new. `SandboxProfile`,
// `ImageDigest`, `NetworkAttachment`, `FixedEnv`, `Resource`, `TeardownReason`, `TeardownReport`,
// `SandboxId`, `ExecArgv`, `ExecRequest`, `ExecResult`, `SandboxSession` and the constants
// `MASK_SOURCE` and `MASK_TARGET` are unchanged. `ExtraMount` and `JobTokenFile` are removed.

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::{Slug, Timestamp};
use factory_ports::agent::JobTokenSecret;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    FixedEnv, ImageDigest, NetworkAttachment, Resource, SandboxId, SandboxProfile, SandboxSession,
};

use crate::workspace::WorkspaceMounts;

/// Resource limits for one container. Every value is at least 1, so "no limit" cannot be written:
/// Docker reads 0 as unlimited for memory, CPUs and processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxLimits {
    /// CPU in thousandths of a core (2000 is two cores).
    pub cpu_millis: NonZeroU32,
    /// Memory in MiB.
    pub memory_mb: NonZeroU32,
    /// Memory plus swap in MiB. At least `memory_mb`. Equal means no swap.
    pub memory_swap_mb: NonZeroU32,
    /// Maximum number of processes.
    pub pids: NonZeroU32,
    /// Maximum number of open files.
    pub nofile: NonZeroU32,
    /// Largest single file in MiB.
    pub max_file_mb: NonZeroU32,
    /// Size of each tmpfs in MiB.
    pub tmpfs_mb: NonZeroU32,
    /// Disk the workspace and output directories may use, in MiB.
    pub workspace_disk_mb: NonZeroU32,
    /// How long the container may live. Not zero. Docker has no such limit, so the supervisor
    /// enforces it.
    pub wall_clock: Duration,
}

/// A named read-only cache the supervisor owns, such as `cargo-registry`. The host directory
/// behind a name is the adapter's own business and is never in a spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheName(pub Slug);

/// A cache mounted into the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheMount {
    /// Which cache.
    pub name: CacheName,
    /// True when the container may write to it. Only the `fetch_deps` profile may.
    pub writable: bool,
}

/// Everything mounted into the container. There is no free-form mount: a spec can name only
/// these kinds, so a mount of the Docker socket or of a host directory cannot be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxMounts {
    /// The checkout and output directories, protected overlays and the `.git` mask.
    pub workspace: WorkspaceMounts,
    /// The caches. Usually empty for `agent`.
    pub caches: Vec<CacheMount>,
}

/// The job token, as the secret itself. The sandbox adapter, and only it, writes the secret to a
/// file on a tmpfs it controls, mode 0400 and owned by the sandbox user, mounts the file
/// read-only at a fixed path, and removes it when the sandbox is torn down, whatever the reason.
/// The engine never writes a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTokenMount {
    /// The token's secret. Never shown in `Debug` output.
    pub secret: JobTokenSecret,
}

/// How a security module (seccomp, AppArmor) is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confinement {
    /// The runtime's default profile, or one derived from it.
    RuntimeDefault,
    /// Turned off. The policy never allows this.
    Unconfined,
    /// The module does not exist on this daemon (AppArmor on Docker Desktop). Allowed only when
    /// [`SandboxPolicy::apparmor_may_be_unavailable`] is set, and only for AppArmor.
    NotAvailable,
}

/// Which namespace a container shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// The container has its own.
    Private,
    /// The container has none (`ipc: none`).
    None,
    /// The container uses the host's. The policy never allows this.
    Host,
}

/// The security settings of a container, as requested in a spec and as read back from the created
/// container. Fields and `Hardening::strict` are unchanged from ports-v1; only the types of
/// `seccomp`, `apparmor`, `pid`, `ipc`, `uts` and `userns` are the enums above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    /// Privileged mode.
    pub privileged: bool,
    /// Numeric user id the process runs as.
    pub uid: u32,
    /// Numeric group id the process runs as.
    pub gid: u32,
    /// Read-only root filesystem.
    pub read_only_rootfs: bool,
    /// All capabilities dropped.
    pub cap_drop_all: bool,
    /// Capabilities added back.
    pub cap_add: Vec<String>,
    /// `no-new-privileges`.
    pub no_new_privileges: bool,
    /// Seccomp setting.
    pub seccomp: Confinement,
    /// AppArmor setting.
    pub apparmor: Confinement,
    /// Process id namespace.
    pub pid: Namespace,
    /// Inter-process communication namespace. `Namespace::None` is `ipc: none`.
    pub ipc: Namespace,
    /// Host name namespace.
    pub uts: Namespace,
    /// User namespace.
    pub userns: Namespace,
    /// Devices passed through.
    pub devices: Vec<String>,
    /// Kernel parameter overrides.
    pub sysctls: Vec<String>,
    /// A minimal init process is PID 1.
    pub init: bool,
    /// The daemon keeps no copy of the logs.
    pub log_driver_none: bool,
}

/// What the policy requires of every sandbox. The values are loaded from
/// `policies/security.yaml`; this crate holds no numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// The smallest user id and group id allowed.
    pub min_uid: u32,
    /// Host paths that may never be mounted or lie under a mount source. A second layer under the
    /// typed mounts: it checks the two host directories a workspace brings.
    pub forbidden_mount_sources: Vec<String>,
    /// Environment names that may never be set.
    pub forbidden_env_names: Vec<String>,
    /// The only environment names the supervisor may set.
    pub allowed_env_names: Vec<String>,
    /// True on a development host whose daemon has no AppArmor. The posture report then records
    /// `NotAvailable` and the reason. Production hosts set it to false.
    pub apparmor_may_be_unavailable: bool,
    /// The largest limits for the `fetch_deps` profile.
    pub fetch_deps_max: SandboxLimits,
    /// The largest limits for the `agent` profile.
    pub agent_max: SandboxLimits,
    /// The largest limits for the `verify` profile.
    pub verify_max: SandboxLimits,
}

/// Everything needed to build one sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The job the sandbox serves.
    pub job: JobId,
    /// The attempt the sandbox belongs to. A sandbox whose attempt is not live is an orphan.
    pub attempt: AttemptId,
    /// Which kind of sandbox.
    pub profile: SandboxProfile,
    /// The image, by digest.
    pub image: ImageDigest,
    /// Resource limits.
    pub limits: SandboxLimits,
    /// Network access.
    pub network: NetworkAttachment,
    /// The mounts. Typed; nothing else can be mounted.
    pub mounts: SandboxMounts,
    /// The job token. `agent` profile only.
    pub job_token: Option<JobTokenMount>,
    /// The environment, set by the supervisor from a fixed list.
    pub env: FixedEnv,
    /// The security settings to build the container with.
    pub hardening: Hardening,
}

/// One mount the spec asks for, as the posture check expects to find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedMount {
    /// Where it is inside the container.
    pub target: String,
    /// True when it is read-only.
    pub read_only: bool,
    /// The host path, when the spec names one (the checkout and the output directory). `None`
    /// for mounts whose host side the adapter chooses (caches, the token file, tmpfs).
    pub source: Option<String>,
}

/// One mount of the created container, as `docker inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMount {
    /// Where it is inside the container.
    pub target: String,
    /// True when it is read-only.
    pub read_only: bool,
    /// The host path, or the kind for a tmpfs.
    pub source: String,
}

/// What the created container actually looked like when the supervisor inspected it.
/// Everything the spec asked for is read back here, so the engine can compare all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureReport {
    /// The security settings read back from the container.
    pub observed: Hardening,
    /// The image the container runs.
    pub image: ImageDigest,
    /// The limits read back. `wall_clock` is the supervisor's deadline for the container.
    pub limits: SandboxLimits,
    /// The network the container is attached to.
    pub network: NetworkAttachment,
    /// Every mount of the container.
    pub mounts: Vec<ObservedMount>,
    /// The environment of the container as `Config.Env` reports it.
    pub env: Vec<(String, String)>,
    /// True when the runtime self-check inside the container passed.
    pub self_check_passed: bool,
    /// When the posture was verified.
    pub verified_at: Timestamp,
}

/// Which parts of the posture differ from the spec. Empty means the posture matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureDiff {
    /// Names of the differing parts: the field names of `Hardening`, and `image`, `limits`,
    /// `network`, `mounts`, `env`, `self_check`.
    pub fields: Vec<&'static str>,
}

impl PostureReport {
    /// Pure. Compares every part of the report with the spec and the policy:
    ///
    /// * `Hardening`: each field equal, except that `apparmor` may be `NotAvailable` against a
    ///   requested `RuntimeDefault` when the policy allows it.
    /// * `image` equal; `limits` equal; `network` equal.
    /// * `mounts`: the observed set equals [`SandboxSpec::expected_mounts`]. A mount that is not
    ///   expected is a difference, and so is a missing one or one whose read-only flag differs.
    /// * `env`: every pair of the spec is present with the same value, and every observed name is
    ///   on the policy's allowed list.
    /// * `self_check_passed` is true.
    #[must_use]
    pub fn differences(&self, spec: &SandboxSpec, policy: &SandboxPolicy) -> PostureDiff {
        let _ = (spec, policy);
        todo!("ports-v1.1: implemented by the port revision package, test first")
    }
}

impl SandboxSpec {
    /// Pure. Every mount the spec asks for, with the flags the policy requires.
    #[must_use]
    pub fn expected_mounts(&self) -> Vec<ExpectedMount> {
        todo!("ports-v1.1")
    }

    /// Pure. Rejects anything weaker than the policy. In addition to the rules of ports-v1
    /// (privileged, capabilities, user, root file system, privilege escalation, seccomp, host
    /// namespaces, devices, sysctls, init, log driver, environment, network and token fit to the
    /// profile, limits at most the maximum, the `.git` mask), it rejects:
    ///
    /// * a zero wall clock, and `memory_swap_mb` below `memory_mb`;
    /// * AppArmor `NotAvailable` unless the policy allows it, and `NotAvailable` for seccomp;
    /// * a workspace or output directory that is not an absolute, normalized host path (no `..`,
    ///   no `.` or empty component, no trailing `/`) or that is, or lies under, a forbidden mount
    ///   source;
    /// * a `verify` workspace that is not read-only, and an `agent` or `fetch_deps` workspace that
    ///   is read-only;
    /// * a writable cache outside `fetch_deps`, and a cache named twice.
    ///
    /// # Errors
    /// Returns every broken rule, not only the first.
    pub fn validate(&self, policy: &SandboxPolicy) -> Result<(), PolicyViolation> {
        let _ = policy;
        todo!("ports-v1.1")
    }
}

/// One way a spec is weaker than the policy. The set is closed. The first group is unchanged from
/// ports-v1 except `ForbiddenMountSource`, which now reports the host path of the workspace or
/// output directory; the second group is new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxRule {
    /// Privileged mode.
    Privileged,
    /// A capability was added back.
    CapabilityAdded(String),
    /// Capabilities were not all dropped.
    CapabilitiesNotDropped,
    /// The user or group id is below the policy minimum.
    UserNotNonRoot,
    /// The root file system is writable.
    WritableRootFilesystem,
    /// `no-new-privileges` is off.
    PrivilegeEscalationPossible,
    /// Seccomp is off.
    SeccompUnconfined,
    /// AppArmor is off.
    AppArmorUnconfined,
    /// A host namespace is shared (process, IPC, host name or user).
    HostNamespace(&'static str),
    /// A device is passed through.
    DeviceAttached(String),
    /// A kernel parameter is overridden.
    SysctlOverride(String),
    /// There is no init process.
    NoInitProcess,
    /// The daemon would keep a copy of the logs.
    DaemonKeepsLogs,
    /// The workspace or output directory is, or lies under, a path the policy forbids.
    ForbiddenMountSource(String),
    /// An environment name the policy forbids.
    EnvNameForbidden(String),
    /// An environment name that is not on the supervisor's list.
    EnvNameNotAllowed(String),
    /// The network does not suit the profile.
    NetworkNotAllowedForProfile,
    /// A job token is present outside the agent profile, or missing from it.
    JobTokenMisplaced,
    /// A limit is above the policy maximum for the profile.
    LimitAboveMaximum(&'static str),
    /// `.git` is not masked.
    GitDirectoryNotMasked,
    /// A limit is zero. Only the wall clock can be, because the others cannot be written as zero.
    LimitIsZero(&'static str),
    /// `memory_swap_mb` is below `memory_mb`.
    SwapBelowMemory,
    /// AppArmor is not available and the policy does not allow that.
    AppArmorUnavailableNotPermitted,
    /// A host path is not absolute and normalized.
    HostPathNotNormalized(&'static str),
    /// The workspace is writable in `verify`, or read-only elsewhere.
    WorkspaceAccessMismatch,
    /// A cache is writable outside `fetch_deps`, or listed twice.
    CacheMisuse,
}

/// A spec was weaker than the policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the sandbox spec is weaker than the policy")]
pub struct PolicyViolation {
    /// Every rule the spec broke, in a fixed order.
    pub rules: Vec<SandboxRule>,
}

/// Where provisioning stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionStage {
    /// Writing the job token file.
    TokenFile,
    /// Making the per-job network or the sidecar.
    Network,
    /// Creating the container.
    Create,
    /// Inspecting it.
    Inspect,
    /// Starting it.
    Start,
    /// Running the self-check.
    SelfCheck,
}

/// Why a sandbox call failed. The set is closed. Changes from ports-v1: `ProvisionFailed` names
/// the stage instead of carrying text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// The spec is weaker than the policy. No container was made.
    #[error("the sandbox spec is weaker than the policy")]
    PolicyViolation(PolicyViolation),
    /// The created container differs from the spec. It was removed.
    #[error("the created container differs from the spec in: {}", .0.fields.join(", "))]
    PostureMismatch(PostureDiff),
    /// The image is not present on the host. Images are never pulled.
    #[error("the image is not available on this host")]
    ImageUnavailable,
    /// The container runtime cannot be reached. The stage run is blocked, never run on the host.
    #[error("the container runtime is unavailable")]
    DaemonUnavailable,
    /// The container could not be made or started. Anything made so far was removed.
    #[error("the sandbox could not be provisioned at {0:?}")]
    ProvisionFailed(ProvisionStage),
    /// The sandbox lived past its wall-clock limit and was killed.
    #[error("the sandbox exceeded its wall-clock limit")]
    Timeout,
    /// A resource limit was hit.
    #[error("a resource limit was exceeded")]
    ResourceExceeded(Resource),
    /// The caller cancelled the call. The process was stopped and anything made was removed.
    #[error("the call was cancelled")]
    Cancelled,
    /// The sandbox could not be fully removed. `leaked` says whether something may still run.
    #[error("teardown failed (leaked: {leaked})")]
    TeardownFailed {
        /// True when a container, network, sidecar or token file may still exist.
        leaked: bool,
    },
}

/// Makes sandboxes.
///
/// # Preconditions
/// The spec's image is on the host, pinned by digest. The caller holds the attempt's lease.
///
/// # Postconditions
/// `create_verified` returns a session only for a container that was created, inspected, found
/// to match the spec and the policy in every part of [`PostureReport::differences`], started, and
/// found to pass the runtime self-check. A mismatch removes the container and fails closed.
/// For an `agent` sandbox the job token file exists inside the container at the fixed path
/// and nowhere else on the host once the sandbox is torn down. `sweep_orphans` leaves no sandbox,
/// network, sidecar or token file whose attempt is not in `live`, and never touches one that is.
///
/// # Errors
/// [`SandboxError`].
///
/// # Idempotency
/// `create_verified` is not idempotent. `sweep_orphans` is.
///
/// # Cancellation and timeouts
/// `create_verified` takes a cancel signal. A cancelled or timed-out provisioning removes
/// everything it made before it returns, and reports `Cancelled` or `ProvisionFailed`. Dropping
/// the future is unsafe for resources, so the supervisor does the removal in a guard that runs on
/// drop; `sweep_orphans` is the backstop.
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    /// Says whether this provider starts real containers (`real`) or simulates them (`fake`).
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity;

    /// Create, inspect, compare with policy, start, run the runtime self-check.
    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError>;

    /// Removes containers, networks, sidecars and token files whose attempt is not in `live`.
    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError>;
}
```

`SandboxSession` is unchanged. `ExecArgv`, `ExecRequest` and `ExecResult` are unchanged.

### 5.6 Agent, router and broker

```rust
// crates/ports/src/agent.rs (ports-v1.1): the items that change or are new. `RuntimeId`,
// `Capability`, `CapabilityObservation`, `RuntimeCapabilities`, `ModelSelection`, `FlagSet`,
// `DataClass`, `DataPart`, `AssembledPrompt`, `AgentRef`, `GrantedTools`, `AgentLimits`,
// `BrokerEndpoint`, `JobTokenId`, `JobTokenSecret`, `JobTokenRef`, `CostMicroUsd`, `Usage`,
// `ExitInfo`, `Denial`, `IssuedJobToken`, `TokenState` and `TokenUsage` are unchanged.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::{ArtifactRef, SchemaRef};
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{
    AgentLimits, AgentRef, AssembledPrompt, BrokerEndpoint, Capability, Denial, ExitInfo,
    FlagSet, IssuedJobToken, JobTokenId, JobTokenRef, JobTokenRequest, ModelSelection, RuntimeCapabilities,
    RuntimeId, TokenUsage, Usage, GrantedTools,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::SandboxSession;

/// Everything one agent run needs. One field is new: `max_output_bytes`.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunRequest {
    /// The attempt the run belongs to.
    pub attempt: AttemptId,
    /// The agent and its version.
    pub agent: AgentRef,
    /// The prompt, with untrusted text only inside the data envelope.
    pub prompt: AssembledPrompt,
    /// The schema the output must follow.
    pub output_schema: SchemaRef,
    /// The most bytes of final output the adapter reads. One more byte is `OutputTooLarge`. From
    /// `untrusted_content.structured_output.max_bytes` in the policy.
    pub max_output_bytes: u64,
    /// Where the sidecar relays to.
    pub broker: BrokerEndpoint,
    /// The job token the tool authenticates with.
    pub job_token: JobTokenRef,
    /// The tools policy granted. The agent never decides this.
    pub tools: GrantedTools,
    /// The limits of this run.
    pub limits: AgentLimits,
    /// The model and runtime.
    pub model: ModelSelection,
    /// The flag set for the stage.
    pub flag_set: FlagSet,
}

/// The final output of a run, **as bytes**. Nothing has parsed it. The engine hands the bytes to
/// `OutputValidator::validate_bytes`, which refuses a document with a repeated key, an
/// oversize body or too deep a nesting before any parser builds a value, and stores the same
/// bytes as an artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct RawOutput(Vec<u8>);

impl RawOutput {
    /// Wraps the bytes the tool wrote.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for RawOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawOutput({} bytes)", self.0.len())
    }
}

/// What a run left behind, whether it worked or not. The failed attempt is the one that needs its
/// evidence and may have cost money, so every part is returned either way.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunReport {
    /// The final output, or why there is none.
    pub outcome: Result<RawOutput, AgentRunError>,
    /// The transcript, stored after redaction. `None` only when the run failed before the tool
    /// produced any.
    pub transcript: Option<ArtifactRef>,
    /// What the run used, as far as the adapter could tell. Zero when nothing was used.
    pub usage: Usage,
    /// The version of the tool that ran, when it started.
    pub runtime_version: Option<String>,
    /// How the process ended, when it started and ended.
    pub exit: Option<ExitInfo>,
    /// Tool calls the tool reported as denied.
    pub permission_denials: Vec<Denial>,
}

/// Why a run failed. The set is closed. `OutputTooLarge` is new.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentRunError {
    /// The model provider cannot be reached.
    #[error("the model provider is unavailable")]
    ProviderUnavailable,
    /// The provider asked the caller to slow down.
    #[error("the model provider is rate limiting this caller")]
    RateLimited {
        /// How long the provider asked to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// The job token or credential was refused.
    #[error("the model provider refused the credential")]
    AuthenticationRequired,
    /// The run took longer than its wall-clock limit.
    #[error("the agent run timed out")]
    Timeout,
    /// The tool's process ended with a failure.
    #[error("the agent process failed")]
    ProcessFailed(ExitInfo),
    /// The tool ended without producing the final output.
    #[error("the agent produced no output")]
    OutputMissing,
    /// The final output is larger than `max_output_bytes`.
    #[error("the agent output is larger than the limit")]
    OutputTooLarge,
    /// The caller cancelled the run and the tool was stopped.
    #[error("the agent run was cancelled")]
    Cancelled,
    /// The run needs a capability the probe did not find.
    #[error("the runtime lacks the capability {}", .0.as_str())]
    CapabilityMissing(Capability),
    /// The broker refused the call because the budget is used up.
    #[error("the budget is used up")]
    BudgetRefused,
}

/// The step of a probe that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStep {
    /// Reading the version.
    Version,
    /// Reading the help text.
    Help,
    /// Running a trial command.
    Trial,
}

/// Why a probe failed. The set is closed. `ProbeFailed` names the step instead of carrying text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The tool is not installed in the sandbox image.
    #[error("the agent tool is not installed in the sandbox image")]
    BinaryMissing,
    /// The tool's version is outside the accepted range, so the stage is blocked.
    #[error("the agent tool version {found} is not supported")]
    UnsupportedVersion {
        /// The version the tool reported.
        found: String,
    },
    /// The probe command failed.
    #[error("the probe failed at {0:?}")]
    ProbeFailed(ProbeStep),
}

/// Runs an agent tool inside a sandbox.
///
/// # Preconditions
/// The session is an `agent`-profile sandbox that passed its posture check. The prompt keeps
/// untrusted text inside its data envelope. The granted tools were decided by policy.
///
/// # Postconditions
/// `probe` returns what the tool can do, read from the tool itself and repeatable. `run` always
/// returns a report. A report with an output carries the tool's final output as bytes,
/// unvalidated. A report with an error still carries the usage, the transcript and the denials
/// of the run. `run` never marks a stage successful, and a cancelled run stops the tool before
/// it returns.
///
/// # Errors
/// [`ProbeError`] for `probe`. For `run`, the error is `report.outcome`.
///
/// # Idempotency
/// `probe` is a read. `run` is not idempotent: each call runs the tool again and may cost money.
///
/// # Cancellation and timeouts
/// `run` takes a cancel signal and `req.limits` holds the wall clock. Dropping the future kills
/// the tool process but loses the report; the usage is still in the broker (`ModelBroker::usage`).
/// `probe` has a fixed timeout of 30 seconds and is safe to drop.
#[async_trait]
pub trait AgentRuntime: Send + Sync {
    /// The runtime's name.
    fn id(&self) -> &RuntimeId;

    /// Says whether this adapter drives a real tool (`real`) or is a scripted stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Reads the tool's version and flags and reports what it can do.
    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError>;

    /// Starts the tool inside `session`. The engine validates the output. This never marks
    /// success.
    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport;
}

/// What the probes of the available runtimes found. Probing is done by the engine, per runtime,
/// and cached by runtime version and image digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbedCapabilities(pub BTreeMap<RuntimeId, RuntimeCapabilities>);

/// What a stage needs from a model, as a routing question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingNeed {
    /// The stage.
    pub stage: StageKind,
    /// How capable the model should be.
    pub tier: RecommendedTier,
    /// Capabilities the runtime must have.
    pub required: Vec<Capability>,
    /// The risk of the job, which can force a larger model.
    pub risk: RiskTier,
    /// Runtimes that already failed for this attempt window. The router never returns one.
    pub exclude: Vec<RuntimeId>,
    /// What the probes found. A runtime with no entry is not a candidate.
    pub probed: ProbedCapabilities,
}

/// The answer to a routing question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    /// The model and runtime to use.
    pub model: ModelSelection,
    /// The flag set for the stage.
    pub flag_set: FlagSet,
}

/// Why no route was found. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoutingError {
    /// The routing policy has no entry for this stage and tier.
    #[error("the routing policy has no route for this need")]
    NoRoute,
    /// Every candidate was excluded.
    #[error("every candidate runtime was excluded")]
    AllExcluded,
    /// Every remaining candidate lacks a capability the need requires, as the probes found.
    #[error("no candidate runtime has the capability {}", .0.as_str())]
    CapabilityUnavailable(Capability),
}

/// Chooses a runtime and model. A pure function of the routing policy and the question.
///
/// # Postconditions
/// The same need, with the same exclusions and the same probe results, always gets the same
/// decision. The decision's runtime is not in `need.exclude`, has an entry in `need.probed`, and
/// that entry supports every capability in `need.required`. The candidates are tried in the
/// order the policy lists them. Excluding the answer of a first call gives a different runtime
/// or an error, never the same one. The flag set is `FlagSet::for_stage`. Routing never calls a
/// provider.
///
/// # Errors
/// [`RoutingError`].
///
/// # Idempotency
/// Idempotent and side-effect free.
pub trait ModelRouter: Send + Sync {
    /// Says whether this router reads the real routing policy (`real`) or a fixed table (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Pure. Reads the routing policy.
    fn route(&self, need: &RoutingNeed) -> Result<RoutingDecision, RoutingError>;
}

/// Why a token request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTokenRequest {
    /// The cost ceiling is zero.
    ZeroCeiling,
    /// The list of allowed models is empty.
    NoModels,
    /// The lifetime is zero.
    ZeroTtl,
}

/// Why a broker call failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// The broker has no such token.
    #[error("the broker has no such token")]
    UnknownToken,
    /// The request was malformed.
    #[error("the token request is invalid: {0:?}")]
    InvalidRequest(InvalidTokenRequest),
    /// The broker cannot be reached.
    #[error("the model broker is unavailable")]
    Unavailable,
}

/// Issues, revokes and meters the per-job tokens that stand between the sandbox and the real
/// model keys.
///
/// # Postconditions
/// An issued token is bound to its tenant, job and stage, starts with zero usage and is `Active`
/// until it is revoked, expires or reaches its ceiling. After `revoke` the token is `Revoked`
/// and no further spending is allowed under it; the usage recorded so far stays readable.
/// `revoke_for_job` revokes every token of the job, including tokens whose attempt crashed. The
/// secret never appears in `Debug` output.
///
/// # Errors
/// [`BrokerError`].
///
/// # Idempotency
/// `revoke` and `revoke_for_job` are idempotent: revoking a revoked token, or a token the broker
/// never issued, succeeds. `issue` is not idempotent. `usage` is a read.
///
/// # Cancellation and timeouts
/// Every call is safe to drop. `issue` that was dropped may have made a token that nobody holds;
/// `revoke_for_job` at the end of the job removes it.
#[async_trait]
pub trait ModelBroker: Send + Sync {
    /// Says whether this is the real broker (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Bound to tenant, job and stage, with a cost ceiling and an allowed provider and model list.
    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError>;

    /// Idempotent.
    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError>;

    /// Revokes every token of the job. Idempotent.
    async fn revoke_for_job(&self, job: JobId) -> Result<(), BrokerError>;

    /// What the token has used and whether it still works.
    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError>;
}

/// The seam through which spend reaches a broker. The real broker's relay calls it in the
/// `egress` crate when it forwards a model request; the fake agent runtime calls it on the fake
/// broker to pretend to spend. **The engine never holds a `MeteringOps`**, and the static check
/// ST-14 fails a reference to it in the `workflow` crate: the engine reads what was spent with
/// `ModelBroker::usage` and cannot invent spend.
///
/// # Postconditions
/// The usage is added to the token's total. If the new total reaches the ceiling, the token is
/// revoked in the same step. Spend under a revoked or expired token is refused with
/// [`BrokerError::UnknownToken`] and adds nothing.
///
/// # Idempotency
/// Not idempotent: each call adds.
#[async_trait]
pub trait MeteringOps: Send + Sync {
    /// Adds `delta` to the token's usage and returns the totals.
    async fn record_usage(
        &self,
        token: &JobTokenId,
        delta: Usage,
    ) -> Result<TokenUsage, BrokerError>;
}
```

### 5.7 Output validator

```rust
// crates/ports/src/registry.rs (ports-v1.1): `OutputValidator` changes. `AgentRegistry`,
// `ContractKind`, `VersionReq`, `LoadedPrompt` and `RegistryError` are unchanged.

use factory_domain::contracts::Violation;
use factory_domain::values::Sha256Digest;
use factory_ports::registry::ContractKind;

/// A document that passed the strict path.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedOutput {
    /// The parsed document.
    pub value: serde_json::Value,
    /// The SHA-256 of the exact bytes that were validated. The artifact that stores them has this
    /// hash.
    pub sha256: Sha256Digest,
    /// The size of the bytes.
    pub size_bytes: u64,
}

/// Checks a JSON document against the schema of a contract kind.
///
/// # Preconditions
/// None. The bytes are untrusted agent output.
///
/// # Postconditions
/// `validate_bytes` refuses, before any parser builds a value: a body over the size limit, bytes
/// that are not UTF-8, nesting deeper than the limit, a node count over the budget, and an object
/// that repeats a key. If it returns `Ok`, the document follows the schema of that kind and
/// version and `value` is the parse of exactly those bytes. On failure the list holds every
/// violation found, each with a path and a plain-English message, and never repeats a large part
/// of the input. `validate_value` is for values the factory built itself and applies the same
/// schema; it cannot see a repeated key because the value no longer has one.
///
/// # Errors
/// A non-empty list of [`Violation`]s. An unknown schema version is a violation.
///
/// # Idempotency
/// Pure: the same input gives the same result.
pub trait OutputValidator: Send + Sync {
    /// The only path for agent output and for anything read from a file or the network.
    fn validate_bytes(
        &self,
        kind: ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<ValidatedOutput, Vec<Violation>>;

    /// For values the factory built itself.
    fn validate_value(
        &self,
        kind: ContractKind,
        version: u32,
        instance: &serde_json::Value,
    ) -> Result<(), Vec<Violation>>;
}
```

### 5.8 Specification provider

```rust
// crates/ports/src/spec.rs (ports-v1.1): `SpecificationProvider` splits in two. `SpecOperation`,
// `FeatureDir`, `HumanAnswer`, `RevisionRequest`, `SpecRequest`, `SpecificationDraft`,
// `SpecOutcome` and `PostCondition` are unchanged.

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::values::{Slug, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{AgentRunError, Denial, Usage};
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, Finding, RepoPath};
use factory_ports::sandbox::SandboxSession;
use factory_ports::spec::{
    FeatureDir, PostCondition, SpecOperation, SpecOutcome, SpecRequest,
};

use crate::agent::{AgentRunRequest, AgentRuntime};

/// What a Spec Kit run may use. The adapter owns none of these, and it has no access to the host
/// side of the repository: files come back through [`SpecFileSet`], read by the engine.
pub struct SpecContext<'a> {
    /// The `agent`-profile sandbox the skills run in.
    pub session: &'a mut dyn SandboxSession,
    /// The agent runtime that runs the skills.
    pub runtime: &'a dyn AgentRuntime,
    /// A request to copy for each skill run. The adapter replaces its prompt.
    pub run_template: AgentRunRequest,
    /// Stops the run.
    pub cancel: &'a dyn CancelSignal,
}

/// What one skill run cost. The stage handler adds it to the attempt's usage and keeps the
/// transcripts as evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillRun {
    /// The transcript, stored after redaction.
    pub transcript: Option<ArtifactRef>,
    /// What the run used.
    pub usage: Usage,
    /// Tool calls the tool reported as denied.
    pub permission_denials: Vec<Denial>,
}

/// What `run` did. The files are in the sandbox's checkout; the stage handler stops the
/// sandbox, ingests, commits and reads them back (`JobRepo::read_file_at`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpecRunReport {
    /// The operation that ran.
    pub op: SpecOperation,
    /// The feature directory the skills wrote to.
    pub feature_directory: FeatureDir,
    /// The files the run is expected to have left, relative to the repository root. The stage
    /// handler reads exactly these.
    pub expected_files: Vec<RepoPath>,
    /// One entry for each skill run, in order.
    pub skill_runs: Vec<SkillRun>,
}

/// One file read back from a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFile {
    /// The path.
    pub path: RepoPath,
    /// The exact bytes of the committed file.
    pub bytes: Vec<u8>,
}

/// The committed files of a Spec Kit run, for `assemble`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFileSet {
    /// The commit the files were read from.
    pub commit: CommitSha,
    /// The files, including the constitution when the operation wrote it.
    pub files: Vec<SpecFile>,
}

/// Why a file could not be read into the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseReason {
    /// The file is not in the set.
    Missing,
    /// The bytes are not UTF-8 text.
    NotText,
    /// A required section is absent.
    SectionMissing,
    /// A requirement or scenario id does not follow the id patterns.
    BadId,
    /// The file is larger than the limit.
    TooLarge,
}

/// Why a Spec Kit run failed. The set is closed. `ForbiddenOperation` is removed: the operation
/// is a closed enum, so the variant could never be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    /// Spec Kit is not installed in the project.
    #[error("Spec Kit is not installed in the project")]
    ToolMissing,
    /// The installed version is not the pinned one.
    #[error("Spec Kit version {found} is installed but {expected} is pinned")]
    VersionMismatch {
        /// The pinned version.
        expected: String,
        /// The installed version.
        found: String,
    },
    /// An installed Spec Kit file differs from the pinned manifest.
    #[error("{} Spec Kit file(s) differ from the pinned manifest", .0.len())]
    IntegrityNotOk(Vec<Finding>),
    /// A Spec Kit extension is installed. None is allowed.
    #[error("a Spec Kit extension is installed, and none is allowed")]
    ExtensionsPresent,
    /// The run finished but left the project in a state the adapter does not accept.
    #[error("{} post-condition(s) of the Spec Kit run do not hold", .0.len())]
    PostConditionFailed(Vec<PostCondition>),
    /// A Spec Kit file could not be read into the contract.
    #[error("the Spec Kit file {path} could not be read: {reason:?}")]
    ParseError {
        /// The file.
        path: RepoPath,
        /// Why not.
        reason: ParseReason,
    },
    /// The agent runtime failed.
    #[error("the agent runtime failed while running a Spec Kit skill")]
    Runtime(AgentRunError),
}

/// Runs the Spec Kit operations and returns a typed specification.
///
/// # Preconditions
/// `run`: the sandbox's checkout holds the project with Spec Kit installed at the pinned
/// version and the session is a verified `agent`-profile sandbox. `assemble`: the files were
/// read from a commit the factory made, after ingestion passed.
///
/// # Postconditions
/// `run` leaves files only under the feature directory and the constitution, and says which it
/// expects. `assemble` is pure: `Draft` carries a contract that validates against its schema with
/// the SHA-256 of each file's exact bytes; `NeedsHuman` lists every blocking question and
/// writes no contract. A cancelled `run` stops before it returns.
///
/// # Errors
/// [`SpecError`].
///
/// # Idempotency
/// `run` is not idempotent: a second `Specify` for the same feature directory may overwrite the
/// first draft, so the caller runs `Specify` once per feature and revises through
/// `SpecRequest::revision`. `assemble` is idempotent.
///
/// # Cancellation and timeouts
/// `run` takes the cancel signal in its context and stops its skill runs. `assemble` is
/// synchronous and bounded by the size of the files.
#[async_trait]
pub trait SpecificationProvider: Send + Sync {
    /// Says whether this provider drives real Spec Kit (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Runs one operation inside the sandbox.
    async fn run(
        &self,
        req: &SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecRunReport, SpecError>;

    /// Builds the typed outcome from the committed files.
    fn assemble(&self, req: &SpecRequest, files: &SpecFileSet) -> Result<SpecOutcome, SpecError>;
}
```

### 5.9 Code host

```rust
// crates/ports/src/githost.rs (ports-v1.1): the items that change or are new. `GitScope`,
// `ActorLogin`, `BadLogin`, `IssueRef`, `DraftPrRequest`, `PullRequestRef`, `PullRequestLifecycle`,
// `CommentTarget` and `CommentRef` are unchanged. `StatusState`, `StatusRequest` and
// `ChangeHost::set_status` are removed (ADR 0014, section 7).

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId};
use factory_domain::values::{Sha256Digest, Slug, Timestamp, Uri};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    ActorLogin, CommentRef, CommentTarget, DraftPrRequest, GitScope, IssueRef, PullRequestLifecycle,
    PullRequestRef,
};
use factory_ports::paths::{BranchName, CommitSha};
use factory_ports::workspace::PushTarget;

use crate::store::{GithubRepositoryId, InstallationId};
use crate::workspace::FetchTarget;

/// A person or service on the code host. Authority comes from the numeric id, never from the
/// login: a login can be renamed or re-registered by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GithubActor {
    /// The immutable numeric id.
    pub id: u64,
    /// The login at the time of the call. Display only.
    pub login: ActorLogin,
}

/// An issue as fetched live. Its text is untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Which issue.
    pub reference: IssueRef,
    /// The title, as written.
    pub title: String,
    /// The body, as written.
    pub body: String,
    /// Who opened it.
    pub author: GithubActor,
    /// The labels on it.
    pub labels: Vec<String>,
    /// When it was last edited, as the host reports. A change after the intake snapshot is an
    /// external change (ADR 0010).
    pub updated_at: Timestamp,
    /// When it was fetched.
    pub fetched_at: Timestamp,
}

/// A comment as fetched live. Its text is untrusted. An operator command comes this way (FR-029).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// Which comment.
    pub reference: CommentRef,
    /// Who wrote it.
    pub author: GithubActor,
    /// The text, as written.
    pub body: String,
    /// When it was written.
    pub created_at: Timestamp,
    /// When it was last edited, if it was.
    pub edited_at: Option<Timestamp>,
}

/// The id of the factory's own GitHub App.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppId(pub u64);

/// A required status check of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredCheck {
    /// The check's name.
    pub context: String,
    /// The App the check must come from, when the rule pins one.
    pub integration_id: Option<u64>,
}

/// How much of the repository's protection the App could read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionSource {
    /// Rules of active rulesets that apply to the default branch (`GET .../rules/branches/{b}`,
    /// Metadata read).
    Rulesets,
    /// The default branch has no active ruleset rule. It may have classic branch protection, which
    /// needs the Administration permission to read and which the App must not hold.
    NoRulesetRules,
}

/// What the repository's protection looks like, as far as the App can read it without the
/// Administration permission. It cannot read the bypass list; see [`BypassAttestation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionReport {
    /// The default branch the rules were read for.
    pub default_branch: BranchName,
    /// Where the rules came from.
    pub source: ProtectionSource,
    /// A rule requires a pull request before merging.
    pub requires_pull_request: bool,
    /// A rule requires code owner review.
    pub requires_code_owner_review: bool,
    /// A rule dismisses approvals when new commits are pushed.
    pub dismisses_stale_approvals: bool,
    /// A rule blocks force pushes (non-fast-forward updates).
    pub blocks_force_push: bool,
    /// A rule blocks deletion of the branch.
    pub blocks_deletion: bool,
    /// The required status checks.
    pub required_checks: Vec<RequiredCheck>,
}

/// A recorded statement by an organization admin that the factory's App is on no bypass list of
/// the repository. The App cannot check this itself without the Administration permission, which
/// the policy forbids, so a person says it and the record is part of the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassAttestation {
    /// The admin who made the statement.
    pub by: PrincipalId,
    /// When it was recorded.
    pub at: Timestamp,
}

/// What the preflight found missing. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightFailure {
    /// No ruleset rule applies to the default branch.
    NoRulesetRules,
    /// A pull request is not required.
    PullRequestNotRequired,
    /// Code owner review is not required.
    CodeOwnerReviewMissing,
    /// Approvals are kept when new commits are pushed.
    StaleApprovalsKept,
    /// Force pushes are allowed.
    ForcePushAllowed,
    /// Deleting the branch is allowed.
    DeletionAllowed,
    /// A check the factory posts is not required.
    FactoryCheckNotRequired(String),
    /// A check the factory posts is required but not pinned to the factory's App.
    FactoryCheckNotPinned(String),
    /// Nobody attested that the App is on no bypass list.
    BypassNotAttested,
}

/// The outcome of the protection preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightVerdict {
    /// The repository may run above L0.
    Pass,
    /// The repository runs at L0 only, for these reasons.
    CapAtL0(Vec<PreflightFailure>),
}

impl ProtectionReport {
    /// Pure. `Pass` only when every item of `policies/security.yaml`
    /// `credentials.repository_requirements` holds: rules apply to the default branch, a pull
    /// request is required, code owner review is required, stale approvals are dismissed, force
    /// pushes and deletion are blocked, every name in `factory_checks` is required and pinned to
    /// `app`, and `attestation` is present. Every failure is listed, not only the first.
    #[must_use]
    pub fn evaluate(
        &self,
        app: AppId,
        factory_checks: &[Slug],
        attestation: Option<&BypassAttestation>,
    ) -> PreflightVerdict {
        let _ = (app, factory_checks, attestation);
        todo!("ports-v1.1: implemented by the port revision package, test first")
    }
}

/// A pull request as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestState {
    /// Open, closed or merged.
    pub lifecycle: PullRequestLifecycle,
    /// True while it is a draft.
    pub draft: bool,
    /// The head branch.
    pub head: BranchName,
    /// The commit the head branch points at now. An approval binds to it.
    pub head_sha: CommitSha,
    /// The base branch.
    pub base: BranchName,
    /// The tag of the current body.
    pub body_etag: String,
}

/// The state of a check run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Running.
    InProgress,
    /// Finished with a conclusion.
    Completed(CheckConclusion),
}

/// How a finished check run ended. The names follow what a required check accepts: success,
/// skipped and neutral count as passing, the others do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckConclusion {
    /// Every gate passed.
    Success,
    /// A gate failed or could not run.
    Failure,
    /// The stage does not apply (a `SKIPPED` stage run).
    Neutral,
    /// A person must act.
    ActionRequired,
    /// The job was cancelled.
    Cancelled,
}

/// A check run to create or update. Gate results reach the code host as check runs, because a
/// check run carries the identity of the App that made it and a commit status does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    /// The commit the check is about.
    pub commit: CommitSha,
    /// The check's name, such as `factory-validation`. This is the name a ruleset requires.
    pub name: Slug,
    /// Which run of which stage: the same `(commit, name, external_id)` updates one check run.
    pub external_id: Slug,
    /// Running or finished.
    pub status: CheckStatus,
    /// A short title, 1 to 100 bytes.
    pub title: String,
    /// A summary, 1 to 4000 bytes. Checked for secrets.
    pub summary: String,
    /// A link to the evidence.
    pub details_url: Option<Uri>,
}

/// A check run that was created or updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckRef {
    /// Its id on the code host.
    pub id: u64,
}

/// Why a request was rejected as malformed. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The head branch is not on the remote. Push it first.
    HeadNotPushed,
    /// The head and the base are the same branch.
    HeadIsBase,
    /// There is nothing to compare: the branches have no difference.
    NoDifference,
    /// A text field is empty or longer than the host allows.
    TextBounds,
    /// The host refused for a reason the adapter could not classify.
    Other,
}

/// Why a code host call failed. The set is closed. `Rejected` names the reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GitHostError {
    /// No such issue, pull request or repository for this scope.
    #[error("no such item for this scope")]
    NotFound,
    /// The token is revoked, expired or was never valid for this scope.
    #[error("the credential is not valid for this scope")]
    Unauthorized,
    /// The code host refused the action for this token's permissions.
    #[error("the code host refused the action")]
    Forbidden,
    /// The item changed since the caller read it (a stale tag).
    #[error("the item changed since it was read")]
    Conflict,
    /// The branch is not under `factory/`.
    #[error("the factory may push only to branches under `factory/`")]
    BranchNotAllowed,
    /// The text to post holds something that looks like a secret. Nothing was posted.
    #[error("the text holds something that looks like a secret and was not posted")]
    UnsafeText,
    /// The code host asked the caller to slow down.
    #[error("the code host is rate limiting this caller")]
    RateLimited {
        /// How long the host asked to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// The code host cannot be reached.
    #[error("the code host is unavailable")]
    Unavailable,
    /// The code host rejected the request as malformed.
    #[error("the code host rejected the request: {0:?}")]
    Rejected(Rejection),
}

/// Reads issues, comments and the repository's protection.
///
/// # Preconditions
/// The scope names the tenant, job, stage and repository the call is for. Nothing here
/// authorizes anyone: the caller matches `GithubActor::id` against the named allowlist.
///
/// # Postconditions
/// Every fetch is live; a webhook payload is only a hint. `label_actor` returns the person who
/// applied the label, or `None` when the label is not on the issue. `repository_protection`
/// reads rulesets only, with the permissions the policy allows (Metadata read), and reports
/// `ProtectionSource::NoRulesetRules` when none applies; it never asks for the Administration
/// permission.
///
/// # Errors
/// [`GitHostError`]: `NotFound`, `Unauthorized`, `Forbidden`, `RateLimited`, `Unavailable`.
///
/// # Idempotency
/// Every method is a read.
///
/// # Cancellation and timeouts
/// Every call is safe to drop. The adapter sets a request timeout of 30 seconds and reports
/// `Unavailable` when it is exceeded.
#[async_trait]
pub trait IssueSource: Send + Sync {
    /// Says whether this source talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Always a live fetch.
    async fn fetch_issue(&self, scope: &GitScope, issue: &IssueRef) -> Result<Issue, GitHostError>;

    /// Always a live fetch. The comment of an operator command, with its author's numeric id.
    async fn fetch_comment(
        &self,
        scope: &GitScope,
        comment: &CommentRef,
    ) -> Result<Comment, GitHostError>;

    /// The person who applied `label` to the issue, or `None` when it is not on the issue.
    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<GithubActor>, GitHostError>;

    /// Reads the rules that apply to the default branch. A failure to read is an error, which the
    /// engine treats as level L0.
    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError>;
}

/// Pushes branches, opens draft pull requests, posts comments and check runs. It never merges and
/// never marks a pull request ready for review.
///
/// # Preconditions
/// The scope's job has not ended: after `revoke_job_tokens` for the job, every call with that
/// job in its scope is refused. Branches are under `factory/`. Text sent to the host is plain
/// English with no secret in it.
///
/// # Postconditions
/// `fetch_target` and `push_target` return credentials narrowed to one repository, read-only and
/// write for a `factory/*` branch only. `resolve_branch` returns the commit a branch points at
/// now. `open_draft_pull_request` opens a pull request in the **draft** state and never merges
/// it; if the head branch is not on the remote it returns `Rejected(HeadNotPushed)`. A comment
/// is posted **at least once** per idempotency key: the adapter embeds a marker derived from the
/// key and looks for it before posting, which reduces duplicates and does not rule them out (ADR
/// 0004). `publish_check` creates or updates one check run per `(commit, name, external_id)` as
/// the App. A call for one tenant's scope never reads or changes another tenant's items.
///
/// # Errors
/// [`GitHostError`].
///
/// # Idempotency
/// `open_draft_pull_request` is idempotent for the same open head branch: a second call returns
/// the first pull request; for a closed one it opens a new one. `post_comment` is at least once
/// by key. `update_pull_request_body` with the same body and a current tag changes nothing
/// visible. `publish_check` is idempotent by `(commit, name, external_id)`.
/// `revoke_job_tokens`is idempotent. The rest are reads.
///
/// # Cancellation and timeouts
/// Every call is safe to drop, with the effect of a call that was sent being possible. The
/// adapter sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait ChangeHost: Send + Sync {
    /// Says whether this host adapter talks to the real code host (`real`) or is scripted
    /// (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// A read credential for fetching the repository.
    async fn fetch_target(&self, scope: &GitScope) -> Result<FetchTarget, GitHostError>;

    /// Where to push. `factory/*` branches only.
    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError>;

    /// The commit the branch points at on the host now. A cheap call, for the checks that
    /// ask whether the base moved (ADR 0010) without fetching objects.
    async fn resolve_branch(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<CommitSha, GitHostError>;

    /// Opens a draft pull request. Idempotent for the same open head branch.
    async fn open_draft_pull_request(
        &self,
        scope: &GitScope,
        req: DraftPrRequest,
    ) -> Result<PullRequestRef, GitHostError>;

    /// Replaces the body. With `etag`, only if the body did not change since it was read.
    async fn update_pull_request_body(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        body: &str,
        etag: Option<&str>,
    ) -> Result<(), GitHostError>;

    /// Sanitized and secret-checked inside the adapter. At least once by key.
    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<CommentRef, GitHostError>;

    /// Creates or updates the check run for a gate result.
    async fn publish_check(
        &self,
        scope: &GitScope,
        req: CheckRequest,
    ) -> Result<CheckRef, GitHostError>;

    /// Reads a pull request.
    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError>;

    /// Called at job end, failure and cancel, and by the cleanup sweep.
    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError>;
    // There is no merge method, no method that marks a pull request ready, and none whose name
    // starts with `merge`, `ready` or `undraft` (rule DEP-09, extended by ADR 0014).
}

/// The headers of a webhook request that matter. Missing ones are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebhookHeaders {
    /// `X-GitHub-Event`.
    pub event: Option<String>,
    /// `X-GitHub-Delivery`.
    pub delivery: Option<String>,
    /// `X-Hub-Signature-256`.
    pub signature_256: Option<String>,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// True when the request also had the legacy `X-Hub-Signature` header.
    pub has_legacy_signature: bool,
}

/// What the payload hints at. The engine fetches the real state before it acts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookHint {
    /// A label was applied to an issue.
    IssueLabeled {
        /// The issue.
        issue: IssueRef,
        /// The label.
        label: String,
    },
    /// An issue was edited.
    IssueEdited {
        /// The issue.
        issue: IssueRef,
    },
    /// A comment was created on an issue or pull request.
    CommentCreated {
        /// The comment.
        comment: CommentRef,
    },
    /// A pull request changed (pushed to, closed, reopened).
    PullRequestChanged {
        /// The pull request.
        pr: PullRequestRef,
    },
    /// An event the factory does not act on. It is still recorded as a delivery.
    Other,
}

/// A delivery whose signature checked out. Everything in it is still untrusted except the
/// fact that GitHub sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    /// `X-GitHub-Delivery`, 8 to 128 bytes.
    pub delivery_id: String,
    /// The event name.
    pub event: Slug,
    /// The action, when the payload has one.
    pub action: Option<Slug>,
    /// The installation the delivery came through.
    pub installation: InstallationId,
    /// The repository, when the payload names one.
    pub repository: Option<GithubRepositoryId>,
    /// The numeric id of the sender.
    pub sender_github_user_id: Option<u64>,
    /// The hash of the raw body.
    pub body_sha256: Sha256Digest,
    /// The hash of event, action, installation, repository, subject, subject update time and
    /// sender.
    pub semantic_key: Option<Sha256Digest>,
    /// What the payload hints at.
    pub hint: WebhookHint,
}

/// Why a delivery was refused. The reply to GitHub is the same for every variant; only the audit
/// record differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebhookRejection {
    /// The body is larger than the limit (1 MiB).
    #[error("the body is too large")]
    TooLarge,
    /// A required header is missing.
    #[error("the header {0} is missing")]
    MissingHeader(&'static str),
    /// The content type is not `application/json`.
    #[error("the content type is not accepted")]
    BadContentType,
    /// The signature does not match, or is not in the `sha256=` form.
    #[error("the signature does not match")]
    BadSignature,
    /// Only the legacy SHA-1 header was present.
    #[error("only the legacy signature header was present")]
    LegacySignatureOnly,
    /// The signature matched and the payload is not a JSON object of the expected shape.
    #[error("the payload is malformed")]
    Malformed,
    /// The event is not on the `webhook.accepted_events` list.
    #[error("the event is not accepted")]
    UnsupportedEvent,
}

/// Verifies a webhook delivery before anything reads it (`policies/security.yaml`,
/// `webhook`). Pure and synchronous: the secrets are loaded when it is built. The `api` binary
/// depends on this port, not on the `github` crate.
///
/// # Preconditions
/// `raw_body` is the request body exactly as received, before any parse or re-serialization.
///
/// # Postconditions
/// The signature is `HMAC-SHA256(secret, raw_body)` compared in constant time with the value of
/// `X-Hub-Signature-256`, against every secret in the rotation window. The check happens before
/// the body is parsed. A delivery with only the legacy header is refused. No store call has been
/// made by the time this returns, so a forged request touches no database.
///
/// # Errors
/// [`WebhookRejection`].
///
/// # Idempotency
/// Pure: the same input gives the same result.
pub trait WebhookVerifier: Send + Sync {
    /// Says whether this verifier holds the real secrets (`real`) or a fixed test secret (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Checks size, headers, content type and signature, then reads the fields the engine needs.
    fn verify(
        &self,
        raw_body: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<VerifiedDelivery, WebhookRejection>;
}
```

### 5.10 Process runner

```rust
// crates/ports/src/process.rs (ports-v1.1): new. The one funnel through which the factory starts a
// host process.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;

/// The programs the factory may start on the host. There is no way to name another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Program {
    /// The Docker command line.
    Docker,
    /// Git.
    Git,
}

impl Program {
    /// The name used in logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Git => "git",
        }
    }
}

/// A value for a process environment. A secret is never shown in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub enum EnvValue {
    /// A value that may appear in logs.
    Plain(String),
    /// A value that must not. Git credentials travel this way, through the environment of the
    /// child only, never through arguments.
    Secret(String),
}

impl fmt::Debug for EnvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(text) => write!(f, "Plain({text:?})"),
            Self::Secret(_) => f.write_str("Secret(<redacted>)"),
        }
    }
}

/// One process to run. The environment of the child is exactly `env` plus a fixed `PATH`: the
/// runner clears everything else, so nothing leaks in from the factory's own environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    /// Which program.
    pub program: Program,
    /// The arguments. No NUL byte in any of them.
    pub args: Vec<String>,
    /// The working directory, an absolute host path, when the program needs one.
    pub cwd: Option<PathBuf>,
    /// The environment, as upper-case names and values.
    pub env: Vec<(String, EnvValue)>,
    /// Bytes for standard input.
    pub stdin: Option<Vec<u8>>,
    /// How long the process may run before it is killed.
    pub timeout: Duration,
    /// How many bytes of each of standard output and standard error are kept.
    pub max_output_bytes: u64,
}

/// What a process did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnOutput {
    /// The exit code, when the process exited by itself.
    pub exit_code: Option<i32>,
    /// The signal that ended it, when it was killed.
    pub signal: Option<i32>,
    /// Standard output, cut at `max_output_bytes`. Not redacted: the caller redacts before it
    /// stores or logs.
    pub stdout: Vec<u8>,
    /// Standard error, cut at `max_output_bytes`. Not redacted.
    pub stderr: Vec<u8>,
    /// True when either stream was cut.
    pub truncated: bool,
}

/// What the adapter was doing when the operating system failed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnStep {
    /// Starting the process.
    Start,
    /// Writing standard input.
    Stdin,
    /// Reading its output.
    Read,
    /// Waiting for it to end.
    Wait,
}

/// Why a process could not be run. A process that ran and exited with a failure is not an error:
/// its exit code is in [`SpawnOutput`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    /// The program is not installed on this host.
    #[error("the program {} is not installed", .0.as_str())]
    ProgramMissing(Program),
    /// The process ran past its timeout and was killed.
    #[error("the process timed out and was killed")]
    Timeout,
    /// The caller cancelled and the process was killed.
    #[error("the process was cancelled and killed")]
    Cancelled,
    /// The operating system failed the call.
    #[error("the operating system failed at {0:?}")]
    Os(SpawnStep),
}

/// Starts host processes. **Only the `sandbox` crate holds one**, and exactly one file in that
/// crate (`process.rs`) contains `std::process` or `tokio::process`; the static check ST-03 is
/// written against that file. The Docker supervisor and the host-side git code both take an
/// `Arc<dyn ProcessRunner>`, so a test replaces the real one with a scripted runner and no test
/// starts a real process by accident.
///
/// # Preconditions
/// Arguments are separate strings; there is no shell. A secret goes in `env`, never in `args`.
///
/// # Postconditions
/// The child is started with a cleared environment, no inherited file descriptors but
/// the three standard streams, and in its own process group. After a timeout or a cancel the
/// whole group is killed before the call returns.
///
/// # Errors
/// [`SpawnError`].
///
/// # Idempotency
/// Not idempotent: each call runs the program again.
///
/// # Cancellation and timeouts
/// Takes a cancel signal and `req.timeout`. Dropping the future kills the process group.
#[async_trait]
pub trait ProcessRunner: Send + Sync {
    /// Says whether this runner starts real processes (`real`) or replays a script (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Runs one process to its end.
    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError>;
}
```

### 5.11 The registry of ports

`docs/architecture/work-packages.json` lists every port, its fake and its real implementation. v1.1 adds:

| Port | Fake | Real | Built by |
|---|---|---|---|
| `SystemTx` | `InMemorySystemTx` | `PgSystemTx` in `storage` | `s1-storage-postgres` |
| `JobRepo` | `FakeJobRepo` | `GitJobRepo` in `sandbox` | `s1-workspace-ingestion` |
| `ProcessRunner` | `ScriptedProcessRunner` | `OsProcessRunner` in `sandbox` | `s1-sandbox-adapter` |
| `WebhookVerifier` | `FakeWebhookVerifier` | `GitHubWebhookVerifier` in `github` | `s1-github-adapter` |

`MeteringOps` and the new store sub-traits end in `Ops` and are helpers, not registered ports. The testkit adds `FakeRemote`, a simulated code-host repository that `FakeWorkspaceProvider` and `FakeChangeHost` share, so a push in one is visible to the other. It is not a port.

## 6. The claim, in prose, for the four places that must agree

| Place | What it does |
|---|---|
| Port | `SystemTx::find_claim_candidates`, then `AttemptOps::start_attempt` (section 5.2) |
| SQL, `docs/database/for-the-storage-crate.md` "Claim a stage run" | Step 1 and step 2 as written there. The recipe already matches. The documents' remaining difference is the sweep: `find_due_attempts` replaces the `expired_leases` text, and the sweep also covers deadlines and teardown |
| Fake | `InMemoryStore` keeps the committed rows and, per transaction, an overlay. `start_attempt` runs under the shared lock: it re-reads the committed row, compares version and status, checks the job, `not_before` and the live-attempt rule, and writes the stage run and the attempt together |
| Engine | `claim_next` as in the paragraph before the code in 5.2. The Deferral reasons stay (`JobNotActive` and `BackingOff` now come from `NotReady`, so the engine no longer re-derives them) |

## 7. Engine adaptation (`crates/workflow`)

The engine changes where it touched a port. The revision package owns these files (all inside the paths `s1-engine-core` owns).

| File | Change |
|---|---|
| `scheduler/claim.rs` | Replace `claim_ready` with `find_claim_candidates` and `start_attempt`. Drop the `lease_compare_and_swap_succeeded` fact; use `claim_candidate_current`. On a deferral for quota, router, contract or budget, call `postpone_stage_run` |
| `scheduler/lease.rs` | `heartbeat` calls `AttemptOps::heartbeat(fence, ttl)` and reads the status and deadline from `LeaseRenewal`; no second read |
| `scheduler/sweeper.rs` | Use `find_due_attempts` for the three reasons; delete the stage-run lease lookup. `A06` and `A10` join `A07` |
| `engine/payload.rs` and `engine/timeline.rs` | Delete the payload keys `STAGE_RUNS`, `CREATED`, `REPLACED_BY`, `ATTEMPT`, `ATTEMPT_NUMBER`, `FAILURE_CLASS`, `NOT_BEFORE`, `DEADLINE`, `OUTPUTS`, `ANSWER`, `ANSWER_MEDIA_TYPE`, `REWORK_TRACK`, `FAILING_SET`. `Timeline` loads `list_stage_runs`, `list_attempts`, `list_stage_run_artifacts`. The window of attempts starts at the newest `human-answer-<n>` input. Add the keys `guard` and `guard_facts_sha256` |
| `engine/admission.rs` | `NewJob` carries repository, mode, autonomy, scope and origin. Stop listing stage runs in the `job.admitted` payload |
| `engine/record.rs` (`Cx::move_*`) | Take a `GuardCleared`; pass the records (`StageRunEffects`, `AttemptEnd`); write `guard` and `guard_facts_sha256` into every transition event; keep the event id as the commit witness and reconcile on `CommitOutcomeUnknown` |
| `engine/failure.rs` | Build `EnvironmentCause` from `SandboxError` and `ProbeError`; take `S21` first; map the rest as before |
| `engine/gate.rs`, `gates/framework/decision.rs` | `GateDecision` gains `assurance: Vec<AssuranceClaim { level, evidence }>`; the engine writes an assurance ledger entry only from real, current evidence. `gate.rs` builds a `GateRecord` and passes it |
| `engine/facts.rs` (new) | The one module that builds guard facts. Each fact builder has a test that tries to break it |
| `engine/control.rs`, `commands/*` | Approvals go through `ApprovalOps`; `valid_approvals` replaces any payload read |
| `engine/progress.rs` | `Board::load` reads `list_stage_runs`; `G_UNRECOVERABLE` facts come from it |
| `handlers/context.rs` | `StageContext` carries `&dyn WorkspaceProvider`, an `&dyn ArtifactStore` and the tenant scope for artifact reads |
| `tests/engine_scenarios.rs`, `tests/invariants.rs`, `tests/audit.rs` | Rewritten against the new store. New scenarios: crash between find and start; crash after start; `CommitOutcomeUnknown`; `S21`; `S22`; two workers find one candidate; `INV-01`, `INV-09`, `INV-11` named |

## 8. Database follow-up (owner `dba`, package `s1-database-port-alignment`)

| Change | Why |
|---|---|
| Regenerate the state machine tables from `state-machine.json` with `docs/database/tools/state_machine_sql.py`: rows for `S21`, `S22`, the events `attempt_blocked` and `require_reauthorization`, the guards | The outbox key references `state_machine_transitions`; a missing row makes `stage_run.blocked` for `S21` fail its foreign key |
| `ALTER TABLE stage_runs ADD COLUMN failing_set_sha256 text` with the hash check | `GateRecord::failing_set_sha256` for the stagnation detector, without reading an artifact inside a transaction |
| `ALTER TABLE repositories ADD COLUMN bypass_attested_by_principal_id uuid, ADD COLUMN bypass_attested_at timestamptz` with the composite foreign key to `principals` | The attestation of decision 7 |
| Grants: the tenant role may `INSERT` and `UPDATE` the new columns; the system role reads `attempts.teardown_deadline_at` and `stage_runs.not_before` (already granted) | The due-work and claim queries |
| `docs/database/for-the-storage-crate.md`: the sweep recipe names `find_due_attempts` and covers deadline and teardown; the recipe for `S21` | One text for the port, the fake, the SQL and the engine |
| Migration header comment says `FOR NO KEY UPDATE SKIP LOCKED` | F-19. The comment of an applied migration is changed only if the DBA's process allows it; otherwise `for-the-storage-crate.md` states the correct mode, which it already does |
| Tests: `lease.sql` gains the due-attempt queries and `start_attempt` as one statement sequence; `statuses.sql` counts the new rows | Contract for `s1-storage-postgres` |

## 9. Contract suites and fakes

For each suite: checks to add, then the seeded defect that must fail each. A check with no defect carries a waiver in the defect table (reason and the trigger that removes the waiver).

**Store** (adds to the existing 45 checks; each new name below is a check):

| New check | Seeded defect that must fail it |
|---|---|
| `a_candidate_is_found_only_for_an_active_job` | `ClaimsForInactiveJob` |
| `a_candidate_is_found_only_after_not_before` | `IgnoresNotBefore` |
| `two_workers_find_one_candidate_and_one_start_wins` | `DoubleStartsAttempt` |
| `start_attempt_raises_the_epoch_by_one_and_creates_the_attempt_together` | `SplitsStart` (epoch raised, attempt missing after a failure) |
| `start_attempt_refuses_a_job_that_is_not_active` | `StartsForInactiveJob` |
| `start_attempt_refuses_a_second_live_attempt` | `AllowsTwoLiveAttempts` |
| `start_attempt_refuses_past_the_attempt_limit` | `IgnoresAttemptLimit` |
| `start_attempt_fails_at_the_largest_epoch` | `WrapsTheEpoch` |
| `a_retry_is_findable_after_its_back_off_and_not_before` | `IgnoresBackOff` |
| `a_lease_has_no_owner_on_the_stage_run` | n/a (type) |
| `a_heartbeat_cannot_revive_a_lapsed_lease` | `RevivesLapsedLease` |
| `a_fence_from_another_worker_name_is_refused` | `IgnoresWorkerName` |
| `due_attempts_cover_lease_deadline_and_teardown` | `MissesDeadline`, `MissesTeardown` |
| `an_insert_is_idempotent_by_id_and_content` | `DuplicatesOnReplay` |
| `the_same_id_with_other_content_is_refused` | `OverwritesOnReplay` |
| `a_job_is_found_by_its_origin` | `IgnoresOrigin` |
| `an_unknown_commit_outcome_is_resolved_by_the_witness` | `LosesWitness` (fake lever: apply, then fail) |
| `a_dropped_call_poisons_the_transaction` | `ContinuesAfterDrop` |
| `the_gate_record_is_required_where_the_table_says` | `AcceptsPassedWithoutOutcome` |
| `the_attempt_end_is_required_where_the_table_says` | `AcceptsFailedWithoutClass` |
| `a_terminal_row_is_not_edited` | `EditsTerminalRows` |
| `a_duplicate_task_key_is_refused` | `AllowsDuplicateTaskKey` (the review's survivor) |
| `a_task_graph_cycle_is_refused` | `AllowsCycle` |
| `a_task_move_needs_a_current_fence` | `IgnoresTaskFence` |
| `the_audit_limit_is_honoured` | `IgnoresAuditLimit` (the review's survivor) |
| `an_audit_event_with_no_job_is_stored_and_read` | `RequiresJobForAudit` |
| `the_platform_audit_event_lands_under_the_platform_tenant_only` | `WritesToCallerTenant` |
| `a_delivery_repeat_is_a_duplicate_not_an_error` | `ErrorsOnRepeat` |
| `an_original_request_revision_is_immutable` | `EditsRequest` |
| `an_approval_counts_only_for_its_head_and_until_it_expires` | `IgnoresHead`, `IgnoresExpiry` |
| `a_lookup_miss_is_none_for_every_reason` | `RevealsReason` |
| `a_tenant_cannot_read_another_tenants_row_through_any_new_method` | `ReadsAcrossTenants` (extended to every new method) |

**Workspace** (adds): `fetch_returns_the_tip_it_fetched`, `fetch_reports_a_moved_base`, `a_second_workspace_can_start_at_a_commit_the_first_made`, `push_works_after_a_restart` (subject lever `restart()`), `a_commit_the_factory_did_not_make_is_not_pushed`, `a_hidden_path_is_not_found_in_the_agent_view_and_is_in_the_trusted_view`, `a_verify_workspace_is_read_only_and_holds_the_holdouts`, `an_added_test_is_allowed_and_an_edited_test_is_refused_under_additions_only`, `a_case_variant_of_a_protected_path_is_refused`, `a_reincluded_path_is_allowed_only_in_its_own_group`, `export_patch_is_the_same_for_the_same_commits`, `a_cancelled_ingest_leaves_nothing_behind`. Defects: `ForgetsCommitsOnRestart`, `PushesForeignCommit`, `IgnoresCaseFold`, `IgnoresHoldouts`, `AllowsAnyEdit`, `UnstablePatch`.

**Sandbox** (adds): one check per posture part: `a_drifted_limit_is_a_mismatch`, `a_drifted_network_is_a_mismatch`, `an_extra_mount_is_a_mismatch`, `a_writable_mount_that_should_be_read_only_is_a_mismatch`, `a_drifted_environment_is_a_mismatch`, `a_different_image_is_a_mismatch`; `a_zero_wall_clock_is_refused`; `a_writable_cache_is_refused_outside_fetch_deps`; `the_job_token_file_is_absent_after_stop_and_remove` (subject lever `token_file_present()`); `the_job_token_never_shows_in_debug_output`; `apparmor_not_available_is_accepted_only_by_policy`; `a_cancelled_create_removes_what_it_made`. Defects: one per drifted part, `KeepsTokenFile`, `AcceptsAnyAppArmor`.

**Agent and router** (adds): `a_failed_run_still_reports_usage_and_transcript`, `output_is_bytes_and_a_oversize_output_is_a_failure`, `excluding_the_answer_gives_another_runtime_or_an_error`, `a_runtime_without_a_probe_is_not_a_candidate`, `a_probe_lacking_a_required_capability_is_skipped`. Defects: `DropsPartialUsage`, `ReturnsExcluded`, `IgnoresProbe`.

**Broker** (adds): `revoke_for_job_revokes_every_token_of_the_job`, `metering_to_the_ceiling_revokes_the_token`, `spend_under_a_revoked_token_is_refused`. Defects: `KeepsOtherTokens`, `NeverRevokesAtCeiling`.

**New suites:** `SpecificationProvider` (`run` with a scripted tool in the fake sandbox, then `assemble` on real file bytes: a missing file, a bad id, a hash of the exact bytes, the needs-human path); `OutputValidator` (repeated key, oversize, depth, node budget, hash of bytes, value path equals bytes path); `WebhookVerifier` (good signature, bad signature, legacy only, rotation window, missing header, oversize, constant-time compare is not tested but the use of the rotation list is); `ProcessRunner` (cleared environment, secret redacted in `Debug`, timeout kills the group, cancel kills the group, output cap); `MeteringOps`; `Clock` (never goes back), `IdGenerator` (unique and version 7), `CancelSignal` (never un-cancels).

**Change host** (adds): `a_pull_request_needs_a_pushed_head`, `a_closed_pull_request_is_not_reused`, `base_is_honoured`, `a_check_run_is_updated_not_duplicated`, `a_check_run_carries_the_apps_identity`, `a_comment_is_found_by_its_marker_before_posting`, `fetch_comment_returns_the_numeric_author_id`, `repository_protection_never_asks_for_administration`. Defects: `OpensForUnpushedHead`, `ReusesClosed`, `DuplicatesChecks`, `ForgesAppIdentity`.

**The register.** Each suite module exports `checks()` and each test file exports its defect table. `contract_register.rs` in `crates/testkit/tests/` loads every suite and every table and fails when a check is named in no table and has no waiver, when a waiver has no reason or trigger, or when a table names a check that does not exist. A second test, `fake_rules_are_mutation_tested`, applies for each fake a list of single-rule mutations (the deletable rules are marked with `rule!("name", ...)` in the fake's source) and fails when the suite still passes. The review's two survivors (the duplicate task key and the audit limit) are the first two entries.

## 10. Schema and state machine changes, and the Rust they need

Applied in this change, in `docs/architecture/state-machine.json`, `docs/architecture/state-machine.md` (regenerated) and `schemas/`. **The Rust tests that read these files fail until the revision package lands**, and the database state-machine test fails until the DBA's migration lands. This table is the contract between them.

### 10.1 JSON change to Rust change

| Change | Rust that must change | Test that proves it | Owner |
|---|---|---|---|
| `state-machine.json`: stage run transition `S21` (`RUNNING` to `BLOCKED`, event `attempt_blocked`, guard `G_ENVIRONMENT_BLOCKED`, actor `engine`, emits `stage_run.blocked`) | `crates/domain/src/state/stage_run.rs`: `StageRunEvent::AttemptBlocked` (`"attempt_blocked"`) in `EVENTS` and the name functions; a row `S21` in `STAGE_RUN_TRANSITIONS`. `state/guard.rs`: `Guard::EnvironmentBlocked = "G_ENVIRONMENT_BLOCKED"` with the JSON text as its documentation. `machines/guards.rs` and `guards/stage_run.rs`: `GuardFacts::Environment(EnvironmentFacts { cause: EnvironmentCause, attempt_ended_failed: bool })`, `EnvironmentCause { DaemonUnavailable, ImageUnavailable, PostureMismatch, PolicyViolation, ToolMissing, PolicyUnloadable }`, the predicate, the arm in `evaluate`. `machines/retry.rs`: `AttemptDisposition::Block(EnvironmentCause)` taken first when `RetryFacts.environment` is `Some`; `stage_run_event()` maps it to `AttemptBlocked`. `crates/workflow/src/engine/failure.rs`: build the cause from `SandboxError` and `ProbeError` and take `S21` | `state_machine_conformance.rs` (reads the JSON, passes unchanged); `retry/tests.rs`: `a_missing_environment_blocks_before_anything_else`, `a_provision_failure_is_still_retried`; engine scenario NT-SBX-14 | rev |
| `state-machine.json`: `S22` (`READY` to `WAITING_FOR_HUMAN`, event `require_reauthorization`, guard `G_REAUTHORIZATION_REQUIRED`, actor `engine`, emits `stage_run.waiting_for_human`) | `StageRunEvent::RequireReauthorization`; row `S22`; `Guard::ReauthorizationRequired`; `GuardFacts::Reauthorization(ReauthorizationFacts { authorized_request: Option<Sha256Digest>, current_request: Sha256Digest, policy_asks_confirmation: bool })` and the predicate; engine: after an external change, the new `INTAKE` run takes `S22` instead of `S03`; the answer (`S13`) links the new hash as `human-answer-<n>` | conformance; guard unit tests; engine scenario NT-AUTHZ-05 (`awaiting_reauthorization` is the job's `WAITING_FOR_HUMAN`) | rev |
| `state-machine.json`: guard text of `G_LEASE_ACQUIRED` | `LeaseGrantFacts.lease_compare_and_swap_succeeded` becomes `claim_candidate_current` (the stage run is `READY` at the version the claim read, in this transaction); the doc comment of `Guard::LeaseAcquired` follows the JSON | guard tests renamed | rev |
| `state-machine.json`: guard text of `G_SANDBOX_PROVISIONED` | `SandboxProvisionFacts` fields become `posture_verified`, `tool_grants_recorded`, `probe_satisfies_stage`, `epoch`; the engine sets `posture_verified` from "`create_verified` returned a session" and nothing else | guard tests; engine test with a fake sandbox that mismatches | rev |
| `state-machine.json`: guard text of `G_UNRECOVERABLE` | `UnrecoverableFacts` gains `newer_run_of_kind_exists: bool` and the predicate requires it false; the engine builds the facts from `list_stage_runs` | guard test: false when a newer run exists; engine test: a rework that created a newer run first does not fail the job | rev |
| `state-machine.json`: new guard ids | `Guard::ALL`, parse and display; the conformance test checks both directions | conformance | rev |
| `review-verdict.schema.json`: non-`PASS` findings need `location.path` and `location.line_start` | `crates/domain/src/contracts/review_verdict.rs`: `ReviewVerdict::validate` rejects with `findings[i].location: a finding of a verdict other than PASS cites a file and a line` and for the missing line `findings[i].location.line_start: a finding of a verdict other than PASS cites a line`. Regenerate the example index with `python3 crates/domain/tests/tools/gen_example_index.py` (it lists the example files, so a new example is invisible to the Rust tests until then), and add two rows to `REJECTED_FOR` in `tests/contract_examples.rs` for `non-pass-finding-without-location.json` and `non-pass-finding-without-a-line.json`. The review gate (`rev-stage`) checks that the line is in `export_patch` output | `contract_rules.rs`, `contract_examples.rs` | rev (domain), rev-stage (gate) |
| `stage-contract.schema.json`: `retry_on` contains `LEASE_LOST` and `TIMED_OUT` | `crates/domain/src/contracts/stage_contract.rs`: reject with `timeout_and_retries.retry_on: must list LEASE_LOST and TIMED_OUT`; `REJECTED_FOR` row for `retry-on-without-lease-lost.json` (after the index is regenerated) | same | rev |
| `evidence-ledger-entry.schema.json`: `evidenceSource.url` is an https URL | `contracts/evidence_ledger_entry.rs`: the `url` field uses an `HttpsUri` value with the message `evidence[i].url: a source URL starts with https://`; `crates/domain/src/patterns.rs` gains `HTTPS_URL = r"^https://[^\s]+$"` and the type compiles it, because the test `patterns_in_the_schemas_equal_the_patterns_compiled_by_the_rust_types` compares the schema's patterns with the Rust ones; `REJECTED_FOR` row for `source-url-not-https.json`; the new valid example `measured-fact-with-a-cited-https-source.json` round-trips | same, and `patterns_in_the_schemas_equal_the_patterns_compiled_by_the_rust_types` | rev |
| New events and guards in `state-machine.json` | `migrations/`: regenerated state machine rows | `scripts/db-test.sh` `statuses` and `outbox` suites | db |

### 10.2 What was applied and what was not

Applied: `S21`, `S22`, the three restated guards, two new guards, the review verdict rule, the `retry_on` rule, the `url` pattern, four invalid examples and one valid example (with their `.expect` sidecars). `schemas/validate.sh`: 123 of 123 checks pass. `render_state_machine.py --check` passes.

What the Rust does today, run at the end of this change (`cargo test --offline -p factory-domain --no-fail-fast`): 7 of the 22 tests in `state_machine_conformance` fail (`guard_registry_matches_json`, `event_names_match_state_machine_json`, `guard_and_actor_names_match_state_machine_json`, `transition_tables_match_state_machine_json`, `the_unchanged_file_conforms`, `every_status_and_event_pair_outside_the_table_is_rejected`, `conformance_detects_a_changed_table`), because the JSON has two more transitions, two more events and two more guards than the code; and 1 of the 10 tests in `contract_examples` fails (`patterns_in_the_schemas_equal_the_patterns_compiled_by_the_rust_types`), because the schema has a URL pattern the Rust type does not compile. Everything else passes: 261 unit tests, `contract_rules` 11, `ledger_chain` 18, `redaction` 69, `state_machine_properties` 19, `values` 39. The new invalid examples are not yet seen by the Rust tests, because `example_index.rs` lists the example files; regenerating it is the first step of the revision package. These failures are expected and are the signal that the Rust has not caught up.

Not applied, because each needs Rust in the same change: the agent-output schema (section 10.3).

The schemas README says tightening a rule needs a new schema version. I tightened version 1 in place because no document has ever been stored under it. **(pending)** A person may prefer `review-verdict` version 2; the cost is a new schema file, examples and a second domain type.

### 10.3 Outline of the agent-output schema for the review verdict (F-26)

Not applied. To be written with its Rust type and examples in the revision package, as `schemas/review-findings.schema.json` and `ContractKind::ReviewFindings`.

```json
{
  "$id": "urn:ortisun:factory:schema:review-findings:1",
  "required": ["schema_version", "verdict", "summary", "findings", "confidence_overall"],
  "properties": {
    "schema_version": { "const": 1 },
    "verdict": { "enum": ["PASS", "CHANGES_REQUIRED", "BLOCK", "NEEDS_HUMAN"] },
    "summary": { "$ref": "#/$defs/humanText" },
    "findings": { "type": "array", "items": "the finding object of review-verdict, unchanged, with the same location rule" },
    "confidence_overall": { "type": "number", "minimum": 0, "maximum": 1 },
    "human_question": "required when NEEDS_HUMAN, as in review-verdict",
    "residual_risks": "as in review-verdict"
  }
}
```

The engine validates the agent's bytes as `ReviewFindings` (through `validate_bytes`), then builds the stored `ReviewVerdict`: it writes `metadata` (ids, mode, the reviewer's agent, runtime and fidelity as the runtime reported them), `inputs_reviewed` (the frozen specification hash, the patch hash, the gate report hashes, `saw_builder_self_assessment: false`), `title`, and copies the rest. The agent can no longer claim what it saw or which runtime it was.

## 11. Edits for owners outside my directories

I own `docs/adr/`, `docs/architecture/` and `schemas/`. The following need a person or another specialist. Each line gives the file, the text to change and the new text. Mark as **(pending)** where ADR 0014 does.

| File | Change |
|---|---|
| `specs/001-end-to-end-mvp/spec.md` line 38 (US1 scenario 1) | "the job passes through all eleven stages in order" becomes "the job passes through every stage of its pipeline scope in order, which for the fixture job is the thirteen Slice 1 stages listed in `docs/architecture/state-machine.json`" |
| `specs/001-end-to-end-mvp/spec.md` line 312 (SC-001) | "with all eleven stages completed and stored" becomes "with every stage of the job's pipeline scope completed (passed, or skipped by a recorded rule) and stored; for the fixture job that is the thirteen Slice 1 stages" |
| `specs/001-end-to-end-mvp/spec.md` FR-023 **(pending)** | Add: "For a verdict other than pass, each finding cites a file and a line. For a pass verdict, a finding cites them when it concerns one." |
| `policies/security.yaml` `credentials.github_app.permissions_required` | Remove `statuses: write` **(pending)** |
| `policies/security.yaml` `credentials.repository_requirements` | Replace `app_in_bypass_list: false` by `app_not_in_bypass_list: attested_by_org_admin` and add `protection_source: rulesets`; classic branch protection alone caps the repository at L0 **(pending)** |
| `policies/security.yaml` header (line 15) | "block style" becomes "block or flow style" (F-27) |
| `docs/security/secrets-and-credentials.md` section 3.1 table | Remove the row "Commit statuses write"; in "Pull requests write" remove "ready-for-review" **(pending)** |
| `docs/security/secrets-and-credentials.md` section 3.5 | The second bullet reads "Required status checks come from a ruleset and are pinned to the factory App's id (`integration_id`)"; the third reads "An organization admin has recorded that the App is on no bypass list; the App cannot read the list, because that needs a permission the policy forbids" |
| `docs/security/negative-test-catalog.md` NT-MRG-07 | Add the variants "classic branch protection only" (result `repo_requirements_failed`, reason `protection_unreadable`) and "bypass not attested" |
| `docs/security/negative-test-catalog.md` NT-MRG-08 **(pending)** | Becomes: "A pull request is created as a draft and the run finishes. Expected: it is still a draft; `ChangeHost` has no method that marks a pull request ready (the scan that forbids `merge*` also forbids `ready*` and `undraft*`)" |
| `docs/security/negative-test-catalog.md` | Add ST-13 (callers of the scope constructors and of `IngestedChange::new`) and ST-14 (no reference to `MeteringOps` in `workflow`); reword ST-03 to "only `crates/sandbox/src/process.rs` contains `std::process` or `tokio::process`" |

Verified facts behind these edits are in ADR 0014 "What was checked". Anything marked UNVERIFIED there stays unverified here.

## 12. Architecture checks (F-12) and related scans

For `s1-xtask-extensions`. Each item is a failing fixture first, then the check. The review's mutations, exactly:

1. **DEP-05 ban list.** Add to the generated `clippy.toml` of the four inner crates, and to the scratch-crate test that proves each ban fires: `std::path::Path::{exists, is_file, is_dir, read_dir, metadata, symlink_metadata, canonicalize, read_link, try_exists}` and the same on `PathBuf`; `std::env::{var, var_os, vars, vars_os, set_var, remove_var, current_dir, current_exe, temp_dir}`; `std::os::unix::net::{UnixStream, UnixListener, UnixDatagram}`; `tokio::time::{sleep, timeout, Instant::now, interval}`; `time::OffsetDateTime::{now_utc, now_local}`; `uuid::Uuid::{now_v7, new_v4, new_v1, new_v6, new_v8}`; `std::net::ToSocketAddrs`. Correct ADR 0011 (it listed a ban on `now_utc` that did not exist) and ADR 0002 (the `uuid` generators).
2. **Feature unification.** Read `resolve.nodes[].features` from `cargo metadata --format-version 1` for `time`, `uuid` and `tokio` as resolved for each inner crate, and compare with an allow list in `crate-dependency-rules.json`. The domain's comment that it "has no way to call `now_utc`" holds only if the resolved set lacks `time/std`; the check proves it. Mutation: enable `time/std` in the empty `storage` crate; the check fails.
3. **`allow` attributes.** Fail the check on `allow` or `expect` of `clippy::disallowed_methods` or `clippy::disallowed_types` (and on `#![allow(clippy::all)]` and `#![allow(warnings)]`) in `domain`, `ports`, `workflow`, `spec_adapter`.
4. **Spawn scan.** Resolve `use ... as` aliases before matching `Command::new`. Scan every `.rs` file the crate's module tree includes (follow `mod` declarations), and decide "test code" only from `#[cfg(test)]` (a module or an item), never from a file name or a directory name (`xtask/src/scan.rs:345-357` skips `tests.rs`, `*_test.rs`, `*_tests.rs` and the directories `tests`, `benches`, `examples`). Mutations: `use std::process::Command as Cmd` in `runtime`; a `mod webhook_tests;` without `cfg(test)` in `github`.
5. **Adapters.** The external-crate check also applies to adapter crates (`external_allow` is today read but not enforced for them: `topology.rs:307`).
6. **ST-03 one file.** After `ProcessRunner`, the only file that contains `std::process` or `tokio::process` is `crates/sandbox/src/process.rs`; the check says so.
7. **ST-13 constructors.** `TenantScope::new` may be called in `workflow` (`engine`), `storage`, `testkit`, and the `api` and `worker` binaries; `SystemScope::engine` in `workflow` only; `PlatformScope::receiver` in the `api` binary's webhook handler; `ResolvedPrincipal` and `ResolvedRepository` literals in `storage` and `testkit`; `IngestedChange::new` in `sandbox` (workspace module) and `testkit`.
8. **ST-14 metering.** The `workflow` crate does not mention `MeteringOps`.
9. **DEP-09 names.** The scan that forbids `ChangeHost` method names starting with `merge` also forbids `ready` and `undraft`.
10. **F-23.** `Scratch::clippy` removes `CARGO_TARGET_DIR` from the child environment and gives each scratch crate its own target directory.
11. **F-24.** `cargo xtask check-invariants` reads the invariant table from `state-machine.json` and fails when an id appears in no `#[test]` name, doc comment or `// INV-nn` marker under `crates/**/tests` or `src`. INV-01, INV-09 and INV-11 are named by the revision package (engine) and the DBA (database).
12. **F-31.** A fixture where a path or git dependency has the name of an allowed crate must fail `cargo xtask check-architecture` or `cargo deny check sources`; whichever catches it, the test says which.
13. **F-16 support.** `contract_register` is a test in `testkit`, not in `xtask`. The register is described in section 9.

## 13. GitHub: what to implement and what is verified

For `s1-github-adapter`. Sources are the pages named in ADR 0014 "What was checked", read on 2026-10-27.

| Operation | Endpoint | Permission | Status |
|---|---|---|---|
| Fetch an issue | `GET /repos/{owner}/{repo}/issues/{n}` | Issues: read | Not re-read here; the policy already lists it |
| Fetch a comment | `GET /repos/{owner}/{repo}/issues/comments/{id}` | Issues: read and Pull requests: read | VERIFIED |
| Resolve a branch | `GET /repos/{owner}/{repo}/branches/{branch}` | Contents: read | VERIFIED |
| Read the rules of the default branch | `GET /repos/{owner}/{repo}/rules/branches/{branch}` | Metadata: read | VERIFIED; the response has `required_status_checks` with `integration_id` and no bypass actors |
| Open a draft pull request | `POST /repos/{owner}/{repo}/pulls` with `draft: true` | Pull requests: write | VERIFIED that the parameter exists |
| Publish a check | `POST /repos/{owner}/{repo}/check-runs`, then `PATCH` | Checks: write; only an App can | VERIFIED |
| Comment | `POST .../issues/{n}/comments` | Issues: write (pull request comments use the issue endpoint) | Not re-read here |
| Read a pull request | `GET /repos/{owner}/{repo}/pulls/{n}` | Pull requests: read | Not re-read here |
| Verify a webhook | HMAC-SHA256 of the raw body, header `X-Hub-Signature-256` with the prefix `sha256=`, constant-time comparison | none | VERIFIED |
| Tell an issue comment from a pull request comment in the payload | `issue.pull_request` is present for a pull request | none | UNVERIFIED (page read does not describe it; the adapter records a real delivery as a fixture) |
| Mark ready for review | GraphQL `markPullRequestReadyForReview` | Pull requests: write | UNVERIFIED; **not implemented** |
| Read the bypass list | `GET .../rulesets/{id}`, `bypass_actors` | "write access to the ruleset" | UNVERIFIED which App permission; **not used** |
| Read classic branch protection | `GET .../branches/{branch}/protection` | Administration: read | VERIFIED; **not used**, the policy forbids the permission |
| That a status posted with an installation token satisfies a requirement pinned to the App's id | n/a | n/a | UNVERIFIED; **not relied on**. Check runs are used |
| The exact ruleset rule type names `pull_request`, `required_status_checks`, `non_fast_forward`, `deletion` and their parameter names | n/a | n/a | UNVERIFIED. Record one real response from the fixture repository before coding the parser |

The contract test for the real adapter, run only with a test App and a fixture repository (labelled, never part of the default suite): a required check pinned by `integration_id` is not satisfied by a check run of the same name from another App. If it is, decision 7 is reopened.

## 14. Edits to the engine's neighbours that are not Rust in this repository

- `docs/architecture/slice-plan.md` section 7: the sketches are replaced by pointers to this file for every port that changed, and the registry gains four ports (done in this change by `check_work_packages.py --write` and the sketch edit).
- `docs/architecture/crate-dependency-rules.json`: the `ports` description lists all ports; `unicode-normalization` joins the `ports` external allow list (done in this change). `testkit` description lists the new fakes.
- `docs/database/for-the-storage-crate.md`: owned by the DBA, in section 8.

## 15. Questions that need a person

1. Rulesets plus an admin attestation, or `administration: read`? (ADR 0014 d7)
2. Check runs only, and drop `statuses: write`? (d7)
3. The factory never marks a pull request ready; reword NT-MRG-08? (d7)
4. Tighten schema version 1 in place? (d8)
5. FR-023: every finding, or every finding of a non-pass verdict? (d8)
6. Keep the platform tenant for audit events that belong to no tenant? (d2)
7. The specification's "eleven stages": apply the edits in section 11? (F-18)
8. Tag `ports-v1.1-rc1` after the Store, workspace, sandbox and agent parts, so the storage and sandbox adapters can start earlier? (ADR 0014, option 3)

## 16. Additions after v1.1 (pending architect confirmation)

Each entry is additive: no existing method changes, and every implementor was updated in the same
change. Each was found by running the real handlers together, and each waits for the architect.

| Addition | Why | Implementors updated | Status |
|---|---|---|---|
| `JobRepo::tree_of(&self, commit: &CommitSha) -> Result<GitSha, WorkspaceError>` | The delivery stage binds an approval to the head commit and to its tree (ADR 0009), and `DeliverySources::tree_of` could not answer: no port exposed a tree identifier, and only the sandbox crate may start `git`. | `GitJobRepo` in `sandbox` (`git rev-parse <commit>^{tree}` in the job's object store), `FakeJobRepo` in `testkit` (a digest of the files, so the same files give the same tree), `IndexingRepo` in `composition` (forwards), and the three repositories of the workflow stage tests (forward). The workspace contract suite has a check for it (`a_commit_has_a_tree_and_the_tree_follows_the_files`) and the fake has a defect that the check catches. | **Pending architect confirmation.** The name and the return type (`GitSha`) are the smallest that served. A version that returns the tree of the base and head together, or that reads from the code host, was not tried. |
| `IssueSource::label_application(&self, scope, issue, label) -> Result<Option<LabelApplication>, GitHostError>`, with a default body, and the type `LabelApplication { actor: GithubActor, applied_at: Option<Timestamp> }` | AUT-11 (R-15 of the earlier review). A job made by a webhook stores the live issue as revision 1, and the port could say who applied the label and not when, so an author who edited the issue after the requester labelled it had the new words acted on under the requester's name. | `GithubIssueSource` in `github` (the time of the latest `labeled` event; `label_actor` now delegates to it) and `FakeIssueSource` in `testkit` (`seed_label_at`). The contract check `the_label_actor_is_the_person_who_applied_it` covers `label_application` for both. The method has a default (the actor of `label_actor`, with no time), so the test doubles in `workflow` need no change. Intake asks for the application, and before it stores the issue as revision 1 it refuses when the label is not on the issue, when the person who applied it is not on the allowlist by numeric id, or when `Issue::updated_at` is more than 5 seconds after `applied_at`. With no `applied_at` the time check is not made. | **Pending architect confirmation.** The default method is what keeps the change additive; a required method, or a `label_actor` that returns the time itself, was not tried. UNVERIFIED against the real GitHub: that the issue's `updated_at` moves when its body is edited and when a label is applied, to the second, and that every `labeled` event carries `created_at`. A comment on the issue after the label moves `updated_at` too, so the job is refused and the requester applies the label again; GraphQL `lastEditedAt` would name a body edit only, and was not used because the adapter has no GraphQL call. |
| `IssueSource::labels_ever_applied(&self, scope, issue) -> Result<Vec<String>, GitHostError>`, with a default body that answers `Unavailable`; the type `AccountType { User, Bot, Organization, Other }` and a field `actor_type` on `LabelApplication`; the types `LabeledEvent` and `LabelTimeline`, which hold the one rule for reading the events of an issue | Findings DG-1, DG-2 and DG-5 of `docs/reviews/design-gate-security-review.md`. The design gate must see every event of the issue: the latest application of a label may be anywhere in the list, the order of the list was never observed, and an issue that once had a `design:` label stays on the design track. A person's approval must come from a person's account. | `GithubIssueSource` in `github` (reads up to 30 pages of 100 events, and a list still cut then is `Unavailable`; parses strictly) and `FakeIssueSource` in `testkit` (events with an order and pages; `seed_event`, `seed_events_of_no_interest`, `list_events_newest_first`). Both use `LabelTimeline`, so they cannot disagree about what the events mean. A field added to `LabelApplication` and the one new method with a default body keep the other implementors unchanged. | **Pending architect confirmation.** UNVERIFIED against the real GitHub: the order of the events list, the `type` of the actor of every event, and the largest list the API gives. A source that cannot read the whole list answers `Unavailable`. A distinct error for "the list is too long" was not added, because it changes the closed `GitHostError`; an honest approval past 3000 events therefore fails the attempt with no comment to the requester. |
| `NameError::HiddenCharacter`, and the rule `paths::hides_text`, applied by `check_text` (`RepoPath`, `RepoGlob`) and by `BranchName::new` | SBX-2, second half. The sandbox's audit of a checkout refuses a name that hides or reorders text (Unicode category Cf: the bidirectional controls, the zero width characters, the byte order mark; the line and paragraph separators Zl and Zp; the tag block; the fillers that render as nothing), but a `RepoPath` made from any other text, such as a webhook or the output of a model, was not checked, so `gpj.\u{202E}rs` could be a path that reads as `src.jpg`. | The `NameError` set was closed and gains one variant; nothing outside `paths.rs` matches it exhaustively (`spec.rs` names one variant), so no implementor changed. The rule is a copy of the audit's, because `ports` may not depend on `sandbox`. Tests: the unit tests of `paths.rs` (every constructor refuses the list; names in other scripts, with accents or emoji, stay valid) and `sandbox::security_review::sbx_2_repo_path_refuses_names_that_hide_or_reorder_text`, which was ignored and now runs. | **Pending architect confirmation.** The new variant, and whether the audit should call this function instead of keeping its copy, are the architect's. Two legitimate uses are refused with the category: the zero width non-joiner of Persian and the zero width joiner of emoji sequences and some Indic scripts. A person renames such a file. |
| `TurnAttestation` (new trait in `ports::agent`): `async fn turn_summary(&self, token: &JobTokenId) -> Result<TurnSummary, BrokerError>`, with the types `TurnSummary { usage: Usage, answers: u64, last_answer: Option<AnswerEnd>, in_flight: u32 }` and `AnswerEnd { EndTurn, ToolUse, Cut, Failed }` | RR-14 of `docs/reviews/isolation-core-security-rereview.md` (part b). The adapters of the agent tools took the tool's event stream, which is the output pipe of a process chain inside the sandbox, as the only proof that a run completed. A process inside the sandbox can sometimes write to a pipe it inherited, so the stream cannot be the only authority. The model broker sits outside the sandbox and sees every request and answer of the job. An adapter takes a summary before it starts the tool (the baseline) and another after it ended, and accepts a run the stream calls completed only when, between the two, the broker read an answer, no request is in flight, the latest answer ended the turn, and the stream claims no more turns and tokens than the broker metered (a stated tolerance of 10 percent and 256 tokens, and 2 messages). A failure is `OutputMissing` with the fixed reason `unattested_completion` or `claim_exceeds_ledger` in the transcript note. | `BrokerCore` in `egress` (the answer end is read from the provider's answer, JSON or event stream, for both providers; a count-tokens call and a refused request never change it), `FakeModelBroker` in `testkit` (`meter` records an ending turn, `meter_answer` scripts another end), `ScriptedAttestation` in the runtime tests. `ClaudeCodeRuntime::new` and `CodexRuntime::new` take the attestation as a third argument, so there is no runtime without one: the composition root passes the same `Arc<BrokerCore>` that is the engine's `ModelBroker`. A new trait, not a method on `ModelBroker`, so that the other implementors of `ModelBroker` (the redacting wrapper in `composition`, the test doubles) need no change. | **Pending architect confirmation.** What it does not cover: the content of the final text (the broker does not bind a digest of it, because the tools reformat it); a tool that makes side requests the stream does not name (the ledger may exceed the claim, never the reverse). A method on `ModelBroker` with a default body, or a digest of the last answer in `TurnSummary`, were not tried. |

### 16.1 Two port changes the routing policy needs (SF-17): made, pending architect confirmation

The routing policy (`policies/model_routing.yaml`) says two things that nothing in the ports could
carry. Both are additive, both were made in the live-adapters work package, every implementor and
every struct literal was updated in the same change, and both are **pending architect confirmation**.

| Addition | Why | Implementors updated | Status |
|---|---|---|---|
| `author: Option<ModelSelection>` on `RoutingNeed`: the model that made the work a reviewing stage judges. `PolicyModelRouter::route` then drops the candidates that the independence rule refuses, and answers `RoutingError::NoRoute` when candidates exist and none is independent (the engine fails the stage closed, the policy's "wait for a person"). `route_after_author` keeps the finer answer (`NoIndependentModel`). | The reviewing stages list the model of the other family first, but if that runtime fails and is excluded, the plain route falls back to the first family, and the reviewer is then the author's kind of model. | Every `RoutingNeed` literal gets `author: None` (the nine stage handlers and their in-stage routes, the testkit router, the workflow and runtime test support, the composition tests). **The REVIEW stage sets it**: the implementation stage records the runtime and model that built each task in its stored manifest (`implementation-evidence`, `builder_model`), and both the engine (when it routes the token, in `prepare`) and the review handler (when it routes the reviewer inside `execute`) read the author from that stored document through `builder_selection`, so a second worker that runs the review learns it from the store and not from memory. Tests: `the_reviewer_is_routed_against_the_model_the_stored_manifest_names` (workflow), `a_need_that_names_the_author_is_routed_to_an_independent_reviewer` and `a_reviewer_of_the_builders_family_gets_no_request_through_the_real_broker` (composition, real policy and real broker core). | **Pending architect confirmation.** Not covered: `DOCUMENTATION_REVIEW` (the documenting stage stores no model; the order of the routes and `verify_read_only_tools` still carry independence there, and the specification reviewer runs inside the specification stage), and a task finished by an earlier attempt (it names no model, so the author is the latest task this attempt built, and unknown when none was). |
| `per_request: Option<RequestCaps>` on `JobTokenRequest` (`RequestCaps { max_input_tokens, max_output_tokens }`), enforced per token by `BrokerCore`: a request is held to the smaller of the broker's cap and the token's. | The broker held one set of per-request caps for all tokens, so `broker_caps` took the largest cap of any role, and the smaller cap of a role was not enforced. | Every `JobTokenRequest` literal gets `per_request: None`. `PolicyBroker` sets it from the role of the stage (`routing::request_caps`: the larger of the caps when two roles share a stage, such as the specification writer and its reviewer) and keeps a smaller cap the request already carries; `routing::token_request` sets it too. Tests: `a_request_over_the_cap_of_the_role_is_clamped_to_it` and its two neighbours (egress, through the real listener), and the three `policy_wiring` tests that read the cap of a token of the intake, builder and specification roles from the real broker. | **Pending architect confirmation.** The cap clamps `max_tokens` only; the worst case charged for an answer that cannot be read still uses the broker's cap (a smaller role cap would make it smaller, never larger). |

Two limits of what was built, because both come from the same gap: the spend of a job is read from
the broker of the process, which keeps its ledger in memory, so a restarted worker counts a job's
spend again from zero and a second worker does not see the first one's. The ceiling of each token
and of each stage still hold, so the error is bounded by one stage per restart. A spend recorded in
the store per job would close it; that is a new store method and was not tried.
