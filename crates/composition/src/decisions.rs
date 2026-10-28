//! The work a worker does before each claim: admit the jobs that were received, and apply the
//! decisions that people asked for.
//!
//! # Why the worker does this
//!
//! The API checks the caller and records what it was asked: a job as `RECEIVED`, and a decision as
//! the audit record `decision.requested`. It holds no sandbox, no runtime and no GitHub
//! credential, so it cannot admit a job or move a stage run. The engine runs in the worker. This
//! module is the step in the worker loop ([`BeforeClaim`]) that reads those two kinds of record
//! and gives them to the engine.
//!
//! # Admission
//!
//! For each tenant the worker serves, [`ClaimWork`] lists the `RECEIVED` jobs and calls
//! `Engine::admit_job`. The engine decides again, from the protected configuration, whether the job
//! runs: a job that is already admitted is refused as illegal and nothing happens twice.
//!
//! # Decisions
//!
//! A decision is applied **exactly once**, and its record says what became of it:
//!
//! * Each `decision.requested` record has an id. That id is the command id the engine uses
//!   (`Actor::command`, `ApprovalCommand::id`), and the engine answers a repeat of a command with
//!   `Duplicate` and changes nothing.
//! * When the decision is dealt with, the worker writes a **marker** under an id derived from the
//!   decision's: `decision.applied` or `decision.rejected`, with the job, so the timeline of the
//!   API shows it. A decision with a marker is never read again.
//! * A worker that stops between the engine's commit and the marker finds, on its next pass, a
//!   `decision.requested` with no marker. It asks the engine whether it already applied that
//!   command (`Engine::command_applied`), and if so writes the marker and does nothing else. So a
//!   stop in that window neither applies the decision twice nor loses it.
//!
//! # Authority
//!
//! The API checked the designation before it recorded the request. That is not enough: the person
//! may have left the allowlist since, and a record is only a record. Before it applies anything the
//! worker reads the allowlist file **as it is now** and looks the sender up by the **numeric
//! GitHub id** of the principal behind the record ([`DecisionAuthority`]). The engine and the
//! approval service check again in their own way (`Authority::roles`, `judge`), so a decision needs
//! three agreeing answers. A refusal is a `decision.rejected` marker with a reason that does not
//! say which test failed.
//!
//! # What it keeps in memory
//!
//! A cursor into the tenant's audit log and the decisions seen so far that have no marker. A
//! worker that starts reads the log again from the beginning, so nothing depends on this memory.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{
    AuditEventId, CausationId, CorrelationId, JobId, PrincipalId, StageRunId, TenantId,
};
use factory_domain::policy::approval::ApprovalPolicy;
use factory_domain::policy::authority::ActorKind;
use factory_domain::policy::decision::Designation;
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, Status as _};
use factory_domain::values::{GitSha, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::Clock;
use factory_ports::githost::ActorLogin;
use factory_ports::store::{
    ApprovalChannel, AuditAction, AuditActor, AuditDecision, AuditFilter, ConstraintRule,
    JobFilter, NewAuditEvent, PrincipalKind, Store, StoreError,
};
use factory_workflow::commands::{Actor, JobCommand};
use factory_workflow::engine::{Engine, EngineError};
use factory_workflow::stages::approval::{ApprovalCommand, ApprovalService, Sender};
use factory_workflow::stages::approval::{
    ApprovalSources, Outcome, ServiceError, Verb, VerbParse, parse_verb,
};

use crate::commands::{CommandContext, ParsedDecision};
use crate::hooks::BeforeClaim;
use crate::seams::{FileAllowlist, designation};

/// The audit action of a request for a decision (written by the API).
pub const REQUESTED: &str = "decision.requested";
/// The audit action of a decision that was applied (written here).
pub const APPLIED: &str = "decision.applied";
/// The audit action of a decision that was refused (written here).
pub const REJECTED: &str = "decision.rejected";

/// The longest wait for a decision that keeps failing for a reason that may pass: this many passes
/// of the loop. Then it is rejected with a reason, and the person may ask again.
pub const MAX_TRIES: u32 = 20;

/// How many received jobs one pass admits, so a long queue never holds the claim back.
const ADMIT_PER_PASS: u32 = 25;

/// The audit records read in one page.
const PAGE: u32 = 500;

// ------------------------------------------------------------------------------------------
// The record the API writes
// ------------------------------------------------------------------------------------------

/// What a `decision.requested` record says, as the subject of the audit record. The API writes it
/// and the worker reads it, so the one grammar is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionFields {
    /// The verb, one of the six words of the grammar.
    pub verb: Verb,
    /// The job.
    pub job: JobId,
    /// The stage run, for approve, reject and rework.
    pub stage_run: Option<StageRunId>,
    /// The head the person says they saw.
    pub head: Option<String>,
    /// The evidence digest the person says they read.
    pub evidence: Option<String>,
    /// The stage to send rework to.
    pub target: Option<String>,
}

impl DecisionFields {
    /// The subject text of the audit record.
    #[must_use]
    pub fn subject(&self) -> String {
        format!(
            "verb={} job={} run={} head={} evidence={} target={}",
            self.verb.as_str(),
            self.job.as_text(),
            self.stage_run
                .map_or_else(|| "none".to_owned(), |run| run.as_text()),
            self.head.as_deref().unwrap_or("none"),
            self.evidence.as_deref().unwrap_or("none"),
            self.target.as_deref().unwrap_or("none"),
        )
    }

    /// Reads a subject back and accepts it only if it is exactly the text [`Self::subject`] writes
    /// for what it says: one space between the six `key=value` words, in the order of the grammar,
    /// each key once, `none` spelled `none`. A subject that reads the same but is not byte for byte
    /// the canonical text was not written by the API (R-2). `None` for anything else.
    #[must_use]
    pub fn parse_canonical(subject: &str) -> Option<Self> {
        let fields = Self::parse(subject)?;
        (fields.subject() == subject).then_some(fields)
    }

    /// Reads a subject back, leniently: any order, any white space, a repeated key taking the last
    /// value. `None` when it is not one this module wrote. The hook uses [`Self::parse_canonical`].
    #[must_use]
    pub fn parse(subject: &str) -> Option<Self> {
        let mut verb = None;
        let mut job = None;
        let mut run = None;
        let mut head = None;
        let mut evidence = None;
        let mut target = None;
        for word in subject.split_whitespace() {
            let (key, value) = word.split_once('=')?;
            let some = (value != "none").then(|| value.to_owned());
            match key {
                "verb" => {
                    verb = match parse_verb(value) {
                        VerbParse::Known(found) => Some(found),
                        VerbParse::Unknown => return None,
                    }
                }
                "job" => job = JobId::parse(value).ok(),
                "run" => run = some.and_then(|text| StageRunId::parse(&text).ok()),
                "head" => head = some,
                "evidence" => evidence = some,
                "target" => target = some,
                _ => return None,
            }
        }
        Some(Self {
            verb: verb?,
            job: job?,
            stage_run: run,
            head,
            evidence,
            target,
        })
    }
}

/// The reason text the API writes, with its prefix.
const REQUEST_PREFIX: &str = "requested: ";

/// A request for a decision that has no marker yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The id of the request: the command id, and the key of the marker.
    pub id: AuditEventId,
    /// Its place in the tenant's audit log.
    pub sequence: u64,
    /// The principal behind the token that asked.
    pub principal: PrincipalId,
    /// What was asked.
    pub fields: DecisionFields,
    /// The reason the person gave.
    pub reason: String,
    /// When the database wrote the request.
    pub requested_at: Timestamp,
    /// How many passes failed for a reason that may pass.
    pub failures: u32,
    /// The numeric GitHub id of the person, once the hook has read it from the principal. The
    /// marker records it (R-13).
    pub actor_github_id: Option<u64>,
    /// The version of the allowlist the decision was checked against, once the hook has read it.
    pub allowlist_version: Option<String>,
}

impl Pending {
    fn command(&self) -> CausationId {
        CausationId::from_uuid(self.id.as_uuid())
    }
}

/// Why a decision was rejected: a fixed sentence for the person and a fixed code for counting and
/// for the audit record (R-13). Nothing from the request is ever part of either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Tried for `MAX_TRIES` passes and kept failing for a reason that may pass.
    GaveUp,
    /// The job is not in the tenant.
    NoJob,
    /// The record is not a request this module understands.
    Malformed,
    /// The person is not a current user of the tenant.
    NotCurrentUser,
    /// The request is older than the approval window.
    Expired,
    /// The job has ended.
    JobEnded,
    /// The person may not take this decision, now, on this repository.
    NotAuthorized,
    /// The job or stage run is not in a state the decision applies to.
    WrongState,
    /// The decision names no stage run.
    NoStageRun,
    /// The decision lacks a part it needs.
    Incomplete,
    /// The pull request moved after the decision was asked for.
    NewCommit,
    /// The base branch moved.
    BaseMoved,
    /// What the person saw is not what the pull request holds.
    StaleBinding,
    /// The evidence changed.
    EvidenceMoved,
    /// The request for approval expired.
    ApprovalExpired,
    /// The pull request is no longer an open draft.
    NotOpen,
    /// A check is not clear.
    GatesNotClear,
    /// The person already took this decision for this version.
    AlreadyDecided,
    /// Any other refusal of the approval service.
    Refused,
}

impl Reason {
    /// Every reason, so that a sentence can be turned back into its code.
    pub const ALL: [Reason; 19] = [
        Self::GaveUp,
        Self::NoJob,
        Self::Malformed,
        Self::NotCurrentUser,
        Self::Expired,
        Self::JobEnded,
        Self::NotAuthorized,
        Self::WrongState,
        Self::NoStageRun,
        Self::Incomplete,
        Self::NewCommit,
        Self::BaseMoved,
        Self::StaleBinding,
        Self::EvidenceMoved,
        Self::ApprovalExpired,
        Self::NotOpen,
        Self::GatesNotClear,
        Self::AlreadyDecided,
        Self::Refused,
    ];

    /// The sentence the person may read. Authority is never explained.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::GaveUp => "The decision could not be applied after repeated tries. Ask again.",
            Self::NoJob => "The job does not exist.",
            Self::Malformed => "The record is not a request this system understands.",
            Self::NotCurrentUser => "The person who asked is not a current user.",
            Self::Expired => "The request is older than the approval window.",
            Self::JobEnded => "The job has ended.",
            Self::NotAuthorized => "The person may not take this decision now.",
            Self::WrongState => "The job is not in a state this decision applies to.",
            Self::NoStageRun => "The decision names no stage run.",
            Self::Incomplete => "The decision is not complete.",
            Self::NewCommit => "The pull request changed after the decision was asked for.",
            Self::BaseMoved => "The base branch moved after the decision was asked for.",
            Self::StaleBinding => "What the person saw is not what the pull request holds now.",
            Self::EvidenceMoved => "The evidence changed after the decision was asked for.",
            Self::ApprovalExpired => "The request for approval has expired.",
            Self::NotOpen => "The pull request is no longer an open draft.",
            Self::GatesNotClear => "A check is not clear, so the work cannot be approved.",
            Self::AlreadyDecided => "This person already took this decision for this version.",
            Self::Refused => "The decision was refused.",
        }
    }

    /// The code for the audit record and for counting outcomes.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GaveUp => "gave_up",
            Self::NoJob => "no_job",
            Self::Malformed => "malformed",
            Self::NotCurrentUser => "not_current_user",
            Self::Expired => "expired",
            Self::JobEnded => "job_ended",
            Self::NotAuthorized => "not_authorized",
            Self::WrongState => "wrong_state",
            Self::NoStageRun => "no_stage_run",
            Self::Incomplete => "incomplete",
            Self::NewCommit => "new_commit",
            Self::BaseMoved => "base_moved",
            Self::StaleBinding => "stale_binding",
            Self::EvidenceMoved => "evidence_moved",
            Self::ApprovalExpired => "approval_expired",
            Self::NotOpen => "not_open",
            Self::GatesNotClear => "gates_not_clear",
            Self::AlreadyDecided => "already_decided",
            Self::Refused => "refused",
        }
    }

    /// The code of a sentence this module wrote, or `other`.
    #[must_use]
    pub fn code_of(text: &str) -> &'static str {
        Self::ALL
            .iter()
            .find(|reason| reason.text() == text)
            .map_or("other", |reason| reason.code())
    }
}

impl From<Reason> for Marked {
    fn from(reason: Reason) -> Self {
        Self::Rejected(reason.text())
    }
}

/// What became of a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Marked {
    /// The engine applied it, now or before.
    Applied(String),
    /// It was refused, with a reason that does not say which test failed.
    Rejected(&'static str),
}

// ------------------------------------------------------------------------------------------
// The collaborators, as traits so that a test can break each one
// ------------------------------------------------------------------------------------------

/// Whether a person may take a decision, read now and by numeric id.
#[async_trait(?Send)]
pub trait DecisionAuthority: Send + Sync {
    /// True when the person with this GitHub id holds, for the tenant and now, a designation the
    /// policy names for the verb, on `repository` (`owner/name`): an allowlist entry narrowed to
    /// other repositories grants nothing here (API-1).
    ///
    /// # Errors
    /// [`Unreadable`] when the allowlist cannot be read. The decision then waits.
    async fn permits(
        &self,
        tenant: TenantId,
        github_user_id: u64,
        verb: Verb,
        repository: &str,
    ) -> Result<bool, Unreadable>;

    /// The version (a hash) of the allowlist the next answer will be read from, for the marker
    /// (R-13). `None` when the authority has none to give.
    fn version(&self) -> Option<String> {
        None
    }
}

/// A source of facts could not answer. Nothing was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a source of facts could not answer")]
pub struct Unreadable;

/// The real [`DecisionAuthority`]: the allowlist file, as it is now, and the action table of
/// `policies/approval.yaml`, the table the API reads for the same check.
pub struct AllowlistAuthority {
    allowlist: Arc<FileAllowlist>,
    approval: Arc<ApprovalPolicy>,
    clock: Arc<dyn Clock>,
}

impl AllowlistAuthority {
    /// An authority over the allowlist, the action table and the clock.
    #[must_use]
    pub fn new(
        allowlist: Arc<FileAllowlist>,
        approval: Arc<ApprovalPolicy>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            allowlist,
            approval,
            clock,
        }
    }

    /// The designations the table names for a verb. Empty when the table has no row, which refuses.
    fn needed(&self, verb: Verb) -> Vec<Designation> {
        self.approval
            .actions
            .iter()
            .find(|row| row.id == verb.action())
            .and_then(|row| row.approver_roles.as_ref())
            .map(|names| names.iter().filter_map(|name| designation(name)).collect())
            .unwrap_or_default()
    }
}

#[async_trait(?Send)]
impl DecisionAuthority for AllowlistAuthority {
    async fn permits(
        &self,
        tenant: TenantId,
        github_user_id: u64,
        verb: Verb,
        repository: &str,
    ) -> Result<bool, Unreadable> {
        let needed = self.needed(verb);
        let held = self
            .allowlist
            .designations_on(tenant, github_user_id, Some(repository), self.clock.now())
            .map_err(|_| Unreadable)?;
        Ok(held.iter().any(|designation| needed.contains(designation)))
    }

    fn version(&self) -> Option<String> {
        self.allowlist
            .entries()
            .ok()
            .map(|(version, _)| version.hex().to_owned())
    }
}

/// Applies an approval, rejection or rework. The real one is the approval service, which judges
/// the decision against the pull request as it is now and moves the stage run.
#[async_trait(?Send)]
pub trait ApprovalSubmitter: Send + Sync {
    /// Judges and applies `command`.
    ///
    /// # Errors
    /// [`ServiceError`].
    async fn submit(&self, command: ApprovalCommand) -> Result<Outcome, ServiceError>;
}

#[async_trait(?Send)]
impl ApprovalSubmitter for ApprovalService {
    async fn submit(&self, command: ApprovalCommand) -> Result<Outcome, ServiceError> {
        ApprovalService::submit(self, command).await
    }
}

/// Records what became of a decision.
#[async_trait(?Send)]
pub trait DecisionMarkers: Send + Sync {
    /// Writes the marker of `decision`. Writing it twice is not an error.
    ///
    /// # Errors
    /// [`Unreadable`] when it could not be written. The decision is read again on the next pass.
    async fn mark(
        &self,
        tenant: TenantId,
        decision: &Pending,
        marked: &Marked,
    ) -> Result<(), Unreadable>;

    /// Writes the marker of a `decision.requested` record that is not a request this module
    /// understands (R-2, R-12): it is rejected with a marker, so that it stops being a candidate.
    /// The marker names the record's id and nothing from the record.
    ///
    /// # Errors
    /// [`Unreadable`] when it could not be written. The record is looked at again on the next pass.
    async fn mark_malformed(&self, _tenant: TenantId, _id: AuditEventId) -> Result<(), Unreadable> {
        Ok(())
    }
}

/// The real [`DecisionMarkers`]: an audit record in the tenant, under an id derived from the
/// decision's, with the job so the timeline of the API shows it.
pub struct AuditMarkers {
    store: Arc<dyn Store>,
    policy_hash: Sha256Digest,
}

impl AuditMarkers {
    /// Markers written to `store`, naming the policy in force.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, policy_hash: Sha256Digest) -> Self {
        Self { store, policy_hash }
    }
}

/// The id of the marker of a decision: derived, so that a second write finds the first.
fn marker_id(decision: AuditEventId) -> AuditEventId {
    let digest = Sha256Digest::of(format!("decision-marker\n{}", decision.as_uuid()).as_bytes());
    let number = u128::from_str_radix(&digest.hex()[..32], 16).unwrap_or(0);
    AuditEventId::from_uuid(uuid::Builder::from_random_bytes(number.to_be_bytes()).into_uuid())
}

/// The code of an outcome, for the marker: `applied` for any application, the code of the reason for
/// a rejection.
fn outcome_code(marked: &Marked) -> &'static str {
    match marked {
        Marked::Applied(_) => "applied",
        Marked::Rejected(text) => Reason::code_of(text),
    }
}

impl AuditMarkers {
    async fn write(
        &self,
        tenant: TenantId,
        event: impl FnOnce(Option<(JobId, Option<StageRunId>, CorrelationId)>) -> Option<NewAuditEvent>,
        job: Option<JobId>,
        stage_run: Option<StageRunId>,
        fallback_correlation: CorrelationId,
    ) -> Result<(), Unreadable> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        // The job's own correlation id, so every record of the job shares it. A decision for a
        // job that does not exist is recorded without a job.
        let found = match job {
            Some(job) => match tx.get_job(job).await {
                Ok(stored) => Some((job, stage_run, stored.value.correlation_id)),
                Err(_) => None,
            },
            None => None,
        };
        let _ = fallback_correlation;
        let Some(event) = event(found) else {
            let _ = tx.rollback().await;
            return Err(Unreadable);
        };
        match tx.record_audit(event).await {
            // A marker that exists with other words is a marker: the decision is dealt with.
            Ok(_) | Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {}
            Err(_) => {
                let _ = tx.rollback().await;
                return Err(Unreadable);
            }
        }
        tx.commit().await.map_err(|_| Unreadable)
    }
}

#[async_trait(?Send)]
impl DecisionMarkers for AuditMarkers {
    async fn mark(
        &self,
        tenant: TenantId,
        decision: &Pending,
        marked: &Marked,
    ) -> Result<(), Unreadable> {
        let (action, outcome, reason) = match marked {
            Marked::Applied(text) => (APPLIED, AuditDecision::Allow, text.clone()),
            Marked::Rejected(text) => (REJECTED, AuditDecision::Deny, (*text).to_owned()),
        };
        // The subject has the request's id first, then fixed words and numbers only: the code of
        // the outcome, the numeric id of the person and the version of the allowlist (R-13).
        let subject = format!(
            "decision={} verb={} job={} code={} actor={} allowlist={}",
            decision.id.as_uuid().hyphenated(),
            decision.fields.verb.as_str(),
            decision.fields.job.as_text(),
            outcome_code(marked),
            decision
                .actor_github_id
                .map_or_else(|| "none".to_owned(), |id| id.to_string()),
            decision
                .allowlist_version
                .as_deref()
                .map_or("none", |version| version.get(..16).unwrap_or(version)),
        );
        let id = marker_id(decision.id);
        let policy_hash = self.policy_hash.clone();
        let actor = AuditActor::System(Slug::parse("worker.decisions").map_err(|_| Unreadable)?);
        let action = AuditAction::new(action).map_err(|_| Unreadable)?;
        let fallback = CorrelationId::from_uuid(decision.id.as_uuid());
        self.write(
            tenant,
            move |found| {
                let (job, run, correlation) = match found {
                    Some((job, run, correlation)) => (Some(job), run, correlation),
                    None => (None, None, fallback),
                };
                Some(NewAuditEvent {
                    id,
                    actor,
                    action,
                    subject,
                    decision: outcome,
                    reason,
                    policy_hash,
                    job,
                    stage_run: run,
                    correlation_id: correlation,
                })
            },
            Some(decision.fields.job),
            decision.fields.stage_run,
            fallback,
        )
        .await
    }

    async fn mark_malformed(&self, tenant: TenantId, id: AuditEventId) -> Result<(), Unreadable> {
        let marker = marker_id(id);
        let policy_hash = self.policy_hash.clone();
        let actor = AuditActor::System(Slug::parse("worker.decisions").map_err(|_| Unreadable)?);
        let action = AuditAction::new(REJECTED).map_err(|_| Unreadable)?;
        let subject = format!(
            "decision={} code={} actor=none allowlist=none",
            id.as_uuid().hyphenated(),
            Reason::Malformed.code()
        );
        let correlation = CorrelationId::from_uuid(id.as_uuid());
        self.write(
            tenant,
            move |_| {
                Some(NewAuditEvent {
                    id: marker,
                    actor,
                    action,
                    subject,
                    decision: AuditDecision::Deny,
                    reason: Reason::Malformed.text().to_owned(),
                    policy_hash,
                    job: None,
                    stage_run: None,
                    correlation_id: correlation,
                })
            },
            None,
            None,
            correlation,
        )
        .await
    }
}

// ------------------------------------------------------------------------------------------
// The hook
// ------------------------------------------------------------------------------------------

/// What one pass of one decision came to.
enum Verdict {
    /// Dealt with: write the marker.
    Done(Marked),
    /// Could not be decided now; try again on the next pass.
    Later,
}

/// The audit log of one tenant as far as this worker has read it.
#[derive(Default)]
struct Scan {
    /// The last sequence read.
    cursor: u64,
    /// Requests with no marker, by sequence.
    pending: BTreeMap<u64, Pending>,
    /// `decision.requested` records that are not requests this module understands and have no
    /// marker yet, by sequence (R-2, R-12).
    malformed: BTreeMap<u64, AuditEventId>,
}

/// The most decisions (and malformed records) one pass deals with for one tenant, unless the hook is
/// built with another number. Bounded work per pass (R-12): a long queue never holds the claim back.
pub const DECISIONS_PER_PASS: usize = 50;

/// The most pages of the audit log one pass reads for one tenant. The cursor keeps its place, so
/// the next pass goes on.
const PAGES_PER_PASS: usize = 20;

/// Admits the received jobs and applies the requested decisions of the tenants this worker serves.
pub struct ClaimWork {
    engine: Arc<Engine>,
    store: Arc<dyn Store>,
    tenants: Vec<TenantId>,
    submitter: Arc<dyn ApprovalSubmitter>,
    approvals: Arc<dyn ApprovalSources>,
    authority: Arc<dyn DecisionAuthority>,
    markers: Arc<dyn DecisionMarkers>,
    clock: Arc<dyn Clock>,
    max_age: Duration,
    per_pass: usize,
    scans: Mutex<BTreeMap<TenantId, Scan>>,
}

/// What [`ClaimWork`] is built from.
pub struct ClaimWorkDeps {
    /// The engine the worker loop runs.
    pub engine: Arc<Engine>,
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The tenants the worker serves.
    pub tenants: Vec<TenantId>,
    /// Applies approvals, rejections and rework.
    pub submitter: Arc<dyn ApprovalSubmitter>,
    /// Reads the stored approval request.
    pub approvals: Arc<dyn ApprovalSources>,
    /// Checks the allowlist now.
    pub authority: Arc<dyn DecisionAuthority>,
    /// Records what became of a decision.
    pub markers: Arc<dyn DecisionMarkers>,
    /// The time now, to tell a request that has waited too long.
    pub clock: Arc<dyn Clock>,
    /// How long a request stays good: the approval window of `policies/approval.yaml`
    /// (`approval_binding.expires_after_hours`, 72 hours). An older request is rejected as expired,
    /// never applied late (R-11).
    pub max_age: Duration,
    /// The most decisions one pass deals with for one tenant. [`DECISIONS_PER_PASS`] is the usual.
    pub per_pass: usize,
}

impl ClaimWork {
    /// The hook, over its collaborators.
    #[must_use]
    pub fn new(deps: ClaimWorkDeps) -> Self {
        Self {
            engine: deps.engine,
            store: deps.store,
            tenants: deps.tenants,
            submitter: deps.submitter,
            approvals: deps.approvals,
            authority: deps.authority,
            markers: deps.markers,
            clock: deps.clock,
            max_age: deps.max_age,
            per_pass: deps.per_pass.max(1),
            scans: Mutex::new(BTreeMap::new()),
        }
    }

    /// One pass for one tenant: admit, then decide. Public so a test can run a pass without a loop.
    pub async fn pass(&self, tenant: TenantId) {
        self.admit_received(tenant).await;
        self.apply_decisions(tenant).await;
    }

    // ---- admission -------------------------------------------------------------------------

    async fn admit_received(&self, tenant: TenantId) {
        let jobs = {
            let Ok(mut tx) = self.store.begin(TenantScope::new(tenant)).await else {
                tracing::warn!("received jobs cannot be listed: the store is unavailable");
                return;
            };
            let listed = tx
                .list_jobs(
                    JobFilter {
                        statuses: vec![JobStatus::Received],
                        repository: None,
                    },
                    None,
                    ADMIT_PER_PASS,
                )
                .await;
            let _ = tx.rollback().await;
            match listed {
                Ok(page) => page.rows,
                Err(error) => {
                    tracing::warn!(%error, "received jobs cannot be listed");
                    return;
                }
            }
        };
        for stored in jobs {
            match self.engine.admit_job(tenant, stored.value.id).await {
                Ok(admission) => tracing::info!(
                    job = %stored.value.id,
                    admitted = matches!(admission, factory_workflow::engine::Admission::Admitted { .. }),
                    "a received job was decided"
                ),
                // Another worker decided first, or the job moved: nothing to do.
                Err(EngineError::Illegal(_) | EngineError::Conflict | EngineError::NotFound) => {}
                Err(error @ EngineError::NoHandler(_)) => tracing::error!(
                    job = %stored.value.id,
                    %error,
                    "a received job cannot be admitted until its stage has a handler"
                ),
                Err(error) => tracing::warn!(
                    job = %stored.value.id,
                    %error,
                    "a received job was not admitted this pass"
                ),
            }
        }
    }

    // ---- decisions -------------------------------------------------------------------------

    async fn apply_decisions(&self, tenant: TenantId) {
        if !self.read_new_records(tenant).await {
            return;
        }
        // Bounded work (R-12): malformed records first, they are cheap, then requests in the order
        // of the tenant's audit sequence (R-10), no more than `per_pass` in all.
        let (malformed, pending): (Vec<(u64, AuditEventId)>, Vec<Pending>) = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or_else(
                || (Vec::new(), Vec::new()),
                |scan| {
                    let malformed: Vec<(u64, AuditEventId)> = scan
                        .malformed
                        .iter()
                        .take(self.per_pass)
                        .map(|(sequence, id)| (*sequence, *id))
                        .collect();
                    let room = self.per_pass.saturating_sub(malformed.len());
                    (
                        malformed,
                        scan.pending.values().take(room).cloned().collect(),
                    )
                },
            )
        };
        for (sequence, id) in malformed {
            match self.markers.mark_malformed(tenant, id).await {
                Ok(()) => {
                    tracing::info!(code = Reason::Malformed.code(), "a request was rejected");
                    let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(scan) = scans.get_mut(&tenant) {
                        scan.malformed.remove(&sequence);
                    }
                }
                Err(Unreadable) => tracing::warn!(
                    "the marker of a malformed request could not be written; it is tried again next pass"
                ),
            }
        }
        for decision in pending {
            let (verdict, decision) = self.decide(tenant, decision).await;
            let marked = match verdict {
                Verdict::Done(marked) => marked,
                Verdict::Later if decision.failures + 1 >= MAX_TRIES => {
                    Marked::Rejected(Reason::GaveUp.text())
                }
                Verdict::Later => {
                    self.note_failure(tenant, decision.sequence);
                    continue;
                }
            };
            match self.markers.mark(tenant, &decision, &marked).await {
                Ok(()) => {
                    // Counted by code, and nothing from the request is in the line (R-13, R-17).
                    tracing::info!(code = outcome_code(&marked), "a decision was dealt with");
                    self.forget(tenant, decision.sequence);
                }
                Err(Unreadable) => tracing::warn!(
                    decision = %decision.id,
                    "the marker could not be written; the decision is checked again next pass"
                ),
            }
        }
    }

    /// Reads the audit records after the cursor into the scan. False when the log cannot be read.
    async fn read_new_records(&self, tenant: TenantId) -> bool {
        let mut cursor = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or(0, |scan| scan.cursor)
        };
        for _ in 0..PAGES_PER_PASS {
            let page = {
                let Ok(mut tx) = self.store.begin(TenantScope::new(tenant)).await else {
                    return false;
                };
                let read = tx.read_audit(AuditFilter::Tenant, cursor, PAGE).await;
                let _ = tx.rollback().await;
                match read {
                    Ok(page) => page,
                    Err(error) => {
                        tracing::warn!(%error, "the audit log cannot be read");
                        return false;
                    }
                }
            };
            let count = page.len();
            {
                let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
                let scan = scans.entry(tenant).or_default();
                for record in page {
                    cursor = record.sequence;
                    scan.cursor = record.sequence;
                    match record.event.action.as_str() {
                        REQUESTED => match requested_from(&record) {
                            Some(pending) => {
                                scan.pending.insert(record.sequence, pending);
                            }
                            None => {
                                scan.malformed.insert(record.sequence, record.event.id);
                            }
                        },
                        APPLIED | REJECTED => {
                            if let Some(id) = marked_decision(&record.event.subject) {
                                scan.pending.retain(|_, pending| pending.id != id);
                                scan.malformed.retain(|_, malformed| *malformed != id);
                            }
                        }
                        _ => {}
                    }
                }
            }
            if u32::try_from(count).unwrap_or(u32::MAX) < PAGE {
                return true;
            }
        }
        // More pages are waiting; the cursor keeps the place for the next pass.
        true
    }

    fn note_failure(&self, tenant: TenantId, sequence: u64) {
        let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(pending) = scans
            .get_mut(&tenant)
            .and_then(|scan| scan.pending.get_mut(&sequence))
        {
            pending.failures += 1;
        }
    }

    fn forget(&self, tenant: TenantId, sequence: u64) {
        let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(scan) = scans.get_mut(&tenant) {
            scan.pending.remove(&sequence);
        }
    }

    /// Decides one request: refuse it, apply it, or leave it for the next pass. Returns the request
    /// with what the hook learned about it (the person's numeric id, the allowlist version), for the
    /// marker.
    async fn decide(&self, tenant: TenantId, mut decision: Pending) -> (Verdict, Pending) {
        let verdict = self.judge(tenant, &mut decision).await;
        (verdict, decision)
    }

    async fn judge(&self, tenant: TenantId, decision: &mut Pending) -> Verdict {
        let fields = decision.fields.clone();
        let command = decision.command();

        // 1. Was it applied already? A worker that stopped after the engine's commit and before
        // the marker finds the engine's events carrying this command id. It writes the marker and
        // does nothing else. This comes before every check that depends on the world as it is now,
        // because an applied decision has changed the world (a cancelled job is ended) and because
        // a request that waited too long after it was applied is still an applied request.
        match self
            .engine
            .command_applied(tenant, fields.job, command)
            .await
        {
            Ok(true) => {
                return Verdict::Done(Marked::Applied(
                    "The engine had applied this decision already.".to_owned(),
                ));
            }
            Ok(false) => {}
            Err(EngineError::NotFound) => return Verdict::Done(Reason::NoJob.into()),
            Err(_) => return Verdict::Later,
        }

        // 2. Is it still good? A request is for the world as the person saw it. One that has waited
        // longer than the approval window is rejected, never applied late (R-11).
        let expired = decision
            .requested_at
            .checked_add(self.max_age)
            .is_none_or(|end| end <= self.clock.now());
        if expired {
            return Verdict::Done(Reason::Expired.into());
        }

        // 3. Who is asking, and are they still a current user of this tenant?
        decision.allowlist_version = self.authority.version();
        let sender = match self.sender_of(tenant, decision.principal).await {
            Ok(Some(sender)) => sender,
            Ok(None) => return Verdict::Done(Reason::NotCurrentUser.into()),
            Err(Unreadable) => return Verdict::Later,
        };
        decision.actor_github_id = Some(sender.id);

        // 4. Is the job still open to a decision?
        let repository = match self.job_facts(tenant, fields.job).await {
            Ok(Some((status, _))) if status.is_terminal() => {
                return Verdict::Done(Reason::JobEnded.into());
            }
            Ok(Some((_, repository))) => repository,
            Ok(None) => return Verdict::Done(Reason::NoJob.into()),
            Err(Unreadable) => return Verdict::Later,
        };

        // 5. May they, now, on this repository? The allowlist is read at this moment and the sender
        // is found by the numeric id of the principal, never by a login.
        match self
            .authority
            .permits(tenant, sender.id, fields.verb, &repository)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Verdict::Done(Reason::NotAuthorized.into()),
            Err(Unreadable) => return Verdict::Later,
        }

        // 6. Apply it.
        let verdict = match fields.verb {
            Verb::Pause | Verb::Resume | Verb::Cancel => {
                self.control(tenant, decision, command).await
            }
            Verb::Approve | Verb::Reject | Verb::Rework => {
                self.approve_or_reject(tenant, decision, command, sender)
                    .await
            }
        };
        // Two workers can take one request at once. The one that lost the race sees a job that the
        // other already moved and would call the request out of place; it asks again whether the
        // engine has this command, and if so the request was applied (R-9).
        match verdict {
            Verdict::Done(Marked::Rejected(_)) | Verdict::Later => {
                match self
                    .engine
                    .command_applied(tenant, fields.job, command)
                    .await
                {
                    Ok(true) => Verdict::Done(Marked::Applied(
                        "The engine had applied this decision already.".to_owned(),
                    )),
                    _ => verdict,
                }
            }
            applied => applied,
        }
    }

    async fn control(&self, tenant: TenantId, decision: &Pending, command: CausationId) -> Verdict {
        let job_command = match decision.fields.verb {
            Verb::Pause => JobCommand::Pause,
            Verb::Resume => JobCommand::Resume,
            _ => JobCommand::Cancel,
        };
        let actor = Actor {
            tenant,
            principal: decision.principal,
            command,
        };
        match self
            .engine
            .control(&actor, decision.fields.job, job_command)
            .await
        {
            Ok(()) => Verdict::Done(Marked::Applied(format!(
                "The job was {}.",
                match job_command {
                    JobCommand::Pause => "paused",
                    JobCommand::Resume => "resumed",
                    JobCommand::Cancel => "cancelled",
                }
            ))),
            Err(EngineError::Duplicate) => Verdict::Done(Marked::Applied(
                "The engine had applied this decision already.".to_owned(),
            )),
            Err(EngineError::NotAuthorized(_)) => Verdict::Done(Reason::NotAuthorized.into()),
            Err(EngineError::Illegal(_) | EngineError::GuardUnmet(_) | EngineError::Refused(_)) => {
                Verdict::Done(Reason::WrongState.into())
            }
            Err(_) => Verdict::Later,
        }
    }

    async fn approve_or_reject(
        &self,
        tenant: TenantId,
        decision: &Pending,
        command: CausationId,
        sender: Sender,
    ) -> Verdict {
        let fields = &decision.fields;
        let Some(stage_run) = fields.stage_run else {
            return Verdict::Done(Reason::NoStageRun.into());
        };
        let parsed = ParsedDecision {
            verb: fields.verb,
            reason: decision.reason.clone(),
            head: fields
                .head
                .as_deref()
                .and_then(|text| GitSha::parse(text).ok()),
            evidence: fields
                .evidence
                .as_deref()
                .and_then(|text| Sha256Digest::parse(text).ok()),
            target: fields
                .target
                .as_deref()
                .and_then(|text| StageKind::parse(text).ok()),
        };
        // An approval is bound to what the person saw, which is taken from the stored request.
        let request = if fields.verb == Verb::Approve {
            match self.approvals.request(tenant, stage_run).await {
                Ok(request) => Some(request),
                // The request is stored by the approval stage. Before it passes there is nothing
                // to approve; the decision waits, up to `MAX_TRIES` passes.
                Err(_) => return Verdict::Later,
            }
        } else {
            None
        };
        // The engine's guard for an approval wants every open translation warning to have a
        // decision of this person. With none open there is nothing undecided. No path of the API
        // records a decision about a warning yet, so with one open the approval is refused.
        let warnings_decided = request
            .as_ref()
            .is_some_and(|found| found.open_translation_warnings == 0);
        let command = match parsed.into_command(
            CommandContext {
                id: command,
                tenant,
                job: fields.job,
                stage_run,
                sender,
                channel: ApprovalChannel::Dashboard,
                comment: None,
                warnings_decided,
            },
            request.as_ref(),
        ) {
            Ok(command) => command,
            Err(_) => return Verdict::Done(Reason::Incomplete.into()),
        };
        match self.submitter.submit(command).await {
            Ok(Outcome::Applied { .. }) => {
                Verdict::Done(Marked::Applied("The decision was applied.".to_owned()))
            }
            Ok(Outcome::Recorded { still_needed, .. }) => Verdict::Done(Marked::Applied(format!(
                "The approval was recorded; {still_needed} more approver(s) are needed."
            ))),
            Ok(Outcome::Replayed) => Verdict::Done(Marked::Applied(
                "The engine had applied this decision already.".to_owned(),
            )),
            Err(ServiceError::Refused(refusal)) => {
                tracing::info!(
                    decision = %decision.id.as_uuid(),
                    code = refusal.code(),
                    "a decision was refused"
                );
                Verdict::Done(refusal_reason(refusal.code()).into())
            }
            Err(ServiceError::Engine(_)) => Verdict::Done(Reason::WrongState.into()),
            Err(ServiceError::Unavailable) => Verdict::Later,
        }
    }

    // ---- reads -----------------------------------------------------------------------------

    async fn sender_of(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Option<Sender>, Unreadable> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = tx.get_principal(principal).await;
        let _ = tx.rollback().await;
        match found {
            Ok(principal) => Ok(match (principal.kind, principal.disabled_at) {
                (PrincipalKind::Human { github_user_id }, None) => Some(Sender {
                    id: github_user_id,
                    login: principal
                        .login
                        .as_deref()
                        .and_then(|login| ActorLogin::new(login).ok())
                        .or_else(|| ActorLogin::new(&format!("user-{github_user_id}")).ok())
                        .ok_or(Unreadable)?,
                    kind: ActorKind::User,
                }),
                _ => None,
            }),
            Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(Unreadable),
        }
    }

    /// The status of the job and the full name (`owner/name`) of its repository, as they are now.
    async fn job_facts(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<Option<(JobStatus, String)>, Unreadable> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = async {
            let stored = tx.get_job(job).await?;
            let repository = tx.get_repository(stored.value.repository).await?;
            Ok::<_, StoreError>((stored.value.status, repository.value.full_name))
        }
        .await;
        let _ = tx.rollback().await;
        match found {
            Ok(facts) => Ok(Some(facts)),
            Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(Unreadable),
        }
    }
}

#[async_trait(?Send)]
impl BeforeClaim for ClaimWork {
    async fn before_claim(&self) {
        for tenant in &self.tenants {
            self.pass(*tenant).await;
        }
    }
}

/// A request for a decision, read from its audit record. `None` for a record that is not a request
/// this module understands (R-2): the record is rejected with a marker and stops being a candidate.
///
/// The row is untrusted input: any login of the application group can write an audit record with
/// any words in it. It is accepted only if the actor is a human principal, the subject is exactly the
/// canonical text the API writes, and the columns for the job and the stage run say what the subject
/// says. The reason is free text and is never read for structure.
fn requested_from(record: &factory_ports::store::AuditRecord) -> Option<Pending> {
    let AuditActor::Human(principal) = record.event.actor.clone() else {
        return None;
    };
    let fields = DecisionFields::parse_canonical(&record.event.subject)?;
    if record.event.job != Some(fields.job) || record.event.stage_run != fields.stage_run {
        return None;
    }
    let reason = record
        .event
        .reason
        .strip_prefix(REQUEST_PREFIX)
        .unwrap_or(&record.event.reason)
        .to_owned();
    Some(Pending {
        id: record.event.id,
        sequence: record.sequence,
        principal,
        fields,
        reason,
        requested_at: record.created_at,
        failures: 0,
        actor_github_id: None,
        allowlist_version: None,
    })
}

/// The decision a marker belongs to, from its subject.
fn marked_decision(subject: &str) -> Option<AuditEventId> {
    let first = subject.split_whitespace().next()?;
    let id = first.strip_prefix("decision=")?;
    AuditEventId::parse(id).ok()
}

/// The reason for a refusal of the approval service. Authority is never explained.
fn refusal_reason(code: &str) -> Reason {
    match code {
        "not_authorized" | "ineligible_approver" | "not_a_command" => Reason::NotAuthorized,
        "new_commit" => Reason::NewCommit,
        "base_moved" => Reason::BaseMoved,
        "tree_changed" | "stale_binding" | "not_bound" => Reason::StaleBinding,
        "evidence_moved" | "evidence_drift" => Reason::EvidenceMoved,
        "expired" => Reason::ApprovalExpired,
        "not_open" | "not_draft" => Reason::NotOpen,
        "gates_not_clear" | "translation_warnings_undecided" => Reason::GatesNotClear,
        "missing_target" | "missing_reason" => Reason::Incomplete,
        "already_decided" => Reason::AlreadyDecided,
        _ => Reason::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subject_reads_back_as_it_was_written() {
        let fields = DecisionFields {
            verb: Verb::Approve,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x1111)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            head: Some("a".repeat(40)),
            evidence: Some(format!("sha256:{}", "b".repeat(64))),
            target: None,
        };
        assert_eq!(DecisionFields::parse(&fields.subject()), Some(fields));
    }

    #[test]
    fn a_subject_with_an_unknown_verb_or_key_is_not_read() {
        let job = JobId::from_uuid(uuid::Uuid::from_u128(1)).as_text();
        assert_eq!(
            DecisionFields::parse(&format!(
                "verb=merge job={job} run=none head=none evidence=none target=none"
            )),
            None
        );
        assert_eq!(
            DecisionFields::parse(&format!("verb=pause job={job} extra=1")),
            None
        );
        assert_eq!(DecisionFields::parse("verb=pause"), None);
    }

    #[test]
    fn the_marker_id_is_derived_and_differs_from_the_decision() {
        let id = AuditEventId::from_uuid(uuid::Uuid::from_u128(7));
        assert_eq!(marker_id(id), marker_id(id));
        assert_ne!(marker_id(id), id);
        assert_ne!(
            marker_id(id),
            marker_id(AuditEventId::from_uuid(uuid::Uuid::from_u128(8)))
        );
    }

    #[test]
    fn a_marker_names_its_decision() {
        let id = AuditEventId::from_uuid(uuid::Uuid::from_u128(9));
        let subject = format!("decision={} verb=pause job=x", id.as_uuid().hyphenated());
        assert_eq!(marked_decision(&subject), Some(id));
        assert_eq!(marked_decision("verb=pause"), None);
    }

    #[test]
    fn a_refusal_of_authority_is_never_explained() {
        for code in ["not_authorized", "ineligible_approver", "not_a_command"] {
            assert_eq!(
                refusal_reason(code).text(),
                "The person may not take this decision now."
            );
        }
    }
}
