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
//! * When the decision is dealt with, the worker writes a **marker** under an id derived (with the
//!   signing key) from the decision's: `decision.applied` or `decision.rejected`, with the job, so
//!   the timeline of the API shows it. A decision with a **signed** marker is never read again. The
//!   marker carries a word of its own (`mac=`, see [`crate::decision_signing`]); a row with the
//!   action of a marker and no good word is ignored and recorded once as `decision.marker_ignored`,
//!   so a writer who is not the worker cannot end a request by writing one (RR-8).
//! * Records that are not requests this module trusts (malformed, unsigned, forged markers) have a
//!   budget of their own per pass, apart from the signed requests, so a queue of them cannot hold a
//!   signed request back (RR-21). Tenants are visited in a different order each round.
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
//! # The proof that the API wrote the request
//!
//! A row in the audit log is only a row: any login of the API's database group can write one with
//! any words in it. A request carries a keyed word (`mac=`, HMAC-SHA256 over the tenant, the person,
//! the event id, the time and the words of the subject; see [`crate::decision_signing`]) that only
//! the API, which holds the key, can make. Before anything else the hook recomputes the word with
//! each key it holds and compares in constant time. A request with no word, or the wrong one, is
//! rejected with a marker that carries the fixed code `not_signed`, and nothing else about it is
//! read (AUT-12, R-1).
//!
//! # While an attempt runs
//!
//! A pass runs between attempts. A worker runs one attempt at a time, so a cancel that a person
//! records while a stage runs would wait for the stage to end. The loop therefore also asks, at
//! its poll interval while an attempt runs, for the cancel requests of the job it is running
//! ([`WhileRunning::apply_cancels`]). They go through the same checks and get the same marker.
//! Only cancels, and only of that job: everything else still waits for the next pass.
//!
//! # What it keeps in memory
//!
//! A cursor into the tenant's audit log and the decisions seen so far that have no marker. A
//! worker that starts reads the log again from the beginning, so nothing depends on this memory.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{
    AuditEventId, CausationId, CorrelationId, JobId, PrincipalId, StageRunId, TenantId,
};
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::approval::ApprovalPolicy;
use factory_domain::policy::authority::{
    ActionContext, ActionDenialReason, ActionVerdict, Actor as PolicyActor, ActorKind, ChangeFacts,
    RepositoryIdentity,
};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::solo::ConfirmationWord;
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, Status as _};
use factory_domain::values::{GitSha, HumanText, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::clock::Clock;
use factory_ports::githost::ActorLogin;
use factory_ports::store::{
    ApprovalChannel, AuditAction, AuditActor, AuditDecision, AuditFilter, ConstraintRule,
    JobFilter, NewAuditEvent, PrincipalKind, Store, StoreError,
};
use factory_workflow::commands::{
    Actor, Decision as EngineDecision, JobCommand, SoloRequest, Subject,
};
use factory_workflow::engine::{Engine, EngineError};
use factory_workflow::gates::supply_chain::approval::{DecisionScope, RecordedApprovals};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::approval::warnings::all_decided;
use factory_workflow::stages::approval::{ApprovalCommand, ApprovalService, Sender};
use factory_workflow::stages::approval::{
    ApprovalSources, Outcome, ServiceError, Verb, VerbParse, parse_verb,
};
use factory_workflow::stages::specification::SpecDrafts;
use tracing::Instrument as _;

use crate::commands::{CommandContext, ParsedDecision};
use crate::decision_signing::{
    DecisionKeys, MarkerSigning, Signing, SubjectKind, actor_text, read_marker_subject,
    read_subject,
};
use crate::dependency_decisions::DependencyDecisions;
use crate::hooks::{BeforeClaim, WhileRunning};
use crate::intake_rejections::IntakeRejections;
use crate::repository_changes::{ChangeAuthority, RepositoryChanges};
use crate::seams::{FileAllowlist, designation};
use crate::stage_decisions::StageDecisions;
use crate::telemetry::{job_span_of, job_stretch};

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
    /// The verb, one of the seven words of the grammar.
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
    /// For `answer`, the SHA-256 of the answer text (`sha256:` and 64 hex digits). The text itself
    /// is the reason of the record, which the keyed word does not cover; its hash is in the
    /// subject, so the word covers the text too, and the hook applies the text only if it has
    /// this hash.
    pub answer: Option<String>,
    /// For `approve`, the word of the confirmation phrase of the solo mode (ADR 0021): 16
    /// lowercase hex digits, when the person typed a phrase. Written last, so a subject without
    /// it is byte for byte the text it always was.
    pub confirm: Option<String>,
}

/// The value of the subject's `answer=` word for an answer text.
#[must_use]
pub fn answer_digest(text: &str) -> String {
    Sha256Digest::of(text.as_bytes()).as_str().to_owned()
}

impl DecisionFields {
    /// The subject text of the audit record. The six words, and for an answer a seventh,
    /// `answer=`, so that the subject of every other verb is the text it always was.
    #[must_use]
    pub fn subject(&self) -> String {
        let mut subject = format!(
            "verb={} job={} run={} head={} evidence={} target={}",
            self.verb.as_str(),
            self.job.as_text(),
            self.stage_run
                .map_or_else(|| "none".to_owned(), |run| run.as_text()),
            self.head.as_deref().unwrap_or("none"),
            self.evidence.as_deref().unwrap_or("none"),
            self.target.as_deref().unwrap_or("none"),
        );
        if let Some(answer) = &self.answer {
            subject.push_str(" answer=");
            subject.push_str(answer);
        }
        if let Some(confirm) = &self.confirm {
            subject.push_str(" confirm=");
            subject.push_str(confirm);
        }
        subject
    }

    /// Reads a subject back and accepts it only if it is exactly the text [`Self::subject`] writes
    /// for what it says: one space between the `key=value` words, in the order of the grammar,
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
        let mut answer = None;
        let mut confirm = None;
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
                "answer" => answer = Some(value.to_owned()),
                "confirm" => confirm = Some(value.to_owned()),
                _ => return None,
            }
        }
        // A confirmation word is 16 lowercase hex digits, and only an approval carries one.
        if let Some(word) = &confirm
            && (verb != Some(Verb::Approve) || ConfirmationWord::parse(word).is_none())
        {
            return None;
        }
        Some(Self {
            verb: verb?,
            job: job?,
            stage_run: run,
            head,
            evidence,
            target,
            answer,
            confirm,
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
    /// The specification draft is not the one the person approved.
    DraftMoved,
    /// The base branch moved.
    BaseMoved,
    /// The pull request targets another base branch than the one the decision was asked for.
    BaseRetargeted,
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
    /// The record does not carry the word that only the API can make (AUT-12).
    NotSigned,
    /// A decision on a dependency names a package, a version or a checksum that the blocked stage
    /// run does not wait for.
    NotAwaited,
    /// A decision on a dependency matches more than one package the stage run waits for.
    Ambiguous,
    /// The block of a stage run has not been cleared, so the stage run was not let go again.
    NotCleared,
    /// Any other refusal of the approval service.
    Refused,
    /// The solo mode asks for a minimum wait that has not passed, or whose start is not known
    /// (ADR 0021).
    SoloDelay,
    /// The solo mode asks for the confirmation phrase, and the request carries none or another.
    ConfirmationMissing,
    /// The requester asked to approve their own request and the solo mode does not apply.
    IneligibleApprover,
}

impl Reason {
    /// Every reason, so that a sentence can be turned back into its code.
    pub const ALL: [Reason; 28] = [
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
        Self::DraftMoved,
        Self::BaseMoved,
        Self::BaseRetargeted,
        Self::StaleBinding,
        Self::EvidenceMoved,
        Self::ApprovalExpired,
        Self::NotOpen,
        Self::GatesNotClear,
        Self::AlreadyDecided,
        Self::NotSigned,
        Self::NotAwaited,
        Self::Ambiguous,
        Self::NotCleared,
        Self::Refused,
        Self::SoloDelay,
        Self::ConfirmationMissing,
        Self::IneligibleApprover,
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
            Self::DraftMoved => "The specification draft is not the one the person approved.",
            Self::BaseMoved => "The base branch moved after the decision was asked for.",
            Self::BaseRetargeted => {
                "The pull request now targets another branch than the one the decision was asked for."
            }
            Self::StaleBinding => "What the person saw is not what the pull request holds now.",
            Self::EvidenceMoved => "The evidence changed after the decision was asked for.",
            Self::ApprovalExpired => "The request for approval has expired.",
            Self::NotOpen => "The pull request is no longer an open draft.",
            Self::GatesNotClear => "A check is not clear, so the work cannot be approved.",
            Self::AlreadyDecided => "This person already took this decision for this version.",
            Self::NotSigned => "The record was not written by the service that takes decisions.",
            Self::NotAwaited => {
                "The stage run does not wait for a decision on that package or file."
            }
            Self::Ambiguous => {
                "More than one package matches; add the start of the checksum to say which."
            }
            Self::NotCleared => {
                "The block has not been cleared, so the stage run was not let go again."
            }
            Self::Refused => "The decision was refused.",
            Self::SoloDelay => {
                "The solo mode requires a wait before this decision, and it has not passed or its start is not known. Ask again later."
            }
            Self::ConfirmationMissing => {
                "The solo mode needs the confirmation phrase, and this decision does not carry the right one."
            }
            Self::IneligibleApprover => {
                "The requester may not approve their own request, because the solo mode does not apply to it."
            }
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
            Self::DraftMoved => "draft_moved",
            Self::BaseMoved => "base_moved",
            Self::BaseRetargeted => "base_retargeted",
            Self::StaleBinding => "stale_binding",
            Self::EvidenceMoved => "evidence_moved",
            Self::ApprovalExpired => "approval_expired",
            Self::NotOpen => "not_open",
            Self::GatesNotClear => "gates_not_clear",
            Self::AlreadyDecided => "already_decided",
            Self::NotSigned => "not_signed",
            Self::NotAwaited => "not_awaited",
            Self::Ambiguous => "ambiguous_package",
            Self::NotCleared => "not_cleared",
            Self::Refused => "refused",
            Self::SoloDelay => "solo_delay",
            Self::ConfirmationMissing => "confirmation_missing",
            Self::IneligibleApprover => "ineligible_approver",
        }
    }

    /// The reason of a refusal of the solo mode by the engine.
    #[must_use]
    pub const fn of_solo(refusal: factory_workflow::engine::SoloRefusal) -> Self {
        match refusal {
            factory_workflow::engine::SoloRefusal::SoloDelay => Self::SoloDelay,
            factory_workflow::engine::SoloRefusal::ConfirmationMissing => Self::ConfirmationMissing,
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
    /// policy names for the verb, on `repository`: an allowlist entry narrowed to other repositories
    /// grants nothing here (API-1), and an entry that lists GitHub's numeric id of the repository
    /// compares the id and not the name (RR-28).
    ///
    /// # Errors
    /// [`Unreadable`] when the allowlist cannot be read. The decision then waits.
    async fn permits(
        &self,
        tenant: TenantId,
        github_user_id: u64,
        verb: Verb,
        repository: &RepositoryIdentity<'_>,
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
        self.needed_for(verb.action())
    }

    /// The designations the table names for an action. Empty when the table has no row, which refuses.
    fn needed_for(&self, action: &str) -> Vec<Designation> {
        self.approval
            .actions
            .iter()
            .find(|row| row.id == action)
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
        repository: &RepositoryIdentity<'_>,
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

#[async_trait(?Send)]
impl ChangeAuthority for AllowlistAuthority {
    async fn permits(
        &self,
        tenant: TenantId,
        github_user_id: u64,
        action: &str,
        repository: &RepositoryIdentity<'_>,
    ) -> Result<bool, Unreadable> {
        let needed = self.needed_for(action);
        let held = self
            .allowlist
            .designations_on(tenant, github_user_id, Some(repository), self.clock.now())
            .map_err(|_| Unreadable)?;
        Ok(held.iter().any(|designation| needed.contains(designation)))
    }

    async fn constrained_holders(
        &self,
        tenant: TenantId,
        repository: &RepositoryIdentity<'_>,
    ) -> Result<std::collections::BTreeSet<u64>, Unreadable> {
        let mut roles: Vec<String> = Vec::new();
        for action in [
            crate::repository_changes::ATTEST_ACTION,
            crate::repository_changes::ENABLE_ACTION,
        ] {
            if let Some(names) = self
                .approval
                .actions
                .iter()
                .find(|row| row.id == action)
                .and_then(|row| row.approver_roles.as_ref())
            {
                roles.extend(names.iter().cloned());
            }
        }
        self.allowlist
            .holders_of(tenant, &roles, repository, self.clock.now())
            .map_err(|_| Unreadable)
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

    /// Writes the marker of a `decision.requested` record that does not carry the API's word
    /// (AUT-12): a record nobody signed, or one signed with another key. The marker names the
    /// record's id and the fixed code `not_signed`, and nothing from the record. The default is the
    /// marker of a malformed record.
    ///
    /// # Errors
    /// [`Unreadable`] when it could not be written. The record is looked at again on the next pass.
    async fn mark_unsigned(&self, tenant: TenantId, id: AuditEventId) -> Result<(), Unreadable> {
        self.mark_malformed(tenant, id).await
    }

    /// Records, once, that a row which looks like a marker (`decision.applied` or
    /// `decision.rejected`) does not carry the worker's word and was therefore not counted (RR-8).
    /// The record names the row's id and a fixed code, and nothing from the row. It is written under
    /// an id that is derived from the row's id, so a second write finds the first.
    ///
    /// # Errors
    /// [`Unreadable`] when it could not be written. The row is looked at again on the next pass.
    async fn mark_ignored(&self, _tenant: TenantId, _id: AuditEventId) -> Result<(), Unreadable> {
        Ok(())
    }
}

/// The audit action of the record that says a marker was ignored. Nothing reads it back: it is the
/// trail a person reads.
pub const MARKER_IGNORED: &str = "decision.marker_ignored";

/// The real [`DecisionMarkers`]: an audit record in the tenant, under an id derived (with the
/// signing key) from the decision's, with the job so the timeline of the API shows it. Every marker
/// carries the worker's word (RR-8): the hook counts no other.
pub struct AuditMarkers {
    store: Arc<dyn Store>,
    policy_hash: Sha256Digest,
    keys: Arc<DecisionKeys>,
}

impl AuditMarkers {
    /// Markers written to `store`, naming the policy in force and signed with `keys`.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, policy_hash: Sha256Digest, keys: Arc<DecisionKeys>) -> Self {
        Self {
            store,
            policy_hash,
            keys,
        }
    }

    /// The subject of a marker with its word: `base` is `decision=<id>` and the fixed words.
    fn signed(
        &self,
        tenant: TenantId,
        event: AuditEventId,
        action: &str,
        actor: &AuditActor,
        base: &str,
    ) -> String {
        self.keys.signed_marker_subject(&MarkerSigning {
            tenant,
            event,
            action,
            actor: &actor_text(actor),
            subject: base,
        })
    }
}

/// True when `record` is a marker the worker wrote: a `decision.applied` or `decision.rejected` row
/// by a component of the system, whose subject names a request and ends with a good word (RR-8).
/// `None` for a row of another action. `Some(None)` for a row that has the action of a marker and is
/// not one: the hook ignores it. `Some(Some(id))` for the request the marker ends.
pub(crate) fn counted_marker(
    tenant: TenantId,
    record: &factory_ports::store::AuditRecord,
    keys: &DecisionKeys,
) -> Option<Option<AuditEventId>> {
    let action = record.event.action.as_str();
    if action != APPLIED && action != REJECTED {
        return None;
    }
    let counted = (|| {
        if !matches!(record.event.actor, AuditActor::System(_)) {
            return None;
        }
        let subject = read_marker_subject(&record.event.subject)?;
        keys.verify_marker(
            &MarkerSigning {
                tenant,
                event: record.event.id,
                action,
                actor: &actor_text(&record.event.actor),
                subject: subject.base,
            },
            subject.word,
        )
        .then_some(subject.decision)
    })();
    Some(counted)
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
    /// Writes one marker in a transaction of the tenant. `build` is given the job (if it exists in
    /// the tenant), its stage run and the correlation id to use, which is the job's own so that
    /// every record of the job shares it, or `fallback` when there is no job.
    async fn write(
        &self,
        tenant: TenantId,
        job: Option<(JobId, Option<StageRunId>)>,
        fallback: CorrelationId,
        build: impl FnOnce(Option<JobId>, Option<StageRunId>, CorrelationId) -> NewAuditEvent,
    ) -> Result<(), Unreadable> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = match job {
            Some((job, run)) => tx
                .get_job(job)
                .await
                .ok()
                .map(|stored| (job, run, stored.value.correlation_id)),
            None => None,
        };
        let event = match found {
            Some((job, run, correlation)) => build(Some(job), run, correlation),
            None => build(None, None, fallback),
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
        let base = format!(
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
        let id = self.keys.marker_id(decision.id);
        let policy_hash = self.policy_hash.clone();
        let actor = AuditActor::System(Slug::parse("worker.decisions").map_err(|_| Unreadable)?);
        let subject = self.signed(tenant, id, action, &actor, &base);
        let action = AuditAction::new(action).map_err(|_| Unreadable)?;
        let fallback = CorrelationId::from_uuid(decision.id.as_uuid());
        self.write(
            tenant,
            Some((decision.fields.job, decision.fields.stage_run)),
            fallback,
            move |job, stage_run, correlation_id| NewAuditEvent {
                id,
                actor,
                action,
                subject,
                decision: outcome,
                reason,
                policy_hash,
                job,
                stage_run,
                correlation_id,
            },
        )
        .await
    }

    async fn mark_malformed(&self, tenant: TenantId, id: AuditEventId) -> Result<(), Unreadable> {
        self.mark_record(tenant, id, Reason::Malformed).await
    }

    async fn mark_unsigned(&self, tenant: TenantId, id: AuditEventId) -> Result<(), Unreadable> {
        self.mark_record(tenant, id, Reason::NotSigned).await
    }

    async fn mark_ignored(&self, tenant: TenantId, id: AuditEventId) -> Result<(), Unreadable> {
        let marker = self.keys.marker_id(id);
        let policy_hash = self.policy_hash.clone();
        let actor = AuditActor::System(Slug::parse("worker.decisions").map_err(|_| Unreadable)?);
        let action = AuditAction::new(MARKER_IGNORED).map_err(|_| Unreadable)?;
        let subject = format!(
            "marker={} code={}",
            id.as_uuid().hyphenated(),
            Reason::NotSigned.code()
        );
        let correlation = CorrelationId::from_uuid(id.as_uuid());
        self.write(
            tenant,
            None,
            correlation,
            move |job, stage_run, correlation_id| NewAuditEvent {
                id: marker,
                actor,
                action,
                subject,
                decision: AuditDecision::Deny,
                reason: "A record with the action of a marker was not written by the worker; it was not counted."
                    .to_owned(),
                policy_hash,
                job,
                stage_run,
                correlation_id,
            },
        )
        .await
    }
}

impl AuditMarkers {
    /// The marker of a record that was refused before it was read: its id, a fixed code, and no
    /// job, because nothing in the record is believed.
    async fn mark_record(
        &self,
        tenant: TenantId,
        id: AuditEventId,
        reason: Reason,
    ) -> Result<(), Unreadable> {
        let marker = self.keys.marker_id(id);
        let policy_hash = self.policy_hash.clone();
        let actor = AuditActor::System(Slug::parse("worker.decisions").map_err(|_| Unreadable)?);
        let base = format!(
            "decision={} code={} actor=none allowlist=none",
            id.as_uuid().hyphenated(),
            reason.code()
        );
        let subject = self.signed(tenant, marker, REJECTED, &actor, &base);
        let action = AuditAction::new(REJECTED).map_err(|_| Unreadable)?;
        let correlation = CorrelationId::from_uuid(id.as_uuid());
        self.write(
            tenant,
            None,
            correlation,
            move |job, stage_run, correlation_id| NewAuditEvent {
                id: marker,
                actor,
                action,
                subject,
                decision: AuditDecision::Deny,
                reason: reason.text().to_owned(),
                policy_hash,
                job,
                stage_run,
                correlation_id,
            },
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
    /// Records that are not requests this module trusts and have no marker yet, by sequence: a
    /// `decision.requested` that is malformed or does not carry the API's word (R-2, R-12, AUT-12),
    /// and a row with the action of a marker that does not carry the worker's word (RR-8). They are
    /// dealt with under a budget of their own, so that they never take the room of a signed request
    /// (RR-21).
    junk: BTreeMap<u64, (AuditEventId, Fault)>,
    /// How many junk records were left out of `junk` because it was full. They are not candidates
    /// either way, and a worker that starts reads them again.
    left_out: u64,
}

impl Scan {
    /// Keeps a junk record to mark, unless the scan already holds [`JUNK_KEPT`] of them.
    fn keep_junk(&mut self, sequence: u64, id: AuditEventId, fault: Fault) {
        if self.junk.len() >= JUNK_KEPT {
            self.left_out = self.left_out.saturating_add(1);
            return;
        }
        self.junk.insert(sequence, (id, fault));
    }
}

/// Why a record is refused before it is read as a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Not the text this module writes.
    Malformed,
    /// The text is right and the word that only the API can make is missing or wrong.
    NotSigned,
    /// A row with the action of a marker that the worker did not write (no word, a wrong word, or
    /// not a component of the system as its actor).
    ForgedMarker,
}

/// The most signed requests one pass deals with for one tenant, unless the hook is built with
/// another number. Bounded work per pass (R-12): a long queue never holds the claim back.
pub const DECISIONS_PER_PASS: usize = 50;

/// The most junk records (unsigned or malformed requests, forged markers) one pass writes a marker
/// for, for one tenant. A budget of its own, apart from [`DECISIONS_PER_PASS`]: junk never takes the
/// room of a signed request (RR-21).
pub const JUNK_PER_PASS: usize = 25;

/// The most junk records a scan keeps in memory for one tenant. A writer who adds more than the
/// worker can mark does not make the worker grow without bound.
const JUNK_KEPT: usize = 10_000;

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
    drafts: Option<Arc<dyn SpecDrafts>>,
    dependencies: Option<Arc<DependencyDecisions>>,
    stages: Option<Arc<StageDecisions>>,
    recorded: Option<Arc<dyn RecordedApprovals>>,
    rejections: Option<Arc<IntakeRejections>>,
    repository_changes: Option<Arc<RepositoryChanges>>,
    policy: Option<Arc<PolicyEngine>>,
    keys: Arc<DecisionKeys>,
    scans: Mutex<BTreeMap<TenantId, Scan>>,
    /// Where the next round of tenants starts, so that the same tenant is not always first.
    turn: AtomicUsize,
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
    /// The keys the API signs its requests with. A request is read only if its word is the one
    /// under one of them.
    pub keys: Arc<DecisionKeys>,
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
            drafts: None,
            dependencies: None,
            stages: None,
            recorded: None,
            rejections: None,
            repository_changes: None,
            policy: None,
            keys: deps.keys,
            scans: Mutex::new(BTreeMap::new()),
            turn: AtomicUsize::new(0),
        }
    }

    /// Lets a person approve a specification draft. The hook reads the draft the stage kept
    /// (`SpecDrafts`) so that an approval counts only for the commit the person names, and the
    /// engine records the approval where `SpecApprovals` reads it. Without it an approval of a
    /// specification is refused as out of place, as it was before.
    #[must_use]
    pub fn with_specification(mut self, drafts: Arc<dyn SpecDrafts>) -> Self {
        self.drafts = Some(drafts);
        self
    }

    /// Lets a person decide on a new dependency or on its build code (`approve-dependency` and
    /// `approve-build-code`). The step reads its own requests, which carry their own audit action,
    /// and calls `Engine::record_dependency_decision`. Without it those requests are left alone.
    #[must_use]
    pub fn with_dependencies(mut self, dependencies: Arc<DependencyDecisions>) -> Self {
        self.dependencies = Some(dependencies);
        self
    }

    /// Lets a person act on a stage run: let a blocked one go again (`unblock`). The step reads
    /// its own requests, which carry their own audit action, and calls the engine. Without it
    /// those requests are left alone.
    #[must_use]
    pub fn with_stage_decisions(mut self, stages: Arc<StageDecisions>) -> Self {
        self.stages = Some(stages);
        self
    }

    /// Lets an approval count the decisions about translation warnings that the person recorded
    /// (`ack-translation-warning`). They are read from the ledger, through this source. Without it
    /// an approval of a request that has an open warning is refused, as it was before.
    #[must_use]
    pub fn with_recorded_decisions(mut self, recorded: Arc<dyn RecordedApprovals>) -> Self {
        self.recorded = Some(recorded);
        self
    }

    /// Lets the worker answer a label from someone who may not ask (FR-002). The step reads the
    /// signed requests the API leaves for such labels, posts the one fixed reply through the
    /// change host, and records the rejection. Without it those requests are left alone.
    #[must_use]
    pub fn with_rejections(mut self, rejections: Arc<IntakeRejections>) -> Self {
        self.rejections = Some(rejections);
        self
    }

    /// Lets the one person who approves on a `single_maintainer` repository approve the
    /// specification of their own request (the solo mode, ADR 0021). The hook asks the policy for
    /// the proof of `freeze_specification` with the solo fact, and hands it to the engine, which
    /// checks the fact again. Without it the requester's approval is refused, as it was before.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<PolicyEngine>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Lets the worker apply the signed requests to register, attest and enable a repository (REG-2).
    /// The step verifies each request, asks the protected allowlist again and applies the change through
    /// the Store. Without it those requests are left alone.
    #[must_use]
    pub fn with_repository_changes(mut self, changes: Arc<RepositoryChanges>) -> Self {
        self.repository_changes = Some(changes);
        self
    }

    /// One pass for one tenant: admit, then decide. Public so a test can run a pass without a loop.
    pub async fn pass(&self, tenant: TenantId) {
        self.admit_received(tenant).await;
        self.apply_decisions(tenant).await;
        if let Some(dependencies) = &self.dependencies {
            dependencies.pass(tenant).await;
        }
        if let Some(stages) = &self.stages {
            stages.pass(tenant).await;
        }
        if let Some(rejections) = &self.rejections {
            rejections.pass(tenant).await;
        }
        if let Some(changes) = &self.repository_changes {
            changes.pass(tenant).await;
        }
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
            // The lines about a job are written inside its stretch span, so they start with its
            // correlation id (the conventions page, section 7). The id is the stored job's.
            let span = job_stretch(
                &stored.value.correlation_id.as_text(),
                &stored.value.id.as_text(),
                &tenant.as_text(),
            );
            self.admit_one(tenant, stored.value.id)
                .instrument(span)
                .await;
        }
    }

    /// Asks the engine to decide one received job, and says what became of it.
    async fn admit_one(&self, tenant: TenantId, job: JobId) {
        match self.engine.admit_job(tenant, job).await {
            Ok(admission) => tracing::info!(
                job = %job,
                admitted = matches!(admission, factory_workflow::engine::Admission::Admitted { .. }),
                "a received job was decided"
            ),
            // Another worker decided first, or the job moved: nothing to do.
            Err(EngineError::Illegal(_) | EngineError::Conflict | EngineError::NotFound) => {}
            Err(error @ EngineError::NoHandler(_)) => tracing::error!(
                job = %job,
                %error,
                "a received job cannot be admitted until its stage has a handler"
            ),
            Err(error) => tracing::warn!(
                job = %job,
                %error,
                "a received job was not admitted this pass"
            ),
        }
    }

    // ---- decisions -------------------------------------------------------------------------

    async fn apply_decisions(&self, tenant: TenantId) {
        if !self.read_new_records(tenant).await {
            return;
        }
        // Bounded work (R-12), in two budgets that do not touch each other (RR-21): junk records
        // (cheap, a marker each) up to `JUNK_PER_PASS`, and signed requests in the order of the
        // tenant's audit sequence (R-10) up to `per_pass`. Whatever the junk writer adds, the
        // signed requests of the pass are the first `per_pass` of them.
        let (junk, pending): (Vec<(u64, AuditEventId, Fault)>, Vec<Pending>) = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or_else(
                || (Vec::new(), Vec::new()),
                |scan| {
                    let junk: Vec<(u64, AuditEventId, Fault)> = scan
                        .junk
                        .iter()
                        .take(JUNK_PER_PASS)
                        .map(|(sequence, (id, fault))| (*sequence, *id, *fault))
                        .collect();
                    (
                        junk,
                        scan.pending.values().take(self.per_pass).cloned().collect(),
                    )
                },
            )
        };
        for (sequence, id, fault) in junk {
            let (marked, code) = match fault {
                Fault::Malformed => (
                    self.markers.mark_malformed(tenant, id).await,
                    Reason::Malformed.code(),
                ),
                Fault::NotSigned => (
                    self.markers.mark_unsigned(tenant, id).await,
                    Reason::NotSigned.code(),
                ),
                Fault::ForgedMarker => (
                    self.markers.mark_ignored(tenant, id).await,
                    "marker_ignored",
                ),
            };
            match marked {
                Ok(()) => {
                    tracing::info!(code, "a record that is not a request was dealt with");
                    let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(scan) = scans.get_mut(&tenant) {
                        scan.junk.remove(&sequence);
                    }
                }
                Err(Unreadable) => tracing::warn!(
                    "the marker of a record that is not a request could not be written; it is tried again next pass"
                ),
            }
        }
        for decision in pending {
            // Everything the hook says about a decision is about the job the decision names, so it
            // is said inside that job's stretch span and starts with that job's correlation id.
            let span = job_span_of(&*self.store, tenant, decision.fields.job).await;
            self.deal_with(tenant, decision).instrument(span).await;
        }
    }

    /// One decision: judge it, apply it, and write the marker that ends it.
    async fn deal_with(&self, tenant: TenantId, decision: Pending) {
        let (verdict, decision) = self.decide(tenant, decision).await;
        let marked = match verdict {
            Verdict::Done(marked) => marked,
            Verdict::Later if decision.failures + 1 >= MAX_TRIES => {
                Marked::Rejected(Reason::GaveUp.text())
            }
            Verdict::Later => {
                self.note_failure(tenant, decision.sequence);
                return;
            }
        };
        self.finish(tenant, &decision, &marked).await;
    }

    /// Writes the marker that ends a decision, and forgets the decision once it is written.
    async fn finish(&self, tenant: TenantId, decision: &Pending, marked: &Marked) {
        match self.markers.mark(tenant, decision, marked).await {
            Ok(()) => {
                // Counted by code, and nothing from the request is in the line (R-13, R-17).
                tracing::info!(code = outcome_code(marked), "a decision was dealt with");
                self.forget(tenant, decision.sequence);
            }
            Err(Unreadable) => tracing::warn!(
                decision = %decision.id,
                "the marker could not be written; the decision is checked again next pass"
            ),
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
                        REQUESTED => match requested_from(tenant, &record, &self.keys) {
                            Ok(pending) => {
                                scan.pending.insert(record.sequence, pending);
                            }
                            Err(fault) => scan.keep_junk(record.sequence, record.event.id, fault),
                        },
                        APPLIED | REJECTED => {
                            // Only a marker the worker signed ends a request (RR-8).
                            match counted_marker(tenant, &record, &self.keys) {
                                Some(Some(id)) => {
                                    scan.pending.retain(|_, pending| pending.id != id);
                                    scan.junk.retain(|_, (junk, _)| *junk != id);
                                }
                                Some(None) => scan.keep_junk(
                                    record.sequence,
                                    record.event.id,
                                    Fault::ForgedMarker,
                                ),
                                None => {}
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
        let (repository, github_repository) = match self.job_facts(tenant, fields.job).await {
            Ok(Some((status, _, _))) if status.is_terminal() => {
                return Verdict::Done(Reason::JobEnded.into());
            }
            Ok(Some((_, repository, github_repository))) => (repository, github_repository),
            Ok(None) => return Verdict::Done(Reason::NoJob.into()),
            Err(Unreadable) => return Verdict::Later,
        };

        // 5. May they, now, on this repository? The allowlist is read at this moment and the sender
        // is found by the numeric id of the principal, never by a login.
        match self
            .authority
            .permits(
                tenant,
                sender.id,
                fields.verb,
                &RepositoryIdentity::registered(&repository, github_repository),
            )
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
                self.approve_or_reject(tenant, decision, command, sender, &repository)
                    .await
            }
            Verb::Answer => self.answer(tenant, decision, command).await,
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
        repository: &str,
    ) -> Verdict {
        let fields = &decision.fields;
        let Some(stage_run) = fields.stage_run else {
            return Verdict::Done(Reason::NoStageRun.into());
        };
        // The approval service judges a decision against a pull request: its head, its base and
        // the evidence bound to them. Only the approval stage has one. A stage before it that
        // waits for a person (a specification with no draft worth approving, a review with no
        // independent reviewer) has no pull request and no stored approval request, so the
        // service could never answer for it and the decision was given up. Those decisions go to
        // the engine, whose own guards say who may take them and from which state.
        let (kind, correlation) = match self.stage_facts(tenant, stage_run).await {
            Ok(Some(facts)) => facts,
            Ok(None) => return Verdict::Done(Reason::NoStageRun.into()),
            Err(Unreadable) => return Verdict::Later,
        };
        match (kind, fields.verb) {
            // The specification stage asks a person before it freezes its draft.
            (StageKind::Specification, Verb::Approve) => {
                return self
                    .approve_specification(
                        tenant,
                        decision,
                        (command, correlation),
                        (&sender, repository),
                    )
                    .await;
            }
            (StageKind::Approval, _) | (_, Verb::Approve) => {}
            (_, Verb::Reject | Verb::Rework) => {
                return self
                    .decide_before_the_pull_request(tenant, decision, command)
                    .await;
            }
            _ => {}
        }
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
        // decision of this person. With none open there is nothing undecided; with some open, the
        // decisions the person recorded (`ack-translation-warning`) are read back from the ledger.
        let warnings_decided = match &request {
            Some(found) => {
                warnings_decided(
                    self.recorded.as_deref(),
                    (tenant, fields.job, stage_run),
                    sender.id,
                    found,
                )
                .await
            }
            None => false,
        };
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
                solo: Some(solo_request_of(decision)),
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

    /// A person's rejection, or their request for rework, of a stage run that waits before the job
    /// has a pull request.
    ///
    /// The engine decides: a rejection is `S16` and needs the approver role, a rework request is
    /// `S15` and needs a route from the waiting stage to the target (`human_rework_routes`), the
    /// approver or operator role and room under the rework cap. The hook has already checked, in
    /// the steps before this one, that the person is a current user of the tenant and that the
    /// allowlist gives them this verb on this repository.
    async fn decide_before_the_pull_request(
        &self,
        tenant: TenantId,
        decision: &Pending,
        command: CausationId,
    ) -> Verdict {
        let fields = &decision.fields;
        let Some(stage_run) = fields.stage_run else {
            return Verdict::Done(Reason::NoStageRun.into());
        };
        let (engine_decision, applied) = match fields.verb {
            Verb::Reject => {
                let Ok(reason) = HumanText::parse(decision.reason.trim()) else {
                    return Verdict::Done(Reason::Incomplete.into());
                };
                (
                    EngineDecision::Reject { reason },
                    "The job was rejected.".to_owned(),
                )
            }
            Verb::Rework => {
                let Some(target) = fields
                    .target
                    .as_deref()
                    .and_then(|text| StageKind::parse(text).ok())
                else {
                    return Verdict::Done(Reason::Incomplete.into());
                };
                (
                    EngineDecision::RequestRework {
                        target,
                        instructions: HumanText::parse(decision.reason.trim()).ok(),
                    },
                    format!("The work was sent back to {}.", target.as_str()),
                )
            }
            _ => return Verdict::Done(Reason::WrongState.into()),
        };
        let actor = Actor {
            tenant,
            principal: decision.principal,
            command,
        };
        let decided = self
            .engine
            .decide(
                &actor,
                Subject {
                    job: fields.job,
                    stage_run,
                },
                engine_decision,
            )
            .await;
        match decided {
            Ok(()) => Verdict::Done(Marked::Applied(applied)),
            Err(EngineError::Duplicate) => Verdict::Done(Marked::Applied(
                "The engine had applied this decision already.".to_owned(),
            )),
            Err(EngineError::NotAuthorized(_)) => Verdict::Done(Reason::NotAuthorized.into()),
            Err(EngineError::NotFound) => Verdict::Done(Reason::NoStageRun.into()),
            // The run does not wait for a person, the target has no route from this stage, or the
            // rework cap is used up.
            Err(EngineError::Illegal(_) | EngineError::GuardUnmet(_) | EngineError::Refused(_)) => {
                Verdict::Done(Reason::WrongState.into())
            }
            Err(_) => Verdict::Later,
        }
    }

    /// A person's approval of a specification draft.
    ///
    /// The person names the commit that holds the draft they read (`head`) and the head of the
    /// ledger they saw (`evidence`). The hook checks the commit against the draft the stage kept,
    /// then asks the engine to record the approval: the engine writes the person's judgment on
    /// the stage run, where [`SpecApprovals`](factory_workflow::stages::specification::SpecApprovals)
    /// reads it, and sends the run back to `READY` so that its next attempt freezes that draft.
    async fn approve_specification(
        &self,
        tenant: TenantId,
        decision: &Pending,
        (command, correlation): (CausationId, CorrelationId),
        (sender, repository): (&Sender, &str),
    ) -> Verdict {
        let fields = &decision.fields;
        let Some(stage_run) = fields.stage_run else {
            return Verdict::Done(Reason::NoStageRun.into());
        };
        let Some(drafts) = &self.drafts else {
            return Verdict::Done(Reason::WrongState.into());
        };
        let identity = RunIdentity {
            tenant,
            job: fields.job,
            correlation,
            stage_run,
            kind: StageKind::Specification,
        };
        let draft = match drafts.load(&identity).await {
            // A record with a contract is a draft that passed its gates and waits for its approval.
            Ok(Some(draft)) if !draft.contract.is_empty() => draft,
            // The stage kept no draft, or kept one with no contract: it stopped to ask a question
            // (its own, or the reviewer's), and a question is answered, not approved. In the
            // thirtieth real run an approval was taken for the answer to the reviewer's question,
            // and the stage ran again and asked the same question.
            Ok(_) => return Verdict::Done(Reason::WrongState.into()),
            Err(_) => return Verdict::Later,
        };
        let (Some(head), Some(evidence)) = (
            fields.head.as_deref(),
            fields
                .evidence
                .as_deref()
                .and_then(|text| Sha256Digest::parse(text).ok()),
        ) else {
            return Verdict::Done(Reason::Incomplete.into());
        };
        if head != draft.commit.as_str() {
            return Verdict::Done(Reason::DraftMoved.into());
        }
        // The solo mode: the requester's own approval needs the policy's stamped proof.
        let proof = match self.spec_proof(&identity, sender, repository).await {
            Ok(proof) => proof,
            Err(verdict) => return verdict,
        };
        let actor = Actor {
            tenant,
            principal: decision.principal,
            command,
        };
        let decided = self
            .engine
            .decide(
                &actor,
                Subject {
                    job: fields.job,
                    stage_run,
                },
                EngineDecision::Approve {
                    evidence_seen: evidence,
                    warnings_decided: true,
                    proof,
                },
            )
            .await;
        match decided {
            Ok(()) => Verdict::Done(Marked::Applied(
                "The specification was approved. The stage will freeze that draft.".to_owned(),
            )),
            Err(EngineError::Duplicate) => Verdict::Done(Marked::Applied(
                "The engine had applied this decision already.".to_owned(),
            )),
            Err(EngineError::NotAuthorized(_)) => Verdict::Done(Reason::NotAuthorized.into()),
            // The only fact of the approval guard left to fail is the evidence the person saw.
            Err(EngineError::GuardUnmet(_)) => Verdict::Done(Reason::EvidenceMoved.into()),
            Err(EngineError::Illegal(_) | EngineError::Refused(_)) => {
                Verdict::Done(Reason::WrongState.into())
            }
            Err(_) => Verdict::Later,
        }
    }

    /// The policy's proof for the freezing of a specification by the requester of the job, in the
    /// solo mode (ADR 0021). `Ok(None)` when the person is not the requester (the engine checks
    /// their role as before) or when the hook has no policy (the engine then refuses the
    /// requester). The facts are those of the approval of a pull request but for the change: a
    /// specification has no pull request and no risk tier yet, so it is the low tier, which asks
    /// for no designation or person beyond the approver; and it has no wait and no phrase.
    async fn spec_proof(
        &self,
        identity: &RunIdentity,
        sender: &Sender,
        repository: &str,
    ) -> Result<Option<factory_domain::policy::decision::AuthorizedApproval>, Verdict> {
        let Some(policy) = &self.policy else {
            return Ok(None);
        };
        let tenant = identity.tenant;
        let (Ok(allowlist), Ok(level), Ok(requester)) = (
            self.approvals.allowlist(tenant).await,
            self.approvals.level(tenant, identity.job).await,
            self.approvals.requester(identity).await,
        ) else {
            return Err(Verdict::Later);
        };
        if requester != sender.id {
            return Ok(None);
        }
        let now = self.clock.now();
        let Ok(inputs) = self.approvals.solo_inputs(tenant, identity.job, now).await else {
            return Err(Verdict::Later);
        };
        let Some(id) = GithubUserId::new(sender.id) else {
            return Err(Verdict::Done(Reason::NotAuthorized.into()));
        };
        let actor = PolicyActor {
            github_user_id: id,
            login: sender.login.as_str(),
            kind: sender.kind,
            github_permission: None,
            author_association: None,
        };
        let verdict = policy.authority.authorize_action(&ActionContext {
            action: "freeze_specification",
            level,
            tenant: &tenant,
            repository,
            actor: &actor,
            allowlist: &allowlist,
            now: &now,
            requester: Some(id),
            change: ChangeFacts {
                risk_tier: RiskTier::Low,
                protected_path_change: false,
                sensitive_file_change: false,
                new_dependency: false,
            },
            require_designation: None,
            step_up_done: false,
            solo: policy
                .authority
                .solo_fact(inputs.single_maintainer, inputs.approver_count),
        });
        match verdict {
            ActionVerdict::Authorized(proof) => Ok(Some(proof)),
            ActionVerdict::Denied(denial) if denial.reason == ActionDenialReason::SelfApproval => {
                Err(Verdict::Done(Reason::IneligibleApprover.into()))
            }
            ActionVerdict::Denied(_) | ActionVerdict::NoHumanNeeded { .. } => {
                Err(Verdict::Done(Reason::NotAuthorized.into()))
            }
        }
    }

    /// A person's answer to the questions of a stage run that waits (the specification stage's
    /// clarification). The engine stores the text, links it to the stage run as a human answer and
    /// sends the run back to `READY` (`S13`); its next attempt reads the answer as data. The text
    /// is applied only if its hash is the one the keyed word covers, so no writer of the audit log
    /// can change what a person answered. An answer never raises a budget ceiling from here.
    async fn answer(&self, tenant: TenantId, decision: &Pending, command: CausationId) -> Verdict {
        let fields = &decision.fields;
        let Some(stage_run) = fields.stage_run else {
            return Verdict::Done(Reason::NoStageRun.into());
        };
        let text = &decision.reason;
        if fields.answer.as_deref() != Some(answer_digest(text).as_str()) {
            return Verdict::Done(Reason::Malformed.into());
        }
        if crate::commands::checked_answer(text).as_deref() != Ok(text.as_str()) {
            return Verdict::Done(Reason::Incomplete.into());
        }
        let actor = Actor {
            tenant,
            principal: decision.principal,
            command,
        };
        let decided = self
            .engine
            .decide(
                &actor,
                Subject {
                    job: fields.job,
                    stage_run,
                },
                EngineDecision::Answer {
                    text: text.clone(),
                    raises_budget_ceiling: false,
                },
            )
            .await;
        match decided {
            Ok(()) => Verdict::Done(Marked::Applied(
                "The answer was recorded. The stage runs again with it.".to_owned(),
            )),
            Err(EngineError::Duplicate) => Verdict::Done(Marked::Applied(
                "The engine had applied this decision already.".to_owned(),
            )),
            Err(EngineError::NotAuthorized(_)) => Verdict::Done(Reason::NotAuthorized.into()),
            Err(EngineError::NotFound) => Verdict::Done(Reason::NoStageRun.into()),
            // The run does not wait for a person (`S13` is not a move from where it is).
            Err(EngineError::Illegal(_) | EngineError::GuardUnmet(_) | EngineError::Refused(_)) => {
                Verdict::Done(Reason::WrongState.into())
            }
            Err(_) => Verdict::Later,
        }
    }

    // ---- reads -----------------------------------------------------------------------------

    /// The kind of a stage run and the correlation id of its job, or `None` for a stage run the
    /// tenant does not hold.
    async fn stage_facts(
        &self,
        tenant: TenantId,
        stage_run: StageRunId,
    ) -> Result<Option<(StageKind, CorrelationId)>, Unreadable> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = async {
            let run = tx.get_stage_run(stage_run).await?;
            let job = tx.get_job(run.value.job_id).await?;
            Ok::<_, StoreError>((run.value.kind, job.value.correlation_id))
        }
        .await;
        let _ = tx.rollback().await;
        match found {
            Ok(facts) => Ok(Some(facts)),
            Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(Unreadable),
        }
    }

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

    /// The status of the job, the full name (`owner/name`) of its repository and GitHub's numeric id of
    /// it, as they are now.
    async fn job_facts(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<Option<(JobStatus, String, u64)>, Unreadable> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = async {
            let stored = tx.get_job(job).await?;
            let repository = tx.get_repository(stored.value.repository).await?;
            Ok::<_, StoreError>((
                stored.value.status,
                repository.value.full_name,
                repository.value.github_repository_id.0,
            ))
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
        // Each tenant has budgets of its own, so one tenant's queue cannot take the room of another's.
        // The order in which they are visited turns on every round, so that none is always last.
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        for tenant in rotated(&self.tenants, turn) {
            self.pass(tenant).await;
        }
    }
}

#[async_trait(?Send)]
impl WhileRunning for ClaimWork {
    /// Reads the new records of the tenant and deals with the cancel requests for `job`, each by
    /// the same path as a pass: the word of the API, the age of the request, the allowlist as it
    /// is now, the engine, and the marker. So a cancel applied here is applied exactly once, and a
    /// pass that finds it later finds its marker.
    ///
    /// Everything else waits for the next pass: admissions, approvals, pauses, the requests about
    /// other jobs and the records that are not requests. A cancel is therefore applied ahead of
    /// an older request for the same job that is still waiting, which then meets a job that is
    /// being cancelled and is refused as out of place.
    ///
    /// A cancel that cannot be decided now (the store or the allowlist cannot be read) is left as
    /// it is, without counting a try: this runs far more often than a pass, and it must not use up
    /// the tries a pass gives a request before it is rejected ([`MAX_TRIES`]).
    async fn apply_cancels(&self, tenant: TenantId, job: JobId) {
        if !self.tenants.contains(&tenant) || !self.read_new_records(tenant).await {
            return;
        }
        let cancels: Vec<Pending> = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or_else(Vec::new, |scan| {
                scan.pending
                    .values()
                    .filter(|pending| {
                        pending.fields.job == job && pending.fields.verb == Verb::Cancel
                    })
                    .take(self.per_pass)
                    .cloned()
                    .collect()
            })
        };
        for decision in cancels {
            let span = job_span_of(&*self.store, tenant, job).await;
            async {
                let (verdict, decision) = self.decide(tenant, decision).await;
                if let Verdict::Done(marked) = verdict {
                    self.finish(tenant, &decision, &marked).await;
                }
            }
            .instrument(span)
            .await;
        }
    }
}

/// The tenants in the order of this round: the list starting at the place `turn` names, wrapping.
fn rotated(tenants: &[TenantId], turn: usize) -> Vec<TenantId> {
    let start = if tenants.is_empty() {
        0
    } else {
        turn % tenants.len()
    };
    tenants[start..]
        .iter()
        .chain(&tenants[..start])
        .copied()
        .collect()
}

/// A request for a decision, read from its audit record. `Err` for a record that is not a request
/// this module trusts: the record is rejected with a marker and stops being a candidate.
///
/// The row is untrusted input: any login of the application group can write an audit record with
/// any words in it. It is accepted only if the actor is a human principal, the subject is exactly the
/// canonical text the API writes, **the word at the end of the subject is the one only the API can
/// make** (AUT-12), and the columns for the job and the stage run say what the subject says. The
/// word is checked before the columns and before anything is believed. The reason is free text and
/// is never read for structure.
fn requested_from(
    tenant: TenantId,
    record: &factory_ports::store::AuditRecord,
    keys: &DecisionKeys,
) -> Result<Pending, Fault> {
    let AuditActor::Human(principal) = record.event.actor.clone() else {
        return Err(Fault::Malformed);
    };
    let (fields, requested_at, word) = match read_subject(&record.event.subject) {
        Some(SubjectKind::Signed {
            fields,
            requested_at,
            word,
        }) => (fields, requested_at, word),
        // The text is the API's, and nobody signed it.
        Some(SubjectKind::Unsigned(_)) => return Err(Fault::NotSigned),
        None => return Err(Fault::Malformed),
    };
    let signing = Signing {
        tenant,
        actor: principal,
        event: record.event.id,
        requested_at: &requested_at,
        fields: &fields,
    };
    if !keys.verify(&signing, &word) {
        return Err(Fault::NotSigned);
    }
    if record.event.job != Some(fields.job) || record.event.stage_run != fields.stage_run {
        return Err(Fault::Malformed);
    }
    // The hash of an answer belongs to an answer, and an answer has one.
    if (fields.verb == Verb::Answer) != fields.answer.is_some() {
        return Err(Fault::Malformed);
    }
    let reason = record
        .event
        .reason
        .strip_prefix(REQUEST_PREFIX)
        .unwrap_or(&record.event.reason)
        .to_owned();
    Ok(Pending {
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

/// When the person asked and the confirmation word their request carried: the time the database
/// wrote the signed request, and the `confirm=` word, read only if it is a well formed one.
fn solo_request_of(decision: &Pending) -> SoloRequest {
    SoloRequest {
        requested_at: decision.requested_at,
        confirmation: decision
            .fields
            .confirm
            .as_deref()
            .and_then(ConfirmationWord::parse),
    }
}

/// True when the person has decided on every open translation warning of the approval request:
/// with none open there is nothing to decide, and with some open the decisions recorded in the
/// ledger for this request and this person must cover them all. A source that cannot give any
/// answers "not decided", which is the safe side.
async fn warnings_decided(
    recorded: Option<&dyn RecordedApprovals>,
    (tenant, job, stage_run): (TenantId, JobId, StageRunId),
    person: u64,
    request: &factory_workflow::stages::approval::ApprovalRequest,
) -> bool {
    if request.open_translation_warnings == 0 {
        return true;
    }
    let Some(recorded) = recorded else {
        return false;
    };
    let decisions = recorded.warning_decisions_for_job(tenant, job).await;
    all_decided(
        &decisions,
        person,
        (&DecisionScope { tenant, job }, stage_run, &request.manifest),
        request.open_translation_warnings,
    )
}

/// The reason for a refusal of the approval service. Authority is never explained, with one
/// exception: `ineligible_approver` names the solo mode (ADR 0021). Whoever reaches the approval
/// stage's judge has passed step 5 of the hook ("May they, now, on this repository?"): they are on
/// the allowlist with the role, so the reason does not tell who is on the list.
fn refusal_reason(code: &str) -> Reason {
    match code {
        "not_authorized" | "not_a_command" => Reason::NotAuthorized,
        "ineligible_approver" => Reason::IneligibleApprover,
        "solo_delay" => Reason::SoloDelay,
        "confirmation_missing" => Reason::ConfirmationMissing,
        "new_commit" => Reason::NewCommit,
        "base_moved" => Reason::BaseMoved,
        "base_retargeted" => Reason::BaseRetargeted,
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

    /// The decisions about translation warnings a test source holds.
    struct Warnings(Vec<factory_workflow::stages::approval::warnings::WarningDecision>);

    #[async_trait]
    impl RecordedApprovals for Warnings {
        fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
            factory_domain::vocabulary::Fidelity::Fake
        }

        async fn for_job(
            &self,
            _: TenantId,
            _: JobId,
        ) -> Vec<factory_workflow::gates::supply_chain::approval::DependencyApproval> {
            Vec::new()
        }

        async fn warning_decisions_for_job(
            &self,
            _: TenantId,
            _: JobId,
        ) -> Vec<factory_workflow::stages::approval::warnings::WarningDecision> {
            self.0.clone()
        }
    }

    fn request(open: u32) -> factory_workflow::stages::approval::ApprovalRequest {
        let sha = |text: &str| Sha256Digest::of(text.as_bytes());
        factory_workflow::stages::approval::ApprovalRequest {
            repository: "acme/widgets".to_owned(),
            pull_request: 7,
            head_branch: "factory/x".to_owned(),
            base_branch: "main".to_owned(),
            pr_head: GitSha::parse(&"a".repeat(40)).expect("a sha"),
            tree: GitSha::parse(&"b".repeat(40)).expect("a sha"),
            base: GitSha::parse(&"c".repeat(40)).expect("a sha"),
            manifest: sha("manifest"),
            spec_version: 1,
            gates_clear: true,
            open_translation_warnings: open,
            tier: factory_domain::vocabulary::RiskTier::Low,
            protected_path_change: false,
            sensitive_file_change: false,
            new_dependency: false,
            requester: 1,
            evidence_binding: factory_workflow::stages::validation::Binding {
                implementation_result: sha("result"),
                base_commit: GitSha::parse(&"c".repeat(40)).expect("a sha"),
                head_commit: GitSha::parse(&"a".repeat(40)).expect("a sha"),
                policy_hash: sha("policy"),
                image_digest: sha("image"),
                definition_hash: sha("definitions"),
            },
            created_at: Timestamp::parse("2026-10-29T10:00:00Z").expect("a time"),
        }
    }

    fn decision_by(
        person: u64,
        warning: u32,
        (tenant, job, run): (TenantId, JobId, StageRunId),
    ) -> factory_workflow::stages::approval::warnings::WarningDecision {
        factory_workflow::stages::approval::warnings::WarningDecision {
            stage_run: run,
            manifest: request(2).manifest,
            warning,
            approver: factory_domain::policy::decision::GithubUserId::new(person).expect("an id"),
            designation: Designation::Approver,
            allowlist_version: "sha256:aa".to_owned(),
            policy_hash: Sha256Digest::of(b"policy"),
            scope: factory_workflow::gates::supply_chain::approval::DecisionScope { tenant, job },
            reason: "The translation says what the original says.".to_owned(),
            decided_at: Timestamp::parse("2026-10-29T12:00:00Z").expect("a time"),
        }
    }

    #[tokio::test]
    async fn an_approval_with_open_warnings_needs_this_persons_decisions_on_all_of_them() {
        let here = (
            TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            JobId::from_uuid(uuid::Uuid::from_u128(2)),
            StageRunId::from_uuid(uuid::Uuid::from_u128(3)),
        );
        // None open: nothing to decide, with or without a source of decisions.
        assert!(warnings_decided(None, here, 7, &request(0)).await);
        // Two open and no source: the approval is refused, as before the verb existed.
        assert!(!warnings_decided(None, here, 7, &request(2)).await);
        // Two open and no decision.
        let empty = Warnings(Vec::new());
        assert!(!warnings_decided(Some(&empty), here, 7, &request(2)).await);
        // One of two.
        let one = Warnings(vec![decision_by(7, 1, here)]);
        assert!(!warnings_decided(Some(&one), here, 7, &request(2)).await);
        // Both, by this person.
        let both = Warnings(vec![decision_by(7, 1, here), decision_by(7, 2, here)]);
        assert!(warnings_decided(Some(&both), here, 7, &request(2)).await);
        // Both, by another person: they do not count for this one's approval.
        assert!(!warnings_decided(Some(&both), here, 8, &request(2)).await);
        // Both, for another stage run.
        let other_run = StageRunId::from_uuid(uuid::Uuid::from_u128(4));
        assert!(!warnings_decided(Some(&both), (here.0, here.1, other_run), 7, &request(2)).await);
    }

    #[test]
    fn a_subject_reads_back_as_it_was_written() {
        let fields = DecisionFields {
            verb: Verb::Approve,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x1111)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            head: Some("a".repeat(40)),
            evidence: Some(format!("sha256:{}", "b".repeat(64))),
            target: None,
            answer: None,
            confirm: None,
        };
        assert_eq!(DecisionFields::parse(&fields.subject()), Some(fields));
    }

    #[test]
    fn an_answer_carries_the_hash_of_its_text_and_the_other_verbs_keep_their_six_words() {
        let job = JobId::from_uuid(uuid::Uuid::from_u128(7));
        let run = StageRunId::from_uuid(uuid::Uuid::from_u128(8));
        let answer = DecisionFields {
            verb: Verb::Answer,
            job,
            stage_run: Some(run),
            head: None,
            evidence: None,
            target: None,
            answer: Some(answer_digest("Q-001: yes")),
            confirm: None,
        };
        let subject = answer.subject();
        assert!(subject.ends_with(&format!(
            " target=none answer={}",
            answer_digest("Q-001: yes")
        )));
        assert_eq!(DecisionFields::parse_canonical(&subject), Some(answer));
        let pause = DecisionFields {
            verb: Verb::Pause,
            job,
            stage_run: None,
            head: None,
            evidence: None,
            target: None,
            answer: None,
            confirm: None,
        };
        assert!(!pause.subject().contains("answer="));
        assert_eq!(pause.subject().split(' ').count(), 6);
        assert_ne!(answer_digest("Q-001: yes"), answer_digest("Q-001: no"));
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

    fn keys(seed: u8) -> DecisionKeys {
        DecisionKeys::fixed_for_tests(&[seed; 40], None).expect("a key")
    }

    fn marker_row(
        keys: &DecisionKeys,
        tenant: TenantId,
        action: &str,
        actor: AuditActor,
        decision: AuditEventId,
    ) -> factory_ports::store::AuditRecord {
        let event = keys.marker_id(decision);
        let base = format!(
            "decision={} code=applied actor=none allowlist=none",
            decision.as_uuid().hyphenated()
        );
        let subject = keys.signed_marker_subject(&MarkerSigning {
            tenant,
            event,
            action,
            actor: &actor_text(&actor),
            subject: &base,
        });
        factory_ports::store::AuditRecord {
            sequence: 1,
            event: NewAuditEvent {
                id: event,
                actor,
                action: AuditAction::new(action).expect("an action"),
                subject,
                decision: AuditDecision::Allow,
                reason: "applied".to_owned(),
                policy_hash: Sha256Digest::of(b"policy"),
                job: None,
                stage_run: None,
                correlation_id: CorrelationId::from_uuid(uuid::Uuid::from_u128(5)),
            },
            created_at: Timestamp::parse("2026-10-29T12:00:00Z").expect("a time"),
            hash: Sha256Digest::of(b"row"),
        }
    }

    #[test]
    fn the_marker_id_is_keyed_and_differs_from_the_decision() {
        let id = AuditEventId::from_uuid(uuid::Uuid::from_u128(7));
        let one = keys(1);
        assert_eq!(one.marker_id(id), one.marker_id(id));
        assert_ne!(one.marker_id(id), id);
        assert_ne!(
            one.marker_id(id),
            one.marker_id(AuditEventId::from_uuid(uuid::Uuid::from_u128(8)))
        );
        // Whoever lacks the key cannot compute the id the worker will write under.
        assert_ne!(one.marker_id(id), keys(2).marker_id(id));
    }

    #[test]
    fn a_signed_marker_names_its_decision_and_counts() {
        let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        let id = AuditEventId::from_uuid(uuid::Uuid::from_u128(9));
        let keys = keys(3);
        let worker = AuditActor::System(Slug::parse("worker.decisions").expect("a slug"));
        for action in [APPLIED, REJECTED] {
            let row = marker_row(&keys, tenant, action, worker.clone(), id);
            assert_eq!(counted_marker(tenant, &row, &keys), Some(Some(id)));
        }
    }

    #[test]
    fn a_marker_without_the_workers_word_is_not_counted() {
        let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        let id = AuditEventId::from_uuid(uuid::Uuid::from_u128(9));
        let keys = keys(3);
        let worker = AuditActor::System(Slug::parse("worker.decisions").expect("a slug"));
        // No word at all.
        let mut bare = marker_row(&keys, tenant, REJECTED, worker.clone(), id);
        bare.event.subject = format!("decision={} code=not_authorized", id.as_uuid().hyphenated());
        assert_eq!(counted_marker(tenant, &bare, &keys), Some(None));
        // A word of another key.
        let other = marker_row(&self::keys(4), tenant, REJECTED, worker.clone(), id);
        assert_eq!(counted_marker(tenant, &other, &keys), Some(None));
        // The right word on a row of another tenant, with another action, by another actor, with a
        // changed subject, under another row id.
        let good = marker_row(&keys, tenant, APPLIED, worker.clone(), id);
        let other_tenant = TenantId::from_uuid(uuid::Uuid::from_u128(2));
        assert_eq!(counted_marker(other_tenant, &good, &keys), Some(None));
        let mut action = good.clone();
        action.event.action = AuditAction::new(REJECTED).expect("an action");
        assert_eq!(counted_marker(tenant, &action, &keys), Some(None));
        let mut actor = good.clone();
        actor.event.actor =
            AuditActor::System(Slug::parse("worker.dependency-decisions").expect("a slug"));
        assert_eq!(counted_marker(tenant, &actor, &keys), Some(None));
        let mut person = good.clone();
        person.event.actor = AuditActor::Human(PrincipalId::from_uuid(uuid::Uuid::from_u128(77)));
        assert_eq!(counted_marker(tenant, &person, &keys), Some(None));
        let mut subject = good.clone();
        subject.event.subject = subject
            .event
            .subject
            .replace("code=applied", "code=refused");
        assert_eq!(counted_marker(tenant, &subject, &keys), Some(None));
        let mut moved = good.clone();
        moved.event.id = AuditEventId::from_uuid(uuid::Uuid::from_u128(1234));
        assert_eq!(counted_marker(tenant, &moved, &keys), Some(None));
        // A row of another action is not a marker at all.
        let mut unrelated = good;
        unrelated.event.action = AuditAction::new("job.submitted").expect("an action");
        assert_eq!(counted_marker(tenant, &unrelated, &keys), None);
    }

    #[test]
    fn the_word_of_a_request_is_not_the_word_of_a_marker() {
        // The same key signs both kinds of text; their first lines differ, so one cannot stand in for
        // the other.
        let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        let id = AuditEventId::from_uuid(uuid::Uuid::from_u128(9));
        let keys = keys(3);
        let worker = AuditActor::System(Slug::parse("worker.decisions").expect("a slug"));
        let mut row = marker_row(&keys, tenant, APPLIED, worker, id);
        let fields = DecisionFields {
            verb: Verb::Pause,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x11)),
            stage_run: None,
            head: None,
            evidence: None,
            target: None,
            answer: None,
            confirm: None,
        };
        let request_word = keys.sign(&Signing {
            tenant,
            actor: PrincipalId::from_uuid(uuid::Uuid::from_u128(2)),
            event: row.event.id,
            requested_at: "2026-10-29T12:00:00Z",
            fields: &fields,
        });
        row.event.subject = format!(
            "decision={} code=applied actor=none allowlist=none mac={request_word}",
            id.as_uuid().hyphenated()
        );
        assert_eq!(counted_marker(tenant, &row, &keys), Some(None));
    }

    #[test]
    fn the_tenants_start_where_the_turn_says() {
        let tenants: Vec<TenantId> = (1..=3)
            .map(|n| TenantId::from_uuid(uuid::Uuid::from_u128(n)))
            .collect();
        assert_eq!(rotated(&tenants, 0), tenants);
        assert_eq!(rotated(&tenants, 1), [tenants[1], tenants[2], tenants[0]]);
        assert_eq!(rotated(&tenants, 5), [tenants[2], tenants[0], tenants[1]]);
        assert!(rotated(&[], 4).is_empty());
        // Over a full round, each tenant is first once.
        let firsts: Vec<TenantId> = (0..3).map(|turn| rotated(&tenants, turn)[0]).collect();
        assert_eq!(firsts, tenants);
    }

    #[test]
    fn a_scan_keeps_a_bounded_number_of_junk_records() {
        let mut scan = Scan::default();
        for n in 0..(JUNK_KEPT as u64 + 5) {
            scan.keep_junk(
                n,
                AuditEventId::from_uuid(uuid::Uuid::from_u128(u128::from(n) + 1)),
                Fault::NotSigned,
            );
        }
        assert_eq!(scan.junk.len(), JUNK_KEPT);
        assert_eq!(scan.left_out, 5);
    }

    #[test]
    fn a_refusal_of_authority_is_never_explained() {
        for code in ["not_authorized", "not_a_command"] {
            assert_eq!(
                refusal_reason(code).text(),
                "The person may not take this decision now."
            );
        }
    }

    #[test]
    fn the_solo_mode_refusals_have_reasons_of_their_own() {
        for (code, reason) in [
            ("ineligible_approver", Reason::IneligibleApprover),
            ("solo_delay", Reason::SoloDelay),
            ("confirmation_missing", Reason::ConfirmationMissing),
        ] {
            assert_eq!(refusal_reason(code), reason);
            assert_eq!(reason.code(), code);
            assert_eq!(Reason::code_of(reason.text()), code);
        }
        // Every sentence is distinct, so a sentence reads back to one code.
        let texts: std::collections::BTreeSet<&str> =
            Reason::ALL.iter().map(|reason| reason.text()).collect();
        assert_eq!(texts.len(), Reason::ALL.len());
    }

    #[test]
    fn only_an_approval_carries_a_confirmation_word_and_it_reads_back() {
        let job = JobId::from_uuid(uuid::Uuid::from_u128(0x77));
        let word = ConfirmationWord::of("I confirm the solo approval of PR 3 at level high");
        let approve = DecisionFields {
            verb: Verb::Approve,
            job,
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x78))),
            head: Some("a".repeat(40)),
            evidence: Some(Sha256Digest::of(b"x").as_str().to_owned()),
            target: None,
            answer: None,
            confirm: Some(word.as_str().to_owned()),
        };
        let subject = approve.subject();
        assert!(subject.ends_with(&format!(" confirm={}", word.as_str())));
        assert_eq!(
            DecisionFields::parse_canonical(&subject),
            Some(approve.clone())
        );
        // Without the word the subject is the six words it always was.
        let bare = DecisionFields {
            confirm: None,
            ..approve.clone()
        };
        assert_eq!(bare.subject().split(' ').count(), 6);
        assert_eq!(DecisionFields::parse_canonical(&bare.subject()), Some(bare));
        // On another verb, or not sixteen lowercase hex digits, it is not a request.
        let cancel = DecisionFields {
            verb: Verb::Cancel,
            ..approve.clone()
        };
        assert_eq!(DecisionFields::parse_canonical(&cancel.subject()), None);
        for bad in ["ABCDEF0123456789", "0123", "the phrase"] {
            let changed = subject.replace(word.as_str(), bad);
            assert_eq!(DecisionFields::parse(&changed), None, "{changed}");
        }
    }
}
