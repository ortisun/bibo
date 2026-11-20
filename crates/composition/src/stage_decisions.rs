//! A person's decision about a stage run that is not an approval of a pull request, from the API to
//! the engine.
//!
//! Three verbs live here, in the same channels as the others:
//!
//! | Verb | What it asks | Designation | Engine |
//! |---|---|---|---|
//! | `unblock` | let a `BLOCKED` stage run go again, after the cause is gone | `operator` | `Engine::decide` with `UnblockRerun` |
//! | `ack-translation-warning` | decide about one open warning of the documentation reviewer's rule `translation-unfaithful`, so that the approval of the pull request can count it | `approver` (`acknowledge_documentation_warning`) | `Engine::record_warning_decision` |
//! | `approve-project-build-code` | accept the project's own new build code, one file with the exact content a reviewer read | `security_approver` (`approve_build_code`) | `Engine::record_project_build_code_decision` |
//!
//! They are not among the six verbs of the approval service, and not dependency decisions. They
//! name a stage run (and a file, or a warning), and each is a request the API
//! records as the audit record [`REQUESTED`], signed with the same key as the other requests but
//! under a context line of its own, so a word made for one kind of request is never the word of
//! another.
//!
//! # What the step does, in this order
//!
//! 1. Reads the requests after its cursor and checks the keyed word before anything else is
//!    believed (AUT-12). A request with no word, or the wrong one, is rejected with the fixed code
//!    `not_signed`.
//! 2. Asks the engine whether it already applied the command, and if so writes the marker only.
//! 3. Rejects a request older than the approval window, from a person who is not a current user
//!    of the tenant, or for a job that ended.
//! 4. Asks the policy engine for the proof of authority, with the allowlist read now, by numeric
//!    id, the level of the repository and the person who asked for the job. Nothing about a
//!    refusal is explained.
//! 5. Calls the engine, which checks the roles the principal holds now and the guard again.
//! 6. Writes a marker, `decision.applied` or `decision.rejected`, under an id derived from the
//!    request's, with a fixed code and no text of the person.
//!
//! # Letting a blocked stage run go again
//!
//! The guard `G_BLOCK_CLEARED_RERUN` has three alternatives: the capability re-probe passed, the
//! missing dependency is available, or a person recorded a decision that the stage run was waiting
//! for. The third the engine reads from what it stored. The first is a fact about the world that
//! only a probe can give, and the worker has no capability probe adapter yet (the seam is on the
//! list of blocked adapters), so [`NoReprobe`] answers that the re-probe did not pass. Until a
//! real probe exists, a block that is not a missing decision cannot be cleared by this verb, and
//! the way out is `rework` (S15) or `cancel`. The verb never asserts a fact for the operator.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{
    AuditEventId, CausationId, CorrelationId, JobId, PrincipalId, StageRunId, TenantId,
};
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::{
    ActionDenialReason, ActionVerdict, Actor as PolicyActor, ActorKind,
};
use factory_domain::policy::decision::GithubUserId;
use factory_domain::policy::solo::ConfirmationWord;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus, Status as _};
use factory_domain::values::{HumanText, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::Clock;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, ConstraintRule, NewAuditEvent,
    PrincipalKind, Store, StoreError,
};
use factory_workflow::commands::{
    Actor, Decision, RecordProjectBuildCodeDecision, RecordWarningDecision, SoloRequest, Subject,
};
use factory_workflow::engine::{Engine, EngineError};
use factory_workflow::gates::scope::own_build_code::{BuildScript, EVIDENCE_KEY};
use factory_workflow::gates::supply_chain::approval::{
    BUILD_CODE_ACTION, Request, WARNING_ACTION, authorize_build_code, authorize_unblock,
    authorize_warning,
};
use factory_workflow::stages::approval::ApprovalSources;
use factory_workflow::stages::validation::EVIDENCE;
use tracing::Instrument as _;

use crate::decision_signing::{
    DecisionKeys, MarkerSigning, StageSigning, StageSubject, actor_text, read_stage_subject,
};
use crate::decisions::{APPLIED, JUNK_PER_PASS, Marked, REJECTED, Reason, counted_marker};
use crate::reading::Reader;
use crate::telemetry::job_span_of;

/// The text the API puts before the person's reason.
const REQUEST_PREFIX: &str = "requested: ";

/// The audit action of a request about a stage run (written by the API).
pub const REQUESTED: &str = "decision.stage_requested";

/// The highest number of a warning a request carries.
pub const MAX_WARNING: u32 = 10_000;

/// The longest repository path a request carries, in bytes.
pub const MAX_PATH_BYTES: usize = 180;

/// The audit records read in one page.
const PAGE: u32 = 500;
/// The most pages one pass reads for one tenant.
const PAGES_PER_PASS: usize = 20;
/// The most signed requests one pass deals with for one tenant.
pub const PER_PASS: usize = 50;
/// The most records that are not requests this step trusts that a scan keeps in memory.
const JUNK_KEPT: usize = 10_000;
/// The most passes a request that keeps failing for a reason that may pass is tried.
pub const MAX_TRIES: u32 = 20;

// ------------------------------------------------------------------------------------------
// The record the API writes
// ------------------------------------------------------------------------------------------

/// What a person asks about a stage run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageVerb {
    /// Lets a blocked stage run go again (`S17`).
    Unblock,
    /// Accepts one file of the project's own new build code, with the content a reviewer read.
    ApproveProjectBuildCode,
    /// Decides about one open translation warning of an approval request.
    AckTranslationWarning,
}

impl StageVerb {
    /// Every verb.
    pub const ALL: [StageVerb; 3] = [
        Self::Unblock,
        Self::ApproveProjectBuildCode,
        Self::AckTranslationWarning,
    ];

    /// The word a person types.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unblock => "unblock",
            Self::ApproveProjectBuildCode => "approve-project-build-code",
            Self::AckTranslationWarning => "ack-translation-warning",
        }
    }

    /// The row of the action table (`policies/approval.yaml`) that authorizes the verb.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Unblock => factory_workflow::gates::supply_chain::approval::UNBLOCK_ACTION,
            Self::ApproveProjectBuildCode => BUILD_CODE_ACTION,
            Self::AckTranslationWarning => WARNING_ACTION,
        }
    }

    /// The verb a word names, or `None`.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.as_str() == word)
    }
}

/// What a request about a stage run says, as the subject of the audit record. The API writes it
/// and the worker reads it, so the one grammar is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageFields {
    /// What is asked.
    pub verb: StageVerb,
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: Option<StageRunId>,
    /// A repository path, for the verbs that name a file.
    pub path: Option<String>,
    /// The start of a content hash, 12 to 64 lower case hexadecimal digits.
    pub digest: Option<String>,
    /// The number of a warning, counted from 1.
    pub index: Option<u32>,
    /// The word of the confirmation phrase of the solo mode (ADR 0022): 16 lowercase hex digits,
    /// when the person typed a phrase. Never on `unblock`. Without it the subject is the six words
    /// it always was.
    pub confirm: Option<String>,
}

/// The longest path of a request that carries a confirmation word: ten bytes less than
/// [`MAX_PATH_BYTES`], so that the audit subject with ` confirm=` and 16 hex digits stays within
/// the 500 characters of the column (`subject` 382 - 10 + 25, plus 103 fixed, is 500).
pub const MAX_PATH_BYTES_WITH_CONFIRM: usize = MAX_PATH_BYTES - 10;

impl StageFields {
    /// The subject text of the audit record.
    #[must_use]
    pub fn subject(&self) -> String {
        let mut subject = format!(
            "verb={} job={} run={} path={} digest={} index={}",
            self.verb.as_str(),
            self.job.as_text(),
            self.stage_run
                .map_or_else(|| "none".to_owned(), |run| run.as_text()),
            self.path.as_deref().unwrap_or("none"),
            self.digest.as_deref().unwrap_or("none"),
            self.index
                .map_or_else(|| "none".to_owned(), |index| index.to_string()),
        );
        if let Some(confirm) = &self.confirm {
            subject.push_str(" confirm=");
            subject.push_str(confirm);
        }
        subject
    }

    /// Reads a subject back and accepts it only if it is exactly the text [`Self::subject`] writes
    /// for what it says.
    #[must_use]
    pub fn parse_canonical(subject: &str) -> Option<Self> {
        let mut words = subject.split(' ');
        let verb = StageVerb::parse(words.next()?.strip_prefix("verb=")?)?;
        let job = JobId::parse(words.next()?.strip_prefix("job=")?).ok()?;
        let run = words.next()?.strip_prefix("run=")?;
        let path = words.next()?.strip_prefix("path=")?;
        let digest = words.next()?.strip_prefix("digest=")?;
        let index = words.next()?.strip_prefix("index=")?;
        let confirm = match words.next() {
            Some(word) => Some(word.strip_prefix("confirm=")?.to_owned()),
            None => None,
        };
        if words.next().is_some() {
            return None;
        }
        let fields = Self {
            verb,
            job,
            stage_run: (run != "none")
                .then(|| StageRunId::parse(run).ok())
                .flatten(),
            path: (path != "none").then(|| path.to_owned()),
            digest: (digest != "none").then(|| digest.to_owned()),
            index: if index == "none" {
                None
            } else {
                Some(index.parse().ok()?)
            },
            confirm,
        };
        (fields.is_well_formed() && fields.subject() == subject).then_some(fields)
    }

    /// True when the words are the ones the verb needs and no others, and each is well formed.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let digest_ok = |digest: &str| {
            (12..=64).contains(&digest.len())
                && digest
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        };
        let longest = if self.confirm.is_some() {
            MAX_PATH_BYTES_WITH_CONFIRM
        } else {
            MAX_PATH_BYTES
        };
        let path_ok = |path: &str| {
            !path.is_empty()
                && path.len() <= longest
                && path
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
                && !path.starts_with('/')
                && path.split('/').all(|part| !part.is_empty() && part != "..")
        };
        let words_of_the_verb = match self.verb {
            StageVerb::Unblock => {
                self.stage_run.is_some()
                    && self.path.is_none()
                    && self.digest.is_none()
                    && self.index.is_none()
            }
            // The file and the start of its hash are the two words a reviewer gives; the stage
            // run is optional, as for a decision on a dependency.
            StageVerb::ApproveProjectBuildCode => {
                self.path.is_some() && self.digest.is_some() && self.index.is_none()
            }
            // The approval stage run and the number of the warning, counted from 1.
            StageVerb::AckTranslationWarning => {
                self.stage_run.is_some()
                    && self.path.is_none()
                    && self.digest.is_none()
                    && self
                        .index
                        .is_some_and(|number| (1..=MAX_WARNING).contains(&number))
            }
        };
        // A confirmation word is 16 lowercase hex digits, and `unblock` takes none.
        let confirm_ok = match (self.verb, self.confirm.as_deref()) {
            (_, None) => true,
            (StageVerb::Unblock, Some(_)) => false,
            (_, Some(word)) => ConfirmationWord::parse(word).is_some(),
        };
        words_of_the_verb
            && confirm_ok
            && self.path.as_deref().is_none_or(path_ok)
            && self.digest.as_deref().is_none_or(digest_ok)
    }
}

// ------------------------------------------------------------------------------------------
// The re-probe
// ------------------------------------------------------------------------------------------

/// Whether a capability re-probe of the environment of a blocked stage run passes now.
///
/// This is the first alternative of the guard `G_BLOCK_CLEARED_RERUN`. It is a fact about the
/// world, and a person's word is not a probe: the operator never asserts it.
#[async_trait]
pub trait Reprobe: Send + Sync {
    /// True when the probe was run again for this stage run and passed.
    async fn passed(&self, tenant: TenantId, job: JobId, stage_run: StageRunId) -> bool;
}

/// The re-probe the worker has until a capability probe adapter exists: it does not pass. A block
/// that is not a missing decision is therefore not cleared by `unblock`, and says so.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReprobe;

#[async_trait]
impl Reprobe for NoReprobe {
    async fn passed(&self, _: TenantId, _: JobId, _: StageRunId) -> bool {
        false
    }
}

/// A re-probe that answers what it was told, for a test. It is a stand-in and is named as one.
#[derive(Debug, Clone, Copy)]
pub struct StandInReprobe(pub bool);

#[async_trait]
impl Reprobe for StandInReprobe {
    async fn passed(&self, _: TenantId, _: JobId, _: StageRunId) -> bool {
        self.0
    }
}

// ------------------------------------------------------------------------------------------
// The step
// ------------------------------------------------------------------------------------------

/// What [`StageDecisions`] is built from.
pub struct StageDecisionsDeps {
    /// The engine the worker loop runs.
    pub engine: Arc<Engine>,
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The artifact store, to read the evidence a blocked stage run stored.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// The tenants the worker serves.
    pub tenants: Vec<TenantId>,
    /// The evaluators of the policies.
    pub policy: Arc<PolicyEngine>,
    /// The hash of the policy bundle in force, for the markers.
    pub policy_hash: Sha256Digest,
    /// The allowlist now, the level of the repository and the requester of the job.
    pub sources: Arc<dyn ApprovalSources>,
    /// The capability re-probe.
    pub reprobe: Arc<dyn Reprobe>,
    /// The redactor of the process. A reason goes through it before the engine sees it: the
    /// engine has none.
    pub redactor: Arc<Redactor>,
    /// The time now.
    pub clock: Arc<dyn Clock>,
    /// How long a request stays good.
    pub max_age: Duration,
    /// The keys the API signs its requests with.
    pub keys: Arc<DecisionKeys>,
}

/// A request that has no marker yet.
#[derive(Debug, Clone)]
struct Pending {
    id: AuditEventId,
    sequence: u64,
    principal: PrincipalId,
    fields: StageFields,
    reason: String,
    requested_at: Timestamp,
    failures: u32,
    actor_github_id: Option<u64>,
}

/// The audit log of one tenant as far as this step has read it.
#[derive(Default)]
struct Scan {
    cursor: u64,
    pending: BTreeMap<u64, Pending>,
    /// Records that are not requests this module trusts, by sequence, with the code to mark.
    refused: BTreeMap<u64, (AuditEventId, Reason)>,
}

/// What one pass of one request came to.
enum Verdict {
    Done(Marked),
    Later,
}

/// A source of facts could not answer. Nothing was decided.
struct Unreadable;

/// What reading the job for a request about build code found.
enum Found {
    /// The blocked validation run, and the one file of build code it awaits that the words select.
    Run {
        stage_run: StageRunId,
        script: BuildScript,
    },
    /// The job has no blocked validation run.
    NoRun,
    /// The run awaits no such file, or the words match more than one.
    NotAwaited,
}

/// The shortest reason accepted, in characters.
const MIN_REASON_CHARS: usize = factory_workflow::gates::supply_chain::approval::MIN_REASON_CHARS;

fn already() -> Marked {
    Marked::Applied("The engine had applied this decision already.".to_owned())
}

/// Applies the requests about a stage run.
pub struct StageDecisions {
    deps: StageDecisionsDeps,
    reader: Reader,
    scans: Mutex<BTreeMap<TenantId, Scan>>,
}

impl StageDecisions {
    /// The step over its collaborators.
    #[must_use]
    pub fn new(deps: StageDecisionsDeps) -> Self {
        let reader = Reader::new(Arc::clone(&deps.store), Arc::clone(&deps.artifacts));
        Self {
            deps,
            reader,
            scans: Mutex::new(BTreeMap::new()),
        }
    }

    /// One pass for one tenant.
    pub async fn pass(&self, tenant: TenantId) {
        if !self.read_new_records(tenant).await {
            return;
        }
        let (refused, pending): (Vec<(u64, AuditEventId, Reason)>, Vec<Pending>) = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or_else(
                || (Vec::new(), Vec::new()),
                |scan| {
                    let refused: Vec<_> = scan
                        .refused
                        .iter()
                        .take(JUNK_PER_PASS)
                        .map(|(sequence, (id, reason))| (*sequence, *id, *reason))
                        .collect();
                    (
                        refused,
                        scan.pending.values().take(PER_PASS).cloned().collect(),
                    )
                },
            )
        };
        for (sequence, id, reason) in refused {
            if self.mark_record(tenant, id, reason).await {
                self.with_scan(tenant, |scan| {
                    scan.refused.remove(&sequence);
                });
            }
        }
        for request in pending {
            let span = job_span_of(&*self.deps.store, tenant, request.fields.job).await;
            self.deal_with(tenant, request).instrument(span).await;
        }
    }

    /// One request: judge it, apply it, and write the marker that ends it.
    async fn deal_with(&self, tenant: TenantId, request: Pending) {
        let (verdict, request) = self.decide(tenant, request).await;
        let marked = match verdict {
            Verdict::Done(marked) => marked,
            Verdict::Later if request.failures + 1 >= MAX_TRIES => {
                Marked::Rejected(Reason::GaveUp.text())
            }
            Verdict::Later => {
                self.with_scan(tenant, |scan| {
                    if let Some(held) = scan.pending.get_mut(&request.sequence) {
                        held.failures += 1;
                    }
                });
                return;
            }
        };
        if self.mark(tenant, &request, &marked).await {
            self.with_scan(tenant, |scan| {
                scan.pending.remove(&request.sequence);
            });
        }
    }

    fn with_scan(&self, tenant: TenantId, change: impl FnOnce(&mut Scan)) {
        let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
        change(scans.entry(tenant).or_default());
    }

    // ---- reading the log ------------------------------------------------------------------

    async fn read_new_records(&self, tenant: TenantId) -> bool {
        let mut cursor = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or(0, |scan| scan.cursor)
        };
        for _ in 0..PAGES_PER_PASS {
            let page = {
                let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
                    return false;
                };
                let read = tx.read_audit(AuditFilter::Tenant, cursor, PAGE).await;
                let _ = tx.rollback().await;
                match read {
                    Ok(page) => page,
                    Err(error) => {
                        tracing::warn!(%error, "the audit log cannot be read for stage decisions");
                        return false;
                    }
                }
            };
            let count = page.len();
            self.with_scan(tenant, |scan| {
                for record in page {
                    cursor = record.sequence;
                    scan.cursor = record.sequence;
                    match record.event.action.as_str() {
                        REQUESTED => match requested_from(tenant, &record, &self.deps.keys) {
                            Ok(pending) => {
                                scan.pending.insert(record.sequence, pending);
                            }
                            Err(reason) => {
                                if scan.refused.len() < JUNK_KEPT {
                                    scan.refused
                                        .insert(record.sequence, (record.event.id, reason));
                                }
                            }
                        },
                        APPLIED | REJECTED => {
                            // Only a marker the worker signed ends a request (RR-8).
                            if let Some(Some(id)) = counted_marker(tenant, &record, &self.deps.keys)
                            {
                                scan.pending.retain(|_, pending| pending.id != id);
                                scan.refused.retain(|_, (refused, _)| *refused != id);
                            }
                        }
                        _ => {}
                    }
                }
            });
            if u32::try_from(count).unwrap_or(u32::MAX) < PAGE {
                return true;
            }
        }
        true
    }

    // ---- deciding -------------------------------------------------------------------------

    async fn decide(&self, tenant: TenantId, mut request: Pending) -> (Verdict, Pending) {
        let verdict = self.judge(tenant, &mut request).await;
        (verdict, request)
    }

    async fn judge(&self, tenant: TenantId, request: &mut Pending) -> Verdict {
        let fields = request.fields.clone();
        let command = CausationId::from_uuid(request.id.as_uuid());

        // 1. Applied already? A worker that stopped after the engine's commit and before the
        // marker finds the engine's record of this command and writes the marker only.
        match self
            .deps
            .engine
            .command_applied(tenant, fields.job, command)
            .await
        {
            Ok(true) => return Verdict::Done(already()),
            Ok(false) => {}
            Err(EngineError::NotFound) => return Verdict::Done(Reason::NoJob.into()),
            Err(_) => return Verdict::Later,
        }

        // 2. Still good? A request is for the world as the person saw it.
        let expired = request
            .requested_at
            .checked_add(self.deps.max_age)
            .is_none_or(|end| end <= self.deps.clock.now());
        if expired {
            return Verdict::Done(Reason::Expired.into());
        }

        // 3. Who asks, and are they a current user of the tenant?
        let (github_id, login) = match self.human_of(tenant, request.principal).await {
            Ok(Some(found)) => found,
            Ok(None) => return Verdict::Done(Reason::NotCurrentUser.into()),
            Err(Unreadable) => return Verdict::Later,
        };
        request.actor_github_id = Some(github_id);

        // 4. Is the job open to a decision?
        let (repository, correlation) = match self.job_facts(tenant, fields.job).await {
            Ok(Some((status, _, _))) if status.is_terminal() => {
                return Verdict::Done(Reason::JobEnded.into());
            }
            Ok(Some((_, repository, correlation))) => (repository, correlation),
            Ok(None) => return Verdict::Done(Reason::NoJob.into()),
            Err(Unreadable) => return Verdict::Later,
        };
        // The stage run: the one the person named, or the blocked validation run of the job. For
        // build code the run also gives the file the words select, from its own stored evidence.
        let (stage_run, script) = match fields.verb {
            StageVerb::Unblock | StageVerb::AckTranslationWarning => match fields.stage_run {
                Some(named) => (named, None),
                None => return Verdict::Done(Reason::NoStageRun.into()),
            },
            StageVerb::ApproveProjectBuildCode => {
                match self.awaited_script(tenant, &fields).await {
                    Ok(Found::Run { stage_run, script }) => (stage_run, Some(script)),
                    Ok(Found::NoRun) => return Verdict::Done(Reason::WrongState.into()),
                    Ok(Found::NotAwaited) => return Verdict::Done(Reason::NotAwaited.into()),
                    Err(Unreadable) => return Verdict::Later,
                }
            }
        };

        // 5. The proof of authority from the policy engine, with the allowlist read now.
        let identity = factory_workflow::handlers::RunIdentity {
            tenant,
            job: fields.job,
            correlation,
            stage_run,
            kind: factory_domain::vocabulary::StageKind::Validation,
        };
        let (Ok(allowlist), Ok(level), Ok(requester)) = (
            self.deps.sources.allowlist(tenant).await,
            self.deps.sources.level(tenant, fields.job).await,
            self.deps.sources.requester(&identity).await,
        ) else {
            return Verdict::Later;
        };
        let Some(approver) = GithubUserId::new(github_id) else {
            return Verdict::Done(Reason::NotAuthorized.into());
        };
        let actor = PolicyActor {
            github_user_id: approver,
            login: &login,
            kind: ActorKind::User,
            github_permission: None,
            author_association: None,
        };
        let now = self.deps.clock.now();
        // The solo mode (ADR 0022): the facts of the repository now, turned into the solo fact by
        // the one function of the policy that computes it. `unblock` is not an approval action,
        // so the fact changes nothing for it.
        let Ok(inputs) = self.deps.sources.solo_inputs(tenant, fields.job, now).await else {
            return Verdict::Later;
        };
        let solo = self
            .deps
            .policy
            .authority
            .solo_fact(inputs.single_maintainer, inputs.approver_count);
        let solo_request = SoloRequest {
            requested_at: request.requested_at,
            confirmation: fields.confirm.as_deref().and_then(ConfirmationWord::parse),
        };
        let authority_request = Request {
            policy: &self.deps.policy.authority,
            level,
            tenant: &tenant,
            repository: &repository,
            actor: &actor,
            allowlist: &allowlist,
            now: &now,
            requester: GithubUserId::new(requester),
            risk_tier: RiskTier::Medium,
            protected_path_change: false,
            sensitive_file_change: false,
            solo,
        };
        let verdict = match fields.verb {
            StageVerb::Unblock => authorize_unblock(&authority_request),
            StageVerb::ApproveProjectBuildCode => authorize_build_code(&authority_request),
            StageVerb::AckTranslationWarning => authorize_warning(&authority_request),
        };
        // The requester who holds the designation learns that the solo mode does not apply; any
        // other refusal is never explained, and a policy that needs no person for the action is
        // not a reason to accept one.
        let proof = match verdict {
            ActionVerdict::Authorized(proof) => proof,
            ActionVerdict::Denied(denial) if denial.reason == ActionDenialReason::SelfApproval => {
                return Verdict::Done(Reason::IneligibleApprover.into());
            }
            ActionVerdict::Denied(_) | ActionVerdict::NoHumanNeeded { .. } => {
                return Verdict::Done(Reason::NotAuthorized.into());
            }
        };

        // 6. The engine applies it, and checks the roles and the guard again.
        let actor = Actor {
            tenant,
            principal: request.principal,
            command,
        };
        match (fields.verb, script) {
            (StageVerb::Unblock, _) => {
                // Only a blocked stage run is let go. The engine would say the guard does not hold
                // for any other, which is true and is the wrong answer to give a person.
                match self.status_of(tenant, fields.job, stage_run).await {
                    Ok(Some(StageRunStatus::Blocked)) => {}
                    Ok(Some(_)) => return Verdict::Done(Reason::WrongState.into()),
                    Ok(None) => return Verdict::Done(Reason::NoStageRun.into()),
                    Err(Unreadable) => return Verdict::Later,
                }
                let reprobed = self
                    .deps
                    .reprobe
                    .passed(tenant, fields.job, stage_run)
                    .await;
                let applied = self
                    .deps
                    .engine
                    .decide(
                        &actor,
                        Subject {
                            job: fields.job,
                            stage_run,
                        },
                        Decision::UnblockRerun {
                            capability_reprobe_passed: reprobed,
                            dependency_now_available: false,
                        },
                    )
                    .await;
                match applied {
                    Ok(()) => Verdict::Done(Marked::Applied(
                        "The blocked stage run was let go again.".to_owned(),
                    )),
                    Err(error) => engine_verdict(error),
                }
            }
            (StageVerb::ApproveProjectBuildCode, Some(script)) => {
                // The reason: at least ten characters, and redacted, because the engine has no
                // redactor and the document it stores is read by people and by the gate.
                let Some(reason) = self.reason_of(&request.reason) else {
                    return Verdict::Done(Reason::Incomplete.into());
                };
                let applied = self
                    .deps
                    .engine
                    .record_project_build_code_decision(
                        &actor,
                        RecordProjectBuildCodeDecision {
                            stage: Subject {
                                job: fields.job,
                                stage_run,
                            },
                            proof,
                            script,
                            reason,
                            solo: Some(solo_request.clone()),
                        },
                    )
                    .await;
                match applied {
                    Ok(_) => Verdict::Done(Marked::Applied(
                        "The decision on the build code was recorded.".to_owned(),
                    )),
                    Err(error) => engine_verdict(error),
                }
            }
            (StageVerb::AckTranslationWarning, _) => {
                // The reason: at least ten characters, and redacted, as for a decision on code.
                let Some(reason) = self.reason_of(&request.reason) else {
                    return Verdict::Done(Reason::Incomplete.into());
                };
                let Some(warning) = fields.index else {
                    return Verdict::Done(Reason::Incomplete.into());
                };
                let applied = self
                    .deps
                    .engine
                    .record_warning_decision(
                        &actor,
                        RecordWarningDecision {
                            stage: Subject {
                                job: fields.job,
                                stage_run,
                            },
                            proof,
                            warning,
                            reason,
                            solo: Some(solo_request.clone()),
                        },
                    )
                    .await;
                match applied {
                    Ok(_) => Verdict::Done(Marked::Applied(
                        "The decision about the translation warning was recorded.".to_owned(),
                    )),
                    Err(error) => engine_verdict(error),
                }
            }
            (StageVerb::ApproveProjectBuildCode, None) => Verdict::Done(Reason::Refused.into()),
        }
    }

    /// The person's reason, redacted, when it is long enough.
    fn reason_of(&self, reason: &str) -> Option<HumanText> {
        if reason.trim().chars().count() < MIN_REASON_CHARS {
            return None;
        }
        // The redactor failed: raw text is never written because of that.
        let redacted = self.deps.redactor.redact_str(reason.trim()).ok()?;
        HumanText::parse(redacted.output.as_ref()).ok()
    }

    // ---- reads ----------------------------------------------------------------------------

    /// The numeric id and login of the person behind a principal, if it is a current human.
    async fn human_of(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Option<(u64, String)>, Unreadable> {
        let mut tx = self
            .deps
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = tx.get_principal(principal).await;
        let _ = tx.rollback().await;
        match found {
            Ok(principal) => Ok(match (principal.kind, principal.disabled_at) {
                (PrincipalKind::Human { github_user_id }, None) => Some((
                    github_user_id,
                    principal
                        .login
                        .unwrap_or_else(|| format!("user-{github_user_id}")),
                )),
                _ => None,
            }),
            Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(Unreadable),
        }
    }

    /// The blocked validation run of the job and the file of build code its stored evidence
    /// awaits that the words select: the path, and the start of the hash of its content.
    async fn awaited_script(
        &self,
        tenant: TenantId,
        fields: &StageFields,
    ) -> Result<Found, Unreadable> {
        let (Some(path), Some(prefix)) = (fields.path.as_deref(), fields.digest.as_deref()) else {
            return Ok(Found::NotAwaited);
        };
        let mut tx = self
            .deps
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let outcome = async {
            let runs = tx
                .list_stage_runs(fields.job)
                .await
                .map_err(|_| Unreadable)?;
            let run = runs
                .iter()
                .filter(|candidate| {
                    candidate.value.kind == StageKind::Validation
                        && candidate.value.status == StageRunStatus::Blocked
                        && fields
                            .stage_run
                            .is_none_or(|named| named == candidate.value.id)
                })
                .max_by_key(|candidate| candidate.value.run_number);
            let Some(run) = run else {
                return Ok(Found::NoRun);
            };
            let outputs = Reader::outputs(&mut *tx, run.value.id)
                .await
                .map_err(|_| Unreadable)?;
            let Some(hash) = outputs.get(EVIDENCE) else {
                return Ok(Found::NoRun);
            };
            let bytes = self
                .reader
                .bytes(&mut *tx, tenant, hash)
                .await
                .map_err(|_| Unreadable)?;
            let awaiting: Vec<BuildScript> = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .filter(|document| {
                    document.get("kind").and_then(serde_json::Value::as_str) == Some(EVIDENCE)
                })
                .and_then(|document| document.get(EVIDENCE_KEY).cloned())
                .and_then(|section| section.get("awaiting").cloned())
                .and_then(|list| list.as_array().cloned())
                .map(|entries| entries.iter().filter_map(BuildScript::from_json).collect())
                .unwrap_or_default();
            // The path is whole, and the hash is the start the person gave. The person's words
            // select an entry of what the run stored; they are never the subject.
            let mut selected = awaiting
                .into_iter()
                .filter(|script| script.path == path && script.sha256.hex().starts_with(prefix));
            Ok(match (selected.next(), selected.next()) {
                (Some(script), None) => Found::Run {
                    stage_run: run.value.id,
                    script,
                },
                _ => Found::NotAwaited,
            })
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }

    /// The status of a stage run of the job, as it is now, or `None` for a run the job does not
    /// have.
    async fn status_of(
        &self,
        tenant: TenantId,
        job: JobId,
        stage_run: StageRunId,
    ) -> Result<Option<StageRunStatus>, Unreadable> {
        let mut tx = self
            .deps
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let found = tx.get_stage_run(stage_run).await;
        let _ = tx.rollback().await;
        match found {
            Ok(run) if run.value.job_id == job => Ok(Some(run.value.status)),
            Ok(_) | Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(Unreadable),
        }
    }

    /// The status of the job, the full name of its repository and its correlation id, as they
    /// are now.
    async fn job_facts(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<Option<(JobStatus, String, CorrelationId)>, Unreadable> {
        let mut tx = self
            .deps
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
                stored.value.correlation_id,
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

    // ---- markers --------------------------------------------------------------------------

    /// Writes the marker of a request that was dealt with. True when it is written (or exists).
    async fn mark(&self, tenant: TenantId, request: &Pending, marked: &Marked) -> bool {
        let (action, outcome, reason) = match marked {
            Marked::Applied(text) => (APPLIED, AuditDecision::Allow, text.clone()),
            Marked::Rejected(text) => (REJECTED, AuditDecision::Deny, (*text).to_owned()),
        };
        let code = match marked {
            Marked::Applied(_) => "applied",
            Marked::Rejected(text) => Reason::code_of(text),
        };
        tracing::info!(code, "a decision about a stage run was dealt with");
        let subject = format!(
            "decision={} verb={} job={} code={} actor={} allowlist=none",
            request.id.as_uuid().hyphenated(),
            request.fields.verb.as_str(),
            request.fields.job.as_text(),
            code,
            request
                .actor_github_id
                .map_or_else(|| "none".to_owned(), |id| id.to_string()),
        );
        self.write_marker(
            tenant,
            request.id,
            Some((request.fields.job, request.fields.stage_run)),
            MarkerText {
                action,
                decision: outcome,
                subject,
                reason,
            },
        )
        .await
    }

    /// The marker of a record that was refused before it was read.
    async fn mark_record(&self, tenant: TenantId, id: AuditEventId, reason: Reason) -> bool {
        tracing::info!(
            code = reason.code(),
            "a request about a stage run was rejected"
        );
        let subject = format!(
            "decision={} code={} actor=none allowlist=none",
            id.as_uuid().hyphenated(),
            reason.code()
        );
        self.write_marker(
            tenant,
            id,
            None,
            MarkerText {
                action: REJECTED,
                decision: AuditDecision::Deny,
                subject,
                reason: reason.text().to_owned(),
            },
        )
        .await
    }

    async fn write_marker(
        &self,
        tenant: TenantId,
        request: AuditEventId,
        job: Option<(JobId, Option<StageRunId>)>,
        text: MarkerText,
    ) -> bool {
        let MarkerText {
            action,
            decision,
            subject,
            reason,
        } = text;
        let Ok(actor) = Slug::parse("worker.stage-decisions").map(AuditActor::System) else {
            return false;
        };
        // The marker carries the worker's word (RR-8), made over the id it is written under.
        let marker = self.deps.keys.marker_id(request);
        let subject = self.deps.keys.signed_marker_subject(&MarkerSigning {
            tenant,
            event: marker,
            action,
            actor: &actor_text(&actor),
            subject: &subject,
        });
        let Ok(action) = AuditAction::new(action) else {
            return false;
        };
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            return false;
        };
        let found = match job {
            Some((job, run)) => tx
                .get_job(job)
                .await
                .ok()
                .map(|stored| (job, run, stored.value.correlation_id)),
            None => None,
        };
        let (job, stage_run, correlation_id) = match found {
            Some((job, run, correlation)) => (Some(job), run, correlation),
            None => (None, None, CorrelationId::from_uuid(request.as_uuid())),
        };
        let event = NewAuditEvent {
            id: marker,
            actor,
            action,
            subject,
            decision,
            reason,
            policy_hash: self.deps.policy_hash.clone(),
            job,
            stage_run,
            correlation_id,
        };
        match tx.record_audit(event).await {
            // A marker that exists with other words is a marker: the request is dealt with.
            Ok(_) | Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {}
            Err(_) => {
                let _ = tx.rollback().await;
                return false;
            }
        }
        tx.commit().await.is_ok()
    }
}

/// The words of a marker.
struct MarkerText {
    action: &'static str,
    decision: AuditDecision,
    subject: String,
    reason: String,
}

/// What an engine refusal means for the request, in the fixed words of [`Reason`].
fn engine_verdict(error: EngineError) -> Verdict {
    match error {
        EngineError::Duplicate => Verdict::Done(already()),
        EngineError::NotAuthorized(_) => Verdict::Done(Reason::NotAuthorized.into()),
        EngineError::SoloRefused(refusal) => Verdict::Done(Reason::of_solo(refusal).into()),
        EngineError::GuardUnmet(_) => Verdict::Done(Reason::NotCleared.into()),
        EngineError::Refused(_) | EngineError::Illegal(_) => {
            Verdict::Done(Reason::WrongState.into())
        }
        EngineError::NotFound => Verdict::Done(Reason::NoStageRun.into()),
        _ => Verdict::Later,
    }
}

/// A request about a stage run, read from its audit record. `Err` for a record that is not a
/// request this module trusts: the record is rejected with a marker and stops being a candidate.
///
/// The row is untrusted input: any login of the application group can write an audit record with
/// any words in it. It is accepted only if the actor is a human principal, the subject is exactly
/// the canonical text the API writes, the word at its end is the one only the API can make
/// (AUT-12), and the columns for the job and the stage run say what the subject says.
fn requested_from(
    tenant: TenantId,
    record: &factory_ports::store::AuditRecord,
    keys: &DecisionKeys,
) -> Result<Pending, Reason> {
    let AuditActor::Human(principal) = record.event.actor.clone() else {
        return Err(Reason::Malformed);
    };
    let (fields, requested_at, word) = match read_stage_subject(&record.event.subject) {
        Some(StageSubject::Signed {
            fields,
            requested_at,
            word,
        }) => (fields, requested_at, word),
        Some(StageSubject::Unsigned(_)) => return Err(Reason::NotSigned),
        None => return Err(Reason::Malformed),
    };
    let signing = StageSigning {
        tenant,
        actor: principal,
        event: record.event.id,
        requested_at: &requested_at,
        fields: &fields,
    };
    if !keys.verify_stage(&signing, &word) {
        return Err(Reason::NotSigned);
    }
    if record.event.job != Some(fields.job) || record.event.stage_run != fields.stage_run {
        return Err(Reason::Malformed);
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unblock() -> StageFields {
        StageFields {
            verb: StageVerb::Unblock,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x1111)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            path: None,
            digest: None,
            index: None,
            confirm: None,
        }
    }

    #[test]
    fn a_subject_reads_back_as_it_was_written() {
        let written = unblock();
        assert_eq!(
            StageFields::parse_canonical(&written.subject()),
            Some(written)
        );
    }

    #[test]
    fn a_subject_that_is_not_exactly_the_canonical_text_is_not_read() {
        let canonical = unblock().subject();
        for changed in [
            canonical.replace("verb=unblock", "verb=override"),
            canonical.replace("verb=unblock", "verb=Unblock"),
            format!("{canonical} extra=1"),
            canonical.replace(' ', "  "),
            canonical.replace("run=", "run=x"),
            canonical.replace("path=none", "path=build.rs"),
            canonical.replace("digest=none", "digest=abababababab"),
            canonical.replace("index=none", "index=1"),
            canonical.replace("index=none", "index=-1"),
            // A request to unblock names the stage run.
            canonical.replace(&unblock().stage_run.expect("a run").as_text(), "none"),
        ] {
            assert_eq!(StageFields::parse_canonical(&changed), None, "{changed}");
        }
    }

    fn build_code() -> StageFields {
        StageFields {
            verb: StageVerb::ApproveProjectBuildCode,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x1111)),
            stage_run: None,
            path: Some("crates/a/build.rs".to_owned()),
            digest: Some("ab".repeat(8)),
            index: None,
            confirm: None,
        }
    }

    #[test]
    fn a_request_about_build_code_names_the_file_and_the_start_of_its_hash() {
        let written = build_code();
        assert_eq!(
            StageFields::parse_canonical(&written.subject()),
            Some(written.clone())
        );
        let with_run = StageFields {
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            ..written.clone()
        };
        assert_eq!(
            StageFields::parse_canonical(&with_run.subject()),
            Some(with_run)
        );
        // Neither word may be missing, and neither may be malformed.
        let canonical = written.subject();
        for changed in [
            canonical.replace("path=crates/a/build.rs", "path=none"),
            canonical.replace(&"ab".repeat(8), "none"),
            canonical.replace("path=crates/a/build.rs", "path=../build.rs"),
            canonical.replace("path=crates/a/build.rs", "path=/etc/passwd"),
            canonical.replace("path=crates/a/build.rs", "path=a//build.rs"),
            canonical.replace(&"ab".repeat(8), "ABABABABABABABAB"),
            canonical.replace(&"ab".repeat(8), "abab"),
            canonical.replace("index=none", "index=1"),
        ] {
            assert_eq!(StageFields::parse_canonical(&changed), None, "{changed}");
        }
        let longest = StageFields {
            path: Some("a".repeat(MAX_PATH_BYTES)),
            digest: Some("f".repeat(64)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            ..written
        };
        assert!(longest.is_well_formed());
        // " at=" + 30 + " mac=" + 64
        assert!(longest.subject().len() + 4 + 30 + 5 + 64 <= 500);
    }

    fn warning() -> StageFields {
        StageFields {
            verb: StageVerb::AckTranslationWarning,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x1111)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            path: None,
            digest: None,
            index: Some(2),
            confirm: None,
        }
    }

    #[test]
    fn a_request_about_a_warning_names_the_approval_run_and_the_number() {
        let written = warning();
        assert_eq!(
            StageFields::parse_canonical(&written.subject()),
            Some(written.clone())
        );
        let canonical = written.subject();
        for changed in [
            canonical.replace("index=2", "index=none"),
            canonical.replace("index=2", "index=0"),
            canonical.replace("index=2", "index=-1"),
            canonical.replace("index=2", "index=10001"),
            canonical.replace("index=2", "index=02x"),
            canonical.replace("path=none", "path=build.rs"),
            canonical.replace(&written.stage_run.expect("a run").as_text(), "none"),
        ] {
            assert_eq!(StageFields::parse_canonical(&changed), None, "{changed}");
        }
    }

    #[test]
    fn the_verb_names_the_action_row_of_the_policy() {
        assert_eq!(
            StageVerb::AckTranslationWarning.action(),
            "acknowledge_documentation_warning"
        );
        assert_eq!(
            StageVerb::parse("ack-translation-warning"),
            Some(StageVerb::AckTranslationWarning)
        );
        assert_eq!(StageVerb::Unblock.action(), "unblock_blocked_stage_run");
        assert_eq!(
            StageVerb::ApproveProjectBuildCode.action(),
            "approve_build_code"
        );
        assert_eq!(
            StageVerb::parse("approve-project-build-code"),
            Some(StageVerb::ApproveProjectBuildCode)
        );
        assert_eq!(StageVerb::parse("unblock"), Some(StageVerb::Unblock));
        for word in ["", "merge", "deploy", "ready", "override", "Unblock"] {
            assert_eq!(StageVerb::parse(word), None, "{word}");
        }
    }

    #[test]
    fn a_confirmation_word_fits_the_column_with_a_shorter_path_and_never_rides_on_unblock() {
        let word = factory_domain::policy::solo::ConfirmationWord::of(
            "I confirm the solo approval of build code a",
        )
        .as_str()
        .to_owned();
        let longest = StageFields {
            path: Some("a".repeat(MAX_PATH_BYTES_WITH_CONFIRM)),
            digest: Some("f".repeat(64)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            confirm: Some(word.clone()),
            ..build_code()
        };
        assert!(longest.is_well_formed());
        // " at=" + 30 + " mac=" + 64
        assert!(longest.subject().len() + 4 + 30 + 5 + 64 <= 500);
        assert_eq!(
            StageFields::parse_canonical(&longest.subject()),
            Some(longest.clone())
        );
        // The full path with the word would not fit, so it is not well formed.
        let too_long = StageFields {
            path: Some("a".repeat(MAX_PATH_BYTES)),
            ..longest.clone()
        };
        assert!(!too_long.is_well_formed());
        // A warning takes the word; unblock does not; a malformed word is refused.
        let ack = StageFields {
            confirm: Some(word.clone()),
            ..warning()
        };
        assert_eq!(StageFields::parse_canonical(&ack.subject()), Some(ack));
        let unblock = StageFields {
            confirm: Some(word),
            ..unblock()
        };
        assert!(!unblock.is_well_formed());
        let bad = StageFields {
            confirm: Some("NOTHEX".to_owned()),
            ..warning()
        };
        assert!(!bad.is_well_formed());
    }
}
