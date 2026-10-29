//! A person's decision on a new dependency or on its build code, from the API to the engine.
//!
//! The supply chain gates block `dependency-review` with `policy_unresolvable` until a person
//! decided on every new direct dependency, and on every package that brings build code
//! (`gates::supply_chain`). The decision is two verbs, `approve-dependency` and
//! `approve-build-code`, in the same channels as the six verbs of a pull request. This module is
//! the worker's side of them: the shape of the request the API records, and the step that applies
//! it.
//!
//! # Why this is not one of the six verbs
//!
//! The six verbs move a stage run through the approval service and need no package. A decision on
//! a dependency names a package, a version and (to tell two packages of one name apart) the start
//! of a checksum, and it does not move a stage run: `Engine::record_dependency_decision` stores
//! the decision where the gate and `UnblockRerun` read it. So the request has its own audit action
//! ([`REQUESTED`]) and its own canonical subject ([`DependencyFields`]), and the hook that applies
//! the six verbs never reads it. The word that proves the API wrote it is made with another
//! context line, so a word made for one kind of request is never the word of the other.
//!
//! # What the step does, in this order
//!
//! 1. Reads the requests after its cursor and checks the keyed word before anything else is
//!    believed (AUT-12). A request with no word, or the wrong one, is rejected with the fixed
//!    code `not_signed`.
//! 2. Asks the engine whether it already applied the command, and if so writes the marker only.
//! 3. Rejects a request older than the approval window, from a person who is not a current user
//!    of the tenant, or for a job that ended.
//! 4. Reads the **evidence the blocked stage run stored** and finds the one awaited package the
//!    words select (`gates::supply_chain::command::resolve`). The subject the engine is given is
//!    the stored one, with its full checksum: it is never built from the person's words.
//! 5. Asks the policy engine for the proof of authority (`approval::authorize` or
//!    `authorize_build_code`) with the allowlist read now, by numeric id, the level of the
//!    repository and the person who asked for the job. Nothing about a refusal is explained.
//! 6. **Redacts the person's reason**, because the engine has no redactor, and calls
//!    `Engine::record_dependency_decision`.
//! 7. Writes a marker, `decision.applied` or `decision.rejected`, under an id derived from the
//!    request's, with a fixed code and no text of the person.
//!
//! It runs inside [`ClaimWork::pass`](crate::decisions::ClaimWork::pass) once
//! [`ClaimWork::with_dependencies`](crate::decisions::ClaimWork::with_dependencies) gave it its
//! collaborators.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use factory_domain::ids::{
    AuditEventId, CausationId, CorrelationId, JobId, PrincipalId, StageRunId, TenantId,
};
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::{ActionVerdict, Actor as PolicyActor, ActorKind};
use factory_domain::policy::decision::GithubUserId;
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
use factory_workflow::commands::{Actor, RecordDependencyDecision, Subject};
use factory_workflow::engine::{Engine, EngineError};
use factory_workflow::gates::supply_chain::approval::{
    ApprovalKind, MIN_REASON_CHARS, Request, Subject as Package, authorize, authorize_build_code,
};
use factory_workflow::gates::supply_chain::command::{
    APPROVE_BUILD_CODE, APPROVE_DEPENDENCY, DependencyCommand, ResolveError, resolve,
};
use factory_workflow::gates::supply_chain::review::awaiting_in;
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::approval::ApprovalSources;
use factory_workflow::stages::validation::EVIDENCE;

use crate::decision_signing::{
    DecisionKeys, DependencySigning, DependencySubject, MarkerSigning, actor_text,
    read_dependency_subject,
};
use crate::decisions::{APPLIED, JUNK_PER_PASS, Marked, REJECTED, Reason, counted_marker};
use crate::reading::Reader;
use crate::telemetry::job_span_of;
use tracing::Instrument as _;

/// The audit action of a request for a decision on a dependency (written by the API).
pub const REQUESTED: &str = "decision.dependency_requested";

/// The longest package name a request carries, in bytes (crates.io allows 64).
pub const MAX_NAME_BYTES: usize = 64;
/// The longest version a request carries, in bytes.
pub const MAX_VERSION_BYTES: usize = 64;

/// The text the API puts before the person's reason.
const REQUEST_PREFIX: &str = "requested: ";

/// The audit records read in one page.
const PAGE: u32 = 500;
/// The most pages one pass reads for one tenant.
const PAGES_PER_PASS: usize = 20;
/// The most signed requests one pass deals with for one tenant. Records that are not requests this
/// step trusts have a budget of their own ([`JUNK_PER_PASS`]), so they never take the room of a
/// signed one (RR-21).
pub const PER_PASS: usize = 50;
/// The most records that are not requests this step trusts that a scan keeps in memory.
const JUNK_KEPT: usize = 10_000;
/// The most passes a request that keeps failing for a reason that may pass is tried.
pub const MAX_TRIES: u32 = 20;

// ------------------------------------------------------------------------------------------
// The record the API writes
// ------------------------------------------------------------------------------------------

/// What a request for a decision on a dependency says, as the subject of the audit record. The API
/// writes it and the worker reads it, so the one grammar is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyFields {
    /// A decision on the dependency, or on its build code.
    pub kind: ApprovalKind,
    /// The job.
    pub job: JobId,
    /// The blocked `VALIDATION` stage run, when the person named it. The step finds the job's
    /// blocked validation run when they did not.
    pub stage_run: Option<StageRunId>,
    /// The package name as the person wrote it.
    pub package: String,
    /// The version as the person wrote it.
    pub version: String,
    /// The start of the checksum, 12 to 64 lower case hexadecimal digits, when the person wrote
    /// one.
    pub checksum: Option<String>,
}

impl DependencyFields {
    /// The verb, as a person writes it.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self.kind {
            ApprovalKind::NewDependency => APPROVE_DEPENDENCY,
            ApprovalKind::BuildCode => APPROVE_BUILD_CODE,
        }
    }

    /// The subject text of the audit record.
    #[must_use]
    pub fn subject(&self) -> String {
        format!(
            "verb={} job={} run={} package={} version={} checksum={}",
            self.verb(),
            self.job.as_text(),
            self.stage_run
                .map_or_else(|| "none".to_owned(), |run| run.as_text()),
            self.package,
            self.version,
            self.checksum.as_deref().unwrap_or("none"),
        )
    }

    /// Reads a subject back and accepts it only if it is exactly the text [`Self::subject`] writes
    /// for what it says. A package name and a version are checked with the grammar of the
    /// dependency commands, so a word that would not be a command is not a request either.
    #[must_use]
    pub fn parse_canonical(subject: &str) -> Option<Self> {
        let mut words = subject.split(' ');
        let kind = match words.next()?.strip_prefix("verb=")? {
            APPROVE_DEPENDENCY => ApprovalKind::NewDependency,
            APPROVE_BUILD_CODE => ApprovalKind::BuildCode,
            _ => return None,
        };
        let job = JobId::parse(words.next()?.strip_prefix("job=")?).ok()?;
        let run = words.next()?.strip_prefix("run=")?;
        let package = words.next()?.strip_prefix("package=")?;
        let version = words.next()?.strip_prefix("version=")?;
        let checksum = words.next()?.strip_prefix("checksum=")?;
        if words.next().is_some() {
            return None;
        }
        let fields = Self {
            kind,
            job,
            stage_run: (run != "none")
                .then(|| StageRunId::parse(run).ok())
                .flatten(),
            package: package.to_owned(),
            version: version.to_owned(),
            checksum: (checksum != "none").then(|| checksum.to_owned()),
        };
        (fields.is_well_formed() && fields.subject() == subject).then_some(fields)
    }

    /// True when every word is one the grammar of the commands accepts and fits the audit subject.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        use factory_domain::policy::dependency::Ecosystem;
        self.package.len() <= MAX_NAME_BYTES
            && self.version.len() <= MAX_VERSION_BYTES
            && Ecosystem::Cargo.valid_name(&self.package)
            && factory_workflow::gates::supply_chain::version::Version::parse(&self.version)
                .is_some()
            && self.checksum.as_deref().is_none_or(|prefix| {
                (factory_workflow::gates::supply_chain::command::MIN_CHECKSUM_PREFIX..=64)
                    .contains(&prefix.len())
                    && prefix
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            })
    }
}

// ------------------------------------------------------------------------------------------
// The step
// ------------------------------------------------------------------------------------------

/// What [`DependencyDecisions`] is built from.
pub struct DependencyDecisionsDeps {
    /// The engine the worker loop runs.
    pub engine: Arc<Engine>,
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The artifact store, to read the evidence the blocked stage run stored.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// The tenants the worker serves.
    pub tenants: Vec<TenantId>,
    /// The evaluators of the policies.
    pub policy: Arc<PolicyEngine>,
    /// The hash of the policy bundle in force, for the markers.
    pub policy_hash: Sha256Digest,
    /// The allowlist now, the level of the repository and the requester of the job.
    pub sources: Arc<dyn ApprovalSources>,
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
    fields: DependencyFields,
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

/// Applies the requests for a decision on a dependency.
pub struct DependencyDecisions {
    deps: DependencyDecisionsDeps,
    reader: Reader,
    scans: Mutex<BTreeMap<TenantId, Scan>>,
}

impl DependencyDecisions {
    /// The step over its collaborators.
    #[must_use]
    pub fn new(deps: DependencyDecisionsDeps) -> Self {
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
            // The lines about a decision are about the job it names, so they are said inside that
            // job's stretch span and start with the correlation id of the stored job.
            let span = job_span_of(&*self.deps.store, tenant, request.fields.job).await;
            self.deal_with(tenant, request).instrument(span).await;
        }
    }

    /// One decision on a dependency: judge it, apply it, and write the marker that ends it.
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
                        tracing::warn!(%error, "the audit log cannot be read for dependency decisions");
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
                            // Only a marker the worker signed ends a request (RR-8). A row that
                            // only looks like one is ignored here; the hook of the decisions
                            // records that it was ignored.
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

    #[allow(clippy::too_many_lines)]
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
        let repository = match self.job_facts(tenant, fields.job).await {
            Ok(Some((status, _))) if status.is_terminal() => {
                return Verdict::Done(Reason::JobEnded.into());
            }
            Ok(Some((_, repository))) => repository,
            Ok(None) => return Verdict::Done(Reason::NoJob.into()),
            Err(Unreadable) => return Verdict::Later,
        };

        // 5. The blocked validation run, and what its stored evidence awaits.
        let (stage_run, correlation, awaited) = match self.awaited_of(tenant, &fields).await {
            Ok(Found::Run {
                stage_run,
                correlation,
                awaited,
            }) => (stage_run, correlation, awaited),
            Ok(Found::NoRun) => return Verdict::Done(Reason::WrongState.into()),
            Ok(Found::NoJob) => return Verdict::Done(Reason::NoJob.into()),
            Err(Unreadable) => return Verdict::Later,
        };
        let command_words = DependencyCommand {
            kind: fields.kind,
            name: fields.package.clone(),
            version: fields.version.clone(),
            checksum_prefix: fields.checksum.clone(),
            reason: String::new(),
        };
        let chosen = match resolve(&awaited, &command_words) {
            Ok(chosen) => chosen.clone(),
            Err(ResolveError::NotAwaited) => return Verdict::Done(Reason::NotAwaited.into()),
            Err(ResolveError::Ambiguous) => return Verdict::Done(Reason::Ambiguous.into()),
        };

        // 6. The reason: at least ten characters, and redacted, because the engine has no
        // redactor and the document it stores is read by people and by the gate.
        if request.reason.trim().chars().count() < MIN_REASON_CHARS {
            return Verdict::Done(Reason::Incomplete.into());
        }
        let Ok(redacted) = self.deps.redactor.redact_str(request.reason.trim()) else {
            // The redactor failed: raw text is never written because of that.
            return Verdict::Done(Reason::Refused.into());
        };
        let Ok(reason) = HumanText::parse(redacted.output.as_ref()) else {
            return Verdict::Done(Reason::Incomplete.into());
        };

        // 7. The proof of authority from the policy engine, with the allowlist read now.
        let identity = RunIdentity {
            tenant,
            job: fields.job,
            correlation,
            stage_run,
            kind: StageKind::Validation,
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
        let authority_request = Request {
            policy: &self.deps.policy.authority,
            level,
            tenant: &tenant,
            repository: &repository,
            actor: &actor,
            allowlist: &allowlist,
            now: &now,
            requester: GithubUserId::new(requester),
            // The two actions are not tiered, so the tier does not change who may decide. The
            // change is marked as adding a dependency, so separation of duties applies.
            risk_tier: RiskTier::Medium,
            protected_path_change: false,
            sensitive_file_change: false,
        };
        let verdict = match chosen.kind {
            ApprovalKind::NewDependency => authorize(&authority_request, chosen.needs),
            ApprovalKind::BuildCode => authorize_build_code(&authority_request),
        };
        let proof = match verdict {
            ActionVerdict::Authorized(proof) => proof,
            // A refusal is never explained, and a policy that needs no person for the action is
            // not a reason to accept one.
            ActionVerdict::Denied(_) | ActionVerdict::NoHumanNeeded { .. } => {
                return Verdict::Done(Reason::NotAuthorized.into());
            }
        };

        // 8. The engine records it, from the subject its own evidence showed.
        let actor = Actor {
            tenant,
            principal: request.principal,
            command,
        };
        let recorded = self
            .deps
            .engine
            .record_dependency_decision(
                &actor,
                RecordDependencyDecision {
                    stage: Subject {
                        job: fields.job,
                        stage_run,
                    },
                    proof,
                    package: Package {
                        name: chosen.subject.name.clone(),
                        version: chosen.subject.version.clone(),
                        checksum: chosen.subject.checksum.clone(),
                    },
                    reason,
                },
            )
            .await;
        match recorded {
            Ok(done) => Verdict::Done(Marked::Applied(match done.kind {
                ApprovalKind::NewDependency => {
                    "The decision on the new dependency was recorded.".to_owned()
                }
                ApprovalKind::BuildCode => {
                    "The decision on the build code was recorded.".to_owned()
                }
            })),
            Err(EngineError::Duplicate) => Verdict::Done(already()),
            Err(EngineError::NotAuthorized(_)) => Verdict::Done(Reason::NotAuthorized.into()),
            Err(EngineError::Refused(_) | EngineError::Illegal(_) | EngineError::GuardUnmet(_)) => {
                Verdict::Done(Reason::Refused.into())
            }
            Err(EngineError::NotFound) => Verdict::Done(Reason::NoStageRun.into()),
            Err(_) => Verdict::Later,
        }
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

    async fn job_facts(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<Option<(JobStatus, String)>, Unreadable> {
        let mut tx = self
            .deps
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

    /// The blocked validation run of the job and the decisions its stored evidence awaits.
    async fn awaited_of(
        &self,
        tenant: TenantId,
        fields: &DependencyFields,
    ) -> Result<Found, Unreadable> {
        let mut tx = self
            .deps
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| Unreadable)?;
        let outcome = async {
            let job = match tx.get_job(fields.job).await {
                Ok(job) => job.value,
                Err(StoreError::NotFound) => return Ok(Found::NoJob),
                Err(_) => return Err(Unreadable),
            };
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
            let awaited = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .filter(|document| {
                    document.get("kind").and_then(serde_json::Value::as_str) == Some(EVIDENCE)
                })
                .and_then(|document| document.get("dependency_review").cloned())
                .map(|review| awaiting_in(&review))
                .unwrap_or_default();
            Ok(Found::Run {
                stage_run: run.value.id,
                correlation: job.correlation_id,
                awaited,
            })
        }
        .await;
        let _ = tx.rollback().await;
        outcome
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
        tracing::info!(code, "a decision on a dependency was dealt with");
        let subject = format!(
            "decision={} verb={} job={} code={} actor={} allowlist=none",
            request.id.as_uuid().hyphenated(),
            request.fields.verb(),
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
            "a request for a dependency decision was rejected"
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
        let Ok(actor) = Slug::parse("worker.dependency-decisions").map(AuditActor::System) else {
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

/// What reading the job for a request found.
enum Found {
    Run {
        stage_run: StageRunId,
        correlation: CorrelationId,
        awaited: Vec<factory_workflow::gates::supply_chain::review::Awaited>,
    },
    NoRun,
    NoJob,
}

/// A source of facts could not answer. Nothing was decided.
struct Unreadable;

fn already() -> Marked {
    Marked::Applied("The engine had applied this decision already.".to_owned())
}

/// A request for a decision, read from its audit record. `Err` for a record that is not a request
/// this module trusts: the record is rejected with a marker and stops being a candidate.
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
    let (fields, requested_at, word) = match read_dependency_subject(&record.event.subject) {
        Some(DependencySubject::Signed {
            fields,
            requested_at,
            word,
        }) => (fields, requested_at, word),
        Some(DependencySubject::Unsigned(_)) => return Err(Reason::NotSigned),
        None => return Err(Reason::Malformed),
    };
    let signing = DependencySigning {
        tenant,
        actor: principal,
        event: record.event.id,
        requested_at: &requested_at,
        fields: &fields,
    };
    if !keys.verify_dependency(&signing, &word) {
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

    fn fields(kind: ApprovalKind) -> DependencyFields {
        DependencyFields {
            kind,
            job: JobId::from_uuid(uuid::Uuid::from_u128(0x1111)),
            stage_run: Some(StageRunId::from_uuid(uuid::Uuid::from_u128(0x2222))),
            package: "tally-counter".to_owned(),
            version: "0.3.1".to_owned(),
            checksum: Some("ab".repeat(8)),
        }
    }

    #[test]
    fn a_subject_reads_back_as_it_was_written_for_both_verbs() {
        for kind in [ApprovalKind::NewDependency, ApprovalKind::BuildCode] {
            let written = fields(kind);
            assert_eq!(
                DependencyFields::parse_canonical(&written.subject()),
                Some(written)
            );
        }
        let bare = DependencyFields {
            stage_run: None,
            checksum: None,
            ..fields(ApprovalKind::NewDependency)
        };
        assert_eq!(
            DependencyFields::parse_canonical(&bare.subject()),
            Some(bare)
        );
    }

    #[test]
    fn a_subject_that_is_not_exactly_the_canonical_text_is_not_read() {
        let canonical = fields(ApprovalKind::NewDependency).subject();
        for changed in [
            canonical.replace("verb=approve-dependency", "verb=approve"),
            canonical.replace("approve-dependency", "approve-dependencies"),
            format!("{canonical} extra=1"),
            canonical.replace(' ', "  "),
            canonical.replace("package=tally-counter", "package=../etc"),
            canonical.replace("version=0.3.1", "version=latest"),
            canonical.replace(&"ab".repeat(8), "ABABABABABABABAB"),
            canonical.replace(&"ab".repeat(8), "abab"),
        ] {
            assert_eq!(
                DependencyFields::parse_canonical(&changed),
                None,
                "{changed}"
            );
        }
    }

    #[test]
    fn the_subject_fits_the_audit_column_with_the_time_and_the_word() {
        let longest = DependencyFields {
            package: "a".repeat(MAX_NAME_BYTES),
            version: format!("1.0.0-{}", "a".repeat(MAX_VERSION_BYTES - 6)),
            checksum: Some("f".repeat(64)),
            ..fields(ApprovalKind::BuildCode)
        };
        assert!(longest.is_well_formed());
        // " at=" + 30 + " mac=" + 64
        assert!(longest.subject().len() + 4 + 30 + 5 + 64 <= 500);
    }
}
