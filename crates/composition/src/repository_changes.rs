//! Register, attest and enable a repository as signed requests that the worker applies (finding REG-2).
//!
//! # Why
//!
//! These three acts WIDEN the factory's reach: they decide which GitHub repositories bind webhooks and
//! take work. The API's database login used to make them with plain column grants and an audit row that
//! nobody signed, so a holder of that login's credentials could register any repository, attest a map in the
//! name of any active human of the tenant and enable it. Since AUT-12 the decisions of people are signed
//! requests that the worker verifies before it applies them. This module puts these three acts on the same
//! path. Disabling stays a direct write by the API, because narrowing is safe.
//!
//! # Who does what
//!
//! * **The API** checks the designation and the narrowing of the caller, then appends one record under the
//!   action [`REQUESTED`] in the same transaction as nothing else, and answers `202`. The record carries a
//!   keyed word (`mac=`) that only the holder of the signing key can make ([`crate::decision_signing`]). The
//!   API no longer holds a grant that changes a repository, and no longer writes the actions of the result.
//! * **The worker** ([`RepositoryChanges`], a step of the hook before each claim) reads the requests and for each
//!   one: verifies the word first and reads nothing else of a record that fails it; checks that the person
//!   behind the record is an active human principal of the tenant; asks the protected allowlist, by the numeric
//!   GitHub id of that person and at this moment, whether they hold the designation that the action table of
//!   `policies/approval.yaml` names (the R-4 rule the decisions follow), narrowed to this repository by its
//!   GitHub id (RR-28); applies the change through the Store; and writes the result as a component of the
//!   system, in the same transaction as the change.
//!
//! # What the word covers
//!
//! The tenant, the person (the actor of the record), the id of the record, the time the API wrote, and the
//! words of the subject: the kind, the repository, the commit or the ids, and the digest of the detail text
//! (see [`RepositoryChangeFields`]). The detail text is the `reason` column of the record: the name and the
//! default branch of a registration, or the reason a person gave. The worker hashes the column and compares
//! it with the digest in the signed subject, so the column cannot be changed after the API signed.
//!
//! # Exactly once
//!
//! The result record has an id that is a keyed function of the id of the request
//! ([`DecisionKeys::repository_change_result_id`]). The change and the result are one transaction. A request
//! whose result exists is not applied again, also by a worker that starts later and reads the log from the
//! beginning, and two workers that race write one result: the second one's transaction fails on the id.
//!
//! # What this does not protect against
//!
//! A holder of the API database credentials who does not hold the key can no longer change a repository. The
//! API process holds the key, so a compromise of the process is not covered: such an attacker signs any
//! request, and the worker applies it only as far as the designation of the active person it names allows. The
//! shared symmetric key is the residual of AUT-12 too: a compromised worker can sign. The residual is accepted
//! by the project owner (ADR 0016, revision note of 2026-11-03).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, PrincipalId, RepositoryId, TenantId};
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, AuditRecord, ConstraintRule,
    GithubRepositoryId, InstallationId, NewAuditEvent, NewRepository, PrincipalKind,
    ProjectMapCommit, Store, StoreError, Tx,
};

use crate::decision_signing::{
    DecisionKeys, RepositoryChangeSigning, read_repository_change_subject,
};
use crate::decisions::{MAX_TRIES, Unreadable};

/// The audit action of a request. The API writes it, and its trigger lists it among the actions the API may
/// write.
pub const REQUESTED: &str = "repository.change_requested";
/// The audit action of a request that was refused. The worker writes it; the API's trigger does not list it.
pub const REFUSED: &str = "repository.change_refused";
/// The results of an applied request. The worker writes them, as a component of the system.
pub const REGISTERED: &str = "repository.registered";
/// The result of an applied attestation.
pub const MAP_ATTESTED: &str = "repository.map_attested";
/// The result of an applied enable.
pub const ENABLED: &str = "repository.enabled";
/// The record of a repository that the table switched off because its map was attested again.
pub const DISABLED: &str = "repository.disabled";

/// The designation rows of `policies/approval.yaml` that the three acts need.
pub const REGISTER_ACTION: &str = "register_repository";
/// The row for an attestation.
pub const ATTEST_ACTION: &str = "confirm_project_map";
/// The row for an enable.
pub const ENABLE_ACTION: &str = "enable_repository";

/// How many requests one pass settles for one tenant.
const PER_PASS: usize = 10;
/// The audit pages read in one pass.
const PAGES_PER_PASS: usize = 20;
/// The records in a page.
const PAGE: u32 = 500;
/// The most requests held in memory for one tenant.
const KEPT: usize = 2_000;
/// The text of an enable that gave no reason.
pub const NO_REASON: &str = "No reason was given.";

/// What a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Register a repository.
    Register {
        /// The id the repository will have.
        repository: RepositoryId,
        /// The GitHub App installation, as typed.
        installation: u64,
        /// GitHub's numeric repository id, as typed.
        github_repository: u64,
        /// The rule about the enabler (finding REG-6).
        single_maintainer: bool,
    },
    /// Attest the project map.
    Attest {
        /// The repository.
        repository: RepositoryId,
        /// The commit that holds the map, 40 lowercase hexadecimal characters.
        commit: String,
    },
    /// Enable the repository for the map commit the approver read.
    Enable {
        /// The repository.
        repository: RepositoryId,
        /// The commit the approver read.
        commit: String,
    },
}

impl Change {
    /// The word for the kind, as the subject spells it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Register { .. } => "register",
            Self::Attest { .. } => "attest",
            Self::Enable { .. } => "enable",
        }
    }

    /// The repository the change is about.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        match self {
            Self::Register { repository, .. }
            | Self::Attest { repository, .. }
            | Self::Enable { repository, .. } => *repository,
        }
    }

    /// The row of the action table that decides who may ask.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self {
            Self::Register { .. } => REGISTER_ACTION,
            Self::Attest { .. } => ATTEST_ACTION,
            Self::Enable { .. } => ENABLE_ACTION,
        }
    }
}

/// What a request says, as the subject of the audit record. The API writes it and the worker reads it, so the
/// one grammar is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryChangeFields {
    /// What is asked.
    pub change: Change,
    /// The digest of the detail text, `sha256:` and 64 hex digits.
    pub payload: String,
}

/// The digest that a request carries for its detail text.
#[must_use]
pub fn payload_digest(detail: &str) -> String {
    Sha256Digest::of(detail.as_bytes()).as_str().to_owned()
}

/// The detail text of a registration: the name and the default branch, which are too long for the subject.
#[must_use]
pub fn registration_detail(full_name: &str, default_branch: &str) -> String {
    format!("name={full_name} branch={default_branch}")
}

/// The name and the branch back from [`registration_detail`], when the text is exactly that.
#[must_use]
pub fn read_registration_detail(detail: &str) -> Option<(String, String)> {
    let (name, branch) = detail.strip_prefix("name=")?.split_once(" branch=")?;
    (registration_detail(name, branch) == detail
        && !name.is_empty()
        && !branch.is_empty()
        && !name.contains(' ')
        && !branch.contains(' '))
    .then(|| (name.to_owned(), branch.to_owned()))
}

impl RepositoryChangeFields {
    /// The canonical words: `change kind=<kind> repository=<id> ... payload=<digest>`.
    #[must_use]
    pub fn subject(&self) -> String {
        match &self.change {
            Change::Register {
                repository,
                installation,
                github_repository,
                single_maintainer,
            } => format!(
                "change kind=register repository={} installation={installation} github_repository={github_repository} single_maintainer={single_maintainer} payload={}",
                repository.as_text(),
                self.payload,
            ),
            Change::Attest { repository, commit } | Change::Enable { repository, commit } => {
                format!(
                    "change kind={} repository={} commit={commit} payload={}",
                    self.change.kind(),
                    repository.as_text(),
                    self.payload,
                )
            }
        }
    }

    /// Reads the canonical words back. `None` for any other text, including the same words in another form.
    #[must_use]
    pub fn parse_canonical(text: &str) -> Option<Self> {
        let mut words = text.split(' ');
        if words.next()? != "change" {
            return None;
        }
        let kind = words.next()?.strip_prefix("kind=")?;
        let repository = RepositoryId::parse(words.next()?.strip_prefix("repository=")?).ok()?;
        let change = match kind {
            "register" => {
                let installation = words.next()?.strip_prefix("installation=")?.parse().ok()?;
                let github_repository = words
                    .next()?
                    .strip_prefix("github_repository=")?
                    .parse()
                    .ok()?;
                let single_maintainer = match words.next()?.strip_prefix("single_maintainer=")? {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                };
                Change::Register {
                    repository,
                    installation,
                    github_repository,
                    single_maintainer,
                }
            }
            "attest" | "enable" => {
                let commit = words.next()?.strip_prefix("commit=")?.to_owned();
                ProjectMapCommit::new(&commit).ok()?;
                if kind == "attest" {
                    Change::Attest { repository, commit }
                } else {
                    Change::Enable { repository, commit }
                }
            }
            _ => return None,
        };
        let payload = words.next()?.strip_prefix("payload=")?.to_owned();
        if words.next().is_some() || Sha256Digest::parse(&payload).is_err() {
            return None;
        }
        let fields = Self { change, payload };
        (fields.subject() == text).then_some(fields)
    }
}

/// Whether a person may do an action on a repository, read now and by numeric id.
#[async_trait(?Send)]
pub trait ChangeAuthority: Send + Sync {
    /// True when the person with this GitHub id holds, for the tenant and now, a designation that the action
    /// row names, on `repository`: an allowlist entry narrowed to other repositories grants nothing here
    /// (API-1), and an entry that lists the GitHub id compares it (RR-28).
    ///
    /// # Errors
    /// [`Unreadable`] when the allowlist cannot be read. The request then waits.
    async fn permits(
        &self,
        tenant: TenantId,
        github_user_id: u64,
        action: &str,
        repository: &RepositoryIdentity<'_>,
    ) -> Result<bool, Unreadable>;
}

/// A request that has no result yet.
#[derive(Debug, Clone)]
struct Pending {
    id: AuditEventId,
    correlation: CorrelationId,
    person: PrincipalId,
    fields: RepositoryChangeFields,
    /// The `reason` column of the record, whose digest the signed subject carries.
    detail: String,
    failures: u32,
}

#[derive(Default)]
struct Scan {
    cursor: u64,
    pending: BTreeMap<u64, Pending>,
}

/// What [`RepositoryChanges`] is built from.
pub struct RepositoryChangesDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The allowlist and the action table.
    pub authority: Arc<dyn ChangeAuthority>,
    /// The hash of the policy in force, written on every record.
    pub policy_hash: Sha256Digest,
    /// The keys the API signs its requests with.
    pub keys: Arc<DecisionKeys>,
}

/// How a request ended, when it ended.
enum Outcome {
    /// Applied, and the result is written.
    Applied,
    /// Refused for a fixed reason: the code, and what to write.
    Refused(&'static str),
    /// Could not be settled now: the store or the allowlist did not answer, or a concurrent change moved the
    /// version. Try again next pass.
    Later,
}

/// Applies the signed requests to register, attest and enable. A step of the hook before each claim
/// ([`crate::decisions::ClaimWork::with_repository_changes`]).
pub struct RepositoryChanges {
    deps: RepositoryChangesDeps,
    scans: Mutex<BTreeMap<TenantId, Scan>>,
}

impl RepositoryChanges {
    /// The step, over its collaborators.
    #[must_use]
    pub fn new(deps: RepositoryChangesDeps) -> Self {
        Self {
            deps,
            scans: Mutex::new(BTreeMap::new()),
        }
    }

    /// One pass for one tenant: read the new records, then settle what has no result yet.
    pub async fn pass(&self, tenant: TenantId) {
        if !self.read_new_records(tenant).await {
            return;
        }
        let pending: Vec<Pending> = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or_else(Vec::new, |scan| {
                scan.pending.values().take(PER_PASS).cloned().collect()
            })
        };
        for request in pending {
            self.settle(tenant, request).await;
        }
    }

    fn with_scan(&self, tenant: TenantId, change: impl FnOnce(&mut Scan)) {
        let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
        change(scans.entry(tenant).or_default());
    }

    // ---- reading the log ------------------------------------------------------------------

    /// Reads the audit records after the cursor. False when the log cannot be read.
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
                        tracing::warn!(%error, "the audit log cannot be read for repository changes");
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
                        REQUESTED => {
                            if let Some(pending) = self.request_from(tenant, &record)
                                && scan.pending.len() < KEPT
                            {
                                scan.pending.insert(record.sequence, pending);
                            }
                        }
                        REGISTERED | MAP_ATTESTED | ENABLED | REFUSED => {
                            // Only the worker can write these actions for a request, so the row is the end of
                            // the request it names.
                            if let Some(id) = ended_request(&record) {
                                scan.pending.retain(|_, pending| pending.id != id);
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

    /// The request a record is, when it is one: a person as the actor, no job, the canonical words, a detail
    /// text that matches its digest, and the word that only the holder of the key can make. Anything else is
    /// ignored without a line: a row with this action and no good word is not a request.
    fn request_from(&self, tenant: TenantId, record: &AuditRecord) -> Option<Pending> {
        if record.event.job.is_some() {
            return None;
        }
        let AuditActor::Human(person) = record.event.actor else {
            return None;
        };
        let subject = read_repository_change_subject(&record.event.subject)?;
        let signing = RepositoryChangeSigning {
            tenant,
            actor: person,
            event: record.event.id,
            requested_at: &subject.requested_at,
            fields: &subject.fields,
        };
        if !self
            .deps
            .keys
            .verify_repository_change(&signing, &subject.word)
        {
            return None;
        }
        // The word covers the digest, so a detail text that does not match it was changed after signing.
        if payload_digest(&record.event.reason) != subject.fields.payload {
            return None;
        }
        Some(Pending {
            id: record.event.id,
            correlation: record.event.correlation_id,
            person,
            fields: subject.fields,
            detail: record.event.reason.clone(),
            failures: 0,
        })
    }

    // ---- applying -------------------------------------------------------------------------

    async fn settle(&self, tenant: TenantId, request: Pending) {
        let outcome = self.apply(tenant, &request).await;
        match outcome {
            Outcome::Applied => {
                tracing::info!(
                    kind = request.fields.change.kind(),
                    "a repository change was applied"
                );
                self.forget(tenant, request.id);
            }
            Outcome::Refused(code) => {
                if self.record_refusal(tenant, &request, code).await {
                    tracing::info!(
                        kind = request.fields.change.kind(),
                        code,
                        "a repository change was refused"
                    );
                    self.forget(tenant, request.id);
                }
            }
            Outcome::Later => {
                if request.failures + 1 >= MAX_TRIES {
                    if self.record_refusal(tenant, &request, "not_settled").await {
                        self.forget(tenant, request.id);
                    }
                } else {
                    self.with_scan(tenant, |scan| {
                        if let Some(held) = scan
                            .pending
                            .values_mut()
                            .find(|pending| pending.id == request.id)
                        {
                            held.failures += 1;
                        }
                    });
                }
            }
        }
    }

    fn forget(&self, tenant: TenantId, id: AuditEventId) {
        self.with_scan(tenant, |scan| {
            scan.pending.retain(|_, pending| pending.id != id);
        });
    }

    /// Applies one request in one transaction, with its result.
    async fn apply(&self, tenant: TenantId, request: &Pending) -> Outcome {
        let result_id = self.deps.keys.repository_change_result_id(request.id);
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            return Outcome::Later;
        };
        let outcome = self.apply_in(&mut *tx, tenant, request, result_id).await;
        match outcome {
            Outcome::Applied => {
                if tx.commit().await.is_ok() {
                    Outcome::Applied
                } else {
                    Outcome::Later
                }
            }
            other => {
                let _ = tx.rollback().await;
                other
            }
        }
    }

    async fn apply_in(
        &self,
        tx: &mut dyn Tx,
        tenant: TenantId,
        request: &Pending,
        result_id: AuditEventId,
    ) -> Outcome {
        // A request whose result exists is done. This is also what makes two workers write one result.
        match tx.find_audit(result_id).await {
            Ok(Some(_)) => return Outcome::Applied,
            Ok(None) => {}
            Err(_) => return Outcome::Later,
        }
        // The person behind the record: an active human principal of the tenant, found now.
        let github_user_id = match tx.get_principal(request.person).await {
            Ok(principal) => match (principal.kind, principal.disabled_at) {
                (PrincipalKind::Human { github_user_id }, None) => github_user_id,
                _ => return Outcome::Refused("not_an_active_person"),
            },
            Err(StoreError::NotFound) => return Outcome::Refused("not_an_active_person"),
            Err(_) => return Outcome::Later,
        };
        let change = &request.fields.change;
        let registration = match change {
            Change::Register { .. } => match read_registration_detail(&request.detail) {
                Some(found) => Some(found),
                None => return Outcome::Refused("malformed"),
            },
            _ => None,
        };
        // The repository the question is about, with GitHub's numeric id (RR-28). A registration has no row
        // yet: it is the name and the id that were typed.
        let stored = match change {
            Change::Register { .. } => None,
            Change::Attest { repository, .. } | Change::Enable { repository, .. } => {
                match tx.get_repository(*repository).await {
                    Ok(row) => Some(row),
                    Err(StoreError::NotFound) => return Outcome::Refused("not_found"),
                    Err(_) => return Outcome::Later,
                }
            }
        };
        let permitted = {
            let identity = match (&registration, &stored, change) {
                (
                    Some((name, _)),
                    _,
                    Change::Register {
                        github_repository, ..
                    },
                ) => RepositoryIdentity::registered(name, *github_repository),
                (_, Some(row), _) => row.value.identity(),
                _ => return Outcome::Refused("malformed"),
            };
            self.deps
                .authority
                .permits(tenant, github_user_id, change.action(), &identity)
                .await
        };
        match permitted {
            Ok(true) => {}
            Ok(false) => return Outcome::Refused("not_permitted"),
            Err(Unreadable) => return Outcome::Later,
        }
        // Apply, and write the result. The Store and the table refuse each rule again.
        let person = request.person;
        let applied = match change {
            Change::Register {
                repository,
                installation,
                github_repository,
                single_maintainer,
            } => {
                let Some((full_name, default_branch)) = registration.clone() else {
                    return Outcome::Refused("malformed");
                };
                tx.register_repository(NewRepository {
                    id: *repository,
                    installation: InstallationId(*installation),
                    github_repository_id: GithubRepositoryId(*github_repository),
                    full_name,
                    default_branch,
                    single_maintainer: *single_maintainer,
                })
                .await
                .map(|_| ())
            }
            Change::Attest { repository, commit } => {
                let (Some(row), Ok(commit)) = (&stored, ProjectMapCommit::new(commit)) else {
                    return Outcome::Refused("malformed");
                };
                tx.attest_project_map(*repository, row.version, commit, person)
                    .await
                    .map(|_| ())
            }
            Change::Enable { repository, commit } => {
                let (Some(row), Ok(commit)) = (&stored, ProjectMapCommit::new(commit)) else {
                    return Outcome::Refused("malformed");
                };
                tx.enable_repository(*repository, row.version, commit, person)
                    .await
                    .map(|_| ())
            }
        };
        if let Err(error) = applied {
            return match error {
                StoreError::Constraint(ConstraintRule::ProjectMapRule) => {
                    Outcome::Refused("project_map_not_attested")
                }
                StoreError::Constraint(ConstraintRule::ProjectMapChanged) => {
                    Outcome::Refused("project_map_changed")
                }
                StoreError::Constraint(ConstraintRule::EnablerIsAttestor) => {
                    Outcome::Refused("enabler_is_attestor")
                }
                // A GitHub repository that another registration holds, here or in another tenant, is
                // reported as not found by the store (NT-TEN-05), and the same id with other content as a
                // reuse. Neither says whose.
                StoreError::NotFound
                | StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent) => {
                    Outcome::Refused("conflict")
                }
                // Another change moved the version since it was read: read again next pass.
                _ => Outcome::Later,
            };
        }
        // The effect on the row that the table has, read and not worked out again.
        let mut switched_off = false;
        if let (Change::Attest { repository, .. }, Some(before)) = (change, &stored)
            && before.value.enabled
        {
            match tx.get_repository(*repository).await {
                Ok(after) => switched_off = !after.value.enabled,
                Err(_) => return Outcome::Later,
            }
        }
        let mut events = vec![self.result_event(request, result_id)];
        if switched_off {
            events.push(self.disabled_event(request));
        }
        for event in events {
            match tx.record_audit(event).await {
                Ok(_) => {}
                Err(_) => return Outcome::Later,
            }
        }
        Outcome::Applied
    }

    fn actor() -> Option<AuditActor> {
        Slug::parse("worker.repository")
            .ok()
            .map(AuditActor::System)
    }

    /// The record of an applied request. The words say who asked and that the designation was checked
    /// again, and the text of an attestation says that it is not a verification.
    fn result_event(&self, request: &Pending, id: AuditEventId) -> NewAuditEvent {
        let change = &request.fields.change;
        let by = request.person.as_text();
        let (action, subject, fixed) = match change {
            Change::Register {
                repository,
                single_maintainer,
                ..
            } => (
                REGISTERED,
                format!(
                    "request={} repository {} {} single_maintainer={single_maintainer} requested_by={by}",
                    request.id.as_uuid().hyphenated(),
                    repository.as_text(),
                    read_registration_detail(&request.detail).map_or_else(String::new, |(name, _)| name),
                ),
                if *single_maintainer {
                    "A person registered the repository as a single-maintainer one: the person who attests its project map may also enable it. It starts disabled, at autonomy level L0, with no project map. The engine did not look at the repository: the installation, the GitHub repository id and the name are what the person gave. The worker applied a signed request and checked the designation again."
                } else {
                    "A person registered the repository under the strict rule: the person who enables it is another than the person who attests its project map. It starts disabled, at autonomy level L0, with no project map. The engine did not look at the repository: the installation, the GitHub repository id and the name are what the person gave. The worker applied a signed request and checked the designation again."
                }
                .to_owned(),
            ),
            Change::Attest { repository, commit } => (
                MAP_ATTESTED,
                format!(
                    "request={} repository {} project map commit {commit} attested by {by}",
                    request.id.as_uuid().hyphenated(),
                    repository.as_text(),
                ),
                format!(
                    "Attestation by a person, not a verification. The person says that commit {commit} of the default branch holds the project map. The engine holds no GitHub credential and did not read the repository. The worker applied a signed request and checked the designation again. Reason given: {}",
                    request.detail
                ),
            ),
            Change::Enable { repository, commit } => (
                ENABLED,
                format!(
                    "request={} repository {} enabled by {by}",
                    request.id.as_uuid().hyphenated(),
                    repository.as_text(),
                ),
                format!(
                    "A person enabled the repository for the project map at commit {commit}, which a person attested. The engine did not verify that map. The worker applied a signed request and checked the designation again. Reason given: {}",
                    request.detail
                ),
            ),
        };
        self.event(request, id, action, subject, AuditDecision::Record, fixed)
    }

    /// The record of the switch-off that an attestation of another map caused in the table.
    fn disabled_event(&self, request: &Pending) -> NewAuditEvent {
        let repository = request.fields.change.repository();
        self.event(
            request,
            self.deps.keys.repository_change_effect_id(request.id),
            DISABLED,
            format!(
                "request={} repository {} disabled",
                request.id.as_uuid().hyphenated(),
                repository.as_text()
            ),
            AuditDecision::Record,
            "A person attested the project map again, so the repository is no longer enabled for the map it was enabled for: the map was attested again; enable it again. The engine did not read the repository.".to_owned(),
        )
    }

    fn event(
        &self,
        request: &Pending,
        id: AuditEventId,
        action: &str,
        subject: String,
        decision: AuditDecision,
        reason: String,
    ) -> NewAuditEvent {
        let cut = |text: String, limit: usize| -> String {
            let mut end = text.len().min(limit);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text[..end].to_owned()
        };
        NewAuditEvent {
            id,
            actor: Self::actor().unwrap_or(AuditActor::Human(request.person)),
            action: AuditAction::new(action).unwrap_or_else(|_| {
                AuditAction::new(REFUSED).expect("a fixed action name is valid")
            }),
            subject: cut(subject, 500),
            decision,
            reason: cut(reason, 1000),
            policy_hash: self.deps.policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: request.correlation,
        }
    }

    /// Writes the record of a refusal, with the fixed code as the first word of the reason. True when it is
    /// written or already exists.
    async fn record_refusal(
        &self,
        tenant: TenantId,
        request: &Pending,
        code: &'static str,
    ) -> bool {
        let result_id = self.deps.keys.repository_change_result_id(request.id);
        let event = self.event(
            request,
            result_id,
            REFUSED,
            format!(
                "request={} kind={} repository {} requested_by={}",
                request.id.as_uuid().hyphenated(),
                request.fields.change.kind(),
                request.fields.change.repository().as_text(),
                request.person.as_text()
            ),
            AuditDecision::Deny,
            format!("{code}: the worker did not apply the request. Nothing changed."),
        );
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            return false;
        };
        match tx.record_audit(event).await {
            // A record that exists with other words is the record: the request is dealt with.
            Ok(_) | Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {}
            Err(_) => {
                let _ = tx.rollback().await;
                return false;
            }
        }
        tx.commit().await.is_ok()
    }
}

/// The request a result record ends: the id after `request=` at the start of its subject, when the actor is a
/// component of the system.
fn ended_request(record: &AuditRecord) -> Option<AuditEventId> {
    if !matches!(record.event.actor, AuditActor::System(_)) {
        return None;
    }
    let first = record.event.subject.split(' ').next()?;
    AuditEventId::parse(first.strip_prefix("request=")?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> RepositoryId {
        RepositoryId::from_uuid(uuid::Uuid::from_u128(n))
    }

    fn digest() -> String {
        payload_digest("a detail")
    }

    fn all() -> Vec<RepositoryChangeFields> {
        vec![
            RepositoryChangeFields {
                change: Change::Register {
                    repository: id(1),
                    installation: 7001,
                    github_repository: u64::MAX,
                    single_maintainer: true,
                },
                payload: digest(),
            },
            RepositoryChangeFields {
                change: Change::Attest {
                    repository: id(2),
                    commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                },
                payload: digest(),
            },
            RepositoryChangeFields {
                change: Change::Enable {
                    repository: id(3),
                    commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                },
                payload: digest(),
            },
        ]
    }

    #[test]
    fn the_words_read_back_as_they_were_written() {
        for fields in all() {
            assert_eq!(
                RepositoryChangeFields::parse_canonical(&fields.subject()),
                Some(fields)
            );
        }
    }

    #[test]
    fn text_that_is_not_the_canonical_words_is_not_read() {
        for fields in all() {
            let good = fields.subject();
            for bad in [
                good.replace("change ", "changed "),
                good.replace("kind=", "type="),
                format!("{good} extra=words"),
                good.replace(' ', "  "),
                good.replace("payload=sha256:", "payload=sha1:"),
                good.replace("repository=", "repo="),
                good.replace("commit=0123", "commit=0123G")
                    .replace("single_maintainer=true", "single_maintainer=yes"),
                good.replace("kind=register", "kind=delete")
                    .replace("kind=attest", "kind=delete")
                    .replace("kind=enable", "kind=delete"),
            ] {
                assert_eq!(RepositoryChangeFields::parse_canonical(&bad), None, "{bad}");
            }
        }
    }

    #[test]
    fn the_subject_fits_the_audit_column_with_its_time_and_word() {
        let long = RepositoryChangeFields {
            change: Change::Register {
                repository: id(1),
                installation: u64::MAX,
                github_repository: u64::MAX,
                single_maintainer: false,
            },
            payload: digest(),
        };
        let signed = format!(
            "{} at=2026-11-03T10:00:00.123456789Z mac={}",
            long.subject(),
            "a".repeat(64)
        );
        assert!(signed.len() <= 500, "{}", signed.len());
    }

    #[test]
    fn a_registration_detail_reads_back_only_as_written() {
        let detail = registration_detail("org/name", "release/1.0");
        assert_eq!(
            read_registration_detail(&detail),
            Some(("org/name".to_owned(), "release/1.0".to_owned()))
        );
        for bad in [
            "",
            "name=a/b",
            "name=a/b branch=",
            "name= branch=main",
            "name=a/b  branch=main",
            "name=a/b branch=main extra",
            "branch=main name=a/b",
        ] {
            assert_eq!(read_registration_detail(bad), None, "{bad:?}");
        }
    }
}
