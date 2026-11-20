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
//! # How long a request lives (finding RH-1)
//!
//! A request is for the world as the person saw it. The time the API wrote is in the keyed word, so it cannot be
//! changed, and the worker refuses a request older than [`REQUEST_MAX_AGE`] (fifteen minutes) with the recorded
//! code `expired`, and one dated more than five minutes ahead of its own clock with `clock_skew`. It also
//! refuses a request whose repository was disabled by a person after the request was made
//! (`disabled_since_request`): a disable is an act of incident response, and an act that was asked for before it
//! must not undo it when the worker next runs. The disable is found in the log, in the same pass that finds the
//! request, and once more in the tail of the log inside the transaction that applies the request, so one that
//! commits between the two is not missed. A person who still wants the act asks again.
//!
//! # Exactly once
//!
//! The result record has an id that is a keyed function of the id of the request
//! ([`DecisionKeys::repository_change_result_id`]). The change and the result are one transaction. A request
//! whose result exists is not applied again, also by a worker that starts later and reads the log from the
//! beginning. The result of a request is looked for under every key in force, because a result written before
//! a key rotation has the id the previous key makes (finding RH-4). A worker that has not read the log to its
//! end applies nothing (the reading is bounded for each pass and continues in the next, finding RH-4).
//!
//! Two workers can still both pass the first look. `record_audit` does not fail on a result that exists with
//! the same words: it reports a repeat (`ON CONFLICT DO NOTHING`), so the second worker's transaction does not
//! fail on the id. What stops the second worker is, in order: the version of the repository row, which the
//! first worker's change moved; and the tail of the log, which the second worker reads inside its own
//! transaction after it read the repository and before it writes: it finds the first worker's result and
//! stops, or finds a disable that came after the request and refuses.
//!
//! # What this does not protect against
//!
//! A holder of the API database credentials who does not hold the key can no longer change a repository. The
//! API process holds the key, so a compromise of the process is not covered: such an attacker signs any
//! request, and the worker applies it only as far as the designation of the active person it names allows. The
//! shared symmetric key is the residual of AUT-12 too: a compromised worker can sign. The residual is accepted
//! by the project owner (ADR 0016, revision note of 2026-11-03).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, PrincipalId, RepositoryId, TenantId};
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::scope::TenantScope;
use factory_domain::values::{
    Sha256Digest, Slug, Timestamp, is_repository_branch, is_repository_full_name,
};
use factory_ports::clock::Clock;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, AuditRecord, ConstraintRule,
    GithubRepositoryId, InstallationId, NewAuditEvent, NewRepository, PrincipalKind,
    ProjectMapCommit, Store, StoreError, Tx,
};

use crate::decision_signing::{
    DecisionKeys, RepositoryChangeSigning, read_repository_change_subject,
};
use crate::decisions::{MAX_TRIES, Unreadable};
use crate::project_rules::RepositoryOnboarded;

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
/// The record of a repository that a person disabled. Only the API writes it, as a person, in the words
/// `repository <id> disabled`; the worker reads it as the cancel of every request made before it (finding RH-1).
pub const DISABLED: &str = "repository.disabled";
/// The record of a repository that the table switched off because its map was attested again. The worker writes
/// it, as a component of the system, in the same transaction as the attestation. It is not `repository.disabled`
/// so that the API's own action means one thing only (finding RH-5), and the API login may not write it.
pub const DISABLED_BY_ATTESTATION: &str = "repository.disabled_by_attestation";

/// The designation rows of `policies/approval.yaml` that the three acts need.
pub const REGISTER_ACTION: &str = "register_repository";
/// The row for an attestation.
pub const ATTEST_ACTION: &str = "confirm_project_map";
/// The row for an enable.
pub const ENABLE_ACTION: &str = "enable_repository";

/// How long a signed request stays good: fifteen minutes (finding RH-1). It is a fixed value in code, as the
/// 72 hours of a decision are ([`crate::pipeline::APPROVAL_WINDOW_HOURS`]), and not a setting, so that no
/// configuration can lengthen it. A person who makes this request is at a terminal and expects it settled in
/// a minute; a request that waits longer is for a world that may have changed.
pub const REQUEST_MAX_AGE: Duration = Duration::from_secs(15 * 60);
/// How far ahead of the worker's clock a request may be dated, for the skew between the clock of the API and the
/// clock of the worker. A request dated further ahead is refused (`clock_skew`) and never waits for its time.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
/// How many requests one pass settles for one tenant.
const PER_PASS: usize = 10;
/// The audit pages read in one pass.
const PAGES_PER_PASS: usize = 20;
/// The records in a page.
const PAGE: u32 = 500;
/// The pages the tail of the log may span before a request is put off to the next pass.
const TAIL_PAGES: usize = 5;
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

/// The name and the branch back from [`registration_detail`], when the text is exactly that and both have the
/// shape the API accepts (finding RH-12). The worker is the trust anchor of this channel: it writes the name and
/// the branch to the table, so it checks them itself and does not rely on the API having done it. The table's own
/// CHECK is looser (it accepts `../..` as a name).
#[must_use]
pub fn read_registration_detail(detail: &str) -> Option<(String, String)> {
    let (name, branch) = detail.strip_prefix("name=")?.split_once(" branch=")?;
    (registration_detail(name, branch) == detail
        && is_repository_full_name(name)
        && is_repository_branch(branch))
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

    /// The numeric GitHub ids of the people who hold, for the tenant and now, a designation that the rows of
    /// the action table for an attestation (`confirm_project_map`) or an enable (`enable_repository`) name, on
    /// `repository` (finding RH-6). These are the people the strict rule "the enabler is not the attestor"
    /// constrains. The caller counts the active people among them.
    ///
    /// # Errors
    /// [`Unreadable`] when the allowlist cannot be read. The request then waits.
    async fn constrained_holders(
        &self,
        tenant: TenantId,
        repository: &RepositoryIdentity<'_>,
    ) -> Result<BTreeSet<u64>, Unreadable>;
}

/// True when the tenant has exactly one active human principal among `holders`, the people who hold the
/// designations the strict rule constrains (finding RH-6). Only then may a repository be registered as a
/// single-maintainer one: with two such people the rule can be kept, so the exception is not needed, and with
/// none nobody could use it. A holder who has no principal, or whose principal is switched off or is not a
/// person, is not counted: they cannot attest or enable.
///
/// # Errors
/// The store's error, when a principal cannot be read. The caller refuses or waits; it never allows.
pub async fn single_maintainer_is_possible(
    tx: &mut dyn Tx,
    holders: &BTreeSet<u64>,
) -> Result<bool, StoreError> {
    count_active_people(tx, holders).await.map(|n| n == 1)
}

/// How many active human principals of the tenant are among `holders` (numeric GitHub ids). A
/// holder who has no principal, or whose principal is switched off or is not a person, is not
/// counted. The one counter of people that both the registration of a `single_maintainer`
/// repository (finding RH-6) and the solo mode (ADR 0022) use, so the two cannot count apart.
///
/// # Errors
/// The store's error, when a principal cannot be read. The caller refuses or waits; it never allows.
pub async fn count_active_people(
    tx: &mut dyn Tx,
    holders: &BTreeSet<u64>,
) -> Result<usize, StoreError> {
    let mut active = BTreeSet::new();
    for github_user in holders {
        if let Some(principal) = tx.find_principal_by_github_user(*github_user).await?
            && principal.disabled_at.is_none()
            && matches!(principal.kind, PrincipalKind::Human { .. })
        {
            active.insert(principal.id);
        }
    }
    Ok(active.len())
}

/// A request that has no result yet.
#[derive(Debug, Clone)]
struct Pending {
    id: AuditEventId,
    /// The sequence of the record in the log: the order of commit.
    sequence: u64,
    correlation: CorrelationId,
    person: PrincipalId,
    fields: RepositoryChangeFields,
    /// The `reason` column of the record, whose digest the signed subject carries.
    detail: String,
    /// The time the API wrote, which the keyed word covers. `None` when the text is not a time: the request is
    /// then refused, never applied.
    requested_at: Option<Timestamp>,
    failures: u32,
    /// Set for a pass: a person disabled this request's repository after the request was made.
    disabled_since: bool,
    /// Set for a pass: how far the log had been read when the pass started. The tail after it is read again
    /// inside the transaction that applies the request.
    read_to: u64,
}

#[derive(Default)]
struct Scan {
    cursor: u64,
    pending: BTreeMap<u64, Pending>,
    /// For each repository, the highest sequence of a record in which a person disabled it.
    disabled: BTreeMap<RepositoryId, u64>,
}

/// How far a reading of the log got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// To the end of the log: every result that exists has been seen.
    Complete,
    /// The pass ran out of pages. Nothing is applied until a later pass reaches the end (finding RH-4).
    Partial,
    /// The log could not be read.
    Failed,
}

/// What the tail of the log says about a request that is about to be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// Nothing that matters.
    Clear,
    /// Another worker ended this request.
    Ended,
    /// A person disabled the repository after the request.
    Disabled,
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
    /// The clock the age of a request is read against.
    pub clock: Arc<dyn Clock>,
    /// How long a request stays good: [`REQUEST_MAX_AGE`] in production.
    pub max_age: Duration,
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
    pages_per_pass: usize,
    page: u32,
    /// Told after a register or an enable was applied and committed: the rules check (ADR 0026).
    onboarded: std::sync::OnceLock<Arc<dyn RepositoryOnboarded>>,
}

impl RepositoryChanges {
    /// The step, over its collaborators.
    #[must_use]
    pub fn new(deps: RepositoryChangesDeps) -> Self {
        Self {
            deps,
            scans: Mutex::new(BTreeMap::new()),
            pages_per_pass: PAGES_PER_PASS,
            page: PAGE,
            onboarded: std::sync::OnceLock::new(),
        }
    }

    /// Names what to tell after a request to register or to enable a repository was applied (the
    /// rules check of ADR 0026). Set once; a second call changes nothing. What it does never
    /// changes the outcome of the request, which is committed before it is told.
    pub fn tell_when_onboarded(&self, listener: Arc<dyn RepositoryOnboarded>) {
        let _ = self.onboarded.set(listener);
    }

    /// The same step reading smaller pages and fewer of them in a pass. For tests that need a log longer than
    /// one pass reads without writing ten thousand records.
    #[doc(hidden)]
    #[must_use]
    pub fn with_page_limits(mut self, pages_per_pass: usize, page: u32) -> Self {
        self.pages_per_pass = pages_per_pass.max(1);
        self.page = page.max(1);
        self
    }

    /// One pass for one tenant: read the new records, then settle what has no result yet.
    pub async fn pass(&self, tenant: TenantId) {
        // Nothing is applied before the log has been read to its end: a result that lies in the part not read
        // would not be seen, and its request would be applied a second time (finding RH-4).
        if self.read_new_records(tenant).await != Reading::Complete {
            return;
        }
        let pending: Vec<Pending> = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or_else(Vec::new, |scan| {
                scan.pending
                    .values()
                    .take(PER_PASS)
                    .map(|pending| Pending {
                        disabled_since: scan
                            .disabled
                            .get(&pending.fields.change.repository())
                            .is_some_and(|disabled| *disabled > pending.sequence),
                        read_to: scan.cursor,
                        ..pending.clone()
                    })
                    .collect()
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

    /// Reads the audit records after the cursor, at most `pages_per_pass` pages. [`Reading::Complete`] only when
    /// a page shorter than a full one shows that the end of the log was reached.
    async fn read_new_records(&self, tenant: TenantId) -> Reading {
        let mut cursor = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            scans.get(&tenant).map_or(0, |scan| scan.cursor)
        };
        for _ in 0..self.pages_per_pass {
            let page = {
                let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
                    return Reading::Failed;
                };
                let read = tx.read_audit(AuditFilter::Tenant, cursor, self.page).await;
                let _ = tx.rollback().await;
                match read {
                    Ok(page) => page,
                    Err(error) => {
                        tracing::warn!(%error, "the audit log cannot be read for repository changes");
                        return Reading::Failed;
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
                        DISABLED => {
                            // A person disabled a repository. Every request for it that was made before this
                            // record is for a world that no longer exists (finding RH-1).
                            if let Some(id) = disabled_repository(&record) {
                                let seen = scan.disabled.entry(id).or_insert(0);
                                *seen = (*seen).max(record.sequence);
                            }
                        }
                        _ => {}
                    }
                }
            });
            if u32::try_from(count).unwrap_or(u32::MAX) < self.page {
                return Reading::Complete;
            }
        }
        Reading::Partial
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
            sequence: record.sequence,
            correlation: record.event.correlation_id,
            person,
            fields: subject.fields,
            detail: record.event.reason.clone(),
            requested_at: Timestamp::parse(&subject.requested_at).ok(),
            failures: 0,
            disabled_since: false,
            read_to: 0,
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
                if let (
                    Change::Register { repository, .. } | Change::Enable { repository, .. },
                    Some(listener),
                ) = (&request.fields.change, self.onboarded.get())
                {
                    listener.onboarded(tenant, *repository).await;
                }
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
        // A request whose result exists is done, under any key in force (finding RH-4).
        for known in self.deps.keys.repository_change_result_ids(request.id) {
            match tx.find_audit(known).await {
                Ok(Some(_)) => return Outcome::Applied,
                Ok(None) => {}
                Err(_) => return Outcome::Later,
            }
        }
        // A request is for the world as the person saw it (finding RH-1): too old, dated ahead of the clock, or
        // overtaken by a disable, it is refused and recorded.
        if let Some(code) = self.stale(request) {
            return Outcome::Refused(code);
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
        // An enable of a repository that is enabled already changes nothing and writes no second name (finding
        // RH-7). The table keeps the first enabler.
        if let (Change::Enable { commit, .. }, Some(row)) = (change, &stored)
            && row.value.enabled
            && row
                .value
                .project_map
                .as_ref()
                .is_some_and(|map| map.commit.as_str() == commit)
        {
            return Outcome::Refused("already_enabled");
        }
        let identity = match (&registration, &stored, change) {
            (
                Some((name, _)),
                _,
                Change::Register {
                    github_repository, ..
                },
            ) => RepositoryIdentity::typed(name, *github_repository),
            (_, Some(row), _) => row.value.identity(),
            _ => return Outcome::Refused("malformed"),
        };
        match self
            .deps
            .authority
            .permits(tenant, github_user_id, change.action(), &identity)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Outcome::Refused("not_permitted"),
            Err(Unreadable) => return Outcome::Later,
        }
        // The exception to the strict rule is for a tenant with one person who could use it (finding RH-6).
        if let Change::Register {
            single_maintainer: true,
            ..
        } = change
        {
            let holders = match self
                .deps
                .authority
                .constrained_holders(tenant, &identity)
                .await
            {
                Ok(holders) => holders,
                Err(Unreadable) => return Outcome::Later,
            };
            match single_maintainer_is_possible(tx, &holders).await {
                Ok(true) => {}
                Ok(false) => return Outcome::Refused("single_maintainer_not_allowed"),
                Err(_) => return Outcome::Later,
            }
        }
        // The tail of the log, read after the repository was read and before anything is written. A result
        // written by another worker, or a disable that committed since this pass read the log, shows here.
        match self.tail(tx, request).await {
            Ok(Tail::Clear) => {}
            Ok(Tail::Ended) => return Outcome::Applied,
            Ok(Tail::Disabled) => return Outcome::Refused("disabled_since_request"),
            Err(()) => return Outcome::Later,
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

    /// The code to refuse a request with when it is too old, dated ahead of the clock, or made before a disable
    /// of its repository; `None` when it is still good (finding RH-1).
    fn stale(&self, request: &Pending) -> Option<&'static str> {
        let Some(requested_at) = request.requested_at else {
            return Some("malformed");
        };
        let now = self.deps.clock.now();
        match now.duration_since(&requested_at) {
            Some(age) if age > self.deps.max_age => return Some("expired"),
            Some(_) => {}
            // The time is ahead of the clock: only the skew between two clocks is allowed for.
            None => {
                if requested_at
                    .duration_since(&now)
                    .is_none_or(|gap| gap > MAX_CLOCK_SKEW)
                {
                    return Some("clock_skew");
                }
            }
        }
        request.disabled_since.then_some("disabled_since_request")
    }

    /// Reads the records after the ones the pass read, inside the transaction that applies the request.
    async fn tail(&self, tx: &mut dyn Tx, request: &Pending) -> Result<Tail, ()> {
        let mut cursor = request.read_to;
        let mut verdict = Tail::Clear;
        for _ in 0..TAIL_PAGES {
            let page = tx
                .read_audit(AuditFilter::Tenant, cursor, self.page)
                .await
                .map_err(|_| ())?;
            for record in &page {
                cursor = record.sequence;
                verdict = tail_verdict(verdict, request, record);
            }
            if u32::try_from(page.len()).unwrap_or(u32::MAX) < self.page {
                return Ok(verdict);
            }
        }
        // The log moved by more than the tail may span: put the request off. A later pass reads it from the start.
        Err(())
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
            DISABLED_BY_ATTESTATION,
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

/// The repository a record of a person's disable names, when it is one: a person as the actor and exactly the
/// words the API writes, `repository <id> disabled`.
fn disabled_repository(record: &AuditRecord) -> Option<RepositoryId> {
    if !matches!(record.event.actor, AuditActor::Human(_)) {
        return None;
    }
    let id = record
        .event
        .subject
        .strip_prefix("repository ")?
        .strip_suffix(" disabled")?;
    RepositoryId::parse(id).ok()
}

/// What one record of the tail says about a request, given what the earlier ones said. A result that ends the
/// request wins over a disable: the request is done, and nothing is applied.
fn tail_verdict(before: Tail, request: &Pending, record: &AuditRecord) -> Tail {
    if before == Tail::Ended {
        return Tail::Ended;
    }
    match record.event.action.as_str() {
        REGISTERED | MAP_ATTESTED | ENABLED | REFUSED
            if ended_request(record) == Some(request.id) =>
        {
            Tail::Ended
        }
        DISABLED if disabled_repository(record) == Some(request.fields.change.repository()) => {
            Tail::Disabled
        }
        _ => before,
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

    fn record(actor: AuditActor, action: &str, subject: String, sequence: u64) -> AuditRecord {
        AuditRecord {
            sequence,
            event: NewAuditEvent {
                id: AuditEventId::from_uuid(uuid::Uuid::from_u128(u128::from(sequence))),
                actor,
                action: AuditAction::new(action).expect("an action"),
                subject,
                decision: AuditDecision::Record,
                reason: "because".to_owned(),
                policy_hash: Sha256Digest::of(b"a policy"),
                job: None,
                stage_run: None,
                correlation_id: CorrelationId::from_uuid(uuid::Uuid::from_u128(7)),
            },
            created_at: Timestamp::parse("2026-11-03T10:00:00Z").expect("a time"),
            hash: Sha256Digest::of(b"a hash"),
        }
    }

    fn person() -> AuditActor {
        AuditActor::Human(PrincipalId::from_uuid(uuid::Uuid::from_u128(9)))
    }

    fn system() -> AuditActor {
        AuditActor::System(Slug::parse("worker.repository").expect("a slug"))
    }

    fn pending(repository: u128, id: u128) -> Pending {
        Pending {
            id: AuditEventId::from_uuid(uuid::Uuid::from_u128(id)),
            sequence: 1,
            correlation: CorrelationId::from_uuid(uuid::Uuid::from_u128(7)),
            person: PrincipalId::from_uuid(uuid::Uuid::from_u128(9)),
            fields: RepositoryChangeFields {
                change: Change::Attest {
                    repository: self::id(repository),
                    commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                },
                payload: digest(),
            },
            detail: "a detail".to_owned(),
            requested_at: None,
            failures: 0,
            disabled_since: false,
            read_to: 0,
        }
    }

    #[test]
    fn only_a_persons_words_of_a_disable_name_a_repository() {
        let repository = id(5);
        let words = format!("repository {} disabled", repository.as_text());
        assert_eq!(
            disabled_repository(&record(person(), DISABLED, words.clone(), 3)),
            Some(repository)
        );
        // The system is not a person, whatever it writes (the worker's old record of an effect; a forgery).
        assert_eq!(
            disabled_repository(&record(system(), DISABLED, words, 4)),
            None
        );
        for bad in [
            format!("request=x repository {} disabled", repository.as_text()),
            format!("repository {}", repository.as_text()),
            format!("repository {} disabled and more", repository.as_text()),
            "repository nothing disabled".to_owned(),
        ] {
            assert_eq!(
                disabled_repository(&record(person(), DISABLED, bad.clone(), 5)),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn the_tail_ends_a_request_that_another_worker_ended_and_cancels_one_that_a_disable_overtook() {
        let request = pending(5, 42);
        let disabled = record(
            person(),
            DISABLED,
            format!("repository {} disabled", id(5).as_text()),
            10,
        );
        let elsewhere = record(
            person(),
            DISABLED,
            format!("repository {} disabled", id(6).as_text()),
            11,
        );
        let ended = record(
            system(),
            ENABLED,
            format!(
                "request={} repository {} enabled by x",
                request.id.as_uuid().hyphenated(),
                id(5).as_text()
            ),
            12,
        );
        let another_request = record(
            system(),
            ENABLED,
            format!(
                "request={} repository {} enabled by x",
                uuid::Uuid::from_u128(43).hyphenated(),
                id(5).as_text()
            ),
            13,
        );
        let by_a_person = record(
            person(),
            ENABLED,
            format!(
                "request={} repository {} enabled by x",
                request.id.as_uuid().hyphenated(),
                id(5).as_text()
            ),
            14,
        );
        assert_eq!(
            tail_verdict(Tail::Clear, &request, &disabled),
            Tail::Disabled
        );
        assert_eq!(tail_verdict(Tail::Clear, &request, &elsewhere), Tail::Clear);
        assert_eq!(tail_verdict(Tail::Clear, &request, &ended), Tail::Ended);
        assert_eq!(
            tail_verdict(Tail::Clear, &request, &another_request),
            Tail::Clear
        );
        assert_eq!(
            tail_verdict(Tail::Clear, &request, &by_a_person),
            Tail::Clear,
            "only the system can end a request"
        );
        // A result that ends the request wins over a disable, in either order: the request is done.
        assert_eq!(tail_verdict(Tail::Disabled, &request, &ended), Tail::Ended);
        assert_eq!(tail_verdict(Tail::Ended, &request, &disabled), Tail::Ended);
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
            // The shape the API accepts, checked again by the worker (finding RH-12).
            "name=../.. branch=main",
            "name=a/b/c branch=main",
            "name=a/b branch=-main",
            "name=a/b branch=a..b",
            "name=a/b;x branch=main",
            "name=a/b branch=main\n",
        ] {
            assert_eq!(read_registration_detail(bad), None, "{bad:?}");
        }
    }
}
