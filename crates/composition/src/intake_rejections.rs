//! The reply to a label from someone who may not ask the factory for work.
//!
//! # What the specification asks for
//!
//! FR-002: the factory rejects every issue that is not from an authorized requester with a short
//! plain-English explanation, and writes an audit record that states who filed it, what was
//! decided, when and why. The explanation must not reveal the contents of the allowlist. SC-002:
//! all of them, and none starts a build.
//!
//! # Who does what
//!
//! * **The API** (`apps/api/src/webhook.rs`) sees the label. It makes no job. It holds no GitHub
//!   credential and may write only the audit actions the database trigger lists
//!   (`2026-10-29-002100_api_audit_actions`), so it leaves one **request** in the audit log, under
//!   the action `webhook_accepted_or_rejected.denied`, in the same transaction that records the
//!   delivery. The request names the registered repository, the issue number, the numeric id of the
//!   sender (or `none`), the delivery id and the version of the allowlist the API read. It carries
//!   a keyed word (`mac=`) that only the API, which holds the signing key, can make
//!   ([`crate::decision_signing`]): any login of the API's database group can write a row with that
//!   action, and a row without the word does nothing.
//! * **The worker** ([`IntakeRejections`], a step of the hook before each claim) reads the
//!   requests, checks the word, posts one fixed reply on the issue through the `ChangeHost` port
//!   with a token narrowed to the one repository, and writes the record `intake.rejected`. The API
//!   cannot write that action, so the record is the worker's own word.
//!
//! # Why the reply is posted at most once for a delivery
//!
//! * The API makes a request only for a delivery the store recorded as new. A repeat is audited as
//!   `webhook.duplicate_delivery` and makes none.
//! * The reply is posted with the idempotency key `intake-rejected-<delivery id>`, so the host keeps
//!   one comment for it even when the worker asks twice (a stop between the reply and the record).
//! * The record of the rejection has an id that is a keyed function of the request's id
//!   ([`DecisionKeys::rejection_id`]), so writing it twice is one record. A request whose record
//!   exists is not answered again, also by a worker that starts later and reads the log from the
//!   beginning.
//!
//! # Why nobody can probe the allowlist
//!
//! The request does not say why the sender was refused. A person the tenant does not know, a
//! person who was disabled, a person who holds another designation and a requester narrowed to
//! other repositories all get the same reply, word for word ([`REPLY`]), and the same record apart
//! from the numeric id. The reply names no one and holds no text of the issue.
//!
//! # How often a sender is answered (SF-16)
//!
//! A sender who removes the label and puts it back sends a delivery for each toggle, and each is a
//! request with its own key. One reply tells them what they need to know, so the step answers a
//! sender under two bounds ([`ReplyLimits`]), and where they meet the safer reading wins: fewer
//! replies, never more.
//!
//! * **Spacing.** At most one reply in [`REPLY_WINDOW`] (ten minutes).
//! * **Cap.** At most [`REPLY_CAP`] replies (three) in [`REPLY_CAP_PERIOD`] (24 hours), in the
//!   style of the cap on the replies about a design (DG-9).
//!
//! Both count from the time the database wrote the request that was answered. A request that is
//! not answered is recorded all the same: the record says `reply=suppressed` and, after it,
//! `withheld=spacing` or `withheld=cap`, so that every reply held back leaves a precise trace, and
//! no comment is posted. The bounds are read from the log: the rejection records that say
//! `reply=posted` rebuild them, so a worker that starts later, or two workers, keep the same
//! limits. A sender is the numeric id the delivery carried, and deliveries with none share a
//! bucket. The bounds are for the sender in the tenant and not for an issue or a repository, so a
//! sender who labels many issues is answered once in ten minutes and three times in a day.
//!
//! The numbers are constants of this module and not keys of the policy file: they bound a reply
//! that names nobody and says the same words to everyone, and a project cannot loosen them. A
//! policy key (tighten only, like `design_reply_cap_per_issue`) would need the policy type, its
//! schema and the Python mirror to change together; it is left for a decision that wants a
//! project to be able to tighten these.
//!
//! # The token
//!
//! The reply is a comment on an issue, which needs `issues: write`. The scope names the approval
//! stage, which holds that right, and the adapter posts a comment with the token class for a
//! comment (SF-14): `issues: write` and `metadata: read` for the one repository, and nothing else.
//! A rejection has no job, so the scope names the id of the request as its job, and the tokens of
//! that job are revoked when the reply is done.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{ChangeHost, CommentTarget, GitHostError, GitScope, IssueRef};
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, AuditRecord, ConstraintRule,
    NewAuditEvent, Store, StoreError,
};

use crate::decision_signing::{DecisionKeys, RejectionSigning, read_rejection_subject};
use crate::decisions::MAX_TRIES;

/// The audit action of a request to answer a label that was refused. The API writes it, and its
/// trigger lists it among the actions the API may write.
pub const REQUESTED: &str = "webhook_accepted_or_rejected.denied";

/// The audit action of the record that a rejection leaves. The worker writes it. The API's
/// trigger does not list it, so a row with this action did not come from the API.
pub const REJECTED: &str = "intake.rejected";

/// The fixed reason code of the record. The first word of its reason.
pub const REASON_CODE: &str = "unauthorized_actor";

/// The reply, the same for everyone. It says that the work did not start and why in the one way
/// the specification allows, and it names nobody and holds no text of the issue.
pub const REPLY: &str = "The factory did not start work on this issue. You are not on the list of people who may ask for this. If you think this is a mistake, ask the person who manages the factory for this repository.";

/// A sender who may not ask is answered at most once in this long (SF-16).
pub const REPLY_WINDOW: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// A sender who may not ask is answered at most this many times in [`REPLY_CAP_PERIOD`] (SF-16).
pub const REPLY_CAP: usize = 3;

/// The period the cap counts over (SF-16).
pub const REPLY_CAP_PERIOD: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// The most replies remembered for one sender, so that the memory stays finite whatever cap a
/// caller gives.
const REMEMBERED_REPLIES: usize = 1_000;

/// How often a sender who may not ask is answered (SF-16). The standard values are the constants
/// above. The fields are open so that a test can switch one bound off and show the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyLimits {
    /// At most one reply in this long. Zero switches the spacing off.
    pub spacing: std::time::Duration,
    /// At most this many replies in `period`. Zero means no reply at all, the safe way to be wrong.
    pub cap: usize,
    /// The period the cap counts over.
    pub period: std::time::Duration,
}

impl ReplyLimits {
    /// The limits the worker runs with.
    pub const STANDARD: Self = Self {
        spacing: REPLY_WINDOW,
        cap: REPLY_CAP,
        period: REPLY_CAP_PERIOD,
    };
}

impl Default for ReplyLimits {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// Which bound held a reply back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Withheld {
    /// A reply was posted to the sender a moment ago.
    Spacing,
    /// The sender has had the most replies the period allows.
    Cap,
}

impl Withheld {
    /// The word the record carries after `withheld=`.
    const fn word(self) -> &'static str {
        match self {
            Self::Spacing => "spacing",
            Self::Cap => "cap",
        }
    }
}

/// How many requests one pass answers for one tenant.
const PER_PASS: usize = 10;

/// The audit pages read in one pass.
const PAGES_PER_PASS: usize = 20;

/// The records in a page.
const PAGE: u32 = 500;

/// The most requests held in memory for one tenant.
const KEPT: usize = 5_000;

/// What a request says, as the subject of the audit record. The API writes it and the worker reads
/// it, so the one grammar is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionFields {
    /// The registered repository, by the id the API resolved from the installation and the
    /// repository ids of the delivery. Never the name in the payload.
    pub repository: RepositoryId,
    /// The issue number.
    pub issue: u64,
    /// The numeric GitHub id of the sender, when the delivery had one.
    pub sender: Option<u64>,
    /// The delivery id (`X-GitHub-Delivery`), in the shape the verifier accepts.
    pub delivery: String,
    /// The version of the allowlist the API read, `sha256:` and 64 hex digits.
    pub allowlist: String,
}

impl RejectionFields {
    /// The canonical words: `rejection repository=<id> issue=<n> sender=<id|none> delivery=<id>
    /// allowlist=<version>`.
    #[must_use]
    pub fn subject(&self) -> String {
        format!(
            "rejection repository={} issue={} sender={} delivery={} allowlist={}",
            self.repository.as_text(),
            self.issue,
            self.sender
                .map_or_else(|| "none".to_owned(), |id| id.to_string()),
            self.delivery,
            self.allowlist,
        )
    }

    /// Reads the canonical words back. `None` for any other text, including the same words in
    /// another form.
    #[must_use]
    pub fn parse_canonical(text: &str) -> Option<Self> {
        let mut words = text.split(' ');
        if words.next()? != "rejection" {
            return None;
        }
        let repository = RepositoryId::parse(words.next()?.strip_prefix("repository=")?).ok()?;
        let issue = words.next()?.strip_prefix("issue=")?.parse().ok()?;
        let sender = match words.next()?.strip_prefix("sender=")? {
            "none" => None,
            number => Some(number.parse().ok()?),
        };
        let delivery = words.next()?.strip_prefix("delivery=")?.to_owned();
        let allowlist = words.next()?.strip_prefix("allowlist=")?.to_owned();
        if words.next().is_some()
            || !(8..=128).contains(&delivery.len())
            || !delivery
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
            || Sha256Digest::parse(&allowlist).is_err()
        {
            return None;
        }
        let fields = Self {
            repository,
            issue,
            sender,
            delivery,
            allowlist,
        };
        (fields.subject() == text).then_some(fields)
    }
}

/// A request that has no record yet.
#[derive(Debug, Clone)]
struct Pending {
    id: AuditEventId,
    correlation: CorrelationId,
    fields: RejectionFields,
    /// When the database wrote the request.
    at: Timestamp,
    failures: u32,
}

#[derive(Default)]
struct Scan {
    cursor: u64,
    pending: BTreeMap<u64, Pending>,
    /// When the replies to each sender were posted, from the log, oldest first and bounded: the
    /// sender's numeric id, or `None` for a delivery that carried none.
    replied: BTreeMap<Option<u64>, Vec<Timestamp>>,
}

impl Scan {
    /// Notes a reply posted at `at`, keeping the list in order and bounded.
    fn note_reply(&mut self, sender: Option<u64>, at: Timestamp) {
        let times = self.replied.entry(sender).or_default();
        let place = times.partition_point(|held| *held <= at);
        times.insert(place, at);
        if times.len() > REMEMBERED_REPLIES {
            times.remove(0);
        }
    }
}

/// Which bound, if any, holds back a request made at `request_at` for a sender who was answered at
/// `replies`. `None` when the sender is to be answered. A reply counts for a bound while the
/// request is made before the reply's time plus the length of the bound, so a reply noted later
/// than the request holds it back too: the safer way to be wrong.
fn withheld(
    limits: &ReplyLimits,
    replies: &[Timestamp],
    request_at: Timestamp,
) -> Option<Withheld> {
    let inside = |length: std::time::Duration| {
        replies
            .iter()
            .filter(|at| at.checked_add(length).is_some_and(|end| request_at < end))
            .count()
    };
    if inside(limits.spacing) > 0 {
        Some(Withheld::Spacing)
    } else if inside(limits.period) >= limits.cap {
        Some(Withheld::Cap)
    } else {
        None
    }
}

/// The sender and the time of a rejection record that says the reply was posted, or `None` for a
/// record that says anything else.
fn posted_reply(record: &AuditRecord) -> Option<(Option<u64>, Timestamp)> {
    if !matches!(record.event.actor, AuditActor::System(_)) {
        return None;
    }
    let mut sender = None;
    let mut posted = false;
    for word in record.event.subject.split(' ') {
        if let Some(id) = word.strip_prefix("sender=") {
            sender = Some(id.parse::<u64>().ok());
        } else if word == "reply=posted" {
            posted = true;
        }
    }
    posted.then_some((sender?, record.created_at))
}

/// What became of the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    Posted,
    /// The reply cannot be sent and will not be: the host refused, or the repository is not here.
    NotSent,
    /// The sender was answered enough already, and the bound named holds this one back (SF-16).
    Suppressed(Withheld),
    /// The host could not be reached or asked for time. Try again next pass.
    Later,
}

/// What [`IntakeRejections`] is built from.
pub struct IntakeRejectionsDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The change host the reply goes through.
    pub host: Arc<dyn ChangeHost>,
    /// The hash of the policy in force, written on the record.
    pub policy_hash: Sha256Digest,
    /// The keys the API signs its requests with.
    pub keys: Arc<DecisionKeys>,
    /// How often a sender is answered ([`ReplyLimits::STANDARD`] in the worker).
    pub limits: ReplyLimits,
}

/// Answers the labels the API refused, and records the rejection. A step of the hook before each
/// claim ([`crate::decisions::ClaimWork::with_rejections`]).
pub struct IntakeRejections {
    deps: IntakeRejectionsDeps,
    scans: Mutex<BTreeMap<TenantId, Scan>>,
}

impl IntakeRejections {
    /// The step, over its collaborators.
    #[must_use]
    pub fn new(deps: IntakeRejectionsDeps) -> Self {
        Self {
            deps,
            scans: Mutex::new(BTreeMap::new()),
        }
    }

    /// One pass for one tenant: read the new records, then answer what has no record yet.
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
                        tracing::warn!(%error, "the audit log cannot be read for rejections");
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
                        REJECTED => {
                            // Only the worker can write this action, so the row is the end of the
                            // request it names.
                            if let Some(id) = ended_request(&record) {
                                scan.pending.retain(|_, pending| pending.id != id);
                            }
                            if let Some((sender, at)) = posted_reply(&record) {
                                scan.note_reply(sender, at);
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

    /// The request a record is, when it is one: the API's own actor, no job, the canonical words,
    /// and the word that only the holder of the key can make. Anything else is ignored without a
    /// line: a row with this action and no good word is not a request.
    fn request_from(&self, tenant: TenantId, record: &AuditRecord) -> Option<Pending> {
        if record.event.job.is_some()
            || !matches!(&record.event.actor, AuditActor::Anonymous(slug) if slug.as_str() == "webhook")
        {
            return None;
        }
        let subject = read_rejection_subject(&record.event.subject)?;
        let signing = RejectionSigning {
            tenant,
            event: record.event.id,
            requested_at: &subject.requested_at,
            fields: &subject.fields,
        };
        if !self.deps.keys.verify_rejection(&signing, &subject.word) {
            return None;
        }
        Some(Pending {
            id: record.event.id,
            correlation: record.event.correlation_id,
            fields: subject.fields,
            at: record.created_at,
            failures: 0,
        })
    }

    // ---- answering ------------------------------------------------------------------------

    async fn settle(&self, tenant: TenantId, request: Pending) {
        // The bounds on the replies to a sender (SF-16). The requests of one pass are settled one
        // after the other, and a reply that was posted is noted before the next request is
        // checked, so two requests of one pass cannot both pass a bound that only one may.
        let sender = request.fields.sender;
        let held_back = {
            let scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
            let replies = scans
                .get(&tenant)
                .and_then(|scan| scan.replied.get(&sender))
                .map_or(&[][..], Vec::as_slice);
            withheld(&self.deps.limits, replies, request.at)
        };
        let (reply, repository) = if let Some(bound) = held_back {
            (Reply::Suppressed(bound), None)
        } else {
            self.reply(tenant, &request).await
        };
        let reply = match reply {
            Reply::Later if request.failures + 1 >= MAX_TRIES => Reply::NotSent,
            Reply::Later => {
                self.with_scan(tenant, |scan| {
                    if let Some(held) = scan
                        .pending
                        .values_mut()
                        .find(|pending| pending.id == request.id)
                    {
                        held.failures += 1;
                    }
                });
                return;
            }
            settled => settled,
        };
        if self
            .record(tenant, &request, repository.as_ref(), reply)
            .await
        {
            if reply == Reply::Posted {
                self.with_scan(tenant, |scan| scan.note_reply(sender, request.at));
            }
            tracing::info!(
                code = REASON_CODE,
                replied = reply == Reply::Posted,
                "a label from someone who may not ask was answered"
            );
            self.with_scan(tenant, |scan| {
                scan.pending.retain(|_, pending| pending.id != request.id);
            });
        }
    }

    /// Posts the reply. The repository is the registered one, found by id in this tenant.
    async fn reply(&self, tenant: TenantId, request: &Pending) -> (Reply, Option<RepoRef>) {
        let repository = match self.repository(tenant, request.fields.repository).await {
            Ok(Some(repository)) => repository,
            Ok(None) => return (Reply::NotSent, None),
            Err(()) => return (Reply::Later, None),
        };
        let scope = GitScope {
            tenant,
            job: JobId::from_uuid(request.id.as_uuid()),
            stage: StageKind::Approval,
            repo: repository.clone(),
        };
        let target = CommentTarget::Issue(IssueRef {
            repo: repository.clone(),
            number: request.fields.issue,
        });
        let key = format!("intake-rejected-{}", request.fields.delivery);
        let posted = self
            .deps
            .host
            .post_comment(&scope, &target, REPLY, &key)
            .await;
        let reply = match posted {
            Ok(_) => Reply::Posted,
            Err(GitHostError::Unavailable | GitHostError::RateLimited { .. }) => Reply::Later,
            Err(_) => Reply::NotSent,
        };
        // The token was for this reply only. It is ended when the reply is settled, not before: a
        // host that is asked again later refuses a job whose tokens were ended.
        if reply != Reply::Later {
            let _ = self.deps.host.revoke_job_tokens(scope.job).await;
        }
        (reply, Some(repository))
    }

    /// The registered repository, when it is in the tenant and still enabled. `Err` when the store
    /// cannot answer.
    async fn repository(&self, tenant: TenantId, id: RepositoryId) -> Result<Option<RepoRef>, ()> {
        let mut tx = self
            .deps
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| ())?;
        let found = tx.get_repository(id).await;
        let _ = tx.rollback().await;
        match found {
            Ok(stored) if stored.value.enabled => Ok(RepoRef::parse(&stored.value.full_name).ok()),
            Ok(_) | Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(()),
        }
    }

    /// Writes the record of the rejection. True when it is written or already exists.
    async fn record(
        &self,
        tenant: TenantId,
        request: &Pending,
        repository: Option<&RepoRef>,
        reply: Reply,
    ) -> bool {
        let Ok(actor) = Slug::parse("worker.intake").map(AuditActor::System) else {
            return false;
        };
        let Ok(action) = AuditAction::new(REJECTED) else {
            return false;
        };
        let fields = &request.fields;
        let place = repository.map_or_else(
            || format!("repository {}", fields.repository.as_text()),
            ToString::to_string,
        );
        // Numbers, the delivery id and fixed words only: nothing the sender wrote.
        let subject = format!(
            "request={} issue={place}#{} sender={} delivery={} allowlist={} reply={}{}",
            request.id.as_uuid().hyphenated(),
            fields.issue,
            fields
                .sender
                .map_or_else(|| "none".to_owned(), |id| id.to_string()),
            fields.delivery,
            fields.allowlist,
            match reply {
                Reply::Posted => "posted",
                Reply::Suppressed(_) => "suppressed",
                Reply::NotSent | Reply::Later => "not_sent",
            },
            // A reply that was held back says which bound held it (SF-16).
            match reply {
                Reply::Suppressed(bound) => format!(" withheld={}", bound.word()),
                Reply::Posted | Reply::NotSent | Reply::Later => String::new(),
            },
        );
        let event = NewAuditEvent {
            id: self.deps.keys.rejection_id(request.id),
            actor,
            action,
            subject,
            decision: AuditDecision::Deny,
            reason: format!(
                "{REASON_CODE}: the sender of the label is not an authorized requester."
            ),
            policy_hash: self.deps.policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: request.correlation,
        };
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            return false;
        };
        match tx.record_audit(event).await {
            // A record that exists with other words is the record: the rejection is dealt with.
            Ok(_) | Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {}
            Err(_) => {
                let _ = tx.rollback().await;
                return false;
            }
        }
        tx.commit().await.is_ok()
    }
}

/// The request a `intake.rejected` record ends: the id after `request=` at the start of its
/// subject, when the actor is a component of the system.
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

    fn fields() -> RejectionFields {
        RejectionFields {
            repository: RepositoryId::from_uuid(uuid::Uuid::from_u128(0x77)),
            issue: 12,
            sender: Some(4242),
            delivery: "0190a3b2-7c4d-4e5f-8a6b-0000000000e6".to_owned(),
            allowlist: Sha256Digest::of(b"a file").as_str().to_owned(),
        }
    }

    #[test]
    fn the_words_read_back_as_they_were_written() {
        for sender in [Some(4242), None] {
            let written = RejectionFields { sender, ..fields() };
            assert_eq!(
                RejectionFields::parse_canonical(&written.subject()),
                Some(written)
            );
        }
    }

    #[test]
    fn text_that_is_not_the_canonical_words_is_not_read() {
        let good = fields().subject();
        for bad in [
            good.replace("rejection ", "rejected "),
            good.replace("sender=4242", "sender=-1"),
            good.replace("issue=12", "issue=twelve"),
            good.replace(
                "delivery=0190a3b2-7c4d-4e5f-8a6b-0000000000e6",
                "delivery=short",
            ),
            good.replace("delivery=0190", "delivery=01 90"),
            format!("{good} extra=words"),
            good.replace(' ', "  "),
            good.replace("allowlist=sha256:", "allowlist=sha1:"),
            good.replace("repository=", "repo="),
        ] {
            assert_eq!(RejectionFields::parse_canonical(&bad), None, "{bad}");
        }
    }

    #[test]
    fn the_subject_fits_the_audit_column_with_its_time_and_word() {
        let long = RejectionFields {
            sender: Some(u64::MAX),
            issue: u64::MAX,
            delivery: "d".repeat(128),
            ..fields()
        };
        let signed = format!(
            "{} at=2026-10-29T10:00:00.123456789Z mac={}",
            long.subject(),
            "a".repeat(64)
        );
        assert!(signed.len() <= 500, "{}", signed.len());
    }

    fn t(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a time")
    }

    #[test]
    fn a_request_inside_the_window_of_a_posted_reply_is_not_answered() {
        let replied = [t("2026-10-29T10:00:00Z")];
        let standard = ReplyLimits::STANDARD;
        // Nothing posted before: answer.
        assert_eq!(withheld(&standard, &[], t("2026-10-29T10:00:00Z")), None);
        // Inside the window.
        for at in ["2026-10-29T10:00:01Z", "2026-10-29T10:09:59Z"] {
            assert_eq!(
                withheld(&standard, &replied, t(at)),
                Some(Withheld::Spacing),
                "{at}"
            );
        }
        // At the end of the window and after it: answer again.
        for at in ["2026-10-29T10:10:00Z", "2026-10-29T11:00:00Z"] {
            assert_eq!(withheld(&standard, &replied, t(at)), None, "{at}");
        }
    }

    #[test]
    fn the_cap_counts_the_replies_of_the_period_and_the_spacing_comes_first() {
        let day = std::time::Duration::from_secs(24 * 60 * 60);
        let limits = ReplyLimits {
            spacing: std::time::Duration::from_secs(60),
            cap: 3,
            period: day,
        };
        let replies = [
            t("2026-10-29T10:00:00Z"),
            t("2026-10-29T12:00:00Z"),
            t("2026-10-29T14:00:00Z"),
        ];
        // Three replies in the period and none in the last minute: the cap holds the request.
        assert_eq!(
            withheld(&limits, &replies, t("2026-10-29T20:00:00Z")),
            Some(Withheld::Cap)
        );
        // Two of them (the oldest has aged out) is under the cap: answer.
        assert_eq!(withheld(&limits, &replies, t("2026-10-30T10:00:00Z")), None);
        // One second before the oldest ages out: still held.
        assert_eq!(
            withheld(&limits, &replies, t("2026-10-30T09:59:59Z")),
            Some(Withheld::Cap)
        );
        // A reply a moment ago is the spacing, also when the cap is reached too.
        assert_eq!(
            withheld(&limits, &replies, t("2026-10-29T14:00:30Z")),
            Some(Withheld::Spacing)
        );
        // Under the cap with no reply a moment ago: answer.
        assert_eq!(
            withheld(&limits, &replies[..2], t("2026-10-29T20:00:00Z")),
            None
        );
        // A cap of zero answers nobody, and a spacing of zero holds nobody.
        let none = ReplyLimits {
            spacing: std::time::Duration::ZERO,
            cap: 0,
            period: day,
        };
        assert_eq!(
            withheld(&none, &[], t("2026-10-29T10:00:00Z")),
            Some(Withheld::Cap)
        );
        let free = ReplyLimits {
            spacing: std::time::Duration::ZERO,
            cap: 10,
            period: day,
        };
        assert_eq!(withheld(&free, &replies, t("2026-10-29T14:00:00Z")), None);
    }

    #[test]
    fn the_replies_of_a_sender_are_kept_in_order_and_bounded() {
        let mut scan = Scan::default();
        for at in [
            "2026-10-29T12:00:00Z",
            "2026-10-29T10:00:00Z",
            "2026-10-29T11:00:00Z",
        ] {
            scan.note_reply(Some(1), t(at));
        }
        assert_eq!(
            scan.replied[&Some(1)],
            [
                t("2026-10-29T10:00:00Z"),
                t("2026-10-29T11:00:00Z"),
                t("2026-10-29T12:00:00Z")
            ]
        );
        for n in 0..(REMEMBERED_REPLIES + 5) {
            scan.note_reply(
                None,
                t("2026-10-30T00:00:00Z")
                    .checked_add(std::time::Duration::from_secs(n as u64))
                    .expect("a time"),
            );
        }
        assert_eq!(scan.replied[&None].len(), REMEMBERED_REPLIES);
    }

    #[test]
    fn only_a_rejection_that_says_posted_opens_a_window_and_it_names_its_sender() {
        let record = |subject: &str, actor: AuditActor| AuditRecord {
            sequence: 1,
            event: NewAuditEvent {
                id: AuditEventId::from_uuid(uuid::Uuid::from_u128(1)),
                actor,
                action: AuditAction::new(REJECTED).expect("an action"),
                subject: subject.to_owned(),
                decision: AuditDecision::Deny,
                reason: "unauthorized_actor: the sender is not an authorized requester.".to_owned(),
                policy_hash: Sha256Digest::of(b"policy"),
                job: None,
                stage_run: None,
                correlation_id: CorrelationId::from_uuid(uuid::Uuid::from_u128(2)),
            },
            created_at: Timestamp::parse("2026-10-29T10:00:00Z").expect("a time"),
            hash: Sha256Digest::of(b"hash"),
        };
        let system = || AuditActor::System(Slug::parse("worker.intake").expect("a slug"));
        let posted = record(
            "request=x issue=a/b#1 sender=42 delivery=d allowlist=a reply=posted",
            system(),
        );
        assert_eq!(
            posted_reply(&posted).map(|(sender, _)| sender),
            Some(Some(42))
        );
        let none = record(
            "request=x issue=a/b#1 sender=none delivery=d allowlist=a reply=posted",
            system(),
        );
        assert_eq!(posted_reply(&none).map(|(sender, _)| sender), Some(None));
        for not_a_window in ["reply=suppressed", "reply=not_sent"] {
            let other = record(
                &format!("request=x issue=a/b#1 sender=42 delivery=d allowlist=a {not_a_window}"),
                system(),
            );
            assert_eq!(posted_reply(&other), None, "{not_a_window}");
        }
        // A row that did not come from the worker opens nothing.
        let forged = record(
            "request=x issue=a/b#1 sender=42 delivery=d allowlist=a reply=posted",
            AuditActor::Anonymous(Slug::parse("webhook").expect("a slug")),
        );
        assert_eq!(posted_reply(&forged), None);
    }

    #[test]
    fn the_reply_is_short_names_nobody_and_does_not_look_like_a_secret() {
        assert!(REPLY.len() < 300);
        for revealing in ["allowlist", "@", "http", "sha256", "tenant"] {
            assert!(!REPLY.contains(revealing), "{revealing}");
        }
    }
}
