//! A label from someone who may not ask the factory for work (FR-002 and SC-002 of the
//! specification, finding SF-01 of the Slice 1 run).
//!
//! The API makes no job for such a label and leaves one signed request in the audit log. The
//! worker's step before each claim (`IntakeRejections`) reads it, posts one plain reply on the
//! issue through the change host, and leaves the record `intake.rejected`. Real: PostgreSQL, the
//! signing, the hook. Fake and labelled so: the change host.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_composition::decision_signing::{DecisionKeys, RejectionSigning};
use factory_composition::intake_rejections::{
    IntakeRejections, IntakeRejectionsDeps, REASON_CODE, REJECTED, REPLY, REQUESTED,
    RejectionFields,
};
use factory_domain::ids::{AuditEventId, CorrelationId, RepositoryId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{
    ChangeHost, CheckRef, CheckRequest, CommentRef, CommentTarget, DraftPrRequest, GitHostError,
    GitScope, IssueRef, PullRequestRef, PullRequestState,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, AuditRecord, NewAuditEvent, Store,
};
use factory_ports::workspace::{FetchTarget, PushTarget};
use factory_testkit::githost::FakeChangeHost;
use support::pg_world;

const REPOSITORY: &str = "org/repo-0";
const ISSUE: u64 = 12;
/// What a payload could carry that must never reach the reply or the record.
const LOGIN_IN_PAYLOAD: &str = "mallory-the-sender";

/// A change host that can be told to fail, in front of the fake. Labelled as a fake by the fake.
struct Hosting {
    inner: Arc<FakeChangeHost>,
    /// Errors for the next calls to `post_comment`, taken from the front.
    fail_next: Mutex<Vec<GitHostError>>,
    /// An error for every call to `post_comment`.
    always: Option<GitHostError>,
    posts: AtomicUsize,
}

impl Hosting {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(FakeChangeHost::new()),
            fail_next: Mutex::new(Vec::new()),
            always: None,
            posts: AtomicUsize::new(0),
        })
    }

    fn failing(error: GitHostError) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(FakeChangeHost::new()),
            fail_next: Mutex::new(Vec::new()),
            always: Some(error),
            posts: AtomicUsize::new(0),
        })
    }

    fn failing_first(errors: Vec<GitHostError>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(FakeChangeHost::new()),
            fail_next: Mutex::new(errors),
            always: None,
            posts: AtomicUsize::new(0),
        })
    }

    fn comments(&self) -> Vec<String> {
        self.inner.comments_on(&issue_target())
    }
}

fn issue_target() -> CommentTarget {
    CommentTarget::Issue(IssueRef {
        repo: RepoRef::parse(REPOSITORY).expect("a repository"),
        number: ISSUE,
    })
}

#[async_trait]
impl ChangeHost for Hosting {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn fetch_target(&self, scope: &GitScope) -> Result<FetchTarget, GitHostError> {
        self.inner.fetch_target(scope).await
    }

    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError> {
        self.inner.push_target(scope, branch).await
    }

    async fn resolve_branch(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<CommitSha, GitHostError> {
        self.inner.resolve_branch(scope, branch).await
    }

    async fn open_draft_pull_request(
        &self,
        scope: &GitScope,
        req: DraftPrRequest,
    ) -> Result<PullRequestRef, GitHostError> {
        self.inner.open_draft_pull_request(scope, req).await
    }

    async fn update_pull_request_body(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        body: &str,
        etag: Option<&str>,
    ) -> Result<(), GitHostError> {
        self.inner
            .update_pull_request_body(scope, pr, body, etag)
            .await
    }

    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<CommentRef, GitHostError> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = &self.always {
            return Err(error.clone());
        }
        {
            let mut next = self.fail_next.lock().expect("lock");
            if !next.is_empty() {
                return Err(next.remove(0));
            }
        }
        self.inner
            .post_comment(scope, target, body, idempotency_key)
            .await
    }

    async fn publish_check(
        &self,
        scope: &GitScope,
        req: CheckRequest,
    ) -> Result<CheckRef, GitHostError> {
        self.inner.publish_check(scope, req).await
    }

    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError> {
        self.inner.pull_request_state(scope, pr).await
    }

    async fn revoke_job_tokens(&self, job: factory_domain::ids::JobId) -> Result<(), GitHostError> {
        self.inner.revoke_job_tokens(job).await
    }
}

struct Rig {
    _db: support::TestDb,
    world: support::engine::PgWorld,
    tenant: TenantId,
    repository: RepositoryId,
    keys: Arc<DecisionKeys>,
    policy_hash: Sha256Digest,
}

impl Rig {
    async fn new() -> Self {
        let (db, world, tenant) = pg_world().await;
        let repository = world.repository;
        Self {
            _db: db,
            world,
            tenant,
            repository,
            keys: Arc::new(DecisionKeys::generated().expect("a signing key")),
            policy_hash: Sha256Digest::of(b"the policy in force"),
        }
    }

    fn hook_over(&self, host: Arc<dyn ChangeHost>) -> IntakeRejections {
        IntakeRejections::new(IntakeRejectionsDeps {
            store: self.world.store.clone(),
            host,
            policy_hash: self.policy_hash.clone(),
            keys: self.keys.clone(),
        })
    }

    fn fields(&self, delivery: &str, sender: Option<u64>) -> RejectionFields {
        RejectionFields {
            repository: self.repository,
            issue: ISSUE,
            sender,
            delivery: delivery.to_owned(),
            allowlist: Sha256Digest::of(b"the allowlist file").as_str().to_owned(),
        }
    }

    /// Writes the record that the API writes for a label it refused, signed with the API's key.
    async fn request(&self, fields: &RejectionFields) -> AuditEventId {
        let id = AuditEventId::from_uuid(self.world.ids.new_uuid());
        let subject = self.keys.signed_rejection_subject(&RejectionSigning {
            tenant: self.tenant,
            event: id,
            requested_at: "2026-10-29T10:00:00Z",
            fields,
        });
        self.write_request(id, subject).await;
        id
    }

    async fn write_request(&self, id: AuditEventId, subject: String) {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        tx.record_audit(NewAuditEvent {
            id,
            actor: AuditActor::Anonymous(Slug::parse("webhook").expect("a slug")),
            action: AuditAction::new(REQUESTED).expect("an action"),
            subject,
            decision: AuditDecision::Deny,
            reason: "A label from a sender who is not an authorized requester was refused."
                .to_owned(),
            policy_hash: self.policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(self.world.ids.new_uuid()),
        })
        .await
        .expect("the request is recorded");
        tx.commit().await.expect("commit");
    }

    async fn records(&self, action: &str) -> Vec<AuditRecord> {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let all = tx
            .read_audit(AuditFilter::Tenant, 0, 500)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        all.into_iter()
            .filter(|record| record.event.action.as_str() == action)
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_request_gets_one_plain_reply_and_one_audit_record() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    let fields = rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(4242));
    let request = rig.request(&fields).await;

    hook.pass(rig.tenant).await;

    assert_eq!(host.comments(), vec![REPLY.to_owned()], "one reply");
    let records = rig.records(REJECTED).await;
    assert_eq!(records.len(), 1, "one record of the rejection");
    let event = &records[0].event;
    assert_eq!(event.decision, AuditDecision::Deny);
    assert!(event.job.is_none(), "a rejection makes no job");
    assert!(
        event.reason.starts_with(REASON_CODE),
        "the fixed reason code comes first: {}",
        event.reason
    );
    for wanted in [
        format!("request={}", request.as_uuid().hyphenated()),
        format!("issue={REPOSITORY}#{ISSUE}"),
        "sender=4242".to_owned(),
        "delivery=0190a3b2-7c4d-4e5f-8a6b-0000000000e6".to_owned(),
        format!("allowlist={}", fields.allowlist),
        "reply=posted".to_owned(),
    ] {
        assert!(
            event.subject.contains(&wanted),
            "the record lacks {wanted}: {}",
            event.subject
        );
    }
    // The id of the record is a keyed function of the request, so a second write is a repeat.
    assert_eq!(event.id, rig.keys.rejection_id(request));
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_after_the_first_add_neither_a_reply_nor_a_record() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    rig.request(&rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1)))
        .await;
    for _ in 0..4 {
        hook.pass(rig.tenant).await;
    }
    // A worker that starts again reads the log from the beginning and finds the same request.
    let restarted = rig.hook_over(host.clone());
    restarted.pass(rig.tenant).await;
    assert_eq!(host.comments().len(), 1, "one reply");
    assert_eq!(rig.records(REJECTED).await.len(), 1, "one record");
    assert_eq!(
        host.posts.load(Ordering::SeqCst),
        1,
        "the restarted worker finds the record of the rejection and asks the host for nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_requests_for_one_delivery_get_one_reply() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    let fields = rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1));
    rig.request(&fields).await;
    rig.request(&fields).await;
    hook.pass(rig.tenant).await;
    assert_eq!(
        host.comments().len(),
        1,
        "the reply is keyed by the delivery id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_nobody_signed_or_signed_with_another_key_or_changed_is_ignored() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    let fields = rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1));

    // Unsigned: the canonical words alone.
    let unsigned = AuditEventId::from_uuid(rig.world.ids.new_uuid());
    rig.write_request(unsigned, fields.subject()).await;

    // Signed with a key the worker does not hold.
    let other = DecisionKeys::generated().expect("another key");
    let strange = AuditEventId::from_uuid(rig.world.ids.new_uuid());
    rig.write_request(
        strange,
        other.signed_rejection_subject(&RejectionSigning {
            tenant: rig.tenant,
            event: strange,
            requested_at: "2026-10-29T10:00:00Z",
            fields: &fields,
        }),
    )
    .await;

    // Signed, then the issue number changed in the row.
    let changed = AuditEventId::from_uuid(rig.world.ids.new_uuid());
    let good = rig.keys.signed_rejection_subject(&RejectionSigning {
        tenant: rig.tenant,
        event: changed,
        requested_at: "2026-10-29T10:00:00Z",
        fields: &fields,
    });
    rig.write_request(changed, good.replace("issue=12", "issue=13"))
        .await;

    // Signed for another event id: a copy of a good row under a new id.
    let copied = AuditEventId::from_uuid(rig.world.ids.new_uuid());
    let copy_of = rig.keys.signed_rejection_subject(&RejectionSigning {
        tenant: rig.tenant,
        event: AuditEventId::from_uuid(rig.world.ids.new_uuid()),
        requested_at: "2026-10-29T10:00:00Z",
        fields: &fields,
    });
    rig.write_request(copied, copy_of).await;

    hook.pass(rig.tenant).await;
    assert_eq!(host.posts.load(Ordering::SeqCst), 0, "nothing was posted");
    assert!(
        rig.records(REJECTED).await.is_empty(),
        "nothing was recorded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_kind_of_sender_gets_the_same_words_and_the_words_name_nobody() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    // A person the tenant does not know, a person who was disabled, and a person narrowed to other
    // repositories look the same to the worker: the API's reason is not in the request, and the
    // reply is one constant text.
    for (n, sender) in [Some(999_999), Some(31_337), Some(7), None]
        .iter()
        .enumerate()
    {
        rig.request(&rig.fields(&format!("0190a3b2-7c4d-4e5f-8a6b-00000000{n:04}"), *sender))
            .await;
    }
    hook.pass(rig.tenant).await;
    let comments = host.comments();
    // Four deliveries, four replies, the same words in each.
    assert_eq!(comments.len(), 4);
    assert!(
        comments.iter().all(|text| text == REPLY),
        "the replies differ: {comments:#?}"
    );
    for reveal in [
        "999999",
        "31337",
        LOGIN_IN_PAYLOAD,
        "allowlist",
        "sha256",
        "tenant",
        "@",
    ] {
        assert!(!REPLY.contains(reveal), "the reply contains {reveal}");
    }
    assert!(
        REPLY.contains("list of people who may ask for this"),
        "the reply says why in the one way the specification allows: {REPLY}"
    );
    // The records differ only in the numeric id and the delivery.
    let subjects: Vec<String> = rig
        .records(REJECTED)
        .await
        .into_iter()
        .map(|record| record.event.subject)
        .collect();
    assert_eq!(subjects.len(), 4);
    assert!(subjects.iter().any(|s| s.contains("sender=none")));
    assert!(
        subjects.iter().all(|s| !s.contains(LOGIN_IN_PAYLOAD)),
        "{subjects:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_is_down_is_asked_again_and_the_reply_is_sent_once() {
    let rig = Rig::new().await;
    let host = Hosting::failing_first(vec![
        GitHostError::Unavailable,
        GitHostError::RateLimited { retry_after: None },
    ]);
    let hook = rig.hook_over(host.clone());
    rig.request(&rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1)))
        .await;
    hook.pass(rig.tenant).await;
    assert!(host.comments().is_empty(), "the host was down");
    assert!(
        rig.records(REJECTED).await.is_empty(),
        "the record waits for the reply to settle"
    );
    hook.pass(rig.tenant).await;
    hook.pass(rig.tenant).await;
    assert_eq!(host.comments(), vec![REPLY.to_owned()]);
    let records = rig.records(REJECTED).await;
    assert_eq!(records.len(), 1);
    assert!(records[0].event.subject.contains("reply=posted"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reply_that_can_never_be_sent_still_leaves_the_record_and_says_so() {
    let rig = Rig::new().await;
    let host = Hosting::failing(GitHostError::Forbidden);
    let hook = rig.hook_over(host.clone());
    rig.request(&rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1)))
        .await;
    hook.pass(rig.tenant).await;
    hook.pass(rig.tenant).await;
    assert!(host.comments().is_empty());
    let records = rig.records(REJECTED).await;
    assert_eq!(
        records.len(),
        1,
        "the rejection is audited whether or not it could be explained"
    );
    assert!(records[0].event.subject.contains("reply=not_sent"));
    assert_eq!(
        host.posts.load(Ordering::SeqCst),
        1,
        "a refusal is not tried again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reply_uses_a_token_for_one_repository_that_can_write_issues_and_nothing_else() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    rig.request(&rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1)))
        .await;
    hook.pass(rig.tenant).await;
    let tokens = host.inner.minted_tokens();
    assert_eq!(tokens.len(), 1, "one token: {tokens:#?}");
    assert_eq!(
        tokens[0].repository,
        RepoRef::parse(REPOSITORY).expect("repo")
    );
    let writes: Vec<&str> = tokens[0]
        .permissions
        .iter()
        .filter(|(_, level)| *level == "write")
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(writes, ["issues"], "{tokens:#?}");
    assert!(
        tokens[0].revoked,
        "the token is ended when the reply is done"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_of_another_tenant_is_not_answered_by_this_one() {
    let rig = Rig::new().await;
    let host = Hosting::new();
    let hook = rig.hook_over(host.clone());
    let mut fields = rig.fields("0190a3b2-7c4d-4e5f-8a6b-0000000000e6", Some(1));
    // A repository id that is not in this tenant.
    fields.repository = RepositoryId::from_uuid(uuid::Uuid::from_u128(0xdead));
    rig.request(&fields).await;
    hook.pass(rig.tenant).await;
    assert!(
        host.comments().is_empty(),
        "no reply on a repository this tenant does not hold"
    );
    let records = rig.records(REJECTED).await;
    assert_eq!(records.len(), 1, "but the rejection is still audited");
    assert!(records[0].event.subject.contains("reply=not_sent"));
}
