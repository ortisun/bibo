//! A small rig around the real approval service, the real engine and the in-memory store, with a
//! code host that a test can change behind the factory's back.
//!
//! It copies only what it needs from `tests/delivery/approval.rs`, whose own rig is private to
//! that target. Everything labelled fake is the testkit's fake.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::ids::{CausationId, JobId, LedgerEntryId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::authority::{Allowlist, AllowlistEntry, AutonomyLevel};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{Fidelity, HumanRole, RiskTier, StageKind};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{
    ChangeHost, CheckRef, CheckRequest, CommentRef, CommentTarget, DraftPrRequest, GitHostError,
    GitScope, GithubActor, Issue, IssueRef, IssueSource, ProtectionReport, PullRequestRef,
    PullRequestState,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::store::{ApprovalChannel, PrincipalKind};
use factory_ports::workspace::{FetchTarget, PushTarget};
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::workspace::FakeRemote;
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::approval::{
    ApprovalCommand, ApprovalDeps, ApprovalRequest, ApprovalService, ApprovalSources, Outcome,
    Sender, ServiceError, Verb,
};
use factory_workflow::stages::delivery::seams::CurrentValues;
use factory_workflow::stages::delivery::{DeliverySources, DeliveryTarget, LedgerState, SeamError};
use factory_workflow::stages::validation::Binding;

use crate::support::World;

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");

pub const REQUESTER: u64 = 1001;

pub fn policy() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

/// The code host as the factory sees it, except that a test may move the pull request to another
/// base branch, as anyone with write access to the repository can on the real host.
pub struct Moved {
    inner: FakeChangeHost,
    base: Mutex<Option<BranchName>>,
}

impl Moved {
    pub fn retarget(&self, base: &BranchName) {
        *self.base.lock().expect("lock") = Some(base.clone());
    }
}

#[async_trait]
impl ChangeHost for Moved {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
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
        key: &str,
    ) -> Result<CommentRef, GitHostError> {
        self.inner.post_comment(scope, target, body, key).await
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
        let mut state = self.inner.pull_request_state(scope, pr).await?;
        if let Some(base) = self.base.lock().expect("lock").clone() {
            state.base = base;
        }
        Ok(state)
    }
    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError> {
        self.inner.revoke_job_tokens(job).await
    }
}

struct Fixed {
    head: Mutex<Sha256Digest>,
    tree: GitSha,
    /// The only commit the job's object store holds. `StoreDeliverySources::tree_of` answers
    /// `NotFound` for any other (`UnknownCommit`), which is the case for a commit that someone
    /// else pushed to the branch.
    known: CommitSha,
}

#[async_trait]
impl DeliverySources for Fixed {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn target(&self, _run: &RunIdentity) -> Result<DeliveryTarget, SeamError> {
        Err(SeamError::NotFound)
    }
    async fn current_values(
        &self,
        _run: &RunIdentity,
        _base: &CommitSha,
    ) -> Result<CurrentValues, SeamError> {
        Ok(CurrentValues {
            definition_hash: Sha256Digest::of(b"definitions"),
            image_digest: Sha256Digest::of(b"image"),
        })
    }
    async fn ledger(&self, _run: &RunIdentity) -> Result<LedgerState, SeamError> {
        Ok(LedgerState {
            entry_count: 10,
            head_sequence: 10,
            head_hash: self.head.lock().expect("lock").clone(),
            chain_verified_at: Timestamp::parse("2026-10-27T10:00:00Z").expect("a time"),
            attained: Vec::new(),
            dispositions: Vec::<(_, LedgerEntryId)>::new(),
        })
    }
    async fn tree_of(&self, _run: &RunIdentity, commit: &CommitSha) -> Result<GitSha, SeamError> {
        if commit == &self.known {
            Ok(self.tree.clone())
        } else {
            Err(SeamError::NotFound)
        }
    }
}

struct Fixture {
    allowlist: Allowlist,
    request: ApprovalRequest,
}

#[async_trait]
impl ApprovalSources for Fixture {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn requester(&self, _run: &RunIdentity) -> Result<u64, SeamError> {
        Ok(REQUESTER)
    }
    async fn allowlist(&self, _tenant: TenantId) -> Result<Allowlist, SeamError> {
        Ok(self.allowlist.clone())
    }
    async fn level(&self, _tenant: TenantId, _job: JobId) -> Result<AutonomyLevel, SeamError> {
        Ok(AutonomyLevel::L1)
    }
    async fn request(
        &self,
        _tenant: TenantId,
        _stage_run: StageRunId,
    ) -> Result<ApprovalRequest, SeamError> {
        Ok(self.request.clone())
    }
}

struct NoComments;

#[async_trait]
impl IssueSource for NoComments {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn fetch_issue(&self, _: &GitScope, _: &IssueRef) -> Result<Issue, GitHostError> {
        Err(GitHostError::NotFound)
    }
    async fn fetch_comment(
        &self,
        _: &GitScope,
        _: &CommentRef,
    ) -> Result<factory_ports::githost::Comment, GitHostError> {
        Err(GitHostError::NotFound)
    }
    async fn label_actor(
        &self,
        _: &GitScope,
        _: &IssueRef,
        _: &str,
    ) -> Result<Option<GithubActor>, GitHostError> {
        Ok(None)
    }
    async fn repository_protection(&self, _: &GitScope) -> Result<ProtectionReport, GitHostError> {
        Err(GitHostError::NotFound)
    }
}

pub struct Rig {
    remote: FakeRemote,
    repo: RepoRef,
    branch: BranchName,
    pub w: World,
    pub host: Arc<Moved>,
    pub service: ApprovalService,
    pub job: JobId,
    pub run: StageRunId,
    pub request: ApprovalRequest,
    pub approver: u64,
    fixed: Arc<Fixed>,
}

async fn github_id(w: &World, principal: PrincipalId) -> u64 {
    let mut tx = w
        .store
        .begin(TenantScope::new(w.tenant))
        .await
        .expect("a tx");
    match tx.get_principal(principal).await.expect("a principal").kind {
        PrincipalKind::Human { github_user_id } => github_user_id,
        PrincipalKind::Service => unreachable!("a person"),
    }
}

impl Rig {
    /// A job at the approval stage, a draft pull request from `factory/job-1` into `main`, and
    /// one approver on the allowlist who is not the requester.
    pub async fn new(tier: RiskTier) -> Self {
        let w = World::new().await;
        let (job, run) = w.at_approval().await;
        let repo = RepoRef::parse("example-org/fixture").expect("a repo");
        let remote = FakeRemote::new();
        let main = BranchName::new("main").expect("a branch");
        let branch = BranchName::new("factory/job-1").expect("a branch");
        let release = BranchName::new("release").expect("a branch");
        let base = remote.commit_on_branch(&repo, &main, &[("README.md", "base")]);
        let _ = remote.commit_on_branch(&repo, &release, &[("README.md", "another base")]);
        let code_head = remote.commit_on_branch(&repo, &branch, &[("README.md", "change")]);
        let head = remote.commit_on_branch(
            &repo,
            &branch,
            &[("README.md", "change"), ("docs/guide.md", "A guide")],
        );
        let host = Arc::new(Moved {
            inner: FakeChangeHost::sharing(remote.clone()),
            base: Mutex::new(None),
        });
        let git = GitScope {
            tenant: w.tenant,
            job,
            stage: StageKind::Delivery,
            repo: repo.clone(),
        };
        let pr = host
            .open_draft_pull_request(
                &git,
                DraftPrRequest {
                    head: branch.clone(),
                    base: main,
                    title: "Add a flag".to_owned(),
                    body: "Closes #1".to_owned(),
                },
            )
            .await
            .expect("a pull request");

        let principal = w.person("approver", &[HumanRole::Approver]).await;
        let approver = github_id(&w, principal).await;
        let entry = |id: u64, held: &[Designation]| AllowlistEntry {
            tenant: w.tenant,
            github_user_id: GithubUserId::new(id).expect("an id"),
            login: format!("person-{id}"),
            designations: held.iter().copied().collect::<BTreeSet<_>>(),
            repositories: None,
            expires_at: None,
        };
        let allowlist = Allowlist::new(
            "allowlist-version-one",
            vec![
                entry(approver, &[Designation::Approver]),
                entry(REQUESTER, &[Designation::Requester]),
            ],
        )
        .expect("an allowlist");

        let tree = GitSha::parse(&"d".repeat(40)).expect("a sha");
        let request = ApprovalRequest {
            repository: repo.to_string(),
            pull_request: pr.number,
            head_branch: "factory/job-1".to_owned(),
            base_branch: "main".to_owned(),
            pr_head: GitSha::parse(head.as_str()).expect("a sha"),
            tree: tree.clone(),
            base: GitSha::parse(base.as_str()).expect("a sha"),
            manifest: Sha256Digest::of(b"manifest"),
            spec_version: 1,
            gates_clear: true,
            open_translation_warnings: 0,
            tier,
            protected_path_change: false,
            sensitive_file_change: false,
            new_dependency: false,
            requester: REQUESTER,
            evidence_binding: Binding {
                implementation_result: Sha256Digest::of(b"result"),
                base_commit: GitSha::parse(base.as_str()).expect("a sha"),
                head_commit: GitSha::parse(code_head.as_str()).expect("a sha"),
                policy_hash: Sha256Digest::of(b"test policy"),
                image_digest: Sha256Digest::of(b"image"),
                definition_hash: Sha256Digest::of(b"definitions"),
            },
            created_at: w.clock.now(),
        };
        let fixed = Arc::new(Fixed {
            head: Mutex::new(w.head(job).await),
            tree,
            known: head.clone(),
        });
        let redactor = Arc::new(
            factory_domain::redaction::Redactor::builder()
                .pattern(
                    "canary",
                    "tok_[A-Za-z0-9]{20}",
                    factory_domain::redaction::PatternAction::Block,
                )
                .build()
                .expect("a redactor"),
        );
        let service = ApprovalService::new(ApprovalDeps {
            engine: Arc::new(w.restarted_engine()),
            store: w.store.clone(),
            host: host.clone(),
            issues: Arc::new(NoComments),
            policy: Arc::new(policy()),
            policy_hash: Sha256Digest::of(b"test policy"),
            delivery: fixed.clone(),
            approvals: Arc::new(Fixture {
                allowlist,
                request: request.clone(),
            }),
            clock: w.clock.clone(),
            ids: w.ids.clone(),
            redactor,
        });
        Self {
            remote,
            repo,
            branch,
            w,
            host,
            service,
            job,
            run,
            request,
            approver,
            fixed,
        }
    }

    /// Someone with write access pushes a commit to the factory branch. The job's object store has
    /// never seen it.
    pub fn push_foreign_commit(&self) -> CommitSha {
        self.remote.commit_on_branch(
            &self.repo,
            &self.branch,
            &[("README.md", "changed by someone else")],
        )
    }

    /// An approval by the approver, who saw what the request holds and the ledger as it is now.
    pub async fn approve(&self) -> Result<Outcome, ServiceError> {
        let head = self.w.head(self.job).await;
        *self.fixed.head.lock().expect("lock") = head.clone();
        let seen = self.request.seen_with(head);
        self.service
            .submit(ApprovalCommand {
                id: CausationId::from_uuid(self.w.ids.new_uuid()),
                tenant: self.w.tenant,
                job: self.job,
                stage_run: self.run,
                verb: Verb::Approve,
                sender: Sender {
                    id: self.approver,
                    login: factory_ports::githost::ActorLogin::new("someone").expect("a login"),
                    kind: factory_domain::policy::authority::ActorKind::User,
                },
                channel: ApprovalChannel::Dashboard,
                reason: "The change does what the specification says.".to_owned(),
                seen: Some(seen),
                warnings_decided: true,
                rework_target: None,
                solo: None,
                comment: None,
            })
            .await
    }
}
