//! The approval service against the real engine: a job waits at the approval, a person decides,
//! and the engine moves (or refuses to move) the stage run.
//!
//! The scripted stage handlers of the engine tests stand in for every stage, and the code host is
//! the in-memory fake behind the recording wrapper. What is real here is the engine, its guards
//! and its role check, the in-memory store with its approval and audit operations, and the policy.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::ids::{CausationId, JobId, LedgerEntryId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::authority::{Allowlist, AllowlistEntry, AutonomyLevel};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{Fidelity, HumanRole, RiskTier, StageKind};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{
    ActorLogin, ChangeHost, Comment, CommentRef, CommentTarget, DraftPrRequest, GitHostError,
    GitScope, GithubActor, Issue, IssueRef, IssueSource, ProtectionReport, PullRequestRef,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::store::{ApprovalChannel, ApprovalInvalidation, AuditFilter, PrincipalKind};
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::workspace::FakeRemote;
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::approval::{
    ApprovalCommand, ApprovalDeps, ApprovalRequest, ApprovalService, ApprovalSources,
    CommentEvidence, NotACommand, Outcome, Refusal, Sender, ServiceError, Verb,
};
use factory_workflow::stages::delivery::seams::CurrentValues;
use factory_workflow::stages::delivery::{DeliverySources, DeliveryTarget, LedgerState, SeamError};
use factory_workflow::stages::validation::Binding;

use crate::judging::{self, policy};
use crate::spy::{Call, Spy};
use crate::support::world::World;

/// The head of the evidence ledger, which a test updates from the engine's own ledger.
struct Fixed {
    head: Mutex<Sha256Digest>,
    values: Mutex<CurrentValues>,
    tree: GitSha,
    /// The only commit the job's object store holds. The real source answers "not found" for a
    /// commit that someone else pushed to the branch (AUT-2).
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
        Ok(self.values.lock().expect("lock").clone())
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
    allowlist: Mutex<Allowlist>,
    request: Mutex<ApprovalRequest>,
}

#[async_trait]
impl ApprovalSources for Fixture {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn requester(&self, _run: &RunIdentity) -> Result<u64, SeamError> {
        Ok(judging::REQUESTER)
    }
    async fn allowlist(&self, _tenant: TenantId) -> Result<Allowlist, SeamError> {
        Ok(self.allowlist.lock().expect("lock").clone())
    }
    async fn level(&self, _tenant: TenantId, _job: JobId) -> Result<AutonomyLevel, SeamError> {
        Ok(AutonomyLevel::L1)
    }
    async fn request(
        &self,
        _tenant: TenantId,
        _stage_run: StageRunId,
    ) -> Result<ApprovalRequest, SeamError> {
        Ok(self.request.lock().expect("lock").clone())
    }
}

/// The comments the code host holds.
#[derive(Default)]
struct Comments {
    held: Mutex<Vec<Comment>>,
}

#[async_trait]
impl IssueSource for Comments {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn fetch_issue(
        &self,
        _scope: &GitScope,
        _issue: &IssueRef,
    ) -> Result<Issue, GitHostError> {
        Err(GitHostError::NotFound)
    }
    async fn fetch_comment(
        &self,
        _scope: &GitScope,
        comment: &CommentRef,
    ) -> Result<Comment, GitHostError> {
        self.held
            .lock()
            .expect("lock")
            .iter()
            .find(|held| &held.reference == comment)
            .cloned()
            .ok_or(GitHostError::NotFound)
    }
    async fn label_actor(
        &self,
        _scope: &GitScope,
        _issue: &IssueRef,
        _label: &str,
    ) -> Result<Option<GithubActor>, GitHostError> {
        Ok(None)
    }
    async fn repository_protection(
        &self,
        _scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError> {
        Err(GitHostError::NotFound)
    }
}

struct Rig {
    w: World,
    host: Arc<Spy>,
    comments: Arc<Comments>,
    fixed: Arc<Fixed>,
    fixture: Arc<Fixture>,
    service: ApprovalService,
    pr: PullRequestRef,
    job: JobId,
    run: StageRunId,
    /// The head of the pull request: the documentation commit.
    head: CommitSha,
    /// The commit the gates ran on, under the head.
    code_head: CommitSha,
    people: Vec<(u64, PrincipalId)>,
}

fn designations(roles: &[Designation]) -> BTreeSet<Designation> {
    roles.iter().copied().collect()
}

impl Rig {
    async fn new(tier: RiskTier) -> Self {
        let w = World::new().await;
        let (job, run) = w.at_approval().await;
        let repo = RepoRef::parse("example-org/fixture").expect("a repo");
        let remote = FakeRemote::new();
        let main = BranchName::new("main").expect("a branch");
        let branch = BranchName::new("factory/job-1").expect("a branch");
        let base = remote.commit_on_branch(&repo, &main, &[("README.md", "base")]);
        // The branch holds the code, and the documentation commit on top of it is the head of the
        // pull request. The gates ran on the code commit.
        let code_head = remote.commit_on_branch(&repo, &branch, &[("README.md", "change")]);
        let head = remote.commit_on_branch(
            &repo,
            &branch,
            &[("README.md", "change"), ("docs/guide.md", "A guide")],
        );
        let host = Arc::new(Spy::new(FakeChangeHost::sharing(remote)));
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
                    head: branch,
                    base: main,
                    title: "Add a flag".to_owned(),
                    body: "Closes #1".to_owned(),
                },
            )
            .await
            .expect("a pull request");

        // The people: the engine knows them by role, the policy by the numeric id.
        let mut people = Vec::new();
        for (name, roles) in [
            ("approver", vec![HumanRole::Approver]),
            ("approver-two", vec![HumanRole::Approver]),
            // A security approver holds the engine role of that name and no other: the critical
            // tier names this designation alone, so it must be enough (AUT-3).
            ("security-one", vec![HumanRole::SecurityApprover]),
            ("security-two", vec![HumanRole::SecurityApprover]),
            ("operator", vec![HumanRole::Operator]),
            ("outsider", vec![]),
        ] {
            let principal = w.person(name, &roles).await;
            let id = github_id(&w, principal).await;
            people.push((id, principal));
        }
        let entries: Vec<AllowlistEntry> = [
            (0, vec![Designation::Approver]),
            (1, vec![Designation::Approver]),
            (2, vec![Designation::SecurityApprover]),
            (3, vec![Designation::SecurityApprover]),
            (4, vec![Designation::Operator]),
        ]
        .into_iter()
        .map(|(index, held)| AllowlistEntry {
            tenant: w.tenant,
            github_user_id: GithubUserId::new(people[index].0).expect("an id"),
            login: format!("person-{index}"),
            designations: designations(&held),
            repositories: None,
            expires_at: None,
        })
        .chain([AllowlistEntry {
            tenant: w.tenant,
            github_user_id: GithubUserId::new(1001).expect("an id"),
            login: "requester".to_owned(),
            designations: designations(&[Designation::Requester, Designation::Approver]),
            repositories: None,
            expires_at: None,
        }])
        .collect();
        let allowlist = Allowlist::new("allowlist-version-one", entries).expect("an allowlist");

        let request = ApprovalRequest {
            repository: repo.to_string(),
            pull_request: pr.number,
            head_branch: "factory/job-1".to_owned(),
            base_branch: "main".to_owned(),
            pr_head: GitSha::parse(head.as_str()).expect("a sha"),
            tree: judging::sha('d'),
            base: GitSha::parse(base.as_str()).expect("a sha"),
            manifest: Sha256Digest::of(b"manifest"),
            spec_version: 1,
            gates_clear: true,
            open_translation_warnings: 0,
            tier,
            protected_path_change: false,
            sensitive_file_change: false,
            new_dependency: false,
            requester: 1001,
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
            values: Mutex::new(CurrentValues {
                definition_hash: Sha256Digest::of(b"definitions"),
                image_digest: Sha256Digest::of(b"image"),
            }),
            tree: judging::sha('d'),
            known: head.clone(),
        });
        let fixture = Arc::new(Fixture {
            allowlist: Mutex::new(allowlist),
            request: Mutex::new(request),
        });
        let comments = Arc::new(Comments::default());
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
            issues: comments.clone(),
            policy: Arc::new(policy()),
            policy_hash: Sha256Digest::of(b"test policy"),
            delivery: fixed.clone(),
            approvals: fixture.clone(),
            clock: w.clock.clone(),
            ids: w.ids.clone(),
            redactor,
        });
        Self {
            w,
            host,
            comments,
            fixed,
            fixture,
            service,
            pr,
            job,
            run,
            head,
            code_head,
            people,
        }
    }

    fn request(&self) -> ApprovalRequest {
        self.fixture.request.lock().expect("lock").clone()
    }

    fn person(&self, index: usize) -> u64 {
        self.people[index].0
    }

    /// A command by one of the people, who saw what the request holds and the ledger as it is.
    async fn command(&self, verb: Verb, sender: u64) -> ApprovalCommand {
        *self.fixed.head.lock().expect("lock") = self.w.head(self.job).await;
        let seen = self
            .request()
            .seen_with(self.fixed.head.lock().expect("lock").clone());
        ApprovalCommand {
            id: CausationId::from_uuid(self.w.ids.new_uuid()),
            tenant: self.w.tenant,
            job: self.job,
            stage_run: self.run,
            verb,
            sender: Sender {
                id: sender,
                login: ActorLogin::new("someone").expect("a login"),
                kind: factory_domain::policy::authority::ActorKind::User,
            },
            channel: ApprovalChannel::Dashboard,
            reason: "The change does what the specification says.".to_owned(),
            seen: Some(seen),
            warnings_decided: true,
            rework_target: Some(StageKind::Implementation),
            comment: None,
        }
    }

    async fn approvals(&self) -> Vec<factory_ports::store::Approval> {
        let mut tx = self
            .w
            .store
            .begin(TenantScope::new(self.w.tenant))
            .await
            .expect("a tx");
        tx.list_approvals(self.job).await.expect("approvals")
    }

    async fn valid(&self, head: &GitSha) -> usize {
        let mut tx = self
            .w
            .store
            .begin(TenantScope::new(self.w.tenant))
            .await
            .expect("a tx");
        tx.valid_approvals(self.job, head)
            .await
            .expect("approvals")
            .len()
    }

    async fn audit_lines(&self) -> Vec<(String, String)> {
        let mut tx = self
            .w
            .store
            .begin(TenantScope::new(self.w.tenant))
            .await
            .expect("a tx");
        tx.read_audit(AuditFilter::Job(self.job), 0, 1000)
            .await
            .expect("audit")
            .into_iter()
            .map(|record| (record.event.action.as_str().to_owned(), record.event.reason))
            .collect()
    }

    async fn run_status(&self) -> StageRunStatus {
        self.w.stage_run(self.run).await.status
    }

    fn host_only_read(&self) {
        for call in self.host.calls() {
            assert!(
                matches!(
                    call,
                    Call::State | Call::ResolveBranch(_) | Call::Open { .. } | Call::Comment(_)
                ),
                "{call:?}"
            );
        }
    }
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

fn refused(result: Result<Outcome, ServiceError>) -> Refusal {
    match result {
        Err(ServiceError::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, found {other:?}"),
    }
}

#[tokio::test]
async fn an_approval_passes_the_stage_and_nothing_merges() {
    let rig = Rig::new(RiskTier::Low).await;
    let cmd = rig.command(Verb::Approve, rig.person(0)).await;
    let outcome = rig.service.submit(cmd).await.expect("applied");
    assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
    assert_eq!(rig.run_status().await, StageRunStatus::Passed);
    // The job is over for the factory: it went as far as the approval and no further.
    let status = rig.w.view(rig.job).await.status;
    assert!(matches!(status, JobStatus::Completed), "{status:?}");
    // The approval is recorded with the binding and counts for the head that was shown.
    let rows = rig.approvals().await;
    assert_eq!(rows.len(), 1);
    let binding = rows[0].binding.as_ref().expect("a binding");
    assert_eq!(binding.pr_head.as_str(), rig.head.as_str());
    assert_eq!(binding.tree.as_str(), judging::sha('d').as_str());
    assert_eq!(rows[0].approver_github_user_id, rig.person(0));
    assert_eq!(rig.valid(&binding.pr_head).await, 1);
    // The audit log has the decision with the sender's numeric id and the allowlist version.
    let lines = rig.audit_lines().await;
    let recorded = lines
        .iter()
        .find(|(action, _)| action == "approval.recorded")
        .expect("an audit record");
    assert!(
        recorded.1.contains(&rig.person(0).to_string()),
        "{recorded:?}"
    );
    assert!(recorded.1.contains("allowlist-version-one"), "{recorded:?}");
    rig.host_only_read();
}

#[tokio::test]
async fn an_approval_is_bound_to_the_pushed_head_while_the_evidence_stays_on_the_code_head() {
    let rig = Rig::new(RiskTier::Low).await;
    let request = rig.request();
    // The person is shown the documentation commit, and the gates ran on the code under it.
    assert_eq!(request.pr_head.as_str(), rig.head.as_str());
    assert_eq!(
        request.evidence_binding.head_commit.as_str(),
        rig.code_head.as_str()
    );
    assert_ne!(rig.head, rig.code_head);

    // The approval is recorded although the two differ: the evidence is compared at the code head.
    let cmd = rig.command(Verb::Approve, rig.person(0)).await;
    let outcome = rig.service.submit(cmd).await.expect("applied");
    assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
    let rows = rig.approvals().await;
    let binding = rows[0].binding.as_ref().expect("a binding");
    assert_eq!(binding.pr_head.as_str(), rig.head.as_str());
    let code_head = GitSha::parse(rig.code_head.as_str()).expect("a sha");
    assert_eq!(rig.valid(&binding.pr_head).await, 1);
    assert_eq!(
        rig.valid(&code_head).await,
        0,
        "it does not count for the code head"
    );
}

#[tokio::test]
async fn an_approval_that_saw_the_code_head_is_refused() {
    // A person who was shown the code head did not see the documentation commit that the pull
    // request now ends with.
    let rig = Rig::new(RiskTier::Low).await;
    let mut cmd = rig.command(Verb::Approve, rig.person(0)).await;
    cmd.seen.as_mut().expect("a binding").pr_head =
        GitSha::parse(rig.code_head.as_str()).expect("a sha");
    assert_eq!(
        refused(rig.service.submit(cmd).await),
        Refusal::StaleBinding("pr_head")
    );
    assert!(rig.approvals().await.is_empty());
    assert_eq!(rig.run_status().await, StageRunStatus::WaitingForHuman);
}

#[tokio::test]
async fn negative_nt_mrg_01_a_failing_gate_refuses_approval_and_nothing_reaches_the_host() {
    let rig = Rig::new(RiskTier::Low).await;
    rig.fixture.request.lock().expect("lock").gates_clear = false;
    let cmd = rig.command(Verb::Approve, rig.person(0)).await;
    assert_eq!(
        refused(rig.service.submit(cmd).await),
        Refusal::GatesNotClear
    );
    // The stage run still waits, no approval counts, and the decision is audited with its code.
    assert_eq!(rig.run_status().await, StageRunStatus::WaitingForHuman);
    assert!(rig.approvals().await.is_empty());
    assert!(
        rig.audit_lines()
            .await
            .iter()
            .any(|(action, reason)| action == "approval.refused"
                && reason.contains("gates_not_clear"))
    );
    rig.host_only_read();
    assert!(
        !rig.host
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Comment(_)))
    );
}

#[tokio::test]
async fn negative_nt_mrg_03_the_head_moving_after_approval_invalidates_the_approval() {
    // The critical tier needs two security approvers, so the first approval is recorded and waits.
    let rig = Rig::new(RiskTier::Critical).await;
    let first = rig.command(Verb::Approve, rig.person(2)).await;
    let outcome = rig.service.submit(first).await.expect("recorded");
    assert!(
        matches!(
            outcome,
            Outcome::Recorded {
                still_needed: 1,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(rig.run_status().await, StageRunStatus::WaitingForHuman);
    let shown = rig.request().pr_head;
    assert_eq!(rig.valid(&shown).await, 1);

    // A push makes the head another commit.
    rig.host
        .head_moves_to(CommitSha::parse(&"9".repeat(40)).expect("a sha"));
    let changed = rig
        .service
        .head_changed(rig.w.tenant, rig.job, rig.run)
        .await
        .expect("checked");
    assert_eq!(changed, 1);
    assert_eq!(rig.valid(&shown).await, 0);
    let rows = rig.approvals().await;
    assert_eq!(
        rows[0].invalidated.map(|(_, reason)| reason),
        Some(ApprovalInvalidation::NewCommit)
    );

    // The second approver still holds the old picture: the approval is refused as `new_commit`
    // and the stage does not pass.
    let second = rig.command(Verb::Approve, rig.person(3)).await;
    assert_eq!(
        refused(rig.service.submit(second).await),
        Refusal::HeadMoved
    );
    assert_eq!(rig.run_status().await, StageRunStatus::WaitingForHuman);
}

#[tokio::test]
async fn negative_nt_mrg_03_a_refusal_for_a_moved_head_also_ends_the_approvals_on_record() {
    // No webhook told the service about the push. The next decision finds the head moved, refuses,
    // and the approval that was on record for the old head stops counting at once.
    let rig = Rig::new(RiskTier::Critical).await;
    let first = rig.command(Verb::Approve, rig.person(2)).await;
    rig.service.submit(first).await.expect("recorded");
    let shown = rig.request().pr_head;
    assert_eq!(rig.valid(&shown).await, 1);
    rig.host
        .head_moves_to(CommitSha::parse(&"9".repeat(40)).expect("a sha"));
    let second = rig.command(Verb::Approve, rig.person(3)).await;
    assert_eq!(
        refused(rig.service.submit(second).await),
        Refusal::HeadMoved
    );
    assert_eq!(rig.valid(&shown).await, 0);
    assert_eq!(
        rig.approvals().await[0]
            .invalidated
            .map(|(_, reason)| reason),
        Some(ApprovalInvalidation::NewCommit)
    );
}

#[tokio::test]
async fn negative_nt_mrg_03_the_second_approver_alone_does_not_pass_a_critical_change() {
    let rig = Rig::new(RiskTier::Critical).await;
    // The same person twice counts once: the second is refused as already decided.
    let first = rig.command(Verb::Approve, rig.person(2)).await;
    rig.service.submit(first).await.expect("recorded");
    let again = rig.command(Verb::Approve, rig.person(2)).await;
    assert_eq!(
        refused(rig.service.submit(again).await),
        Refusal::AlreadyDecided
    );
    assert_eq!(rig.valid(&rig.request().pr_head).await, 1);
    // A plain approver is not enough for the critical tier either.
    let plain = rig.command(Verb::Approve, rig.person(0)).await;
    assert!(matches!(
        refused(rig.service.submit(plain).await),
        Refusal::Unauthorized(_)
    ));
    // Two distinct security approvers pass it.
    let second = rig.command(Verb::Approve, rig.person(3)).await;
    let outcome = rig.service.submit(second).await.expect("applied");
    assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
    assert_eq!(rig.run_status().await, StageRunStatus::Passed);
}

#[tokio::test]
async fn negative_nt_authz_02_an_unauthorized_command_is_audited_and_gets_no_reply() {
    let rig = Rig::new(RiskTier::Low).await;
    let outsider = rig.person(5);
    let mut cmd = rig.command(Verb::Approve, outsider).await;
    cmd.channel = ApprovalChannel::GithubComment;
    let target = CommentTarget::PullRequest(rig.pr.clone());
    let comment = Comment {
        reference: CommentRef {
            target: target.clone(),
            id: 1,
        },
        author: GithubActor {
            id: outsider,
            login: ActorLogin::new("someone").expect("a login"),
        },
        body: "/factory approve".to_owned(),
        created_at: rig.w.clock.now(),
        edited_at: None,
    };
    cmd.comment = Some(CommentEvidence {
        comment: comment.reference.clone(),
        body_sha256: Sha256Digest::of(comment.body.as_bytes()),
    });
    rig.comments.held.lock().expect("lock").push(comment);

    let error = rig.service.submit(cmd).await.expect_err("refused");
    assert!(!error.reply_allowed(), "no oracle for outsiders");
    assert!(matches!(
        error,
        ServiceError::Refused(Refusal::Unauthorized(_))
    ));
    // The approval table is unchanged, nothing was posted, and the stage still waits.
    assert!(rig.approvals().await.is_empty());
    assert_eq!(rig.host.inner().comment_count(&target), 0);
    assert_eq!(rig.run_status().await, StageRunStatus::WaitingForHuman);
    // The audit record has the numeric id and the allowlist version.
    let lines = rig.audit_lines().await;
    let refused = lines
        .iter()
        .find(|(action, _)| action == "approval.refused")
        .expect("an audit record");
    assert!(refused.1.contains(&outsider.to_string()), "{refused:?}");
    assert!(refused.1.contains("allowlist-version-one"), "{refused:?}");
}

#[tokio::test]
async fn negative_nt_lse_03_a_replayed_command_is_applied_once_and_answered_once() {
    let rig = Rig::new(RiskTier::Low).await;
    let mut cmd = rig.command(Verb::Approve, rig.person(0)).await;
    cmd.channel = ApprovalChannel::GithubComment;
    let target = CommentTarget::PullRequest(rig.pr.clone());
    let comment = Comment {
        reference: CommentRef {
            target: target.clone(),
            id: 2,
        },
        author: GithubActor {
            id: rig.person(0),
            login: ActorLogin::new("someone").expect("a login"),
        },
        body: "/factory approve".to_owned(),
        created_at: rig.w.clock.now(),
        edited_at: None,
    };
    cmd.comment = Some(CommentEvidence {
        comment: comment.reference.clone(),
        body_sha256: Sha256Digest::of(comment.body.as_bytes()),
    });
    rig.comments.held.lock().expect("lock").push(comment);

    let first = rig.service.submit(cmd.clone()).await.expect("applied");
    assert!(matches!(first, Outcome::Applied { .. }), "{first:?}");
    // The webhook delivers the same command again, and again.
    for _ in 0..3 {
        let again = rig.service.submit(cmd.clone()).await;
        // The first judgement is repeated against a stage run that has moved on, so the answer
        // is either a replay or a refusal that records nothing. Either way nothing is applied.
        assert!(
            matches!(again, Ok(Outcome::Replayed) | Err(ServiceError::Refused(_))),
            "{again:?}"
        );
    }
    assert_eq!(rig.approvals().await.len(), 1, "one approval row");
    assert_eq!(rig.host.inner().comment_count(&target), 1, "one comment");
    assert_eq!(rig.valid(&rig.request().pr_head).await, 1);
}

#[tokio::test]
async fn an_edited_command_comment_is_not_a_command() {
    let rig = Rig::new(RiskTier::Low).await;
    let mut cmd = rig.command(Verb::Approve, rig.person(0)).await;
    cmd.channel = ApprovalChannel::GithubComment;
    let reference = CommentRef {
        target: CommentTarget::PullRequest(rig.pr.clone()),
        id: 3,
    };
    cmd.comment = Some(CommentEvidence {
        comment: reference.clone(),
        body_sha256: Sha256Digest::of(b"/factory approve"),
    });
    // The person edited the comment after the parser read it.
    rig.comments.held.lock().expect("lock").push(Comment {
        reference,
        author: GithubActor {
            id: rig.person(0),
            login: ActorLogin::new("someone").expect("a login"),
        },
        body: "/factory approve".to_owned(),
        created_at: rig.w.clock.now(),
        edited_at: Some(rig.w.clock.now()),
    });
    assert_eq!(
        refused(rig.service.submit(cmd).await),
        Refusal::NotACommand(NotACommand::CommentEdited)
    );
    assert!(rig.approvals().await.is_empty());
    assert_eq!(rig.run_status().await, StageRunStatus::WaitingForHuman);
}

#[tokio::test]
async fn an_approval_after_seventy_two_hours_is_refused() {
    let rig = Rig::new(RiskTier::Low).await;
    let cmd = rig.command(Verb::Approve, rig.person(0)).await;
    rig.w.advance(73 * 3600);
    assert_eq!(refused(rig.service.submit(cmd).await), Refusal::Expired);
    assert!(rig.approvals().await.is_empty());
}

#[tokio::test]
async fn evidence_binding_is_rechecked() {
    // When an approval is recorded the gate definitions, the policy, the image and the base are
    // compared with the evidence. A difference supersedes the runs that depend on it, and the
    // approval is refused.
    let rig = Rig::new(RiskTier::Low).await;
    rig.fixed.values.lock().expect("lock").image_digest = Sha256Digest::of(b"another image");
    let cmd = rig.command(Verb::Approve, rig.person(0)).await;
    assert_eq!(
        refused(rig.service.submit(cmd).await),
        Refusal::EvidenceDrift(vec!["image_digest"])
    );
    assert!(rig.approvals().await.is_empty());
    let view = rig.w.view(rig.job).await;
    let old = view
        .runs_of(StageKind::Approval)
        .next()
        .expect("the old run");
    assert_eq!(old.status, StageRunStatus::Superseded);
    for kind in [
        StageKind::Validation,
        StageKind::Review,
        StageKind::DocumentationReview,
        StageKind::Delivery,
        StageKind::Approval,
    ] {
        assert!(view.runs_of(kind).count() >= 2, "{kind:?} has a new run");
        assert_eq!(
            view.runs_of(kind).next().expect("a run").status,
            StageRunStatus::Superseded,
            "{kind:?}"
        );
    }
    // The documenting stage is not superseded: the text did not change.
    assert_eq!(view.runs_of(StageKind::Documenting).count(), 1);
}

#[tokio::test]
async fn the_base_moving_supersedes_and_invalidates() {
    let rig = Rig::new(RiskTier::Critical).await;
    let first = rig.command(Verb::Approve, rig.person(2)).await;
    rig.service.submit(first).await.expect("recorded");
    rig.host
        .base_moves_to(CommitSha::parse(&"8".repeat(40)).expect("a sha"));
    let second = rig.command(Verb::Approve, rig.person(3)).await;
    assert_eq!(
        refused(rig.service.submit(second).await),
        Refusal::BaseMoved
    );
    let rows = rig.approvals().await;
    assert_eq!(
        rows[0].invalidated.map(|(_, reason)| reason),
        Some(ApprovalInvalidation::BaseMoved)
    );
    let view = rig.w.view(rig.job).await;
    assert_eq!(
        view.runs_of(StageKind::Validation)
            .next()
            .expect("a run")
            .status,
        StageRunStatus::Superseded
    );
}

#[tokio::test]
async fn a_reason_with_a_secret_is_refused_before_it_is_stored() {
    let rig = Rig::new(RiskTier::Low).await;
    let mut cmd = rig.command(Verb::Approve, rig.person(0)).await;
    let secret = crate::world::canary();
    cmd.reason = format!("Looks fine, the key is {secret}");
    assert!(matches!(
        rig.service.submit(cmd).await,
        Err(ServiceError::Refused(_))
    ));
    assert!(rig.approvals().await.is_empty());
    for (_, reason) in rig.audit_lines().await {
        assert!(!reason.contains(&secret));
    }
}

#[tokio::test]
async fn reject_ends_the_job_as_rejected() {
    let rig = Rig::new(RiskTier::Low).await;
    let cmd = rig.command(Verb::Reject, rig.person(0)).await;
    rig.service.submit(cmd).await.expect("applied");
    assert_eq!(rig.w.view(rig.job).await.status, JobStatus::Rejected);
    let rows = rig.approvals().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].decision,
        factory_ports::store::ApprovalDecision::Reject
    );
    assert!(
        rows[0].binding.is_some(),
        "a rejection is bound to the head it was about"
    );
}

#[tokio::test]
async fn pause_resume_and_cancel_follow_the_operator_designation() {
    let rig = Rig::new(RiskTier::Low).await;
    // An approver is not an operator.
    let wrong = rig.command(Verb::Pause, rig.person(0)).await;
    assert!(matches!(
        refused(rig.service.submit(wrong).await),
        Refusal::Unauthorized(_)
    ));
    let pause = rig.command(Verb::Pause, rig.person(4)).await;
    rig.service.submit(pause).await.expect("paused");
    assert_eq!(rig.w.view(rig.job).await.status, JobStatus::Paused);
    let resume = rig.command(Verb::Resume, rig.person(4)).await;
    rig.service.submit(resume).await.expect("resumed");
    assert_ne!(rig.w.view(rig.job).await.status, JobStatus::Paused);
    let cancel = rig.command(Verb::Cancel, rig.person(4)).await;
    rig.service.submit(cancel).await.expect("cancelled");
    let status = rig.w.view(rig.job).await.status;
    assert!(
        matches!(status, JobStatus::Cancelling | JobStatus::Cancelled),
        "{status:?}"
    );
}

#[tokio::test]
async fn human_rework_targets() {
    let rig = Rig::new(RiskTier::Low).await;
    // Only the agent-produced stages at or before the waiting stage are targets.
    for target in [
        StageKind::Specification,
        StageKind::Intake,
        StageKind::Validation,
        StageKind::Review,
        StageKind::Delivery,
        StageKind::Approval,
    ] {
        let mut cmd = rig.command(Verb::Rework, rig.person(0)).await;
        cmd.rework_target = Some(target);
        let result = rig.service.submit(cmd).await;
        assert!(
            matches!(result, Err(ServiceError::Engine(_))),
            "{target:?}: {result:?}"
        );
        assert_eq!(
            rig.run_status().await,
            StageRunStatus::WaitingForHuman,
            "{target:?}"
        );
    }
    // The code count: two rounds to IMPLEMENTATION, and the third is refused.
    let mut run = rig.run;
    for round in 1..=2u8 {
        let mut cmd = rig.command(Verb::Rework, rig.person(0)).await;
        cmd.stage_run = run;
        cmd.rework_target = Some(StageKind::Implementation);
        rig.service
            .submit(cmd)
            .await
            .unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        // implementation, validation, review, documenting, documentation review, delivery,
        // approval.
        rig.w.run_stages(7).await;
        run = rig
            .w
            .view(rig.job)
            .await
            .newest(StageKind::Approval)
            .expect("a run")
            .id;
        // Each round ends in a new commit, so the next request names another head.
        rig.fixture.request.lock().expect("lock").pr_head = judging::sha(char::from(b'0' + round));
    }
    let mut third = rig.command(Verb::Rework, rig.person(0)).await;
    third.stage_run = run;
    third.rework_target = Some(StageKind::Implementation);
    assert!(matches!(
        rig.service.submit(third).await,
        Err(ServiceError::Engine(_))
    ));
    // The documentation count is separate: two rounds to DOCUMENTING are allowed.
    for round in 1..=2u8 {
        let mut cmd = rig.command(Verb::Rework, rig.person(0)).await;
        cmd.stage_run = run;
        cmd.rework_target = Some(StageKind::Documenting);
        rig.service
            .submit(cmd)
            .await
            .unwrap_or_else(|e| panic!("doc round {round}: {e:?}"));
        // documenting, documentation review, delivery, approval.
        rig.w.run_stages(4).await;
        run = rig
            .w
            .view(rig.job)
            .await
            .newest(StageKind::Approval)
            .expect("a run")
            .id;
        rig.fixture.request.lock().expect("lock").pr_head = judging::sha(char::from(b'4' + round));
    }
    let mut again = rig.command(Verb::Rework, rig.person(0)).await;
    again.stage_run = run;
    again.rework_target = Some(StageKind::Documenting);
    assert!(matches!(
        rig.service.submit(again).await,
        Err(ServiceError::Engine(_))
    ));
}
