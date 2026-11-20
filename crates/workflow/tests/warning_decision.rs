//! Recording an approver's decision about a translation warning, through the real engine over the
//! in-memory store.
//!
//! The scripted `APPROVAL` handler stores an approval request that counts two open warnings and
//! waits for a person. Each test then does what the API and the worker do: it asks the policy
//! engine for the proof of authority and hands the engine the proof and the number of the warning.

mod support;

use factory_domain::ids::{JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::authority::{
    ActionVerdict, Actor, ActorKind, Allowlist, AllowlistEntry, AutonomyLevel,
};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{HumanText, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{HumanRole, RiskTier, StageKind};
use factory_ports::store::PrincipalKind;
use factory_workflow::commands::{RecordWarningDecision, Subject};
use factory_workflow::engine::EngineError;
use factory_workflow::gates::supply_chain::approval::{
    RecordedApprovals, Request, authorize_build_code, authorize_warning,
};
use factory_workflow::gates::supply_chain::ledger::LedgerApprovals;
use factory_workflow::stages::approval::warnings::all_decided;
use serde_json::json;
use support::World;

const SECURITY: &str = include_str!("../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../domain/tests/fixtures/policy/approval.json");
const REPOSITORY: &str = "example-org/app";

fn manifest() -> Sha256Digest {
    Sha256Digest::of(b"the manifest of the request")
}

fn reason() -> HumanText {
    HumanText::parse("The translation says what the original says.").expect("a text")
}

fn now() -> Timestamp {
    Timestamp::parse("2026-10-28T12:00:00Z").expect("a time")
}

struct Rig {
    world: World,
    policy: PolicyEngine,
    job: JobId,
    run: StageRunId,
    approver: PrincipalId,
    other_approver: PrincipalId,
    security: PrincipalId,
}

impl Rig {
    async fn new() -> Self {
        let world = World::new().await;
        world.script(StageKind::Approval).with(|script| {
            script.document = Some(json!({
                "kind": "approval-request",
                "open_translation_warnings": 2,
                "manifest": manifest().as_str(),
            }));
        });
        let (job, run) = world.at_approval().await;
        let view = world.view(job).await;
        assert_eq!(
            view.newest(StageKind::Approval).map(|run| run.status),
            Some(StageRunStatus::WaitingForHuman)
        );
        let approver = world.person("approver-1", &[HumanRole::Approver]).await;
        let other_approver = world.person("approver-2", &[HumanRole::Approver]).await;
        let security = world
            .person("security-1", &[HumanRole::SecurityApprover])
            .await;
        let security_policy: SecurityPolicy = serde_json::from_str(SECURITY).expect("security");
        let approval_policy: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("approval");
        Self {
            world,
            policy: PolicyEngine::new(&security_policy, &approval_policy).expect("an engine"),
            job,
            run,
            approver,
            other_approver,
            security,
        }
    }

    async fn github(&self, principal: PrincipalId) -> u64 {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.world.tenant))
            .await
            .expect("a tx");
        let found = tx.get_principal(principal).await.expect("a principal");
        tx.rollback().await.expect("rollback");
        match found.kind {
            PrincipalKind::Human { github_user_id } => github_user_id,
            PrincipalKind::Service => panic!("a person was expected"),
        }
    }

    async fn allowlist(&self, requester_extra: &[Designation]) -> Allowlist {
        let tenant: TenantId = self.world.tenant;
        let entry = |id: u64, login: &str, designations: &[Designation]| AllowlistEntry {
            tenant,
            github_user_id: GithubUserId::new(id).expect("an id"),
            login: login.to_owned(),
            designations: designations.iter().copied().collect(),
            repositories: None,
            expires_at: None,
        };
        let mut requester = vec![Designation::Requester];
        requester.extend_from_slice(requester_extra);
        Allowlist::new(
            "sha256:allowlist-v1",
            vec![
                entry(
                    self.github(self.world.requester).await,
                    "requester",
                    &requester,
                ),
                entry(
                    self.github(self.approver).await,
                    "approver",
                    &[Designation::Approver],
                ),
                entry(
                    self.github(self.other_approver).await,
                    "other-approver",
                    &[Designation::Approver],
                ),
                entry(
                    self.github(self.security).await,
                    "security",
                    &[Designation::SecurityApprover],
                ),
            ],
        )
        .expect("no duplicates")
    }

    async fn verdict(
        &self,
        who: PrincipalId,
        requester_extra: &[Designation],
        decide: impl FnOnce(&Request<'_>) -> ActionVerdict,
    ) -> ActionVerdict {
        let (tenant, allowlist, now) = (
            self.world.tenant,
            self.allowlist(requester_extra).await,
            now(),
        );
        let id = self.github(who).await;
        let requester = self.github(self.world.requester).await;
        let actor = Actor {
            github_user_id: GithubUserId::new(id).expect("an id"),
            login: "someone",
            kind: ActorKind::User,
            github_permission: None,
            author_association: None,
        };
        decide(&Request {
            policy: &self.policy.authority,
            level: AutonomyLevel::L1,
            tenant: &tenant,
            repository: REPOSITORY,
            actor: &actor,
            allowlist: &allowlist,
            now: &now,
            // A caller that tells the policy engine the requester is someone else gets a proof
            // for the requester; the engine must not rely on it.
            requester: GithubUserId::new(requester + 10_000),
            risk_tier: RiskTier::Low,
            protected_path_change: false,
            sensitive_file_change: false,
        })
    }

    async fn proof(&self, who: PrincipalId) -> AuthorizedApproval {
        match self.verdict(who, &[], authorize_warning).await {
            ActionVerdict::Authorized(proof) => proof,
            other => panic!("expected a proof, got {other:?}"),
        }
    }

    async fn record(
        &self,
        who: PrincipalId,
        proof: AuthorizedApproval,
        warning: u32,
    ) -> Result<factory_workflow::commands::WarningDecisionRecorded, EngineError> {
        self.world
            .engine
            .record_warning_decision(
                &self.world.actor(who),
                RecordWarningDecision {
                    stage: Subject {
                        job: self.job,
                        stage_run: self.run,
                    },
                    proof,
                    warning,
                    reason: reason(),
                },
            )
            .await
    }

    async fn stored(&self) -> Vec<factory_workflow::stages::approval::warnings::WarningDecision> {
        LedgerApprovals::new(self.world.store.clone(), self.world.artifacts.clone())
            .warning_decisions_for_job(self.world.tenant, self.job)
            .await
    }
}

#[tokio::test]
async fn an_approver_decides_on_each_warning_and_the_approval_reads_them_back() {
    let rig = Rig::new().await;
    assert!(rig.stored().await.is_empty());
    let before = rig.world.ledger(rig.job).await.len();
    for warning in [1, 2] {
        let proof = rig.proof(rig.approver).await;
        rig.record(rig.approver, proof, warning)
            .await
            .expect("the decision is recorded");
    }
    assert_eq!(rig.world.ledger(rig.job).await.len(), before + 2);
    // Recording moves nothing: the stage run still waits for a person.
    assert_eq!(
        rig.world.stage_run(rig.run).await.status,
        StageRunStatus::WaitingForHuman
    );

    let decisions = rig.stored().await;
    assert_eq!(decisions.len(), 2);
    let scope = factory_workflow::gates::supply_chain::approval::DecisionScope {
        tenant: rig.world.tenant,
        job: rig.job,
    };
    let m = manifest();
    let who = rig.github(rig.approver).await;
    let other = rig.github(rig.other_approver).await;
    // The manifest is the one in the stored request, not one the caller named.
    assert!(decisions.iter().all(|held| held.manifest == m));
    // Both are decided for the person who decided, and for nobody else.
    assert!(all_decided(&decisions, who, (&scope, rig.run, &m), 2));
    assert!(!all_decided(&decisions, other, (&scope, rig.run, &m), 2));
    // A request that changed (another manifest) needs its decisions again.
    assert!(!all_decided(
        &decisions,
        who,
        (&scope, rig.run, &Sha256Digest::of(b"another")),
        2
    ));
    // Another job reads none.
    let reader = LedgerApprovals::new(rig.world.store.clone(), rig.world.artifacts.clone());
    assert!(
        reader
            .warning_decisions_for_job(rig.world.tenant, JobId::from_uuid(uuid::Uuid::from_u128(9)))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_warning_the_request_does_not_count_is_refused() {
    let rig = Rig::new().await;
    for warning in [0, 3, 99] {
        let proof = rig.proof(rig.approver).await;
        let refused = rig.record(rig.approver, proof, warning).await;
        assert!(
            matches!(
                refused,
                Err(EngineError::Refused(
                    "the approval request does not count a warning with that number"
                ))
            ),
            "{warning}: {refused:?}"
        );
    }
    assert!(rig.stored().await.is_empty());
}

#[tokio::test]
async fn only_an_approver_other_than_the_requester_may_decide() {
    let rig = Rig::new().await;
    // The policy row names the approver, so a security approver gets no proof.
    let verdict = rig.verdict(rig.security, &[], authorize_warning).await;
    assert!(matches!(verdict, ActionVerdict::Denied(_)), "{verdict:?}");
    // A proof made for one person is not another's.
    let proof = rig.proof(rig.approver).await;
    let refused = rig.record(rig.other_approver, proof, 1).await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    // A proof for another action is not a proof for this one.
    let build_proof = match rig.verdict(rig.security, &[], authorize_build_code).await {
        ActionVerdict::Authorized(proof) => proof,
        other => panic!("expected a proof, got {other:?}"),
    };
    let refused = rig.record(rig.security, build_proof, 1).await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    // The requester holds the approver designation on this allowlist, and the policy engine was
    // told the requester is someone else. The engine knows who asked for the job and refuses.
    let proof = match rig
        .verdict(
            rig.world.requester,
            &[Designation::Approver],
            authorize_warning,
        )
        .await
    {
        ActionVerdict::Authorized(proof) => proof,
        other => panic!("expected a proof, got {other:?}"),
    };
    rig.world.authority.grant(
        rig.world.requester,
        &[HumanRole::Requester, HumanRole::Approver],
    );
    let refused = rig.record(rig.world.requester, proof, 1).await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    assert!(rig.stored().await.is_empty());
}

#[tokio::test]
async fn a_repeat_of_the_command_is_applied_once() {
    let rig = Rig::new().await;
    let actor = rig.world.actor(rig.approver);
    let command = |proof| RecordWarningDecision {
        stage: Subject {
            job: rig.job,
            stage_run: rig.run,
        },
        proof,
        warning: 1,
        reason: reason(),
    };
    rig.world
        .engine
        .record_warning_decision(&actor, command(rig.proof(rig.approver).await))
        .await
        .expect("recorded");
    let ledger = rig.world.ledger(rig.job).await.len();
    let again = rig
        .world
        .engine
        .record_warning_decision(&actor, command(rig.proof(rig.approver).await))
        .await;
    assert!(matches!(again, Err(EngineError::Duplicate)), "{again:?}");
    assert_eq!(rig.world.ledger(rig.job).await.len(), ledger);
}
