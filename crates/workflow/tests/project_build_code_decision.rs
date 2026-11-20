//! Recording a security approver's decision on the project's own build code, through the real
//! engine over the in-memory store.
//!
//! The scripted `VALIDATION` handler stops at the gate with a block and stores the evidence
//! document the validation stage makes, which lists the files of build code that wait, each with
//! the hash of its content. Each test then does what the API and the worker do: it asks the policy
//! engine for the proof of authority, and hands the engine the proof and the exact file.

mod support;

use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence};
use factory_domain::ids::{JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::authority::{
    ActionVerdict, Actor, ActorKind, Allowlist, AllowlistEntry, AutonomyLevel,
};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::policy::solo::ConfirmationWord;
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::{HumanText, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{HumanRole, RiskTier, StageKind};
use factory_ports::store::{ArtifactDirection, PrincipalKind};
use factory_workflow::commands::{Decision, RecordProjectBuildCodeDecision, SoloRequest, Subject};
use factory_workflow::engine::{EngineError, SoloRefusal};
use factory_workflow::gates::scope::own_build_code::{BuildScript, EVIDENCE_KEY};
use factory_workflow::gates::supply_chain::approval::{RecordedApprovals, Request};
use factory_workflow::gates::supply_chain::approval::{authorize, authorize_build_code};
use factory_workflow::gates::supply_chain::ledger::LedgerApprovals;
use serde_json::json;
use support::{Eval, World};

const SECURITY: &str = include_str!("../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../domain/tests/fixtures/policy/approval.json");
const REPOSITORY: &str = "example-org/app";
const SCRIPT: &[u8] = b"fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n";

fn script(path: &str, content: &[u8]) -> BuildScript {
    BuildScript {
        path: path.to_owned(),
        sha256: Sha256Digest::of(content),
    }
}

/// What the validation stage stores when the change adds one build script.
fn evidence() -> serde_json::Value {
    json!({
        "kind": "validation-evidence",
        "reports": [],
        EVIDENCE_KEY: {
            "awaiting": [script("build.rs", SCRIPT).to_json()],
            "decided": []
        }
    })
}

fn reason() -> HumanText {
    HumanText::parse("Read the script; it only prints cargo directives.").expect("a text")
}

fn engine() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("the security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("the approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
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
    security: PrincipalId,
    operator: PrincipalId,
}

impl Rig {
    async fn new() -> Self {
        Self::on(World::new().await).await
    }

    async fn solo() -> Self {
        Self::on(World::solo().await).await
    }

    async fn on(world: World) -> Self {
        let job = world.admitted_job().await;
        world.script(StageKind::Validation).with(|script| {
            script.document = Some(evidence());
        });
        world
            .script(StageKind::Validation)
            .queue_evals([Eval::Blocked]);
        world.run_stages(7).await;
        world.advance(400);
        world.run_next("worker-1").await;
        let view = world.view(job).await;
        assert_eq!(view.status, JobStatus::Blocked);
        let run = view.newest(StageKind::Validation).expect("a run");
        assert_eq!(run.status, StageRunStatus::Blocked);
        let run = run.id;
        let approver = world.person("approver-1", &[HumanRole::Approver]).await;
        let security = world
            .person("security-1", &[HumanRole::SecurityApprover])
            .await;
        let operator = world.person("operator-1", &[HumanRole::Operator]).await;
        Self {
            world,
            policy: engine(),
            job,
            run,
            approver,
            security,
            operator,
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

    /// The allowlist of the tenant. `requester_designations` is what the requester holds besides
    /// being the requester: a test that wants them to hold the security designation says so.
    async fn allowlist(&self, requester_designations: &[Designation]) -> Allowlist {
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
        requester.extend_from_slice(requester_designations);
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
                    self.github(self.security).await,
                    "security",
                    &[Designation::SecurityApprover],
                ),
                entry(
                    self.github(self.operator).await,
                    "operator",
                    &[Designation::Operator],
                ),
            ],
        )
        .expect("no duplicates")
    }

    async fn verdict(
        &self,
        who: PrincipalId,
        requester_designations: &[Designation],
        decide: impl FnOnce(&Request<'_>) -> ActionVerdict,
    ) -> ActionVerdict {
        let (tenant, allowlist, now) = (
            self.world.tenant,
            self.allowlist(requester_designations).await,
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
            solo: factory_domain::policy::solo::SoloFact::NONE,
        })
    }

    async fn proof(&self, who: PrincipalId) -> AuthorizedApproval {
        match self.verdict(who, &[], authorize_build_code).await {
            ActionVerdict::Authorized(proof) => proof,
            other => panic!("expected a proof, got {other:?}"),
        }
    }

    fn request(
        &self,
        proof: AuthorizedApproval,
        script: BuildScript,
    ) -> RecordProjectBuildCodeDecision {
        RecordProjectBuildCodeDecision {
            stage: Subject {
                job: self.job,
                stage_run: self.run,
            },
            proof,
            script,
            reason: reason(),
            solo: None,
        }
    }

    async fn record(
        &self,
        who: PrincipalId,
        proof: AuthorizedApproval,
        script: BuildScript,
    ) -> Result<factory_workflow::commands::ProjectBuildCodeRecorded, EngineError> {
        self.world
            .engine
            .record_project_build_code_decision(&self.world.actor(who), self.request(proof, script))
            .await
    }

    async fn unblock(&self) -> Result<(), EngineError> {
        self.world
            .engine
            .decide(
                &self.world.actor(self.operator),
                Subject {
                    job: self.job,
                    stage_run: self.run,
                },
                Decision::UnblockRerun {
                    capability_reprobe_passed: false,
                    dependency_now_available: false,
                },
            )
            .await
    }

    async fn status(&self) -> StageRunStatus {
        self.world.stage_run(self.run).await.status
    }
}

#[tokio::test]
async fn a_security_approver_decides_on_the_file_and_the_content_the_stage_run_showed() {
    let rig = Rig::new().await;
    // Nothing is decided, so the operator cannot let the run go.
    assert!(matches!(
        rig.unblock().await,
        Err(EngineError::GuardUnmet(_))
    ));

    let before = rig.world.ledger(rig.job).await.len();
    let proof = rig.proof(rig.security).await;
    let recorded = rig
        .record(rig.security, proof, script("build.rs", SCRIPT))
        .await
        .expect("the decision is recorded");
    // Recording changes no status. The ledger holds one judgment that names the person and the
    // file, and the document is linked to the stage run under the role `UnblockRerun` reads.
    assert_eq!(rig.status().await, StageRunStatus::Blocked);
    let ledger = rig.world.ledger(rig.job).await;
    assert_eq!(ledger.len(), before + 1);
    let entry = ledger.last().expect("an entry");
    assert_eq!(entry.entry_hash, recorded.ledger_hash);
    assert_eq!(entry.claim.kind, ClaimKind::ExpertJudgment);
    assert!(entry.claim.assurance_level.is_none());
    assert!(entry.claim.statement.as_str().contains("build.rs"));
    let attestor = entry.evidence.iter().find_map(|evidence| match evidence {
        Evidence::ExpertJudgment(judgment) => Some(&judgment.attestor),
        _ => None,
    });
    assert_eq!(
        attestor.map(|a| (a.principal_id, a.role)),
        Some((rig.security, HumanRole::SecurityApprover))
    );
    let links = rig.world.links(rig.run).await;
    assert!(links.iter().any(|link| {
        link.direction == ArtifactDirection::Input
            && link.role.as_str().starts_with("dependency-decision-1-")
            && link.sha256 == recorded.artifact.sha256
    }));

    // The decision is the third alternative of the guard: the run goes again.
    rig.unblock().await.expect("the guard holds now");
    assert_eq!(rig.status().await, StageRunStatus::Ready);

    // The gate reads it back, for this tenant and this job only, bound to the path and the hash.
    let reader = LedgerApprovals::new(rig.world.store.clone(), rig.world.artifacts.clone());
    let found = reader.build_code_for_job(rig.world.tenant, rig.job).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].script, script("build.rs", SCRIPT));
    assert_eq!(found[0].approver.get(), rig.github(rig.security).await);
    assert_eq!(found[0].designation, Designation::SecurityApprover);
    assert_eq!(found[0].policy_hash, rig.world.config.policy_hash);
    assert!(reader.for_job(rig.world.tenant, rig.job).await.is_empty());
    let other_job = JobId::from_uuid(uuid::Uuid::from_u128(77));
    assert!(
        reader
            .build_code_for_job(rig.world.tenant, other_job)
            .await
            .is_empty()
    );
    let other_tenant = TenantId::from_uuid(uuid::Uuid::from_u128(78));
    assert!(
        reader
            .build_code_for_job(other_tenant, rig.job)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_decision_for_a_script_that_changed_since_it_was_shown_is_refused() {
    let rig = Rig::new().await;
    let proof = rig.proof(rig.security).await;
    // The person read another text than the one the stage run holds, or the file was edited
    // after the evidence was made: the hash is not the awaited one.
    let edited = script(
        "build.rs",
        b"fn main() { std::process::Command::new(\"sh\"); }\n",
    );
    let refused = rig.record(rig.security, proof, edited).await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "{refused:?}"
    );
    // The same content at another path is another file.
    let proof = rig.proof(rig.security).await;
    let refused = rig
        .record(rig.security, proof, script("tools/build.rs", SCRIPT))
        .await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "{refused:?}"
    );
    // Nothing was written, and the run is still blocked.
    assert_eq!(rig.status().await, StageRunStatus::Blocked);
    let reader = LedgerApprovals::new(rig.world.store.clone(), rig.world.artifacts.clone());
    assert!(
        reader
            .build_code_for_job(rig.world.tenant, rig.job)
            .await
            .is_empty()
    );
    assert!(matches!(
        rig.unblock().await,
        Err(EngineError::GuardUnmet(_))
    ));
}

#[tokio::test]
async fn only_a_security_approver_other_than_the_requester_may_decide() {
    let rig = Rig::new().await;
    // An approver gets no proof for this action from the policy engine, and a proof made for
    // another person is not the approver's.
    let verdict = rig.verdict(rig.approver, &[], authorize_build_code).await;
    assert!(matches!(verdict, ActionVerdict::Denied(_)), "{verdict:?}");
    let proof = rig.proof(rig.security).await;
    let refused = rig
        .record(rig.approver, proof, script("build.rs", SCRIPT))
        .await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    // A proof for the dependency action is not a proof for build code.
    let dependency_proof = match rig
        .verdict(rig.security, &[], |r| {
            authorize(r, Designation::SecurityApprover)
        })
        .await
    {
        ActionVerdict::Authorized(proof) => proof,
        other => panic!("expected a proof, got {other:?}"),
    };
    let refused = rig
        .record(rig.security, dependency_proof, script("build.rs", SCRIPT))
        .await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    // The requester holds the security designation on this allowlist, and the policy engine was
    // told the requester is someone else, so it made a proof. The engine knows who asked for
    // the job and refuses.
    let proof = match rig
        .verdict(
            rig.world.requester,
            &[Designation::SecurityApprover],
            authorize_build_code,
        )
        .await
    {
        ActionVerdict::Authorized(proof) => proof,
        other => panic!("expected a proof, got {other:?}"),
    };
    let refused = rig
        .record(rig.world.requester, proof, script("build.rs", SCRIPT))
        .await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    assert_eq!(rig.status().await, StageRunStatus::Blocked);
}

#[tokio::test]
async fn a_repeat_of_the_command_is_applied_once() {
    let rig = Rig::new().await;
    let actor = rig.world.actor(rig.security);
    let first = rig
        .world
        .engine
        .record_project_build_code_decision(
            &actor,
            rig.request(rig.proof(rig.security).await, script("build.rs", SCRIPT)),
        )
        .await
        .expect("recorded");
    let ledger = rig.world.ledger(rig.job).await.len();
    let again = rig
        .world
        .engine
        .record_project_build_code_decision(
            &actor,
            rig.request(rig.proof(rig.security).await, script("build.rs", SCRIPT)),
        )
        .await;
    assert!(matches!(again, Err(EngineError::Duplicate)), "{again:?}");
    assert_eq!(rig.world.ledger(rig.job).await.len(), ledger);
    assert_eq!(
        first.ledger_hash,
        rig.world
            .ledger(rig.job)
            .await
            .last()
            .expect("an entry")
            .entry_hash
    );
}

// ---- The solo mode (ADR 0021) ---------------------------------------------------------------

#[tokio::test]
async fn the_solo_security_approver_decides_on_the_build_code_after_thirty_minutes() {
    let rig = Rig::solo().await;
    rig.world.make_solo(&[
        HumanRole::Requester,
        HumanRole::Approver,
        HumanRole::SecurityApprover,
    ]);
    let blocked = rig
        .world
        .engine
        .state_entered_at(rig.world.tenant, rig.job, rig.run, StageRunStatus::Blocked)
        .await
        .expect("a read")
        .expect("the run blocked");
    let ask = |seconds: u64, phrase: Option<&str>| {
        let mut request = rig.request(
            support::solo_proof(&rig.world, authorize_build_code),
            script("build.rs", SCRIPT),
        );
        request.solo = Some(SoloRequest {
            requested_at: blocked
                .checked_add(std::time::Duration::from_secs(seconds))
                .expect("a time"),
            confirmation: phrase.map(ConfirmationWord::of),
        });
        request
    };
    let phrase = "I confirm the solo approval of build code build.rs";
    let early = rig
        .world
        .engine
        .record_project_build_code_decision(
            &rig.world.actor(rig.world.requester),
            ask(30 * 60 - 1, Some(phrase)),
        )
        .await;
    assert_eq!(
        early.err(),
        Some(EngineError::SoloRefused(SoloRefusal::SoloDelay))
    );
    rig.world
        .engine
        .record_project_build_code_decision(
            &rig.world.actor(rig.world.requester),
            ask(30 * 60, Some(phrase)),
        )
        .await
        .expect("thirty minutes after the block, with the phrase");
}
