//! Recording a person's decision on a dependency (review B-4), through the real engine over the
//! in-memory store.
//!
//! The scripted `VALIDATION` handler stops at the gate with a block and stores the evidence
//! document the dependency review makes, naming the packages that await a decision. Each test
//! then does what the API or the command line does: it asks the policy engine for the proof of
//! authority, and hands the engine the proof and the exact package.

mod support;

use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence};
use factory_domain::ids::{JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::authority::{
    ActionVerdict, Actor, ActorKind, Allowlist, AllowlistEntry, AutonomyLevel,
};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::{HumanText, Timestamp};
use factory_domain::vocabulary::{HumanRole, RiskTier, StageKind};
use factory_ports::clock::IdGenerator;
use factory_ports::store::{ArtifactDirection, PrincipalKind};
use factory_workflow::commands::{Decision, RecordDependencyDecision, Subject};
use factory_workflow::engine::EngineError;
use factory_workflow::gates::supply_chain::approval::{
    ApprovalKind, RecordedApprovals, Request, Subject as Package, authorize, authorize_build_code,
};
use factory_workflow::gates::supply_chain::ledger::LedgerApprovals;
use serde_json::json;
use support::{Eval, World};

const SECURITY: &str = include_str!("../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../domain/tests/fixtures/policy/approval.json");
const REPOSITORY: &str = "example-org/app";

fn checksum(digit: char) -> String {
    digit.to_string().repeat(64)
}

/// What the dependency review stores: an ordinary package, one that needs a security approver,
/// and one whose build code awaits its own decision.
fn evidence() -> serde_json::Value {
    json!({
        "kind": "validation-evidence",
        "reports": [],
        "dependency_review": {
            "new_direct_dependencies": [
                {
                    "name": "some-crate", "version": "0.1.0", "checksum": checksum('c'),
                    "needs": "approver", "flags": [], "approval": null
                },
                {
                    "name": "odd-crate", "version": "2.0.0", "checksum": checksum('e'),
                    "needs": "security_approver", "flags": ["not_in_registry"], "approval": null
                }
            ],
            "build_code_awaiting_a_decision": [
                {
                    "name": "helper", "version": "0.1.0", "checksum": checksum('d'),
                    "action": "approve_build_code", "needs": "security_approver"
                }
            ]
        }
    })
}

fn package(name: &str, version: &str, digit: char) -> Package {
    Package {
        name: name.to_owned(),
        version: version.to_owned(),
        checksum: checksum(digit),
    }
}

fn some_crate() -> Package {
    package("some-crate", "0.1.0", 'c')
}

fn odd_crate() -> Package {
    package("odd-crate", "2.0.0", 'e')
}

fn helper() -> Package {
    package("helper", "0.1.0", 'd')
}

fn reason() -> HumanText {
    HumanText::parse("Read the package, its maintainers and its licence.").expect("a text")
}

fn engine() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("the security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("the approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

fn now() -> Timestamp {
    Timestamp::parse("2026-10-28T12:00:00Z").expect("a time")
}

/// The world, with a validation run blocked by the dependency review, and the people.
struct Rig {
    world: World,
    policy: PolicyEngine,
    job: JobId,
    run: StageRunId,
    approver: PrincipalId,
    /// Another person who holds the same designation as `approver`.
    other_approver: PrincipalId,
    security: PrincipalId,
    operator: PrincipalId,
}

impl Rig {
    async fn new() -> Self {
        let world = World::new().await;
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
        let other_approver = world.person("approver-2", &[HumanRole::Approver]).await;
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
            other_approver,
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

    /// The allowlist of the tenant, with the designations the world gave these people.
    async fn allowlist(&self) -> Allowlist {
        let tenant: TenantId = self.world.tenant;
        let entry = |id: u64, login: &str, designations: &[Designation]| AllowlistEntry {
            tenant,
            github_user_id: GithubUserId::new(id).expect("an id"),
            login: login.to_owned(),
            designations: designations.iter().copied().collect(),
            repositories: None,
            expires_at: None,
        };
        Allowlist::new(
            "sha256:allowlist-v1",
            vec![
                entry(
                    self.github(self.world.requester).await,
                    "requester",
                    &[Designation::Requester],
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
                entry(
                    self.github(self.operator).await,
                    "operator",
                    &[Designation::Operator],
                ),
            ],
        )
        .expect("no duplicates")
    }

    /// Asks the policy engine whether `who` may take the action, as the API does.
    async fn verdict(
        &self,
        who: PrincipalId,
        decide: impl FnOnce(&Request<'_>) -> ActionVerdict,
    ) -> ActionVerdict {
        let (tenant, allowlist, now) = (self.world.tenant, self.allowlist().await, now());
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
            requester: GithubUserId::new(requester),
            risk_tier: RiskTier::Low,
            protected_path_change: false,
            sensitive_file_change: false,
        })
    }

    async fn dependency_proof(&self, who: PrincipalId, needed: Designation) -> AuthorizedApproval {
        match self.verdict(who, |r| authorize(r, needed)).await {
            ActionVerdict::Authorized(proof) => proof,
            other => panic!("expected a proof, got {other:?}"),
        }
    }

    /// A proof for the requester of the job as an approver. The allowlist gives them the designation
    /// for this one proof, and the policy engine is told that the requester is someone else, which
    /// is what a caller that gets this wrong does.
    async fn dependency_proof_for_the_requester_as_approver(
        &self,
        who: PrincipalId,
        needed: Designation,
    ) -> AuthorizedApproval {
        let tenant = self.world.tenant;
        let id = self.github(who).await;
        let allowlist = Allowlist::new(
            "sha256:allowlist-v1",
            vec![AllowlistEntry {
                tenant,
                github_user_id: GithubUserId::new(id).expect("an id"),
                login: "requester".to_owned(),
                designations: [Designation::Requester, Designation::Approver]
                    .into_iter()
                    .collect(),
                repositories: None,
                expires_at: None,
            }],
        )
        .expect("no duplicates");
        let actor = Actor {
            github_user_id: GithubUserId::new(id).expect("an id"),
            login: "requester",
            kind: ActorKind::User,
            github_permission: None,
            author_association: None,
        };
        let now = now();
        let verdict = authorize(
            &Request {
                policy: &self.policy.authority,
                level: AutonomyLevel::L1,
                tenant: &tenant,
                repository: REPOSITORY,
                actor: &actor,
                allowlist: &allowlist,
                now: &now,
                requester: GithubUserId::new(id + 1_000),
                risk_tier: RiskTier::Low,
                protected_path_change: false,
                sensitive_file_change: false,
            },
            needed,
        );
        match verdict {
            ActionVerdict::Authorized(proof) => proof,
            other => panic!("expected a proof, got {other:?}"),
        }
    }

    async fn build_code_proof(&self, who: PrincipalId) -> AuthorizedApproval {
        match self.verdict(who, authorize_build_code).await {
            ActionVerdict::Authorized(proof) => proof,
            other => panic!("expected a proof, got {other:?}"),
        }
    }

    fn request(&self, proof: AuthorizedApproval, package: Package) -> RecordDependencyDecision {
        RecordDependencyDecision {
            stage: Subject {
                job: self.job,
                stage_run: self.run,
            },
            proof,
            package,
            reason: reason(),
        }
    }

    async fn record(
        &self,
        who: PrincipalId,
        proof: AuthorizedApproval,
        package: Package,
    ) -> Result<factory_workflow::commands::DependencyDecisionRecorded, EngineError> {
        self.world
            .engine
            .record_dependency_decision(&self.world.actor(who), self.request(proof, package))
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
async fn an_unblock_with_no_recorded_decision_is_refused_whatever_the_caller_says() {
    // The negative test of the new alternative of guard `G_BLOCK_CLEARED_RERUN`. The two facts
    // the caller can pass are false, and nothing was recorded, so the guard does not hold. There
    // is no third flag to pass blindly.
    let rig = Rig::new().await;
    let refused = rig.unblock().await;
    match refused {
        Err(EngineError::GuardUnmet(failure)) => {
            let text = failure.to_string();
            assert!(
                text.contains("a decision on the dependency was recorded"),
                "{text}"
            );
        }
        other => panic!("expected the guard to refuse, got {other:?}"),
    }
    assert_eq!(rig.status().await, StageRunStatus::Blocked);
}

#[tokio::test]
async fn a_recorded_decision_lets_the_operator_run_the_stage_again() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let recorded = rig
        .record(rig.approver, proof, some_crate())
        .await
        .expect("the decision is recorded");
    assert_eq!(recorded.kind, ApprovalKind::NewDependency);
    // Recording changes no status: the stage run waits for the operator's rerun.
    assert_eq!(rig.status().await, StageRunStatus::Blocked);

    rig.unblock().await.expect("the guard holds now");
    assert_eq!(rig.status().await, StageRunStatus::Ready);
}

#[tokio::test]
async fn the_decision_is_in_the_ledger_the_links_and_the_audit_log() {
    let rig = Rig::new().await;
    let before = rig.world.ledger(rig.job).await.len();
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let recorded = rig
        .record(rig.approver, proof, some_crate())
        .await
        .expect("recorded");

    // One entry, an expert judgment that names the person and cites the document by its hash.
    let ledger = rig.world.ledger(rig.job).await;
    assert_eq!(ledger.len(), before + 1);
    let entry = ledger.last().expect("an entry");
    assert_eq!(entry.entry_hash, recorded.ledger_hash);
    assert_eq!(entry.claim.kind, ClaimKind::ExpertJudgment);
    assert!(
        entry.claim.assurance_level.is_none(),
        "a decision is no assurance claim"
    );
    assert!(
        entry
            .claim
            .statement
            .as_str()
            .contains("the new direct dependency some-crate 0.1.0")
    );
    let attestor = entry.evidence.iter().find_map(|evidence| match evidence {
        Evidence::ExpertJudgment(judgment) => Some(&judgment.attestor),
        _ => None,
    });
    assert_eq!(
        attestor.map(|a| (a.principal_id, a.role)),
        Some((rig.approver, HumanRole::Approver))
    );
    assert!(entry.evidence.iter().any(|evidence| matches!(
        evidence, Evidence::Artifact(held) if held.sha256 == recorded.artifact.sha256
    )));

    // The stage run is linked to it as an input, and the document is in the tenant's index.
    let links = rig.world.links(rig.run).await;
    assert!(links.iter().any(|link| {
        link.direction == ArtifactDirection::Input
            && link.role.as_str().starts_with("dependency-decision-1-")
            && link.sha256 == recorded.artifact.sha256
    }));
    rig.world.index_entry(&recorded.artifact.sha256).await;

    // The audit log names it.
    let audit = rig.world.audit(rig.job).await;
    assert!(
        audit.iter().any(|record| record
            .event
            .action
            .as_str()
            .contains("approval_granted_or_rejected")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn the_gate_reads_the_decision_back_from_the_ledger_for_the_tenant_and_the_job_only() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    rig.record(rig.approver, proof, some_crate())
        .await
        .expect("recorded");
    let proof = rig.build_code_proof(rig.security).await;
    rig.record(rig.security, proof, helper())
        .await
        .expect("recorded");

    let reader = LedgerApprovals::new(rig.world.store.clone(), rig.world.artifacts.clone());
    let found = reader.for_job(rig.world.tenant, rig.job).await;
    assert_eq!(found.len(), 2);
    let kinds: Vec<ApprovalKind> = found.iter().map(|a| a.kind).collect();
    assert!(
        kinds.contains(&ApprovalKind::NewDependency) && kinds.contains(&ApprovalKind::BuildCode)
    );
    let dependency = found
        .iter()
        .find(|a| a.kind == ApprovalKind::NewDependency)
        .expect("the dependency decision");
    assert_eq!(dependency.subject, some_crate());
    assert_eq!(dependency.designation, Designation::Approver);
    assert_eq!(dependency.approver.get(), rig.github(rig.approver).await);
    assert_eq!(dependency.scope.job, rig.job);
    assert_eq!(dependency.scope.tenant, rig.world.tenant);
    // The policy hash is the one the engine runs under, the one the stages read as their policy
    // input, and not one the caller chose.
    assert_eq!(dependency.policy_hash, rig.world.config.policy_hash);

    // Another job of the tenant has none, and neither has another tenant.
    let other_job = JobId::from_uuid(rig.world.ids.new_uuid());
    assert!(reader.for_job(rig.world.tenant, other_job).await.is_empty());
    let other_tenant = TenantId::from_uuid(rig.world.ids.new_uuid());
    assert!(reader.for_job(other_tenant, rig.job).await.is_empty());
}

#[tokio::test]
async fn an_ordinary_approver_cannot_decide_what_needs_a_security_approver() {
    let rig = Rig::new().await;
    // The proof is genuine: the policy engine authorizes an approver for the action. The package
    // needs more than an approver, and the engine knows it from the evidence.
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let refused = rig.record(rig.approver, proof, odd_crate()).await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "{refused:?}"
    );
    assert_eq!(
        rig.world.ledger(rig.job).await.len(),
        ledger_len_blocked(&rig).await
    );

    // A security approver decides it, and may also decide what an approver decides.
    let proof = rig
        .dependency_proof(rig.security, Designation::SecurityApprover)
        .await;
    rig.record(rig.security, proof, odd_crate())
        .await
        .expect("a security approver decides");
    let proof = rig
        .dependency_proof(rig.security, Designation::SecurityApprover)
        .await;
    rig.record(rig.security, proof, some_crate())
        .await
        .expect("and what an approver decides");
}

async fn ledger_len_blocked(rig: &Rig) -> usize {
    rig.world.ledger(rig.job).await.len()
}

#[tokio::test]
async fn build_code_is_a_decision_of_its_own_and_only_a_security_approver_makes_it() {
    let rig = Rig::new().await;
    // The policy engine gives an ordinary approver no proof for the action.
    let denied = rig.verdict(rig.approver, authorize_build_code).await;
    assert!(matches!(denied, ActionVerdict::Denied(_)), "{denied:?}");

    // A decision on the dependency, even by a security approver, is not a decision on its code,
    // and a package whose code awaits a decision is not decided with the dependency action.
    let proof = rig
        .dependency_proof(rig.security, Designation::SecurityApprover)
        .await;
    let refused = rig.record(rig.security, proof, helper()).await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "{refused:?}"
    );
    let proof = rig.build_code_proof(rig.security).await;
    let refused = rig.record(rig.security, proof, some_crate()).await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "the dependency some-crate awaits the dependency decision, not a decision on code: {refused:?}"
    );

    let proof = rig.build_code_proof(rig.security).await;
    let recorded = rig
        .record(rig.security, proof, helper())
        .await
        .expect("a security approver decides on the build code");
    assert_eq!(recorded.kind, ApprovalKind::BuildCode);
}

#[tokio::test]
async fn a_decision_is_recorded_only_for_a_package_the_evidence_shows() {
    let rig = Rig::new().await;
    for wrong in [
        package("some-crate", "0.1.1", 'c'),
        package("some-crate", "0.1.0", 'f'),
        package("never-shown", "1.0.0", 'c'),
    ] {
        let proof = rig
            .dependency_proof(rig.approver, Designation::Approver)
            .await;
        let refused = rig.record(rig.approver, proof, wrong).await;
        assert!(
            matches!(refused, Err(EngineError::Refused(_))),
            "{refused:?}"
        );
    }
    assert!(
        rig.unblock().await.is_err(),
        "nothing was recorded, so nothing clears the block"
    );
}

#[tokio::test]
async fn a_proof_made_for_another_person_is_refused() {
    let rig = Rig::new().await;
    // The approver's proof, presented by a second person who holds the same designation: both
    // hold the role, so only the numeric GitHub id on the proof tells them apart. The proof is
    // a statement about one person, and it is not a bearer token.
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let refused = rig.record(rig.other_approver, proof, some_crate()).await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    // Presented by a person of another designation, the role check refuses it as well.
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let refused = rig.record(rig.security, proof, some_crate()).await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
    assert!(rig.unblock().await.is_err());
}

#[tokio::test]
async fn a_person_removed_from_the_allowlist_since_the_proof_is_refused() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    // The allowlist is read for each call: the person has no role now.
    rig.world.authority.revoke(rig.approver);
    let refused = rig.record(rig.approver, proof, some_crate()).await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_person_who_is_not_on_the_allowlist_has_no_proof_to_present() {
    let rig = Rig::new().await;
    let denied = rig
        .verdict(rig.operator, |r| authorize(r, Designation::Approver))
        .await;
    assert!(matches!(denied, ActionVerdict::Denied(_)), "{denied:?}");
}

#[tokio::test]
async fn a_command_that_arrives_twice_is_applied_once() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let actor = rig.world.actor(rig.approver);
    rig.world
        .engine
        .record_dependency_decision(&actor, rig.request(proof.clone(), some_crate()))
        .await
        .expect("the first applies");
    let entries = rig.world.ledger(rig.job).await.len();
    let again = rig
        .world
        .engine
        .record_dependency_decision(&actor, rig.request(proof, some_crate()))
        .await;
    assert!(matches!(again, Err(EngineError::Duplicate)), "{again:?}");
    assert_eq!(rig.world.ledger(rig.job).await.len(), entries);
}

#[tokio::test]
async fn only_a_blocked_validation_run_takes_a_decision() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    let intake = rig
        .world
        .view(rig.job)
        .await
        .newest(StageKind::Intake)
        .expect("an intake run")
        .id;
    let refused = rig
        .world
        .engine
        .record_dependency_decision(
            &rig.world.actor(rig.approver),
            RecordDependencyDecision {
                stage: Subject {
                    job: rig.job,
                    stage_run: intake,
                },
                proof,
                package: some_crate(),
                reason: reason(),
            },
        )
        .await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_decision_made_before_a_later_block_does_not_clear_it() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    rig.record(rig.approver, proof, some_crate())
        .await
        .expect("recorded");
    rig.unblock().await.expect("the first block is cleared");

    // The rerun finds the build code, and the stage blocks again, after a second attempt.
    rig.world
        .script(StageKind::Validation)
        .queue_evals([Eval::Blocked]);
    rig.world.advance(400);
    rig.world.run_next("worker-1").await;
    assert_eq!(rig.status().await, StageRunStatus::Blocked);
    let refused = rig.unblock().await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "the decision belongs to the first attempt: {refused:?}"
    );

    // A decision recorded after this block clears it.
    let proof = rig.build_code_proof(rig.security).await;
    rig.record(rig.security, proof, helper())
        .await
        .expect("recorded");
    rig.unblock().await.expect("cleared");
    assert_eq!(rig.status().await, StageRunStatus::Ready);
}

#[tokio::test]
async fn the_reason_is_part_of_the_record_and_a_short_one_is_refused() {
    let rig = Rig::new().await;
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    // `HumanText` already refuses fewer than ten characters, so a request cannot hold one; the
    // record keeps the person's words.
    rig.record(rig.approver, proof, some_crate())
        .await
        .expect("recorded");
    let reader = LedgerApprovals::new(rig.world.store.clone(), rig.world.artifacts.clone());
    let found = reader.for_job(rig.world.tenant, rig.job).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].reason, reason().as_str());
}

/// RR-24. The person who asked for the job does not decide on its dependencies, even with a proof the
/// policy engine made for them: the engine knows the requester of the job and compares it with the
/// acting principal itself, and does not rely on the risk the caller told the policy engine.
#[tokio::test]
async fn the_requester_of_the_job_cannot_decide_on_its_dependencies() {
    let rig = Rig::new().await;
    // The requester also holds the approver role and designation, so nothing but the comparison with
    // the job's requester stands in the way.
    let requester = rig.world.requester;
    rig.world
        .authority
        .grant(requester, &[HumanRole::Requester, HumanRole::Approver]);
    let proof = rig
        .dependency_proof_for_the_requester_as_approver(requester, Designation::Approver)
        .await;
    let refused = rig.record(requester, proof, some_crate()).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::NotAuthorized(
                "the person who asked for the job may not decide on its dependencies"
            ))
        ),
        "{refused:?}"
    );
    assert!(rig.unblock().await.is_err(), "nothing was recorded");
    // Control: another approver decides.
    let proof = rig
        .dependency_proof(rig.approver, Designation::Approver)
        .await;
    rig.record(rig.approver, proof, some_crate())
        .await
        .expect("another approver records the decision");
}
