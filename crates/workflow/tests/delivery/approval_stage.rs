//! The approval stage handler: what it stores for the person, and the gate it hands the engine.
//!
//! A delivery run comes first (the pull request is really opened on the fake host), then the
//! approval stage run reads it back.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, Contract, StageContract};
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::policy::authority::{Allowlist, AutonomyLevel};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::{ExecutionMode, Fidelity, GateOutcome, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::paths::CommitSha;
use factory_ports::store::LeaseEpoch;
use factory_workflow::gates::framework::{
    BlockCause, Expectation, Resolution, check_evidence, resolve,
};
use factory_workflow::handlers::{
    ContractContext, GateContext, NamedArtifact, RunIdentity, StageContext, StageError,
    StageHandler, UpstreamRun,
};
use factory_workflow::stages::approval::{
    ApprovalConfig, ApprovalHandler, ApprovalHandlerDeps, ApprovalRequest, ApprovalSources,
};
use factory_workflow::stages::delivery::SeamError;
use serde_json::{Value, json};

use crate::world::{Scenario, World};

struct Approvals;

#[async_trait]
impl ApprovalSources for Approvals {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn requester(&self, _run: &RunIdentity) -> Result<u64, SeamError> {
        Ok(1001)
    }
    async fn allowlist(&self, _tenant: TenantId) -> Result<Allowlist, SeamError> {
        Err(SeamError::NotFound)
    }
    async fn level(&self, _tenant: TenantId, _job: JobId) -> Result<AutonomyLevel, SeamError> {
        Ok(AutonomyLevel::L1)
    }
    async fn request(
        &self,
        _tenant: TenantId,
        _stage_run: StageRunId,
    ) -> Result<ApprovalRequest, SeamError> {
        Err(SeamError::NotFound)
    }
}

struct Stage {
    world: World,
    upstream: Vec<UpstreamRun>,
    identity: RunIdentity,
}

fn handler(world: &World) -> ApprovalHandler {
    ApprovalHandler::new(
        Arc::new(ApprovalConfig {
            policy: world.policy.clone(),
            definition_commit: GitSha::parse(&"e".repeat(40)).expect("a sha"),
        }),
        ApprovalHandlerDeps {
            host: world.host.clone(),
            delivery: world.sources.clone(),
            approvals: Arc::new(Approvals),
            drift: world.drift.clone(),
        },
    )
}

/// A delivery run, then the upstream an approval stage run sees.
async fn after_delivery(scenario: Scenario) -> Stage {
    let world = World::with(scenario);
    let (base, head) = world.commits().await;
    let delivered = world.run_on(&base, &head).await;
    let mut upstream = world.upstream(&base, &head).await;
    upstream.push(UpstreamRun {
        id: world.fixture.stage_run(),
        kind: StageKind::Delivery,
        status: StageRunStatus::Passed,
        outputs: delivered.outputs.clone(),
    });
    let identity = RunIdentity {
        tenant: world.tenant,
        job: world.job,
        correlation: world.correlation,
        stage_run: world.fixture.stage_run(),
        kind: StageKind::Approval,
    };
    Stage {
        world,
        upstream,
        identity,
    }
}

struct Ran {
    request: ApprovalRequest,
    resolution: Resolution,
    problem: Option<factory_workflow::gates::framework::EvidenceProblem>,
    reports: Vec<GateOutcome>,
    human_gate: bool,
}

impl Stage {
    fn contract(&self, handler: &ApprovalHandler) -> Result<StageContract, StageError> {
        handler.contract(&ContractContext {
            identity: self.identity,
            mode: ExecutionMode::Test,
            policy_hash: &self.world.policy_hash,
            now: self.world.now(),
            upstream: &self.upstream,
            human_inputs: &[],
            request_edited: false,
        })
    }

    async fn execute(&self) -> Result<Vec<NamedArtifact>, StageError> {
        let handler = handler(&self.world);
        let contract = self.contract(&handler)?;
        let mut ctx = StageContext::new(
            self.identity,
            self.world.attempt,
            1,
            LeaseEpoch::NEVER_CLAIMED,
            ExecutionMode::Test,
            &contract,
            self.world.ports(),
            &self.world.cancel,
            None,
            &[],
            &self.upstream,
        );
        let output = handler.execute(&mut ctx).await?;
        let mut stored = Vec::new();
        for document in &output.documents {
            stored.push(NamedArtifact {
                name: document.name.clone(),
                artifact: self.world.store_json(&document.value).await,
            });
        }
        Ok(stored)
    }

    async fn run(&self) -> Result<Ran, StageError> {
        let handler = handler(&self.world);
        let contract = self.contract(&handler)?;
        let outputs = self.execute().await?;
        let gate = GateContext {
            identity: self.identity,
            attempt: self.world.attempt,
            mode: ExecutionMode::Test,
            contract: &contract,
            ports: self.world.ports(),
            cancel: &self.world.cancel,
            outputs: &outputs,
            human_inputs: &[],
            upstream: &self.upstream,
        };
        let decision = handler.evaluate(&gate).await?;
        let problem = check_evidence(
            &decision,
            &Expectation {
                job: self.identity.job,
                stage_run: self.identity.stage_run,
                attempt: self.world.attempt,
                mode: ExecutionMode::Test,
            },
        )
        .err();
        let resolution = resolve(&contract, &decision);
        let stored = &outputs[0];
        let bytes = self
            .world
            .artifacts
            .get(&TenantScope::new(self.world.tenant), &stored.artifact)
            .await
            .expect("readable");
        let value: Value = serde_json::from_slice(&bytes).expect("JSON");
        Ok(Ran {
            request: ApprovalRequest::from_json(&value).expect("a request"),
            resolution,
            problem,
            reports: decision.reports.iter().map(|r| r.outcome).collect(),
            human_gate: decision.human_gate,
        })
    }

    /// Replaces the validation evidence with reports of these outcomes, bound as before.
    async fn with_evidence(&mut self, outcomes: &[(&'static str, &'static str)]) {
        let slot = self
            .upstream
            .iter_mut()
            .find(|run| run.kind == StageKind::Validation)
            .expect("the validation run");
        let old: ArtifactRef = slot.outputs[0].artifact.clone();
        let bytes = self
            .world
            .artifacts
            .get(&TenantScope::new(self.world.tenant), &old)
            .await
            .expect("readable");
        let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
        value["reports"] = json!(
            outcomes
                .iter()
                .map(|(gate, outcome)| self
                    .world
                    .report(gate, outcome)
                    .to_json_value()
                    .expect("JSON"))
                .collect::<Vec<_>>()
        );
        slot.outputs[0].artifact = self.world.store_json(&value).await;
    }
}

#[tokio::test]
async fn the_approval_stage_stores_what_the_person_will_see() {
    let stage = after_delivery(Scenario::default()).await;
    let ran = stage.run().await.expect("the stage runs");
    let request = &ran.request;
    let sources = &stage.world.sources;
    assert_eq!(request.repository, "example-org/word-count");
    assert_eq!(request.head_branch, "factory/job-1");
    assert_eq!(request.base_branch, "main");
    assert_eq!(request.spec_version, 1);
    assert_eq!(request.requester, 1001);
    assert_eq!(request.tree, sources.tree);
    assert!(request.gates_clear);
    assert_eq!(request.open_translation_warnings, 0);
    assert_eq!(request.tier, factory_domain::vocabulary::RiskTier::Low);
    // The binding names the delivered commits, and the evidence binding is the validation one.
    assert_eq!(
        request.evidence_binding.head_commit.as_str(),
        request.pr_head.as_str()
    );
    assert_eq!(
        request.evidence_binding.base_commit.as_str(),
        request.base.as_str()
    );
}

#[tokio::test]
async fn the_approval_stage_is_a_human_gate_and_never_passes_by_itself() {
    let stage = after_delivery(Scenario::default()).await;
    let ran = stage.run().await.expect("the stage runs");
    assert!(ran.human_gate);
    assert_eq!(ran.problem, None);
    assert_eq!(ran.resolution, Resolution::HumanGate);
    assert_eq!(ran.reports, vec![GateOutcome::Passed]);
}

#[tokio::test]
async fn a_failed_gate_is_not_put_in_front_of_a_person() {
    let mut stage = after_delivery(Scenario::default()).await;
    stage
        .with_evidence(&[("format", "PASSED"), ("unit-tests", "FAILED")])
        .await;
    let ran = stage.run().await.expect("the stage runs");
    assert!(!ran.request.gates_clear);
    assert_eq!(ran.reports, vec![GateOutcome::Failed]);
    assert!(
        matches!(ran.resolution, Resolution::Failed { .. }),
        "{:?}",
        ran.resolution
    );
}

#[tokio::test]
async fn a_blocked_gate_is_clear_only_when_a_person_decided_about_it() {
    let mut stage = after_delivery(Scenario::default()).await;
    stage
        .with_evidence(&[("format", "PASSED"), ("lint", "BLOCKED")])
        .await;
    let ran = stage.run().await.expect("the stage runs");
    assert!(!ran.request.gates_clear);
    assert!(matches!(ran.resolution, Resolution::Failed { .. }));

    stage
        .world
        .sources
        .ledger
        .lock()
        .expect("lock")
        .dispositions
        .push((
            Slug::parse("lint").expect("a slug"),
            factory_domain::ids::LedgerEntryId::from_uuid(uuid::Uuid::from_u128(5)),
        ));
    let ran = stage.run().await.expect("the stage runs");
    assert!(ran.request.gates_clear);
    assert_eq!(ran.resolution, Resolution::HumanGate);
}

#[tokio::test]
async fn translation_warnings_are_counted_for_the_decision() {
    let stage = after_delivery(Scenario {
        translation_warnings: 2,
        ..Scenario::default()
    })
    .await;
    let ran = stage.run().await.expect("the stage runs");
    assert_eq!(ran.request.open_translation_warnings, 2);
}

#[tokio::test]
async fn a_pull_request_that_is_not_the_open_draft_at_the_delivered_commit_stops_the_stage() {
    let stage = after_delivery(Scenario::default()).await;
    stage.world.host.pull_request_reads_as_ready();
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));

    let stage = after_delivery(Scenario::default()).await;
    stage
        .world
        .host
        .head_moves_to(CommitSha::parse(&"9".repeat(40)).expect("a sha"));
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));
}

#[tokio::test]
async fn evidence_binding_is_rechecked_before_a_person_is_asked() {
    let stage = after_delivery(Scenario::default()).await;
    stage
        .world
        .sources
        .values
        .lock()
        .expect("lock")
        .definition_hash = factory_domain::values::Sha256Digest::of(b"definitions two");
    assert_eq!(stage.execute().await.err(), Some(StageError::Cancelled));
    assert_eq!(stage.world.drift.told.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn a_missing_input_blocks_the_stage() {
    let mut stage = after_delivery(Scenario::default()).await;
    stage.upstream.retain(|run| run.kind != StageKind::Delivery);
    assert_eq!(
        stage.execute().await.err(),
        Some(StageError::Blocked(
            factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable
        ))
    );
}

#[tokio::test]
async fn a_delivery_that_opened_no_pull_request_is_not_approved() {
    let mut stage = after_delivery(Scenario::default()).await;
    // Replace the delivery result with one that says nothing was delivered.
    let slot = stage
        .upstream
        .iter_mut()
        .find(|run| run.kind == StageKind::Delivery)
        .expect("the delivery run");
    let output = slot
        .outputs
        .iter_mut()
        .find(|output| output.name.as_str() == "delivery-result")
        .expect("a result");
    let bytes = stage
        .world
        .artifacts
        .get(&TenantScope::new(stage.world.tenant), &output.artifact)
        .await
        .expect("readable");
    let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
    value["delivered"] = json!(false);
    output.artifact = stage.world.store_json(&value).await;
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));
    // The block cause the engine would see for a missing gate is unrelated to this refusal.
    let _ = BlockCause::MissingEvidence;
}
