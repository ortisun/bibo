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

use crate::world::{Documentation, Scenario, World};

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
    // The person is shown the pushed head, the documentation commit on top of the code. The
    // evidence binding is the validation one and names the code head the gates ran on.
    let docs_head = stage.world.documented.lock().expect("lock").clone();
    let docs_head = docs_head.expect("the documenting stage made a commit");
    assert_eq!(request.pr_head.as_str(), docs_head.as_str());
    assert_ne!(
        request.evidence_binding.head_commit.as_str(),
        request.pr_head.as_str()
    );
    assert_eq!(
        stage.world.sources.trees_asked.lock().expect("lock").last(),
        Some(&docs_head),
        "the tree is the tree of the pushed head"
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

/// Condition C-c: the flag the person is shown covers the documentation gate as well, by the same
/// rule as the validation reports. A documentation gate that failed, or was blocked and nobody
/// decided about, is not clear; a blocked one with a recorded decision is.
#[tokio::test]
async fn the_documentation_gate_is_part_of_what_the_person_is_told_is_clear() {
    for outcome in ["FAILED", "BLOCKED"] {
        let stage = after_delivery(Scenario {
            documentation_outcome: outcome,
            ..Scenario::default()
        })
        .await;
        let ran = stage.run().await.expect("the stage runs");
        assert!(!ran.request.gates_clear, "{outcome}");
    }

    let stage = after_delivery(Scenario {
        documentation_outcome: "BLOCKED",
        ..Scenario::default()
    })
    .await;
    for gate in factory_workflow::stages::documentation_review::gate_ids() {
        stage
            .world
            .sources
            .ledger
            .lock()
            .expect("lock")
            .dispositions
            .push((
                Slug::parse(gate).expect("a slug"),
                factory_domain::ids::LedgerEntryId::from_uuid(uuid::Uuid::from_u128(7)),
            ));
    }
    let ran = stage.run().await.expect("the stage runs");
    assert!(ran.request.gates_clear, "every blocked gate was decided");
}

/// Condition C-a, again at the approval: a specification that is not approved is not put in front
/// of a person.
#[tokio::test]
async fn a_specification_that_is_not_approved_stops_the_approval_stage() {
    let mut stage = after_delivery(Scenario::default()).await;
    stage
        .world
        .edit_upstream(
            &mut stage.upstream,
            StageKind::Specification,
            "specification-contract",
            |value| value["metadata"]["status"] = json!("draft"),
        )
        .await;
    let error = stage.execute().await.err();
    assert!(
        matches!(
            error,
            Some(StageError::PolicyDenied | StageError::InvalidOutput)
        ),
        "{error:?}"
    );
}

/// Condition C-b, again at the approval: the documentation reviewer's verdict is read from the
/// document the contract pinned. A verdict that is not a `PASS`, or that judged other reports or
/// another specification, stops the stage.
#[tokio::test]
async fn a_documentation_review_that_does_not_hold_stops_the_approval_stage() {
    // Not a pass.
    let mut stage = after_delivery(Scenario::default()).await;
    stage
        .world
        .edit_upstream(
            &mut stage.upstream,
            StageKind::DocumentationReview,
            "documentation-review",
            |value| *value = crate::world::changes_required_review(),
        )
        .await;
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));

    // Judged other reports.
    let mut stage = after_delivery(Scenario::default()).await;
    stage
        .world
        .edit_upstream(
            &mut stage.upstream,
            StageKind::DocumentationReview,
            "documentation-review",
            |value| {
                value["inputs_reviewed"]["gate_reports"][0]["sha256"] =
                    json!(factory_domain::values::Sha256Digest::of(b"other"));
            },
        )
        .await;
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));

    // Judged another specification.
    let mut stage = after_delivery(Scenario::default()).await;
    stage
        .world
        .edit_upstream(
            &mut stage.upstream,
            StageKind::DocumentationReview,
            "documentation-review",
            |value| {
                value["inputs_reviewed"]["frozen_spec_sha256"] =
                    json!(factory_domain::values::Sha256Digest::of(b"another"));
            },
        )
        .await;
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));

    // Untouched, the same stage runs.
    let stage = after_delivery(Scenario::default()).await;
    assert!(stage.execute().await.is_ok());
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

/// Changes a field of the stored delivery result.
async fn edit_delivery(stage: &mut Stage, edit: impl FnOnce(&mut Value)) {
    stage
        .world
        .edit_upstream(
            &mut stage.upstream,
            StageKind::Delivery,
            "delivery-result",
            edit,
        )
        .await;
}

#[tokio::test]
async fn the_evidence_binding_is_checked_against_the_code_head_and_not_the_pushed_head() {
    // The delivery says the gates ran on another commit than the evidence is bound to: the
    // documents contradict each other, and no one is asked to approve.
    let mut stage = after_delivery(Scenario::default()).await;
    edit_delivery(&mut stage, |result| {
        result["code_head"] = result["base_commit"].clone();
    })
    .await;
    assert_eq!(stage.execute().await.err(), Some(StageError::PolicyDenied));

    // A delivery that does not name the code head cannot be checked, and is not read.
    let mut stage = after_delivery(Scenario::default()).await;
    edit_delivery(&mut stage, |result| {
        result.as_object_mut().expect("object").remove("code_head");
    })
    .await;
    assert_eq!(stage.execute().await.err(), Some(StageError::InvalidOutput));
}

#[tokio::test]
async fn without_a_documentation_commit_the_person_is_shown_the_code_head() {
    let stage = after_delivery(Scenario {
        documentation: Documentation::NotApplicable,
        ..Scenario::default()
    })
    .await;
    let ran = stage.run().await.expect("the stage runs");
    assert_eq!(
        ran.request.pr_head.as_str(),
        ran.request.evidence_binding.head_commit.as_str()
    );
    assert_eq!(ran.resolution, Resolution::HumanGate);
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

/// Changes a field of the stored documentation gate report.
async fn edit_documentation_gate(stage: &mut Stage, edit: impl FnOnce(&mut Value)) {
    stage
        .world
        .edit_upstream(
            &mut stage.upstream,
            StageKind::DocumentationReview,
            "documentation-gate-report",
            edit,
        )
        .await;
}

#[tokio::test]
async fn the_approval_stage_reads_the_document_the_documentation_stage_stores() {
    // The document is not one gate report: it holds a binding and a report for every gate of the
    // Documentation Quality Gate. The warnings of all of them are counted.
    let mut stage = after_delivery(Scenario {
        translation_warnings: 3,
        ..Scenario::default()
    })
    .await;
    edit_documentation_gate(&mut stage, |document| {
        assert!(document["reports"].as_array().expect("a list").len() > 1);
        assert!(document["binding"]["documentation_head"].is_string());
    })
    .await;
    let ran = stage.run().await.expect("the stage runs");
    assert_eq!(ran.request.open_translation_warnings, 3);
    assert_eq!(ran.resolution, Resolution::HumanGate);
}

#[tokio::test]
async fn reports_made_for_other_commits_or_another_plan_are_not_evidence() {
    // The stored document is read by its hash, so it is the bytes that were stored. The reports in
    // it must also have been made for the commits that were delivered and for this plan.
    let other = "9".repeat(40);
    let other_plan = factory_domain::values::Sha256Digest::of(b"a plan nobody delivered");
    for field in [
        "base_commit",
        "code_head",
        "documentation_head",
        "plan_sha256",
    ] {
        let mut stage = after_delivery(Scenario::default()).await;
        edit_documentation_gate(&mut stage, |document| {
            document["binding"][field] = if field == "plan_sha256" {
                json!(other_plan)
            } else {
                json!(other)
            };
        })
        .await;
        assert_eq!(
            stage.execute().await.err(),
            Some(StageError::PolicyDenied),
            "{field}"
        );
        // A contradiction between documents is not a change in the world: nothing is superseded.
        assert!(stage.world.drift.told.lock().expect("lock").is_empty());
    }
}

#[tokio::test]
async fn a_documentation_gate_report_that_is_not_the_stored_document_is_not_read() {
    // A single gate report, the shape this stage read before it read the document as it is.
    let mut stage = after_delivery(Scenario::default()).await;
    let single = stage
        .world
        .report("documentation-gate", "PASSED")
        .to_json_value()
        .expect("JSON");
    edit_documentation_gate(&mut stage, |document| *document = single).await;
    assert_eq!(stage.execute().await.err(), Some(StageError::InvalidOutput));

    let broken: [fn(&mut Value); 3] = [
        |document| document["reports"] = json!([]),
        |document| {
            document.as_object_mut().expect("object").remove("binding");
        },
        |document| document["kind"] = json!("documentation-result"),
    ];
    for edit in broken {
        let mut stage = after_delivery(Scenario::default()).await;
        edit_documentation_gate(&mut stage, edit).await;
        assert_eq!(stage.execute().await.err(), Some(StageError::InvalidOutput));
    }
}

#[tokio::test]
async fn the_contract_of_the_approval_stage_pins_the_documentation_plan() {
    let mut stage = after_delivery(Scenario::default()).await;
    let contract = stage.contract(&handler(&stage.world)).expect("a contract");
    for name in [
        "delivery-result",
        "evidence-manifest",
        "validation-evidence",
        "documentation-plan",
        "documentation-gate-report",
        "policy-bundle",
    ] {
        assert!(
            contract
                .inputs
                .iter()
                .any(|input| input.name.as_str() == name),
            "{name}"
        );
    }
    stage
        .upstream
        .retain(|run| run.kind != StageKind::Documenting);
    assert_eq!(
        stage.execute().await.err(),
        Some(StageError::Blocked(
            factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable
        ))
    );
}
