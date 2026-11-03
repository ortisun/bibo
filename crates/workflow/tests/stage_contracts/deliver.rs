//! The delivery and approval stages, run for real on what the stages before them stored.
//!
//! The delivery handler and the approval handler are the real ones. They run over the repository of
//! the rig, on the commits the real implementation and documenting stages made, with the code host
//! sharing the rig's remote. What they read is what [`Pipeline`] holds: no document here is written
//! by hand. The few facts that no port offers (the ledger, the tree id, the target) come from fixed
//! values, as they do in the delivery tests, and say that they are fakes.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, Contract, StageContract, Violation};
use factory_domain::ids::{AttemptId, CorrelationId, JobId, LedgerEntryId, StageRunId, TenantId};
use factory_domain::policy::authority::{Allowlist, AutonomyLevel};
use factory_domain::policy::risk::RiskFacts;
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{AssuranceLevel, ExecutionMode, Fidelity, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::Clock;
use factory_ports::githost::IssueRef;
use factory_ports::paths::{BranchName, CommitSha, RepoPath};
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use factory_ports::store::LeaseEpoch;
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::FakeCancel;
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_workflow::gates::framework::{GateDecision, Resolution, resolve};
use factory_workflow::gates::readability::{Options, ReadabilityGate};
use factory_workflow::gates::supply_chain::approval::StaticApprovals;
use factory_workflow::gates::supply_chain::facts::{StaticDatabase, StaticRegistry};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::run::{FetchSandbox, SbomRule};
use factory_workflow::gates::supply_chain::tools::SbomTool;
use factory_workflow::handlers::{
    ContractContext, GateContext, NamedArtifact, RunIdentity, StageContext, StageError,
    StageHandler, StagePorts, UpstreamRun,
};
use factory_workflow::stages::approval::{
    ApprovalConfig, ApprovalHandler, ApprovalHandlerDeps, ApprovalRequest, ApprovalSources,
};
use factory_workflow::stages::delivery::seams::CurrentValues;
use factory_workflow::stages::delivery::{
    DeliveryConfig, DeliveryDeps, DeliveryHandler, DeliverySources, DeliveryTarget, DocLink,
    EvidenceDrift, LedgerState, SeamError,
};
use factory_workflow::stages::validation::{
    Binding, Bounds, JsonManifestReader, SupplyChainSeams, SupplyChainSettings, ValidationConfig,
    ValidationHandler, VerifySandbox,
};
use serde_json::Value;

use crate::chain::{Output, Pipeline};
use crate::design_fakes::{DesignWorld, LABEL, REQUESTER_ID, person};
use crate::rig::{policy_engine, redactor, rules};
use factory_workflow::stages::delivery::DesignRecheck;
use factory_workflow::stages::intake::judge::DesignJudge;

/// The real validation handler, built the way the validation tests build it. Its stage cannot run
/// on the rig, which has a stand-in for it, but its contract can be resolved on the real job.
pub fn validation_handler() -> ValidationHandler {
    let image = factory_testkit::fixtures::sandbox_spec(
        &factory_testkit::fixtures::Ids::new(),
        factory_ports::sandbox::SandboxProfile::Verify,
    );
    let fetch = factory_testkit::fixtures::sandbox_spec(
        &factory_testkit::fixtures::Ids::new(),
        factory_ports::sandbox::SandboxProfile::FetchDeps,
    );
    ValidationHandler::new(Arc::new(ValidationConfig {
        policy: policy_engine(),
        path_rules: rules(),
        holdouts: Vec::new(),
        redactor: redactor(),
        sandbox: VerifySandbox {
            image: image.image,
            limits: image.limits,
            env: image.env,
            hardening: image.hardening,
            caches: Vec::new(),
            arch: "arm64".to_owned(),
        },
        manifest: Arc::new(JsonManifestReader),
        flaky_registry: std::collections::BTreeSet::new(),
        bounds: Bounds::default(),
        supply_chain: SupplyChainSeams {
            settings: SupplyChainSettings::new(
                FetchSandbox {
                    image: fetch.image,
                    limits: fetch.limits,
                    env: fetch.env,
                    hardening: fetch.hardening,
                    caches: Vec::new(),
                    sidecar: "sidecar-fixture".to_owned(),
                    arch: "arm64".to_owned(),
                },
                LicensePolicy::owner_approved(),
                PopularNames::bundled().expect("the bundled list"),
                SbomRule {
                    required: false,
                    tool: SbomTool::default(),
                },
            ),
            approvals: Arc::new(StaticApprovals::default()),
            registry: Arc::new(StaticRegistry::new()),
            advisory_db: Arc::new(StaticDatabase(None)),
        },
    }))
}

/// Accepts every document: the delivery gates read the documents back and check them themselves.
struct AcceptAll;

impl OutputValidator for AcceptAll {
    fn validate_bytes(
        &self,
        _kind: ContractKind,
        _version: u32,
        bytes: &[u8],
    ) -> Result<ValidatedOutput, Vec<Violation>> {
        let value = serde_json::from_slice(bytes).map_err(|_| Vec::new())?;
        Ok(ValidatedOutput {
            sha256: Sha256Digest::of(bytes),
            size_bytes: bytes.len() as u64,
            value,
        })
    }
    fn validate_value(
        &self,
        _kind: ContractKind,
        _version: u32,
        _instance: &Value,
    ) -> Result<(), Vec<Violation>> {
        Ok(())
    }
}

/// The facts the composition root would read from the store. Nothing in the world has changed
/// since the gates ran, so the values the evidence is bound to are the ones it names.
struct Sources {
    target: DeliveryTarget,
    values: CurrentValues,
    ledger: LedgerState,
    tree: GitSha,
    trees_asked: Mutex<Vec<CommitSha>>,
}

#[async_trait]
impl DeliverySources for Sources {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn target(&self, _run: &RunIdentity) -> Result<DeliveryTarget, SeamError> {
        Ok(self.target.clone())
    }
    async fn current_values(
        &self,
        _run: &RunIdentity,
        _base: &CommitSha,
    ) -> Result<CurrentValues, SeamError> {
        Ok(self.values.clone())
    }
    async fn ledger(&self, _run: &RunIdentity) -> Result<LedgerState, SeamError> {
        Ok(self.ledger.clone())
    }
    async fn tree_of(&self, _run: &RunIdentity, commit: &CommitSha) -> Result<GitSha, SeamError> {
        self.trees_asked.lock().expect("lock").push(commit.clone());
        Ok(self.tree.clone())
    }
}

/// Records that the engine was told a bound value changed.
#[derive(Default)]
pub struct Drift {
    pub told: Mutex<Vec<(TenantId, JobId)>>,
}

#[async_trait]
impl EvidenceDrift for Drift {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn binding_changed(&self, tenant: TenantId, job: JobId) -> Result<(), SeamError> {
        self.told.lock().expect("lock").push((tenant, job));
        Ok(())
    }
}

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

/// What a real run of a stage left: what it stored and what its gate handed the engine.
pub struct Ran {
    /// The deliverables, as the engine would have stored them.
    pub outputs: Vec<Output>,
    /// The gate decision.
    pub decision: GateDecision,
    /// What the engine would decide from it.
    pub resolution: Resolution,
}

impl Ran {
    pub fn find(&self, name: &str) -> &Output {
        self.outputs
            .iter()
            .find(|output| output.name == name)
            .unwrap_or_else(|| panic!("the stage did not store {name}"))
    }
}

/// The delivery stage and the approval stage, over the rig of a pipeline.
pub struct Delivery<'a> {
    pipeline: &'a Pipeline,
    sources: Arc<Sources>,
    host: Arc<FakeChangeHost>,
    pub drift: Arc<Drift>,
    policy_hash: Sha256Digest,
    cancel: FakeCancel,
    sandbox: FakeSandbox,
    runtime: FakeAgentRuntime,
    router: StaticModelRouter,
    registry: InMemoryAgentRegistry,
    broker: Arc<FakeModelBroker>,
    /// What the delivery stage reads to check the design again before it opens the pull request:
    /// the issue the job came from, a small change with the factory label and no design label.
    design: DesignWorld,
}

fn identity(pipeline: &Pipeline, kind: StageKind, n: u128) -> RunIdentity {
    RunIdentity {
        tenant: pipeline.rig.world.tenant,
        job: pipeline.rig.job,
        correlation: CorrelationId::from_uuid(uuid::Uuid::from_u128(0xC0)),
        stage_run: StageRunId::from_uuid(uuid::Uuid::from_u128(0x5100 + n)),
        kind,
    }
}

impl<'a> Delivery<'a> {
    /// The stages after the documentation review, over the repository of the pipeline.
    pub async fn over(pipeline: &'a Pipeline) -> Delivery<'a> {
        let rig = &pipeline.rig;
        let world = &rig.world;
        // The policy hash the engine resolved the validation contract with: the one in force.
        let validation = pipeline.find(StageKind::Validation, "validation-evidence");
        let row = world.stage_run(validation.run).await;
        let contract_ref = ArtifactRef {
            sha256: row.contract_sha256.expect("the engine stored the contract"),
            media_type: MediaType::parse("application/json").expect("a media type"),
            size_bytes: None,
        };
        let bytes = ArtifactStore::get(&*rig.artifacts, &pipeline.scope(), &contract_ref)
            .await
            .expect("the contract is stored");
        let contract = StageContract::from_json_str(std::str::from_utf8(&bytes).expect("UTF-8"))
            .expect("a valid contract");
        let policy_hash = contract
            .inputs
            .iter()
            .find(|input| input.name.as_str() == "policy-bundle")
            .expect("the policy bundle is an input")
            .artifact
            .sha256
            .clone();
        // The values the evidence is bound to, read from the evidence: nothing has changed.
        let binding = Binding::from_json(&validation.json()["binding"]).expect("a binding");
        let target = DeliveryTarget {
            repo: rig.repo.clone(),
            base: BranchName::new("main").expect("a branch"),
            head: BranchName::new("factory/job-1").expect("a branch"),
            issue: IssueRef {
                repo: rig.repo.clone(),
                number: 12,
            },
            risk: RiskFacts {
                single_module_change_without_sensitive_or_protected_paths: true,
                ..RiskFacts::default()
            },
            agent_claim: None,
            links: vec![DocLink {
                label: "Readme".to_owned(),
                path: RepoPath::new("README.md").expect("a path"),
            }],
        };
        let ledger = LedgerState {
            entry_count: 40,
            head_sequence: 40,
            head_hash: Sha256Digest::of(b"ledger head forty"),
            chain_verified_at: world.clock.now(),
            attained: vec![
                (
                    AssuranceLevel::VerifiedInSandbox,
                    LedgerEntryId::from_uuid(uuid::Uuid::from_u128(0x77)),
                ),
                (
                    AssuranceLevel::Specified,
                    LedgerEntryId::from_uuid(uuid::Uuid::from_u128(0x78)),
                ),
                (
                    AssuranceLevel::Implemented,
                    LedgerEntryId::from_uuid(uuid::Uuid::from_u128(0x79)),
                ),
            ],
            dispositions: Vec::new(),
        };
        let sources = Arc::new(Sources {
            target,
            values: CurrentValues {
                definition_hash: binding.definition_hash,
                image_digest: binding.image_digest,
            },
            ledger,
            tree: GitSha::parse(&"d".repeat(40)).expect("a tree"),
            trees_asked: Mutex::default(),
        });
        let design = DesignWorld::new();
        let now = world.clock.now();
        design
            .issues
            .fake()
            .put_issue(factory_ports::githost::Issue {
                reference: IssueRef {
                    repo: rig.repo.clone(),
                    number: 12,
                },
                title: "Add a --json flag".to_owned(),
                body: "Please let the word count tool print its counts as JSON.".to_owned(),
                author: person(REQUESTER_ID, "requester-one"),
                labels: vec![LABEL.to_owned()],
                updated_at: now,
                fetched_at: now,
            });
        Self {
            pipeline,
            sources,
            design,
            host: Arc::new(FakeChangeHost::sharing(rig.remote.clone())),
            drift: Arc::new(Drift::default()),
            policy_hash,
            cancel: FakeCancel::new(),
            sandbox: FakeSandbox::new(world.clock.clone(), rig.artifacts.clone(), sandbox_policy()),
            runtime: FakeAgentRuntime::new(rig.artifacts.clone()),
            router: StaticModelRouter::new(Vec::new()),
            registry: InMemoryAgentRegistry::new(),
            broker: Arc::new(FakeModelBroker::new(world.clock.clone(), world.ids.clone())),
        }
    }

    fn ports(&self) -> StagePorts<'_> {
        let rig = &self.pipeline.rig;
        StagePorts {
            artifacts: &*rig.artifacts,
            sandbox: &self.sandbox,
            workspaces: &*rig.provider,
            runtime: &self.runtime,
            router: &self.router,
            registry: &self.registry,
            validator: &AcceptAll,
            broker: &*self.broker,
            clock: &*rig.world.clock,
            ids: &*rig.world.ids,
        }
    }

    fn contract_context<'b>(
        &'b self,
        identity: RunIdentity,
        upstream: &'b [UpstreamRun],
    ) -> ContractContext<'b> {
        ContractContext {
            identity,
            mode: ExecutionMode::Test,
            policy_hash: &self.policy_hash,
            now: self.pipeline.rig.world.clock.now(),
            upstream,
            human_inputs: &[],
            request_edited: false,
        }
    }

    /// The delivery handler of the world, over the repository of the pipeline.
    pub fn delivery_handler(&self) -> DeliveryHandler {
        DeliveryHandler::new(
            Arc::new(DeliveryConfig {
                policy: policy_engine(),
                redactor: redactor(),
                definition_commit: GitSha::parse(&"e".repeat(40)).expect("a sha"),
                readability: ReadabilityGate::new(Options::new()),
                max_patch_bytes: 1_000_000,
            }),
            DeliveryDeps {
                host: self.host.clone(),
                sources: self.sources.clone(),
                drift: self.drift.clone(),
                recheck: DesignRecheck::new(
                    DesignJudge::new(
                        self.design.issues.clone(),
                        self.design.rule.clone(),
                        policy_engine(),
                        redactor(),
                    ),
                    self.design.people.clone(),
                    self.design.replies.clone(),
                    LABEL.to_owned(),
                ),
            },
        )
    }

    /// The approval handler.
    pub fn approval_handler(&self) -> ApprovalHandler {
        ApprovalHandler::new(
            Arc::new(ApprovalConfig {
                policy: policy_engine(),
                definition_commit: GitSha::parse(&"e".repeat(40)).expect("a sha"),
            }),
            ApprovalHandlerDeps {
                host: self.host.clone(),
                delivery: self.sources.clone(),
                approvals: Arc::new(Approvals),
                drift: self.drift.clone(),
            },
        )
    }

    /// The contract a stage resolves from these upstream runs.
    pub fn contract(
        &self,
        handler: &dyn StageHandler,
        kind: StageKind,
        upstream: &[UpstreamRun],
    ) -> Result<StageContract, StageError> {
        handler
            .contract(&self.contract_context(identity(self.pipeline, kind, kind as u128), upstream))
    }

    /// `execute`, then the engine's storing of the documents, then `evaluate` and `resolve`.
    pub async fn run(
        &self,
        handler: &dyn StageHandler,
        kind: StageKind,
        upstream: &[UpstreamRun],
    ) -> Result<Ran, StageError> {
        let rig = &self.pipeline.rig;
        let identity = identity(self.pipeline, kind, kind as u128);
        let contract = self.contract(handler, kind, upstream)?;
        let attempt = AttemptId::from_uuid(uuid::Uuid::from_u128(0xA7));
        let mut ctx = StageContext::new(
            identity,
            attempt,
            1,
            LeaseEpoch::NEVER_CLAIMED,
            ExecutionMode::Test,
            &contract,
            self.ports(),
            &self.cancel,
            None,
            &[],
            upstream,
        );
        let output = handler.execute(&mut ctx).await?;
        let mut stored: Vec<NamedArtifact> = Vec::new();
        for document in &output.documents {
            let artifact = rig
                .artifacts
                .put(
                    serde_json::to_vec(&document.value).expect("JSON"),
                    MediaType::parse("application/json").expect("a media type"),
                )
                .await
                .expect("the artifact is stored");
            stored.push(NamedArtifact {
                name: document.name.clone(),
                artifact,
            });
        }
        stored.extend(output.artifacts.iter().cloned());
        let gate = GateContext {
            identity,
            attempt,
            mode: ExecutionMode::Test,
            contract: &contract,
            ports: self.ports(),
            cancel: &self.cancel,
            outputs: &stored,
            human_inputs: &[],
            upstream,
        };
        let decision = handler.evaluate(&gate).await?;
        let resolution = resolve(&contract, &decision);
        let scope = TenantScope::new(rig.world.tenant);
        let mut outputs = Vec::new();
        for named in &stored {
            let bytes = ArtifactStore::get(&*rig.artifacts, &scope, &named.artifact)
                .await
                .expect("readable");
            outputs.push(Output {
                run: identity.stage_run,
                kind,
                name: named.name.as_str().to_owned(),
                artifact: named.artifact.clone(),
                bytes,
            });
        }
        Ok(Ran {
            outputs,
            decision,
            resolution,
        })
    }

    /// The upstream runs the delivery stage sees: the whole pipeline.
    pub fn upstream_of_delivery(&self) -> Vec<UpstreamRun> {
        self.pipeline.upstream()
    }

    /// The upstream runs the approval stage sees: the pipeline and the delivery run.
    pub fn upstream_of_approval(&self, delivered: &Ran) -> Vec<UpstreamRun> {
        let mut upstream = self.pipeline.upstream();
        upstream.push(UpstreamRun {
            id: delivered.outputs[0].run,
            kind: StageKind::Delivery,
            status: StageRunStatus::Passed,
            outputs: delivered
                .outputs
                .iter()
                .map(|output| NamedArtifact {
                    name: Slug::parse(&output.name).expect("a slug"),
                    artifact: output.artifact.clone(),
                })
                .collect(),
        });
        upstream
    }

    /// Replaces a deliverable of a stage run in `upstream` with the same document after `edit`
    /// changed it, as a producer that wrote it differently would have stored it.
    pub async fn edit(
        &self,
        upstream: &mut [UpstreamRun],
        kind: StageKind,
        name: &str,
        edit: impl FnOnce(&mut Value),
    ) {
        let rig = &self.pipeline.rig;
        let scope = TenantScope::new(rig.world.tenant);
        let slot = upstream
            .iter_mut()
            .rev()
            .filter(|run| run.kind == kind)
            .find_map(|run| run.outputs.iter_mut().find(|o| o.name.as_str() == name))
            .unwrap_or_else(|| panic!("{kind} has no deliverable {name}"));
        let bytes = ArtifactStore::get(&*rig.artifacts, &scope, &slot.artifact)
            .await
            .expect("readable");
        let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
        edit(&mut value);
        slot.artifact = rig
            .artifacts
            .put(
                serde_json::to_vec(&value).expect("JSON"),
                MediaType::parse("application/json").expect("a media type"),
            )
            .await
            .expect("stored");
    }

    /// The same deliverable, stored under another name.
    pub fn rename(upstream: &mut [UpstreamRun], kind: StageKind, from: &str, to: &str) {
        let slot = upstream
            .iter_mut()
            .filter(|run| run.kind == kind)
            .find_map(|run| run.outputs.iter_mut().find(|o| o.name.as_str() == from))
            .unwrap_or_else(|| panic!("{kind} has no deliverable {from}"));
        slot.name = Slug::parse(to).expect("a slug");
    }

    /// The code host the stages ran against.
    pub fn host(&self) -> &FakeChangeHost {
        &self.host
    }

    /// The commits whose tree the delivery stage asked for.
    pub fn trees_asked(&self) -> Vec<CommitSha> {
        self.sources.trees_asked.lock().expect("lock").clone()
    }
}
