//! The harness: in-memory ports, a fixture repository with a real commit made through the fake
//! workspace, the stored documents of the stages before delivery, and the whole stage run.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, StageContract, Violation};
use factory_domain::ids::{
    AttemptId, CorrelationId, GateReportId, JobId, LedgerEntryId, StageRunId, TenantId,
};
use factory_domain::policy::risk::RiskFacts;
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::redaction::{PatternAction, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{AssuranceLevel, ExecutionMode, Fidelity, StageKind};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::clock::Clock;
use factory_ports::githost::IssueRef;
use factory_ports::paths::{BranchName, CommitSha, RepoPath, RepoRef};
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use factory_ports::store::LeaseEpoch;
use factory_ports::workspace::{
    CommitRequest, FetchCredential, FetchTarget, WorkspaceProvider, WorkspacePurpose,
    WorkspaceRequest,
};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeCancel, FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::workspace::{TreeEdit, fixture_rules};
use factory_testkit::fixtures::{Ids, sandbox_policy};
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::gates::docs::plan::{
    Audience, Binding as PlanBinding, DocPlan, Form, Interface, Item, ItemKind, NotApplicable,
};
use factory_workflow::gates::framework::{
    EvidenceProblem, Expectation, GateDecision, Resolution, check_evidence, resolve,
};
use factory_workflow::gates::readability::{Options, ReadabilityGate};
use factory_workflow::handlers::{
    ContractContext, GateContext, NamedArtifact, RunIdentity, StageContext, StageError,
    StageHandler, StagePorts, UpstreamRun,
};
use factory_workflow::stages::delivery::seams::CurrentValues;
use factory_workflow::stages::delivery::{
    DeliveryConfig, DeliveryDeps, DeliveryHandler, DeliverySources, DeliveryTarget, EvidenceDrift,
    LedgerState, SeamError,
};
use factory_workflow::stages::documentation_review::{GateBinding, gate_document, gate_ids};
use factory_workflow::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};
use factory_workflow::stages::validation::{Binding, GATES};

use crate::spy::Spy;

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");
const SPECIFICATION: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);
const PLAN: &str =
    include_str!("../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
const VERDICT: &str = include_str!(
    "../../../../schemas/examples/review-verdict/valid/changes-required-missing-test.json"
);

pub const IMAGE: &str = "image-digest-one";
pub const DEFINITIONS: &str = "definitions-one";

/// Wraps an artifact store so that whatever is stored is readable by the test tenant.
pub struct Granting {
    inner: InMemoryArtifactStore,
    tenant: TenantId,
}

#[async_trait]
impl ArtifactStore for Granting {
    fn backend(&self) -> ArtifactBackend {
        self.inner.backend()
    }
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError> {
        let reference = self.inner.put(bytes, media_type).await?;
        self.inner.grant(self.tenant, &reference.sha256);
        Ok(reference)
    }
    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError> {
        self.inner.get(scope, reference).await
    }
    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        self.inner.exists(scope, reference).await
    }
}

/// Accepts every document.
pub struct AcceptAll;

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
        _instance: &serde_json::Value,
    ) -> Result<(), Vec<Violation>> {
        Ok(())
    }
}

/// The facts the composition root would read from the store.
pub struct Sources {
    pub target: Mutex<DeliveryTarget>,
    pub values: Mutex<CurrentValues>,
    pub ledger: Mutex<LedgerState>,
    pub tree: GitSha,
    /// The commits whose tree the stage asked for.
    pub trees_asked: Mutex<Vec<CommitSha>>,
    pub fidelity: Fidelity,
}

#[async_trait]
impl DeliverySources for Sources {
    fn fidelity(&self) -> Fidelity {
        self.fidelity
    }
    async fn target(&self, _run: &RunIdentity) -> Result<DeliveryTarget, SeamError> {
        Ok(self.target.lock().expect("lock").clone())
    }
    async fn current_values(
        &self,
        _run: &RunIdentity,
        _base: &CommitSha,
    ) -> Result<CurrentValues, SeamError> {
        Ok(self.values.lock().expect("lock").clone())
    }
    async fn ledger(&self, _run: &RunIdentity) -> Result<LedgerState, SeamError> {
        Ok(self.ledger.lock().expect("lock").clone())
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
    async fn binding_changed(&self, tenant: TenantId, job: JobId) -> Result<(), SeamError> {
        self.told.lock().expect("lock").push((tenant, job));
        Ok(())
    }
}

/// What the documenting stage left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Documentation {
    /// The writer committed a page on top of the code head.
    Committed,
    /// The plan is not applicable: nothing was written and the documentation head is the code head.
    NotApplicable,
}

/// What a test changes before the stage runs.
#[derive(Clone)]
pub struct Scenario {
    /// Gate id and outcome (`PASSED`, `FAILED` or `BLOCKED`) of the validation reports.
    pub gates: Vec<(String, &'static str)>,
    /// The title of the frozen specification.
    pub spec_title: Option<String>,
    /// The verdict of the review.
    pub verdict: &'static str,
    /// A deliverable an earlier stage did not produce.
    pub missing: Option<&'static str>,
    /// Gates that a person disposed of after they were blocked.
    pub dispositions: Vec<String>,
    /// The fidelity the sources report.
    pub sources_fidelity: Fidelity,
    /// What the factory measured about the change.
    pub risk: RiskFacts,
    /// Open warnings of the rule `translation-unfaithful` in the documentation gate report.
    pub translation_warnings: u32,
    /// What the documenting stage did.
    pub documentation: Documentation,
    /// The status the frozen specification carries. `None` leaves the fixture's own (approved).
    pub spec_status: Option<&'static str>,
    /// The verdict of the documentation review.
    pub documentation_verdict: &'static str,
    /// The outcome of every report of the documentation gate (`PASSED`, `FAILED` or `BLOCKED`).
    pub documentation_outcome: &'static str,
    /// What the documentation reviewer's verdict says it read.
    pub documentation_review: ReviewBinding,
}

/// A review verdict that is valid and is not a pass: the example of a review that asks for
/// changes, with its finding.
pub fn changes_required_review() -> serde_json::Value {
    serde_json::from_str(VERDICT).expect("a verdict")
}

/// What the documentation reviewer's verdict says it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewBinding {
    /// Exactly the stored reports and the frozen specification.
    Reports,
    /// Reports that are not the stored ones.
    OtherReports,
    /// Another specification.
    OtherSpecification,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            gates: GATES
                .iter()
                .map(|(gate, _)| ((*gate).to_owned(), "PASSED"))
                .collect(),
            spec_title: None,
            verdict: "PASS",
            missing: None,
            dispositions: Vec::new(),
            sources_fidelity: Fidelity::Real,
            risk: RiskFacts {
                single_module_change_without_sensitive_or_protected_paths: true,
                ..RiskFacts::default()
            },
            translation_warnings: 0,
            documentation: Documentation::Committed,
            spec_status: None,
            documentation_verdict: "PASS",
            documentation_outcome: "PASSED",
            documentation_review: ReviewBinding::Reports,
        }
    }
}

/// One whole run of the stage: what `execute` stored and what `evaluate` handed the engine.
pub struct Ran {
    pub outputs: Vec<NamedArtifact>,
    pub result: serde_json::Value,
    pub manifest: serde_json::Value,
    pub decision: GateDecision,
    pub resolution: Resolution,
    pub problem: Option<EvidenceProblem>,
}

impl Ran {
    pub fn report(&self, gate: &str) -> &GateReport {
        self.decision
            .reports
            .iter()
            .find(|report| report.metadata.gate_id.as_str() == gate)
            .unwrap_or_else(|| panic!("no report for {gate}"))
    }
}

pub struct World {
    pub clock: Arc<FakeClock>,
    pub ids: Arc<SequentialIdGenerator>,
    pub fixture: Ids,
    pub artifacts: Arc<Granting>,
    pub remote: FakeRemote,
    pub workspaces: Arc<FakeWorkspaceProvider>,
    pub host: Arc<Spy>,
    pub sources: Arc<Sources>,
    pub drift: Arc<Drift>,
    pub cancel: FakeCancel,
    pub tenant: TenantId,
    pub job: JobId,
    pub stage_run: StageRunId,
    pub attempt: AttemptId,
    pub correlation: CorrelationId,
    pub repo: RepoRef,
    pub base: BranchName,
    pub policy: Arc<PolicyEngine>,
    pub redactor: Arc<Redactor>,
    pub policy_hash: Sha256Digest,
    pub scenario: Scenario,
    /// The policy hash the contract is resolved with, when a test changes the policy.
    pub contract_policy: Mutex<Option<Sha256Digest>>,
    /// The commit the documenting stage made on top of the code head, once `commits` has run.
    pub documented: Mutex<Option<CommitSha>>,
    runtime: FakeAgentRuntime,
    router: StaticModelRouter,
    registry: InMemoryAgentRegistry,
    broker: Arc<FakeModelBroker>,
    sandbox: FakeSandbox,
}

impl World {
    pub fn new() -> Self {
        Self::with(Scenario::default())
    }

    pub fn with(scenario: Scenario) -> Self {
        let fixture = Ids::new();
        let tenant = fixture.tenant();
        let clock = Arc::new(FakeClock::new());
        let ids = Arc::new(SequentialIdGenerator::new());
        let artifacts = Arc::new(Granting {
            inner: InMemoryArtifactStore::new(),
            tenant,
        });
        let repo = RepoRef::parse("example-org/word-count").expect("a repository");
        let base = BranchName::new("main").expect("a branch");
        let head = BranchName::new("factory/job-1").expect("a branch");
        let remote = FakeRemote::new();
        let workspaces = Arc::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            artifacts.clone(),
            fixture_rules(),
        ));
        let host = Arc::new(Spy::new(FakeChangeHost::sharing(remote.clone())));
        let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("security policy");
        let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("approval policy");
        let policy = Arc::new(PolicyEngine::new(&security, &approval).expect("a policy engine"));
        let redactor = Arc::new(
            Redactor::builder()
                .pattern("canary", "tok_[A-Za-z0-9]{20}", PatternAction::Block)
                .pattern("github-token", "ghp_[A-Za-z0-9]{36}", PatternAction::Block)
                .build()
                .expect("a redactor"),
        );
        let target = DeliveryTarget {
            repo: repo.clone(),
            base: base.clone(),
            head: head.clone(),
            issue: IssueRef {
                repo: repo.clone(),
                number: 12,
            },
            risk: scenario.risk,
            links: vec![
                factory_workflow::stages::delivery::DocLink {
                    label: "Architecture decision".to_owned(),
                    path: RepoPath::new("docs/adr/0001-json-output.md").expect("a path"),
                },
                factory_workflow::stages::delivery::DocLink {
                    label: "Task plan".to_owned(),
                    path: RepoPath::new("specs/001-json/tasks.md").expect("a path"),
                },
            ],
        };
        let ledger = LedgerState {
            entry_count: 40,
            head_sequence: 40,
            head_hash: Sha256Digest::of(b"ledger head forty"),
            chain_verified_at: clock.now(),
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
            dispositions: scenario
                .dispositions
                .iter()
                .map(|gate| {
                    (
                        Slug::parse(gate).expect("a gate id"),
                        LedgerEntryId::from_uuid(uuid::Uuid::from_u128(0x99)),
                    )
                })
                .collect(),
        };
        let sources = Arc::new(Sources {
            target: Mutex::new(target),
            values: Mutex::new(CurrentValues {
                definition_hash: Sha256Digest::of(DEFINITIONS.as_bytes()),
                image_digest: Sha256Digest::of(IMAGE.as_bytes()),
            }),
            ledger: Mutex::new(ledger),
            tree: GitSha::parse(&"d".repeat(40)).expect("a tree"),
            trees_asked: Mutex::default(),
            fidelity: scenario.sources_fidelity,
        });
        Self {
            runtime: FakeAgentRuntime::new(artifacts.clone()),
            router: StaticModelRouter::new(Vec::new()),
            registry: InMemoryAgentRegistry::new(),
            broker: Arc::new(FakeModelBroker::new(clock.clone(), ids.clone())),
            sandbox: FakeSandbox::new(clock.clone(), artifacts.clone(), sandbox_policy()),
            job: fixture.job(),
            stage_run: fixture.stage_run(),
            attempt: fixture.attempt(),
            correlation: fixture.correlation(),
            policy_hash: Sha256Digest::of(b"policy bundle one"),
            clock,
            ids,
            fixture,
            artifacts,
            remote,
            workspaces,
            host,
            sources,
            drift: Arc::new(Drift::default()),
            cancel: FakeCancel::new(),
            tenant,
            repo,
            base,
            policy,
            redactor,
            scenario,
            contract_policy: Mutex::default(),
            documented: Mutex::default(),
        }
    }

    /// Puts the base commit on the remote and fetches it into the job's store, then makes one
    /// commit on top of it through a workspace, as the implementation stage does.
    pub async fn commits(&self) -> (CommitSha, CommitSha) {
        self.remote.commit_on_branch(
            &self.repo,
            &self.base,
            &[
                ("README.md", "# Word count\n"),
                ("src/lib.rs", "pub fn one() {}\n"),
            ],
        );
        let fetched = self
            .workspaces
            .fetch(
                self.job,
                &FetchTarget {
                    repo: self.repo.clone(),
                    credential: FetchCredential::new("read-token-for-tests".to_owned()),
                },
                &self.base,
                &self.cancel,
            )
            .await
            .expect("the fetch works");
        let workspace = self
            .workspaces
            .create(
                WorkspaceRequest {
                    job: self.job,
                    attempt: self.attempt,
                    base: fetched.commit.clone(),
                    rules: fixture_rules(),
                    purpose: WorkspacePurpose::Agent,
                },
                &self.cancel,
            )
            .await
            .expect("a workspace");
        let dir = workspace.mounts().workspace;
        self.workspaces
            .edit_tree(
                &dir,
                TreeEdit::Write(
                    RepoPath::new("src/lib.rs").expect("a path"),
                    b"pub fn one() {}\npub fn two() {}\n".to_vec(),
                ),
            )
            .expect("an edit");
        let change = workspace.ingest(&self.cancel).await.expect("ingest");
        let head = workspace
            .commit(
                &change,
                CommitRequest {
                    message: "Add two".to_owned(),
                    author_name: "Software Factory".to_owned(),
                    author_email: "factory@example.test".to_owned(),
                },
            )
            .await
            .expect("a commit");
        workspace.dispose().await.expect("dispose");
        if self.scenario.documentation == Documentation::Committed {
            let documented = self.document(&head).await;
            *self.documented.lock().expect("lock") = Some(documented);
        }
        (fetched.commit, head)
    }

    /// One commit on top of `code_head` that adds a page under `docs`, made the way the
    /// documenting stage makes its own: through a workspace, after the audit.
    pub async fn document(&self, code_head: &CommitSha) -> CommitSha {
        let workspace = self
            .workspaces
            .create(
                WorkspaceRequest {
                    job: self.job,
                    attempt: self.attempt,
                    base: code_head.clone(),
                    rules: fixture_rules(),
                    purpose: WorkspacePurpose::Agent,
                },
                &self.cancel,
            )
            .await
            .expect("a workspace");
        self.workspaces
            .edit_tree(
                &workspace.mounts().workspace,
                TreeEdit::Write(
                    RepoPath::new("docs/guide.md").expect("a path"),
                    b"# Guide\n\nCall two to add the second number.\n".to_vec(),
                ),
            )
            .expect("an edit");
        let change = workspace.ingest(&self.cancel).await.expect("ingest");
        let head = workspace
            .commit(
                &change,
                CommitRequest {
                    message: "Document the change".to_owned(),
                    author_name: "Software Factory".to_owned(),
                    author_email: "factory@example.test".to_owned(),
                },
            )
            .await
            .expect("a commit");
        workspace.dispose().await.expect("dispose");
        head
    }

    pub async fn store_json(&self, value: &serde_json::Value) -> ArtifactRef {
        self.artifacts
            .put(
                serde_json::to_vec(value).expect("JSON"),
                MediaType::parse("application/json").expect("a media type"),
            )
            .await
            .expect("the artifact is stored")
    }

    pub fn report(&self, gate: &'static str, outcome: &'static str) -> GateReport {
        let now = self.clock.now();
        gate_report(
            &GateSubject {
                job: self.job,
                stage_run: self.fixture.stage_run(),
                attempt: self.attempt,
                mode: ExecutionMode::Test,
                report_id: GateReportId::from_uuid(uuid::Uuid::from_u128(
                    0x1000 + u128::from(self.ids_next()),
                )),
                started_at: now,
                finished_at: now,
            },
            &GateFacts {
                definition: GateDefinition {
                    id: gate,
                    version: "1.0.0",
                    text: "a gate definition used by the tests",
                    commit: GitSha::parse(&"e".repeat(40)).expect("a sha"),
                },
                outcome,
                title: "A gate of the validation stage".to_owned(),
                reason: "The gate ran in the test world.".to_owned(),
                failures: if outcome == "FAILED" {
                    vec![("check-failed".to_owned(), "The check failed.".to_owned())]
                } else {
                    Vec::new()
                },
                blocked: (outcome == "BLOCKED")
                    .then(|| ("tool_unavailable", "a tool the gate needs".to_owned())),
                fidelity: "real",
                executor: Executor::InProcess,
                commands: Vec::new(),
                tools: vec![("factory-test-gate".to_owned(), "1.0.0".to_owned())],
                evidence: vec![format!("{gate}={outcome}")],
            },
        )
        .expect("a gate report")
    }

    fn ids_next(&self) -> u32 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    /// The upstream runs a delivery stage run sees, with every document the stage reads.
    pub async fn upstream(&self, base: &CommitSha, head: &CommitSha) -> Vec<UpstreamRun> {
        let mut runs: Vec<UpstreamRun> = Vec::new();
        let result = self
            .store_json(&serde_json::json!({
                "base_commit": base.as_str(),
                "head_commit": head.as_str(),
            }))
            .await;

        let mut spec: serde_json::Value = serde_json::from_str(SPECIFICATION).expect("a spec");
        if let Some(title) = &self.scenario.spec_title {
            spec["title"] = serde_json::json!(title);
        }
        if let Some(status) = self.scenario.spec_status {
            spec["metadata"]["status"] = serde_json::json!(status);
        }
        let spec = self.store_json(&spec).await;
        let plan: serde_json::Value = serde_json::from_str(PLAN).expect("a plan");
        let plan = self.store_json(&plan).await;

        let mut verdict: serde_json::Value = serde_json::from_str(VERDICT).expect("a verdict");
        verdict["verdict"] = serde_json::json!(self.scenario.verdict);
        verdict["findings"] = serde_json::json!([]);
        verdict
            .as_object_mut()
            .expect("object")
            .remove("human_question");
        let verdict = self.store_json(&verdict).await;

        let reports: Vec<serde_json::Value> = self
            .scenario
            .gates
            .iter()
            .map(|(gate, outcome)| {
                let id: &'static str = Box::leak(gate.clone().into_boxed_str());
                self.report(id, outcome)
                    .to_json_value()
                    .expect("a report is JSON")
            })
            .collect();
        let binding = Binding {
            implementation_result: result.sha256.clone(),
            base_commit: GitSha::parse(base.as_str()).expect("a sha"),
            head_commit: GitSha::parse(head.as_str()).expect("a sha"),
            policy_hash: self.policy_hash.clone(),
            image_digest: Sha256Digest::of(IMAGE.as_bytes()),
            definition_hash: Sha256Digest::of(DEFINITIONS.as_bytes()),
        };
        let evidence = self
            .store_json(&serde_json::json!({
                "kind": "validation-evidence",
                "binding": binding.to_json(),
                "policy_violation": false,
                "reports": reports,
            }))
            .await;
        let blob = |text: &str| serde_json::json!({ "document": text });
        let architecture = self.store_json(&blob("architecture")).await;
        let documented = self.documented.lock().expect("lock").clone();
        let documentation = self
            .store_json(&documentation_plan(
                base,
                head,
                &spec.sha256,
                documented.is_some(),
            ))
            .await;
        let documentation_result = self
            .store_json(&documentation_result(
                base,
                head,
                documented.as_ref().unwrap_or(head),
            ))
            .await;
        // The document the documentation review stage stores, written by that stage's own
        // function: every gate of the stage has a report, and the document says which commits and
        // which plan the reports are about.
        let docs_head = documented.as_ref().unwrap_or(head);
        let mut documentation_reports: Vec<serde_json::Value> = gate_ids()
            .into_iter()
            .map(|gate| {
                self.report(gate, self.scenario.documentation_outcome)
                    .to_json_value()
                    .expect("a report is JSON")
            })
            .collect();
        if self.scenario.translation_warnings > 0 {
            documentation_reports[0]["warnings"] = serde_json::json!(
                (0..self.scenario.translation_warnings)
                    .map(|n| serde_json::json!({
                        "check_id": "translation-unfaithful",
                        "message": format!("The English text may not say what the original says, case {n}."),
                        "suggested_fix": "Ask the requester to read the English text and confirm it.",
                    }))
                    .collect::<Vec<_>>()
            );
        }
        let documentation_gate = self
            .store_json(&gate_document(
                &GateBinding {
                    base_commit: base,
                    code_head: head,
                    documentation_head: docs_head,
                    plan_sha256: &documentation.sha256,
                    specification_sha256: &spec.sha256,
                },
                Some("sandbox-1"),
                0,
                &documentation_reports,
            ))
            .await;
        // The documentation reviewer's verdict names the reports it read by identifier and by the
        // hash of the stored report, and the frozen specification by its hash.
        let mut review: serde_json::Value = serde_json::from_str(VERDICT).expect("a verdict");
        if self.scenario.documentation_verdict == "PASS" {
            review["verdict"] = serde_json::json!("PASS");
            review["findings"] = serde_json::json!([]);
            review
                .as_object_mut()
                .expect("object")
                .remove("human_question");
        }
        let read: Vec<serde_json::Value> = match self.scenario.documentation_review {
            ReviewBinding::OtherReports => vec![serde_json::json!({
                "gate_report_id": "018f3a80-1c22-7a44-9b55-6c7d8e9fa0b3",
                "sha256": Sha256Digest::of(b"some other report"),
            })],
            _ => documentation_reports
                .iter()
                .map(|value| {
                    serde_json::json!({
                        "gate_report_id": value["metadata"]["gate_report_id"],
                        "sha256": Sha256Digest::of(&serde_json::to_vec(value).expect("JSON")),
                    })
                })
                .collect(),
        };
        review["inputs_reviewed"]["gate_reports"] = serde_json::Value::Array(read);
        review["inputs_reviewed"]["frozen_spec_sha256"] =
            if self.scenario.documentation_review == ReviewBinding::OtherSpecification {
                serde_json::json!(Sha256Digest::of(b"another specification"))
            } else {
                serde_json::json!(spec.sha256)
            };
        let documentation_review = self.store_json(&review).await;

        let mut add = |kind: StageKind, name: &'static str, artifact: ArtifactRef| {
            if self.scenario.missing == Some(name) {
                return;
            }
            runs.push(UpstreamRun {
                id: self.fixture.stage_run(),
                kind,
                status: StageRunStatus::Passed,
                outputs: vec![NamedArtifact {
                    name: Slug::parse(name).expect("a slug"),
                    artifact,
                }],
            });
        };
        add(StageKind::Specification, "specification-contract", spec);
        add(StageKind::Architecture, "architecture-design", architecture);
        add(StageKind::TaskPlanning, "task-plan", plan);
        add(StageKind::Implementation, "implementation-result", result);
        add(StageKind::Validation, "validation-evidence", evidence);
        add(StageKind::Review, "review-verdict", verdict);
        add(StageKind::Documenting, "documentation-plan", documentation);
        add(
            StageKind::Documenting,
            "documentation-result",
            documentation_result,
        );
        add(
            StageKind::DocumentationReview,
            "documentation-gate-report",
            documentation_gate,
        );
        add(
            StageKind::DocumentationReview,
            "documentation-review",
            documentation_review,
        );
        runs
    }

    pub fn config(&self) -> DeliveryConfig {
        DeliveryConfig {
            policy: self.policy.clone(),
            redactor: self.redactor.clone(),
            definition_commit: GitSha::parse(&"e".repeat(40)).expect("a sha"),
            readability: ReadabilityGate::new(Options::new()),
            max_patch_bytes: 1_000_000,
        }
    }

    pub fn handler(&self) -> DeliveryHandler {
        DeliveryHandler::new(
            Arc::new(self.config()),
            DeliveryDeps {
                host: self.host.clone(),
                sources: self.sources.clone(),
                drift: self.drift.clone(),
            },
        )
    }

    pub fn ports(&self) -> StagePorts<'_> {
        StagePorts {
            artifacts: &*self.artifacts,
            sandbox: &self.sandbox,
            workspaces: &*self.workspaces,
            runtime: &self.runtime,
            router: &self.router,
            registry: &self.registry,
            validator: &AcceptAll,
            broker: &*self.broker,
            clock: &*self.clock,
            ids: &*self.ids,
        }
    }

    pub fn identity(&self) -> RunIdentity {
        RunIdentity {
            tenant: self.tenant,
            job: self.job,
            correlation: self.correlation,
            stage_run: self.stage_run,
            kind: StageKind::Delivery,
        }
    }

    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    pub fn resolve_contract(
        &self,
        handler: &DeliveryHandler,
        upstream: &[UpstreamRun],
    ) -> Result<StageContract, StageError> {
        let policy = self
            .contract_policy
            .lock()
            .expect("lock")
            .clone()
            .unwrap_or_else(|| self.policy_hash.clone());
        handler.contract(&ContractContext {
            identity: self.identity(),
            mode: ExecutionMode::Test,
            policy_hash: &policy,
            now: self.now(),
            upstream,
            human_inputs: &[],
            request_edited: false,
        })
    }

    /// `execute`, and the storing of its documents the way the engine does it.
    pub async fn execute(
        &self,
        handler: &DeliveryHandler,
        contract: &StageContract,
        upstream: &[UpstreamRun],
    ) -> Result<Vec<NamedArtifact>, StageError> {
        let mut ctx = StageContext::new(
            self.identity(),
            self.attempt,
            1,
            LeaseEpoch::NEVER_CLAIMED,
            ExecutionMode::Test,
            contract,
            self.ports(),
            &self.cancel,
            None,
            &[],
            upstream,
        );
        let output = handler.execute(&mut ctx).await?;
        let mut stored = Vec::new();
        for document in &output.documents {
            stored.push(NamedArtifact {
                name: document.name.clone(),
                artifact: self.store_json(&document.value).await,
            });
        }
        stored.extend(output.artifacts.iter().cloned());
        Ok(stored)
    }

    pub async fn read_output(&self, outputs: &[NamedArtifact], name: &str) -> serde_json::Value {
        let stored = outputs
            .iter()
            .find(|output| output.name.as_str() == name)
            .unwrap_or_else(|| panic!("no output {name}"));
        let bytes = self
            .artifacts
            .get(&TenantScope::new(self.tenant), &stored.artifact)
            .await
            .expect("readable");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    /// Changes a stored deliverable of an earlier stage: reads it, lets `edit` change it, stores
    /// the result and points the upstream run at the new document.
    pub async fn edit_upstream(
        &self,
        upstream: &mut [UpstreamRun],
        kind: StageKind,
        name: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) {
        let slot = upstream
            .iter_mut()
            .rev()
            .filter(|run| run.kind == kind)
            .find_map(|run| run.outputs.iter_mut().find(|o| o.name.as_str() == name))
            .unwrap_or_else(|| panic!("no output {name}"));
        let bytes = self
            .artifacts
            .get(&TenantScope::new(self.tenant), &slot.artifact)
            .await
            .expect("readable");
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        edit(&mut value);
        slot.artifact = self.store_json(&value).await;
    }

    /// `evaluate`, the engine's evidence check and `resolve`.
    pub async fn evaluate(
        &self,
        handler: &DeliveryHandler,
        contract: &StageContract,
        outputs: &[NamedArtifact],
        upstream: &[UpstreamRun],
    ) -> Result<Ran, StageError> {
        let gate = GateContext {
            identity: self.identity(),
            attempt: self.attempt,
            mode: ExecutionMode::Test,
            contract,
            ports: self.ports(),
            cancel: &self.cancel,
            outputs,
            human_inputs: &[],
            upstream,
        };
        let decision = handler.evaluate(&gate).await?;
        let problem = check_evidence(
            &decision,
            &Expectation {
                job: self.job,
                stage_run: self.stage_run,
                attempt: self.attempt,
                mode: ExecutionMode::Test,
            },
        )
        .err();
        let resolution = resolve(contract, &decision);
        Ok(Ran {
            outputs: outputs.to_vec(),
            result: self.read_output(outputs, "delivery-result").await,
            manifest: self.read_output(outputs, "evidence-manifest").await,
            decision,
            resolution,
            problem,
        })
    }

    /// The whole stage run with the world's own handler, on a fresh pair of commits.
    pub async fn run(&self) -> Ran {
        let (base, head) = self.commits().await;
        self.run_on(&base, &head).await
    }

    pub async fn run_on(&self, base: &CommitSha, head: &CommitSha) -> Ran {
        let handler = self.handler();
        let upstream = self.upstream(base, head).await;
        let contract = self
            .resolve_contract(&handler, &upstream)
            .expect("the contract resolves");
        let outputs = self
            .execute(&handler, &contract, &upstream)
            .await
            .expect("execute works");
        self.evaluate(&handler, &contract, &outputs, &upstream)
            .await
            .expect("evaluate works")
    }
}

/// The plan the documenting stage stores, as it writes it.
fn documentation_plan(
    base: &CommitSha,
    code_head: &CommitSha,
    specification: &Sha256Digest,
    applicable: bool,
) -> serde_json::Value {
    let binding = PlanBinding {
        base_commit: base.as_str().to_owned(),
        code_head: code_head.as_str().to_owned(),
        specification_sha256: specification.to_string(),
    };
    let item = Item {
        id: "update-guide".to_owned(),
        kind: ItemKind::Usage,
        page: "docs/guide.md".to_owned(),
        form: Form::HowTo,
        audience: vec![Audience::Developers],
        sources: vec!["src/lib.rs".to_owned()],
        terms: vec!["two".to_owned()],
        acceptance: vec!["The page says what the new function does.".to_owned()],
    };
    DocPlan {
        binding,
        change_types: Vec::new(),
        interface: Interface::default(),
        program: None,
        breaking: false,
        items: if applicable { vec![item] } else { Vec::new() },
        not_applicable: (!applicable).then(|| NotApplicable {
            rule: "no-user-visible-change".to_owned(),
            reason: "The change adds no interface that a reader sees.".to_owned(),
        }),
    }
    .to_json()
}

/// The result the documenting stage stores. `head` is the code head when it committed nothing.
fn documentation_result(
    base: &CommitSha,
    code_head: &CommitSha,
    head: &CommitSha,
) -> serde_json::Value {
    let committed = head != code_head;
    serde_json::json!({
        "schema_version": 1,
        "kind": "documentation-result",
        "base_commit": base.as_str(),
        "code_head": code_head.as_str(),
        "head_commit": head.as_str(),
        "writer_ran": committed,
        "changes": if committed {
            serde_json::json!([{ "path": "docs/guide.md", "kind": "added" }])
        } else {
            serde_json::json!([])
        },
        "additions": if committed { 3 } else { 0 },
        "deletions": 0,
        "reported": {
            "claims": [],
            "plan_coverage": [],
            "files_written": [],
            "ignored_instructions": [],
        },
        "unresolved_claims": [],
        "refusal": null,
        "out_of_scope": [],
        "spent": { "input_tokens": 0, "output_tokens": 0, "cost_micro_usd": 0, "requests": 0 },
        "fake": true,
    })
}

/// A secret-shaped text built at run time, so that no source file holds one.
pub fn canary() -> String {
    format!("{}{}", "tok_", "A1b2C3d4E5f6G7h8I9j0")
}
