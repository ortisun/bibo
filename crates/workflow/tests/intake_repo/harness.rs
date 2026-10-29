//! The rig: a test engine over the labelled fakes, with the two real handlers registered.
//!
//! `World` (shared with the engine tests) supplies the store, the clock, the broker, the router and
//! the principals. The rig replaces what the stages need to be real handlers: the registry holds
//! the real manifest and prompt of the intake classifier, the runtime is a handle the test can
//! script and read back, and the workspace provider and the sandbox are the fakes over which the
//! repository stage reads and builds the fixture.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{AgentManifest, SchemaRef, Violation};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::approval::ApprovalPolicy;
use factory_domain::policy::authority::{Allowlist, AllowlistEntry};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::{PolicyEngine, SecurityPolicy};
use factory_domain::redaction::{EntropySpec, PatternAction, PatternSpec, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, Sha256Digest, Uri};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{BrokerEndpoint, JobTokenRef, ProbedCapabilities};
use factory_ports::githost::{ActorLogin, GithubActor, IssueRef};
use factory_ports::paths::RepoRef;
use factory_ports::registry::ValidatedOutput;
use factory_ports::sandbox::{SandboxProfile, SandboxSpec};
use factory_ports::store::{NewOriginalRequest, RequestSource as StoreRequestSource, Store};
use factory_testkit::agent::{AdversarialScript, FakeAgentRuntime};
use factory_testkit::contracts::githost::IssueSourceSubject;
use factory_testkit::fixtures::{Ids, sandbox_spec};
use factory_testkit::githost::FakeIssueSource;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::probed;
use factory_workflow::engine::{AttemptOutcome, Engine};
use factory_workflow::handlers::HandlerRegistry;
use factory_workflow::scheduler::ClaimedAttempt;
use factory_workflow::stages::intake::{
    AgentOutputCheck, AgentSandboxSpecs, AllowlistSource, CapabilityProbes, FetchedRequest,
    IntakeConfig, IntakeDeps, IntakeHandler, IntakeRules, RecordedRequest, RequestSnapshot,
    RequestSource, SeamError,
};
use serde_json::{Value, json};

use crate::repo_rig::{
    CargoBehavior, FixedRepository, JsonManifests, Reads, RecordingWorkspaces, TestVerifySpecs,
    publish, rules as repo_rules, word_count,
};
use crate::support::world::World;
use factory_ports::paths::CommitSha;
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::stages::repo_intel::{RepoIntelConfig, RepoIntelDeps, RepoIntelHandler};

const SECURITY_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");
const CLASSIFIER_MANIFEST: &str =
    include_str!("../../../../agents/intake-classifier/manifest.json");
const CLASSIFIER_PROMPT: &str = include_str!("../../../../agents/intake-classifier/prompt.md");

/// The numeric id of the principal the world calls the requester, and of the allowlisted person.
pub const REQUESTER_ID: u64 = 1001;
/// The label that asks the factory to work.
pub const LABEL: &str = "factory";

pub fn security_policy() -> SecurityPolicy {
    serde_json::from_str(SECURITY_POLICY).expect("the security policy fixture is valid")
}

pub fn policy_engine() -> Arc<PolicyEngine> {
    let approval: ApprovalPolicy =
        serde_json::from_str(APPROVAL_POLICY).expect("the approval policy fixture is valid");
    Arc::new(PolicyEngine::new(&security_policy(), &approval).expect("the policies build"))
}

pub fn redactor() -> Arc<Redactor> {
    let policy = security_policy();
    let patterns = policy.secrets.patterns.iter().map(|p| {
        let action = match p.action {
            factory_domain::policy::security::SecretAction::Block => PatternAction::Block,
            factory_domain::policy::security::SecretAction::Flag => PatternAction::Flag,
        };
        PatternSpec::new(p.id.clone(), p.regex.0.clone(), action)
    });
    Arc::new(
        Redactor::builder()
            .patterns(patterns)
            .entropy(EntropySpec {
                min_length: 32,
                min_bits_per_char: 4.2,
                action: PatternAction::Flag,
            })
            .build()
            .expect("the policy patterns compile"),
    )
}

pub fn classifier_manifest() -> AgentManifest {
    serde_json::from_str(CLASSIFIER_MANIFEST).expect("the real manifest is valid")
}

pub fn definition_commit() -> GitSha {
    GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4").expect("a commit")
}

// ---- the seams, over the store and fixed lists -----------------------------------------------

/// The original requests of the rig: written to the store, and mirrored in memory for the one
/// answer that `contract` must give without waiting.
pub struct StoreRequests {
    store: Arc<factory_testkit::store::InMemoryStore>,
    ids: Arc<dyn factory_ports::clock::IdGenerator>,
    mirror: Mutex<BTreeMap<JobId, (u32, Sha256Digest)>>,
    issues: Mutex<BTreeMap<JobId, IssueRef>>,
    /// Jobs that a webhook created and that have no text yet.
    waiting: Mutex<BTreeMap<JobId, IssueRef>>,
    corrupt: Mutex<bool>,
}

impl StoreRequests {
    fn new(
        store: Arc<factory_testkit::store::InMemoryStore>,
        ids: Arc<dyn factory_ports::clock::IdGenerator>,
    ) -> Self {
        Self {
            store,
            ids,
            mirror: Mutex::new(BTreeMap::new()),
            issues: Mutex::new(BTreeMap::new()),
            waiting: Mutex::new(BTreeMap::new()),
            corrupt: Mutex::new(false),
        }
    }

    /// Says that `job` came from a webhook for `issue` and has no text yet.
    pub fn await_issue(&self, job: JobId, issue: IssueRef) {
        self.waiting.lock().expect("lock").insert(job, issue);
    }

    /// Makes `latest` return text that no longer has its hash, as a damaged store would.
    pub fn corrupt_next_reads(&self) {
        *self.corrupt.lock().expect("lock") = true;
    }
}

#[async_trait]
impl RequestSource for StoreRequests {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn recorded(&self, job: JobId) -> Option<RecordedRequest> {
        self.mirror
            .lock()
            .expect("lock")
            .get(&job)
            .map(|(revision, sha256)| RecordedRequest {
                revision: *revision,
                sha256: sha256.clone(),
            })
    }

    fn awaiting(&self, job: JobId) -> Option<IssueRef> {
        if self.mirror.lock().expect("lock").contains_key(&job) {
            return None;
        }
        self.waiting.lock().expect("lock").get(&job).cloned()
    }

    async fn record_first(
        &self,
        tenant: TenantId,
        job: JobId,
        request: FetchedRequest,
    ) -> Result<RequestSnapshot, SeamError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| SeamError::Unavailable)?;
        let stored = tx
            .record_original_request(NewOriginalRequest {
                id: self.ids.new_uuid(),
                job,
                revision: 1,
                source: StoreRequestSource::GithubIssue,
                source_ref: Some(format!(
                    "{}/{}#{}",
                    request.issue.repo.owner(),
                    request.issue.repo.name(),
                    request.issue.number
                )),
                author_github_user_id: Some(request.author),
                text: request.text.clone(),
            })
            .await
            .map_err(|_| SeamError::Unavailable)?;
        tx.commit().await.map_err(|_| SeamError::Unavailable)?;
        let sha256 = stored.row.value.content_sha256.clone();
        self.mirror
            .lock()
            .expect("lock")
            .insert(job, (1, sha256.clone()));
        self.issues
            .lock()
            .expect("lock")
            .insert(job, request.issue.clone());
        Ok(RequestSnapshot {
            revision: 1,
            text: request.text,
            sha256,
            author: Some(request.author),
            issue: request.issue,
        })
    }

    async fn latest(&self, tenant: TenantId, job: JobId) -> Result<RequestSnapshot, SeamError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| SeamError::Unavailable)?;
        let found = tx.get_original_request(job, None).await;
        tx.rollback().await.map_err(|_| SeamError::Unavailable)?;
        let row = found.map_err(|_| SeamError::NotFound)?;
        let issue = self
            .issues
            .lock()
            .expect("lock")
            .get(&job)
            .cloned()
            .ok_or(SeamError::NotFound)?;
        let mut text = row.text;
        if *self.corrupt.lock().expect("lock") {
            text.push_str(" (changed behind the store)");
        }
        Ok(RequestSnapshot {
            revision: row.revision,
            text,
            sha256: row.content_sha256,
            author: row.author_github_user_id,
            issue,
        })
    }
}

/// The allowlist of the protected configuration, as a list the test edits.
pub struct FixedAllowlist {
    tenant: TenantId,
    people: Mutex<Vec<(u64, &'static str, Vec<Designation>)>>,
    unreadable: Mutex<bool>,
}

impl FixedAllowlist {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            people: Mutex::new(vec![(
                REQUESTER_ID,
                "requester-one",
                vec![Designation::Requester],
            )]),
            unreadable: Mutex::new(false),
        }
    }

    /// Takes a person off the list.
    pub fn remove(&self, id: u64) {
        self.people
            .lock()
            .expect("lock")
            .retain(|(i, _, _)| *i != id);
    }

    /// Puts a person on the list with these designations.
    pub fn add(&self, id: u64, login: &'static str, designations: Vec<Designation>) {
        self.people
            .lock()
            .expect("lock")
            .push((id, login, designations));
    }
}

#[async_trait]
impl AllowlistSource for FixedAllowlist {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn current(&self, tenant: TenantId) -> Result<Allowlist, SeamError> {
        if *self.unreadable.lock().expect("lock") {
            return Err(SeamError::Unavailable);
        }
        let entries = self
            .people
            .lock()
            .expect("lock")
            .iter()
            .map(|(id, login, designations)| AllowlistEntry {
                tenant,
                github_user_id: GithubUserId::new(*id).expect("a numeric id"),
                login: (*login).to_owned(),
                designations: designations.iter().copied().collect(),
                repositories: None,
                expires_at: None,
            })
            .collect();
        let _ = self.tenant;
        Allowlist::new("allowlist-v1-test", entries).map_err(|_| SeamError::Unavailable)
    }
}

/// How the stand-in for the schema check behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckMode {
    /// Accepts any document that is JSON, so the second defence of the stage is the only one.
    Permissive,
    /// Refuses every document, as the real check does for one that breaks the schema.
    Refusing,
}

/// A stand-in for `AgentSchema::validate_bytes`. The real one lives in `factory-contracts`, which
/// this crate cannot depend on; its behavior is proved by `tests/agent_output_schemas.rs` there.
pub struct StandInCheck {
    mode: Mutex<CheckMode>,
    calls: Mutex<Vec<SchemaRef>>,
}

impl StandInCheck {
    pub fn set(&self, mode: CheckMode) {
        *self.mode.lock().expect("lock") = mode;
    }

    /// The schemas the stage asked about, oldest first.
    pub fn asked(&self) -> Vec<SchemaRef> {
        self.calls.lock().expect("lock").clone()
    }
}

impl AgentOutputCheck for StandInCheck {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn check(&self, schema: &SchemaRef, bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>> {
        self.calls.lock().expect("lock").push(schema.clone());
        let refuse = |message: &str| {
            vec![Violation {
                path: "$".to_owned(),
                message: message.to_owned(),
            }]
        };
        if *self.mode.lock().expect("lock") == CheckMode::Refusing {
            return Err(refuse("the stand-in check refuses every document"));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| refuse("the bytes are not JSON"))?;
        Ok(ValidatedOutput {
            value,
            sha256: Sha256Digest::of(bytes),
            size_bytes: bytes.len() as u64,
        })
    }
}

/// Builds the `agent` sandbox spec from the fixture of the testkit.
pub struct TestSpecs;

impl AgentSandboxSpecs for TestSpecs {
    fn agent_spec(
        &self,
        job: JobId,
        attempt: factory_domain::ids::AttemptId,
        _token: JobTokenRef,
    ) -> Result<SandboxSpec, SeamError> {
        let mut spec = sandbox_spec(&Ids::new(), SandboxProfile::Agent);
        spec.job = job;
        spec.attempt = attempt;
        Ok(spec)
    }
}

/// One probed runtime, `fake`, that supports structured output.
pub struct FixedProbes;

impl CapabilityProbes for FixedProbes {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    fn probed(&self) -> ProbedCapabilities {
        probed(&["fake"])
    }
}

// ---- the rig -------------------------------------------------------------------------------

/// A test engine with the real intake handler registered.
pub struct Rig {
    pub world: World,
    pub engine: Engine,
    pub runtime: FakeAgentRuntime,
    pub issues: Arc<FakeIssueSource>,
    pub requests: Arc<StoreRequests>,
    pub allowlist: Arc<FixedAllowlist>,
    pub check: Arc<StandInCheck>,
    pub issue: IssueRef,
    pub remote: FakeRemote,
    pub reads: Arc<Reads>,
    pub cargo: CargoBehavior,
    pub commit: CommitSha,
    pub repo: RepoRef,
}

/// What differs from one test to the next.
#[derive(Default)]
pub struct Options {
    pub rules: Option<IntakeRules>,
    pub scope: Option<Vec<StageKind>>,
    /// Register the real repository stage, over the fixture. Without it the stage is scripted.
    pub real_repo: bool,
    /// The files of the repository, instead of the Rust fixture.
    pub repo_files: Option<Vec<(String, String)>>,
    /// `cargo` is missing from the image.
    pub no_cargo: bool,
    /// `cargo` fails on this subcommand.
    pub cargo_fails_on: Option<&'static str>,
    /// The issue source, instead of a faithful fake. For the tests that break it on purpose.
    pub issue_source: Option<FakeIssueSource>,
}

impl Rig {
    pub async fn new() -> Self {
        Self::build(Options::default()).await
    }

    pub async fn build(options: Options) -> Self {
        let scope = options
            .scope
            .unwrap_or_else(|| vec![StageKind::Intake, StageKind::RepositoryIntelligence]);
        let world = World::with_config(|config| config.scope.clone_from(&scope)).await;
        let runtime = FakeAgentRuntime::new(world.artifacts.clone());
        let mut registry = InMemoryAgentRegistry::new();
        registry.add(classifier_manifest(), Some(CLASSIFIER_PROMPT));
        let mut deps = world.deps.clone();
        deps.runtime = Arc::new(runtime.clone());
        deps.registry = Arc::new(registry);

        let repo = RepoRef::parse("example-org/fixture").expect("a repository");
        let issue = IssueRef {
            repo: repo.clone(),
            number: 12,
        };
        let issues = Arc::new(options.issue_source.unwrap_or_default());
        let requests = Arc::new(StoreRequests::new(world.memory_store(), world.ids.clone()));
        let allowlist = Arc::new(FixedAllowlist::new(world.tenant));
        let check = Arc::new(StandInCheck {
            mode: Mutex::new(CheckMode::Permissive),
            calls: Mutex::new(Vec::new()),
        });
        let handler = IntakeHandler::new(
            IntakeConfig {
                label: LABEL.to_owned(),
                agent: factory_domain::values::Slug::parse("intake-classifier").expect("a slug"),
                rules: options.rules.unwrap_or_default(),
                definition_commit: definition_commit(),
                broker: BrokerEndpoint {
                    base_url: Uri::parse("https://model-broker.sandbox.internal:8443")
                        .expect("a URI"),
                },
                max_output_bytes: 524_288,
            },
            IntakeDeps {
                requests: requests.clone(),
                issues: issues.clone(),
                allowlists: allowlist.clone(),
                policy: policy_engine(),
                redactor: redactor(),
                schemas: check.clone(),
                sandboxes: Arc::new(TestSpecs),
                probes: Arc::new(FixedProbes),
            },
        );
        let mut handlers = HandlerRegistry::new();
        handlers.register(Arc::new(handler)).expect("one handler");
        // The repository the stage reads, on a fake remote that the workspace provider and the
        // change host share.
        let remote = FakeRemote::new();
        let files = options.repo_files.clone().unwrap_or_else(word_count);
        let commit = publish(&remote, &repo, &files);
        let recording = Arc::new(RecordingWorkspaces::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            world.artifacts.clone(),
            repo_rules(),
        )));
        let reads = Arc::clone(&recording.reads);
        let cargo = CargoBehavior::working();
        let mut sandbox = FakeSandbox::new(
            world.clock.clone(),
            world.artifacts.clone(),
            sandbox_policy(),
        );
        if !options.no_cargo {
            sandbox = sandbox.with_program("cargo", cargo.program(options.cargo_fails_on));
        }
        if options.real_repo {
            deps.workspaces = recording;
            deps.sandbox = Arc::new(sandbox);
        }
        for kind in scope.iter().filter(|kind| **kind != StageKind::Intake) {
            if options.real_repo && *kind == StageKind::RepositoryIntelligence {
                let repo_handler = RepoIntelHandler::new(
                    RepoIntelConfig {
                        definition_commit: definition_commit(),
                        path_rules: repo_rules(),
                        default_timeout_seconds: 900,
                        max_file_bytes: 64 * 1024,
                        max_paths: 5000,
                    },
                    RepoIntelDeps {
                        changes: Arc::new(FakeChangeHost::sharing(remote.clone())),
                        repos: Arc::new(FixedRepository { repo: repo.clone() }),
                        specs: Arc::new(TestVerifySpecs),
                        manifests: Arc::new(JsonManifests),
                        policy: policy_engine(),
                        redactor: redactor(),
                    },
                );
                handlers
                    .register(Arc::new(repo_handler))
                    .expect("one handler per stage");
            } else {
                handlers
                    .register(Arc::clone(
                        world.handlers.get(*kind).expect("a scripted handler"),
                    ))
                    .expect("one handler per stage");
            }
        }
        let engine = Engine::new(deps, world.config.clone(), handlers).expect("the engine starts");
        Self {
            world,
            engine,
            runtime,
            issues,
            requests,
            allowlist,
            check,
            issue,
            remote,
            reads,
            cargo,
            commit,
            repo,
        }
    }

    /// The person who applied the label.
    pub fn actor(id: u64, login: &str) -> GithubActor {
        GithubActor {
            id,
            login: ActorLogin::new(login).expect("a login"),
        }
    }

    /// Stores one revision of the original request, as the API does, and mirrors its hash.
    pub async fn record_request(&self, job: JobId, revision: u32, text: &str) {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.world.tenant))
            .await
            .expect("a tx");
        let stored = tx
            .record_original_request(NewOriginalRequest {
                id: factory_ports::clock::IdGenerator::new_uuid(&*self.world.ids),
                job,
                revision,
                source: StoreRequestSource::GithubIssue,
                source_ref: None,
                author_github_user_id: Some(REQUESTER_ID),
                text: text.to_owned(),
            })
            .await
            .expect("the request is stored");
        tx.commit().await.expect("commit");
        self.requests
            .mirror
            .lock()
            .expect("lock")
            .insert(job, (revision, stored.row.value.content_sha256.clone()));
        self.requests
            .issues
            .lock()
            .expect("lock")
            .insert(job, self.issue.clone());
    }

    /// Records that `actor` applied the factory label.
    pub async fn label_applied_by(&self, actor: &GithubActor) {
        self.issues.seed_label(&self.issue, LABEL, actor).await;
    }

    /// A job whose request is stored, labelled by the allowlisted requester, and admitted.
    pub async fn job(&self, text: &str) -> JobId {
        let job = self.received_job(text).await;
        self.label_applied_by(&Self::actor(REQUESTER_ID, "requester-one"))
            .await;
        self.admit(job).await;
        job
    }

    /// A job as a webhook makes it: received for the rig's issue, with no text stored, labelled by
    /// the allowlisted requester and admitted. The issue is on the fake host only if the test put
    /// it there.
    pub async fn webhook_job(&self) -> JobId {
        let job = self
            .engine
            .receive_job(
                self.world.tenant,
                self.world.requester,
                self.world.repository,
            )
            .await
            .expect("receive");
        self.requests.await_issue(job, self.issue.clone());
        self.label_applied_by(&Self::actor(REQUESTER_ID, "requester-one"))
            .await;
        self.admit(job).await;
        job
    }

    /// Puts the issue of the rig on the fake host with this title and body, opened by `author`.
    pub fn host_has_issue(&self, title: &str, body: &str, author: u64) {
        let now = factory_domain::values::Timestamp::parse("2026-10-28T10:00:00Z").expect("a time");
        self.issues.put_issue(factory_ports::githost::Issue {
            reference: self.issue.clone(),
            title: title.to_owned(),
            body: body.to_owned(),
            author: Self::actor(author, "requester-one"),
            labels: vec![LABEL.to_owned()],
            updated_at: now,
            fetched_at: now,
        });
    }

    /// A job that is received and has its request stored, not yet labelled or admitted.
    pub async fn received_job(&self, text: &str) -> JobId {
        let job = self
            .engine
            .receive_job(
                self.world.tenant,
                self.world.requester,
                self.world.repository,
            )
            .await
            .expect("receive");
        self.record_request(job, 1, text).await;
        job
    }

    pub async fn admit(&self, job: JobId) {
        let admission = self
            .engine
            .admit_job(self.world.tenant, job)
            .await
            .expect("admit");
        assert!(
            matches!(
                admission,
                factory_workflow::engine::Admission::Admitted { .. }
            ),
            "{admission:?}"
        );
    }

    /// Every artifact the newest run of `kind` is linked to, with its bytes, oldest first.
    pub async fn artifacts_of(&self, job: JobId, kind: StageKind) -> Vec<(Sha256Digest, Vec<u8>)> {
        let view = self.world.view(job).await;
        let Some(run) = view.newest(kind) else {
            return Vec::new();
        };
        let tenant = TenantScope::new(self.world.tenant);
        let mut found = Vec::new();
        for link in self.world.links(run.id).await {
            let reference = factory_domain::contracts::ArtifactRef {
                sha256: link.sha256.clone(),
                media_type: factory_domain::values::MediaType::parse("application/octet-stream")
                    .expect("a media type"),
                size_bytes: None,
            };
            if let Ok(bytes) = factory_ports::artifact::ArtifactStore::get(
                &*self.world.artifacts,
                &tenant,
                &reference,
            )
            .await
            {
                found.push((link.sha256, bytes));
            }
        }
        found
    }

    /// Every gate report the ledger of the job cites, read back through the artifact store.
    pub async fn gate_reports(&self, job: JobId) -> Vec<Value> {
        fn hashes(value: &Value, found: &mut Vec<String>) {
            match value {
                Value::String(text) if text.starts_with("sha256:") => found.push(text.clone()),
                Value::Array(items) => items.iter().for_each(|item| hashes(item, found)),
                Value::Object(map) => map.values().for_each(|item| hashes(item, found)),
                _ => {}
            }
        }
        let tenant = TenantScope::new(self.world.tenant);
        let mut seen = Vec::new();
        let mut reports = Vec::new();
        for entry in self.world.ledger(job).await {
            let mut found = Vec::new();
            hashes(
                &serde_json::to_value(&entry).expect("an entry serializes"),
                &mut found,
            );
            for text in found {
                if seen.contains(&text) {
                    continue;
                }
                seen.push(text.clone());
                let Ok(sha256) = Sha256Digest::parse(&text) else {
                    continue;
                };
                let reference = factory_domain::contracts::ArtifactRef {
                    sha256,
                    media_type: factory_domain::values::MediaType::parse("application/json")
                        .expect("a media type"),
                    size_bytes: None,
                };
                if let Ok(bytes) = factory_ports::artifact::ArtifactStore::get(
                    &*self.world.artifacts,
                    &tenant,
                    &reference,
                )
                .await
                    && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                    && value.pointer("/metadata/gate_id").is_some()
                {
                    reports.push(value);
                }
            }
        }
        reports
    }

    /// The JSON documents of the newest run of `kind` that have this top-level field.
    pub async fn documents_with(&self, job: JobId, kind: StageKind, field: &str) -> Vec<Value> {
        self.artifacts_of(job, kind)
            .await
            .into_iter()
            .filter_map(|(_, bytes)| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|value| value.get(field).is_some())
            .collect()
    }

    /// Queues what the classifier returns on its next run.
    pub fn classifier_returns(&self, output: Value) {
        self.runtime.queue(AdversarialScript::returning(output));
    }

    /// Claims the next stage run and runs its attempt.
    pub async fn run_next(&self) -> (ClaimedAttempt, AttemptOutcome) {
        self.world.advance(400);
        let claimed = self
            .engine
            .claim_next(&World::worker("worker-1"))
            .await
            .expect("claim");
        assert_eq!(claimed.started.len(), 1, "{claimed:?}");
        let claimed = claimed.started.into_iter().next().expect("one");
        let outcome = self
            .engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        (claimed, outcome)
    }
}

/// A valid classification, with this kind and summary.
pub fn classified(kind: &str, summary: &str) -> Value {
    json!({
        "schema_version": 1,
        "status": "CLASSIFIED",
        "request_kind": kind,
        "summary": summary,
        "domain_tags": ["general-software", "command-line-tool"],
        "risk_hint": "low",
        "risk_reasons": [],
        "ambiguity": { "material": false, "questions": [] },
        "confidence": 0.9,
        "ignored_instructions": []
    })
}

/// The classification of the usual request in these tests.
pub fn usual() -> Value {
    classified(
        "feature",
        "The request asks for a flag on the word count tool that prints its counts as JSON, so that other programs can read them.",
    )
}

pub const USUAL_REQUEST: &str =
    "Add a --json flag\n\nPlease let the word count tool print its counts as JSON.";
