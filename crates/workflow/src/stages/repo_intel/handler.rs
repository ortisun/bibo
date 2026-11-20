//! The `REPOSITORY_INTELLIGENCE` stage handler.
//!
//! `execute` fetches the repository into the job's object store (the base commit comes from the
//! fetch and from nothing else), reads what it needs through `JobRepo` and builds the map. No code
//! runs and no sandbox starts in `execute`. `evaluate` produces the evidence: the map has the
//! shape of its schema, nothing that looks like a secret is in what later stages will read, and
//! the baseline build and test run in a fresh `verify` sandbox with no network.
//!
//! Repository text is untrusted data in every step. Nothing in a README or a source file becomes
//! a command, a path rule or a decision: commands come from the project manifest at the protected
//! base or from the table in `detect`, and paths are classified by the rules of the policy.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{ArtifactRef, ProjectManifest, StageContract};
use factory_domain::ids::GateReportId;
use factory_domain::policy::{PolicyEngine, SandboxProfileKind};
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::githost::{ChangeHost, GitHostError, GitScope};
use factory_ports::paths::{CommitSha, PathMode, PathRules, RepoGlob, RepoPath};
use factory_ports::sandbox::{ExecArgv, ExecRequest, SandboxError, TeardownReason};
use factory_ports::workspace::{
    JobRepo, ReadView, WorkspaceError, WorkspacePurpose, WorkspaceRequest,
};
use serde_json::{Value, json};

use super::codeowners;
use super::detect::{CommandChoice, Detection, NoCommand, Place, detect, is_test_path, line_of};
use super::map::{
    self, MAX_LISTED_FILES, baseline_json, command_json, detection_json, evidence, owners_json,
};
use super::seams::{
    JobRepository, ManifestProblem, ProjectManifestParser, SeamError, VerifySandboxSpecs,
};
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::framework::GateDecision;
use crate::handlers::{
    ContractContext, GateContext, NamedArtifact, StageContext, StageError, StageHandler,
    StageOutput,
};
use crate::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec, Executor,
    GateDefinition, GateFacts, GateSubject, gate_report, stage_contract,
};

/// The gate that checks the map against its schema.
pub const MAP_GATE: &str = "repository-map-valid";
/// The gate that checks that nothing a later stage reads holds a secret.
pub const SECRET_GATE: &str = "context-secret-free";
/// The gate that runs the baseline build and test.
pub const BASELINE_GATE: &str = "baseline-build-and-test";

const MAP_GATE_TEXT: &str = "repository-map-valid 1.0.0: the repository map has exactly the fields of its schema, and every claim names the file, the commit and the lines it was read from.";
const SECRET_GATE_TEXT: &str = "context-secret-free 1.0.0: neither the repository map nor the summary holds a string that the redactor takes for a secret.";
const BASELINE_GATE_TEXT: &str = "baseline-build-and-test 1.0.0: the build and test commands of the repository run in a fresh verify sandbox with no network, on the base commit, and their results are recorded.";

/// The path of the project manifest at the protected base.
const MANIFEST_PATH: &str = ".factory/project.yaml";

/// How many documents get a title read.
const TITLE_DOCUMENTS: usize = 20;

/// The most bytes of output a baseline command keeps.
const OUTPUT_BYTES: u64 = 256 * 1024;

/// The configuration of the stage. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct RepoIntelConfig {
    /// The commit of the factory's gate definitions, named in every report.
    pub definition_commit: GitSha,
    /// What the policy does with each path.
    pub path_rules: PathRules,
    /// How long a detected command may run, in seconds.
    pub default_timeout_seconds: u32,
    /// The most bytes of one file the stage reads.
    pub max_file_bytes: u64,
    /// The most paths the stage lists.
    pub max_paths: usize,
}

/// The collaborators of the handler.
pub struct RepoIntelDeps {
    /// The code host, for the read credential of the fetch.
    pub changes: Arc<dyn ChangeHost>,
    /// The repository of the job.
    pub repos: Arc<dyn JobRepository>,
    /// The `verify` sandbox spec factory.
    pub specs: Arc<dyn VerifySandboxSpecs>,
    /// The reader of the project manifest.
    pub manifests: Arc<dyn ProjectManifestParser>,
    /// The policy evaluators.
    pub policy: Arc<PolicyEngine>,
    /// The redactor of the job.
    pub redactor: Arc<Redactor>,
}

/// The `REPOSITORY_INTELLIGENCE` handler.
pub struct RepoIntelHandler {
    config: RepoIntelConfig,
    changes: Arc<dyn ChangeHost>,
    repos: Arc<dyn JobRepository>,
    specs: Arc<dyn VerifySandboxSpecs>,
    manifests: Arc<dyn ProjectManifestParser>,
    policy: Arc<PolicyEngine>,
    redactor: Arc<Redactor>,
}

impl RepoIntelHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: RepoIntelConfig, deps: RepoIntelDeps) -> Self {
        Self {
            config,
            changes: deps.changes,
            repos: deps.repos,
            specs: deps.specs,
            manifests: deps.manifests,
            policy: deps.policy,
            redactor: deps.redactor,
        }
    }
}

fn seam(error: SeamError) -> StageError {
    match error {
        SeamError::Unavailable => StageError::Tool,
        SeamError::NotFound => StageError::Internal,
    }
}

fn host_error(error: GitHostError) -> StageError {
    match error {
        GitHostError::Unauthorized | GitHostError::Forbidden => StageError::PolicyDenied,
        GitHostError::RateLimited { .. } | GitHostError::Unavailable => StageError::Provider,
        _ => StageError::Tool,
    }
}

fn workspace_error(error: WorkspaceError) -> StageError {
    match error {
        WorkspaceError::Cancelled => StageError::Cancelled,
        WorkspaceError::Unauthorized => StageError::PolicyDenied,
        WorkspaceError::Timeout
        | WorkspaceError::BaseMoved
        | WorkspaceError::Git { .. }
        | WorkspaceError::Io(_) => StageError::Tool,
        _ => StageError::Internal,
    }
}

fn slug(name: &str) -> Result<Slug, StageError> {
    Slug::parse(name).map_err(|_| StageError::Internal)
}

/// The text of a file at the commit, or `None` when the file is not there or is too large.
async fn read_text(
    repo: &dyn JobRepo,
    commit: &CommitSha,
    path: &str,
    max: u64,
) -> Result<Option<String>, StageError> {
    let Ok(path) = RepoPath::new(path) else {
        return Ok(None);
    };
    match repo.read_file_at(commit, &path, max, ReadView::Agent).await {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(WorkspaceError::PathNotFound(_) | WorkspaceError::TooLarge) => Ok(None),
        Err(other) => Err(workspace_error(other)),
    }
}

fn mode_word(mode: PathMode) -> &'static str {
    match mode {
        PathMode::Hidden => "hidden",
        PathMode::DenyWrite => "deny_write",
        PathMode::AppendOnly => "append_only",
        PathMode::AdditionsOnly => "additions_only",
        PathMode::Sensitive => "sensitive",
    }
}

fn role_of(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = path.to_ascii_lowercase();
    if matches!(
        name,
        "Cargo.toml" | "package.json" | "go.mod" | "pyproject.toml" | "pytest.ini" | "project.yaml"
    ) {
        "manifest"
    } else if is_test_path(path) {
        "test"
    } else if lower.ends_with(".md") || name.starts_with("README") || name.starts_with("LICENSE") {
        "document"
    } else if super::detect::EXTENSIONS
        .iter()
        .any(|(ext, _)| name.rsplit('.').next() == Some(ext) && name.contains('.'))
    {
        "source"
    } else {
        "configuration"
    }
}

fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(|line| line.trim().trim_start_matches('#').trim())
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(120).collect())
}

/// The gate commands of a project manifest that stand for the baseline.
fn manifest_commands(
    manifest: &ProjectManifest,
    text: &str,
    default_timeout: u32,
) -> Vec<CommandChoice> {
    let mut found: Vec<CommandChoice> = Vec::new();
    for (role, ids) in [
        ("build", &["build"][..]),
        ("test", &["unit-tests", "test"][..]),
    ] {
        let Some(gate) = manifest
            .gates
            .as_slice()
            .iter()
            .find(|gate| ids.contains(&gate.id.as_str()))
        else {
            continue;
        };
        let argv: Vec<String> = gate.argv.as_slice().to_vec();
        let Some(program) = argv.first().cloned() else {
            continue;
        };
        let line = line_of(text, gate.id.as_str()).unwrap_or(1);
        found.push(CommandChoice {
            role,
            argv,
            origin: "project-manifest",
            place: Place {
                path: MANIFEST_PATH.to_owned(),
                start: line,
                end: line,
            },
            toolchain: program,
            timeout_seconds: u32::try_from(gate.timeout_seconds.get())
                .unwrap_or(default_timeout)
                .max(1),
        });
    }
    found
}

#[async_trait]
impl StageHandler for RepoIntelHandler {
    fn fidelity(&self) -> Fidelity {
        // The handler holds no state. It is as real as the code host it reads through.
        self.changes.fidelity()
    }

    fn kind(&self) -> StageKind {
        StageKind::RepositoryIntelligence
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        let intake = ctx
            .upstream
            .iter()
            .find(|run| run.kind == StageKind::Intake)
            .ok_or(StageError::Internal)?;
        let request = intake
            .outputs
            .iter()
            .find(|output| output.name.as_str() == "normalized-request")
            .ok_or(StageError::Internal)?;
        stage_contract(&ContractSpec {
            kind: StageKind::RepositoryIntelligence,
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            mode: ctx.mode,
            created_at: ctx.now,
            contract_id: "stage-contract.repository-intelligence",
            title: "Map the repository and run its baseline",
            purpose: "Learn what the repository is made of, who owns it, which paths are protected and whether it builds and passes its tests today, so that later stages work from facts.",
            problem: "A change can only be judged against what was true before it. The factory needs the languages, the build and test commands, the owners and the protected paths of the repository at one commit, each with the place it was read, and a baseline run that shows whether the repository was already broken.",
            inputs: vec![ContractInput {
                name: "normalized-request",
                description: "The normalized request from intake. It names the work, not the repository.",
                sha256: request.artifact.sha256.clone(),
                media_type: "application/json",
                source: "previous_stage",
                produced_by: Some(intake.id),
                commit_sha: None,
                retrieved_at: ctx.now,
                trust: "untrusted",
            }],
            preconditions: vec![(
                "intake-passed",
                "The intake stage run passed and the request was accepted.",
                "upstream_stage_passed",
            )],
            method: (
                "Read the repository through the job's object store and run the baseline in a verify sandbox",
                "Files are read from the fetched commit by the control plane, hidden paths are never read, and commands run only in a sandbox with no network.",
                "Ask a model to explore the repository",
                "A model would read files the policy hides and could follow instructions written in them.",
            ),
            agent: ("repository-intelligence".to_owned(), "1.0.0"),
            granted_tools: Vec::new(),
            // `execute` reads through the job's object store and starts no sandbox. The baseline
            // runs in `evaluate`, in a sandbox of its own, so the attempt has none to wait for.
            shell: "sandboxed_typed_wrapper",
            placement: None,
            deliverables: vec![
                ContractDeliverable {
                    name: "repository-map",
                    description: "The repository map: languages, build and test commands, owners, protected paths and documents, each with provenance.",
                    media_type: "application/json",
                    required: true,
                },
                ContractDeliverable {
                    name: "context-summary",
                    description: "A compact summary of the map with a citation after each fact, for the prompts of later stages.",
                    media_type: "text/markdown",
                    required: true,
                },
            ],
            criteria: vec![
                ContractCriterion {
                    id: "map-is-valid",
                    description: "The repository map has the shape of its schema and every claim has provenance.",
                    gate: MAP_GATE,
                },
                ContractCriterion {
                    id: "context-has-no-secret",
                    description: "Nothing a later stage reads holds a secret.",
                    gate: SECRET_GATE,
                },
                ContractCriterion {
                    id: "baseline-recorded",
                    description: "The baseline build and test ran in a verify sandbox, or the report says what was missing.",
                    gate: BASELINE_GATE,
                },
            ],
            gates: vec![MAP_GATE, SECRET_GATE, BASELINE_GATE],
            budget: ContractBudget {
                wall_time_seconds: 1800,
                max_tokens: 0,
                max_cost_usd: 0.0,
                attempt_timeout_seconds: 1500,
                max_attempts: 2,
            },
            rollback: "Nothing outside the job is changed. Discard the map, the summary and the baseline report.",
            span_name: "stage.repository_intelligence",
        })
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let identity = ctx.identity;
        let ports = ctx.ports;
        let max = self.config.max_file_bytes;

        // The repository, fetched into the job's object store. The base commit is what the fetch
        // returned.
        let target = self
            .repos
            .of(identity.tenant, identity.job)
            .await
            .map_err(seam)?;
        let scope = GitScope {
            tenant: identity.tenant,
            job: identity.job,
            stage: StageKind::RepositoryIntelligence,
            repo: target.repo.clone(),
        };
        let credential = self
            .changes
            .fetch_target(&scope)
            .await
            .map_err(host_error)?;
        let fetched = ports
            .workspaces
            .fetch(identity.job, &credential, &target.branch, ctx.cancel)
            .await
            .map_err(workspace_error)?;
        let commit = fetched.commit;
        let commit_text = commit.as_str().to_owned();
        let repo = ports
            .workspaces
            .repo(identity.job)
            .await
            .map_err(workspace_error)?;

        // What the model may see, and what the policy hides. A hidden path is listed by name and
        // never read.
        let everything = RepoGlob::new("**").map_err(|_| StageError::Internal)?;
        let limit = self.config.max_paths;
        let visible: Vec<String> = repo
            .list_at(&commit, &everything, limit, ReadView::Agent)
            .await
            .map_err(workspace_error)?
            .iter()
            .map(|path| path.as_str().to_owned())
            .collect();
        let all: BTreeSet<String> = repo
            .list_at(&commit, &everything, limit, ReadView::Trusted)
            .await
            .map_err(workspace_error)?
            .iter()
            .map(|path| path.as_str().to_owned())
            .collect();
        let visible_set: BTreeSet<&str> = visible.iter().map(String::as_str).collect();
        let hidden: Vec<&String> = all
            .iter()
            .filter(|path| !visible_set.contains(path.as_str()))
            .collect();

        // The project manifest at the protected base.
        let mut project_manifest = None;
        if visible_set.contains(MANIFEST_PATH) {
            let path = RepoPath::new(MANIFEST_PATH).map_err(|_| StageError::Internal)?;
            let bytes = repo
                .read_file_at(&commit, &path, max, ReadView::Agent)
                .await
                .map_err(workspace_error)?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let parsed =
                self.manifests
                    .parse(MANIFEST_PATH, &bytes)
                    .map_err(|_: ManifestProblem| {
                        StageError::Blocked(BlockedCode::PolicyUnresolvable)
                    })?;
            project_manifest = Some((parsed, text, Sha256Digest::of(&bytes)));
        }

        // The files that detection needs to read.
        let mut texts: BTreeMap<String, String> = BTreeMap::new();
        for rule in super::detect::RULES {
            for need in [rule.build_needs, rule.test_needs].into_iter().flatten() {
                if visible_set.contains(need.file)
                    && !texts.contains_key(need.file)
                    && let Some(text) = read_text(&*repo, &commit, need.file, max).await?
                {
                    texts.insert(need.file.to_owned(), text);
                }
            }
        }
        let mut read = |file: &str| texts.get(file).cloned();
        let detection: Detection = detect(&visible, &mut read, self.config.default_timeout_seconds);

        // The commands: the manifest's, when it names them, else the detected ones.
        let from_manifest = project_manifest
            .as_ref()
            .map(|(manifest, text, _)| {
                manifest_commands(manifest, text, self.config.default_timeout_seconds)
            })
            .unwrap_or_default();
        let (commands, none): (Vec<CommandChoice>, Option<NoCommand>) = if from_manifest.is_empty()
        {
            (detection.commands.clone(), detection.none)
        } else {
            (from_manifest, None)
        };

        // Owners.
        let mut codeowners_json = Vec::new();
        for location in codeowners::LOCATIONS {
            if visible_set.contains(location)
                && let Some(text) = read_text(&*repo, &commit, location, max).await?
            {
                codeowners_json = owners_json(location, &codeowners::parse(&text), &commit_text);
                break;
            }
        }

        // Protected paths: the manifest's globs, and what the policy rules say of each path.
        let mut protected = Vec::new();
        if let Some((manifest, text, _)) = &project_manifest {
            for pattern in manifest.protected_paths.as_slice() {
                let line = line_of(text, pattern.as_str()).unwrap_or(1);
                protected.push(json!({
                    "pattern": pattern.as_str(),
                    "mode": "deny_write",
                    "origin": "project-manifest",
                    "evidence": evidence(&Place { path: MANIFEST_PATH.to_owned(), start: line, end: line }, &commit_text),
                }));
            }
        }
        for path in &visible {
            if protected.len() >= 200 {
                break;
            }
            if let Ok(repo_path) = RepoPath::new(path)
                && let Some(mode) = self.config.path_rules.classify(&repo_path)
                && matches!(
                    mode,
                    PathMode::DenyWrite | PathMode::AppendOnly | PathMode::AdditionsOnly
                )
            {
                protected.push(json!({
                    "pattern": path,
                    "mode": mode_word(mode),
                    "origin": "policy",
                }));
            }
        }

        // Files, tests and documents.
        let mut files = Vec::new();
        let mut sources: BTreeMap<String, Vec<&String>> = BTreeMap::new();
        for path in &visible {
            if role_of(path) == "source" {
                let stem = stem_of(path);
                sources.entry(stem).or_default().push(path);
            }
        }
        let mut test_mapping = Vec::new();
        let mut documents = Vec::new();
        let mut titles = 0usize;
        let mut readme_title = None;
        for path in &visible {
            let role = role_of(path);
            if files.len() < MAX_LISTED_FILES {
                files.push(json!({
                    "path": path,
                    "role": role,
                    "evidence": evidence(&Place::file(path), &commit_text),
                }));
            }
            if role == "test" && test_mapping.len() < 200 {
                let stem = stem_of(path);
                let covers: Vec<&String> = sources.get(&stem).cloned().unwrap_or_default();
                test_mapping.push(json!({
                    "test": path,
                    "covers": covers,
                    "evidence": evidence(&Place::file(path), &commit_text),
                }));
            }
            let lower = path.to_ascii_lowercase();
            let kind = if path.starts_with("README") || lower.ends_with("/readme.md") {
                Some("readme")
            } else if lower.starts_with("contributing") {
                Some("contributing")
            } else if lower.starts_with("docs/adr/") || lower.starts_with("docs/decisions/") {
                Some("decision")
            } else if lower.starts_with("docs/") && lower.ends_with(".md") {
                Some("guide")
            } else {
                None
            };
            if let Some(kind) = kind
                && documents.len() < 100
            {
                let mut title = None;
                if titles < TITLE_DOCUMENTS
                    && let Some(text) = read_text(&*repo, &commit, path, max).await?
                {
                    titles += 1;
                    title = first_line(&text);
                    if kind == "readme" && readme_title.is_none() {
                        readme_title.clone_from(&title);
                    }
                }
                let mut entry = json!({
                    "path": path,
                    "kind": kind,
                    "evidence": evidence(&Place::file(path), &commit_text),
                });
                if let (Some(title), Some(object)) = (title, entry.as_object_mut()) {
                    // The title is text from the repository: nothing that looks like a secret
                    // stays in it.
                    let redacted = self
                        .redactor
                        .redact_str(&title)
                        .map_err(|_| StageError::Internal)?;
                    object.insert("title".into(), json!(redacted.output));
                }
                documents.push(entry);
            }
        }
        let redacted_title = match &readme_title {
            Some(title) => Some(
                self.redactor
                    .redact_str(title)
                    .map_err(|_| StageError::Internal)?
                    .output
                    .into_owned(),
            ),
            None => None,
        };

        let (languages, build_systems) = detection_json(&detection, &commit_text);
        let excluded: Vec<Value> = hidden
            .iter()
            .take(100)
            .map(|path| json!({ "path": path, "reason": "hidden-by-policy" }))
            .collect();
        let mut repository_map = json!({
            "schema_version": 1,
            "repository": format!("{}/{}", target.repo.owner(), target.repo.name()),
            "commit_sha": commit_text,
            "languages": languages,
            "build_systems": build_systems,
            "commands": commands.iter().map(|c| command_json(c, &commit_text)).collect::<Vec<_>>(),
            "codeowners": codeowners_json,
            "protected_paths": protected,
            "files": files,
            "test_mapping": test_mapping,
            "documents": documents,
            "excluded_paths": excluded,
            "baseline": baseline_json(&commands, none),
            "counts": {
                "files_seen": visible.len(),
                "files_listed": visible.len().min(MAX_LISTED_FILES),
                "truncated": visible.len() > MAX_LISTED_FILES,
            },
        });
        if let (Some((_, text, sha)), Some(object)) =
            (&project_manifest, repository_map.as_object_mut())
        {
            object.insert(
                "project_manifest".into(),
                json!({
                    "path": MANIFEST_PATH,
                    "sha256": sha,
                    "evidence": evidence(
                        &Place { path: MANIFEST_PATH.to_owned(), start: 1, end: u32::try_from(text.lines().count().max(1)).unwrap_or(1) },
                        &commit_text,
                    ),
                }),
            );
        }
        // The map must have the shape of its schema before anything is stored.
        map::validate(&repository_map).map_err(|_| StageError::InvalidOutput)?;

        let summary = self
            .redactor
            .redact_str(&map::summary(&repository_map, redacted_title.as_deref()))
            .map_err(|_| StageError::Internal)?
            .output
            .into_owned();

        // A protected-path decision is audited once for the whole map.
        ctx.note_audit(AuditAction::new(
            AuditKind::ProtectedPathDecision,
            AuditDecision::Noted,
        ));
        let map_bytes = serde_json::to_vec(&repository_map).map_err(|_| StageError::Internal)?;
        let map_ref = self
            .store(ports.artifacts, map_bytes, "application/json")
            .await?;
        let summary_ref = self
            .store(ports.artifacts, summary.into_bytes(), "text/markdown")
            .await?;
        Ok(StageOutput {
            documents: Vec::new(),
            artifacts: vec![
                NamedArtifact {
                    name: slug("repository-map")?,
                    artifact: map_ref,
                },
                NamedArtifact {
                    name: slug("context-summary")?,
                    artifact: summary_ref,
                },
            ],
            ..StageOutput::default()
        })
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let scope = TenantScope::new(ctx.identity.tenant);
        let find = |name: &str| ctx.outputs.iter().find(|o| o.name.as_str() == name);
        let (Some(map_output), Some(summary_output)) =
            (find("repository-map"), find("context-summary"))
        else {
            return Err(StageError::InvalidOutput);
        };
        let map_bytes = ctx
            .ports
            .artifacts
            .get(&scope, &map_output.artifact)
            .await
            .map_err(|_| StageError::Tool)?;
        let summary_bytes = ctx
            .ports
            .artifacts
            .get(&scope, &summary_output.artifact)
            .await
            .map_err(|_| StageError::Tool)?;
        let value: Value =
            serde_json::from_slice(&map_bytes).map_err(|_| StageError::InvalidOutput)?;
        let now = ctx.ports.clock.now();
        let subject = || GateSubject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
            report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
            started_at: now,
            finished_at: ctx.ports.clock.now(),
        };
        let definition = |id: &'static str, text: &'static str| GateDefinition {
            id,
            version: "1.0.0",
            text,
            commit: self.config.definition_commit.clone(),
        };
        let in_process = |facts: GateFacts| gate_report(&subject(), &facts);
        let base = |id: &'static str, text: &'static str| GateFacts {
            definition: definition(id, text),
            outcome: "PASSED",
            title: String::new(),
            reason: String::new(),
            failures: Vec::new(),
            blocked: None,
            fidelity: "real",
            executor: Executor::InProcess,
            commands: Vec::new(),
            tools: vec![(
                "factory-repository-intelligence".to_owned(),
                "1.0.0".to_owned(),
            )],
            evidence: Vec::new(),
        };

        // Gate: the map.
        let shape = map::validate(&value);
        let mut facts = base(MAP_GATE, MAP_GATE_TEXT);
        match shape {
            Ok(()) => {
                facts.title = "The repository map has the shape of its schema".to_owned();
                facts.reason = "Every field of the map is one the schema names, and every claim names the file, the commit and the lines it was read from.".to_owned();
            }
            Err(problem) => {
                facts.outcome = "FAILED";
                facts.title = "The repository map does not have the shape of its schema".to_owned();
                facts.reason = "The map has a field the schema does not name, a value of the wrong kind or a claim without provenance, so later stages cannot rely on it.".to_owned();
                facts.failures = vec![(
                    match problem {
                        map::MapProblem::Shape => "map-shape".to_owned(),
                        map::MapProblem::Provenance => "map-provenance".to_owned(),
                    },
                    "The map is refused. Fix the stage that built it.".to_owned(),
                )];
            }
        }
        facts.evidence = vec![format!("map={}", Sha256Digest::of(&map_bytes))];
        let map_report = in_process(facts)?;

        // Gate: no secret in what later stages read.
        let mut facts = base(SECRET_GATE, SECRET_GATE_TEXT);
        let scan = |bytes: &[u8]| self.redactor.contains_secret(bytes);
        match (scan(&map_bytes), scan(&summary_bytes)) {
            (Ok(false), Ok(false)) => {
                facts.title = "Nothing in the repository context looks like a secret".to_owned();
                facts.reason =
                    "The redactor found no secret in the map or in the summary.".to_owned();
            }
            (Ok(_), Ok(_)) => {
                facts.outcome = "FAILED";
                facts.title =
                    "The repository context holds something that looks like a secret".to_owned();
                facts.reason = "The redactor found a secret in the map or in the summary. Its value is not repeated here.".to_owned();
                facts.failures = vec![(
                    "secret-in-context".to_owned(),
                    "A later stage would have read a secret.".to_owned(),
                )];
            }
            _ => {
                facts.outcome = "BLOCKED";
                facts.title = "The repository context could not be scanned for secrets".to_owned();
                facts.reason = "The redactor could not check the map and the summary, so nothing can be said about secrets in them.".to_owned();
                facts.blocked = Some(("dependency_unavailable", "the secret scanner".to_owned()));
            }
        }
        facts.evidence = vec![format!("summary={}", Sha256Digest::of(&summary_bytes))];
        let secret_report = in_process(facts)?;

        // Gate: the baseline.
        let (baseline_report, policy_violation) = self.baseline(ctx, &value, now).await?;

        Ok(GateDecision {
            reports: vec![map_report, secret_report, baseline_report],
            review: None,
            human_gate: false,
            policy_violation,
            assurance: Vec::new(),
        })
    }
}

fn stem_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.split('.').next().unwrap_or(name);
    stem.trim_start_matches("test_")
        .trim_end_matches("_test")
        .to_owned()
}

impl RepoIntelHandler {
    async fn store(
        &self,
        artifacts: &dyn factory_ports::artifact::ArtifactStore,
        bytes: Vec<u8>,
        media_type: &str,
    ) -> Result<ArtifactRef, StageError> {
        artifacts
            .put(
                bytes,
                MediaType::parse(media_type).map_err(|_| StageError::Internal)?,
            )
            .await
            .map_err(|_| StageError::Tool)
    }

    /// Runs the commands of the map in a fresh `verify` sandbox and reports. Returns the report and
    /// whether a command was refused by policy.
    async fn baseline(
        &self,
        ctx: &GateContext<'_>,
        map: &Value,
        started: factory_domain::values::Timestamp,
    ) -> Result<(factory_domain::contracts::GateReport, bool), StageError> {
        let subject = |finished| GateSubject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
            report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
            started_at: started,
            finished_at: finished,
        };
        let definition = GateDefinition {
            id: BASELINE_GATE,
            version: "1.0.0",
            text: BASELINE_GATE_TEXT,
            commit: self.config.definition_commit.clone(),
        };
        let sandbox_fidelity = match ctx.ports.sandbox.fidelity() {
            Fidelity::Real => "real",
            Fidelity::Fake => "fake",
        };
        let blocked = |code: &'static str, missing: String, reason: String, finished| {
            gate_report(
                &subject(finished),
                &GateFacts {
                    definition: definition.clone(),
                    outcome: "BLOCKED",
                    title: "The baseline build and test could not run".to_owned(),
                    reason,
                    failures: Vec::new(),
                    blocked: Some((code, missing.clone())),
                    fidelity: "real",
                    executor: Executor::InProcess,
                    commands: Vec::new(),
                    tools: vec![(
                        "factory-repository-intelligence".to_owned(),
                        "1.0.0".to_owned(),
                    )],
                    evidence: vec![format!("blocked={code}"), format!("missing={missing}")],
                },
            )
        };

        // No command: the map says why, and the gate does not guess.
        if map["baseline"]["status"] == "blocked" {
            let missing = map["baseline"]["blocked"]["missing"]
                .as_str()
                .unwrap_or("a build and test command")
                .to_owned();
            let report = blocked(
                "environment_unsupported",
                missing,
                "The repository does not say how to build and test it, and the factory does not guess a command, so the baseline did not run. Add a project manifest with the commands.".to_owned(),
                ctx.ports.clock.now(),
            )?;
            return Ok((report, false));
        }
        let commit = CommitSha::parse(map["commit_sha"].as_str().unwrap_or_default())
            .map_err(|_| StageError::InvalidOutput)?;
        let commands: Vec<(String, Vec<String>, u32)> = map["commands"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| {
                (
                    c["role"].as_str().unwrap_or_default().to_owned(),
                    c["argv"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|w| w.as_str().map(str::to_owned))
                        .collect(),
                    u32::try_from(c["timeout_seconds"].as_u64().unwrap_or(900)).unwrap_or(900),
                )
            })
            .collect();

        // Each command passes the command policy before it runs.
        for (_, argv, _) in &commands {
            if !self
                .policy
                .commands
                .evaluate(argv, SandboxProfileKind::Verify)
                .is_allowed()
            {
                let report = blocked(
                    "environment_unsupported",
                    "a command that the command policy allows".to_owned(),
                    "A command of the repository is not one the command policy allows in a verify sandbox, so it was not run.".to_owned(),
                    ctx.ports.clock.now(),
                )?;
                return Ok((report, true));
            }
        }

        // The checkout and the sandbox.
        let workspace = ctx
            .ports
            .workspaces
            .create(
                WorkspaceRequest {
                    job: ctx.identity.job,
                    attempt: ctx.attempt,
                    base: commit,
                    protected_base: None,
                    rules: self.config.path_rules.clone(),
                    purpose: WorkspacePurpose::Verify {
                        holdouts: Vec::new(),
                    },
                },
                ctx.cancel,
            )
            .await
            .map_err(workspace_error)?;
        let spec = match self
            .specs
            .verify_spec(ctx.identity.job, ctx.attempt, workspace.mounts())
        {
            Ok(spec) => spec,
            Err(error) => {
                let _ = workspace.dispose().await;
                return Err(seam(error));
            }
        };
        let mut session = match ctx.ports.sandbox.create_verified(spec, ctx.cancel).await {
            Ok(session) => session,
            Err(error) => {
                let _ = workspace.dispose().await;
                return Err(StageError::from(error));
            }
        };
        let sandbox_id = session.id().to_string();
        let image = session.posture().image.reference();
        let image_digest = image
            .split_once('@')
            .map_or(image, |(_, digest)| digest)
            .to_owned();
        let image_digest = Sha256Digest::parse(&image_digest).map_err(|_| StageError::Internal)?;

        let mut ran = Vec::new();
        let mut failures: Vec<(String, String)> = Vec::new();
        let mut missing_tool: Option<String> = None;
        let mut evidence_lines = Vec::new();
        for (role, argv, timeout) in &commands {
            let exec = ExecArgv::new(argv.clone()).map_err(|_| StageError::InvalidOutput)?;
            let result = session
                .exec(
                    ExecRequest {
                        argv: exec,
                        cwd: None,
                        stdin: None,
                        timeout: std::time::Duration::from_secs(u64::from(*timeout)),
                        max_output_bytes: OUTPUT_BYTES,
                    },
                    ctx.cancel,
                )
                .await;
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    let _ = session.stop_and_remove(TeardownReason::Failed).await;
                    let _ = workspace.dispose().await;
                    return Err(match error {
                        SandboxError::Timeout => StageError::Sandbox,
                        other => StageError::from(other),
                    });
                }
            };
            ctx_note(&mut ran, argv, &result);
            evidence_lines.push(format!(
                "{role}:{:?}:{}",
                result.exit_code, result.timed_out
            ));
            match (result.exit_code, result.timed_out) {
                (_, true) => failures.push((
                    format!("{role}-timed-out"),
                    format!("The {role} command ran past its limit and was stopped."),
                )),
                (Some(126 | 127), _) => {
                    missing_tool = Some(argv.first().cloned().unwrap_or_default());
                    break;
                }
                (Some(0), _) => {}
                _ => failures.push((
                    format!("{role}-failed"),
                    format!("The {role} command did not finish cleanly on the base commit."),
                )),
            }
            if !failures.is_empty() {
                break;
            }
        }
        let _ = session.stop_and_remove(TeardownReason::Completed).await;
        let _ = workspace.dispose().await;

        let finished = ctx.ports.clock.now();
        let executor = Executor::Sandbox {
            sandbox_id,
            image_digest,
            network: "none",
        };
        let (outcome, title, reason, blocked_reason) = if let Some(tool) = missing_tool {
            (
                "BLOCKED",
                "The baseline build and test could not run".to_owned(),
                format!(
                    "The sandbox image has no `{tool}`, so the repository could not be built. The factory does not guess another way to build it."
                ),
                Some(("tool_unavailable", tool)),
            )
        } else if failures.is_empty() {
            (
                "PASSED",
                "The repository builds and passes its tests at the base commit".to_owned(),
                "The build and test commands ran in a fresh verify sandbox with no network and finished cleanly.".to_owned(),
                None,
            )
        } else {
            (
                "FAILED",
                "The repository is already failing at the base commit".to_owned(),
                "A baseline command failed before any change, so later gates cannot tell old failures from new ones. A person decides what to do.".to_owned(),
                None,
            )
        };
        let report = gate_report(
            &subject(finished),
            &GateFacts {
                definition,
                outcome,
                title,
                reason,
                failures,
                blocked: blocked_reason,
                fidelity: sandbox_fidelity,
                executor,
                commands: ran,
                tools: commands
                    .first()
                    .map(|(_, argv, _)| {
                        vec![(
                            argv.first().cloned().unwrap_or_default(),
                            "unknown".to_owned(),
                        )]
                    })
                    .unwrap_or_default(),
                evidence: evidence_lines,
            },
        )?;
        Ok((report, false))
    }
}

/// Adds the record of one command run to the commands of the report.
fn ctx_note(ran: &mut Vec<Value>, argv: &[String], result: &factory_ports::sandbox::ExecResult) {
    let reference = |artifact: &ArtifactRef| {
        let mut value = json!({
            "sha256": artifact.sha256,
            "media_type": artifact.media_type,
        });
        if let (Some(size), Some(object)) = (&artifact.size_bytes, value.as_object_mut()) {
            object.insert("size_bytes".into(), json!(size.get()));
        }
        value
    };
    let mut stdout = reference(&result.stdout);
    let mut stderr = reference(&result.stderr);
    for value in [&mut stdout, &mut stderr] {
        if let Some(object) = value.as_object_mut()
            && !object.contains_key("size_bytes")
        {
            object.insert("size_bytes".into(), json!(0));
        }
    }
    ran.push(json!({
        "argv": argv,
        "cwd": "/workspace",
        "executed": true,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "stdout": stdout,
        "stderr": stderr,
    }));
}
