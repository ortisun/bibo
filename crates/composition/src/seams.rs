//! The seams that the stage handlers and the engine declare and that only a composition root can
//! implement, over the real store, the real contracts crate and the protected configuration.
//!
//! Each type states which trait it implements and what it reads. A seam that cannot be written yet
//! is listed in `apps/worker/README.md` with the reason; nothing here pretends.
//!
//! | Seam | Type | Reads |
//! |---|---|---|
//! | `AgentOutputCheck` | [`SchemaChecker`] | the agent's own schema file, through `factory_contracts::agent_schema` |
//! | `ProjectManifestParser` | [`YamlManifests`] | `DefinitionLoader::project_manifest` (restricted YAML or JSON) |
//! | `AllowlistSource` | [`FileAllowlist`] | `allowlist/allowlist.yaml` in the protected checkout, on every call |
//! | `RequestSource` | [`StoreRequests`] | `RequestOps`, with a cache for the synchronous `recorded` |
//! | `JobRepository` | [`StoreRepositories`] | `JobOps` and `RepositoryOps` |
//! | `CapabilityProbes` | [`CachedProbes`] | the probes taken at start-up |
//! | `Authority` | [`StoreAuthority`] | the allowlist and `PrincipalOps` |
//! | `Ticker` | `system::TokioTicker` | the tokio timer |

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use async_trait::async_trait;
use factory_contracts::agent_schema::AgentSchemaLoader;
use factory_contracts::loader::{DefinitionFormat, DefinitionLoader};
use factory_contracts::yaml::{self, YamlLimits};
use factory_domain::contracts::{ProjectManifest, SchemaRef, Violation};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::authority::{Allowlist, AllowlistEntry};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::scope::TenantScope;
use factory_domain::state::Status as _;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::ProbedCapabilities;
use factory_ports::githost::IssueRef;
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::registry::ValidatedOutput;
use factory_ports::store::{
    AuditFilter, JobFilter, JobOrigin, NewOriginalRequest, RequestSource as StoredSource, Store,
    StoreError, Tx,
};
use factory_workflow::stages::intake::seams::{
    AgentOutputCheck, AllowlistSource, CapabilityProbes, FetchedRequest, RecordedRequest,
    RequestSnapshot, RequestSource, SeamError,
};
use factory_workflow::stages::repo_intel::seams::{
    JobRepository, ManifestProblem, ProjectManifestParser, TargetRepository,
};
use serde::Deserialize;

// ------------------------------------------------------------------------------------------
// AgentOutputCheck
// ------------------------------------------------------------------------------------------

/// Checks an agent's output against that agent's own schema, with the limits and the strict
/// parse of `factory-contracts`.
pub struct SchemaChecker {
    loader: AgentSchemaLoader,
}

impl SchemaChecker {
    /// A checker that reads schemas under `root` (the `agents/schemas` directory sits below it).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            loader: AgentSchemaLoader::new(root),
        }
    }
}

impl AgentOutputCheck for SchemaChecker {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn check(&self, schema: &SchemaRef, bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>> {
        let loaded = self.loader.load_ref(schema).map_err(|error| {
            vec![Violation {
                path: "$".to_owned(),
                message: format!("the agent's output schema cannot be loaded: {error}"),
            }]
        })?;
        loaded.validate_bytes(bytes)
    }
}

// ------------------------------------------------------------------------------------------
// ProjectManifestParser
// ------------------------------------------------------------------------------------------

/// Reads a project manifest from YAML or JSON through the contracts loader.
pub struct YamlManifests {
    loader: DefinitionLoader,
}

impl YamlManifests {
    /// # Errors
    /// The schema-load error text, when the embedded schemas do not load.
    pub fn new() -> Result<Self, String> {
        DefinitionLoader::new()
            .map(|loader| Self { loader })
            .map_err(|error| error.to_string())
    }
}

impl ProjectManifestParser for YamlManifests {
    fn parse(&self, file: &str, bytes: &[u8]) -> Result<ProjectManifest, ManifestProblem> {
        let format = DefinitionFormat::from_path(Path::new(file))
            .ok_or_else(|| ManifestProblem(format!("{file} is neither YAML nor JSON")))?;
        self.loader
            .project_manifest(file, format, bytes)
            .map_err(|error| ManifestProblem(error.to_string()))
    }
}

// ------------------------------------------------------------------------------------------
// AllowlistSource and the allowlist file
// ------------------------------------------------------------------------------------------

/// The path of the allowlist inside the protected checkout.
pub const ALLOWLIST_PATH: &str = "allowlist/allowlist.yaml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistFile {
    version: u32,
    #[serde(default)]
    entries: Vec<EntryFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    tenant: String,
    github_user_id: u64,
    login: String,
    designations: Vec<String>,
    #[serde(default)]
    repositories: Option<Vec<String>>,
    #[serde(default)]
    expires_at: Option<String>,
}

fn designation(name: &str) -> Option<Designation> {
    Some(match name {
        "requester" => Designation::Requester,
        "operator" => Designation::Operator,
        "approver" => Designation::Approver,
        "security_approver" => Designation::SecurityApprover,
        "repo_admin" => Designation::RepoAdmin,
        "org_admin" => Designation::OrgAdmin,
        _ => return None,
    })
}

/// The named allowlist of the protected configuration, read from the file at every call, so that
/// removing a person takes effect on the next decision (NT-AUTHZ-04). The file format is decided
/// here (no document defines one yet) and is listed for architect review in the README.
pub struct FileAllowlist {
    path: PathBuf,
}

impl FileAllowlist {
    /// An allowlist at `<protected checkout>/allowlist/allowlist.yaml`.
    #[must_use]
    pub fn in_checkout(checkout: &Path) -> Self {
        Self {
            path: checkout.join(ALLOWLIST_PATH),
        }
    }

    /// Reads the whole list.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the file is missing, too large or does not parse: the
    /// stage fails closed.
    pub fn read(&self) -> Result<Allowlist, SeamError> {
        let (version, entries) = self.entries()?;
        Allowlist::new(version.as_str(), entries).map_err(|_| SeamError::Unavailable)
    }

    /// The entries and the version hash of the file as it is now.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    pub fn entries(&self) -> Result<(Sha256Digest, Vec<AllowlistEntry>), SeamError> {
        let text = std::fs::read_to_string(&self.path).map_err(|_| SeamError::Unavailable)?;
        let file: AllowlistFile =
            yaml::from_str(&text, YamlLimits::POLICY).map_err(|_| SeamError::Unavailable)?;
        if file.version != 1 {
            return Err(SeamError::Unavailable);
        }
        let mut entries = Vec::new();
        for entry in file.entries {
            let tenant = entry
                .tenant
                .parse::<uuid::Uuid>()
                .map(TenantId::from_uuid)
                .map_err(|_| SeamError::Unavailable)?;
            let mut designations = BTreeSet::new();
            for name in &entry.designations {
                designations.insert(designation(name).ok_or(SeamError::Unavailable)?);
            }
            entries.push(AllowlistEntry {
                tenant,
                github_user_id: GithubUserId::new(entry.github_user_id)
                    .ok_or(SeamError::Unavailable)?,
                login: entry.login,
                designations,
                repositories: entry.repositories.map(|r| r.into_iter().collect()),
                expires_at: match entry.expires_at {
                    Some(text) => {
                        Some(Timestamp::parse(&text).map_err(|_| SeamError::Unavailable)?)
                    }
                    None => None,
                },
            });
        }
        Ok((Sha256Digest::of(text.as_bytes()), entries))
    }
}

#[async_trait]
impl AllowlistSource for FileAllowlist {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn current(&self, _tenant: TenantId) -> Result<Allowlist, SeamError> {
        self.read()
    }
}

// ------------------------------------------------------------------------------------------
// RequestSource
// ------------------------------------------------------------------------------------------

/// Reads the stored original request, and answers the synchronous `recorded` from a cache.
///
/// `RequestSource::recorded` is not asynchronous because `StageHandler::contract` is not, and the
/// engine calls `contract` while it claims, for candidates from every tenant. A database read
/// cannot happen there. So the cache is filled by [`StoreRequests::refresh`], which the worker
/// loop calls before each claim for the tenants it serves, and by [`StoreRequests::remember`].
/// A job whose request is not in the cache has no contract, the claim defers it as `NoContract`,
/// and the next refresh finds it. That is a latency of one poll, and a mismatch worth a change in
/// the stage package (README, "Cross-stage mismatches").
pub struct StoreRequests {
    store: Arc<dyn Store>,
    cache: RwLock<HashMap<JobId, (u32, Sha256Digest)>>,
    /// Jobs that a webhook created and that have no text yet, with the issue each came from.
    waiting: RwLock<HashMap<JobId, IssueRef>>,
}

/// The audit action the API writes when a labelled issue makes a job (`apps/api/src/webhook.rs`).
/// Its subject is `issue <owner>/<name>#<number>`, which is the only place the issue of a job that
/// a webhook created is stored.
pub const WEBHOOK_JOB_ACTION: &str = "job.received_from_webhook";

/// The id of revision 1 of a job's request: derived from the job, so a stage that fetches the
/// issue twice (a retry, a second worker) writes one row.
fn first_request_id(job: JobId) -> uuid::Uuid {
    let digest = Sha256Digest::of(format!("original-request\n{job}\n1").as_bytes());
    let number = u128::from_str_radix(&digest.hex()[..32], 16).unwrap_or(0);
    uuid::Builder::from_random_bytes(number.to_be_bytes()).into_uuid()
}

/// The issue a webhook job came from, read from the audit record the API wrote for it.
async fn webhook_issue(tx: &mut dyn Tx, job: JobId) -> Option<IssueRef> {
    let records = tx.read_audit(AuditFilter::Job(job), 0, 100).await.ok()?;
    records
        .iter()
        .filter(|record| record.event.action.as_str() == WEBHOOK_JOB_ACTION)
        .find_map(|record| issue_of(record.event.subject.strip_prefix("issue ")?))
}

impl StoreRequests {
    /// A source over `store`.
    #[must_use]
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            store,
            cache: RwLock::new(HashMap::new()),
            waiting: RwLock::new(HashMap::new()),
        }
    }

    /// Notes that `job` came from a webhook for `issue` and has no text yet.
    pub fn await_issue(&self, job: JobId, issue: IssueRef) {
        self.waiting
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job, issue);
    }

    /// Notes the revision and hash of a job's newest request.
    pub fn remember(&self, job: JobId, revision: u32, sha256: Sha256Digest) {
        self.cache
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job, (revision, sha256));
        self.waiting
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&job);
    }

    /// Reads the newest request of every job in these statuses, for each tenant, into the cache.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    pub async fn refresh(&self, tenants: &[TenantId]) -> Result<usize, SeamError> {
        let mut found = 0;
        for tenant in tenants {
            let mut tx = self
                .store
                .begin(TenantScope::new(*tenant))
                .await
                .map_err(|_| SeamError::Unavailable)?;
            let jobs = tx
                .list_jobs(
                    JobFilter {
                        statuses: Vec::new(),
                        repository: None,
                    },
                    None,
                    200,
                )
                .await;
            let jobs = match jobs {
                Ok(page) => page.rows,
                Err(_) => {
                    let _ = tx.rollback().await;
                    return Err(SeamError::Unavailable);
                }
            };
            for job in jobs {
                match tx.get_original_request(job.value.id, None).await {
                    Ok(request) => {
                        self.remember(job.value.id, request.revision, request.content_sha256);
                        found += 1;
                    }
                    // A job that a webhook created has no text until its intake stage fetches
                    // the issue. The issue is named in the audit record of the job.
                    Err(StoreError::NotFound)
                        if matches!(job.value.origin, Some(JobOrigin::Webhook(_)))
                            && !job.value.status.is_terminal() =>
                    {
                        if let Some(issue) = webhook_issue(&mut *tx, job.value.id).await {
                            self.await_issue(job.value.id, issue);
                        }
                    }
                    Err(_) => {}
                }
            }
            let _ = tx.rollback().await;
        }
        Ok(found)
    }
}

/// Fills the request cache before each claim, for the tenants this worker serves.
///
/// The worker is told its tenants in the configuration (`worker.tenants`). The system pool can
/// find work across tenants but cannot read a request, and a tenant transaction needs the tenant,
/// so the list is how the composition root learns which tenants to read for.
pub struct RefreshRequests {
    requests: Arc<StoreRequests>,
    tenants: Vec<TenantId>,
}

impl RefreshRequests {
    /// A hook that refreshes `requests` for `tenants`.
    #[must_use]
    pub fn new(requests: Arc<StoreRequests>, tenants: Vec<TenantId>) -> Self {
        Self { requests, tenants }
    }
}

#[async_trait(?Send)]
impl crate::hooks::BeforeClaim for RefreshRequests {
    async fn before_claim(&self) {
        if self.requests.refresh(&self.tenants).await.is_err() {
            tracing::warn!("the request cache could not be refreshed; some jobs wait one poll");
        }
    }
}

/// Parses `owner/name#number`.
pub(crate) fn issue_of(source_ref: &str) -> Option<IssueRef> {
    let (repo, number) = source_ref.split_once('#')?;
    Some(IssueRef {
        repo: RepoRef::parse(repo).ok()?,
        number: number.parse().ok()?,
    })
}

#[async_trait]
impl RequestSource for StoreRequests {
    fn fidelity(&self) -> Fidelity {
        self.store.fidelity()
    }

    fn recorded(&self, job: JobId) -> Option<RecordedRequest> {
        self.cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&job)
            .map(|(revision, sha256)| RecordedRequest {
                revision: *revision,
                sha256: sha256.clone(),
            })
    }

    fn awaiting(&self, job: JobId) -> Option<IssueRef> {
        if self
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&job)
        {
            return None;
        }
        self.waiting
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&job)
            .cloned()
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
        // Idempotent by id and content: the same fetch twice finds its row, and other words under
        // the same id are refused by the store. A stored revision never changes.
        let stored = tx
            .record_original_request(NewOriginalRequest {
                id: first_request_id(job),
                job,
                revision: 1,
                source: StoredSource::GithubIssue,
                source_ref: Some(format!(
                    "{}/{}#{}",
                    request.issue.repo.owner(),
                    request.issue.repo.name(),
                    request.issue.number
                )),
                author_github_user_id: Some(request.author),
                text: request.text.clone(),
            })
            .await;
        let stored = match stored {
            Ok(stored) => stored,
            Err(_) => {
                let _ = tx.rollback().await;
                return Err(SeamError::Unavailable);
            }
        };
        tx.commit().await.map_err(|_| SeamError::Unavailable)?;
        let sha256 = stored.row.value.content_sha256.clone();
        self.remember(job, 1, sha256.clone());
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
        // The issue the text came from is stored as `owner/name#number` in `source_ref`.
        let issue = row
            .source_ref
            .as_deref()
            .and_then(issue_of)
            .ok_or(SeamError::NotFound)?;
        Ok(RequestSnapshot {
            revision: row.revision,
            text: row.text,
            sha256: row.content_sha256,
            author: row.author_github_user_id,
            issue,
        })
    }
}

// ------------------------------------------------------------------------------------------
// JobRepository
// ------------------------------------------------------------------------------------------

/// The repository and default branch a job targets, from the job row and the repository row.
pub struct StoreRepositories {
    store: Arc<dyn Store>,
}

impl StoreRepositories {
    /// A source over `store`.
    #[must_use]
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl JobRepository for StoreRepositories {
    async fn of(&self, tenant: TenantId, job: JobId) -> Result<TargetRepository, SeamError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| SeamError::Unavailable)?;
        let outcome = async {
            let job_row = tx.get_job(job).await.map_err(|_| SeamError::NotFound)?;
            let repository = tx
                .get_repository(job_row.value.repository)
                .await
                .map_err(|_| SeamError::NotFound)?;
            Ok::<_, SeamError>(repository.value)
        }
        .await;
        let _ = tx.rollback().await;
        let repository = outcome?;
        Ok(TargetRepository {
            repo: RepoRef::parse(&repository.full_name).map_err(|_| SeamError::NotFound)?,
            branch: BranchName::new(&repository.default_branch).map_err(|_| SeamError::NotFound)?,
        })
    }
}

// ------------------------------------------------------------------------------------------
// CapabilityProbes
// ------------------------------------------------------------------------------------------

/// What the runtimes were found to support, taken once at start-up and replaced when a probe is
/// repeated. The router considers only a runtime that appears here.
pub struct CachedProbes {
    current: RwLock<ProbedCapabilities>,
}

impl CachedProbes {
    /// A cache holding `probed`.
    #[must_use]
    pub fn new(probed: ProbedCapabilities) -> Self {
        Self {
            current: RwLock::new(probed),
        }
    }

    /// Replaces the cached capabilities.
    pub fn replace(&self, probed: ProbedCapabilities) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = probed;
    }
}

impl CapabilityProbes for CachedProbes {
    fn probed(&self) -> ProbedCapabilities {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
