//! The real end-to-end run: scenario E1 (or E2) against the owner's GitHub fixture repository and
//! the owner's Claude subscription, judged by the harness in `tests/end_to_end`.
//!
//! Only `scripts/e2e-composed.sh` starts this, through the two ignored tests of `real_e2e.rs`. It is
//! the composed wiring program of `tests/end_to_end/README.md` ("Wirings"): `protection` prints the
//! protection of the fixture's default branch, `run SCENARIO` drives the scenario and prints the
//! evidence. A missing prerequisite is written as one `BLOCKED:` reason per line, never a pass.
//!
//! # What is real
//!
//! Everything the live-adapters rig of `live/mod.rs` runs for real (the Docker sandbox and the
//! pinned images, both runtimes' adapters, the broker and its policy, the router, the git
//! workspaces, Spec Kit, the validation gates, the engine, the API server, PostgreSQL, the worker's
//! hook and the thirteen handlers), and in place of its two fakes:
//!
//! * **GitHub**: `https://api.github.com`, through the owner's GitHub App (its id and key), the
//!   installation on the fixture repository, and `github.com` for git over HTTPS.
//! * **The model**: `https://api.anthropic.com`, through the broker in subscription mode, signed
//!   with the owner's Claude subscription token (ADR 0020). Codex does not run in this mode.
//!
//! The registry is `https://crates.io`. The run is in the production profile, so its evidence says
//! `production`, and the start refuses a routing policy the owner has not confirmed.
//!
//! # What a person does
//!
//! The owner files the issue and applies the `factory` label as the requester: the run does that
//! with the owner's own `gh` login, because the App holds no permission to create issues or labels.
//! The job is then submitted through the API (`POST /v1/jobs`, no webhook), which checks the
//! requester by numeric GitHub id against the allowlist; intake checks it again and compares the
//! live issue text with the job's text (DG-3). Every decision a person takes (the specification
//! draft, the pull request, a review that waits for a person) is taken by the owner with
//! `factory-cli` against this run's API. The run never decides for them: it says what is waiting,
//! prints the exact command, and waits.
//!
//! # What is not real
//!
//! Listed in the evidence's mode file (`limitations`), and summed up here: the database is a private
//! copy made for the run, with the repository seeded as registered, attested and enabled by the
//! owner (the registration path is not part of E1); the statement that the App is not on the bypass
//! list is the owner's, recorded in the configuration, because the App cannot read the bypass list;
//! the advisory database is a stand-in with a fixed date.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use factory_composition::config::FactoryConfig;
use factory_composition::external::GithubTransportWrapper;
use factory_composition::profile::Profile;
use factory_composition::redaction::{FactorySecrets, SecretKind, redactor_from_policy};
use factory_composition::routing::{broker_caps, price_table};
use factory_composition::startup::{LoadedPolicies, LoadedRouting, load_policy, load_routing};
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::security::ProviderCredentialMode;
use factory_domain::redaction::Redactor;
use factory_domain::state::{StageRunStatus, Status as _};
use factory_domain::vocabulary::StageKind;
use factory_egress::broker::{BrokerCore, BrokerParts, MemoryAudit, Provider, SystemEntropy};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_github::{Transport, TransportError, WireRequest, WireResponse};
use factory_ports::clock::Clock as _;
use factory_workflow::engine::JobView;
use serde_json::{Value, json};

use crate::e2e::{self, Extras, RunProfile, Sources, Tokens, Transitions};
use crate::live::docker_lock::DockerLock;
use crate::live::{self, Bench, LiveRig};
use crate::support::{Env, Options, RealSeed, Req};

/// The variables the run reads. The first four are what only the owner can provide.
pub const APP_ID: &str = "FACTORY_E2E_GITHUB_APP_ID";
pub const APP_KEY_FILE: &str = "FACTORY_E2E_GITHUB_APP_KEY_FILE";
pub const FIXTURE_REPO: &str = "FACTORY_E2E_FIXTURE_REPO";
pub const ALLOWLIST: &str = "FACTORY_E2E_REQUESTER_ALLOWLIST";
pub const TOKEN_FILE: &str = "FACTORY_E2E_SUBSCRIPTION_TOKEN_FILE";
pub const BUDGET: &str = "FACTORY_E2E_JOB_BUDGET_USD";
/// Where the run writes its answer, the blocked reasons, the evidence and the next step.
pub const OUT: &str = "FACTORY_E2E_OUT";
/// The scenario to run.
pub const SCENARIO: &str = "FACTORY_E2E_SCENARIO";
/// The `factory-cli` program the owner runs for a decision.
pub const CLI: &str = "FACTORY_E2E_CLI";
/// How long the run waits for one decision of a person, in minutes (default 240).
pub const HUMAN_WAIT_MINUTES: &str = "FACTORY_E2E_HUMAN_WAIT_MINUTES";

fn var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The root of the repository.
pub fn root() -> PathBuf {
    live::root()
}

fn out_dir() -> PathBuf {
    var(OUT).map_or_else(|| root().join("target/e2e-real/out"), PathBuf::from)
}

/// Writes the reasons the run cannot go on, one per line, where the program reads them, and stops.
pub fn blocked(reasons: &[String]) -> ! {
    let dir = out_dir();
    let _ = std::fs::create_dir_all(&dir);
    let text: String = reasons
        .iter()
        .map(|reason| format!("{}\n", reason.replace('\n', " ")))
        .collect();
    let _ = std::fs::write(dir.join("blocked.txt"), &text);
    panic!("BLOCKED: {}", reasons.join(" | "));
}

/// Writes the program's answer (one JSON document) where the program reads it.
fn answer(value: &Value) {
    let dir = out_dir();
    std::fs::create_dir_all(&dir).expect("the output directory");
    std::fs::write(
        dir.join("answer.json"),
        serde_json::to_vec_pretty(value).expect("JSON"),
    )
    .expect("the answer file");
}

/// Says something to the person running the run: on their terminal when there is one, in the
/// file `next-step.txt` of the output directory, and in the log.
pub fn tell(text: &str) {
    eprintln!("{text}");
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(tty, "{text}");
    }
    let dir = out_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("next-step.txt"))
    {
        let _ = writeln!(file, "{text}");
    }
}

// ---- the settings ------------------------------------------------------------------------------

/// The owner, as the allowlist names them.
#[derive(Debug, Clone)]
pub struct Owner {
    pub tenant: TenantId,
    pub github_id: u64,
    pub login: String,
}

/// What the run is given.
pub struct Settings {
    pub app_id: u64,
    pub key_file: PathBuf,
    pub repo: String,
    pub allowlist_file: PathBuf,
    pub allowlist_text: String,
    pub owner: Owner,
    pub token_file: PathBuf,
    pub budget_micro_usd: u64,
    pub human_wait: Duration,
}

fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode() & 0o777)
}

/// The owner of the run: the allowlist entry that holds both `requester` and `approver` (they
/// work alone; `policies/approval.yaml` lets them approve their own low-risk request), or the
/// first requester.
fn owner_in(text: &str) -> Option<Owner> {
    #[derive(Default)]
    struct Entry {
        tenant: Option<String>,
        id: Option<u64>,
        login: String,
        designations: Vec<String>,
    }
    let mut entries: Vec<Entry> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let value = |prefix: &str| {
            trimmed
                .strip_prefix(prefix)
                .map(|rest| rest.split('#').next().unwrap_or("").trim().to_owned())
        };
        if let Some(tenant) = value("- tenant:") {
            entries.push(Entry {
                tenant: Some(tenant),
                ..Entry::default()
            });
        } else if let Some(entry) = entries.last_mut() {
            if let Some(id) = value("github_user_id:") {
                entry.id = id.parse().ok();
            } else if let Some(login) = value("login:") {
                entry.login = login;
            } else if let Some(list) = value("designations:") {
                entry.designations = list
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .map(|word| word.trim().to_owned())
                    .collect();
            }
        }
    }
    let holds = |entry: &Entry, word: &str| entry.designations.iter().any(|d| d == word);
    let chosen = entries
        .iter()
        .find(|entry| holds(entry, "requester") && holds(entry, "approver"))
        .or_else(|| entries.iter().find(|entry| holds(entry, "requester")))?;
    Some(Owner {
        tenant: TenantId::from_uuid(chosen.tenant.as_deref()?.parse().ok()?),
        github_id: chosen.id.filter(|id| *id > 0)?,
        login: chosen.login.clone(),
    })
}

impl Settings {
    /// Reads the settings, or every reason they cannot be read. `for_run` adds what only a run
    /// needs (the allowlist, the token, the budget).
    pub fn read(for_run: bool, routing: &LoadedRouting) -> Result<Self, Vec<String>> {
        let mut reasons = Vec::new();
        let app_id = match var(APP_ID).map(|id| id.parse::<u64>()) {
            Some(Ok(id)) if id > 0 => id,
            Some(_) => {
                reasons.push(format!("{APP_ID} is not the number of a GitHub App"));
                0
            }
            None => {
                reasons.push(format!("a registered GitHub App (its id) (set {APP_ID})"));
                0
            }
        };
        let key_file = var(APP_KEY_FILE).map(PathBuf::from).unwrap_or_default();
        if key_file.as_os_str().is_empty() {
            reasons.push(format!(
                "the private key file of the GitHub App (set {APP_KEY_FILE})"
            ));
        } else if mode_of(&key_file).is_none_or(|mode| mode & 0o077 != 0) {
            reasons.push(format!(
                "the App key file {} does not exist or is open to group or others; run chmod 600 on it",
                key_file.display()
            ));
        }
        let repo = var(FIXTURE_REPO).unwrap_or_default();
        let shaped = repo.split_once('/').is_some_and(|(owner, name)| {
            !owner.is_empty() && !name.is_empty() && !name.contains('/')
        });
        if !shaped {
            reasons.push(format!(
                "a fixture repository on GitHub with a branch-protection ruleset, as owner/name (set {FIXTURE_REPO})"
            ));
        }
        let allowlist_file = var(ALLOWLIST).map(PathBuf::from).unwrap_or_default();
        let allowlist_text = std::fs::read_to_string(&allowlist_file).unwrap_or_default();
        let owner = owner_in(&allowlist_text);
        if for_run && owner.is_none() {
            reasons.push(format!(
                "the named requester allowlist (set {ALLOWLIST} to a file in the factory's allowlist format whose entry for the owner has a tenant, a numeric github_user_id and the designations requester and approver)"
            ));
        }
        let token_file = var(TOKEN_FILE).map_or_else(
            || Path::new(&std::env::var("HOME").unwrap_or_default()).join("claud-oauth-token.txt"),
            |path| match path.strip_prefix("~/") {
                Some(rest) => Path::new(&std::env::var("HOME").unwrap_or_default()).join(rest),
                None => PathBuf::from(path),
            },
        );
        if for_run {
            match (mode_of(&token_file), std::fs::read_to_string(&token_file)) {
                (Some(mode), Ok(text)) if mode & 0o077 == 0 => {
                    if ProviderKey::subscription_token(&text).is_err() {
                        reasons.push(format!(
                            "the file {} does not hold one Claude subscription token on one line (run `claude setup-token`)",
                            token_file.display()
                        ));
                    }
                }
                (Some(_), Ok(_)) => reasons.push(format!(
                    "the subscription token file {} is open to group or others; run chmod 600 on it",
                    token_file.display()
                )),
                _ => reasons.push(format!(
                    "the owner's Claude subscription token file {} cannot be read (set {TOKEN_FILE})",
                    token_file.display()
                )),
            }
        }
        let ceiling = routing.policy.job.max_micro_usd;
        let budget_micro_usd = match var(BUDGET).map(|text| text.parse::<f64>()) {
            None => ceiling,
            Some(Ok(dollars)) if dollars > 0.0 && dollars * 1_000_000.0 <= ceiling as f64 => {
                (dollars * 1_000_000.0).round() as u64
            }
            Some(_) => {
                reasons.push(format!(
                    "{BUDGET} must be a positive number of US dollars no larger than the job budget of the policy ({:.2})",
                    ceiling as f64 / 1_000_000.0
                ));
                ceiling
            }
        };
        let human_wait = Duration::from_secs(
            var(HUMAN_WAIT_MINUTES)
                .and_then(|minutes| minutes.parse::<u64>().ok())
                .unwrap_or(240)
                * 60,
        );
        if !reasons.is_empty() {
            return Err(reasons);
        }
        Ok(Self {
            app_id,
            key_file,
            repo,
            allowlist_file,
            allowlist_text,
            owner: owner.unwrap_or(Owner {
                tenant: TenantId::from_uuid(uuid_of("00000000-0000-0000-0000-000000000001")),
                github_id: 1,
                login: String::new(),
            }),
            token_file,
            budget_micro_usd,
            human_wait,
        })
    }
}

fn uuid_of(text: &str) -> uuid::Uuid {
    text.parse().expect("a UUID")
}

// ---- GitHub, read without the factory ----------------------------------------------------------

/// Runs `gh` with these arguments (read-only calls, and the two calls of the requester: the issue
/// and its label) and returns its output, or why it failed.
pub fn gh(args: &[&str]) -> Result<String, String> {
    let output = Command::new("gh")
        .args(args)
        .output()
        .map_err(|error| format!("gh did not start: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("gh failed")
            .to_owned())
    }
}

fn gh_json(args: &[&str]) -> Result<Value, String> {
    let text = gh(args)?;
    serde_json::from_str(&text).map_err(|error| format!("gh printed no JSON: {error}"))
}

/// The installation of the App on the repository, read with the App's own JWT.
async fn installation_of(settings: &Settings) -> Result<u64, String> {
    let pem = std::fs::read_to_string(&settings.key_file)
        .map_err(|_| format!("{} cannot be read", settings.key_file.display()))?;
    let signer = factory_github::RingRs256Signer::from_pem(&pem).map_err(|_| {
        format!(
            "{} is not an RSA private key in PEM form",
            settings.key_file.display()
        )
    })?;
    let jwt = factory_github::AppJwt::make(settings.app_id, &SystemClock.now(), &signer)
        .map_err(|_| "the App's JWT could not be signed".to_owned())?;
    let transport = factory_github::UreqTransport::new(factory_github::ApiBase::github_com());
    let response = transport
        .execute(WireRequest {
            method: factory_github::Method::Get,
            target: format!("/repos/{}/installation", settings.repo),
            headers: vec![
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", jwt.expose()),
                ),
                (
                    "accept".to_owned(),
                    "application/vnd.github+json".to_owned(),
                ),
                ("x-github-api-version".to_owned(), "2022-11-28".to_owned()),
                (
                    "user-agent".to_owned(),
                    "software-factory-end-to-end".to_owned(),
                ),
            ],
            body: Vec::new(),
        })
        .await
        .map_err(|error| format!("GitHub did not answer: {error}"))?;
    if response.status != 200 {
        return Err(format!(
            "GitHub answered {} for the App's installation on {}: install the App on the repository (and check the App id and key)",
            response.status, settings.repo
        ));
    }
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| "GitHub's answer is not JSON".to_owned())?;
    body["id"]
        .as_u64()
        .ok_or_else(|| "GitHub's answer names no installation id".to_owned())
}

/// GitHub's facts about the fixture: its numeric id, its default branch and that branch's tip.
fn repository_facts(repo: &str) -> Result<(u64, String, String), String> {
    let found = gh_json(&["api", &format!("repos/{repo}")])?;
    let id = found["id"].as_u64().ok_or("no repository id")?;
    let branch = found["default_branch"]
        .as_str()
        .ok_or("no default branch")?
        .to_owned();
    let tip = branch_tip(repo, &branch)?;
    Ok((id, branch, tip))
}

fn branch_tip(repo: &str, branch: &str) -> Result<String, String> {
    let found = gh_json(&["api", &format!("repos/{repo}/branches/{branch}")])?;
    found["commit"]["sha"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("no tip for {branch}"))
}

// ---- the record of what the GitHub adapter sent ------------------------------------------------

/// One installation token the adapter asked for: its permissions and its repositories.
type Mint = (BTreeMap<String, String>, Vec<String>);

/// The requests the adapter sent (method and path, never a header) and the installation tokens
/// it asked for (the permissions and the repositories, never a value).
#[derive(Default)]
pub struct Recorder {
    requests: Mutex<Vec<(String, String)>>,
    mints: Mutex<Vec<Mint>>,
}

struct Recording {
    inner: Arc<dyn Transport>,
    recorder: Arc<Recorder>,
}

#[async_trait]
impl Transport for Recording {
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError> {
        let method = format!("{:?}", request.method).to_uppercase();
        let path = request
            .target
            .split('?')
            .next()
            .unwrap_or_default()
            .to_owned();
        if method == "POST" && path.ends_with("/access_tokens") {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            let permissions = body["permissions"]
                .as_object()
                .map(|found| {
                    found
                        .iter()
                        .map(|(name, level)| {
                            (name.clone(), level.as_str().unwrap_or_default().to_owned())
                        })
                        .collect()
                })
                .unwrap_or_default();
            let repositories = body["repositories"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(|name| name.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            self.recorder
                .mints
                .lock()
                .expect("the lock is never poisoned")
                .push((permissions, repositories));
        }
        self.recorder
            .requests
            .lock()
            .expect("the lock is never poisoned")
            .push((method, path));
        self.inner.execute(request).await
    }
}

impl Recorder {
    /// The requests recorded so far: method and path.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.requests
            .lock()
            .expect("the lock is never poisoned")
            .clone()
    }

    /// The installation tokens asked for so far.
    pub fn mints(&self) -> Vec<(BTreeMap<String, String>, Vec<String>)> {
        self.mints
            .lock()
            .expect("the lock is never poisoned")
            .clone()
    }

    /// The wrapper the GitHub adapter's transport is built through.
    pub fn wrapper(self: &Arc<Self>) -> GithubTransportWrapper {
        let recorder = Arc::clone(self);
        Arc::new(move |inner: Arc<dyn Transport>| {
            Arc::new(Recording {
                inner,
                recorder: Arc::clone(&recorder),
            }) as Arc<dyn Transport>
        })
    }
}

// ---- the bench: the real broker in front of the real provider -----------------------------------

/// The bench of a real run: the policies, the broker in subscription mode in front of
/// `https://api.anthropic.com`, the scratch directory and the lock of the Docker daemon.
pub struct RealBench {
    pub root: PathBuf,
    pub scratch: PathBuf,
    pub run: String,
    pub policies: LoadedPolicies,
    pub routing: LoadedRouting,
    pub redactor: Arc<Redactor>,
    pub core: Arc<BrokerCore>,
    pub broker: BrokerServer,
    pub host_ip: String,
    pub definition_commit: String,
    _lock: DockerLock,
}

impl Drop for RealBench {
    fn drop(&mut self) {
        self.broker.shutdown();
        live::remove_run(&self.run);
    }
}

impl Bench for RealBench {
    fn root(&self) -> &Path {
        &self.root
    }
    fn scratch(&self) -> &Path {
        &self.scratch
    }
    fn policies(&self) -> &LoadedPolicies {
        &self.policies
    }
    fn routing(&self) -> &LoadedRouting {
        &self.routing
    }
    fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }
    fn core(&self) -> &Arc<BrokerCore> {
        &self.core
    }
    fn mode(&self) -> ProviderCredentialMode {
        ProviderCredentialMode::Subscription
    }
    fn profile(&self) -> Profile {
        Profile::Production
    }
    fn definition_commit(&self) -> String {
        self.definition_commit.clone()
    }
}

/// What must hold on this machine before anything starts: Docker answers, the pinned images are
/// here, `gh` is logged in, and the routing policy is confirmed.
fn machine_problems(routing: &LoadedRouting, for_run: bool) -> Vec<String> {
    let mut found = Vec::new();
    if !for_run {
        return found;
    }
    let (answers, _, _) = live::docker(&["info", "--format", "{{.ServerVersion}}"]);
    if answers {
        let text = std::fs::read_to_string(root().join("infra/sandbox-images/images.json"))
            .unwrap_or_default();
        let catalog: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        for kind in ["agent", "verify", "egress-sidecar"] {
            let entry = &catalog["platforms"]["linux/arm64"]["images"][kind];
            match entry["reference"].as_str() {
                Some(reference) if entry["status"] == "ready" => {
                    let (here, _, _) =
                        live::docker(&["image", "inspect", "--format", "{{.Id}}", reference]);
                    if !here {
                        found.push(format!(
                            "the {kind} image {reference} is not on this host (build it with infra/sandbox-images/build.sh; images are never pulled)"
                        ));
                    }
                }
                _ => found.push(format!("the image catalog has no ready {kind} image")),
            }
        }
    } else {
        found.push("the Docker daemon does not answer, so no sandbox can be made".to_owned());
    }
    if gh(&["auth", "status"]).is_err() {
        found.push(
            "the GitHub command line `gh` is not installed or not logged in as the owner; the owner files the issue and applies its label with it (gh auth login)"
                .to_owned(),
        );
    }
    let waiting = routing.policy.unconfirmed();
    if !waiting.is_empty() {
        found.push(format!(
            "policies/model_routing.yaml waits for the owner's confirmation ({}), and the production profile refuses it",
            waiting.join("; ")
        ));
    }
    found
}

fn loaded() -> (LoadedPolicies, LoadedRouting) {
    let policies = load_policy(&root(), &[])
        .unwrap_or_else(|error| blocked(&[format!("the policies do not load: {error}")]));
    let routing = load_routing(&root(), &[], &policies.security).unwrap_or_else(|error| {
        blocked(&[format!(
            "policies/model_routing.yaml does not load: {error}"
        )])
    });
    (policies, routing)
}

impl RealBench {
    fn start(settings: &Settings, policies: LoadedPolicies, mut routing: LoadedRouting) -> Self {
        // The run waits for the owner between its containers, up to `human_wait` at each wait.
        // The automatic tests' five minutes would end it during the first one (the twelfth run on
        // 2026-11-16 was ended so, waiting on the specification). Two waits and an hour of work
        // bound it instead.
        let lock = DockerLock::take_holding(settings.human_wait * 2 + Duration::from_secs(3600));
        let run = format!("real-{}", std::process::id());
        let scratch = root().join("target/e2e-real").join(&run);
        let _ = std::fs::remove_dir_all(&scratch);
        for directory in [
            "keys",
            "artifacts",
            "tokens",
            "workspaces",
            "specs",
            "probe-specs",
        ] {
            std::fs::create_dir_all(scratch.join(directory)).expect("a scratch directory");
        }
        // The job budget of this run: the policy's, or the lower amount the owner named.
        if settings.budget_micro_usd < routing.policy.job.max_micro_usd {
            let mut lowered = (*routing.policy).clone();
            lowered.job.max_micro_usd = settings.budget_micro_usd;
            routing.policy = Arc::new(lowered);
        }
        let redactor = Arc::new(redactor_from_policy(&policies.security).expect("a redactor"));
        // The token is registered with the redactor by exact value before anything can print it.
        let text = std::fs::read_to_string(&settings.token_file).expect("the token file");
        let token = ProviderKey::subscription_token(&text).expect("a subscription token");
        let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
        secrets
            .register(SecretKind::SubscriptionToken, text.trim())
            .expect("the token is registered with the redactor");
        let core = BrokerCore::new(BrokerParts {
            clock: Arc::new(SystemClock),
            ids: Arc::new(RandomIds::new().expect("random")),
            entropy: Arc::new(SystemEntropy),
            prices: Arc::new(price_table(&routing.policy).expect("prices")),
            caps: broker_caps(&routing.policy).expect("caps"),
            audit: Arc::new(MemoryAudit::new()),
        });
        let broker = BrokerServer::start(
            BrokerServerConfig {
                listen: "0.0.0.0:0".parse().expect("an address"),
                upstreams: vec![
                    UpstreamConfig::subscription(
                        Provider::Anthropic,
                        "https://api.anthropic.com",
                        token,
                    )
                    .expect("an upstream"),
                ],
                expected_job: None,
                limits: ServerLimits::default(),
            },
            core.clone(),
        )
        .expect("the broker listener starts");
        let verify = live::image("verify");
        let (resolved, listing, why) = live::docker(&[
            "run",
            "--rm",
            "--pull=never",
            "--label",
            "factory.test=true",
            "--label",
            &format!("factory.test.run={run}"),
            &verify,
            "getent",
            "hosts",
            "host.docker.internal",
        ]);
        if !resolved {
            blocked(&[format!(
                "host.docker.internal does not resolve in a container: {why}"
            )]);
        }
        let host_ip = listing
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let definition_commit = Command::new("git")
            .arg("-C")
            .arg(root())
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
            .filter(|sha| sha.len() == 40)
            .unwrap_or_else(|| {
                blocked(&["git cannot name the commit of this checkout".to_owned()])
            });
        Self {
            root: root(),
            scratch,
            run,
            policies,
            routing,
            redactor,
            core,
            broker,
            host_ip,
            definition_commit,
            _lock: lock,
        }
    }

    /// The worker's configuration for this run, in the production profile.
    fn config_text(&self, settings: &Settings, env: &Env, installation: u64) -> String {
        live::write_private(&self.scratch.join("keys/decisions"), &live::random_hex(32));
        live::write_private(&self.scratch.join("advisory.date"), "2026-10-27\n");
        worker_config(&ConfigInputs {
            root: &self.root,
            scratch: &self.scratch,
            run: &self.run,
            host: &self.host_ip,
            port: self.broker.local_addr().port(),
            token_file: &settings.token_file,
            app_id: settings.app_id,
            key_file: &settings.key_file,
            repo: &settings.repo,
            tenant: env.a.id.as_uuid(),
            installation,
            owner: env.a.operator.principal.as_uuid(),
            now: SystemClock.now().to_string(),
            commit: &self.definition_commit,
            docker_host: std::env::var("DOCKER_HOST")
                .ok()
                .filter(|host| !host.is_empty()),
        })
    }
}

/// What the worker's configuration of a real run is made of.
pub struct ConfigInputs<'a> {
    pub root: &'a Path,
    pub scratch: &'a Path,
    pub run: &'a str,
    /// Where the sidecar finds the broker: the host's address on the daemon's network.
    pub host: &'a str,
    pub port: u16,
    pub token_file: &'a Path,
    pub app_id: u64,
    pub key_file: &'a Path,
    pub repo: &'a str,
    pub tenant: uuid::Uuid,
    pub installation: u64,
    /// The principal of the owner, who states the App is not on the bypass list.
    pub owner: uuid::Uuid,
    pub now: String,
    pub commit: &'a str,
    /// The daemon the worker's `docker` client talks to, as `DOCKER_HOST` says. The worker runs
    /// the client with an empty environment, so the run passes on its own `DOCKER_HOST` here. On
    /// a Mac that is a Linux VM with AppArmor (Colima): Docker Desktop has none, and the
    /// production profile refuses a sandbox without it.
    pub docker_host: Option<String>,
}

/// The worker's configuration of a real run, in the production profile.
pub fn worker_config(inputs: &ConfigInputs<'_>) -> String {
    {
        format!(
            "profile: production\n\
             protected_checkout: {root}\n\
             definitions_root: {root}\n\
             database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
             artifacts: {{ root: {scratch}/artifacts }}\n\
             sandbox:\n  images_catalog: {root}/infra/sandbox-images/images.json\n  token_root: {scratch}/tokens\n  workspace_root: {scratch}/workspaces\n  platform: linux/arm64\n  owner: factory-real-run\n  labels: {{ factory.test: 'true', factory.test.run: '{run}' }}\n  remote: {{ https_host: github.com }}\n  sidecar_command: [--mode, broker, --listen, '0.0.0.0:8443', --upstream, '{host}:{port}', --job, real-run]\n{docker_host}\
             broker:\n  listen: '127.0.0.1:0'\n  upstreams:\n    - {{ provider: anthropic, base_url: 'https://api.anthropic.com', key_file: {token} }}\n\
             github:\n  app_id: {app_id}\n  key_file: {key}\n  api_base_url: 'https://api.github.com'\n  installations:\n    - {{ tenant: {tenant}, repository: {repo}, installation_id: {installation} }}\n  bypass_attestations:\n    - {{ tenant: {tenant}, repository: {repo}, principal: {owner}, recorded_at: '{now}' }}\n\
             registry: {{ base_url: 'https://crates.io', user_agent: 'software-factory end-to-end run' }}\n\
             advisory_database: {{ date_file: {scratch}/advisory.date }}\n\
             decisions: {{ key_file: {scratch}/keys/decisions }}\n\
             stages: {{ definition_commit: {commit} }}\n\
             worker:\n  tenants: [{tenant}]\n",
            root = inputs.root.display(),
            scratch = inputs.scratch.display(),
            run = inputs.run,
            host = inputs.host,
            port = inputs.port,
            token = inputs.token_file.display(),
            app_id = inputs.app_id,
            key = inputs.key_file.display(),
            repo = inputs.repo,
            tenant = inputs.tenant,
            installation = inputs.installation,
            owner = inputs.owner,
            now = inputs.now,
            commit = inputs.commit,
            docker_host = inputs
                .docker_host
                .as_deref()
                .map(|host| format!("  docker_host: '{host}'\n"))
                .unwrap_or_default(),
        )
    }
}

// ---- `protection` -------------------------------------------------------------------------------

/// The protection of the fixture's default branch, as the factory's own GitHub adapter reads it
/// through the App, in the fields of the harness's `ProtectionFacts`.
pub async fn protection() {
    let (policies, routing) = loaded();
    let settings = Settings::read(false, &routing).unwrap_or_else(|reasons| blocked(&reasons));
    let installation = installation_of(&settings)
        .await
        .unwrap_or_else(|why| blocked(&[why]));
    let mut reasons = Vec::new();
    // The code owners of the copy on GitHub: real owners, no placeholder.
    match gh_json(&[
        "api",
        &format!("repos/{}/contents/CODEOWNERS", settings.repo),
    ]) {
        Ok(found) => {
            let text = found["content"]
                .as_str()
                .map(|encoded| encoded.replace('\n', ""))
                .and_then(|encoded| factory_github::base64_decode(&encoded))
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            if text.contains("@example-org/") {
                reasons.push(format!(
                    "the CODEOWNERS of {} still lists a placeholder handle (@example-org/...)",
                    settings.repo
                ));
            }
        }
        Err(why) => reasons.push(format!(
            "the CODEOWNERS of {} cannot be read: {why}",
            settings.repo
        )),
    }
    if !reasons.is_empty() {
        blocked(&reasons);
    }
    let facts = read_protection(&settings, &policies, installation)
        .await
        .unwrap_or_else(|why| blocked(&[why]));
    answer(&facts);
}

/// The configuration the `protection` command builds its GitHub adapter from. Only the GitHub
/// section is used. The configuration requires a sandbox and a broker, so both are written with
/// paths that this command never opens: it starts no container and no broker.
pub fn protection_config(
    root: &Path,
    app_id: u64,
    key_file: &Path,
    tenant: uuid::Uuid,
    repo: &str,
    installation: u64,
) -> String {
    format!(
        "profile: local\nprotected_checkout: {root}\ndefinitions_root: {root}\n\
         database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
         artifacts: {{ root: /tmp/unused }}\n\
         sandbox:\n  images_catalog: {root}/infra/sandbox-images/images.json\n  token_root: /tmp/unused/tokens\n  workspace_root: /tmp/unused/workspaces\n  platform: linux/arm64\n  owner: factory-real-run\n\
         broker:\n  listen: '127.0.0.1:0'\n  upstreams: []\n\
         github:\n  app_id: {app_id}\n  key_file: {key}\n  api_base_url: 'https://api.github.com'\n  installations:\n    - {{ tenant: {tenant}, repository: {repo}, installation_id: {installation} }}\n",
        root = root.display(),
        key = key_file.display(),
    )
}

/// The protection of the fixture's default branch through the factory's own GitHub adapter.
async fn read_protection(
    settings: &Settings,
    policies: &LoadedPolicies,
    installation: u64,
) -> Result<Value, String> {
    let tenant = TenantId::from_uuid(uuid_of("00000000-0000-4000-8000-00000000e2e1"));
    let text = protection_config(
        &root(),
        settings.app_id,
        &settings.key_file,
        tenant.as_uuid(),
        &settings.repo,
        installation,
    );
    let config = FactoryConfig::from_yaml(&text)
        .map_err(|error| format!("the configuration does not parse: {error}"))?;
    let github = config
        .github
        .as_ref()
        .ok_or("the configuration has no github section")?;
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("a redactor"));
    let adapter = factory_composition::external::github_adapter(
        Profile::Production,
        github,
        &policies.security,
        redactor,
        Arc::new(SystemClock),
    )
    .map_err(|(key, why)| format!("{key}: {why}"))?;
    let job = JobId::from_uuid(uuid_of("00000000-0000-4000-8000-00000000e2e2"));
    let scope = factory_ports::githost::GitScope {
        tenant,
        job,
        stage: StageKind::Intake,
        repo: factory_ports::paths::RepoRef::parse(&settings.repo)
            .map_err(|_| format!("{} is not owner/name", settings.repo))?,
    };
    use factory_ports::githost::{ChangeHost as _, IssueSource as _};
    let report = adapter.issue_source().repository_protection(&scope).await;
    let _ = adapter.change_host().revoke_job_tokens(job).await;
    let report = report.map_err(|error| {
        format!(
            "the protection of {} cannot be read through the App: {error:?}",
            settings.repo
        )
    })?;
    // The App cannot read the bypass list; the owner states it is not on it (the setup script
    // creates the ruleset with no bypass actor).
    Ok(protection_facts(&report, settings.app_id, false))
}

/// The harness's `ProtectionFacts` from the adapter's report. `app_may_bypass` is the owner's
/// statement (the App cannot read the bypass list); `enforce_admins` is not in the report and is
/// recorded as false, which no assertion reads.
pub fn protection_facts(
    report: &factory_ports::githost::ProtectionReport,
    app_id: u64,
    app_may_bypass: bool,
) -> Value {
    json!({
        "require_pull_request": report.requires_pull_request,
        "required_approvals": report.required_approving_reviews.unwrap_or(0),
        "required_checks": report.required_checks.iter().map(|check| json!({
            "context": check.context,
            "pinned_to_app": check.integration_id == Some(app_id),
        })).collect::<Vec<_>>(),
        "dismiss_stale_reviews": report.dismisses_stale_approvals,
        "enforce_admins": false,
        "allow_force_pushes": !report.blocks_force_push,
        "allow_deletions": !report.blocks_deletion,
        "require_code_owner_review": report.requires_code_owner_review,
        "app_may_bypass": app_may_bypass,
    })
}

// ---- `run` --------------------------------------------------------------------------------------

/// The issue a scenario files: its title and body, from `tests/end_to_end/issues`.
fn issue_text(scenario: &str) -> Result<(String, String, &'static str), String> {
    let (file, language) = match scenario {
        "E1" => ("json-output-en.json", "en"),
        "E2" => ("json-output-pt.json", "pt"),
        other => return Err(format!("the real wiring runs E1 and E2, not {other}")),
    };
    let text = std::fs::read_to_string(root().join("tests/end_to_end/issues").join(file))
        .map_err(|_| format!("tests/end_to_end/issues/{file} cannot be read"))?;
    let document: Value = serde_json::from_str(&text).map_err(|_| format!("{file} is not JSON"))?;
    let first = &document["revisions"][0];
    let title = first["title"].as_str().ok_or("no title")?.to_owned();
    let body = first["body"]
        .as_array()
        .ok_or("no body")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    Ok((title, body, language))
}

fn cli() -> String {
    var(CLI).unwrap_or_else(|| "factory-cli".to_owned())
}

/// The lines that tell the owner how to answer the questions a waiting specification asked, with
/// the exact command (one `Q-00N: <answer>` per question; `--` lets the text hold words such as
/// `--json`), then the questions. Empty when the stage asked none.
pub fn answer_lines(
    cli: &str,
    opts: &str,
    job: &str,
    run: &str,
    questions: &[(String, String)],
) -> String {
    if questions.is_empty() {
        return String::new();
    }
    let template: Vec<String> = questions
        .iter()
        .map(|(id, _)| format!("{id}: <answer>"))
        .collect();
    let mut text = format!(
        "\nAnswer it:   {cli} answer {opts} {job} {run} -- {}\n             The questions:",
        template.join(" ")
    );
    for (id, question) in questions {
        text.push_str(&format!("\n               {id}: {question}"));
    }
    text
}

/// What a person is asked to do while a stage run waits, with the exact command.
async fn ask_the_owner(rig: &LiveRig, api: &str, token_file: &Path, job: JobId, view: &JobView) {
    let Some(run) = view
        .stage_runs
        .iter()
        .find(|run| run.status == StageRunStatus::WaitingForHuman)
    else {
        return;
    };
    // The command comes first: `factory-cli` reads its options after the command name.
    let cli = cli();
    let opts = format!("--api {api} --token-file {}", token_file.display());
    let job_id = job.as_text();
    let run_id = run.id.as_text();
    let text = match run.kind {
        StageKind::Specification => {
            let evidence = rig.ledger_head(job, StageKind::Specification, run.id).await;
            let questions = rig.spec_questions(job, run.id).await;
            let answer = answer_lines(&cli, &opts, &job_id, &run_id, &questions);
            let Some(head) = rig.spec_draft_commit(job, run.id).await else {
                let reason = rig
                    .wait_reason(job, run.id)
                    .await
                    .unwrap_or_else(|| "unknown".to_owned());
                tell(&format!(
                    "WAITING FOR YOU: the specification of job {job_id} waits for a person, with no draft to approve (reason: {reason}).\n\
                     See why:        {cli} status {opts} --gates {job_id}\n\
                     Send it back:   {cli} rework {opts} {job_id} {run_id} target=SPECIFICATION \"<what to change>\"\n\
                     Or reject:      {cli} reject {opts} {job_id} {run_id} \"<why>\"{answer}"
                ));
                return;
            };
            format!(
                "WAITING FOR YOU: the specification draft of job {job_id} waits for your decision.\n\
                 Read it:     {cli} show-draft {opts} {job_id}\n\
                 Approve it:  {cli} approve {opts} {job_id} {run_id} head={head} evidence={} \"The specification says what the issue asked for.\"\n\
                 Or reject:   {cli} reject {opts} {job_id} {run_id} \"<why>\"{answer}",
                evidence.as_str()
            )
        }
        StageKind::Approval => {
            use factory_workflow::stages::approval::ApprovalSources as _;
            match rig.approvals.request(rig.tenant, run.id).await {
                Ok(request) => {
                    let evidence = rig.ledger_head(job, StageKind::Approval, run.id).await;
                    format!(
                        "WAITING FOR YOU: draft pull request #{} waits for your approval.\n\
                         Read it on GitHub, then\n\
                         Approve it:  {cli} approve {opts} {job_id} {run_id} head={} evidence={} \"The change does what the issue asked.\"\n\
                         Or reject:   {cli} reject {opts} {job_id} {run_id} \"<why>\"\n\
                         Approving does not merge anything: the pull request stays a draft.",
                        request.pull_request,
                        request.pr_head.as_str(),
                        evidence.as_str()
                    )
                }
                Err(_) => format!(
                    "WAITING FOR YOU: the approval stage of job {job_id} waits; see {cli} status {opts} {job_id}"
                ),
            }
        }
        StageKind::Review => format!(
            "WAITING FOR YOU: the code review of job {job_id} waits for a person.\n\
             No model other than the builder's own was available to review the work, at any tier\n\
             (policies/model_routing.yaml, independence). In subscription mode Claude Opus reviews\n\
             Claude Sonnet's work; check that the broker serves both Claude models.\n\
             What you can do now:\n\
             Send the work back:  {cli} rework {opts} {job_id} {run_id} target=IMPLEMENTATION \"<what to change>\"\n\
             Reject the job:      {cli} reject {opts} {job_id} {run_id} \"No independent reviewer is available.\"\n\
             The factory refuses an approval here: the review would pass with no review verdict.\n\
             See docs/guides/first-real-run.md, \"Who reviews the code\"."
        ),
        other => format!(
            "WAITING FOR YOU: the stage {} of job {job_id} waits for a person. See: {cli} status {opts} --gates {job_id}",
            other.as_str()
        ),
    };
    tell(&text);
}

fn waiting_run(view: &JobView) -> Option<(String, factory_domain::ids::StageRunId)> {
    view.stage_runs
        .iter()
        .find(|run| run.status == StageRunStatus::WaitingForHuman)
        .map(|run| (run.kind.as_str().to_owned(), run.id))
}

fn finished(view: &JobView) -> bool {
    view.status.is_terminal()
        || view
            .stage_runs
            .iter()
            .any(|run| matches!(run.status, StageRunStatus::Blocked))
}

/// Drives the job to its end, asking the owner at each wait, and returns the last view.
async fn drive_to_the_end(
    rig: &LiveRig,
    settings: &Settings,
    api: &str,
    token_file: &Path,
    job: JobId,
) -> Option<JobView> {
    // The stage run the owner was last asked about. The loop of the worker keeps running while a
    // stage waits, so that the owner's decision, sent through the API, is applied.
    let mut asked: Option<factory_domain::ids::StageRunId> = None;
    let mut waiting_since = Instant::now();
    loop {
        let view = rig
            .drive(job, 600, |view| {
                finished(view) || waiting_run(view).is_some_and(|(_, id)| asked != Some(id))
            })
            .await?;
        crate::full::print_states("real run", &view);
        if finished(&view) {
            return Some(view);
        }
        match waiting_run(&view) {
            Some((_, id)) if asked != Some(id) => {
                asked = Some(id);
                waiting_since = Instant::now();
                ask_the_owner(rig, api, token_file, job, &view).await;
            }
            Some(_) if waiting_since.elapsed() > settings.human_wait => {
                tell(&format!(
                    "Nobody decided within {} minutes; the run stops here and records what it has.",
                    settings.human_wait.as_secs() / 60
                ));
                return Some(view);
            }
            // Still waiting for the same decision, or working: drive on.
            _ => {}
        }
    }
}

/// What GitHub holds after the run, read with the owner's `gh` (read-only) and from the record of
/// the adapter's own requests.
fn real_github(
    settings: &Settings,
    recorder: &Recorder,
    documents: &BTreeMap<String, Value>,
    extras: &Extras,
    base_branch: &str,
    protection: Option<Value>,
) -> Value {
    let repo = &settings.repo;
    let base_after = branch_tip(repo, base_branch).unwrap_or_default();
    let delivery = documents.get("DELIVERY delivery-result");
    let mut pull_requests = Vec::new();
    let mut head_commits = Vec::new();
    let mut changed_paths: Vec<String> = Vec::new();
    let mut check_runs = Vec::new();
    let mut comments: Vec<String> = Vec::new();
    for found in gh_json(&[
        "api",
        &format!("repos/{repo}/issues/{}/comments", extras.issue_number),
    ])
    .ok()
    .and_then(|list| list.as_array().cloned())
    .unwrap_or_default()
    {
        comments.push(found["body"].as_str().unwrap_or_default().to_owned());
    }
    if let Some(number) = delivery.and_then(|doc| doc["pull_request"].as_u64())
        && let Ok(pr) = gh_json(&["api", &format!("repos/{repo}/pulls/{number}")])
    {
        let head_sha = pr["head"]["sha"].as_str().unwrap_or_default().to_owned();
        pull_requests.push(json!({
            "number": number,
            "draft": pr["draft"].as_bool().unwrap_or(false),
            "merged": pr["merged"].as_bool().unwrap_or(false),
            "state": pr["state"].as_str().unwrap_or_default(),
            "head_branch": pr["head"]["ref"].as_str().unwrap_or_default(),
            "head_sha": head_sha,
            "title": pr["title"].as_str().unwrap_or_default(),
            "body": pr["body"].as_str().unwrap_or_default(),
        }));
        if let Ok(compare) = gh_json(&[
            "api",
            &format!("repos/{repo}/compare/{}...{head_sha}", extras.base_before),
        ]) {
            for commit in compare["commits"].as_array().into_iter().flatten() {
                let sha = commit["sha"].as_str().unwrap_or_default().to_owned();
                let paths: Vec<String> = gh_json(&["api", &format!("repos/{repo}/commits/{sha}")])
                    .ok()
                    .and_then(|detail| detail["files"].as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|file| file["filename"].as_str().map(str::to_owned))
                    .collect();
                changed_paths.extend(paths.iter().cloned());
                head_commits.push(json!({
                    "sha": sha,
                    "message": commit["commit"]["message"].as_str().unwrap_or_default(),
                    "paths": paths,
                }));
            }
        }
        if let Ok(runs) = gh_json(&[
            "api",
            &format!("repos/{repo}/commits/{head_sha}/check-runs"),
        ]) {
            for run in runs["check_runs"].as_array().into_iter().flatten() {
                check_runs.push(json!({
                    "name": run["name"].as_str().unwrap_or_default(),
                    "conclusion": run["conclusion"].as_str().unwrap_or("in_progress"),
                    "head_sha": run["head_sha"].as_str().unwrap_or_default(),
                }));
            }
        }
        for found in gh_json(&["api", &format!("repos/{repo}/issues/{number}/comments")])
            .ok()
            .and_then(|list| list.as_array().cloned())
            .unwrap_or_default()
        {
            comments.push(found["body"].as_str().unwrap_or_default().to_owned());
        }
    }
    let name = repo.split_once('/').map_or(repo.as_str(), |(_, name)| name);
    let tokens: Vec<Value> = recorder
        .mints
        .lock()
        .expect("the lock is never poisoned")
        .iter()
        .enumerate()
        .map(|(index, (permissions, repositories))| {
            json!({
                "id": format!("installation-token-{}", index + 1),
                "permissions": permissions,
                "repositories": repositories.iter().map(|listed| {
                    if listed == name { repo.clone() } else { listed.clone() }
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    let requests: Vec<Value> = recorder
        .requests
        .lock()
        .expect("the lock is never poisoned")
        .iter()
        .map(|(method, path)| json!({ "method": method, "path": path }))
        .collect();
    json!({
        "repository": repo,
        "base_branch": base_branch,
        "base_sha_before": extras.base_before,
        "base_sha_after": base_after,
        "pull_requests": pull_requests,
        "head_commits": head_commits,
        "head_files": {},
        "changed_paths": changed_paths,
        "check_runs": check_runs,
        "comments": comments,
        "requests": requests,
        "tokens": tokens,
        "protection": protection,
    })
}

const REAL_LIMITATIONS: [&str; 6] = [
    "The database is a private copy made for this run. The fixture repository was seeded in it as registered, its project map attested and the repository enabled by the owner, who works alone (a single-maintainer repository, finding REG-6); the registration commands were not part of the run.",
    "The statement that the factory's App is not on the bypass list of the fixture's ruleset is the owner's, written in the run's configuration (github.bypass_attestations): the App cannot read the bypass list. The fixture setup script creates the ruleset with no bypass actor.",
    "enforce_admins in the protection facts is not read from GitHub (the adapter's report does not carry it) and is recorded as false; no assertion reads it.",
    "The advisory database is a stand-in with the fixed date 2026-10-27 and no advisory. The change the issue asks for adds no dependency.",
    "Subscription mode: only Claude runs, so no reviewer is of another model family than the author. The code review, the documentation review and the specification review are made by another Claude model than the one that wrote the work (policies/model_routing.yaml, independence, must_differ_by: model; ADR 0020, amendment of 2026-11-13). That is a weaker check than a review by another family: two models of one family tend to share blind spots. The audit log records each such review, and the evidence manifest lists the code review and the documentation review among its limitations when it happened.",
    "The spend is what the broker metered at the list price of policies/model_routing.yaml. On a subscription it is how much of the plan the job used, counted in dollars, not what the owner pays.",
];

/// Runs the scenario and prints the evidence.
pub async fn scenario() {
    let capture = e2e::spans::install();
    let scenario: &'static str = match var(SCENARIO).as_deref() {
        Some("E1") => "E1",
        Some("E2") => "E2",
        other => blocked(&[format!(
            "the real wiring runs E1 and E2, and was asked for {other:?}"
        )]),
    };
    let (policies, routing) = loaded();
    let mut reasons = match Settings::read(true, &routing) {
        Ok(_) => Vec::new(),
        Err(reasons) => reasons,
    };
    reasons.extend(machine_problems(&routing, true));
    if !reasons.is_empty() {
        blocked(&reasons);
    }
    let settings = Settings::read(true, &routing).unwrap_or_else(|reasons| blocked(&reasons));
    let (title, body, language) = issue_text(scenario).unwrap_or_else(|why| blocked(&[why]));
    let installation = installation_of(&settings)
        .await
        .unwrap_or_else(|why| blocked(&[why]));
    let (github_repository, default_branch, base_before) = repository_facts(&settings.repo)
        .unwrap_or_else(|why| {
            blocked(&[format!("{} cannot be read with gh: {why}", settings.repo)])
        });

    let bench = RealBench::start(&settings, policies, routing);
    let env = Env::start_with(Options {
        profile: Profile::Production,
        real: Some(RealSeed {
            tenant: settings.owner.tenant,
            installation,
            github_repository,
            full_name: settings.repo.clone(),
            default_branch: default_branch.clone(),
            map_commit: base_before.clone(),
            owner_github_id: settings.owner.github_id,
            owner_login: settings.owner.login.clone(),
            allowlist_text: settings.allowlist_text.clone(),
        }),
        ..Options::default()
    })
    .await;
    let text = bench.config_text(&settings, &env, installation);
    let logins = env.db.server.logins().await;
    let store: Arc<dyn factory_ports::store::Store> = Arc::new(
        factory_storage::pg::PgStore::connect(factory_composition::database::pools(
            crate::support::small_pool(env.db.url(&logins.worker)),
            crate::support::small_pool(env.db.url(&logins.engine)),
        ))
        .await
        .expect("the worker store becomes ready"),
    );
    let artifacts: Arc<dyn factory_ports::artifact::ArtifactStore> = Arc::new(
        factory_storage::artifact_fs::LocalFsArtifactStore::open(
            env.artifacts_root.clone(),
            64 * 1024 * 1024,
            Arc::new(
                factory_storage::pg::PgStore::connect(factory_composition::database::pools(
                    crate::support::small_pool(env.db.url(&logins.worker)),
                    crate::support::small_pool(env.db.url(&logins.engine)),
                ))
                .await
                .expect("the worker store becomes ready"),
            ),
        )
        .expect("the artifact root opens"),
    );
    let skills = factory_composition::spec_skills::bundle_for_writer(
        &bench.root,
        &bench.root,
        &bench.policies.security,
        "specification-writer",
    )
    .unwrap_or_else(|error| blocked(&[format!("the skills of the specification writer: {error}")]));
    let recorder = Arc::new(Recorder::default());
    let world = live::build_world_over(
        &bench,
        &env,
        &text,
        store,
        artifacts,
        Some(skills),
        Some(recorder.wrapper()),
    )
    .await;
    if !world.blocked.is_empty() {
        blocked(&world.blocked);
    }
    let rig = LiveRig::assemble(&bench, env, world).await;
    let mark = capture.mark();
    let started = Instant::now();

    // The owner, as the requester, files the issue and applies the label with their own login.
    let body_file = bench.scratch.join("issue-body.md");
    std::fs::write(&body_file, &body).expect("the issue body");
    let url = gh(&[
        "issue",
        "create",
        "--repo",
        &settings.repo,
        "--title",
        &title,
        "--body-file",
        &body_file.to_string_lossy(),
    ])
    .unwrap_or_else(|why| blocked(&[format!("the issue could not be filed with gh: {why}")]));
    let issue_number: u64 = url
        .trim()
        .rsplit('/')
        .next()
        .and_then(|number| number.parse().ok())
        .unwrap_or_else(|| blocked(&[format!("gh printed no issue address: {url}")]));
    gh(&[
        "issue",
        "edit",
        &issue_number.to_string(),
        "--repo",
        &settings.repo,
        "--add-label",
        "factory",
    ])
    .unwrap_or_else(|why| blocked(&[format!("the label could not be applied with gh: {why}")]));
    tell(&format!(
        "Filed issue #{issue_number} on {} and applied the label `factory` as you.",
        settings.repo
    ));

    // The job, through the API: no webhook. The API checks the requester by numeric GitHub id.
    let owner_token = rig.env().a.requester.token.clone();
    let out = out_dir();
    std::fs::create_dir_all(&out).expect("the output directory");
    let token_file = out.join("owner-api-token");
    live::write_private(&token_file, &owner_token);
    let api = format!("http://127.0.0.1:{}", rig.env().addr.port());
    let submitted = rig
        .env()
        .send(
            Req::post("/v1/jobs")
                .bearer(&owner_token)
                .header(
                    "idempotency-key",
                    &format!("real-{scenario}-{issue_number}"),
                )
                .json(&json!({
                    "repository_id": rig.env().a.repository.as_uuid().to_string(),
                    "text": format!("{title}\n\n{body}"),
                    "source_ref": format!("{}#{issue_number}", settings.repo),
                })),
        )
        .await;
    if submitted.status != 201 {
        blocked(&[format!(
            "the API refused the job ({}): {}",
            submitted.status,
            submitted.text()
        )]);
    }
    let job = JobId::parse(submitted.json()["job_id"].as_str().unwrap_or_default())
        .or_else(|_| JobId::parse(submitted.json()["id"].as_str().unwrap_or_default()))
        .unwrap_or_else(|_| blocked(&["the API's answer names no job".to_owned()]));
    tell(&format!(
        "Job {} started for issue #{issue_number}. The run's API is {api}; your token for it is in {}.\n\
         Budget of this job: {:.2} US dollars at list price (policies/model_routing.yaml, job.max_micro_usd{}).",
        job.as_text(),
        token_file.display(),
        settings.budget_micro_usd as f64 / 1_000_000.0,
        if var(BUDGET).is_some() {
            ", lowered by FACTORY_E2E_JOB_BUDGET_USD"
        } else {
            ""
        }
    ));

    let view = drive_to_the_end(&rig, &settings, &api, &token_file, job).await;
    rig.revoke_ended_jobs().await;
    let mut facts = BTreeMap::new();
    if let Some(view) = &view
        && let Some(run) = view.newest(StageKind::Approval)
    {
        use factory_workflow::stages::approval::ApprovalSources as _;
        if let Ok(request) = rig.approvals.request(rig.tenant, run.id).await {
            facts.insert(
                "risk_tier".to_owned(),
                json!(format!("{:?}", request.tier).to_lowercase()),
            );
        }
    }
    let spent = factory_composition::policy_broker::JobSpend::spent(bench.core.as_ref(), job).0;
    let extras = Extras {
        issue_number,
        base_before: base_before.clone(),
        span_mark: mark,
        took: started.elapsed(),
        facts,
        ..Extras::default()
    };
    let profile = RunProfile {
        wiring: "composed",
        mode: "production",
        usage: json!({
            "total_micro_usd": spent,
            "budget_micro_usd": settings.budget_micro_usd,
            "calls_after_exhaustion": 0,
        }),
        adapters: vec![
            (
                "store".to_owned(),
                "postgres-store".to_owned(),
                "real".to_owned(),
            ),
            (
                "artifact-store".to_owned(),
                "local-fs-artifact-store".to_owned(),
                "real".to_owned(),
            ),
            (
                "api-server".to_owned(),
                "factory-api-server".to_owned(),
                "real".to_owned(),
            ),
            (
                "change-host".to_owned(),
                "github-app-adapter".to_owned(),
                "real".to_owned(),
            ),
            (
                "issue-source".to_owned(),
                "github-app-adapter".to_owned(),
                "real".to_owned(),
            ),
            (
                "model-broker".to_owned(),
                "broker-subscription-anthropic".to_owned(),
                "real".to_owned(),
            ),
            (
                "sandbox".to_owned(),
                "docker-sandbox".to_owned(),
                "real".to_owned(),
            ),
        ],
        limitations: REAL_LIMITATIONS
            .iter()
            .map(|line| (*line).to_owned())
            .collect(),
        timings_note: "Durations of one real run on the owner's machine, against GitHub and the provider.",
    };
    let protection = read_protection(&settings, &bench.policies, installation)
        .await
        .ok();
    let tokens = Tokens {
        requester: owner_token.clone(),
    };
    let transitions = Transitions::load(&root());
    let collected = e2e::collect_from(
        &rig,
        Some(job),
        scenario,
        &tokens,
        extras,
        &transitions,
        &profile,
        async |documents: &BTreeMap<String, Value>, extras: &Extras| {
            real_github(
                &settings,
                &recorder,
                documents,
                extras,
                &default_branch,
                protection.clone(),
            )
        },
    )
    .await;
    let mut evidence = collected.evidence.clone();
    evidence["source_language"] = json!(language);
    e2e::write(&out.join("recording").join(scenario), &collected);
    answer(&evidence);
    tell(&format!(
        "The run is over: job {} is {}. The evidence is in {}.",
        job.as_text(),
        view.as_ref()
            .map_or("unreadable".to_owned(), |view| format!("{:?}", view.status)),
        out.display()
    ));
}

impl Sources for LiveRig {
    fn env(&self) -> &Env {
        &self.env
    }
    fn engine(&self) -> &factory_workflow::engine::Engine {
        &self.engine
    }
    fn store(&self) -> &Arc<dyn factory_ports::store::Store> {
        &self.store
    }
    fn artifacts(&self) -> &Arc<dyn factory_ports::artifact::ArtifactStore> {
        &self.artifacts
    }
    fn tenant(&self) -> TenantId {
        self.tenant
    }
}
