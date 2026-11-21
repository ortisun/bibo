//! The live-adapters rig: one `word-count` job through the REAL adapters, with only the model's
//! answers and GitHub's server faked, and both labelled.
//!
//! # What is real
//!
//! * The GitHub adapter (`factory-github`: the App JWT signed with a throwaway RSA key, installation
//!   tokens, the issue source, the change host, the preflight), built from the configuration by
//!   `assemble_external`, over loopback HTTP.
//! * The agent runtimes (Claude Code and Codex, whichever the routing policy assigns), the **real
//!   tools** of the pinned agent image, in the **real Docker sandbox**: the hardened container, its
//!   per-job internal network, and the real egress sidecar program in broker mode.
//! * The model broker (`BrokerCore` and its listener) with the routing policy in front of it
//!   (`PolicyBroker`), the real router (`PolicyModelRouter`) and the real price list.
//! * The git workspaces (host-side git over a bare repository), the Spec Kit provider, the
//!   validation gates in the real `verify` image, the engine, the API server, PostgreSQL, the
//!   worker's hook and the thirteen handlers.
//!
//! # What is fake
//!
//! * The model: [`provider::FakeProvider`], which plays the playbook over the wire in the two
//!   shapes the tools send.
//! * GitHub's server: [`github::GitHub`], FX-GH of the test kit over a real bare repository.
//! * The registry server for the dependency gates (it knows no package; the patch adds none).
//!
//! # What the dependency rules force
//!
//! The API and the worker cannot be linked together (DEP-01), so the loop is the few lines of
//! [`LiveRig::drive`], as in the other rigs of this package.

#![allow(dead_code)]

pub mod github;
pub mod provider;

use factory_domain::policy::security::ProviderCredentialMode;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use factory_composition::config::FactoryConfig;
use factory_composition::external::{
    ExternalInputs, ExternalWorld, ProbeInputs, ProbeReport, RuntimeParts, assemble_external,
    probe_at_startup, runtimes_for_tenant,
};
use factory_composition::indexing::ActiveJobs;
use factory_composition::policy_broker::{JobSpend, PolicyBroker};
use factory_composition::providers::{ProviderInputs, Providers, assemble, system_runner};
use factory_composition::redaction::{RegisteringBroker, redactor_from_policy};
use factory_composition::routing::{broker_caps, enabled_models, first_selection, price_table};
use factory_composition::sandbox_specs::PolicySpecs;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::{LoadedPolicies, LoadedRouting, load_policy, load_routing};
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::redaction::Redactor;
use factory_domain::vocabulary::StageKind;
use factory_egress::broker::{BrokerCore, BrokerParts, MemoryAudit, Provider, SystemEntropy};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_ports::agent::ModelBroker;
use factory_ports::store::Store;
use factory_sandbox::container::images::ImageCatalog;
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_testkit::fx::http::{HttpResponse, HttpServer};
use factory_workflow::engine::{Engine, JobView};

use crate::playbook::Playbook;
use crate::support::{Env, small_pool};

/// The cross-process lock of every real-Docker test that makes a network. The sandbox crate's file,
/// included here, so that this run and the sandbox, runtime and egress tests wait for each other.
#[path = "../../../../crates/sandbox/tests/support/docker_lock.rs"]
pub mod docker_lock;

use docker_lock::DockerLock;

/// The number of times a `docker create` was repeated because the daemon did not see a directory
/// that had just been made (see [`Printing`]). The report of the run says how many.
pub static CREATE_RETRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Prints the command line and the end of the standard error of a `docker` command that failed, so
/// that a `ProvisionFailed` has a reason in the log of the test. The arguments are the factory's own
/// flags and paths; the agent profile's token is a file path, never a value.
///
/// **A stand-in for a missing retry, labelled.** On Docker Desktop for Mac a directory that was
/// made a moment ago is sometimes not yet visible to the daemon, and `docker create` answers
/// "bind source path does not exist" (worker README, "The real Docker sandbox"; seen again in this
/// work). The sandbox adapter does not repeat the command. This wrapper does, up to six times a
/// second apart, and only for that one answer, and counts the repeats in [`CREATE_RETRIES`]; the
/// smallest fix for the adapter (owner `sandbox`) is the same bounded repeat.
pub struct Printing(pub Arc<dyn factory_ports::process::ProcessRunner>);

#[async_trait::async_trait]
impl factory_ports::process::ProcessRunner for Printing {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        self.0.fidelity()
    }

    async fn run(
        &self,
        req: factory_ports::process::SpawnRequest,
        cancel: &dyn factory_ports::clock::CancelSignal,
    ) -> Result<factory_ports::process::SpawnOutput, factory_ports::process::SpawnError> {
        let args = req.args.join(" ");
        let mut out = self.0.run(req.clone(), cancel).await;
        for _ in 0..6 {
            let not_seen = req.args.first().is_some_and(|word| word == "create")
                && matches!(&out, Ok(done) if done.exit_code != Some(0)
                    && String::from_utf8_lossy(&done.stderr).contains("bind source path does not exist"));
            if !not_seen {
                break;
            }
            CREATE_RETRIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Is the path really missing on the host, or only for the daemon? The answer is
            // printed, and the daemon is asked to list the parent, which makes it look again.
            if let Ok(done) = &out {
                let text = String::from_utf8_lossy(&done.stderr).into_owned();
                if let Some(at) = text.find("bind source path does not exist: /host_mnt") {
                    let path = text[at + "bind source path does not exist: /host_mnt".len()..]
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_owned();
                    let parent = std::path::Path::new(&path)
                        .parent()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    println!(
                        "BIND-SOURCE host_exists={} parent_exists={} {path}",
                        std::path::Path::new(&path).exists(),
                        std::path::Path::new(&parent).exists()
                    );
                    let _ = docker(&[
                        "run",
                        "--rm",
                        "--pull=never",
                        "--label",
                        "factory.test=true",
                        "--label",
                        &format!("factory.test.run={}", std::process::id()),
                        "--label",
                        &format!("factory.test.owner={OWNER}"),
                        "-v",
                        &format!("{parent}:/p:ro"),
                        &image("verify"),
                        "ls",
                        "-la",
                        "/p",
                    ]);
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            out = self.0.run(req.clone(), cancel).await;
        }
        if std::env::var_os("LIVE_TRACE").is_some() {
            let short: String = args.chars().take(150).collect();
            match &out {
                Ok(done) => println!("DOCKER-TRACE {short} => {:?}", done.exit_code),
                Err(error) => println!("DOCKER-TRACE {short} => error {error:?}"),
            }
        }
        match &out {
            Ok(done) if done.exit_code != Some(0) => println!(
                "DOCKER failed: {args}\n  exit {:?}: {}",
                done.exit_code,
                String::from_utf8_lossy(&done.stderr)
            ),
            Err(error) => println!("DOCKER error: {args}: {error:?}"),
            _ => {}
        }
        out
    }
}

/// The label value that says which test made an object. A sweep removes only what carries it and
/// the label of a process that is gone.
pub const OWNER: &str = "live-adapters";

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// `bytes` random bytes as hex, from the operating system, so no key-shaped literal sits in the
/// source.
pub fn random_hex(bytes: usize) -> String {
    use std::io::Read as _;
    let mut buffer = vec![0_u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .expect("random bytes");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs `docker` and returns whether it succeeded, its standard output and its standard error.
pub fn docker(args: &[&str]) -> (bool, String, String) {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("the docker client runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    )
}

fn process_is_alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Removes the containers and networks that carry this test's owner label and the run label
/// `run`. Nothing else is touched, and nothing is pruned.
pub fn remove_run(run: &str) {
    let owner = format!("label=factory.test.owner={OWNER}");
    let mine = format!("label=factory.test.run={run}");
    let (_, ids, _) = docker(&["ps", "-a", "-q", "--filter", &owner, "--filter", &mine]);
    for id in ids.split_whitespace() {
        let _ = docker(&["rm", "-f", "-v", id]);
    }
    let (_, ids, _) = docker(&["network", "ls", "-q", "--filter", &owner, "--filter", &mine]);
    for id in ids.split_whitespace() {
        let _ = docker(&["network", "rm", id]);
    }
}

/// Removes what an earlier run of this test left when its process died: the objects that carry
/// the owner label and the run label of a process that is not alive.
pub fn sweep_dead_runs() {
    let owner = format!("label=factory.test.owner={OWNER}");
    let (_, listing, _) = docker(&[
        "ps",
        "-a",
        "--filter",
        &owner,
        "--format",
        "{{.ID}} {{.Label \"factory.test.run\"}}",
    ]);
    let mut dead = std::collections::BTreeSet::new();
    for line in listing.lines() {
        if let Some((_, pid)) = line.split_once(' ')
            && !pid.is_empty()
            && !process_is_alive(pid)
        {
            dead.insert(pid.to_owned());
        }
    }
    for pid in dead {
        remove_run(&pid);
    }
}

/// The world around the pipeline: the lock on the daemon's network pool, the broker, the fake
/// provider and the policies.
pub struct Lab {
    pub root: PathBuf,
    pub run: String,
    pub scratch: PathBuf,
    pub provider: provider::FakeProvider,
    pub playbook: Arc<Playbook>,
    pub provider_key: String,
    pub core: Arc<BrokerCore>,
    pub audit: Arc<MemoryAudit>,
    pub broker: BrokerServer,
    pub host_ip: String,
    pub policies: LoadedPolicies,
    pub routing: LoadedRouting,
    pub redactor: Arc<Redactor>,
    _lock: DockerLock,
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.broker.shutdown();
        remove_run(&self.run);
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// The reference of an image of the catalog, or a `BLOCKED:` panic when it is not ready or not on
/// this host. Images are never pulled.
pub fn image(kind: &str) -> String {
    let text = std::fs::read_to_string(root().join("infra/sandbox-images/images.json"))
        .expect("the image catalog");
    let catalog: serde_json::Value = serde_json::from_str(&text).expect("a JSON catalog");
    let entry = &catalog["platforms"]["linux/arm64"]["images"][kind];
    let reference = entry["reference"]
        .as_str()
        .unwrap_or_else(|| panic!("BLOCKED: the catalog names no {kind} image"));
    assert!(
        entry["status"] == "ready",
        "BLOCKED: the {kind} image is not ready in the catalog"
    );
    let (found, _, _) = docker(&["image", "inspect", "--format", "{{.Id}}", reference]);
    assert!(
        found,
        "BLOCKED: the image {reference} is not on this host (images are never pulled)"
    );
    reference.to_owned()
}

impl Lab {
    /// Starts the world. A `BLOCKED:` panic when the Docker daemon does not answer or an image is
    /// missing, which is never a pass.
    pub fn start(playbook: Arc<Playbook>) -> Self {
        let answers = Command::new("timeout")
            .args(["20", "docker", "info"])
            .output()
            .is_ok_and(|out| out.status.success());
        assert!(
            answers,
            "BLOCKED: the Docker daemon does not answer, so no container can be made"
        );
        let verify = image("verify");
        let _agent = image("agent");
        let _sidecar = image("egress-sidecar");
        sweep_dead_runs();
        // The daemon's pool of network blocks is small and shared with the other stacks: every
        // test that makes a network holds this lock for as long as it lives.
        let lock = DockerLock::take();
        let run = std::process::id().to_string();
        // One directory for each lab, never the one a lab before it removed: on Docker Desktop for
        // Mac a directory made again under a name that was just removed is not seen by the daemon
        // for a while ("bind source path does not exist"), which looked like a lag of the file
        // sharing and was this.
        static LABS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let scratch = root().join("target/live").join(format!(
            "{run}-{}",
            LABS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        for directory in ["keys", "artifacts", "tokens", "workspaces", "remote"] {
            std::fs::create_dir_all(scratch.join(directory)).expect("a scratch directory");
        }

        let policies = load_policy(&root(), &[]).expect("the policies load");
        let routing =
            load_routing(&root(), &[], &policies.security).expect("the routing policy loads");
        let redactor = Arc::new(redactor_from_policy(&policies.security).expect("a redactor"));

        // The model broker, as the worker builds it: the core with the prices and the per-request
        // caps of the routing policy, and its listener on every interface, so that the sidecar
        // can reach it from the daemon's network.
        let audit = Arc::new(MemoryAudit::new());
        let core = BrokerCore::new(BrokerParts {
            clock: Arc::new(SystemClock),
            ids: Arc::new(RandomIds::new().expect("random")),
            entropy: Arc::new(SystemEntropy),
            prices: Arc::new(price_table(&routing.policy).expect("prices")),
            caps: broker_caps(&routing.policy).expect("caps"),
            audit: audit.clone(),
        });
        let provider_key = format!("fake-upstream-{}", random_hex(12));
        let provider = provider::FakeProvider::start(provider_key.clone(), Arc::clone(&playbook));
        let upstream = |which: Provider| {
            UpstreamConfig::new(
                which,
                &provider.base_url(),
                ProviderKey::new(provider_key.clone()).expect("a key"),
            )
            .expect("an upstream")
        };
        let broker = BrokerServer::start(
            BrokerServerConfig {
                listen: "0.0.0.0:0".parse().expect("an address"),
                upstreams: vec![upstream(Provider::Anthropic), upstream(Provider::OpenAi)],
                expected_job: None,
                limits: ServerLimits::default(),
            },
            core.clone(),
        )
        .expect("the broker listener starts");

        // Where the host is, as a container on the default bridge sees it. The sidecar is the
        // one container with a way out, and the broker is the only place it relays to.
        let (resolved, listing, why) = docker(&[
            "run",
            "--rm",
            "--pull=never",
            "--label",
            "factory.test=true",
            "--label",
            &format!("factory.test.run={run}"),
            "--label",
            &format!("factory.test.owner={OWNER}"),
            &verify,
            "getent",
            "hosts",
            "host.docker.internal",
        ]);
        assert!(
            resolved,
            "BLOCKED: host.docker.internal does not resolve: {why}"
        );
        let host_ip = listing
            .split_whitespace()
            .next()
            .expect("an address")
            .to_owned();

        Self {
            root: root(),
            run,
            scratch,
            provider,
            playbook,
            provider_key,
            core,
            audit,
            broker,
            host_ip,
            policies,
            routing,
            redactor,
            _lock: lock,
        }
    }

    /// The configuration of the worker for this lab, as text. `github` is the base URL of the
    /// fake GitHub, `registry` that of the fake registry.
    pub fn config_text(&self, env: &Env, github: &str, registry: &str, app_id: u64) -> String {
        for (name, text) in [
            (
                "keys/anthropic",
                format!("fake-anthropic-{}", random_hex(8)),
            ),
            ("keys/openai", format!("fake-openai-{}", random_hex(8))),
        ] {
            write_private(&self.scratch.join(name), &text);
        }
        write_private(
            &self.scratch.join("keys/app.pem"),
            &crate::live::app_key_pem(),
        );
        write_private(&self.scratch.join("advisory.date"), "2026-10-27\n");
        let tenant = env.a.id.as_uuid();
        format!(
            "profile: local\n\
             protected_checkout: {root}\n\
             definitions_root: {root}\n\
             database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
             artifacts: {{ root: {scratch}/artifacts }}\n\
             sandbox:\n  images_catalog: {root}/infra/sandbox-images/images.json\n  token_root: {scratch}/tokens\n  workspace_root: {scratch}/workspaces\n  platform: linux/arm64\n  owner: factory-live-test\n  labels: {{ factory.test: 'true', factory.test.run: '{run}', factory.test.owner: {OWNER} }}\n  remote: {{ directory: {scratch}/remote }}\n  sidecar_command: [--mode, broker, --listen, '0.0.0.0:8443', --upstream, '{host}:{port}', --job, live-run]\n\
             broker:\n  listen: '127.0.0.1:0'\n  upstreams:\n    - {{ provider: anthropic, base_url: '{provider}', key_file: {scratch}/keys/anthropic }}\n    - {{ provider: openai, base_url: '{provider}', key_file: {scratch}/keys/openai }}\n\
             github:\n  app_id: {app_id}\n  key_file: {scratch}/keys/app.pem\n  api_base_url: '{github}'\n  installations:\n    - {{ tenant: {tenant}, repository: {repo}, installation_id: {installation} }}\n  bypass_attestations:\n    - {{ tenant: {tenant}, repository: {repo}, principal: {operator}, recorded_at: '2026-10-28T09:00:00Z' }}\n\
             registry: {{ base_url: '{registry}', user_agent: factory-live-test }}\n\
             advisory_database: {{ date_file: {scratch}/advisory.date }}\n\
             worker:\n  tenants: [{tenant}]\n",
            root = self.root.display(),
            scratch = self.scratch.display(),
            run = self.run,
            host = self.host_ip,
            port = self.broker.local_addr().port(),
            provider = self.provider.base_url(),
            repo = env.a.full_name,
            installation = env.a.installation,
            operator = env.a.operator.principal.as_uuid(),
        )
    }

    /// The broker the engine issues tokens through: the broker core behind the routing policy,
    /// exactly as the worker builds it.
    pub fn policy_broker(&self) -> Arc<dyn ModelBroker> {
        Arc::new(PolicyBroker::new(
            self.core.clone(),
            Arc::clone(&self.routing.policy),
            self.core.clone() as Arc<dyn JobSpend>,
        ))
    }

    /// The image catalog for this host.
    pub fn catalog(&self) -> ImageCatalog {
        let text = std::fs::read_to_string(self.root.join("infra/sandbox-images/images.json"))
            .expect("the catalog");
        ImageCatalog::from_json(&text, "linux/arm64").expect("a catalog")
    }
}

/// What the world and the pipeline are built from: the lab of the loopback run, or the bench of a
/// real run (`real/mod.rs`), which has the real provider behind its broker.
pub trait Bench {
    /// The root of the repository: the policies, the agents and the images catalog.
    fn root(&self) -> &Path;
    /// The scratch directory of this run.
    fn scratch(&self) -> &Path;
    /// The policies.
    fn policies(&self) -> &LoadedPolicies;
    /// The routing policy.
    fn routing(&self) -> &LoadedRouting;
    /// The one redactor.
    fn redactor(&self) -> &Arc<Redactor>;
    /// The broker core behind the broker's listener.
    fn core(&self) -> &Arc<BrokerCore>;
    /// How the model credentials are held.
    fn mode(&self) -> ProviderCredentialMode;
    /// The profile the pipeline is assembled in.
    fn profile(&self) -> factory_composition::profile::Profile;
    /// The commit of the stage definitions the pipeline records.
    fn definition_commit(&self) -> String;

    /// The broker the engine issues tokens through: the broker core behind the routing policy,
    /// exactly as the worker builds it.
    fn policy_broker(&self) -> Arc<dyn ModelBroker> {
        Arc::new(PolicyBroker::new(
            self.core().clone(),
            Arc::clone(&self.routing().policy),
            self.core().clone() as Arc<dyn JobSpend>,
        ))
    }

    /// The image catalog for this host.
    fn catalog(&self) -> ImageCatalog {
        let text = std::fs::read_to_string(self.root().join("infra/sandbox-images/images.json"))
            .expect("the catalog");
        ImageCatalog::from_json(&text, "linux/arm64").expect("a catalog")
    }
}

impl Bench for Lab {
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
    // The lab runs both tools, Claude Code and Codex, so it runs the policy in API-key mode: in the
    // default subscription mode Codex is unavailable (ADR 0020).
    fn mode(&self) -> ProviderCredentialMode {
        ProviderCredentialMode::ApiKey
    }
    fn profile(&self) -> factory_composition::profile::Profile {
        factory_composition::profile::Profile::Local
    }
    fn definition_commit(&self) -> String {
        "1405df66cbe219b0bf6355bc3d60361a8376b6b4".to_owned()
    }
}

pub fn write_private(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, text).expect("a secret file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
}

/// A throwaway RSA key in PKCS#8 form, made by `openssl` into a scratch file and read back. The
/// test kit's key maker is in the GitHub adapter's tests, which this package does not include.
pub fn app_key_pem() -> String {
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        let dir = root()
            .join("target/live")
            .join(format!("key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("app.pem");
        let made = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&path)
            .output()
            .expect("openssl runs");
        assert!(made.status.success(), "BLOCKED: openssl cannot make a key");
        let pem = std::fs::read_to_string(&path).expect("the key");
        let _ = std::fs::remove_dir_all(dir);
        pem
    })
    .clone()
}

/// A registry server for the dependency gates. It knows no package, which is true of a patch that
/// adds none. Labelled fake.
pub fn registry_server() -> HttpServer {
    HttpServer::start("live-fake-registry", |_| {
        HttpResponse::json(
            404,
            &serde_json::json!({"errors": [{"detail": "Not Found"}]}),
        )
        .with_header("X-Factory-Fidelity", "fake")
    })
    .expect("the registry fake starts")
}

/// What a stage run took, for the report.
#[derive(Debug, Clone)]
pub struct Timed {
    pub kind: StageKind,
    pub outcome: String,
    pub took: Duration,
}

/// The ports of the outside world, built by `assemble_external` from the configuration, with the
/// real start-up probe of the runtimes.
pub struct World {
    /// The ports of the outside world, or `None` when something could not be built.
    pub built: Option<ExternalWorld>,
    /// One line for each item that could not be built, as the worker prints them after `BLOCKED: `.
    pub blocked: Vec<String>,
    pub probe: ProbeReport,
    pub providers: Providers,
    pub jobs: Arc<ActiveJobs>,
    pub config: Arc<FactoryConfig>,
}

/// Builds the real providers (Docker sandbox, git workspaces, Spec Kit), probes the runtimes in a
/// real `agent` sandbox, and assembles the outside world from the configuration.
pub async fn build_world(
    lab: &impl Bench,
    env: &Env,
    config_text: &str,
    store: Arc<dyn Store>,
    artifacts: Arc<dyn factory_ports::artifact::ArtifactStore>,
    spec_skills: Option<factory_runtime::SkillBundle>,
) -> World {
    build_world_over(lab, env, config_text, store, artifacts, spec_skills, None).await
}

/// [`build_world`], with the GitHub transport passed through `github_transport`: a real run keeps a
/// record of each request the adapter sends.
pub async fn build_world_over(
    lab: &impl Bench,
    env: &Env,
    config_text: &str,
    store: Arc<dyn Store>,
    artifacts: Arc<dyn factory_ports::artifact::ArtifactStore>,
    spec_skills: Option<factory_runtime::SkillBundle>,
    github_transport: Option<factory_composition::external::GithubTransportWrapper>,
) -> World {
    let config = Arc::new(
        FactoryConfig::from_yaml(config_text).unwrap_or_else(|error| {
            panic!("the live configuration does not parse: {error}\n{config_text}")
        }),
    );
    let jobs = Arc::new(ActiveJobs::new());
    let providers = assemble(ProviderInputs {
        config: &config,
        policies: lab.policies(),
        redactor: Arc::clone(lab.redactor()),
        artifacts: Arc::clone(&artifacts),
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("random")),
        store: Arc::clone(&store),
        jobs: Arc::clone(&jobs),
        runner: Arc::new(Printing(system_runner())),
    })
    .expect("the providers assemble");

    // The start-up probe, in a real sandbox of the real agent image.
    let registering = Arc::new(RegisteringBroker::new(
        lab.policy_broker(),
        Arc::clone(lab.redactor()),
    ));
    let specs = PolicySpecs::new(
        Arc::clone(&lab.policies().security),
        lab.catalog(),
        Arc::clone(&registering),
        lab.scratch().join("probe-specs"),
    );
    let enabled = enabled_models(&lab.routing().policy, &config.broker.upstreams).expect("enabled");
    let model = first_selection(&lab.routing().policy, StageKind::Intake, &enabled)
        .expect("a model for INTAKE");
    let parts = RuntimeParts {
        config: Arc::clone(&config),
        artifacts: Arc::clone(&artifacts),
        redactor: Arc::clone(lab.redactor()),
        attestation: lab.core().clone(),
        spec_skills: None,
        mode: lab.mode(),
    };
    let ids = RandomIds::new().expect("random");
    let probe = probe_at_startup(ProbeInputs {
        sandbox: Arc::clone(&providers.sandbox),
        specs: &specs,
        broker: &registering,
        jobs: &jobs,
        tenant: env.a.id,
        ids: &ids,
        model,
        runtimes: runtimes_for_tenant(&parts, env.a.id),
    })
    .await;

    // The bench says how the model credentials are held: the lab runs both tools, which only the
    // API-key mode allows; a real run uses the default subscription mode (ADR 0020).
    let mut in_mode = (*lab.policies().security).clone();
    in_mode.credentials.model_providers.mode = lab.mode();
    let external = assemble_external(ExternalInputs {
        config: &config,
        security: &in_mode,
        routing: lab.routing(),
        redactor: Arc::clone(lab.redactor()),
        clock: Arc::new(SystemClock),
        artifacts,
        jobs: Arc::clone(&jobs),
        attestation: lab.core().clone(),
        spec_skills,
        probes: probe.clone(),
        github_transport: github_transport.clone(),
    });
    let (built, blocked) = match external {
        Ok(world) => (Some(world), Vec::new()),
        Err(items) => (None, items.iter().map(ToString::to_string).collect()),
    };
    World {
        built,
        blocked,
        probe,
        providers,
        jobs,
        config,
    }
}

/// The worker's side of the run: the pipeline over the real adapters.
pub struct LiveRig {
    pub env: Env,
    pub engine: Arc<Engine>,
    pub requests: Arc<factory_composition::seams::StoreRequests>,
    pub hook: Arc<factory_composition::decisions::ClaimWork>,
    pub pump: Arc<factory_composition::drift::DriftPump>,
    pub preflight: Arc<factory_composition::preflight::ProtectionPreflight>,
    pub before_claim: Vec<Arc<dyn factory_composition::hooks::BeforeClaim>>,
    pub store: Arc<dyn Store>,
    pub artifacts: Arc<dyn factory_ports::artifact::ArtifactStore>,
    pub tenant: TenantId,
    pub jobs: Arc<ActiveJobs>,
    pub timings: Mutex<Vec<Timed>>,
    pub handlers: Vec<(StageKind, factory_domain::vocabulary::Fidelity)>,
    pub delivery: Arc<factory_composition::delivery::StoreDeliverySources>,
    pub approvals: Arc<factory_composition::delivery::StoreApprovalSources>,
    pub spec_drafts: Arc<factory_composition::specs::StoreSpecDrafts>,
    /// The workspaces, for the job's own object store: the evidence collector reads the
    /// specification commits and the documentation pages there.
    pub workspaces: Arc<dyn factory_ports::workspace::WorkspaceProvider>,
}

impl LiveRig {
    /// Assembles the pipeline from the world, as the worker's `assemble_loop` does.
    pub async fn start(lab: &Lab, env: Env, world: World, github: &github::GitHub) -> Self {
        let _ = github;
        Self::assemble(lab, env, world).await
    }

    /// Assembles the pipeline from the world on any bench.
    pub async fn assemble(lab: &impl Bench, env: Env, world: World) -> Self {
        assert!(
            world.blocked.is_empty(),
            "BLOCKED: the outside world cannot be assembled:\n{}",
            world.blocked.join("\n")
        );
        let built = world.built.expect("a complete world");
        let workspaces = Arc::clone(&world.providers.workspaces);
        let tenant = env.a.id;
        let logins = env.db.server.logins().await;
        let store = Arc::new(
            factory_storage::pg::PgStore::connect(factory_composition::database::pools(
                small_pool(env.db.url(&logins.worker)),
                small_pool(env.db.url(&logins.engine)),
            ))
            .await
            .expect("the worker store becomes ready"),
        );
        let store_dyn: Arc<dyn Store> = store.clone();
        let artifacts: Arc<dyn factory_ports::artifact::ArtifactStore> = Arc::new(
            LocalFsArtifactStore::open(env.artifacts_root.clone(), 64 * 1024 * 1024, store.clone())
                .expect("the artifact root opens"),
        );
        let allowlist = Arc::new(FileAllowlist::in_checkout(&env.checkout));
        let settings = factory_composition::config::StageSettings {
            label: "factory".to_owned(),
            definition_commit: Some(lab.definition_commit()),
            ..Default::default()
        };
        let sweep = factory_composition::token_sweep::RevokeEndedJobs::new(
            built.github.clone(),
            Arc::clone(&store_dyn),
            vec![tenant],
            Arc::clone(&world.jobs),
        );
        let pipeline = factory_composition::pipeline::assemble_pipeline(
            factory_composition::pipeline::PipelineInputs {
                profile: lab.profile(),
                settings,
                definitions_root: lab.root().to_path_buf(),
                policies: lab.policies().clone(),
                redactor: Arc::clone(lab.redactor()),
                store: Arc::clone(&store_dyn),
                artifacts: Arc::clone(&artifacts),
                clock: Arc::new(SystemClock),
                ids: Arc::new(RandomIds::new().expect("random")),
                providers: world.providers.clone(),
                catalog: lab.catalog(),
                sandbox_scratch: lab.scratch().join("specs"),
                broker: lab.policy_broker(),
                external: built.ports,
                allowlist,
                tenants: vec![tenant],
                decision_keys: Arc::clone(&env.state.decision_keys),
                tuning: factory_composition::pipeline::Tuning {
                    decorate: None,
                    markers: None,
                    // Shorter leases make a lost worker show sooner in a test. The production
                    // profile refuses any tuning, so a real run keeps the engine's own values.
                    engine: (lab.profile() != factory_composition::profile::Profile::Production)
                        .then(|| -> factory_composition::pipeline::EngineTuning {
                            Box::new(|config| {
                                config.lease_ttl = Duration::from_secs(60);
                                config.heartbeat_interval = Duration::from_secs(2);
                                config.teardown_grace = Duration::from_secs(5);
                            })
                        }),
                },
            },
        )
        .unwrap_or_else(|error| panic!("the pipeline assembles: {error}"));
        let factory_composition::pipeline::Pipeline {
            engine,
            handlers,
            hook,
            preflight,
            requests,
            drift,
            delivery,
            approvals,
            spec_drafts,
            ..
        } = pipeline;
        Self {
            env,
            engine,
            requests,
            hook,
            pump: drift,
            preflight,
            before_claim: vec![Arc::new(sweep)],
            store: store_dyn,
            artifacts,
            tenant,
            jobs: world.jobs,
            timings: Mutex::new(Vec::new()),
            handlers,
            delivery,
            approvals,
            spec_drafts,
            workspaces,
        }
    }

    /// The identity of a stage run, as a seam is given it.
    pub async fn identity(
        &self,
        job: JobId,
        stage_run: factory_domain::ids::StageRunId,
        kind: StageKind,
    ) -> factory_workflow::handlers::RunIdentity {
        let mut tx = self
            .store
            .begin(factory_domain::scope::TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
        let _ = tx.rollback().await;
        factory_workflow::handlers::RunIdentity {
            tenant: self.tenant,
            job,
            correlation,
            stage_run,
            kind,
        }
    }

    /// The head of the job's evidence ledger: what a person looking at the job now has seen.
    pub async fn ledger_head(
        &self,
        job: JobId,
        kind: StageKind,
        stage_run: factory_domain::ids::StageRunId,
    ) -> factory_domain::values::Sha256Digest {
        use factory_workflow::stages::delivery::DeliverySources as _;
        let identity = self.identity(job, stage_run, kind).await;
        self.delivery
            .ledger(&identity)
            .await
            .expect("the ledger verifies and is read")
            .head_hash
    }

    /// The commit of the specification draft the stage kept for a person to read, or `None` when
    /// the stage run waits for another reason (a reviewer that asks a person, for one): the
    /// engine can stop a run for a person without the stage keeping a draft.
    pub async fn spec_draft_commit(
        &self,
        job: JobId,
        stage_run: factory_domain::ids::StageRunId,
    ) -> Option<String> {
        use factory_workflow::stages::specification::SpecDrafts as _;
        let identity = self
            .identity(job, stage_run, StageKind::Specification)
            .await;
        // Only a kept contract is a draft to approve. A record with no contract is a stop on a
        // question, and it is answered, not approved (the thirtieth real run).
        self.spec_drafts
            .load(&identity)
            .await
            .expect("the draft is readable")
            .filter(|draft| !draft.contract.is_empty())
            .map(|draft| draft.commit.as_str().to_owned())
    }

    /// The question the independent reviewer of the specification put to a person, when its
    /// verdict was `NEEDS_HUMAN`: the `human_question` of the review the stage kept with its
    /// record. `None` when the reviewer asked nothing.
    pub async fn spec_review_question(
        &self,
        job: JobId,
        stage_run: factory_domain::ids::StageRunId,
    ) -> Option<String> {
        use factory_workflow::stages::specification::SpecDrafts as _;
        let identity = self
            .identity(job, stage_run, StageKind::Specification)
            .await;
        let draft = self.spec_drafts.load(&identity).await.ok()??;
        let evidence: serde_json::Value = serde_json::from_slice(&draft.evidence).ok()?;
        evidence
            .pointer("/review/answer/human_question")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    /// The questions the specification stage asked when it kept its draft, as `(id, question)`:
    /// the `questions` of the evidence it kept with the draft. Empty when it asked none or kept no
    /// draft.
    pub async fn spec_questions(
        &self,
        job: JobId,
        stage_run: factory_domain::ids::StageRunId,
    ) -> Vec<(String, String)> {
        use factory_workflow::stages::specification::SpecDrafts as _;
        let identity = self
            .identity(job, stage_run, StageKind::Specification)
            .await;
        let Some(draft) = self
            .spec_drafts
            .load(&identity)
            .await
            .expect("the draft is readable")
        else {
            return Vec::new();
        };
        let evidence: serde_json::Value =
            serde_json::from_slice(&draft.evidence).unwrap_or(serde_json::Value::Null);
        evidence
            .get("questions")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|pair| {
                Some((
                    pair.get(0)?.as_str()?.to_owned(),
                    pair.get(1)?.as_str()?.to_owned(),
                ))
            })
            .collect()
    }

    /// Why a stage run waits for a person: the reason code of the newest transition the store
    /// holds for it, such as `reviewer-needs-a-person`.
    /// What the agent of a waiting stage run said a person must know or decide: the `detail` of
    /// the request it left as its last attempt's output. `None` when it said nothing more.
    pub async fn wait_detail(&self, stage_run: factory_domain::ids::StageRunId) -> Option<String> {
        let scope = factory_domain::scope::TenantScope::new(self.tenant);
        let mut tx = self.store.begin(scope).await.ok()?;
        let attempts = tx.list_attempts(stage_run).await.ok()?;
        let _ = tx.rollback().await;
        let output = attempts
            .iter()
            .rev()
            .find_map(|attempt| attempt.value.output.clone())?;
        let reference = factory_domain::contracts::ArtifactRef {
            sha256: output,
            media_type: factory_domain::values::MediaType::parse("application/json").ok()?,
            size_bytes: None,
        };
        let bytes = self.artifacts.get(&scope, &reference).await.ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        value
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    pub async fn wait_reason(
        &self,
        job: JobId,
        stage_run: factory_domain::ids::StageRunId,
    ) -> Option<String> {
        let mut tx = self
            .store
            .begin(factory_domain::scope::TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let events = tx
            .read_events(job, factory_ports::store::OutboxSeq::START, 5000)
            .await
            .expect("events");
        let _ = tx.rollback().await;
        let wanted = stage_run.to_string();
        events
            .iter()
            .rev()
            .map(|row| &row.event)
            .find(|event| {
                event.aggregate.kind.as_str() == "stage_run"
                    && event.aggregate.id.to_string() == wanted
            })
            .map(|event| {
                event
                    .reason_code
                    .as_ref()
                    .map_or_else(|| event.event_type.as_str().to_owned(), ToString::to_string)
            })
    }

    /// What a stopped job left, for the person reading a failure: the audit records, the status
    /// and gate of each stage run, and the failure reasons.
    pub async fn dump(&self, job: JobId) {
        let scope = factory_domain::scope::TenantScope::new(self.tenant);
        let mut tx = self.store.begin(scope).await.expect("a tx");
        let audit = tx
            .read_audit(factory_ports::store::AuditFilter::Job(job), 0, 2000)
            .await
            .expect("audit");
        let runs = tx.list_stage_runs(job).await.expect("stage runs");
        let _ = tx.rollback().await;
        for record in &audit {
            println!(
                "AUDIT {} {} | {} | {}",
                record.sequence,
                record.event.action.as_str(),
                record.event.subject,
                record.event.reason
            );
        }
        let mut tx = self.store.begin(scope).await.expect("a tx");
        let mut links = Vec::new();
        for run in &runs {
            let found = tx
                .list_stage_run_artifacts(run.value.id)
                .await
                .expect("links");
            links.push((run.value.kind, run.value.status, found));
        }
        let _ = tx.rollback().await;
        for (kind, status, found) in links {
            if status == factory_domain::state::StageRunStatus::Passed {
                continue;
            }
            println!("LINKS {kind:?} {status:?}");
            for link in found {
                let reference = factory_domain::contracts::ArtifactRef {
                    sha256: link.sha256.clone(),
                    media_type: factory_domain::values::MediaType::parse("application/json")
                        .expect("a media type"),
                    size_bytes: None,
                };
                let text = match self.artifacts.get(&scope, &reference).await {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    Err(error) => format!("(unreadable: {error:?})"),
                };
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
                    && let Some(list) = value["transcripts"].as_array()
                {
                    for hash in list.iter().filter_map(|h| h.as_str()) {
                        for media in ["text/plain", "application/json"] {
                            let probe = factory_domain::contracts::ArtifactRef {
                                sha256: factory_domain::values::Sha256Digest::parse(hash)
                                    .expect("a hash"),
                                media_type: factory_domain::values::MediaType::parse(media)
                                    .expect("a media type"),
                                size_bytes: None,
                            };
                            if let Ok(bytes) = self.artifacts.get(&scope, &probe).await {
                                let shown: String =
                                    String::from_utf8_lossy(&bytes).chars().take(6000).collect();
                                println!("  TRANSCRIPT {hash} ({media}): {shown}");
                            }
                        }
                    }
                }
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
                    && let Some(reports) = value["reports"].as_array()
                {
                    for report in reports {
                        println!(
                            "  REPORT {} {} | {} | failures {} | commands {}",
                            report["metadata"]["gate_id"],
                            report["outcome"],
                            report["reason"]
                                .as_str()
                                .unwrap_or_default()
                                .chars()
                                .take(300)
                                .collect::<String>(),
                            report["failures"]
                                .to_string()
                                .chars()
                                .take(600)
                                .collect::<String>(),
                            report["commands"]
                                .to_string()
                                .chars()
                                .take(900)
                                .collect::<String>(),
                        );
                    }
                }
                let short: String = text.chars().take(1200).collect();
                println!("  {:?} {} => {short}", link.direction, link.role.as_str());
            }
        }
        for run in runs {
            println!(
                "STAGE {:?} {:?} gate {:?}",
                run.value.kind, run.value.status, run.value.gate
            );
            if let Some(record) = run.value.gate
                && record.outcome != factory_domain::vocabulary::GateOutcome::Passed
                && let Some(hash) = record.report_sha256
            {
                let reference = factory_domain::contracts::ArtifactRef {
                    sha256: hash,
                    media_type: factory_domain::values::MediaType::parse("application/json")
                        .expect("a media type"),
                    size_bytes: None,
                };
                if let Ok(bytes) = self.artifacts.get(&scope, &reference).await {
                    let text: String = String::from_utf8_lossy(&bytes).chars().take(4000).collect();
                    println!("  GATE-REPORT {text}");
                }
            }
        }
    }

    /// The loop of a worker as a few lines: the request cache, the steps before the claim, the
    /// claim, the attempt with the drift pump served next to it. Returns the view when `done`
    /// holds or the time is up.
    pub async fn drive(
        &self,
        job: JobId,
        seconds: u64,
        done: impl Fn(&JobView) -> bool,
    ) -> Option<JobView> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
        let worker = factory_ports::store::WorkerId::new("worker-live-run").expect("a worker id");
        loop {
            let _ = self.requests.refresh(&[self.tenant]).await;
            for step in &self.before_claim {
                step.before_claim().await;
            }
            self.preflight.pass(self.tenant).await;
            self.hook.pass(self.tenant).await;
            let _ = self.engine.sweep().await;
            let claimed = self.engine.claim_next(&worker).await.expect("a claim");
            for attempt in claimed.started {
                let started = Instant::now();
                self.jobs.enter(attempt.job, attempt.tenant);
                self.jobs.enter_attempt(attempt.attempt, attempt.tenant);
                let outcome = {
                    let run = self.engine.run_attempt(&attempt);
                    tokio::pin!(run);
                    loop {
                        tokio::select! {
                            outcome = &mut run => break outcome,
                            _ = self.pump.serve_next(&self.engine) => {}
                        }
                    }
                };
                self.jobs.leave(attempt.job);
                self.jobs.leave_attempt(attempt.attempt);
                println!(
                    "LIVE-RUN {:?} {:?} in {:.1?}",
                    attempt.kind,
                    outcome,
                    started.elapsed()
                );
                self.timings
                    .lock()
                    .expect("the lock is never poisoned")
                    .push(Timed {
                        kind: attempt.kind,
                        outcome: format!("{outcome:?}"),
                        took: started.elapsed(),
                    });
            }
            if let Ok(view) = self.engine.job_view(self.tenant, job).await
                && done(&view)
            {
                return Some(view);
            }
            if tokio::time::Instant::now() > deadline {
                return self.engine.job_view(self.tenant, job).await.ok();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Runs the steps before a claim once more, which revokes the installation tokens of the jobs
    /// that are over.
    pub async fn revoke_ended_jobs(&self) {
        for step in &self.before_claim {
            step.before_claim().await;
        }
    }

    /// The seconds each stage took, summed over its attempts, in the order the stages ran.
    pub fn durations(&self) -> BTreeMap<String, Duration> {
        let mut found: BTreeMap<String, Duration> = BTreeMap::new();
        for timed in self.timings.lock().expect("lock").iter() {
            *found.entry(format!("{:?}", timed.kind)).or_default() += timed.took;
        }
        found
    }
}
