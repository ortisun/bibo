//! The adapters for the outside world, assembled from a loopback configuration.
//!
//! Real: the configuration parser, the policies, `assemble_external`, the GitHub App adapter (its
//! JWT signed with a throwaway RSA key, its HTTP over `ureq`), the crates.io client, the date file,
//! the router and the runtime set. Fake, and labelled: the GitHub server (FX-GH of the test kit),
//! the registry server, and the sandbox of the probe. Nothing leaves the machine.
#![allow(dead_code)]

#[path = "../../github/tests/common/mod.rs"]
mod gh;

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use factory_composition::config::FactoryConfig;
use factory_composition::external::{
    BlockedItem, ExternalInputs, ProbeInputs, ProbeReport, assemble_external, probe_at_startup,
    runtime_ids,
};
use factory_composition::indexing::ActiveJobs;
use factory_composition::policy_broker::{JobSpend, PolicyBroker};
use factory_composition::redaction::{RegisteringBroker, redactor_from_policy};
use factory_composition::routing::{broker_caps, price_table};
use factory_composition::sandbox_specs::PolicySpecs;
use factory_composition::startup::{LoadedRouting, load_policy, load_routing};
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::ids::TenantId;
use factory_domain::policy::security::ProviderCredentialMode;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_egress::broker::{BrokerCore, BrokerParts, MemoryAudit, SystemEntropy};
use factory_ports::agent::{AgentRuntime, ModelSelection};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, IdGenerator};
use factory_ports::githost::{
    ChangeHost, DraftPrRequest, GitHostError, GitScope, IssueRef, IssueSource,
};
use factory_ports::paths::BranchName;
use factory_ports::sandbox::{SandboxError, SandboxProvider, SandboxSession, SandboxSpec};
use factory_sandbox::container::images::ImageCatalog;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::http::{HttpResponse, HttpServer};
use gh::harness::{FIXTURE, World};
use gh::keys::{Form, Throwaway};
use serde_json::json;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn scratch(name: &str) -> PathBuf {
    let dir = root()
        .join("target/external-world")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn secret(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
    path
}

/// The pieces every test builds a configuration and the inputs from.
struct Lab {
    dir: PathBuf,
    key: PathBuf,
    date: PathBuf,
    routing: LoadedRouting,
    security: Arc<factory_domain::policy::SecurityPolicy>,
    core: Arc<BrokerCore>,
    artifacts: Arc<InMemoryArtifactStore>,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = scratch(name);
        let key = secret(
            &dir,
            "app.pem",
            &Throwaway::new(Form::Pkcs8).private_pem,
            0o600,
        );
        let date = secret(&dir, "advisory.date", "2026-10-27\n", 0o644);
        let policies = load_policy(&root(), &[]).expect("policies");
        let routing = load_routing(&root(), &[], &policies.security).expect("routing");
        let core = BrokerCore::new(BrokerParts {
            clock: Arc::new(SystemClock),
            ids: Arc::new(RandomIds::new().expect("random")),
            entropy: Arc::new(SystemEntropy),
            prices: Arc::new(price_table(&routing.policy).expect("prices")),
            caps: broker_caps(&routing.policy).expect("caps"),
            audit: Arc::new(MemoryAudit::new()),
        });
        Self {
            dir,
            key,
            date,
            routing,
            // The lab configures both tools, which only the API-key mode runs (ADR 0020). The
            // subscription tests switch it back with `in_mode`.
            security: in_mode(&policies.security, ProviderCredentialMode::ApiKey),
            core,
            artifacts: Arc::new(InMemoryArtifactStore::new()),
        }
    }

    /// A loopback configuration with everything set. `github_base` is the fake server.
    fn yaml(&self, github_base: &str, extra: &str) -> String {
        let tenant = scope(1, 1).tenant.as_uuid();
        format!(
            "profile: local\nprotected_checkout: {root}\ndefinitions_root: {root}\n\
             database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
             artifacts: {{ root: {dir} }}\n\
             sandbox: {{ images_catalog: {root}/infra/sandbox-images/images.json, token_root: {dir}/tokens, workspace_root: {dir}/ws }}\n\
             broker:\n  listen: '127.0.0.1:0'\n  upstreams:\n    - {{ provider: anthropic, base_url: 'http://127.0.0.1:9', key_file: {dir}/k }}\n    - {{ provider: openai, base_url: 'http://127.0.0.1:9', key_file: {dir}/k }}\n\
             github:\n  app_id: {app}\n  key_file: {key}\n  api_base_url: '{github_base}'\n  installations:\n    - {{ tenant: {tenant}, repository: {fixture}, installation_id: 1 }}\n\
             registry: {{ base_url: 'http://127.0.0.1:9', user_agent: factory-test }}\n\
             advisory_database: {{ date_file: {date} }}\n\
             runtimes: {{ declare_capabilities: true }}\n{extra}",
            root = root().display(),
            dir = self.dir.display(),
            key = self.key.display(),
            date = self.date.display(),
            app = 7,
            fixture = FIXTURE,
        )
    }

    fn inputs(&self, config: &Arc<FactoryConfig>, probes: ProbeReport) -> ExternalInputs<'_> {
        let redactor = Arc::new(redactor_from_policy(&self.security).expect("redactor"));
        ExternalInputs {
            config: Box::leak(Box::new(Arc::clone(config))),
            security: &self.security,
            routing: &self.routing,
            redactor,
            clock: Arc::new(SystemClock),
            artifacts: self.artifacts.clone() as Arc<dyn ArtifactStore>,
            jobs: Arc::new(ActiveJobs::new()),
            attestation: self.core.clone(),
            spec_skills: None,
            probes,
        }
    }
}

/// The repository policy with another credential mode.
fn in_mode(
    policy: &factory_domain::policy::SecurityPolicy,
    mode: ProviderCredentialMode,
) -> Arc<factory_domain::policy::SecurityPolicy> {
    let mut changed = policy.clone();
    changed.credentials.model_providers.mode = mode;
    Arc::new(changed)
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config(text: &str) -> Arc<FactoryConfig> {
    Arc::new(FactoryConfig::from_yaml(text).unwrap_or_else(|error| panic!("{error}\n{text}")))
}

fn lines(items: &[BlockedItem]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

// ---- assembling from a complete configuration ------------------------------------------------

#[test]
fn a_complete_loopback_configuration_assembles_every_port_and_blocks_nothing() {
    let lab = Lab::new("complete");
    let config = config(&lab.yaml("http://127.0.0.1:9", ""));
    let world = assemble_external(lab.inputs(&config, ProbeReport::Declared))
        .unwrap_or_else(|blocked| panic!("{:?}", lines(&blocked)));
    let ports = world.ports;
    assert_eq!(ports.runtime.fidelity(), Fidelity::Real);
    assert_eq!(ports.router.fidelity(), Fidelity::Real);
    assert_eq!(ports.issues.fidelity(), Fidelity::Real);
    assert_eq!(ports.changes.fidelity(), Fidelity::Real);
    // The declared list is labelled for what it is.
    assert_eq!(ports.probes.fidelity(), Fidelity::Fake);
    assert_eq!(ports.app.0, 7);
    assert!(
        ports
            .supply_chain
            .standings()
            .iter()
            .all(|(_, standing)| *standing == factory_composition::supply_chain::Standing::Real)
    );
    // Both tools exist, one per provider.
    assert_eq!(
        runtime_ids(&config)
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        ["claude-code-cli", "codex-cli"]
    );
}

/// ADR 0020: in the default subscription mode Codex is unavailable, and a configuration that lists
/// openai is BLOCKED by name rather than run without it.
#[test]
fn in_subscription_mode_an_openai_entry_is_blocked_by_name() {
    let mut lab = Lab::new("subscription-openai");
    lab.security = in_mode(&lab.security, ProviderCredentialMode::Subscription);
    let config = config(&lab.yaml("http://127.0.0.1:9", ""));
    let blocked = match assemble_external(lab.inputs(&config, ProbeReport::Declared)) {
        Ok(_) => panic!("nothing was blocked"),
        Err(blocked) => lines(&blocked),
    };
    assert!(
        blocked.iter().any(
            |line| line.starts_with("agent runtime codex-cli: broker.upstreams:")
                && line.contains("unavailable in subscription mode")
                && line.contains("does not fall back")
        ),
        "{blocked:?}"
    );
}

/// ADR 0020: in subscription mode with only the Anthropic entry, everything assembles and the one
/// tool is Claude Code.
#[test]
fn in_subscription_mode_the_anthropic_entry_alone_assembles_with_claude_code_only() {
    let mut lab = Lab::new("subscription-anthropic");
    lab.security = in_mode(&lab.security, ProviderCredentialMode::Subscription);
    let text = lab.yaml("http://127.0.0.1:9", "");
    let without_openai: String = text
        .lines()
        .filter(|line| !line.contains("provider: openai"))
        .map(|line| format!("{line}\n"))
        .collect();
    let config = config(&without_openai);
    let world = assemble_external(lab.inputs(&config, ProbeReport::Declared))
        .unwrap_or_else(|blocked| panic!("{:?}", lines(&blocked)));
    assert_eq!(world.ports.runtime.fidelity(), Fidelity::Real);
    assert_eq!(
        runtime_ids(&config)
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        ["claude-code-cli"]
    );
}

/// The lines of the BLOCKED list when one thing is taken out of a complete configuration.
fn blocked_without(
    name: &str,
    edit: impl FnOnce(String) -> String,
    probes: ProbeReport,
) -> Vec<String> {
    let lab = Lab::new(name);
    let config = config(&edit(lab.yaml("http://127.0.0.1:9", "")));
    match assemble_external(lab.inputs(&config, probes)) {
        Ok(_) => panic!("{name}: nothing was blocked"),
        Err(blocked) => lines(&blocked),
    }
}

fn names_the_key(lines: &[String], label: &str, key: &str) {
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with(&format!("{label}: {key}:"))),
        "no line starts with {label}: {key}: in {lines:#?}"
    );
}

#[test]
fn each_missing_key_is_named_by_the_blocked_line_it_causes() {
    // Break: a configuration with one missing key. The line names that key.
    let no_github = blocked_without(
        "no-github",
        |text| {
            let start = text.find("github:").expect("github");
            let end = text.find("registry:").expect("registry");
            format!("{}{}", &text[..start], &text[end..])
        },
        ProbeReport::Declared,
    );
    names_the_key(&no_github, "issue source", "github");
    names_the_key(&no_github, "change host", "github");
    assert_eq!(no_github.len(), 2, "{no_github:#?}");

    let no_installations = blocked_without(
        "no-installations",
        |text| {
            let start = text.find("  installations:").expect("installations");
            let end = text.find("registry:").expect("registry");
            format!("{}{}", &text[..start], &text[end..])
        },
        ProbeReport::Declared,
    );
    names_the_key(&no_installations, "issue source", "github.installations");
    names_the_key(&no_installations, "change host", "github.installations");

    let no_registry = blocked_without(
        "no-registry",
        |text| {
            let start = text.find("registry:").expect("registry");
            let end = text.find("advisory_database:").expect("advisory");
            format!("{}{}", &text[..start], &text[end..])
        },
        ProbeReport::Declared,
    );
    assert_eq!(no_registry.len(), 1, "{no_registry:#?}");
    names_the_key(&no_registry, "RegistryMetadata", "registry.base_url");

    let no_advisory = blocked_without(
        "no-advisory",
        |text| {
            let start = text.find("advisory_database:").expect("advisory");
            let end = text.find("runtimes:").expect("runtimes");
            format!("{}{}", &text[..start], &text[end..])
        },
        ProbeReport::Declared,
    );
    assert_eq!(no_advisory.len(), 1, "{no_advisory:#?}");
    names_the_key(
        &no_advisory,
        "AdvisoryDatabase",
        "advisory_database.date_file",
    );

    let no_providers = blocked_without(
        "no-providers",
        |text| {
            let start = text.find("  upstreams:").expect("upstreams");
            let end = text.find("github:").expect("github");
            format!("{}  upstreams: []\n{}", &text[..start], &text[end..])
        },
        ProbeReport::Declared,
    );
    names_the_key(&no_providers, "agent runtime", "broker.upstreams");
    names_the_key(&no_providers, "model router", "broker.upstreams");

    let probe_blocked = blocked_without(
        "probe-blocked",
        |text| text,
        ProbeReport::Blocked("the Docker daemon does not answer".to_owned()),
    );
    assert_eq!(probe_blocked.len(), 1, "{probe_blocked:#?}");
    names_the_key(&probe_blocked, "CapabilityProbes", "runtimes");
    assert!(probe_blocked[0].contains("the Docker daemon does not answer"));
}

#[test]
fn a_secret_key_file_that_group_can_read_blocks_the_github_ports_and_says_why() {
    // Break: the App's private key is readable by group.
    let lab = Lab::new("open-key");
    std::fs::set_permissions(&lab.key, std::fs::Permissions::from_mode(0o640)).expect("mode");
    let config = config(&lab.yaml("http://127.0.0.1:9", ""));
    let blocked = match assemble_external(lab.inputs(&config, ProbeReport::Declared)) {
        Ok(_) => panic!("an open key file was accepted"),
        Err(blocked) => lines(&blocked),
    };
    names_the_key(&blocked, "issue source", "github.key_file");
    names_the_key(&blocked, "change host", "github.key_file");
    assert!(
        blocked[0].contains("readable by group or others"),
        "{blocked:#?}"
    );
    // And a key file that is not a private key.
    std::fs::set_permissions(&lab.key, std::fs::Permissions::from_mode(0o600)).expect("mode");
    std::fs::write(&lab.key, "not a key").expect("write");
    std::fs::set_permissions(&lab.key, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let blocked = match assemble_external(lab.inputs(&config, ProbeReport::Declared)) {
        Ok(_) => panic!("junk was accepted as a key"),
        Err(blocked) => lines(&blocked),
    };
    names_the_key(&blocked, "issue source", "github.key_file");
}

#[test]
fn a_model_a_provider_may_not_serve_stops_the_router_and_names_the_key() {
    let blocked = blocked_without(
        "bad-model",
        |text| {
            text.replace("provider: anthropic, base_url: 'http://127.0.0.1:9', key_file:", "provider: anthropic, models: [gpt-6.1-sol], base_url: 'http://127.0.0.1:9', key_file:")
        },
        ProbeReport::Declared,
    );
    names_the_key(&blocked, "model router", "broker.upstreams");
}

// ---- the registry client ---------------------------------------------------------------------

#[tokio::test]
async fn the_registry_client_reads_the_documented_shape_and_treats_anything_else_as_unknown() {
    use factory_composition::config::RegistryConfig;
    use factory_composition::crates_io::CratesIoRegistry;
    use factory_composition::profile::Profile;
    use factory_workflow::gates::supply_chain::facts::{RegistryMetadata, RegistryRecord};

    let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, Option<String>)>::new()));
    let log = Arc::clone(&seen);
    let server = HttpServer::start("fx-crates-io", move |request| {
        log.lock().expect("lock").push((
            request.path().to_owned(),
            request.header("user-agent").map(str::to_owned),
        ));
        match request.path() {
            "/api/v1/crates/serde" => HttpResponse::json(
                200,
                &json!({"crate": {"created_at": "2014-12-19T21:49:41.309388+00:00",
                         "downloads": 42, "repository": "https://github.com/serde-rs/serde"},
                        "versions": [{"num": "1.0.0", "license": "MIT OR Apache-2.0"}]}),
            ),
            "/api/v1/crates/ghost" => {
                HttpResponse::json(404, &json!({"errors": [{"detail": "Not Found"}]}))
            }
            "/api/v1/crates/broken" => HttpResponse::text(500, "boom"),
            "/api/v1/crates/garbage" => HttpResponse::text(200, "<html>not json</html>"),
            "/api/v1/crates/huge" => HttpResponse::text(200, &"x".repeat(8192)),
            "/api/v1/crates/slow" => HttpResponse::json(200, &json!({"crate": {"downloads": 1}}))
                .with_delay(std::time::Duration::from_secs(3)),
            _ => HttpResponse::empty(404),
        }
    })
    .expect("the fake registry starts");
    let client = CratesIoRegistry::new(
        Profile::Local,
        &RegistryConfig {
            base_url: server.base_url(),
            user_agent: Some("factory-test (ops@example.org)".to_owned()),
            timeout_seconds: 1,
            max_response_bytes: 4096,
        },
    )
    .expect("a client");
    assert_eq!(client.fidelity(), Fidelity::Real);

    let serde = client.lookup("serde", "1.0.0").await;
    assert_eq!(serde.exists, Some(true));
    assert_eq!(serde.downloads, Some(42));
    assert_eq!(serde.license.as_deref(), Some("MIT OR Apache-2.0"));
    assert!(serde.first_published.is_some());

    // Only a 404 says something about the package.
    assert_eq!(client.lookup("ghost", "1.0.0").await.exists, Some(false));
    // Everything else is unknown: a server error, a page that is not JSON, an answer over the cap,
    // a request that takes longer than the timeout, a name that could change the URL.
    for name in ["broken", "garbage", "huge", "slow"] {
        assert_eq!(
            client.lookup(name, "1.0.0").await,
            RegistryRecord::default(),
            "{name}"
        );
    }
    assert_eq!(
        client.lookup("a/../b", "1.0.0").await,
        RegistryRecord::default()
    );
    // It identified itself, and the bad name never reached the server.
    let seen = seen.lock().expect("lock").clone();
    assert!(
        seen.iter()
            .all(|(_, agent)| agent.as_deref() == Some("factory-test (ops@example.org)"))
    );
    assert!(seen.iter().all(|(path, _)| !path.contains("..")));
}

#[tokio::test]
async fn a_registry_that_cannot_be_reached_is_unknown_and_not_an_error() {
    use factory_composition::config::RegistryConfig;
    use factory_composition::crates_io::CratesIoRegistry;
    use factory_composition::profile::Profile;
    use factory_workflow::gates::supply_chain::facts::{RegistryMetadata, RegistryRecord};
    let client = CratesIoRegistry::new(
        Profile::Local,
        &RegistryConfig {
            base_url: "http://127.0.0.1:1".to_owned(),
            user_agent: None,
            timeout_seconds: 1,
            max_response_bytes: 4096,
        },
    )
    .expect("a client");
    assert_eq!(
        client.lookup("serde", "1.0.0").await,
        RegistryRecord::default()
    );
}

// ---- GitHub over the loopback fake -----------------------------------------------------------

fn github_scope(stage: StageKind) -> GitScope {
    GitScope {
        stage,
        ..scope(1, 1)
    }
}

#[tokio::test]
async fn the_github_ports_talk_to_the_fake_server_with_narrowed_tokens_and_revoke_them_at_job_end()
{
    let lab = Lab::new("github");
    let world = World::new();
    let github_base = world.server.base_url();
    let config = FactoryConfig::from_yaml(
        &lab.yaml(&github_base, "")
            .replace("app_id: 7", &format!("app_id: {}", world.fake.app().id)),
    )
    .expect("config");
    let github = config.github.as_ref().expect("github");
    let adapter = factory_composition::external::github_adapter(
        config.profile,
        github,
        &lab.security,
        Arc::new(redactor_from_policy(&lab.security).expect("redactor")),
        world.clock.clone(),
    )
    .unwrap_or_else(|(key, reason)| panic!("{key}: {reason}"));
    let issues = adapter.issue_source();
    let changes = adapter.change_host();

    // The issue source reads the issue through the real adapter.
    let number = world.fake.add_issue(
        FIXTURE,
        "Add a word count command",
        "Count words.",
        "octocat",
        &["factory"],
    );
    let issue = issues
        .fetch_issue(
            &github_scope(StageKind::Intake),
            &IssueRef {
                repo: scope(1, 1).repo,
                number,
            },
        )
        .await
        .expect("the issue");
    assert_eq!(issue.title, "Add a word count command");

    // A fetch credential is narrowed to the one repository and to read permissions.
    let fetch = changes
        .fetch_target(&github_scope(StageKind::RepositoryIntelligence))
        .await
        .expect("a fetch target");
    let _ = fetch;
    let mints = world.fake.mints();
    let last = mints.last().expect("a token was minted");
    assert_eq!(
        last.requested_repositories.as_deref(),
        Some(&["fixture".to_owned()][..])
    );
    let permissions = last
        .requested_permissions
        .clone()
        .expect("permissions were asked for");
    assert!(
        permissions.values().all(|level| level == "read"),
        "a fetch token carries no write permission: {permissions:?}"
    );

    // The delivery stage may push, to a branch under factory/ only, and opens a draft pull request.
    changes
        .push_target(
            &github_scope(StageKind::Delivery),
            &BranchName::new("factory/job-1").expect("a branch"),
        )
        .await
        .expect("a push target");
    assert_eq!(
        changes
            .push_target(
                &github_scope(StageKind::Delivery),
                &BranchName::new("main").expect("a branch")
            )
            .await
            .unwrap_err(),
        GitHostError::BranchNotAllowed
    );
    let pull = changes
        .open_draft_pull_request(
            &github_scope(StageKind::Delivery),
            DraftPrRequest {
                head: BranchName::new("factory/job-1").expect("a branch"),
                base: BranchName::new("main").expect("a branch"),
                title: "Add a word count command".to_owned(),
                body: "The evidence manifest follows.".to_owned(),
            },
        )
        .await
        .expect("a draft pull request");
    assert_eq!(
        world
            .fake
            .pull_json(FIXTURE, pull.number)
            .expect("the pull")["draft"],
        json!(true)
    );
    assert!(world.fake.merge_attempts().is_empty(), "nothing merges");

    // Every token the adapter minted covers one repository, and while the job runs none is revoked.
    let live = world.fake.tokens();
    assert!(!live.is_empty());
    assert!(
        live.iter()
            .all(|token| token.repositories == ["example-org/fixture"])
    );
    assert!(live.iter().all(|token| token.revoked_at.is_none()));

    // The job ends: the sweep (which the worker runs before each claim) revokes them all, and a
    // later call for the job is refused.
    let revoked = adapter.sweep_orphans(&HashSet::new()).await;
    assert_eq!(revoked, live.len());
    assert!(
        world
            .fake
            .tokens()
            .iter()
            .all(|token| token.revoked_at.is_some())
    );
    assert!(!world.fake.revocations().is_empty());
    assert_eq!(
        changes
            .fetch_target(&github_scope(StageKind::RepositoryIntelligence))
            .await
            .unwrap_err(),
        GitHostError::Unauthorized
    );
}

#[tokio::test]
async fn break_a_wrong_installation_id_is_refused_by_the_server_and_no_token_is_used() {
    // The configuration names an installation the App does not have. The server refuses to mint,
    // the adapter reports the host as unavailable, and nothing is read or written.
    let lab = Lab::new("wrong-installation");
    let world = World::new();
    let config = FactoryConfig::from_yaml(
        &lab.yaml(&world.server.base_url(), "")
            .replace("app_id: 7", &format!("app_id: {}", world.fake.app().id))
            .replace("installation_id: 1 }", "installation_id: 987654 }"),
    )
    .expect("config");
    let adapter = factory_composition::external::github_adapter(
        config.profile,
        config.github.as_ref().expect("github"),
        &lab.security,
        Arc::new(redactor_from_policy(&lab.security).expect("redactor")),
        world.clock.clone(),
    )
    .unwrap_or_else(|(key, reason)| panic!("{key}: {reason}"));
    let number = world
        .fake
        .add_issue(FIXTURE, "A title", "A body.", "octocat", &["factory"]);
    let refusal = adapter
        .issue_source()
        .fetch_issue(
            &github_scope(StageKind::Intake),
            &IssueRef {
                repo: scope(1, 1).repo,
                number,
            },
        )
        .await
        .expect_err("a wrong installation reads nothing");
    println!("wrong installation: {refusal:?}");
    assert!(world.fake.tokens().is_empty(), "no token was minted");
    assert!(world.fake.mints().is_empty(), "the server minted nothing");
}

#[tokio::test]
async fn a_job_the_sweep_is_told_is_open_keeps_its_tokens() {
    // Break: the sweep must not revoke the tokens of a job that is still open.
    let lab = Lab::new("github-open");
    let world = World::new();
    let config = FactoryConfig::from_yaml(
        &lab.yaml(&world.server.base_url(), "")
            .replace("app_id: 7", &format!("app_id: {}", world.fake.app().id)),
    )
    .expect("config");
    let adapter = factory_composition::external::github_adapter(
        config.profile,
        config.github.as_ref().expect("github"),
        &lab.security,
        Arc::new(redactor_from_policy(&lab.security).expect("redactor")),
        world.clock.clone(),
    )
    .unwrap_or_else(|(key, reason)| panic!("{key}: {reason}"));
    let changes = adapter.change_host();
    changes
        .fetch_target(&github_scope(StageKind::RepositoryIntelligence))
        .await
        .expect("a fetch target");
    let open: HashSet<_> = [scope(1, 1).job].into_iter().collect();
    assert_eq!(adapter.sweep_orphans(&open).await, 0);
    assert!(
        world
            .fake
            .tokens()
            .iter()
            .all(|token| token.revoked_at.is_none())
    );
}

// ---- the start-up probe ----------------------------------------------------------------------

/// A sandbox provider that cannot make a sandbox, labelled fake.
struct Refusing(SandboxError);

#[async_trait]
impl SandboxProvider for Refusing {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn create_verified(
        &self,
        _: SandboxSpec,
        _: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        Err(self.0.clone())
    }

    async fn sweep_orphans(
        &self,
        _: &[factory_domain::ids::AttemptId],
    ) -> Result<Vec<factory_ports::sandbox::SandboxId>, SandboxError> {
        Ok(Vec::new())
    }
}

async fn probe_with(provider: SandboxError) -> ProbeReport {
    let lab = Lab::new("probe");
    let config = config(&lab.yaml("http://127.0.0.1:9", ""));
    let policies = load_policy(&root(), &[]).expect("policies");
    let catalog_text =
        std::fs::read_to_string(root().join("infra/sandbox-images/images.json")).expect("catalog");
    let catalog = ImageCatalog::from_json(&catalog_text, "linux/arm64").expect("catalog");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
    let policy_broker: Arc<dyn factory_ports::agent::ModelBroker> = Arc::new(PolicyBroker::new(
        lab.core.clone(),
        Arc::clone(&lab.routing.policy),
        lab.core.clone() as Arc<dyn JobSpend>,
    ));
    let registering = Arc::new(RegisteringBroker::new(policy_broker, redactor));
    let specs = PolicySpecs::new(
        Arc::clone(&policies.security),
        catalog,
        Arc::clone(&registering),
        lab.dir.join("scratch"),
    );
    let ids = RandomIds::new().expect("random");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    let parts = factory_composition::external::RuntimeParts {
        config: Arc::clone(&config),
        artifacts: lab.artifacts.clone(),
        redactor: Arc::new(redactor_from_policy(&policies.security).expect("redactor")),
        attestation: lab.core.clone(),
        spec_skills: None,
        mode: ProviderCredentialMode::ApiKey,
    };
    let runtimes: Vec<Arc<dyn AgentRuntime>> =
        factory_composition::external::runtimes_for_tenant(&parts, tenant);
    assert_eq!(runtimes.len(), 2);
    let jobs = ActiveJobs::new();
    probe_at_startup(ProbeInputs {
        sandbox: Arc::new(Refusing(provider)),
        specs: &specs,
        broker: &registering,
        jobs: &jobs,
        tenant,
        ids: &ids,
        model: ModelSelection {
            runtime: factory_ports::agent::RuntimeId::new("claude-code-cli").expect("runtime"),
            model: factory_domain::values::NonEmptyString::parse("claude-sonnet-5-5")
                .expect("model"),
        },
        runtimes,
    })
    .await
}

#[tokio::test]
async fn the_probe_is_blocked_with_the_reason_when_the_docker_daemon_does_not_answer() {
    match probe_with(SandboxError::DaemonUnavailable).await {
        ProbeReport::Blocked(reason) => {
            assert!(reason.contains("Docker daemon does not answer"), "{reason}")
        }
        other => panic!("{other:?}"),
    }
    match probe_with(SandboxError::ImageUnavailable).await {
        ProbeReport::Blocked(reason) => assert!(
            reason.contains("agent image is not on this host"),
            "{reason}"
        ),
        other => panic!("{other:?}"),
    }
}
