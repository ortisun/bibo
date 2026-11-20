//! The real providers are assembled from the configuration, by profile, and nothing starts a
//! container or a git process while they are assembled.

use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::config::{ConfigError, FactoryConfig, Remote};
use factory_composition::indexing::ActiveJobs;
use factory_composition::providers::{
    ProviderError, ProviderInputs, assemble, path_rules, spec_kit_config, system_runner,
};
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::redaction::Redactor;
use factory_domain::vocabulary::{ExecutionMode, Fidelity};
use factory_ports::artifact::ArtifactStore;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::FakeClock;
use factory_testkit::store::InMemoryStore;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn config_text(profile: &str, extra: &str) -> String {
    let root = root();
    format!(
        "profile: {profile}\n\
         protected_checkout: {root}\n\
         definitions_root: {root}\n\
         database:\n  tenant: {{ url_file: /run/secrets/db_worker, login: factory_worker }}\n  system: {{ url_file: /run/secrets/db_engine, login: factory_engine }}\n\
         artifacts: {{ root: /var/lib/factory/artifacts }}\n\
         sandbox:\n  images_catalog: {root}/infra/sandbox-images/images.json\n  token_root: /var/lib/factory/tokens\n  workspace_root: /var/lib/factory/workspaces\n  platform: linux/arm64\n{extra}\
         broker:\n  listen: '127.0.0.1:0'\n",
        root = root.display()
    )
}

fn inputs<'a>(
    config: &'a FactoryConfig,
    policies: &'a factory_composition::startup::LoadedPolicies,
) -> ProviderInputs<'a> {
    let clock = Arc::new(FakeClock::new());
    let store = Arc::new(InMemoryStore::new(clock));
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(InMemoryArtifactStore::new());
    ProviderInputs {
        config,
        policies,
        redactor: Arc::new(Redactor::builder().build().expect("a redactor")),
        artifacts,
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("the random source opens")),
        store,
        jobs: Arc::new(ActiveJobs::new()),
        runner: system_runner(),
    }
}

#[test]
fn the_local_profile_assembles_a_real_sandbox_workspace_and_specification_provider() {
    let config = FactoryConfig::from_yaml(&config_text(
        "local",
        "  remote: { directory: /var/lib/factory/mirror }\n",
    ))
    .expect("the configuration parses");
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let providers = assemble(inputs(&config, &policies)).expect("the providers assemble");
    // Real, not stand-ins: the profile checks above this line would refuse a fake in production.
    assert_eq!(providers.sandbox.fidelity(), Fidelity::Real);
    assert_eq!(providers.workspaces.fidelity(), Fidelity::Real);
    assert_eq!(providers.specification.fidelity(), Fidelity::Real);
    assert_eq!(providers.process.fidelity(), Fidelity::Real);
}

#[test]
fn the_spec_kit_provider_takes_its_host_and_mode_from_the_installation_and_the_profile() {
    let config = FactoryConfig::from_yaml(&config_text("local", "")).expect("parses");
    let spec = spec_kit_config(&config, config.profile).expect("the installation is read");
    assert_eq!(spec.mode, ExecutionMode::Test);
    assert_eq!(spec.fallback_adapter_version, "1.1.2");
}

#[test]
fn a_missing_spec_kit_installation_or_image_catalog_is_an_error_and_not_a_fallback() {
    let mut config = FactoryConfig::from_yaml(&config_text("local", "")).expect("parses");
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    config.sandbox.images_catalog = PathBuf::from("/nonexistent/images.json");
    assert!(matches!(
        assemble(inputs(&config, &policies)),
        Err(ProviderError::Catalog(_))
    ));
    let mut config = FactoryConfig::from_yaml(&config_text("local", "")).expect("parses");
    config.protected_checkout = PathBuf::from("/nonexistent");
    assert!(matches!(
        spec_kit_config(&config, config.profile),
        Err(ProviderError::Installation(_, _))
    ));
}

#[test]
fn production_fetches_over_https_only() {
    // The production profile also needs a provider, the GitHub App, the key that signs decision
    // requests and the commit of the gate definitions; give it all of them so that the remote is
    // the only thing wrong.
    let extra = "  remote: { directory: /var/lib/factory/mirror }\n";
    let text = config_text("production", extra).replace(
        "broker:\n  listen: '127.0.0.1:0'\n",
        "broker:\n  listen: '127.0.0.1:0'\n  upstreams:\n    - { provider: anthropic, base_url: 'https://api.anthropic.com', key_file: /run/secrets/anthropic }\ngithub: { app_id: 1, key_file: /run/secrets/github_app_key }\ndecisions: { key_file: /run/secrets/decision_signing_key }\nstages: { definition_commit: 1405df66cbe219b0bf6355bc3d60361a8376b6b4 }\n",
    );
    let refused = FactoryConfig::from_yaml(&text).expect_err("a local directory is not https");
    assert!(
        matches!(refused, ConfigError::OutOfRange { field, .. } if field == "sandbox.remote"),
        "{refused:?}"
    );
    let allowed = text.replace(extra, "  remote: { https_host: github.com }\n");
    let config = FactoryConfig::from_yaml(&allowed).expect("https is accepted");
    assert_eq!(
        config.sandbox.remote.remote(),
        Ok(Remote::Https("github.com".to_owned()))
    );
    // Both at once is an error in every profile.
    let both = text.replace(
        extra,
        "  remote: { https_host: github.com, directory: /var/lib/factory/mirror }\n",
    );
    assert!(FactoryConfig::from_yaml(&both).is_err());
}

#[test]
fn the_path_rules_follow_the_protection_groups_of_the_policy() {
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let rules = path_rules(&policies.security);
    // A target repository's hidden, deny-write and append-only groups are all there; the groups
    // that apply to the factory's own repository are not.
    let shown = format!("{rules:?}");
    assert!(shown.contains("Hidden"), "{shown}");
    assert!(shown.contains("DenyWrite"), "{shown}");
}

// ---- where the Docker daemon is (LB-01) ------------------------------------------------------------

/// A runner that records every request and answers as a daemon with nothing in it would: exit code
/// 0 and no output. No process starts.
#[derive(Default)]
struct Recorder {
    seen: std::sync::Mutex<Vec<factory_ports::process::SpawnRequest>>,
}

#[async_trait::async_trait]
impl factory_ports::process::ProcessRunner for Recorder {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        req: factory_ports::process::SpawnRequest,
        _cancel: &dyn factory_ports::clock::CancelSignal,
    ) -> Result<factory_ports::process::SpawnOutput, factory_ports::process::SpawnError> {
        self.seen.lock().expect("lock").push(req);
        Ok(factory_ports::process::SpawnOutput {
            exit_code: Some(0),
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
        })
    }
}

/// Builds the providers on a recorder, asks the sandbox to sweep (the one call that reaches the
/// `docker` client with no database behind it) and returns what the client was asked to run.
async fn docker_requests_of(config: &FactoryConfig) -> Vec<factory_ports::process::SpawnRequest> {
    let recorder = Arc::new(Recorder::default());
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let mut given = inputs(config, &policies);
    given.runner = recorder.clone();
    let providers = assemble(given).expect("the providers assemble");
    providers
        .sandbox
        .sweep_orphans(&[])
        .await
        .expect("an empty daemon has nothing to sweep");
    recorder.seen.lock().expect("lock").clone()
}

fn plain(env: &[(String, factory_ports::process::EnvValue)], name: &str) -> Option<String> {
    env.iter().find_map(|(key, value)| match value {
        factory_ports::process::EnvValue::Plain(text) if key == name => Some(text.clone()),
        _ => None,
    })
}

#[tokio::test]
async fn the_docker_keys_of_the_configuration_reach_every_docker_command_of_the_sandbox() {
    let directory =
        std::env::temp_dir().join(format!("composition-docker-config-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a directory");
    let extra = format!(
        "  docker_host: 'unix:///run/user/1000/docker.sock'\n  docker_config: {}\n",
        directory.display()
    );
    let config = FactoryConfig::from_yaml(&config_text("local", &extra)).expect("parses");
    let seen = docker_requests_of(&config).await;
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        seen.len() >= 2,
        "the sweep lists containers and networks: {seen:?}"
    );
    for request in &seen {
        assert_eq!(request.program, factory_ports::process::Program::Docker);
        assert_eq!(
            plain(&request.env, "DOCKER_HOST").as_deref(),
            Some("unix:///run/user/1000/docker.sock"),
            "{request:?}"
        );
        assert_eq!(
            plain(&request.env, "DOCKER_CONFIG"),
            Some(directory.display().to_string()),
            "{request:?}"
        );
        // The default context rides with the directory so that it cannot name a daemon (DR-6).
        assert_eq!(
            plain(&request.env, "DOCKER_CONTEXT").as_deref(),
            Some("default"),
            "{request:?}"
        );
        assert_eq!(request.env.len(), 3, "nothing else is passed: {request:?}");
    }
}

#[tokio::test]
async fn without_the_keys_the_docker_client_gets_no_environment_at_all() {
    // The default stays what it was: the client's own default socket, and no variable of ours.
    let config = FactoryConfig::from_yaml(&config_text("local", "")).expect("parses");
    let seen = docker_requests_of(&config).await;
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|request| request.env.is_empty()),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_remote_docker_host_allowed_by_the_flag_reaches_the_client_unchanged() {
    let extra = "  docker_host: 'tcp://10.0.0.5:2375'\n  allow_remote_docker: true\n";
    let config = FactoryConfig::from_yaml(&config_text("local", extra)).expect("parses");
    let seen = docker_requests_of(&config).await;
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|request| {
        plain(&request.env, "DOCKER_HOST").as_deref() == Some("tcp://10.0.0.5:2375")
    }));
}

/// A fresh directory with `files` in it (a path with a slash makes the folders), for a test of the
/// Docker configuration directory. The caller removes it.
fn docker_config_with(label: &str, files: &[(&str, &str)]) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "composition-docker-config-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a directory");
    for (name, content) in files {
        let path = directory.join(name);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a folder");
        std::fs::write(&path, content).expect("a file");
    }
    directory
}

fn assembled_with_docker_config(
    directory: &std::path::Path,
    flag: bool,
) -> Result<(), ProviderError> {
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let extra = format!(
        "  docker_config: {}\n  allow_docker_config_contexts: {flag}\n",
        directory.display()
    );
    let config = FactoryConfig::from_yaml(&config_text("local", &extra)).expect("parses");
    assemble(inputs(&config, &policies)).map(|_| ())
}

#[test]
fn a_docker_config_that_names_a_daemon_or_a_credential_helper_stops_the_assembly_and_names_the_key()
{
    // DR-6: a context in the directory points the client at a daemon whatever `docker_host` says.
    let big = format!("{{\"auths\":{{}},\"pad\":\"{}\"}}", "x".repeat(1_100_000));
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "other-context",
            vec![("config.json", r#"{"currentContext":"remote"}"#)],
        ),
        (
            "other-context-with-default-name-case",
            vec![("config.json", r#"{"currentContext":"Default"}"#)],
        ),
        (
            "context-not-a-string",
            vec![("config.json", r#"{"currentContext":7}"#)],
        ),
        (
            "contexts-entry",
            vec![("contexts/meta/0a1b/meta.json", "{}")],
        ),
        ("contexts-file", vec![("contexts", "not a directory")]),
        (
            "creds-store",
            vec![("config.json", r#"{"credsStore":"desktop"}"#)],
        ),
        (
            "creds-helpers",
            vec![("config.json", r#"{"credHelpers":{"example.org":"helper"}}"#)],
        ),
        (
            "creds-store-not-a-string",
            vec![("config.json", r#"{"credsStore":true}"#)],
        ),
        ("not-json", vec![("config.json", "this is not json")]),
        ("not-an-object", vec![("config.json", "[]")]),
        ("too-big", vec![("config.json", big.as_str())]),
    ];
    for (label, files) in cases {
        let directory = docker_config_with(label, &files);
        let refused = assembled_with_docker_config(&directory, false)
            .err()
            .unwrap_or_else(|| panic!("{label}: the directory was accepted"));
        assert!(
            matches!(refused, ProviderError::DockerConfigContent(..)),
            "{label}: {refused:?}"
        );
        let text = refused.to_string();
        assert!(text.contains("sandbox.docker_config"), "{label}: {text}");
        assert!(
            text.contains("allow_docker_config_contexts"),
            "{label}: the message says how to allow it: {text}"
        );
        // The flag is the one way through, in a profile that allows it.
        assembled_with_docker_config(&directory, true)
            .unwrap_or_else(|e| panic!("{label}: the flag allows it: {e}"));
        let _ = std::fs::remove_dir_all(&directory);
    }
}

#[test]
fn a_docker_config_with_no_context_and_no_helper_is_accepted() {
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("empty", vec![]),
        ("empty-json", vec![("config.json", "{}")]),
        (
            "default-context",
            vec![("config.json", r#"{"currentContext":"default","auths":{}}"#)],
        ),
        (
            "blank-context",
            vec![(
                "config.json",
                r#"{"currentContext":"","credsStore":"","credHelpers":{}}"#,
            )],
        ),
        (
            "other-keys",
            vec![(
                "config.json",
                r#"{"auths":{},"proxies":{},"psFormat":"table"}"#,
            )],
        ),
    ];
    for (label, files) in cases {
        let directory = docker_config_with(label, &files);
        let result = assembled_with_docker_config(&directory, false);
        let _ = std::fs::remove_dir_all(&directory);
        result.unwrap_or_else(|e| panic!("{label}: {e}"));
    }
    // An empty `contexts` folder names nothing.
    let directory = docker_config_with("empty-contexts", &[]);
    std::fs::create_dir_all(directory.join("contexts")).expect("a folder");
    let result = assembled_with_docker_config(&directory, false);
    let _ = std::fs::remove_dir_all(&directory);
    result.expect("an empty contexts folder is accepted");
}

#[tokio::test]
async fn a_docker_config_directory_comes_with_the_default_context_so_it_cannot_redirect_the_client()
{
    // Defence in depth for DR-6: whatever the directory says when a command runs, the client is
    // told to use the default context, unless the flag was set.
    let directory = docker_config_with("context-env", &[("config.json", "{}")]);
    let extra = format!("  docker_config: {}\n", directory.display());
    let config = FactoryConfig::from_yaml(&config_text("local", &extra)).expect("parses");
    let seen = docker_requests_of(&config).await;
    assert!(!seen.is_empty());
    for request in &seen {
        assert_eq!(
            plain(&request.env, "DOCKER_CONTEXT").as_deref(),
            Some("default"),
            "{request:?}"
        );
    }
    // With the flag, the directory is the operator's to use as it is.
    let allowed = format!("{extra}  allow_docker_config_contexts: true\n");
    let config = FactoryConfig::from_yaml(&config_text("local", &allowed)).expect("parses");
    let seen = docker_requests_of(&config).await;
    let _ = std::fs::remove_dir_all(&directory);
    assert!(!seen.is_empty());
    assert!(
        seen.iter()
            .all(|request| plain(&request.env, "DOCKER_CONTEXT").is_none()),
        "{seen:?}"
    );
}

#[test]
fn a_docker_config_that_is_not_a_directory_stops_the_assembly_and_names_the_key() {
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    for path in ["/nonexistent/docker-config", "/etc/hosts"] {
        let config =
            FactoryConfig::from_yaml(&config_text("local", &format!("  docker_config: {path}\n")))
                .expect("parses: the absolute path is all the parser can check");
        let refused = assemble(inputs(&config, &policies))
            .err()
            .unwrap_or_else(|| panic!("{path} is not a directory"));
        assert!(
            matches!(refused, ProviderError::DockerConfig(_)),
            "{refused:?}"
        );
        assert!(
            refused.to_string().contains("sandbox.docker_config"),
            "{refused}"
        );
    }
}
