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
