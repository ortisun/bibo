//! The profile rule over the API's own ports, and the configuration file of the local stack.
//!
//! The worker's registry runs `require_permitted` for its 37 ports and a test shows a fake refused
//! for each. The API has six ports of its own; `assemble_state` is the code start-up runs, so these
//! tests run the production rule, not a copy of it.

mod support;

use std::sync::Arc;

use factory_api::boot::{StateInputs, assemble_state};
use factory_api::config::ApiConfig;
use factory_api::state::ApiPorts;
use factory_composition::profile::{PortName, Profile};
use factory_composition::startup::StartupFailure;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::WebhookVerifier;
use factory_ports::store::Store;
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::store::InMemoryStore;
use factory_testkit::webhook::FakeWebhookVerifier;
use support::{Env, FakeAllowlist, FixedAuthority};

fn inputs(env: &Env, profile: Profile, ports: ApiPorts) -> StateInputs {
    StateInputs {
        profile,
        ports,
        allowlist_file: Arc::clone(&env.state.allowlist_file),
        policies: env.state.policies.clone(),
        redactor: Arc::clone(&env.state.redactor),
        decision_keys: Arc::clone(&env.state.decision_keys),
        audience: "factory-api".to_owned(),
        github: env.state.github.clone(),
        limits: env.state.limits.clone(),
    }
}

/// The ports of the environment with one of them replaced by a fake.
fn with_fake(env: &Env, port: PortName) -> ApiPorts {
    let mut ports = env.state.ports.clone();
    let clock: Arc<dyn Clock> = Arc::new(FakeClock::new());
    match port {
        PortName::Store => ports.store = Arc::new(InMemoryStore::new(clock)) as Arc<dyn Store>,
        PortName::Clock => ports.clock = clock,
        PortName::Ids => ports.ids = Arc::new(SequentialIdGenerator::new()) as Arc<dyn IdGenerator>,
        PortName::Webhooks => {
            ports.webhooks = Some(Arc::new(FakeWebhookVerifier::new()) as Arc<dyn WebhookVerifier>);
        }
        PortName::Authority => ports.authority = Arc::new(FixedAuthority { roles: Vec::new() }),
        PortName::Allowlist => ports.allowlist = Arc::new(FakeAllowlist),
        other => panic!("the API has no {other:?} port"),
    }
    ports
}

const API_PORTS: [PortName; 6] = [
    PortName::Store,
    PortName::Clock,
    PortName::Ids,
    PortName::Webhooks,
    PortName::Authority,
    PortName::Allowlist,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_profile_refuses_fakes() {
    let env = Env::start().await;
    // The control: every port real, and the production profile starts.
    let real = env.state.ports.clone();
    assert!(real.check(Profile::Production).is_ok());
    assert!(assemble_state(inputs(&env, Profile::Production, real)).is_ok());

    // Each port in turn replaced by a fake: the refusal names that port and no other.
    for port in API_PORTS {
        let refused = match assemble_state(inputs(&env, Profile::Production, with_fake(&env, port)))
        {
            Err(StartupFailure::Ports(refused)) => refused,
            Err(other) => panic!("{port:?}: {other}"),
            Ok(_) => panic!("{port:?}: the production profile started with a fake"),
        };
        assert_eq!(refused.refused, vec![port], "{port:?}");
        assert_eq!(refused.profile, "production");
        // The `local` profile may stand in for the GitHub ports and nothing that holds state.
        let local = assemble_state(inputs(&env, Profile::Local, with_fake(&env, port)));
        assert_eq!(local.is_ok(), port == PortName::Webhooks, "local, {port:?}");
        // The `test` profile accepts any.
        assert!(
            assemble_state(inputs(&env, Profile::Test, with_fake(&env, port))).is_ok(),
            "test, {port:?}"
        );
    }

    // Several fakes at once are all named.
    let mut many = with_fake(&env, PortName::Clock);
    many.ids = with_fake(&env, PortName::Ids).ids;
    many.authority = with_fake(&env, PortName::Authority).authority;
    let Err(StartupFailure::Ports(refused)) =
        assemble_state(inputs(&env, Profile::Production, many))
    else {
        panic!("three fakes started");
    };
    assert_eq!(refused.refused.len(), 3);
    env.stop().await;
}

/// A webhook endpoint with no verifier is not an endpoint: the production configuration refuses to
/// load without a webhook secret, and a profile that runs without one answers the route as unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_verifier_the_webhook_route_does_not_exist() {
    let env = Env::start_with(support::Options {
        webhooks: Some(None),
        ..support::Options::default()
    })
    .await;
    let reply = env
        .send(
            support::Req::post("/v1/webhooks/github")
                .header("Content-Type", "application/json")
                .body(b"{}".to_vec()),
        )
        .await;
    assert_eq!(reply.status, 404);
    env.stop().await;
}

// ---- the example configuration of the local stack -----------------------------------------------

fn example() -> String {
    let path = support::repository_root().join("infra/compose/config/api.local.example.yaml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The example is the file the local stack mounts, read from `infra/compose/config/`, so it can
/// never drift from the parser again: the test fails when the file stops parsing, and the stack and
/// the test read the same bytes. It names the protected checkout the API reads, the key that signs
/// decision requests (the same file the worker mounts, or the worker rejects every request as
/// unsigned) and the webhook secret.
#[test]
fn the_corrected_api_example_for_the_local_stack_parses_and_names_the_key_the_worker_shares() {
    let config =
        ApiConfig::from_yaml(&example()).expect("the example in infra/compose/config parses");
    assert_eq!(config.profile, Profile::Local);
    assert_eq!(config.database.api.login, "factory_api");
    assert_eq!(config.listen.port(), 8080);
    assert_eq!(config.github.webhook_secret_files.len(), 1);
    assert!(
        config.decisions.is_some(),
        "the key that signs decision requests is named"
    );
}

/// The deliberate break of the example: take the real file and remove the protected checkout, and
/// the parser refuses it and names the setting. The first version of the example lacked exactly
/// this line, and the test that read an inline copy did not notice.
#[test]
fn an_example_without_the_protected_checkout_is_refused_by_the_parser_and_names_it() {
    let broken: String = example()
        .lines()
        .filter(|line| !line.starts_with("protected_checkout:"))
        .collect::<Vec<_>>()
        .join("\n");
    let refused = ApiConfig::from_yaml(&broken).expect_err("the checkout is required");
    assert!(
        refused.to_string().contains("protected_checkout"),
        "{refused}"
    );
}

/// A misspelled setting in the example is an error and not a weaker run.
#[test]
fn a_misspelled_setting_in_the_api_example_is_an_error() {
    let broken = example().replace("key_file:", "key_flie:");
    assert!(ApiConfig::from_yaml(&broken).is_err());
}

/// The API signs and the worker verifies with one file. If the two examples named different paths,
/// the stack would start and the worker would reject every decision request as unsigned. Both are
/// parsed by their own parser and the key file they name is compared.
#[test]
fn the_api_and_the_worker_examples_name_the_same_decision_key_file() {
    let worker_path =
        support::repository_root().join("infra/compose/config/worker.local.example.yaml");
    let worker_text = std::fs::read_to_string(&worker_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", worker_path.display()));
    let worker = factory_composition::config::FactoryConfig::from_yaml(&worker_text)
        .expect("the worker example parses");
    let api = ApiConfig::from_yaml(&example()).expect("the API example parses");
    let api_key = api.decisions.expect("the API names the key").key_file;
    let worker_key = worker.decisions.expect("the worker names the key").key_file;
    assert_eq!(api_key.path(), worker_key.path());
}
