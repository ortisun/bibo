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

/// What the lead has to change in `infra/compose/config/api.local.example.yaml` (this package does not
/// edit `infra/**`): add `protected_checkout`, and mount that directory into the API container. The
/// rest of the file (`profile`, `database.api`, `artifacts`, `listen`) is read by the API as written.
#[test]
fn the_api_example_of_the_local_stack_parses_once_it_names_the_protected_checkout() {
    let as_it_is =
        ApiConfig::from_yaml(&example()).expect_err("the example lacks the protected checkout");
    assert!(
        as_it_is.to_string().contains("protected_checkout"),
        "{as_it_is}"
    );
    let corrected = format!(
        "{}\nprotected_checkout: /etc/factory/protected\n",
        example()
    );
    let config = ApiConfig::from_yaml(&corrected).expect("the corrected example parses");
    assert_eq!(config.profile, Profile::Local);
    assert_eq!(config.database.api.login, "factory_api");
    assert_eq!(config.listen.port(), 8080);
    assert!(config.github.webhook_secret_files.is_empty());
}

/// The text the owner of `infra/compose` puts in `config/api.local.example.yaml`, in full: the
/// protected checkout the API reads, the key that signs decision requests (the same file the
/// worker mounts, or the worker rejects every request as unsigned), and the webhook secret. This
/// test parses it with the API's own parser, so the text printed in the report is a text that works.
const CORRECTED_API_EXAMPLE: &str = "\
profile: local
protected_checkout: /etc/factory/protected   # mounted read-only: policies/ and allowlist/allowlist.yaml
database:
  api: { url_file: /run/secrets/db_api, login: factory_api, max_connections: 8 }
listen: 0.0.0.0:8080
github:
  webhook_secret_files: [/run/secrets/webhook_secret]
  factory_label: factory
decisions:
  key_file: /run/secrets/decision_signing_key   # the SAME file the worker mounts; mode 0600; 32 bytes or more
artifacts: { root: /var/lib/factory/artifacts }
";

#[test]
fn the_corrected_api_example_for_the_local_stack_parses_and_names_the_key_the_worker_shares() {
    let config = ApiConfig::from_yaml(CORRECTED_API_EXAMPLE).expect("the corrected example parses");
    assert_eq!(config.profile, Profile::Local);
    assert_eq!(config.listen.port(), 8080);
    assert_eq!(config.github.webhook_secret_files.len(), 1);
    assert!(
        config.decisions.is_some(),
        "the key that signs decision requests is named"
    );
}
