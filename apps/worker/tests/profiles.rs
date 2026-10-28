//! The production profile refuses fakes, shown with every fake the testkit has.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::githost::{FakeChangeHost, FakeIssueSource};
use factory_testkit::process::ScriptedProcessRunner;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::spec::FakeSpecificationProvider;
use factory_testkit::store::InMemoryStore;
use factory_testkit::webhook::FakeWebhookVerifier;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_worker::profile::{PortName, Profile};
use factory_worker::registry::PortRegistry;
use factory_worker::system::{RandomIds, SystemClock, TokioTicker};

mod support;
use support::engine::StaticAuthority;

/// A registry in which every port is the testkit's fake, except that `real` names ports for which
/// the real clock, id generator or ticker is used (those three have no fake worth the name).
fn registry(real_system_ports: bool) -> PortRegistry {
    let clock = Arc::new(FakeClock::new());
    let ids = Arc::new(SequentialIdGenerator::new());
    let store = Arc::new(InMemoryStore::new(clock.clone()));
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(InMemoryArtifactStore::new());
    let repo = factory_ports::paths::RepoRef::parse("example-org/fixture").expect("a repository");
    PortRegistry {
        store,
        clock: if real_system_ports {
            Arc::new(SystemClock)
        } else {
            clock.clone()
        },
        ids: if real_system_ports {
            Arc::new(RandomIds::new().expect("random"))
        } else {
            ids.clone()
        },
        artifacts: artifacts.clone(),
        sandbox: Arc::new(FakeSandbox::new(
            clock.clone(),
            artifacts.clone(),
            sandbox_policy(),
        )),
        workspaces: Arc::new(FakeWorkspaceProvider::new(
            repo,
            FakeRemote::new(),
            artifacts.clone(),
            fixture_rules(),
        )),
        runtime: Arc::new(FakeAgentRuntime::new(artifacts.clone())),
        router: Arc::new(StaticModelRouter::new(Vec::new())),
        agents: Arc::new(InMemoryAgentRegistry::new()),
        validator: Arc::new(support::engine::ScriptedValidator),
        broker: Arc::new(FakeModelBroker::new(clock, ids)),
        specification: Arc::new(FakeSpecificationProvider::new()),
        issues: Arc::new(FakeIssueSource::new()),
        changes: Arc::new(FakeChangeHost::new()),
        webhooks: Some(Arc::new(FakeWebhookVerifier::new())),
        process: Arc::new(ScriptedProcessRunner::new()),
        ticker: if real_system_ports {
            Arc::new(TokioTicker)
        } else {
            Arc::new(FakeTicker)
        },
        authority: Arc::new(StaticAuthority::new()),
    }
}

struct FakeTicker;

#[async_trait]
impl factory_workflow::scheduler::Ticker for FakeTicker {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn sleep(&self, _: std::time::Duration) {}
}

#[test]
fn production_profile_refuses_fakes() {
    let registry = registry(false);
    // Every one of the 17 ports is a fake here, and the registry reports all 17.
    let reported: Vec<PortName> = registry
        .fidelities()
        .iter()
        .map(|(port, _)| *port)
        .collect();
    for port in PortName::ALL {
        assert!(
            reported.contains(&port),
            "{port:?} is missing from the registry"
        );
    }
    let refusal = registry
        .check(Profile::Production)
        .expect_err("production must refuse a registry made of fakes");
    for port in PortName::ALL {
        assert!(
            refusal.refused.contains(&port),
            "production did not refuse the fake {}",
            port.label()
        );
        assert!(refusal.to_string().contains(port.label()));
    }
    assert_eq!(registry.lowest_fidelity(), Fidelity::Fake);
}

#[test]
fn production_profile_refuses_a_single_fake_among_real_system_ports() {
    // With the real clock, ids and ticker, the other 14 ports are still fakes and still refused.
    let refusal = registry(true)
        .check(Profile::Production)
        .expect_err("fakes remain");
    for port in PortName::ALL {
        let real = matches!(port, PortName::Clock | PortName::Ids | PortName::Ticker);
        assert_eq!(refusal.refused.contains(&port), !real, "{}", port.label());
    }
}

#[test]
fn the_local_profile_refuses_a_fake_store_and_accepts_fake_model_and_github_ports() {
    let refusal = registry(true)
        .check(Profile::Local)
        .expect_err("local keeps state and execution real");
    for port in PortName::ALL {
        let expected = !port.is_credentialed()
            && !matches!(port, PortName::Clock | PortName::Ids | PortName::Ticker);
        assert_eq!(
            refusal.refused.contains(&port),
            expected,
            "{}",
            port.label()
        );
    }
}

#[test]
fn the_test_profile_accepts_a_registry_of_fakes() {
    assert_eq!(registry(false).check(Profile::Test), Ok(()));
}
