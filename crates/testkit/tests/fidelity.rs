//! Every fake reports fidelity `fake`, so a production run can refuse it (invariant INV-08).
//!
//! The test builds one fake for every port that reports a fidelity, checks the label, and checks
//! that the production gate refuses it. A second test reads the port sources and fails when a port
//! gains a `fidelity` method that this file does not cover, so a new fake cannot slip past.

use std::sync::Arc;

use factory_domain::vocabulary::{ExecutionMode, Fidelity};
use factory_ports::agent::{AgentRuntime, ModelBroker, ModelRouter, TurnAttestation};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock, IdGenerator};
use factory_ports::githost::{ChangeHost, IssueSource, WebhookVerifier};
use factory_ports::process::ProcessRunner;
use factory_ports::registry::AgentRegistry;
use factory_ports::require_permitted;
use factory_ports::sandbox::SandboxProvider;
use factory_ports::spec::SpecificationProvider;
use factory_ports::store::Store;
use factory_ports::workspace::WorkspaceProvider;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeCancel, FakeClock, SequentialIdGenerator};
use factory_testkit::githost::{FakeChangeHost, FakeIssueSource};
use factory_testkit::process::ScriptedProcessRunner;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::spec::FakeSpecificationProvider;
use factory_testkit::store::InMemoryStore;
use factory_testkit::webhook::FakeWebhookVerifier;
use factory_testkit::workspace::FakeWorkspaceProvider;
use factory_testkit::{agent::FakeAgentRuntime, fixtures};

/// The ports whose traits have a `fidelity` method, each with the fidelity of its fake.
fn every_fake() -> Vec<(&'static str, Fidelity)> {
    let clock = Arc::new(FakeClock::new());
    let artifacts = Arc::new(InMemoryArtifactStore::new());
    let ids: Arc<dyn IdGenerator> = Arc::new(SequentialIdGenerator::new());
    let repo = factory_ports::paths::RepoRef::parse("example-org/fixture").expect("a repo");
    vec![
        ("Clock", Clock::fidelity(&*clock)),
        ("IdGenerator", ids.fidelity()),
        ("CancelSignal", CancelSignal::fidelity(&FakeCancel::new())),
        ("Store", InMemoryStore::new(clock.clone()).fidelity()),
        ("ArtifactStore", ArtifactStore::fidelity(&*artifacts)),
        (
            "SandboxProvider",
            FakeSandbox::new(clock.clone(), artifacts.clone(), fixtures::sandbox_policy())
                .fidelity(),
        ),
        (
            "WorkspaceProvider",
            FakeWorkspaceProvider::new(
                repo,
                factory_testkit::workspace::FakeRemote::new(),
                artifacts.clone(),
                factory_ports::paths::PathRules::default(),
            )
            .fidelity(),
        ),
        (
            "AgentRuntime",
            FakeAgentRuntime::new(artifacts.clone()).fidelity(),
        ),
        (
            "ModelRouter",
            ModelRouter::fidelity(&StaticModelRouter::new(vec![])),
        ),
        (
            "ModelBroker",
            ModelBroker::fidelity(&FakeModelBroker::new(clock.clone(), ids.clone())),
        ),
        (
            "TurnAttestation",
            TurnAttestation::fidelity(&FakeModelBroker::new(clock.clone(), ids)),
        ),
        (
            "AgentRegistry",
            AgentRegistry::fidelity(&InMemoryAgentRegistry::new()),
        ),
        (
            "SpecificationProvider",
            FakeSpecificationProvider::new().fidelity(),
        ),
        (
            "IssueSource",
            IssueSource::fidelity(&FakeIssueSource::new()),
        ),
        ("ChangeHost", ChangeHost::fidelity(&FakeChangeHost::new())),
        (
            "WebhookVerifier",
            WebhookVerifier::fidelity(&FakeWebhookVerifier::new()),
        ),
        (
            "ProcessRunner",
            ProcessRunner::fidelity(&ScriptedProcessRunner::new()),
        ),
    ]
}

#[test]
fn every_fake_reports_fake_fidelity() {
    for (port, fidelity) in every_fake() {
        assert_eq!(
            fidelity,
            Fidelity::Fake,
            "the fake for {port} must report fake"
        );
    }
}

#[test]
fn a_production_run_refuses_every_fake_and_a_test_run_accepts_it() {
    for (port, fidelity) in every_fake() {
        let refused = require_permitted(ExecutionMode::Production, port, fidelity)
            .expect_err("production mode must refuse a fake");
        assert_eq!(refused.component, port);
        assert_eq!(
            require_permitted(ExecutionMode::Test, port, fidelity),
            Ok(())
        );
    }
}

const PORT_SOURCES: [&str; 10] = [
    include_str!("../../ports/src/agent.rs"),
    include_str!("../../ports/src/artifact.rs"),
    include_str!("../../ports/src/clock.rs"),
    include_str!("../../ports/src/githost.rs"),
    include_str!("../../ports/src/process.rs"),
    include_str!("../../ports/src/registry.rs"),
    include_str!("../../ports/src/sandbox.rs"),
    include_str!("../../ports/src/spec.rs"),
    include_str!("../../ports/src/store.rs"),
    include_str!("../../ports/src/workspace.rs"),
];

/// The names of the public traits that declare `fn fidelity`.
fn traits_with_a_fidelity_method() -> Vec<String> {
    let mut found = Vec::new();
    for source in PORT_SOURCES {
        let mut current: Option<String> = None;
        for line in source.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("pub trait ") {
                current = Some(
                    rest.chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect(),
                );
            }
            if line.contains("fn fidelity(&self)")
                && let Some(name) = &current
                && !found.contains(name)
            {
                found.push(name.clone());
            }
            // Free items after the trait body end it; a top-level `}` closes the trait.
            if line == "}" {
                current = None;
            }
        }
    }
    found
}

#[test]
fn no_port_with_a_fidelity_method_is_missing_from_this_file() {
    let covered: Vec<&str> = every_fake().iter().map(|(port, _)| *port).collect();
    let mut missing: Vec<String> = traits_with_a_fidelity_method()
        .into_iter()
        .filter(|name| !covered.contains(&name.as_str()))
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "these ports report a fidelity but have no fake covered here: {missing:?}"
    );
    // And the other way: the list holds only real ports.
    let known = traits_with_a_fidelity_method();
    for port in covered {
        assert!(
            known.iter().any(|name| name == port),
            "{port} is not a port with a fidelity method"
        );
    }
}
