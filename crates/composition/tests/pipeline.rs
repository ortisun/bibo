//! The pipeline assembled from the configuration (AUT-13): the thirteen handlers, the engine, the
//! approval service, the hook and the preflight, and what each profile says about the ports that
//! went into it.
//!
//! Every port here is the testkit's stand-in, because this library may not build one and a test may.
//! The journey through the assembled pipeline, with PostgreSQL, is `apps/api/tests/full_run.rs`,
//! whose rig calls the same function.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::config::StageSettings;
use factory_composition::decision_signing::DecisionKeys;
use factory_composition::pipeline::{
    ExternalPorts, PipelineError, PipelineInputs, Tuning, assemble_pipeline, missing_handlers,
};
use factory_composition::preflight::NoAttestations;
use factory_composition::profile::{PortName, Profile};
use factory_composition::providers::Providers;
use factory_composition::seams::{CachedProbes, FileAllowlist};
use factory_composition::startup::load_policy;
use factory_composition::supply_chain::{Standing, SupplyChainSources};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::ProbedCapabilities;
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::Store;
use factory_sandbox::container::images::ImageCatalog;
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::githost::{FAKE_APP_ID, FakeChangeHost, FakeIssueSource};
use factory_testkit::process::ScriptedProcessRunner;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::spec::FakeSpecificationProvider;
use factory_testkit::store::InMemoryStore;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::engine::EngineConfig;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// Inputs in which every port is a stand-in.
fn inputs(profile: Profile, settings: StageSettings) -> PipelineInputs {
    let clock = Arc::new(FakeClock::new());
    let ids = Arc::new(SequentialIdGenerator::new());
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new(clock.clone()));
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(InMemoryArtifactStore::new());
    let repo = factory_ports::paths::RepoRef::parse("example-org/fixture").expect("a repository");
    let catalog_text = std::fs::read_to_string(root().join("infra/sandbox-images/images.json"))
        .expect("the catalog");
    let sources = SupplyChainSources::stand_in(clock.clone());
    PipelineInputs {
        profile,
        settings,
        definitions_root: root(),
        policies: load_policy(&root(), &[]).expect("the real policies load"),
        redactor: Arc::new(
            factory_domain::redaction::Redactor::builder()
                .build()
                .expect("one"),
        ),
        store,
        artifacts: artifacts.clone(),
        clock: clock.clone(),
        ids: ids.clone(),
        providers: Providers {
            process: Arc::new(ScriptedProcessRunner::new()),
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
            specification: Arc::new(FakeSpecificationProvider::new()),
        },
        catalog: ImageCatalog::from_json(&catalog_text, "linux/arm64").expect("a catalog"),
        sandbox_scratch: std::env::temp_dir().join("factory-pipeline-test"),
        broker: Arc::new(FakeModelBroker::new(clock, ids)),
        external: ExternalPorts {
            runtime: Arc::new(FakeAgentRuntime::new(artifacts)),
            router: Arc::new(StaticModelRouter::new(Vec::new())),
            issues: Arc::new(FakeIssueSource::new()),
            changes: Arc::new(FakeChangeHost::new()),
            probes: Arc::new(CachedProbes::new(ProbedCapabilities(BTreeMap::new()))),
            supply_chain: sources,
            attestations: Arc::new(NoAttestations),
            app: FAKE_APP_ID,
        },
        allowlist: Arc::new(FileAllowlist::in_checkout(&root())),
        tenants: Vec::new(),
        decision_keys: Arc::new(DecisionKeys::generated().expect("a key")),
        tuning: Tuning::default(),
    }
}

fn settings_with_commit() -> StageSettings {
    StageSettings {
        definition_commit: Some("1405df66cbe219b0bf6355bc3d60361a8376b6b4".to_owned()),
        ..StageSettings::default()
    }
}

#[test]
fn the_test_profile_assembles_all_thirteen_handlers_and_the_parts_around_them() {
    let pipeline = assemble_pipeline(inputs(Profile::Test, StageSettings::default()))
        .unwrap_or_else(|error| panic!("{error}"));
    let scope = EngineConfig::new(
        Profile::Test.execution_mode(),
        factory_domain::values::Sha256Digest::of(b"policy"),
    )
    .scope;
    assert_eq!(pipeline.handlers.len(), 13, "{:?}", pipeline.handlers);
    for kind in &scope {
        assert!(
            pipeline.handlers.iter().any(|(held, _)| held == kind),
            "no handler for {kind:?}"
        );
    }
    // The hook, the preflight and the request cache run before each claim, in that order.
    assert_eq!(pipeline.before_claim.len(), 3);
    // The stand-ins are what the registry reports, and a stage handler that holds one says so.
    assert!(
        pipeline
            .ports
            .fidelities()
            .iter()
            .any(|(_, fidelity)| *fidelity == Fidelity::Fake)
    );
}

/// Production inputs: every port is still a stand-in, which production refuses, but the sources of
/// the dependency gates are the blocked adapters production takes.
fn production_inputs() -> PipelineInputs {
    let mut inputs = inputs(Profile::Production, settings_with_commit());
    inputs.external.supply_chain = SupplyChainSources::blocked();
    inputs
}

#[test]
fn the_production_profile_refuses_every_stand_in_and_lists_them() {
    let refused = assemble_pipeline(production_inputs())
        .err()
        .expect("production refuses stand-ins");
    let PipelineError::Refused(refusal) = refused else {
        panic!("not a refusal of ports: {refused}");
    };
    for port in [
        PortName::Store,
        PortName::Sandbox,
        PortName::Workspaces,
        PortName::Runtime,
        PortName::Router,
        PortName::Issues,
        PortName::Changes,
        PortName::Broker,
        PortName::Specification,
    ] {
        assert!(refusal.refused.contains(&port), "{port:?} was not refused");
    }
}

#[test]
fn the_local_profile_lets_the_model_and_github_side_stand_in_and_nothing_that_holds_state() {
    let refused = assemble_pipeline(inputs(Profile::Local, settings_with_commit()))
        .err()
        .expect("local refuses a stand-in store");
    let PipelineError::Refused(refusal) = refused else {
        panic!("not a refusal of ports: {refused}");
    };
    for allowed in [
        PortName::Runtime,
        PortName::Router,
        PortName::Issues,
        PortName::Changes,
        PortName::Broker,
    ] {
        assert!(
            !refusal.refused.contains(&allowed),
            "{allowed:?} may stand in locally: {:?}",
            refusal.refused
        );
    }
    assert!(refusal.refused.contains(&PortName::Store));
    assert!(refusal.refused.contains(&PortName::Sandbox));
}

#[test]
fn the_production_profile_needs_the_commit_of_the_gate_definitions() {
    let refused = assemble_pipeline(inputs(Profile::Production, StageSettings::default()))
        .err()
        .expect("refused");
    assert!(
        matches!(&refused, PipelineError::Settings(text) if text.contains("definition_commit")),
        "{refused}"
    );
    let unusable = StageSettings {
        definition_commit: Some("not a commit".to_owned()),
        ..StageSettings::default()
    };
    assert!(matches!(
        assemble_pipeline(inputs(Profile::Test, unusable)).err(),
        Some(PipelineError::Settings(_))
    ));
}

#[test]
fn a_registry_that_lacks_a_handler_is_named_before_any_job_runs() {
    let all: Vec<(StageKind, Fidelity)> = StageKind::ALL
        .iter()
        .map(|kind| (*kind, Fidelity::Real))
        .collect();
    let scope = EngineConfig::new(
        Profile::Test.execution_mode(),
        factory_domain::values::Sha256Digest::of(b"policy"),
    )
    .scope;
    assert!(missing_handlers(&all, &scope).is_empty());
    for dropped in &scope {
        let without: Vec<(StageKind, Fidelity)> = all
            .iter()
            .copied()
            .filter(|(kind, _)| kind != dropped)
            .collect();
        assert_eq!(missing_handlers(&without, &scope), vec![*dropped]);
    }
}

#[test]
fn the_production_profile_refuses_a_stand_in_for_the_registry_and_the_advisory_database() {
    let refused = assemble_pipeline(inputs(Profile::Production, settings_with_commit()))
        .err()
        .expect("production refuses the stand-in sources");
    match refused {
        PipelineError::StandIn(names) => {
            assert_eq!(names, ["RegistryMetadata", "AdvisoryDatabase"]);
        }
        other => panic!("not a refusal of the stand-in sources: {other}"),
    }
}

#[test]
fn the_blocked_sources_are_accepted_in_production_and_reported_as_blocked() {
    // The ports are stand-ins here, so production still refuses the pipeline, but not for the
    // sources: the refusal is the list of ports, and the sources are not in it.
    let refused = assemble_pipeline(production_inputs())
        .err()
        .expect("production refuses stand-in ports");
    assert!(matches!(refused, PipelineError::Refused(_)), "{refused}");
    // The same sources assemble where the profile allows the ports.
    let mut accepted = inputs(Profile::Test, StageSettings::default());
    accepted.external.supply_chain = SupplyChainSources::blocked();
    let pipeline = assemble_pipeline(accepted).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        pipeline
            .supply_chain
            .iter()
            .all(|(_, standing)| *standing == Standing::Blocked),
        "{:?}",
        pipeline.supply_chain
    );
}

#[test]
fn the_test_profile_reports_the_stand_in_sources_as_stand_ins() {
    let pipeline = assemble_pipeline(inputs(Profile::Test, StageSettings::default()))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        pipeline.supply_chain,
        [
            ("RegistryMetadata", Standing::StandIn),
            ("AdvisoryDatabase", Standing::StandIn)
        ]
    );
}
