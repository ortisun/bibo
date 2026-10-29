//! The production profile refuses fakes, shown with every fake the testkit has.

use std::sync::Arc;

use async_trait::async_trait;
use factory_composition::delivery::{StoreApprovalSources, StoreDeliverySources};
use factory_composition::feedback::StoreFeedback;
use factory_composition::ledger::StoreTaskLedger;
use factory_composition::preflight::BypassAttestations;
use factory_composition::profile::{PortName, Profile};
use factory_composition::registry::PortRegistry;
use factory_composition::registry::{Seams, SeamsBuilder};
use factory_composition::risk::StoreRisk;
use factory_composition::seams::{CachedProbes, FileAllowlist, StoreRepositories, StoreRequests};
use factory_composition::specs::{StoreSpecApprovals, StoreSpecDrafts, StoreSpecHistory};
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, SystemClock, TokioTicker};
use factory_domain::contracts::ProjectManifest;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::ProbedCapabilities;
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::Store;
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
use factory_workflow::gates::supply_chain::approval::StaticApprovals;
use factory_workflow::gates::supply_chain::facts::{StaticDatabase, StaticRegistry};
use factory_workflow::stages::delivery::seams::EvidenceDrift;
use factory_workflow::stages::intake::seams::{AgentOutputCheck, AllowlistSource, SeamError};
use factory_workflow::stages::repo_intel::seams::{ManifestProblem, ProjectManifestParser};

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
    let seams = seams(&store, &artifacts, &clock, &ids, true)
        .build()
        .expect("every seam is supplied");
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
        seams,
    }
}

/// A seam that reads a fixed list and says so.
struct FakeCheck;

impl AgentOutputCheck for FakeCheck {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn check(
        &self,
        _: &factory_domain::contracts::SchemaRef,
        _: &[u8],
    ) -> Result<factory_ports::registry::ValidatedOutput, Vec<factory_domain::contracts::Violation>>
    {
        Err(Vec::new())
    }
}

/// A manifest parser that accepts nothing and says it is a stand-in.
struct FakeManifests;

impl ProjectManifestParser for FakeManifests {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn parse(&self, _: &str, _: &[u8]) -> Result<ProjectManifest, ManifestProblem> {
        Err(ManifestProblem("a stand-in".to_owned()))
    }
}

/// An evidence drift channel that drops the news and says it is a stand-in.
struct FakeDrift;

#[async_trait]
impl EvidenceDrift for FakeDrift {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn binding_changed(
        &self,
        _: factory_domain::ids::TenantId,
        _: factory_domain::ids::JobId,
    ) -> Result<(), SeamError> {
        Ok(())
    }
}

/// A statement about the bypass list that attests nothing and says it is a stand-in.
struct FakeAttestations;

#[async_trait]
impl BypassAttestations for FakeAttestations {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn attestation(
        &self,
        _: factory_domain::ids::TenantId,
        _: &factory_ports::paths::RepoRef,
    ) -> Option<factory_ports::githost::BypassAttestation> {
        None
    }
}

struct FakeAllowlist;

#[async_trait]
impl AllowlistSource for FakeAllowlist {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn current(
        &self,
        _: factory_domain::ids::TenantId,
    ) -> Result<factory_domain::policy::authority::Allowlist, SeamError> {
        Err(SeamError::Unavailable)
    }
}

/// The seams over the in-memory store, which reports `fake`, and two stand-ins for the seams that
/// read files and so would report `real` on their own.
fn seams(
    store: &Arc<InMemoryStore>,
    artifacts: &Arc<dyn ArtifactStore>,
    clock: &Arc<FakeClock>,
    ids: &Arc<SequentialIdGenerator>,
    with_ledger: bool,
) -> SeamsBuilder {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policies = load_policy(&root, &[]).expect("the repository policy loads");
    let store: Arc<dyn Store> = store.clone();
    let requests = Arc::new(StoreRequests::new(store.clone()));
    let feedback = Arc::new(StoreFeedback::new(store.clone(), artifacts.clone()));
    let builder = SeamsBuilder::default()
        .output_check(Arc::new(FakeCheck))
        .manifests(Arc::new(FakeManifests))
        .allowlist(Arc::new(FakeAllowlist))
        .requests(requests)
        .repositories(Arc::new(StoreRepositories::new(store.clone())))
        .probes(Arc::new(CachedProbes::new(
            ProbedCapabilities::default(),
            Fidelity::Fake,
        )))
        .rework(feedback.clone())
        .rounds(feedback)
        .risk(Arc::new(StoreRisk::new(store.clone(), artifacts.clone())))
        .drift(Arc::new(FakeDrift))
        .package_metadata(Arc::new(StaticRegistry::new()))
        .advisory_database(Arc::new(StaticDatabase::default()))
        .recorded_approvals(Arc::new(StaticApprovals::default()))
        .attestations(Arc::new(FakeAttestations))
        .spec_approvals(Arc::new(StoreSpecApprovals::new(
            store.clone(),
            artifacts.clone(),
        )))
        .spec_drafts(Arc::new(StoreSpecDrafts::new(
            store.clone(),
            artifacts.clone(),
        )))
        .spec_history(Arc::new(StoreSpecHistory::new(
            store.clone(),
            artifacts.clone(),
        )))
        .delivery(Arc::new(StoreDeliverySources::new(
            store.clone(),
            artifacts.clone(),
            policies.engine.clone(),
            clock.clone(),
        )))
        .approvals(Arc::new(StoreApprovalSources::new(
            store.clone(),
            artifacts.clone(),
            Arc::new(FileAllowlist::in_checkout(&root)),
        )));
    if with_ledger {
        builder.ledger(Arc::new(StoreTaskLedger::new(
            store,
            clock.clone(),
            ids.clone(),
        )))
    } else {
        builder
    }
}

#[test]
fn a_seam_forgotten_at_wiring_stops_start_up_and_is_named() {
    let clock = Arc::new(FakeClock::new());
    let ids = Arc::new(SequentialIdGenerator::new());
    let store = Arc::new(InMemoryStore::new(clock.clone()));
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(InMemoryArtifactStore::new());
    // The full set builds.
    assert!(
        seams(&store, &artifacts, &clock, &ids, true)
            .build()
            .is_ok()
    );
    // Every seam but the task ledger: the set cannot be built, so there is no registry and no
    // engine, and the report names exactly the seam that was forgotten.
    let refusal = seams(&store, &artifacts, &clock, &ids, false)
        .build()
        .err()
        .expect("an incomplete set is refused");
    assert_eq!(refusal.missing, vec!["task ledger"], "{refusal}");
    assert!(
        refusal
            .to_string()
            .contains("forgot 1 seam(s): task ledger")
    );
    // Nothing at all names all twenty.
    let nothing = SeamsBuilder::default()
        .build()
        .err()
        .expect("nothing is refused");
    assert_eq!(nothing.missing.len(), 20);
}

/// Every seam is in the registry's report (RR-6 and RR-7: twenty, the sixteen of the stages and the
/// four inputs of the security decisions), and production refuses a stand-in in each of them. The
/// local profile refuses it too, except for the seams that stand for an outside service.
#[test]
fn production_refuses_a_stand_in_for_each_seam() {
    let registry = registry(true);
    let reported: Vec<PortName> = registry.fidelities().iter().map(|(p, _)| *p).collect();
    assert_eq!(Seams::port_names().len(), 20);
    for port in Seams::port_names() {
        assert!(reported.contains(port), "{port:?} is not reported");
        let refusal = registry
            .check(Profile::Production)
            .expect_err("a stand-in remains");
        assert!(refusal.refused.contains(port), "{}", port.label());
        let local = registry
            .check(Profile::Local)
            .expect_err("stand-ins remain");
        assert_eq!(
            local.refused.contains(port),
            !port.is_credentialed(),
            "{}",
            port.label()
        );
    }
}

/// RR-6 and RR-7 one by one: a registry made of real seams but one, which is a stand-in, is refused
/// in production and the refusal names that seam alone. The twelve seams that reported nothing are
/// among them.
#[test]
fn one_stand_in_among_real_seams_is_named_alone() {
    use factory_composition::registry::check_fidelities;
    for odd in Seams::port_names() {
        let reported: Vec<(PortName, Fidelity)> = PortName::ALL
            .iter()
            .map(|port| {
                (
                    *port,
                    if port == odd {
                        Fidelity::Fake
                    } else {
                        Fidelity::Real
                    },
                )
            })
            .collect();
        let refusal = check_fidelities(Profile::Production, &reported)
            .expect_err("production must refuse a stand-in");
        assert_eq!(refusal.refused, vec![*odd], "{}", odd.label());
    }
}

/// The registry does not take the label a seam was handed with: a stand-in given to
/// `SupplyChainSources::real` is still refused, because the registry reads what the source says it is.
#[test]
fn a_stand_in_handed_over_as_real_is_still_refused_in_production() {
    use factory_composition::supply_chain::SupplyChainSources;
    let sources = SupplyChainSources::real(
        Arc::new(StaticRegistry::new()),
        Arc::new(StaticDatabase::default()),
    );
    assert!(sources.stand_ins().is_empty(), "the label says real");
    let registry = registry(true);
    let mut reported = registry.fidelities();
    for (port, fidelity) in &mut reported {
        match port {
            PortName::PackageMetadata => *fidelity = sources.registry().fidelity(),
            PortName::AdvisoryDatabase => *fidelity = sources.advisory_db().fidelity(),
            _ => *fidelity = Fidelity::Real,
        }
    }
    let refusal = factory_composition::registry::check_fidelities(Profile::Production, &reported)
        .expect_err("the two stand-ins are refused");
    assert_eq!(
        refusal.refused,
        [PortName::PackageMetadata, PortName::AdvisoryDatabase]
    );
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
    // Every one of the 37 ports is a fake here, and the registry reports all 37.
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
    // With the real clock, ids and ticker, the other 34 ports are still fakes and still refused.
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
