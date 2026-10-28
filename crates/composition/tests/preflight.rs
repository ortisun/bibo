//! The protection preflight recorder, over a real PostgreSQL and the testkit's code host.
//!
//! Before this nothing recorded the preflight: a repository ran at level L0 for ever and every
//! approval was refused as below its minimum level. The complete run recorded the result in the
//! database by hand, as an administrator would.

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use factory_composition::authority::StoreAuthority;
use factory_composition::hooks::BeforeClaim;
use factory_composition::preflight::{
    BypassAttestations, NoAttestations, PreflightDeps, ProtectionPreflight,
};
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_domain::ids::{PrincipalId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::Slug;
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{BypassAttestation, ProtectionReport, RequiredCheck};
use factory_ports::paths::RepoRef;
use factory_ports::store::{AuditFilter, Store};
use factory_testkit::contracts::githost::IssueSourceSubject;
use factory_testkit::githost::{FAKE_APP_ID, FakeIssueSource};
use factory_workflow::commands::Authority;
use support::pg_world;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// An administrator's statement, from a test.
struct Attested(PrincipalId);

#[async_trait]
impl BypassAttestations for Attested {
    async fn attestation(&self, _: TenantId, _: &RepoRef) -> Option<BypassAttestation> {
        Some(BypassAttestation {
            by: self.0,
            at: factory_domain::values::Timestamp::parse("2026-10-28T09:00:00Z").expect("a time"),
        })
    }
}

fn protected_as_the_policy_wants() -> ProtectionReport {
    ProtectionReport {
        default_branch: factory_ports::paths::BranchName::new("main").expect("a branch"),
        source: factory_ports::githost::ProtectionSource::Rulesets,
        requires_pull_request: true,
        requires_code_owner_review: true,
        dismisses_stale_approvals: true,
        blocks_force_push: true,
        blocks_deletion: true,
        required_checks: vec![RequiredCheck {
            context: "factory-validation".to_owned(),
            integration_id: Some(FAKE_APP_ID.0),
        }],
    }
}

struct Fixture {
    /// Keeps the database of the test alive.
    _db: Box<dyn std::any::Any>,
    world: support::engine::PgWorld,
    tenant: TenantId,
    repo: RepoRef,
}

async fn fixture() -> Fixture {
    let (db, world, tenant) = pg_world().await;
    let repo = RepoRef::parse("org/repo-0").expect("a repository");
    // A job that waits to be admitted: the preflight looks at the repositories of those.
    world
        .engine
        .receive_job(tenant, world.requester, world.repository)
        .await
        .expect("a received job");
    Fixture {
        _db: Box::new(db),
        world,
        tenant,
        repo,
    }
}

fn recorder(
    fixture: &Fixture,
    source: Arc<FakeIssueSource>,
    attestations: Arc<dyn BypassAttestations>,
) -> ProtectionPreflight {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    ProtectionPreflight::new(PreflightDeps {
        store: fixture.world.store.clone(),
        source,
        app: FAKE_APP_ID,
        checks: vec![Slug::parse("factory-validation").expect("a slug")],
        attestations,
        tenants: vec![fixture.tenant],
        policy_hash: policies.hash.clone(),
        ids: fixture.world.ids.clone(),
    })
}

async fn admission_level_passed(fixture: &Fixture) -> bool {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let checkout = root()
        .join("target/preflight")
        .join(fixture.world.ids.new_uuid().simple().to_string());
    std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
    std::fs::write(
        checkout.join("allowlist/allowlist.yaml"),
        format!(
            "version: 1\nentries:\n  - tenant: {}\n    github_user_id: 1001\n    login: requester-one\n    designations: [requester]\n",
            fixture.tenant.as_uuid()
        ),
    )
    .expect("the allowlist file");
    let authority = StoreAuthority::new(
        fixture.world.store.clone(),
        Arc::new(FileAllowlist::in_checkout(&checkout)),
        Arc::clone(&policies.engine),
        fixture.world.deps.clock.clone(),
    );
    authority
        .admission(
            fixture.tenant,
            fixture.world.requester,
            fixture.world.repository,
        )
        .await
        .expect("facts")
        .protection_preflight_passed
}

async fn audit_actions(fixture: &Fixture) -> Vec<String> {
    let mut tx = fixture
        .world
        .store
        .begin(TenantScope::new(fixture.tenant))
        .await
        .expect("a tx");
    let records = tx
        .read_audit(AuditFilter::Tenant, 0, 500)
        .await
        .expect("audit");
    let _ = tx.rollback().await;
    records
        .iter()
        .filter(|record| record.event.action.as_str() == "repository.protection_preflight")
        .map(|record| format!("{:?}: {}", record.event.decision, record.event.reason))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_protected_as_the_policy_wants_passes_and_the_result_is_recorded() {
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    let preflight = recorder(
        &fixture,
        source,
        Arc::new(Attested(fixture.world.requester)),
    );
    assert!(
        !admission_level_passed(&fixture).await,
        "before the step the repository has no passed preflight"
    );

    let done = preflight.pass(fixture.tenant).await;

    assert_eq!(done.len(), 1);
    assert!(done[0].passed, "{:?}", done[0].missing);
    assert!(
        admission_level_passed(&fixture).await,
        "the result is in the repository's row, where the admission reads it"
    );
    let audit = audit_actions(&fixture).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert!(audit[0].starts_with("Allow"), "{audit:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_attestation_caps_the_repository_and_says_why() {
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    let preflight = recorder(&fixture, source, Arc::new(NoAttestations));

    let done = preflight.pass(fixture.tenant).await;

    assert_eq!(done.len(), 1);
    assert!(!done[0].passed);
    assert_eq!(
        done[0].missing,
        ["Nobody recorded that the App is on no bypass list."]
    );
    assert!(!admission_level_passed(&fixture).await);
    let audit = audit_actions(&fixture).await;
    assert!(audit[0].starts_with("Deny"), "{audit:?}");
    assert!(audit[0].contains("level L0"), "{audit:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_protection_that_fell_short_is_listed_item_by_item() {
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    let mut weak = protected_as_the_policy_wants();
    weak.requires_code_owner_review = false;
    weak.blocks_force_push = false;
    weak.required_checks.clear();
    source.seed_protection(&fixture.repo, weak).await;
    let preflight = recorder(
        &fixture,
        source,
        Arc::new(Attested(fixture.world.requester)),
    );

    let done = preflight.pass(fixture.tenant).await;

    assert!(!done[0].passed);
    assert_eq!(done[0].missing.len(), 3, "{:?}", done[0].missing);
    assert!(!admission_level_passed(&fixture).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_protection_that_cannot_be_read_is_not_a_protection_that_holds() {
    let fixture = fixture().await;
    // The code host knows nothing of the repository.
    let source = Arc::new(FakeIssueSource::new());
    let preflight = recorder(
        &fixture,
        source,
        Arc::new(Attested(fixture.world.requester)),
    );

    let done = preflight.pass(fixture.tenant).await;

    assert!(!done[0].passed);
    assert_eq!(
        done[0].missing,
        ["The protection of the default branch could not be read."]
    );
    assert!(!admission_level_passed(&fixture).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_that_lost_its_protection_is_capped_again_at_the_next_job() {
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    let preflight = recorder(
        &fixture,
        source.clone(),
        Arc::new(Attested(fixture.world.requester)),
    );
    preflight.pass(fixture.tenant).await;
    assert!(admission_level_passed(&fixture).await);

    // Someone loosens the ruleset. The next job to wait for admission finds out.
    let mut loosened = protected_as_the_policy_wants();
    loosened.blocks_deletion = false;
    source.seed_protection(&fixture.repo, loosened).await;
    preflight.before_claim().await;

    assert!(
        !admission_level_passed(&fixture).await,
        "the repository is capped again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_with_no_waiting_job_is_not_asked_about_anything() {
    let (_db, world, tenant) = pg_world().await;
    let source = Arc::new(FakeIssueSource::new());
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let preflight = ProtectionPreflight::new(PreflightDeps {
        store: world.store.clone(),
        source,
        app: FAKE_APP_ID,
        checks: Vec::new(),
        attestations: Arc::new(NoAttestations),
        tenants: vec![tenant],
        policy_hash: policies.hash.clone(),
        ids: world.ids.clone(),
    });
    assert!(preflight.pass(tenant).await.is_empty());
}
