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
use factory_domain::policy::security::ExposedWorkflows;
use factory_domain::scope::TenantScope;
use factory_domain::values::Slug;
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{
    BypassAttestation, ProtectionReport, RequiredCheck, WorkflowExposureAcknowledgement,
};
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
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn attestation(&self, _: TenantId, _: &RepoRef) -> Option<BypassAttestation> {
        Some(BypassAttestation {
            by: self.0,
            at: factory_domain::values::Timestamp::parse("2026-10-28T09:00:00Z").expect("a time"),
        })
    }
}

/// An administrator's statement about the bypass list, and an owner's acknowledgement of the
/// workflows named here (threat T-48), from a test.
struct AttestedAndAcknowledged {
    by: PrincipalId,
    workflows: Vec<&'static str>,
}

#[async_trait]
impl BypassAttestations for AttestedAndAcknowledged {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn attestation(&self, tenant: TenantId, repo: &RepoRef) -> Option<BypassAttestation> {
        Attested(self.by).attestation(tenant, repo).await
    }

    async fn workflow_acknowledgement(
        &self,
        _: TenantId,
        _: &RepoRef,
    ) -> Option<WorkflowExposureAcknowledgement> {
        Some(WorkflowExposureAcknowledgement {
            by: self.by,
            at: factory_domain::values::Timestamp::parse("2026-11-12T09:00:00Z").expect("a time"),
            workflows: self
                .workflows
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
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
        required_approving_reviews: Some(1),
        required_checks: vec![RequiredCheck {
            context: "factory-validation".to_owned(),
            integration_id: Some(FAKE_APP_ID.0),
        }],
        // As the adapter answers: the preflight reads and judges the workflows itself.
        exposed_workflows: None,
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
    // What the shipped policy says an exposed workflow costs: a cap at L0.
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let consequence = policies
        .security
        .credentials
        .repository_requirements
        .exposed_workflows;
    recorder_under(fixture, source, attestations, consequence)
}

fn recorder_under(
    fixture: &Fixture,
    source: Arc<FakeIssueSource>,
    attestations: Arc<dyn BypassAttestations>,
    exposed_workflows: ExposedWorkflows,
) -> ProtectionPreflight {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    ProtectionPreflight::new(PreflightDeps {
        store: fixture.world.store.clone(),
        source,
        app: FAKE_APP_ID,
        checks: vec![Slug::parse("factory-validation").expect("a slug")],
        required_approvals: policies
            .engine
            .authority
            .approvals_every_pull_request_needs(),
        exposed_workflows,
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
async fn rules_that_ask_for_fewer_approving_reviews_than_the_policy_needs_cap_the_repository() {
    // SF-07. The policy says every pull request needs at least one approval. A ruleset that asks
    // for none, and one whose count could not be read, each cap the repository with a named
    // reason, and the audit record carries it.
    for (count, reason) in [
        (
            Some(0),
            "The rules require 0 approving reviews, and the policy needs at least 1.",
        ),
        (
            None,
            "The number of approving reviews that the rules require could not be read.",
        ),
    ] {
        let fixture = fixture().await;
        let source = Arc::new(FakeIssueSource::new());
        let mut short = protected_as_the_policy_wants();
        short.required_approving_reviews = count;
        source.seed_protection(&fixture.repo, short).await;
        let preflight = recorder(
            &fixture,
            source,
            Arc::new(Attested(fixture.world.requester)),
        );

        let done = preflight.pass(fixture.tenant).await;

        assert!(!done[0].passed, "{count:?}");
        assert_eq!(done[0].missing, [reason], "{count:?}");
        assert!(!admission_level_passed(&fixture).await, "{count:?}");
        let audit = audit_actions(&fixture).await;
        assert!(audit[0].contains(reason), "{audit:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rules_that_ask_for_as_many_approving_reviews_as_the_policy_or_more_pass() {
    // The sibling of the test above: the number the policy needs, and more, is enough.
    for count in [1, 2, 5] {
        let fixture = fixture().await;
        let source = Arc::new(FakeIssueSource::new());
        let mut enough = protected_as_the_policy_wants();
        enough.required_approving_reviews = Some(count);
        source.seed_protection(&fixture.repo, enough).await;
        let preflight = recorder(
            &fixture,
            source,
            Arc::new(Attested(fixture.world.requester)),
        );

        let done = preflight.pass(fixture.tenant).await;

        assert!(done[0].passed, "{count}: {:?}", done[0].missing);
        assert!(admission_level_passed(&fixture).await, "{count}");
    }
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
async fn a_protection_the_app_may_not_read_is_named_and_not_taken_for_unprotected() {
    // A classic protection read refused for want of `administration: read` (the owner's decision
    // of 2026-11-12 made it required) caps the repository, and the record says which permission
    // is missing instead of saying that the branch is unprotected.
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    source.refuse_the_protection_read(true);
    let preflight = recorder(
        &fixture,
        source,
        Arc::new(Attested(fixture.world.requester)),
    );

    let done = preflight.pass(fixture.tenant).await;

    assert!(!done[0].passed);
    assert_eq!(
        done[0].missing,
        [
            "The App was refused a read of the protection of the default branch: it needs metadata: read for the rulesets and administration: read for classic branch protection."
        ]
    );
    assert!(!done[0].missing[0].contains("Neither"));
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
        required_approvals: 1,
        exposed_workflows: ExposedWorkflows::CapAtL0,
        attestations: Arc::new(NoAttestations),
        tenants: vec![tenant],
        policy_hash: policies.hash.clone(),
        ids: world.ids.clone(),
    });
    assert!(preflight.pass(tenant).await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// The workflows of the target repository (threat T-48)
// ---------------------------------------------------------------------------------------------
//
// Each test seeds a repository that is protected as the policy wants, with a bypass statement, so
// that the workflows are the only thing that can cap it. The workflow files are real YAML; the
// preflight reads them through the code host port and judges them.

const CI: &str = ".github/workflows/ci.yml";
const DEPLOY: &str = ".github/workflows/deploy.yml";

/// A job that reads no secret, on a runner of GitHub.
const JOB: &str = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: make test\n";

/// The same job with a deployment secret in its environment.
const JOB_WITH_A_SECRET: &str = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n        env:\n          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n";

const READ_ONLY: &str = "permissions:\n  contents: read\n";

/// Runs one pass over a well protected repository that has these workflow files.
async fn pass_with(
    workflows: &[(&str, Option<&str>)],
    attestations: impl FnOnce(&Fixture) -> Arc<dyn BypassAttestations>,
) -> (Fixture, factory_composition::preflight::Recorded) {
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    for (path, text) in workflows {
        source.seed_workflow(&fixture.repo, path, *text);
    }
    let attestations = attestations(&fixture);
    let preflight = recorder(&fixture, source, attestations);
    let mut done = preflight.pass(fixture.tenant).await;
    assert_eq!(done.len(), 1);
    (fixture, done.remove(0))
}

fn attested(fixture: &Fixture) -> Arc<dyn BypassAttestations> {
    Arc::new(Attested(fixture.world.requester))
}

/// Asserts that the repository passed, that the admission sees it, and that the one audit record
/// allows it with no word about workflows.
async fn assert_passes(workflows: &[(&str, Option<&str>)], what: &str) {
    let (fixture, done) = pass_with(workflows, attested).await;
    assert!(done.passed, "{what}: {:?}", done.missing);
    assert!(done.exposed_workflows.is_empty(), "{what}: {done:?}");
    assert!(!done.passed_on_acknowledgement, "{what}");
    assert!(admission_level_passed(&fixture).await, "{what}");
    let audit = audit_actions(&fixture).await;
    assert_eq!(audit.len(), 1, "{what}: {audit:?}");
    assert!(audit[0].starts_with("Allow"), "{what}: {audit:?}");
    assert!(!audit[0].contains("workflow"), "{what}: {audit:?}");
}

/// Asserts that the repository is capped for one workflow and that the sentence, with its reason
/// code, is in the result and in the audit record.
async fn assert_exposed(text: Option<&str>, reason: &str, what: &str) {
    let (fixture, done) = pass_with(&[(CI, text)], attested).await;
    assert!(!done.passed, "{what}");
    assert_eq!(done.missing.len(), 1, "{what}: {:?}", done.missing);
    let sentence = &done.missing[0];
    assert!(
        sentence.starts_with(
            "The workflow .github/workflows/ci.yml is exposed to factory branches: it "
        ),
        "{what}: {sentence}"
    );
    assert!(sentence.contains(reason), "{what}: {sentence}");
    assert_eq!(done.exposed_workflows.len(), 1, "{what}");
    assert!(
        !admission_level_passed(&fixture).await,
        "{what}: the repository is capped"
    );
    let audit = audit_actions(&fixture).await;
    assert_eq!(audit.len(), 1, "{what}: {audit:?}");
    assert!(audit[0].starts_with("Deny"), "{what}: {audit:?}");
    assert!(audit[0].contains("level L0"), "{what}: {audit:?}");
    assert!(audit[0].contains(sentence.as_str()), "{what}: {audit:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_with_no_workflows_passes() {
    assert_passes(&[], "no workflow directory").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workflow_that_only_runs_for_pushes_to_main_passes_even_with_a_secret() {
    let text = format!("on:\n  push:\n    branches: [main]\n{JOB_WITH_A_SECRET}");
    assert_passes(&[(CI, Some(&text))], "push to main only").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_workflow_with_no_branch_filter_and_a_secret_is_exposed() {
    let text = format!("on:\n  push:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    assert_exposed(
        Some(&text),
        "reads a secret (uses_secrets)",
        "push without a filter",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_workflow_that_ignores_factory_branches_passes_even_with_a_secret() {
    let text = format!(
        "on:\n  push:\n    branches-ignore: ['factory/**']\n{READ_ONLY}{JOB_WITH_A_SECRET}"
    );
    assert_passes(&[(CI, Some(&text))], "branches-ignore factory/**").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_pull_request_workflow_without_secrets_passes() {
    let text = format!("on:\n  pull_request:\n    branches: [main]\n{READ_ONLY}{JOB}");
    assert_passes(&[(CI, Some(&text))], "read-only pull request check").await;
    // The usual form, with no base branch filter at all.
    let text = format!("on:\n  pull_request:\n{READ_ONLY}{JOB}");
    assert_passes(&[(CI, Some(&text))], "read-only pull request check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pull_request_workflow_with_a_secret_is_exposed() {
    let text =
        format!("on:\n  pull_request:\n    branches: [main]\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    assert_exposed(
        Some(&text),
        "reads a secret (uses_secrets)",
        "pull request with a secret",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pull_request_workflow_for_another_base_branch_passes_even_with_a_secret() {
    // The sibling of the test above: the factory opens its pull request against `main`.
    let text =
        format!("on:\n  pull_request:\n    branches: [release]\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    assert_passes(&[(CI, Some(&text))], "pull request to another branch").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workflow_without_declared_permissions_or_with_a_write_permission_is_exposed() {
    let text = format!("on:\n  pull_request:\n{JOB}");
    assert_exposed(
        Some(&text),
        "(permissions_not_declared)",
        "no permissions declared",
    )
    .await;
    let text = format!("on:\n  pull_request:\npermissions:\n  contents: write\n{JOB}");
    assert_exposed(Some(&text), "(write_permissions)", "a write permission").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pull_request_target_workflow_is_exposed() {
    let text = format!("on:\n  pull_request_target:\n{READ_ONLY}{JOB}");
    assert_exposed(
        Some(&text),
        "starts on pull_request_target (pull_request_target)",
        "pull_request_target",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workflow_on_a_self_hosted_runner_is_exposed() {
    let text = format!(
        "on:\n  pull_request:\n{READ_ONLY}jobs:\n  test:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make test\n"
    );
    assert_exposed(
        Some(&text),
        "runs on a self-hosted runner (self_hosted_runner)",
        "self-hosted",
    )
    .await;
    let text = format!(
        "on:\n  pull_request:\n{READ_ONLY}jobs:\n  test:\n    runs-on: ${{{{ matrix.os }}}}\n    steps:\n      - run: make test\n"
    );
    assert_exposed(
        Some(&text),
        "(runner_unknown)",
        "a runner from an expression",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workflow_that_cannot_be_parsed_or_read_is_exposed() {
    assert_exposed(
        Some("on: [push\njobs: {"),
        "could not be read as a workflow (unreadable)",
        "broken YAML",
    )
    .await;
    assert_exposed(
        Some("on: push\nshared: &steps [a]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: *steps\n"),
        "(unreadable)",
        "an anchor, outside what the reader accepts",
    )
    .await;
    assert_exposed(None, "(unreadable)", "a file the host gave no text for").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn workflow_files_that_cannot_be_listed_cap_the_repository() {
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    source.make_the_workflow_read_fail(true);
    let preflight = recorder(&fixture, source.clone(), attested(&fixture));

    let done = preflight.pass(fixture.tenant).await;

    assert!(!done[0].passed);
    assert_eq!(
        done[0].missing,
        [
            "The workflows of the default branch could not be read, so nothing says that none is exposed to factory branches."
        ]
    );
    assert!(!admission_level_passed(&fixture).await);
    // The sibling: once the read works, the same repository passes.
    source.make_the_workflow_read_fail(false);
    let done = preflight.pass(fixture.tenant).await;
    assert!(done[0].passed, "{:?}", done[0].missing);
    assert!(admission_level_passed(&fixture).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_of_exactly_the_exposed_workflows_passes_and_is_audited() {
    let exposed = format!("on:\n  pull_request:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    let target = format!("on:\n  pull_request_target:\n{READ_ONLY}{JOB}");
    let safe = format!("on:\n  pull_request:\n{READ_ONLY}{JOB}");
    let workflows = [
        (CI, Some(exposed.as_str())),
        (DEPLOY, Some(target.as_str())),
        (".github/workflows/lint.yml", Some(safe.as_str())),
    ];
    let (fixture, done) = pass_with(&workflows, |fixture| {
        Arc::new(AttestedAndAcknowledged {
            by: fixture.world.requester,
            workflows: vec![DEPLOY, CI],
        })
    })
    .await;

    assert!(done.passed, "{:?}", done.missing);
    assert!(done.passed_on_acknowledgement);
    assert_eq!(done.exposed_workflows.len(), 2, "{done:?}");
    assert!(admission_level_passed(&fixture).await);
    let audit = audit_actions(&fixture).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    let record = &audit[0];
    assert!(record.starts_with("Allow"), "{record}");
    assert!(
        record.contains("passed because of an acknowledgement of exposed workflows"),
        "{record}"
    );
    assert!(
        record.contains(&format!("principal {}", fixture.world.requester)),
        "the record names who acknowledged: {record}"
    );
    assert!(record.contains("2026-11-12T09:00:00Z"), "{record}");
    for part in [CI, DEPLOY, "uses_secrets", "pull_request_target"] {
        assert!(record.contains(part), "{part}: {record}");
    }
    assert!(!record.contains("lint.yml"), "{record}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pass_on_an_acknowledgement_is_audited_at_every_pass() {
    let exposed = format!("on:\n  pull_request:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    source.seed_workflow(&fixture.repo, CI, Some(&exposed));
    let preflight = recorder(
        &fixture,
        source,
        Arc::new(AttestedAndAcknowledged {
            by: fixture.world.requester,
            workflows: vec![CI],
        }),
    );
    preflight.pass(fixture.tenant).await;
    preflight.pass(fixture.tenant).await;
    let audit = audit_actions(&fixture).await;
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert!(
        audit
            .iter()
            .all(|record| record.contains("acknowledgement"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_of_a_different_set_of_workflows_does_not_pass() {
    let exposed = format!("on:\n  pull_request:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    let target = format!("on:\n  pull_request_target:\n{READ_ONLY}{JOB}");
    let workflows = [
        (CI, Some(exposed.as_str())),
        (DEPLOY, Some(target.as_str())),
    ];
    for (named, what) in [
        (vec![CI], "one exposed workflow is not named"),
        (
            vec![CI, DEPLOY, ".github/workflows/old.yml"],
            "a workflow that is not exposed is named",
        ),
        (
            vec![CI, ".github/workflows/other.yml"],
            "another workflow is named",
        ),
    ] {
        let (fixture, done) = pass_with(&workflows, |fixture| {
            Arc::new(AttestedAndAcknowledged {
                by: fixture.world.requester,
                workflows: named.clone(),
            })
        })
        .await;

        assert!(!done.passed, "{what}");
        assert!(!done.passed_on_acknowledgement, "{what}");
        assert_eq!(done.missing.len(), 3, "{what}: {:?}", done.missing);
        assert_eq!(
            done.missing[2],
            "The recorded acknowledgement of exposed workflows names a different list of workflows, so it covers none of them.",
            "{what}"
        );
        assert!(!admission_level_passed(&fixture).await, "{what}");
        let audit = audit_actions(&fixture).await;
        assert!(audit[0].starts_with("Deny"), "{what}: {audit:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_does_not_stand_in_for_the_bypass_statement() {
    /// Acknowledges the workflow and says nothing about the bypass list.
    struct OnlyAcknowledged(PrincipalId);

    #[async_trait]
    impl BypassAttestations for OnlyAcknowledged {
        fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
            factory_domain::vocabulary::Fidelity::Fake
        }

        async fn attestation(&self, _: TenantId, _: &RepoRef) -> Option<BypassAttestation> {
            None
        }

        async fn workflow_acknowledgement(
            &self,
            tenant: TenantId,
            repo: &RepoRef,
        ) -> Option<WorkflowExposureAcknowledgement> {
            AttestedAndAcknowledged {
                by: self.0,
                workflows: vec![CI],
            }
            .workflow_acknowledgement(tenant, repo)
            .await
        }
    }

    let exposed = format!("on:\n  pull_request:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    let (fixture, done) = pass_with(&[(CI, Some(&exposed))], |fixture| {
        Arc::new(OnlyAcknowledged(fixture.world.requester))
    })
    .await;
    assert!(!done.passed);
    assert!(!done.passed_on_acknowledgement);
    assert_eq!(
        done.missing,
        ["Nobody recorded that the App is on no bypass list."]
    );
    assert!(!admission_level_passed(&fixture).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_that_only_records_names_the_exposed_workflows_and_does_not_cap() {
    let exposed = format!("on:\n  pull_request:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    let fixture = fixture().await;
    let source = Arc::new(FakeIssueSource::new());
    source
        .seed_protection(&fixture.repo, protected_as_the_policy_wants())
        .await;
    source.seed_workflow(&fixture.repo, CI, Some(&exposed));
    let preflight = recorder_under(
        &fixture,
        source,
        attested(&fixture),
        ExposedWorkflows::RecordOnly,
    );

    let done = preflight.pass(fixture.tenant).await;

    assert!(done[0].passed, "{:?}", done[0].missing);
    assert!(!done[0].passed_on_acknowledgement);
    assert_eq!(done[0].exposed_workflows.len(), 1);
    assert!(admission_level_passed(&fixture).await);
    let audit = audit_actions(&fixture).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert!(audit[0].starts_with("Allow"), "{audit:?}");
    assert!(audit[0].contains("record_only"), "{audit:?}");
    assert!(audit[0].contains("uses_secrets"), "{audit:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_configured_acknowledgements_are_what_the_preflight_is_given() {
    // The production source: `github.workflow_exposure_acknowledgements` of the worker
    // configuration, read by the same type that reads the bypass statements.
    use factory_composition::config::{
        AttestationConfig, GithubConfig, WorkflowAcknowledgementConfig,
    };
    use factory_composition::external::ConfigAttestations;

    let exposed = format!("on:\n  pull_request:\n{READ_ONLY}{JOB_WITH_A_SECRET}");
    for (named, passes) in [(CI, true), (DEPLOY, false)] {
        let (fixture, done) = pass_with(&[(CI, Some(&exposed))], |fixture| {
            let tenant = fixture.tenant.as_uuid().to_string();
            let principal = fixture.world.requester.to_string();
            let github: GithubConfig = serde_json::from_value(serde_json::json!({
                "app_id": 7,
                "key_file": "/run/secrets/app",
            }))
            .expect("a GitHub configuration");
            let github = GithubConfig {
                bypass_attestations: vec![AttestationConfig {
                    tenant: tenant.clone(),
                    repository: "org/repo-0".to_owned(),
                    principal: principal.clone(),
                    recorded_at: "2026-10-28T09:00:00Z".to_owned(),
                }],
                workflow_exposure_acknowledgements: vec![WorkflowAcknowledgementConfig {
                    tenant,
                    repository: "org/repo-0".to_owned(),
                    principal,
                    recorded_at: "2026-11-12T09:00:00Z".to_owned(),
                    workflows: vec![named.to_owned()],
                }],
                ..github
            };
            Arc::new(ConfigAttestations::from_config(&github))
        })
        .await;
        assert_eq!(done.passed, passes, "{named}: {:?}", done.missing);
        assert_eq!(done.passed_on_acknowledgement, passes, "{named}");
        assert_eq!(admission_level_passed(&fixture).await, passes, "{named}");
    }
}
