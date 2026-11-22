//! The rules check (ADR 0026) over the in-memory store and the fake rules host of the test kit:
//! the onboarding trigger, the trigger before each claim, the hour between two checks, the
//! decision on what the default branch holds, the skeleton files, the audit trail and the
//! credential that ends with each check.
//!
//! **Fake, and labelled so:** the store (`InMemoryStore`), the code host
//! (`FakeProposalHost`, `FakeChangeHost`) and the clock. Nothing here reaches GitHub.

use std::sync::Arc;
use std::time::Duration;

use factory_composition::hooks::BeforeClaim as _;
use factory_composition::indexing::ActiveJobs;
use factory_composition::project_rules::{
    Checked, NOT_PROPOSED, PROPOSED, ProjectRulesSync, ProjectRulesSyncDeps, RECHECK_AFTER,
    RepositoryOnboarded as _,
};
use factory_domain::ids::{CorrelationId, JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::project_rules::{
    END_MARKER, NothingBecause, TEMPLATE, TEMPLATE_VERSION, Template, begin_marker,
};
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::clock::Uuid;
use factory_ports::paths::RepoRef;
use factory_ports::proposal::RULES_BRANCH;
use factory_ports::store::{
    AuditFilter, NewJob, NewPrincipal, PipelineScope, PrincipalKind, Store,
};
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::proposal::{DEFAULT_BRANCH, FakeProposalHost};
use factory_testkit::store::InMemoryStore;

fn uid(n: u128) -> Uuid {
    Uuid::from_u128((n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62) | n)
}

/// The name `InMemoryStore::seed_repository` gives every repository.
fn repo() -> RepoRef {
    RepoRef::parse("acme/widgets").unwrap()
}

struct Rig {
    clock: Arc<FakeClock>,
    store: Arc<InMemoryStore>,
    host: Arc<FakeProposalHost>,
    changes: Arc<FakeChangeHost>,
    jobs: Arc<ActiveJobs>,
    tenant: TenantId,
    repository: RepositoryId,
}

impl Rig {
    fn new() -> Self {
        let clock = Arc::new(FakeClock::starting_at("2026-11-20T10:00:00Z"));
        let store = Arc::new(InMemoryStore::new(clock.clone()));
        let tenant = TenantId::from_uuid(uid(1));
        let repository = store.seed_repository(tenant);
        let host = Arc::new(FakeProposalHost::new());
        host.person_commit(
            &repo(),
            DEFAULT_BRANCH,
            &[("README.md", Some("# Widgets\n"))],
        );
        Self {
            clock,
            store,
            host,
            changes: Arc::new(FakeChangeHost::new()),
            jobs: Arc::new(ActiveJobs::new()),
            tenant,
            repository,
        }
    }

    fn sync(&self) -> ProjectRulesSync {
        self.sync_with(Template::current())
    }

    fn sync_with(&self, template: Template<'static>) -> ProjectRulesSync {
        ProjectRulesSync::with_template(
            ProjectRulesSyncDeps {
                store: self.store.clone(),
                host: self.host.clone(),
                changes: self.changes.clone(),
                jobs: Arc::clone(&self.jobs),
                clock: self.clock.clone(),
                ids: Arc::new(SequentialIdGenerator::new()),
                tenants: vec![self.tenant],
                policy_hash: Sha256Digest::of(b"the policy in force"),
            },
            template,
        )
    }

    fn default_file(&self, path: &str) -> Option<String> {
        self.host
            .files_on(&repo(), DEFAULT_BRANCH)
            .get(path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }

    fn branch_file(&self, path: &str) -> Option<String> {
        self.host
            .files_on(&repo(), RULES_BRANCH)
            .get(path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }

    async fn audit_actions(&self) -> Vec<String> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        let records = tx.read_audit(AuditFilter::Tenant, 0, 100).await.unwrap();
        let _ = tx.rollback().await;
        records
            .into_iter()
            .map(|record| record.event.action.as_str().to_owned())
            .collect()
    }

    async fn received_job(&self) -> JobId {
        let principal = PrincipalId::from_uuid(uid(50));
        let job = JobId::from_uuid(uid(51));
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        tx.insert_principal(NewPrincipal {
            id: principal,
            kind: PrincipalKind::Human { github_user_id: 7 },
            login: Some("octocat".to_owned()),
        })
        .await
        .unwrap();
        tx.insert_job(NewJob {
            id: job,
            correlation_id: CorrelationId::from_uuid(uid(52)),
            repository: self.repository,
            requester: principal,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L1,
            pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).unwrap(),
            origin: None,
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
        job
    }
}

/// A template one version above the shipped one, with another text.
fn next_template() -> Template<'static> {
    Template {
        text: "# Rules for agents, the next version\n",
        version: TEMPLATE_VERSION + 1,
    }
}

#[tokio::test]
async fn onboarding_a_project_without_rules_opens_one_draft_pull_request_with_the_skeleton() {
    let rig = Rig::new();
    let sync = rig.sync();
    sync.onboarded(rig.tenant, rig.repository).await;

    let pulls = rig.host.pulls(&repo());
    assert_eq!(pulls.len(), 1);
    let pull = &pulls[0];
    assert!(pull.draft && pull.by_factory);
    assert_eq!(pull.head, RULES_BRANCH);
    assert_eq!(
        pull.title,
        format!("Install the rules for agents in AGENTS.md (version {TEMPLATE_VERSION})")
    );
    assert!(
        pull.body.contains("- `docs/adr/README.md`"),
        "{}",
        pull.body
    );

    let rules = rig
        .branch_file("AGENTS.md")
        .expect("the rules on the branch");
    assert!(rules.starts_with(&format!(
        "{}\n{TEMPLATE}{END_MARKER}\n",
        begin_marker(TEMPLATE_VERSION)
    )));
    for path in [
        "docs/README.md",
        "docs/specifications/README.md",
        "docs/architecture/README.md",
        "docs/adr/README.md",
        "docs/guides/README.md",
        "docs/reference/README.md",
        "docs/knowledge/README.md",
    ] {
        assert!(rig.branch_file(path).is_some(), "{path}");
    }
    assert_eq!(
        rig.default_file("AGENTS.md"),
        None,
        "the default branch is not written"
    );
    assert_eq!(rig.audit_actions().await, vec![PROPOSED.to_owned()]);
    assert!(
        rig.changes.revoked_jobs().len() == 1,
        "the credential of the check ends with it"
    );
}

#[tokio::test]
async fn a_skeleton_file_the_project_has_is_never_proposed() {
    let rig = Rig::new();
    rig.host.person_commit(
        &repo(),
        DEFAULT_BRANCH,
        &[("docs/README.md", Some("# Our own index\n"))],
    );
    rig.sync().onboarded(rig.tenant, rig.repository).await;
    assert_eq!(
        rig.branch_file("docs/README.md").as_deref(),
        Some("# Our own index\n"),
        "the project's file is left as it is"
    );
    assert!(
        !rig.host.pulls(&repo())[0]
            .body
            .contains("- `docs/README.md`")
    );
}

#[tokio::test]
async fn a_hand_written_agents_file_is_kept_after_the_factory_section() {
    let rig = Rig::new();
    rig.host.person_commit(
        &repo(),
        DEFAULT_BRANCH,
        &[("AGENTS.md", Some("# Our agents\n\nUse tabs.\n"))],
    );
    rig.sync().onboarded(rig.tenant, rig.repository).await;
    let rules = rig.branch_file("AGENTS.md").unwrap();
    assert!(
        rules.ends_with(&format!("{END_MARKER}\n\n# Our agents\n\nUse tabs.\n")),
        "{rules}"
    );
}

#[tokio::test]
async fn after_the_merge_the_repository_is_up_to_date_and_nothing_is_proposed() {
    let rig = Rig::new();
    let sync = rig.sync();
    sync.onboarded(rig.tenant, rig.repository).await;
    rig.host.merge(&repo(), 1);
    assert_eq!(
        sync.check_now(rig.tenant, rig.repository).await,
        Checked::Nothing(NothingBecause::UpToDate)
    );
    assert_eq!(rig.host.pulls(&repo()).len(), 1);
}

#[tokio::test]
async fn an_open_proposal_of_this_version_is_not_opened_again() {
    let rig = Rig::new();
    let sync = rig.sync();
    sync.onboarded(rig.tenant, rig.repository).await;
    // The enable comes a minute later and checks again.
    assert_eq!(
        sync.check_now(rig.tenant, rig.repository).await,
        Checked::Nothing(NothingBecause::AlreadyProposed)
    );
    assert_eq!(rig.host.pulls(&repo()).len(), 1);
}

#[tokio::test]
async fn a_declined_version_is_not_proposed_again_and_the_next_version_is() {
    let rig = Rig::new();
    rig.sync().onboarded(rig.tenant, rig.repository).await;
    rig.host.close(&repo(), 1);
    assert_eq!(
        rig.sync().check_now(rig.tenant, rig.repository).await,
        Checked::Nothing(NothingBecause::Declined)
    );
    let next = rig.sync_with(next_template());
    assert!(matches!(
        next.check_now(rig.tenant, rig.repository).await,
        Checked::Proposed(_)
    ));
    assert_eq!(rig.host.pulls(&repo()).len(), 2);
}

#[tokio::test]
async fn a_new_release_updates_an_installed_older_version_and_keeps_the_project_section() {
    let rig = Rig::new();
    rig.sync().onboarded(rig.tenant, rig.repository).await;
    rig.host.merge(&repo(), 1);
    // A person adds a rule of the project after the factory's section.
    let installed = rig.default_file("AGENTS.md").unwrap();
    let with_ours = format!("{installed}- Money is in cents.\n");
    rig.host
        .person_commit(&repo(), DEFAULT_BRANCH, &[("AGENTS.md", Some(&with_ours))]);

    let next = rig.sync_with(next_template());
    let Checked::Proposed(pr) = next.check_now(rig.tenant, rig.repository).await else {
        panic!("the update is proposed");
    };
    let pull = rig
        .host
        .pulls(&repo())
        .into_iter()
        .find(|p| p.number == pr.number)
        .unwrap();
    assert_eq!(
        pull.title,
        format!(
            "Update the rules for agents in AGENTS.md to version {}",
            TEMPLATE_VERSION + 1
        )
    );
    let rules = rig.branch_file("AGENTS.md").unwrap();
    assert!(rules.starts_with(&begin_marker(TEMPLATE_VERSION + 1)));
    assert!(rules.contains("# Rules for agents, the next version\n"));
    assert!(rules.ends_with("- Money is in cents.\n"), "{rules}");
    assert!(
        !pull.body.contains("index files"),
        "the skeleton was merged already"
    );
}

#[tokio::test]
async fn a_file_edited_by_hand_or_installed_by_a_newer_factory_is_left_alone() {
    let rig = Rig::new();
    let edited = format!(
        "{}\nour own words\n{END_MARKER}\n",
        begin_marker(TEMPLATE_VERSION)
    );
    rig.host
        .person_commit(&repo(), DEFAULT_BRANCH, &[("AGENTS.md", Some(&edited))]);
    assert_eq!(
        rig.sync().check_now(rig.tenant, rig.repository).await,
        Checked::Nothing(NothingBecause::EditedByHand)
    );
    let newer = format!(
        "{}\nlater\n{END_MARKER}\n",
        begin_marker(TEMPLATE_VERSION + 5)
    );
    rig.host
        .person_commit(&repo(), DEFAULT_BRANCH, &[("AGENTS.md", Some(&newer))]);
    assert_eq!(
        rig.sync().check_now(rig.tenant, rig.repository).await,
        Checked::Nothing(NothingBecause::NewerFactory)
    );
    assert!(rig.host.pulls(&repo()).is_empty());
    assert!(rig.audit_actions().await.is_empty());
}

#[tokio::test]
async fn an_unreadable_file_is_not_proposed_and_the_audit_says_why() {
    let rig = Rig::new();
    let broken = format!("{}\nno end marker\n", begin_marker(TEMPLATE_VERSION));
    rig.host
        .person_commit(&repo(), DEFAULT_BRANCH, &[("AGENTS.md", Some(&broken))]);
    let checked = rig.sync().check_now(rig.tenant, rig.repository).await;
    assert!(matches!(
        checked,
        Checked::Nothing(NothingBecause::Unreadable(_))
    ));
    assert!(rig.host.pulls(&repo()).is_empty());
    assert_eq!(rig.audit_actions().await, vec![NOT_PROPOSED.to_owned()]);
}

#[tokio::test]
async fn before_a_claim_the_repository_of_a_waiting_job_is_checked_once_an_hour() {
    let rig = Rig::new();
    let sync = rig.sync();
    // No job waits: nothing is read.
    sync.before_claim().await;
    assert!(rig.host.pulls(&repo()).is_empty());

    rig.received_job().await;
    sync.before_claim().await;
    assert_eq!(rig.host.pulls(&repo()).len(), 1);

    // The person closes it; within the hour nothing is looked at again.
    rig.host.close(&repo(), 1);
    assert_eq!(
        sync.pass(rig.tenant).await,
        vec![(rig.repository, Checked::Recently)]
    );
    rig.clock.advance(RECHECK_AFTER + Duration::from_secs(1));
    assert_eq!(
        sync.pass(rig.tenant).await,
        vec![(rig.repository, Checked::Nothing(NothingBecause::Declined))]
    );
}

#[tokio::test]
async fn a_failure_of_the_host_is_reported_and_changes_nothing() {
    let rig = Rig::new();
    // The rules host knows no repository of that name: every read is NotFound.
    let other = Arc::new(FakeProposalHost::new());
    let sync = ProjectRulesSync::new(ProjectRulesSyncDeps {
        store: rig.store.clone(),
        host: other.clone(),
        changes: rig.changes.clone(),
        jobs: Arc::clone(&rig.jobs),
        clock: rig.clock.clone(),
        ids: Arc::new(SequentialIdGenerator::new()),
        tenants: vec![rig.tenant],
        policy_hash: Sha256Digest::of(b"the policy in force"),
    });
    assert!(matches!(
        sync.check_now(rig.tenant, rig.repository).await,
        Checked::Failed(_)
    ));
    assert!(rig.audit_actions().await.is_empty());
    assert_eq!(
        rig.changes.revoked_jobs().len(),
        1,
        "the credential ends even when the check fails"
    );
}

#[tokio::test]
async fn an_unknown_repository_is_not_checked() {
    let rig = Rig::new();
    let unknown = RepositoryId::from_uuid(uid(999));
    assert_eq!(
        rig.sync().check_now(rig.tenant, unknown).await,
        Checked::UnknownRepository
    );
}
