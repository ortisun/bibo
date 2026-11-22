//! The weekly measurement pull request (ADR 0029, ADR 0031) over the in-memory store, the fake
//! proposal host and the fake clock: every row of the design's table, every reason to propose
//! nothing, and the entry read back by the factory's own reader. Nothing here reaches GitHub.

use std::sync::Arc;

use factory_composition::indexing::ActiveJobs;
use factory_composition::knowledge_measurements::{
    KnowledgeMeasurements, KnowledgeMeasurementsDeps, Measured, PROPOSED, Skipped,
};
use factory_domain::ids::{CorrelationId, JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::knowledge::{EntryId, KnowledgeBase};
use factory_domain::metrics::{WeeklyNothingBecause, Window};
use factory_domain::project_rules::SKELETON;
use factory_domain::scope::TenantScope;
use factory_domain::state::JobStatus;
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::githost::PullRequestLifecycle;
use factory_ports::paths::RepoRef;
use factory_ports::proposal::MEASUREMENTS_BRANCH;
use factory_ports::store::{AuditFilter, Job, PipelineScope, Store};
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::proposal::{DEFAULT_BRANCH, FakeProposalHost};
use factory_testkit::store::InMemoryStore;
use factory_workflow::process_metrics::JobRecord;
use uuid::Uuid;

const INDEX: &str = "docs/knowledge/README.md";

fn uid(n: u128) -> Uuid {
    Uuid::from_u128((n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62) | n)
}

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("valid timestamp")
}

fn week(from: &str) -> Window {
    let start = at(from);
    let end = start
        .checked_add(std::time::Duration::from_secs(7 * 24 * 3600))
        .expect("in range");
    Window::new(start, end).expect("ordered")
}

/// The name `InMemoryStore::seed_repository` gives every repository.
fn repo() -> RepoRef {
    RepoRef::parse("acme/widgets").expect("valid")
}

struct Rig {
    store: Arc<InMemoryStore>,
    host: Arc<FakeProposalHost>,
    tenant: TenantId,
    repository: RepositoryId,
    step: KnowledgeMeasurements,
}

impl Rig {
    fn new(commit: Option<GitSha>, with_knowledge_base: bool) -> Self {
        let clock = Arc::new(FakeClock::starting_at("2026-11-23T10:00:00Z"));
        let store = Arc::new(InMemoryStore::new(clock.clone()));
        let tenant = TenantId::from_uuid(uid(1));
        let repository = store.seed_repository(tenant);
        let host = Arc::new(FakeProposalHost::new());
        let index = SKELETON
            .iter()
            .find(|(path, _)| *path == INDEX)
            .expect("the skeleton has the index")
            .1;
        let mut files = vec![("README.md", Some("# Widgets\n"))];
        if with_knowledge_base {
            files.push((INDEX, Some(index)));
        }
        host.person_commit(&repo(), DEFAULT_BRANCH, &files);
        let step = KnowledgeMeasurements::new(KnowledgeMeasurementsDeps {
            store: store.clone(),
            host: host.clone(),
            changes: Arc::new(FakeChangeHost::new()),
            jobs: Arc::new(ActiveJobs::new()),
            clock,
            ids: Arc::new(SequentialIdGenerator::new()),
            tenants: vec![tenant],
            policy_hash: Sha256Digest::of(b"the policy in force"),
            commit,
        });
        Self {
            store,
            host,
            tenant,
            repository,
            step,
        }
    }

    fn ready() -> Self {
        Self::new(Some(GitSha::parse(&"a".repeat(40)).expect("valid")), true)
    }

    /// One job of the repository that ended at `ended`: one sample of the human wait and of the
    /// rework rounds in the week that holds that instant.
    fn ended_job(&self, ended: &str) -> JobRecord {
        JobRecord {
            job: Job {
                id: JobId::from_uuid(uid(100)),
                tenant_id: self.tenant,
                correlation_id: CorrelationId::from_uuid(uid(101)),
                repository: self.repository,
                requester: PrincipalId::from_uuid(uid(102)),
                status: JobStatus::Completed,
                execution_mode: ExecutionMode::Test,
                autonomy_level: AutonomyLevel::L1,
                pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).expect("valid"),
                origin: None,
                policy_hash: None,
                normalized_request: None,
                created_at: at("2026-11-02T09:00:00Z"),
                terminal_at: Some(at(ended)),
            },
            stage_runs: vec![],
            task_nodes: vec![],
            attempts: vec![],
            task_runs: vec![],
            pull_requests: vec![],
            events: vec![],
        }
    }

    async fn propose(&self, records: &[JobRecord], from: &str) -> Measured {
        self.step
            .propose_for(self.tenant, self.repository, records, week(from))
            .await
    }

    fn on_branch(&self, path: &str) -> Option<String> {
        self.host
            .files_on(&repo(), MEASUREMENTS_BRANCH)
            .get(path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }

    async fn audit_actions(&self) -> Vec<String> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let records = tx
            .read_audit(AuditFilter::Tenant, 0, 100)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        records
            .into_iter()
            .map(|record| record.event.action.as_str().to_owned())
            .collect()
    }
}

fn proposed_week(measured: &Measured) -> (u64, String) {
    match measured {
        Measured::Proposed(pr, id) => (pr.number, id.to_string()),
        other => panic!("expected a proposal, found {other:?}"),
    }
}

#[tokio::test]
async fn the_first_week_opens_one_draft_pull_request_with_the_entry_and_its_index_line() {
    let rig = Rig::ready();
    let job = rig.ended_job("2026-11-18T12:00:00Z");
    let measured = rig.propose(&[job], "2026-11-16T00:00:00Z").await;
    assert_eq!(proposed_week(&measured).1, "M-2026-W47");

    let entry = rig
        .on_branch("docs/knowledge/measurements/M-2026-W47.md")
        .expect("the entry is on the branch");
    let header =
        factory_contracts::knowledge::read_header(&entry).expect("the factory's reader reads it");
    assert_eq!(header.id().as_str(), "M-2026-W47");
    assert!(entry.contains("computed_at_commit: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
    assert!(
        entry.contains("| MT-0003 human-wait-time, median | too few samples | 1 |"),
        "{entry}"
    );

    let index = rig.on_branch(INDEX).expect("the index is on the branch");
    assert!(index.contains("| [M-2026-W47](measurements/M-2026-W47.md) | Process numbers, week 47 of 2026 | recorded |\n"));
    // The index on the branch is the one the factory writes, and the default branch is untouched.
    let file = factory_contracts::knowledge::read_file("measurements/M-2026-W47.md", &entry)
        .expect("reads");
    assert_eq!(KnowledgeBase::new(vec![file]).check_index(Some(&index)), []);
    let default = rig.host.files_on(&repo(), DEFAULT_BRANCH);
    assert!(!default.contains_key("docs/knowledge/measurements/M-2026-W47.md"));

    let pulls = rig.host.pulls(&repo());
    assert_eq!(pulls.len(), 1);
    assert!(pulls[0].draft);
    assert_eq!(pulls[0].head, MEASUREMENTS_BRANCH);
    assert_eq!(
        pulls[0].title,
        "Record the process numbers of week 47 of 2026"
    );
    assert!(pulls[0].body.contains("This pull request holds one week:"));
    assert!(
        pulls[0]
            .body
            .ends_with("<!-- factory-knowledge-measurement id=M-2026-W47 -->")
    );
    assert_eq!(rig.audit_actions().await, vec![PROPOSED.to_owned()]);
}

#[tokio::test]
async fn the_same_week_again_proposes_nothing_and_the_next_week_joins_the_open_pull_request() {
    let rig = Rig::ready();
    let first = rig
        .propose(
            &[rig.ended_job("2026-11-18T12:00:00Z")],
            "2026-11-16T00:00:00Z",
        )
        .await;
    let (number, _) = proposed_week(&first);
    assert_eq!(
        rig.propose(
            &[rig.ended_job("2026-11-18T12:00:00Z")],
            "2026-11-16T00:00:00Z"
        )
        .await,
        Measured::Skipped(Skipped::Decided(WeeklyNothingBecause::AlreadyProposed))
    );
    let next = rig
        .propose(
            &[rig.ended_job("2026-11-25T12:00:00Z")],
            "2026-11-23T00:00:00Z",
        )
        .await;
    assert_eq!(
        proposed_week(&next),
        (number, "M-2026-W48".to_owned()),
        "the same pull request"
    );
    let index = rig.on_branch(INDEX).expect("the index");
    assert!(
        index.contains("[M-2026-W47]") && index.contains("[M-2026-W48]"),
        "{index}"
    );
    assert!(
        rig.on_branch("docs/knowledge/measurements/M-2026-W47.md")
            .is_some(),
        "the earlier week is kept"
    );
    let pulls = rig.host.pulls(&repo());
    assert_eq!(pulls.len(), 1);
    assert_eq!(
        pulls[0].title,
        "Record the process numbers of week 48 of 2026"
    );
    assert!(pulls[0].body.contains("This pull request holds 2 weeks:"));
}

#[tokio::test]
async fn after_a_merge_the_next_week_opens_a_new_pull_request_and_a_declined_week_stays_declined() {
    let rig = Rig::ready();
    let first = rig
        .propose(
            &[rig.ended_job("2026-11-18T12:00:00Z")],
            "2026-11-16T00:00:00Z",
        )
        .await;
    rig.host.merge(&repo(), proposed_week(&first).0);
    assert_eq!(
        rig.propose(
            &[rig.ended_job("2026-11-18T12:00:00Z")],
            "2026-11-16T00:00:00Z"
        )
        .await,
        Measured::Skipped(Skipped::Decided(WeeklyNothingBecause::Recorded))
    );
    let second = rig
        .propose(
            &[rig.ended_job("2026-11-25T12:00:00Z")],
            "2026-11-23T00:00:00Z",
        )
        .await;
    let (number, _) = proposed_week(&second);
    assert_ne!(number, proposed_week(&first).0, "a new pull request");
    let pulls = rig.host.pulls(&repo());
    let open = pulls
        .iter()
        .find(|pull| pull.number == number)
        .expect("the new pull request");
    assert!(
        open.body.contains("holds one week:"),
        "the merged week is not counted again"
    );
    assert_eq!(
        pulls
            .iter()
            .filter(|pull| pull.lifecycle == PullRequestLifecycle::Open)
            .count(),
        1
    );

    rig.host.close(&repo(), number);
    assert_eq!(
        rig.propose(
            &[rig.ended_job("2026-11-25T12:00:00Z")],
            "2026-11-23T00:00:00Z"
        )
        .await,
        Measured::Skipped(Skipped::Decided(WeeklyNothingBecause::Declined))
    );
}

#[tokio::test]
async fn nothing_is_proposed_without_a_commit_a_sample_a_knowledge_base_or_an_enabled_repository() {
    let without_commit = Rig::new(None, true);
    let job = without_commit.ended_job("2026-11-18T12:00:00Z");
    assert_eq!(
        without_commit.propose(&[job], "2026-11-16T00:00:00Z").await,
        Measured::Skipped(Skipped::NoBuildCommit)
    );

    let rig = Rig::ready();
    assert_eq!(
        rig.propose(&[], "2026-11-16T00:00:00Z").await,
        Measured::Skipped(Skipped::NoSample)
    );
    // A job that ended the week after has no sample in this week.
    let later = rig.ended_job("2026-11-23T00:00:00Z");
    assert_eq!(
        rig.propose(&[later], "2026-11-16T00:00:00Z").await,
        Measured::Skipped(Skipped::NoSample)
    );

    let without_base = Rig::new(Some(GitSha::parse(&"a".repeat(40)).expect("valid")), false);
    let job = without_base.ended_job("2026-11-18T12:00:00Z");
    assert_eq!(
        without_base.propose(&[job], "2026-11-16T00:00:00Z").await,
        Measured::Skipped(Skipped::NoKnowledgeBase)
    );

    let unknown = rig
        .step
        .propose_for(
            rig.tenant,
            RepositoryId::from_uuid(uid(999)),
            &[rig.ended_job("2026-11-18T12:00:00Z")],
            week("2026-11-16T00:00:00Z"),
        )
        .await;
    assert_eq!(unknown, Measured::Skipped(Skipped::NotEnabled));
    assert!(rig.host.pulls(&repo()).is_empty());
    assert!(rig.audit_actions().await.is_empty());
}

#[tokio::test]
async fn a_pass_runs_at_most_once_an_hour_for_a_tenant() {
    let rig = Rig::ready();
    // No job in the store: the pass looks at nothing, and the next one within the hour is skipped.
    assert!(rig.step.pass(rig.tenant).await.is_empty());
    assert!(rig.step.pass(rig.tenant).await.is_empty());
    let id = EntryId::parse("M-2026-W47").expect("valid");
    assert_eq!(id.as_str(), "M-2026-W47");
}
