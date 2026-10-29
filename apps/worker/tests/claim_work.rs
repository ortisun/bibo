//! The worker loop with the step it takes before each claim (`ClaimWork`): a received job is
//! admitted and run, and without the step it is never looked at.
//!
//! The stage handlers are the engine suite's scripted ones; everything else is real: PostgreSQL,
//! the engine, the loop, the hook, the allowlist file and the policy files.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::decisions::{
    AllowlistAuthority, ApprovalSubmitter, AuditMarkers, ClaimWork, ClaimWorkDeps,
};
use factory_composition::delivery::StoreApprovalSources;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, Shutdown, TokioTicker};
use factory_domain::ids::TenantId;
use factory_domain::state::JobStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_worker::run::WorkerLoop;
use factory_workflow::engine::{Engine, JobView};
use factory_workflow::stages::approval::{ApprovalCommand, Outcome, ServiceError};
use support::engine::{Eval, PgWorld};
use support::{seed_tenant, seeded_repository, server, worker_config};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The loop never asks the approval service in these tests: no decision is made.
struct NoDecisions;

#[async_trait(?Send)]
impl ApprovalSubmitter for NoDecisions {
    async fn submit(&self, _: ApprovalCommand) -> Result<Outcome, ServiceError> {
        Err(ServiceError::Unavailable)
    }
}

struct Setup {
    world: PgWorld,
    tenant: TenantId,
    engine: Arc<Engine>,
    hook: Arc<ClaimWork>,
    checkout: PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.checkout);
    }
}

async fn setup(db: &support::TestDb) -> Setup {
    let ids = RandomIds::new().expect("random");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(db, tenant, 0, "org/repo-0").await;
    let store = factory_storage::pg::PgStore::connect(worker_config(db).await)
        .await
        .expect("the store becomes ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    // The approval stage waits for a person, as it does for a real job.
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
    let checkout = repository_root()
        .join("target/claim-work-loop")
        .join(ids.new_uuid().simple().to_string());
    std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
    let allowlist = Arc::new(FileAllowlist::in_checkout(&checkout));
    std::fs::write(
        checkout.join("allowlist/allowlist.yaml"),
        format!(
            "version: 1\nentries:\n  - tenant: {}\n    github_user_id: 1001\n    login: requester-one\n    designations: [requester]\n",
            tenant.as_uuid()
        ),
    )
    .expect("the allowlist file");
    let engine = Arc::new(world.restarted_engine());
    let hook = Arc::new(ClaimWork::new(ClaimWorkDeps {
        engine: Arc::clone(&engine),
        store: world.store.clone(),
        tenants: vec![tenant],
        submitter: Arc::new(NoDecisions),
        approvals: Arc::new(StoreApprovalSources::new(
            world.store.clone(),
            world.deps.artifacts.clone(),
            allowlist.clone(),
        )),
        authority: Arc::new(AllowlistAuthority::new(
            allowlist,
            Arc::clone(&policies.approval),
            world.deps.clock.clone(),
        )),
        markers: Arc::new(AuditMarkers::new(
            world.store.clone(),
            policies.hash.clone(),
        )),
        clock: world.deps.clock.clone(),
        max_age: std::time::Duration::from_secs(72 * 3600),
        per_pass: factory_composition::decisions::DECISIONS_PER_PASS,
    }));
    Setup {
        world,
        tenant,
        engine,
        hook,
        checkout,
    }
}

/// Runs the loop until `done` holds for the job or the time is up. Returns the last view.
async fn drive(
    setup: &Setup,
    job: factory_domain::ids::JobId,
    with_hook: bool,
    seconds: u64,
    done: impl Fn(&JobView) -> bool,
) -> JobView {
    let shutdown = Shutdown::new();
    let mut worker_loop = WorkerLoop::shared(
        Arc::clone(&setup.engine),
        Arc::new(TokioTicker),
        PgWorld::worker("worker-hook"),
        PgWorld::loop_settings(),
        shutdown.clone(),
    );
    if with_hook {
        worker_loop = worker_loop.with_before_claim(setup.hook.clone());
    }
    let watcher = setup.world.restarted_engine();
    let poll = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
        loop {
            let view = watcher.job_view(setup.tenant, job).await.expect("a view");
            if done(&view) || tokio::time::Instant::now() > deadline {
                return view;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let view = tokio::select! {
        view = poll => view,
        summary = worker_loop.run() => panic!("the loop ended on its own: {summary:?}"),
    };
    shutdown.raise();
    view
}

#[tokio::test(flavor = "multi_thread")]
async fn the_loop_admits_a_received_job_and_runs_it_to_the_approval() {
    let db = server().clone_database().await;
    let setup = setup(&db).await;
    let job = setup
        .engine
        .receive_job(setup.tenant, setup.world.requester, setup.world.repository)
        .await
        .expect("received");
    let view = drive(&setup, job, true, 60, |view| {
        view.status == JobStatus::WaitingForHuman
    })
    .await;
    assert_eq!(
        view.status,
        JobStatus::WaitingForHuman,
        "the job was admitted by the loop and ran to the approval: {view:#?}"
    );
}

/// The break. A loop with no such step leaves the job in `RECEIVED` for as long as it runs: this is
/// how the repository was before the step existed, and it is the check above that tells the two
/// apart.
#[tokio::test(flavor = "multi_thread")]
async fn break_a_loop_without_the_step_never_admits_a_received_job() {
    let db = server().clone_database().await;
    let setup = setup(&db).await;
    let job = setup
        .engine
        .receive_job(setup.tenant, setup.world.requester, setup.world.repository)
        .await
        .expect("received");
    let view = drive(&setup, job, false, 4, |view| {
        view.status != JobStatus::Received
    })
    .await;
    assert_eq!(view.status, JobStatus::Received, "{view:#?}");
    assert!(view.stage_runs.is_empty());
}
