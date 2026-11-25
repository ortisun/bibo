//! The loop stays alive for everyone: it sweeps while it is busy, one bad job does not stop the
//! others, and a cancel reaches an attempt that is running.
//!
//! Real: PostgreSQL, the engine, the loop, the ticker, and for the cancel the hook that applies
//! decisions with the allowlist file and the policy files. Scripted: the stage handlers (the
//! engine suite's), as in the other loop tests.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::decision_signing::{DecisionKeys, Signing};
use factory_composition::decisions::{
    AllowlistAuthority, ApprovalSubmitter, AuditMarkers, ClaimWork, ClaimWorkDeps, DecisionFields,
    REQUESTED,
};
use factory_composition::delivery::StoreApprovalSources;
use factory_composition::hooks::WhileRunning;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, Shutdown, TokioTicker};
use factory_domain::contracts::StageContract;
use factory_domain::ids::{AuditEventId, JobId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{AttemptStatus, JobStatus, StageRunStatus};
use factory_domain::vocabulary::{Fidelity, HumanRole, StageKind};
use factory_ports::agent::RoutingNeed;
use factory_ports::clock::IdGenerator;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, NewAuditEvent, Store,
};
use factory_storage::pg::PgStore;
use factory_worker::run::{Flow, LoopSummary, Observer, WorkerLoop};
use factory_workflow::engine::{AttemptOutcome, Engine, EngineConfig, JobView};
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::handlers::{
    Applicability, ContractContext, GateContext, HandlerRegistry, StageContext, StageError,
    StageHandler, StageOutput,
};
use factory_workflow::scheduler::ClaimedAttempt;
use factory_workflow::stages::approval::{ApprovalCommand, Outcome, ServiceError, Verb};
use support::engine::{PgWorld, ScriptedHandler, Step};
use support::{seed_tenant, seeded_repository, server, worker_config};

async fn world(tune: impl FnOnce(&mut EngineConfig)) -> (support::TestDb, PgWorld, TenantId) {
    let db = server().clone_database().await;
    let ids = RandomIds::new().expect("random");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = PgStore::connect(worker_config(&db).await)
        .await
        .expect("ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), tune).await;
    (db, world, tenant)
}

/// Passes the loop's cancel watch through to the decision hook, and notes when each call to
/// `apply_cancels` started and how long it took. When a cancel never arrives, these notes tell
/// apart a watch that never ran from a hook that ran and did not apply the request.
struct WatchedCancels {
    hook: Arc<ClaimWork>,
    started: tokio::time::Instant,
    calls: std::sync::Mutex<Vec<(Duration, Duration)>>,
}

#[async_trait(?Send)]
impl WhileRunning for WatchedCancels {
    async fn apply_cancels(&self, tenant: TenantId, job: JobId) {
        let at = self.started.elapsed();
        self.hook.apply_cancels(tenant, job).await;
        let took = self.started.elapsed().saturating_sub(at);
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((at, took));
    }
}

impl WatchedCancels {
    /// How many times the watch called the hook, when it first and last did, and the longest call.
    fn summary(&self) -> String {
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let longest = calls.iter().map(|(_, took)| *took).max();
        format!(
            "the cancel watch called the hook {} times; first at {:?}, last at {:?}, longest call {:?}",
            calls.len(),
            calls.first().map(|(at, _)| *at),
            calls.last().map(|(at, _)| *at),
            longest,
        )
    }
}

/// The decision records of the tenant's audit log, one line each: the request, and the marker the
/// worker writes when it applies or rejects it, with its reason.
async fn decision_trail(world: &PgWorld, tenant: TenantId) -> String {
    let mut tx = world
        .store
        .begin(TenantScope::new(tenant))
        .await
        .expect("a tx");
    let records = tx
        .read_audit(AuditFilter::Tenant, 0, 1000)
        .await
        .expect("the audit log");
    let _ = tx.rollback().await;
    let lines: Vec<String> = records
        .iter()
        .filter(|record| record.event.action.as_str().starts_with("decision."))
        .map(|record| {
            format!(
                "#{} {} {:?} {:?} at {:?}",
                record.sequence,
                record.event.action.as_str(),
                record.event.decision,
                record.event.reason,
                record.created_at,
            )
        })
        .collect();
    if lines.is_empty() {
        "no decision record in the audit log".to_owned()
    } else {
        lines.join("\n")
    }
}

/// Waits until `done` holds for the job, for at most `seconds`. Returns the last view.
async fn until(
    world: &PgWorld,
    job: JobId,
    seconds: u64,
    done: impl Fn(&JobView) -> bool,
) -> JobView {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let view = world.view(job).await;
        if done(&view) || tokio::time::Instant::now() > deadline {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stopped(shutdown: &Shutdown, task: tokio::task::JoinHandle<LoopSummary>) -> LoopSummary {
    shutdown.raise();
    tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("the loop stops")
        .expect("joins")
}

// ------------------------------------------------------------------------------------------------
// The sweep runs while the queue is busy
// ------------------------------------------------------------------------------------------------

/// Stops the loop after a number of attempts, so the test ends while work is still waiting.
struct StopAfter {
    seen: AtomicU32,
    limit: u32,
}

impl Observer for StopAfter {
    fn after_attempt(&self, _: &ClaimedAttempt, _: &AttemptOutcome) -> Flow {
        if self.seen.fetch_add(1, Ordering::SeqCst) + 1 >= self.limit {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }
}

/// A peer claimed an attempt and died. The loop that is left has work on every pass, so it never
/// waits. The lease of the dead peer is still recovered, because the sweep is due by time and not
/// by idleness.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_lease_is_recovered_while_the_queue_never_empties() {
    const BUSY_ATTEMPTS: u32 = 12;
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world(|config| {
                config.lease_ttl = Duration::from_secs(1);
                config.heartbeat_interval = Duration::from_millis(200);
            })
            .await;
            // Every intake attempt takes about 300 ms, and there are more of them than the loop is
            // allowed to run: the queue is never empty while the loop runs.
            let release = Arc::new(tokio::sync::Notify::new());
            world
                .script(StageKind::Intake)
                .otherwise(Step::Hang(release.clone()));
            let orphan = world.admitted_job().await;
            for _ in 0..(BUSY_ATTEMPTS + 4) {
                world.admitted_job().await;
            }
            let releaser = tokio::task::spawn_local(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    release.notify_one();
                }
            });
            // The peer that dies: it holds the lease of the first job and never runs it.
            let lost = world.claim_one("worker-that-died").await;
            assert_eq!(lost.job, orphan);

            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-busy"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            )
            .with_observer(Arc::new(StopAfter {
                seen: AtomicU32::new(0),
                limit: BUSY_ATTEMPTS,
            }));
            let summary = tokio::time::timeout(Duration::from_secs(60), worker_loop.run())
                .await
                .expect("the loop reaches the attempt count");
            releaser.abort();

            assert!(summary.failure.is_none(), "{summary:?}");
            assert_eq!(summary.attempts_run, BUSY_ATTEMPTS, "{summary:?}");
            let view = world.view(orphan).await;
            let intake = view.newest(StageKind::Intake).expect("a run");
            assert_eq!(
                intake.attempts[0].status,
                AttemptStatus::LeaseLost,
                "the attempt of the dead peer was recovered although the loop never idled: \
                 {summary:?} {intake:#?}"
            );
            assert!(summary.sweeps >= 2, "{summary:?}");
        })
        .await;
}

// ------------------------------------------------------------------------------------------------
// One bad job does not stop the others
// ------------------------------------------------------------------------------------------------

/// A registry with the scripted handler of every stage of the world, except where `replace` gives
/// another one (`Some(None)` leaves the stage without a handler).
fn registry(
    world: &PgWorld,
    replace: impl Fn(StageKind, Arc<dyn StageHandler>) -> Option<Arc<dyn StageHandler>>,
) -> HandlerRegistry {
    let mut handlers = HandlerRegistry::new();
    for kind in &world.config.scope {
        let scripted: Arc<dyn StageHandler> =
            Arc::new(ScriptedHandler::new(*kind, world.script(*kind).clone()));
        if let Some(handler) = replace(*kind, scripted) {
            handlers.register(handler).expect("one handler per stage");
        }
    }
    handlers
}

/// The first candidate of the queue cannot even be claimed: the worker has no handler for its
/// stage, which the claim reports as a hard error. A job behind it still runs.
#[tokio::test(flavor = "current_thread")]
async fn a_candidate_that_cannot_be_claimed_does_not_hold_back_the_job_behind_it() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world(|_| {}).await;
            // The first job passes its intake, so its next stage run is the oldest ready one.
            let first = world.admitted_job().await;
            let intake = world.claim_one("worker-setup").await;
            let outcome = world
                .engine
                .run_attempt(&intake)
                .await
                .expect("intake runs");
            assert_eq!(outcome, AttemptOutcome::Succeeded);
            let view = world.view(first).await;
            let stuck = view
                .stage_runs
                .iter()
                .find(|run| run.status == StageRunStatus::Ready)
                .expect("the stage after intake is ready")
                .clone();
            let second = world.admitted_job().await;

            // The loop's engine has no handler for that stage.
            let handlers = registry(&world, |kind, scripted| {
                (kind != stuck.kind).then_some(scripted)
            });
            let engine = Engine::new(world.deps.clone(), world.config.clone(), handlers)
                .expect("the engine starts");
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                engine,
                Arc::new(TokioTicker),
                PgWorld::worker("worker-partial"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });

            let view = until(&world, second, 20, |view| {
                view.newest(StageKind::Intake)
                    .is_some_and(|run| run.status == StageRunStatus::Passed)
            })
            .await;
            assert!(!task.is_finished(), "the loop ended on its own");
            assert_eq!(
                view.newest(StageKind::Intake).map(|run| run.status),
                Some(StageRunStatus::Passed),
                "the job behind the bad candidate ran: {view:#?}"
            );
            let summary = stopped(&shutdown, task).await;
            assert!(summary.failure.is_none(), "{summary:?}");
            assert!(summary.stopped_cleanly, "{summary:?}");
            assert!(summary.set_aside >= 1, "{summary:?}");
            // Nothing was started on the stage the worker cannot run.
            let view = world.view(first).await;
            let run = view
                .stage_runs
                .iter()
                .find(|run| run.id == stuck.id)
                .expect("the run");
            assert_eq!(run.status, StageRunStatus::Ready, "{run:#?}");
            assert!(run.attempts.is_empty(), "{run:#?}");
        })
        .await;
}

/// The scripted handler of a stage, except that for one job the contract stops resolving after a
/// number of calls. The engine reads that at the start of an attempt as a damaged record
/// (`EngineError::Corrupt`), which is a hard error of `run_attempt`.
struct BreaksForOneJob {
    inner: Arc<dyn StageHandler>,
    job: std::sync::Mutex<Option<JobId>>,
    calls: AtomicU32,
    good_calls: AtomicU32,
}

impl BreaksForOneJob {
    fn new(inner: Arc<dyn StageHandler>) -> Self {
        Self {
            inner,
            job: std::sync::Mutex::new(None),
            calls: AtomicU32::new(0),
            good_calls: AtomicU32::new(u32::MAX),
        }
    }

    /// From now on the contract of `job` resolves `more` more times and then never again.
    fn break_after(&self, job: JobId, more: u32) {
        *self.job.lock().expect("the lock") = Some(job);
        self.calls.store(0, Ordering::SeqCst);
        self.good_calls.store(more, Ordering::SeqCst);
    }
}

#[async_trait]
impl StageHandler for BreaksForOneJob {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    fn kind(&self) -> StageKind {
        self.inner.kind()
    }

    fn applicability(&self, ctx: &ContractContext<'_>) -> Applicability {
        self.inner.applicability(ctx)
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        self.inner.routing_need(ctx)
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        if *self.job.lock().expect("the lock") == Some(ctx.identity.job)
            && self.calls.fetch_add(1, Ordering::SeqCst) >= self.good_calls.load(Ordering::SeqCst)
        {
            return Err(StageError::Tool);
        }
        self.inner.contract(ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        self.inner.execute(ctx).await
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        self.inner.evaluate(ctx).await
    }
}

/// The first job is claimed and its attempt then raises a hard error. The failure is recorded
/// against that attempt, and the job behind it runs.
#[tokio::test(flavor = "current_thread")]
async fn an_attempt_that_raises_a_hard_error_is_failed_and_the_job_behind_it_runs() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world(|_| {}).await;
            let breaking: std::sync::Mutex<Option<Arc<BreaksForOneJob>>> =
                std::sync::Mutex::new(None);
            let handlers = registry(&world, |kind, scripted| {
                if kind == StageKind::Intake {
                    let handler = Arc::new(BreaksForOneJob::new(scripted));
                    *breaking.lock().expect("the lock") = Some(handler.clone());
                    Some(handler)
                } else {
                    Some(scripted)
                }
            });
            let breaking = breaking.lock().expect("the lock").clone().expect("intake");
            let first = world.admitted_job().await;
            // One more good answer, for the claim. The next one, at the start of the attempt, fails.
            breaking.break_after(first, 1);
            let second = world.admitted_job().await;

            let engine = Engine::new(world.deps.clone(), world.config.clone(), handlers)
                .expect("the engine starts");
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                engine,
                Arc::new(TokioTicker),
                PgWorld::worker("worker-hard-error"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });

            let view = until(&world, second, 20, |view| {
                view.newest(StageKind::Intake)
                    .is_some_and(|run| run.status == StageRunStatus::Passed)
            })
            .await;
            assert!(!task.is_finished(), "the loop ended on its own");
            assert_eq!(
                view.newest(StageKind::Intake).map(|run| run.status),
                Some(StageRunStatus::Passed),
                "the job behind the failing one ran: {view:#?}"
            );
            let summary = stopped(&shutdown, task).await;
            assert!(summary.failure.is_none(), "{summary:?}");
            assert_eq!(summary.faulted, 1, "{summary:?}");
            // The failure is in the store, against the attempt that raised it, and it is final:
            // a fault of the factory is never retried.
            let view = world.view(first).await;
            let intake = view.newest(StageKind::Intake).expect("a run");
            assert_eq!(intake.attempts.len(), 1, "{intake:#?}");
            assert_eq!(
                intake.attempts[0].status,
                AttemptStatus::Failed,
                "{intake:#?}"
            );
            assert_eq!(intake.status, StageRunStatus::Failed, "{intake:#?}");
        })
        .await;
}

// ------------------------------------------------------------------------------------------------
// A cancel reaches a running attempt
// ------------------------------------------------------------------------------------------------

/// No approval is asked for in this test.
struct NoDecisions;

#[async_trait(?Send)]
impl ApprovalSubmitter for NoDecisions {
    async fn submit(&self, _: ApprovalCommand) -> Result<Outcome, ServiceError> {
        Err(ServiceError::Unavailable)
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

struct Checkout(PathBuf);

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// With one worker, a cancel that a person records while a stage runs is applied while it runs:
/// the attempt is told to stop and ends as cancelled, long before the stage would have ended.
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_recorded_while_an_attempt_runs_ends_that_attempt_as_cancelled() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, tenant) = world(|_| {}).await;
            let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
            let checkout = Checkout(
                factory_testkit::fx::scratch::mountable_scratch("worker-liveness")
                    .join(world.ids.new_uuid().simple().to_string()),
            );
            std::fs::create_dir_all(checkout.0.join("allowlist")).expect("a directory");
            // The first person `PgWorld::person` makes has the GitHub id 2000.
            let operator = world.person("operator-one", &[HumanRole::Operator]).await;
            std::fs::write(
                checkout.0.join("allowlist/allowlist.yaml"),
                format!(
                    "version: 1\nentries:\n  - tenant: {tenant}\n    github_user_id: 1001\n    login: requester-one\n    designations: [requester]\n  - tenant: {tenant}\n    github_user_id: 2000\n    login: operator-one\n    designations: [operator]\n",
                    tenant = tenant.as_uuid()
                ),
            )
            .expect("the allowlist file");
            let allowlist = Arc::new(FileAllowlist::in_checkout(&checkout.0));
            let engine = Arc::new(world.restarted_engine());
            let keys = Arc::new(DecisionKeys::generated().expect("a signing key"));
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
                    Arc::clone(&keys),
                )),
                clock: world.deps.clock.clone(),
                max_age: Duration::from_secs(72 * 3600),
                per_pass: factory_composition::decisions::DECISIONS_PER_PASS,
                keys: Arc::clone(&keys),
            }));

            // The intake stage of the job never ends by itself.
            let never = Arc::new(tokio::sync::Notify::new());
            world.script(StageKind::Intake).queue([Step::Hang(never)]);
            let job = world.admitted_job().await;
            let watched = Arc::new(WatchedCancels {
                hook: Arc::clone(&hook),
                started: tokio::time::Instant::now(),
                calls: std::sync::Mutex::new(Vec::new()),
            });

            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::shared(
                Arc::clone(&engine),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-alone"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            )
            .with_before_claim(hook.clone())
            .with_cancel_watch(watched.clone());
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });
            while world.script(StageKind::Intake).executed().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            // The record `POST /v1/jobs/{id}/decisions` writes, with the word only the API makes.
            let id = AuditEventId::from_uuid(world.ids.new_uuid());
            let fields = DecisionFields {
                verb: Verb::Cancel,
                job,
                stage_run: None,
                head: None,
                evidence: None,
                target: None,
                answer: None,
                confirm: None,
            };
            let mut tx = world
                .store
                .begin(TenantScope::new(tenant))
                .await
                .expect("a tx");
            let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
            tx.record_audit(NewAuditEvent {
                id,
                actor: AuditActor::Human(operator),
                action: AuditAction::new(REQUESTED).expect("an action"),
                subject: keys.signed_subject(&Signing {
                    tenant,
                    actor: operator,
                    event: id,
                    requested_at: "2026-10-28T12:00:00Z",
                    fields: &fields,
                }),
                decision: AuditDecision::Record,
                reason: "requested: not needed".to_owned(),
                policy_hash: policies.hash.clone(),
                job: Some(job),
                stage_run: None,
                correlation_id: correlation,
            })
            .await
            .expect("the request is recorded");
            tx.commit().await.expect("commit");
            let recorded_at = watched.started.elapsed();

            // The loop polls every 50 ms, the heartbeat that tells the attempt runs every 500 ms.
            let view = until(&world, job, 8, |view| {
                view.newest(StageKind::Intake)
                    .is_some_and(|run| run.attempts[0].status == AttemptStatus::Cancelled)
            })
            .await;
            let intake = view.newest(StageKind::Intake).expect("a run");
            // When the cancel did not arrive, say what the watch did and what the audit log holds,
            // so a failure tells a watch that never ran from a request that was not applied.
            let evidence = if intake.attempts[0].status == AttemptStatus::Cancelled {
                String::new()
            } else {
                format!(
                    "{}; the request was recorded at {:?}\n{}",
                    watched.summary(),
                    recorded_at,
                    decision_trail(&world, tenant).await
                )
            };
            assert_eq!(
                intake.attempts[0].status,
                AttemptStatus::Cancelled,
                "the running attempt was cancelled: {evidence}\n{view:#?}"
            );
            assert!(
                matches!(view.status, JobStatus::Cancelling | JobStatus::Cancelled),
                "{view:#?}"
            );
            assert!(!task.is_finished(), "the loop goes on after a cancel");
            let summary = stopped(&shutdown, task).await;
            assert!(summary.failure.is_none(), "{summary:?}");
            assert!(summary.abandoned.is_empty(), "{summary:?}");
        })
        .await;
}
