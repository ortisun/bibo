//! Deliberate breaks: each test builds the wrong thing on purpose and shows that it is caught.
//!
//! The breaks that concern the production profile and the redactor are in `profiles.rs` and
//! `telemetry.rs` (the registry refuses every fake; a configuration without the real scrubber
//! leaks a registered value). The two role-readiness breaks (a superuser login, swapped logins)
//! are in `database.rs`. This file holds the others:
//!
//! * a sandbox output that is not indexed cannot be read, and the wrapper makes it readable;
//! * the system pool cannot write a row, so work found there cannot be applied there;
//! * a loop that is told to stop does stop, drains a running attempt, and says so when the drain
//!   budget ends before the attempt does;
//! * SIGTERM sent to the process raises the shutdown signal.

mod support;

use std::sync::Arc;
use std::time::Duration;

use factory_composition::indexing::{ActiveJobs, IndexingSandbox};
use factory_composition::system::{RandomIds, Shutdown, TokioTicker, raise_on_termination};
use factory_domain::ids::TenantId;
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::artifact::ArtifactError;
use factory_ports::clock::IdGenerator;
use factory_ports::sandbox::{ExecArgv, ExecRequest, SandboxProvider};
use factory_storage::pg::PgStore;
use factory_testkit::clock::{FakeCancel, FakeClock};
use factory_testkit::fixtures::{Ids, sandbox_policy, sandbox_spec};
use factory_testkit::sandbox::{FakeSandbox, ProgramOutput};
use factory_worker::run::{WorkerLoop, exit_code};
use support::engine::{PgWorld, Step};
use support::{seed_tenant, seeded_repository, server, worker_config};

async fn world() -> (support::TestDb, PgWorld, TenantId) {
    let db = server().clone_database().await;
    let ids = RandomIds::new().expect("random");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = PgStore::connect(worker_config(&db).await)
        .await
        .expect("ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    (db, world, tenant)
}

/// Runs `echo` in a fake sandbox and returns what it printed as the artifact the adapter wrote.
async fn print_one_line(provider: &dyn SandboxProvider) -> factory_ports::sandbox::ExecResult {
    let ids = Ids::new();
    let spec = sandbox_spec(&ids, factory_ports::sandbox::SandboxProfile::Verify);
    let cancel = FakeCancel::new();
    let mut session = provider
        .create_verified(spec, &cancel)
        .await
        .expect("a session");
    session
        .exec(
            ExecRequest {
                argv: ExecArgv::new(vec!["echo".to_owned(), "hello".to_owned()]).expect("argv"),
                cwd: None,
                stdin: None,
                timeout: Duration::from_secs(5),
                max_output_bytes: 4096,
            },
            &cancel,
        )
        .await
        .expect("the command runs")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_output_that_is_not_indexed_cannot_be_read_and_the_wrapper_indexes_it() {
    let (_db, world, tenant) = world().await;
    let fake_clock = Arc::new(FakeClock::new());
    let artifacts = world.deps.artifacts.clone();
    let program = |_: &[String], _: &[u8]| ProgramOutput {
        exit_code: Some(0),
        stdout: b"hello from the sandbox\n".to_vec(),
        stderr: Vec::new(),
    };
    let fake = Arc::new(
        FakeSandbox::new(fake_clock, artifacts.clone(), sandbox_policy())
            .with_program("echo", program),
    );

    // The break: the sandbox is used as it is. The blob exists, but it is not indexed for the
    // tenant, so the tenant cannot read what its own command printed.
    let result = print_one_line(fake.as_ref()).await;
    let scope = TenantScope::new(tenant);
    let refused = artifacts.get(&scope, &result.stdout).await;
    assert_eq!(refused, Err(ArtifactError::NotFound));

    // The fix: the wrapper indexes stdout and stderr when the command ends.
    let jobs = Arc::new(ActiveJobs::new());
    let indexing = IndexingSandbox::new(fake, world.store.clone(), jobs.clone());
    let ids = Ids::new();
    // The spec's job is the key: the loop would have entered it when it claimed the attempt.
    let spec = sandbox_spec(&ids, factory_ports::sandbox::SandboxProfile::Verify);
    jobs.enter(spec.job, tenant);
    let cancel = FakeCancel::new();
    let mut session = indexing
        .create_verified(spec, &cancel)
        .await
        .expect("a session");
    let result = session
        .exec(
            ExecRequest {
                argv: ExecArgv::new(vec!["echo".to_owned(), "hello".to_owned()]).expect("argv"),
                cwd: None,
                stdin: None,
                timeout: Duration::from_secs(5),
                max_output_bytes: 4096,
            },
            &cancel,
        )
        .await
        .expect("the command runs");
    let bytes = artifacts
        .get(&scope, &result.stdout)
        .await
        .expect("the indexed output can be read");
    assert_eq!(bytes, b"hello from the sandbox\n");
    assert!(
        artifacts
            .exists(&scope, &result.stderr)
            .await
            .expect("exists")
    );

    // Another tenant still cannot read it: the index is per tenant.
    let other = TenantScope::new(TenantId::from_uuid(RandomIds::new().expect("r").new_uuid()));
    assert_eq!(
        artifacts.get(&other, &result.stdout).await,
        Err(ArtifactError::NotFound)
    );

    // A job the loop never entered has no tenant, and the wrapper fails closed instead of
    // guessing one.
    let mut stranger = sandbox_spec(&Ids::new(), factory_ports::sandbox::SandboxProfile::Verify);
    stranger.job = factory_domain::ids::JobId::from_uuid(RandomIds::new().expect("r").new_uuid());
    let mut orphan = indexing
        .create_verified(stranger, &cancel)
        .await
        .expect("a session");
    let failure = orphan
        .exec(
            ExecRequest {
                argv: ExecArgv::new(vec!["echo".to_owned()]).expect("argv"),
                cwd: None,
                stdin: None,
                timeout: Duration::from_secs(5),
                max_output_bytes: 4096,
            },
            &cancel,
        )
        .await;
    assert!(failure.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_system_pool_cannot_write_a_row() {
    // The engine login is the system pool's. A tenant transaction on it would be refused by the
    // database even if the code asked: the login has no INSERT on any table.
    let db = server().clone_database().await;
    let logins = db.server.logins().await;
    let mut connection = db.connect_as(&logins.engine).await;
    use diesel_async::SimpleAsyncConnection;
    let attempt = connection
        .batch_execute(
            "INSERT INTO tenants (id, slug, display_name) VALUES (gen_random_uuid(), 'x', 'X')",
        )
        .await;
    assert!(attempt.is_err(), "the system login wrote a row");
    let message = attempt.unwrap_err().to_string();
    assert!(message.contains("permission denied"), "{message}");
}

fn quick_loop_settings(drain_s: u64) -> factory_composition::config::LoopConfig {
    factory_composition::config::LoopConfig {
        poll_interval_ms: 50,
        sweep_interval_s: 1,
        drain_s,
        ..factory_composition::config::LoopConfig::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_stop_request_ends_an_idle_loop_at_once() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world().await;
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-idle"),
                quick_loop_settings(5),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });
            tokio::time::sleep(Duration::from_millis(300)).await;
            shutdown.raise();
            let summary = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("the loop stops within five seconds")
                .expect("joins");
            assert!(summary.stopped_cleanly, "{summary:?}");
            assert_eq!(exit_code(&summary), 0);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stop_request_lets_a_running_attempt_finish_within_the_drain_budget() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world().await;
            let release = Arc::new(tokio::sync::Notify::new());
            world
                .script(StageKind::Intake)
                .queue([Step::Hang(release.clone())]);
            let job = world.admitted_job().await;
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-drain"),
                quick_loop_settings(10),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });
            while world.script(StageKind::Intake).executed().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // SIGTERM arrives while the attempt runs; the attempt then finishes inside the budget.
            shutdown.raise();
            tokio::time::sleep(Duration::from_millis(200)).await;
            release.notify_one();
            let summary = tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("the loop stops")
                .expect("joins");
            assert_eq!(summary.attempts_run, 1, "{summary:?}");
            assert!(summary.abandoned.is_empty(), "{summary:?}");
            assert_eq!(exit_code(&summary), 0);
            let view = world.view(job).await;
            let intake = view.newest(StageKind::Intake).expect("a run");
            assert_eq!(intake.status, StageRunStatus::Passed);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stop_request_that_outlasts_the_drain_budget_is_reported_and_not_silent() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world().await;
            let never = Arc::new(tokio::sync::Notify::new());
            world.script(StageKind::Intake).queue([Step::Hang(never)]);
            world.admitted_job().await;
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-abandon"),
                quick_loop_settings(1),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });
            while world.script(StageKind::Intake).executed().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            shutdown.raise();
            let summary = tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("the loop stops after the drain budget")
                .expect("joins");
            assert_eq!(summary.abandoned.len(), 1, "{summary:?}");
            assert!(!summary.stopped_cleanly);
            assert_eq!(exit_code(&summary), 4);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn sigterm_sent_to_the_process_raises_the_shutdown_signal() {
    let shutdown = Shutdown::new();
    let watcher = tokio::spawn(raise_on_termination(shutdown.clone()));
    // The handlers are installed before the first poll returns; the pause is for the spawn.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!shutdown.is_raised());
    // nextest runs each test in a process of its own, so the signal stops nothing else.
    let status = std::process::Command::new("kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success());
    tokio::time::timeout(Duration::from_secs(5), shutdown.raised())
        .await
        .expect("SIGTERM raised the shutdown signal");
    watcher.await.expect("the signal task ends");
}
