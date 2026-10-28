//! The telemetry set-up gets the real redactor, and the worker runs each stretch of work on a job
//! inside a `factory.job` span, with the correlation id on every line.

mod support;

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use factory_domain::ids::TenantId;
use factory_domain::redaction::Redactor;
use factory_observability::telemetry::{TelemetryConfig, build_pipeline};
use factory_ports::clock::IdGenerator;
use factory_ports::store::Store;
use factory_worker::config::TelemetryConfig as TelemetrySettings;
use factory_worker::profile::Profile;
use factory_worker::redaction::{FactorySecrets, SecretKind, redactor_from_policy};
use factory_worker::run::{Flow, Observer, WorkerLoop};
use factory_worker::startup::load_policy;
use factory_worker::system::{RandomIds, Shutdown, TokioTicker};
use factory_worker::telemetry::config_for;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::scheduler::ClaimedAttempt;
use support::engine::PgWorld;
use support::{seed_tenant, seeded_repository, server, worker_config};

/// A log sink the tests can read.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn policy_redactor() -> (Arc<Redactor>, FactorySecrets) {
    let policies = load_policy(&repository_root(), &[]).expect("the policy loads");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("builds"));
    let secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    (redactor, secrets)
}

#[test]
fn telemetry_gets_the_real_redactor() {
    let (redactor, mut secrets) = policy_redactor();
    // A value the factory holds and no pattern would find: only the registry knows it.
    let held = "factory-held-value-9f8e7d6c5b4a";
    secrets
        .register(SecretKind::BrokerKeys, held)
        .expect("registers");

    let log_line = |config: &TelemetryConfig| {
        let capture = Capture::default();
        let sink = capture.clone();
        let pipeline = build_pipeline(config, move || sink.clone()).expect("pipeline");
        pipeline.in_scope(|| tracing::info!("a provider call failed for {held}"));
        capture.text()
    };

    let with_real = config_for(
        "factory-worker-test",
        "0.0.0",
        Profile::Test,
        &TelemetrySettings::default(),
        &redactor,
    )
    .expect("config");
    let cleaned = log_line(&with_real);
    assert!(cleaned.contains("a provider call failed"), "{cleaned}");
    assert!(
        !cleaned.contains(held),
        "the registered value reached the log: {cleaned}"
    );
    assert!(cleaned.contains("[REDACTED:broker_keys]"), "{cleaned}");

    // The deliberate break: a binary that forgets the scrubber starts with the stopgap one, which
    // knows the patterns and none of the held values. The line leaks, and the test above would
    // have failed had `config_for` not passed the real one.
    let without = TelemetryConfig::new("factory-worker-test", "0.0.0");
    let leaked = log_line(&without);
    assert!(
        leaked.contains(held),
        "the stopgap scrubber was expected to miss it: {leaked}"
    );
}

struct StopAfterFirst;

impl Observer for StopAfterFirst {
    fn after_attempt(&self, _: &ClaimedAttempt, _: &AttemptOutcome) -> Flow {
        Flow::Stop
    }
}

#[test]
fn job_work_runs_in_a_job_span() {
    let (redactor, _secrets) = policy_redactor();
    let config = config_for(
        "factory-worker-test",
        "0.0.0",
        Profile::Test,
        &TelemetrySettings::default(),
        &redactor,
    )
    .expect("config");
    let capture = Capture::default();
    let sink = capture.clone();
    let pipeline = build_pipeline(&config, move || sink.clone()).expect("pipeline");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (job, correlation) = pipeline.in_scope(|| {
        runtime.block_on(async {
            let db = server().clone_database().await;
            let ids = RandomIds::new().expect("random");
            let tenant = TenantId::from_uuid(ids.new_uuid());
            seed_tenant(&db, tenant, 0, "org/repo-0").await;
            let store = factory_storage::pg::PgStore::connect(worker_config(&db).await)
                .await
                .expect("ready");
            let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
            let job = world.admitted_job().await;
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-1"),
                PgWorld::loop_settings(),
                Shutdown::new(),
            )
            .with_observer(Arc::new(StopAfterFirst));
            let summary = worker_loop.run().await;
            assert_eq!(summary.attempts_run, 1, "{summary:?}");
            let mut tx = world
                .store
                .begin(factory_domain::scope::TenantScope::new(tenant))
                .await
                .expect("a tx");
            let correlation = tx
                .get_job(job)
                .await
                .expect("the job")
                .value
                .correlation_id
                .to_string();
            let _ = tx.rollback().await;
            (job.to_string(), correlation)
        })
    });
    let text = capture.text();
    let line = text
        .lines()
        .find(|line| line.contains("attempt finished"))
        .unwrap_or_else(|| panic!("no 'attempt finished' line in:\n{text}"));
    // The line is written by the loop, outside `Engine::run_attempt` and so outside the engine's
    // own attempt span. The logging layer takes `correlation_id` from the enclosing span, so the
    // id on this line proves the `factory.job` span of the loop is there, with the job's id.
    assert!(
        line.contains(&format!("\"correlation_id\":\"{correlation}\"")),
        "the job's correlation id is not on the line: {line}"
    );
    assert!(!job.is_empty());
}
