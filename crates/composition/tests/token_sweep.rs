//! The installation tokens of a job are revoked when the job is over, and only then.
//!
//! Real: PostgreSQL, the engine (which ends the job), the GitHub App adapter and the step the
//! worker runs before each claim. Fake, and labelled: the GitHub server (FX-GH of the test kit).
#![allow(dead_code)]

mod support;

#[path = "../../github/tests/common/mod.rs"]
mod gh;

use std::sync::Arc;
use std::time::Duration;

use factory_composition::config::FactoryConfig;
use factory_composition::hooks::BeforeClaim as _;
use factory_composition::indexing::ActiveJobs;
use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::load_policy;
use factory_composition::token_sweep::RevokeEndedJobs;
use factory_domain::state::JobStatus;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::githost::{ChangeHost, GitScope};
use factory_ports::paths::RepoRef;
use factory_ports::store::Store;
use factory_workflow::commands::JobCommand;
use gh::harness::{FIXTURE, World};
use gh::keys::{Form, Throwaway};
use std::os::unix::fs::PermissionsExt;
use support::engine::{Eval, PgWorld};

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The adapter of the worker, built from a configuration, for the tenant of the engine's world.
fn adapter_for(
    world: &World,
    tenant: factory_domain::ids::TenantId,
    dir: &std::path::Path,
) -> factory_github::GithubAdapter {
    let key = dir.join("app.pem");
    std::fs::write(&key, Throwaway::new(Form::Pkcs8).private_pem).expect("write");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let text = format!(
        "profile: local\nprotected_checkout: {root}\ndefinitions_root: {root}\n\
         database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
         artifacts: {{ root: {dir} }}\n\
         sandbox: {{ images_catalog: {root}/infra/sandbox-images/images.json, token_root: {dir}/t, workspace_root: {dir}/w }}\n\
         broker: {{ listen: '127.0.0.1:0' }}\n\
         github:\n  app_id: {app}\n  key_file: {key}\n  api_base_url: '{base}'\n  installations:\n    - {{ tenant: {tenant}, repository: {FIXTURE}, installation_id: 1 }}\n",
        root = root().display(),
        dir = dir.display(),
        key = key.display(),
        app = world.fake.app().id,
        base = world.server.base_url(),
        tenant = tenant.as_uuid(),
    );
    let config = FactoryConfig::from_yaml(&text).expect("a configuration");
    let policies = load_policy(&root(), &[]).expect("policies");
    factory_composition::external::github_adapter(
        config.profile,
        config.github.as_ref().expect("github"),
        &policies.security,
        Arc::new(redactor_from_policy(&policies.security).expect("redactor")),
        world.clock.clone(),
    )
    .unwrap_or_else(|(key, reason)| panic!("{key}: {reason}"))
}

fn scope(
    tenant: factory_domain::ids::TenantId,
    job: factory_domain::ids::JobId,
    stage: StageKind,
) -> GitScope {
    GitScope {
        tenant,
        job,
        stage,
        repo: RepoRef::parse(FIXTURE).expect("a repository"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tokens_of_a_job_live_while_it_is_open_and_are_revoked_once_it_is_over() {
    let (_db, engine, tenant) = support::pg_world().await;
    let github = World::new();
    let dir = root()
        .join("target/token-sweep")
        .join(format!("{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let adapter = adapter_for(&github, tenant, &dir);
    let changes = adapter.change_host();
    let store: Arc<dyn Store> = engine.store.clone();
    let jobs = Arc::new(ActiveJobs::new());
    let step = RevokeEndedJobs::new(adapter, store, vec![tenant], Arc::clone(&jobs));

    // A job that is open, with a token the adapter minted for a stage of it.
    let job = engine.admitted_job().await;
    changes
        .fetch_target(&scope(tenant, job, StageKind::RepositoryIntelligence))
        .await
        .expect("a fetch target");
    let live = github.fake.tokens();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].repositories, ["example-org/fixture"]);

    // Before each claim the step looks: the job is open, so nothing is revoked.
    step.before_claim().await;
    assert!(github.fake.tokens().iter().all(|t| t.revoked_at.is_none()));
    assert!(github.fake.revocations().is_empty());

    // A job that this process is working on is open whatever the store says.
    // The requester ends the job.
    engine
        .authority
        .grant(engine.requester, &[HumanRole::Requester]);
    engine
        .engine
        .control(&engine.actor(engine.requester), job, JobCommand::Cancel)
        .await
        .expect("cancels");
    assert_eq!(engine.view(job).await.status, JobStatus::Cancelled);
    // The job is over but this process is still working on it (the loop notes the job while an
    // attempt runs): its tokens stay.
    jobs.enter(job, tenant);
    step.before_claim().await;
    assert!(github.fake.tokens().iter().all(|t| t.revoked_at.is_none()));
    jobs.leave(job);

    // Nothing runs it and the store says it is over: the tokens are revoked on the next claim, and
    // the job can mint no more.
    step.before_claim().await;
    let after = github.fake.tokens();
    assert!(after.iter().all(|t| t.revoked_at.is_some()), "{after:?}");
    assert!(!github.fake.revocations().is_empty());
    let again = adapter_for(&github, tenant, &dir)
        .change_host()
        .fetch_target(&scope(tenant, job, StageKind::RepositoryIntelligence))
        .await;
    // A new adapter does not know the job ended (it is a different process), so it can mint: the
    // end of a job is the adapter's memory, and the store is what the step reads.
    assert!(again.is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_step_the_tokens_of_an_ended_job_stay_live() {
    // Break: the step is not in the loop. This is what the worker did before it was added.
    let (_db, engine, tenant) = support::pg_world().await;
    let github = World::new();
    let dir = root()
        .join("target/token-sweep")
        .join(format!("no-step-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let adapter = adapter_for(&github, tenant, &dir);
    let job = engine.admitted_job().await;
    adapter
        .change_host()
        .fetch_target(&scope(tenant, job, StageKind::RepositoryIntelligence))
        .await
        .expect("a fetch target");
    engine
        .authority
        .grant(engine.requester, &[HumanRole::Requester]);
    engine
        .engine
        .control(&engine.actor(engine.requester), job, JobCommand::Cancel)
        .await
        .expect("cancels");
    assert_eq!(engine.view(job).await.status, JobStatus::Cancelled);
    // Nothing revoked the token of the ended job.
    let tokens = github.fake.tokens();
    assert_eq!(tokens.len(), 1);
    assert!(tokens[0].revoked_at.is_none());
    assert!(github.fake.revocations().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// Runs the next claimed attempt of the world, which is the stage the script is set for.
async fn run_next(world: &PgWorld) {
    let claimed = world.claim_one("worker-sweep").await;
    world
        .engine
        .run_attempt(&claimed)
        .await
        .expect("the attempt runs");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_blocked_for_the_bound_gives_up_its_read_token_and_a_job_waiting_for_a_person_keeps_its()
 {
    // LB-04. Real: PostgreSQL, the engine, the adapter and the step. Fake: the GitHub server.
    let (_db, engine, tenant) = support::pg_world().await;
    let github = World::new();
    let dir = root()
        .join("target/token-sweep")
        .join(format!("blocked-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let adapter = adapter_for(&github, tenant, &dir);
    let changes = adapter.change_host();
    let store: Arc<dyn Store> = engine.store.clone();
    let jobs = Arc::new(ActiveJobs::new());
    // A bound of ten minutes, so that the tokens (which GitHub expires after an hour) are still
    // alive when it runs out.
    let bound = Duration::from_secs(600);
    let step = RevokeEndedJobs::new(adapter, store, vec![tenant], Arc::clone(&jobs))
        .revoking_blocked_after(bound, github.clock.clone());

    // Job A is blocked at intake; job B waits for a person at intake. Each holds a read token.
    let blocked = engine.admitted_job().await;
    engine
        .script(StageKind::Intake)
        .queue_evals([Eval::Blocked]);
    run_next(&engine).await;
    assert_eq!(engine.view(blocked).await.status, JobStatus::Blocked);
    let waiting = engine.admitted_job().await;
    engine
        .script(StageKind::Intake)
        .evals_otherwise(Eval::HumanGate);
    run_next(&engine).await;
    assert_eq!(
        engine.view(waiting).await.status,
        JobStatus::WaitingForHuman
    );
    for job in [blocked, waiting] {
        changes
            .fetch_target(&scope(tenant, job, StageKind::RepositoryIntelligence))
            .await
            .expect("a fetch target");
    }
    assert_eq!(github.fake.tokens().len(), 2);

    // The first pass notes that A is blocked. Less than the bound later, nothing is revoked.
    step.before_claim().await;
    github.clock.advance(bound - Duration::from_secs(60));
    step.before_claim().await;
    assert!(github.fake.tokens().iter().all(|t| t.revoked_at.is_none()));

    // The bound has run: A's token goes, B's stays, however long B waits.
    github.clock.advance(Duration::from_secs(120));
    step.before_claim().await;
    let revoked: Vec<bool> = github
        .fake
        .tokens()
        .iter()
        .map(|t| t.revoked_at.is_some())
        .collect();
    assert_eq!(revoked.iter().filter(|r| **r).count(), 1, "{revoked:?}");
    assert_eq!(github.fake.revocations().len(), 1, "one DELETE, for job A");
    // Many passes later, B is still not touched: only the blocked job is ever revoked.
    github.clock.advance(Duration::from_secs(300));
    step.before_claim().await;
    step.before_claim().await;
    assert_eq!(
        github.fake.revocations().len(),
        1,
        "the job that waits for a person keeps its token"
    );

    // A is not ended: it can still read, with a new token.
    let before = github.fake.mints().len();
    changes
        .fetch_target(&scope(tenant, blocked, StageKind::RepositoryIntelligence))
        .await
        .expect("a blocked job that is unblocked can mint again");
    assert_eq!(github.fake.mints().len(), before + 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_bound_a_blocked_job_keeps_its_token_as_before() {
    // The control: a step built without the bound leaves the token of a blocked job alone.
    let (_db, engine, tenant) = support::pg_world().await;
    let github = World::new();
    let dir = root()
        .join("target/token-sweep")
        .join(format!("unbounded-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let adapter = adapter_for(&github, tenant, &dir);
    let store: Arc<dyn Store> = engine.store.clone();
    let changes = adapter.change_host();
    let step = RevokeEndedJobs::new(adapter, store, vec![tenant], Arc::new(ActiveJobs::new()));
    let blocked = engine.admitted_job().await;
    engine
        .script(StageKind::Intake)
        .queue_evals([Eval::Blocked]);
    run_next(&engine).await;
    changes
        .fetch_target(&scope(tenant, blocked, StageKind::RepositoryIntelligence))
        .await
        .expect("a fetch target");
    step.before_claim().await;
    github.clock.advance(Duration::from_secs(1_200));
    step.before_claim().await;
    assert!(github.fake.tokens().iter().all(|t| t.revoked_at.is_none()));
    assert!(github.fake.revocations().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}
