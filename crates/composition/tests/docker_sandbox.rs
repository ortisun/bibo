//! The Docker sandbox provider that `providers::assemble` builds, against the real Docker daemon:
//! a `verify` sandbox (no network, so no address block and no lock on the shared pool) is made from
//! the real policy and the pinned image, a command runs in it, its output is readable by the
//! tenant that owns the job because the indexing wrapper indexed it, and the container is gone
//! afterwards.
//!
//! Docker is shared with other stacks. This test labels everything it makes with
//! `factory.test=true` and a label of its own (`factory.test.run=<pid>`), removes only what carries
//! both, and checks that nothing carrying them is left. It never prunes and never restarts the
//! daemon. When Docker or the pinned image is missing the test panics with `BLOCKED:`; that is
//! never a pass.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use factory_composition::config::FactoryConfig;
use factory_composition::indexing::ActiveJobs;
use factory_composition::providers::{ProviderInputs, assemble, system_runner};
use factory_composition::redaction::redactor_from_policy;
use factory_composition::sandbox_specs::PolicySpecs;
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, Shutdown, SystemClock};
use factory_domain::ids::AttemptId;
use factory_domain::scope::TenantScope;
use factory_ports::clock::IdGenerator;
use factory_ports::sandbox::{ExecArgv, ExecRequest, TeardownReason};
use factory_ports::workspace::WorkspaceMounts;
use factory_workflow::stages::repo_intel::seams::VerifySandboxSpecs;
use support::pg_world;

/// Prints the command line and the end of the standard error of a `docker` command that failed, so
/// that `ProvisionFailed(Create)` has a reason in the log of the test. The arguments are the
/// factory's own flags and paths; no secret is among them (the verify profile has no token).
struct Printing(Arc<dyn factory_ports::process::ProcessRunner>);

#[async_trait::async_trait]
impl factory_ports::process::ProcessRunner for Printing {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        self.0.fidelity()
    }

    async fn run(
        &self,
        req: factory_ports::process::SpawnRequest,
        cancel: &dyn factory_ports::clock::CancelSignal,
    ) -> Result<factory_ports::process::SpawnOutput, factory_ports::process::SpawnError> {
        let args = req.args.join(" ");
        let out = self.0.run(req, cancel).await;
        match &out {
            Ok(done) if done.exit_code != Some(0) => println!(
                "DOCKER failed: docker {args}\n  exit {:?}: {}",
                done.exit_code,
                String::from_utf8_lossy(&done.stderr)
            ),
            Err(error) => println!("DOCKER error: docker {args}: {error:?}"),
            _ => {}
        }
        out
    }
}

/// Removes the scratch directory on every way out of the test, a panic included.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The ids of the containers that carry this run's labels.
fn mine(run: &str) -> Vec<String> {
    let out = std::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "-q",
            "--filter",
            "label=factory.test=true",
            "--filter",
            &format!("label=factory.test.run={run}"),
        ])
        .output()
        .expect("docker runs");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Runs the body with the telemetry pipeline as the subscriber, so that a failure of a `docker`
/// command (a short, redacted piece of its standard error) shows in the log of the test.
///
/// **Ignored, and why.** The test needs the Docker daemon and the pinned images, and a machine
/// without them gets a `BLOCKED:` panic, so it is not part of the default suite. It is not ignored
/// for being flaky any more, as far as this checkout can show: on 2026-10-28 it passed seven runs
/// out of seven in a worktree under `/Users/.../target`, with the one retry of a failed creation
/// below never taken (a failed `docker` command would have been printed as `DOCKER failed:`, and
/// none was), and no container with the test labels was left (`docker ps -a --filter
/// label=factory.test=true` listed none). Before that, on a different checkout, the first run
/// passed and the next four had `docker create` answer "bind source path does not exist" for a
/// directory the test had just made, five seconds running, while a plain `docker run` over a
/// directory of the same tree worked. That could **not be reproduced**, so the cause is not known:
/// it is consistent with Docker Desktop for Mac sharing host directories with its VM through a
/// cache that lags behind a directory created a moment ago, which is not something the harness
/// can fix, but nothing here proves it. Whether to move the test into the default suite for a
/// machine that has Docker is a decision for the lead. Run it with `cargo nextest run -p
/// factory-composition --run-ignored only --test docker_sandbox`.
#[test]
#[ignore = "needs the Docker daemon and the pinned images; passed 7 of 7 runs on 2026-10-28, an earlier failure could not be reproduced and its cause is not known; see the doc comment"]
fn the_assembled_docker_provider_runs_a_command_and_the_tenant_reads_its_output() {
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("a redactor"));
    let telemetry = factory_composition::telemetry::config_for(
        "factory-composition-test",
        "0.0.0",
        factory_composition::profile::Profile::Test,
        &factory_composition::config::TelemetryConfig {
            otlp_endpoint: None,
            log_filter: Some("warn,factory_sandbox=debug".to_owned()),
        },
        &redactor,
    )
    .expect("a telemetry configuration");
    let pipeline = factory_observability::telemetry::build_pipeline(&telemetry, std::io::stderr)
        .expect("a pipeline");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    pipeline.in_scope(|| runtime.block_on(body()));
}

async fn body() {
    let docker = std::process::Command::new("docker").arg("info").output();
    assert!(
        docker.is_ok_and(|out| out.status.success()),
        "BLOCKED: the Docker daemon is not reachable, so no container was made"
    );
    let run = format!("composition-{}", std::process::id());
    let (_db, world, tenant) = pg_world().await;
    let job = world.admitted_job().await;

    // Everything this test creates lives in a folder the policy allows as a mount source on this
    // host (`mountable_scratch`: the system temporary directory is under /var on macOS and the
    // repository under /home on most Linux hosts, both forbidden).
    let scratch = factory_testkit::fx::scratch::mountable_scratch("composition-docker").join(&run);
    let _cleanup = Scratch(scratch.clone());
    for dir in ["workspace", "out", "tokens", "workspaces"] {
        std::fs::create_dir_all(scratch.join(dir)).expect("a directory");
    }
    // The checkout has a `.git` entry that `/dev/null` is bound over (`git_masked`); the mount
    // point has to exist in a read-only workspace.
    std::fs::write(scratch.join("workspace/.git"), b"").expect("the placeholder");
    use std::os::unix::fs::PermissionsExt;
    for dir in ["workspace", "out"] {
        std::fs::set_permissions(scratch.join(dir), std::fs::Permissions::from_mode(0o777))
            .expect("open to the sandbox user");
    }

    let text = format!(
        "profile: test\n\
         protected_checkout: {root}\n\
         definitions_root: {root}\n\
         database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
         artifacts: {{ root: {scratch}/artifacts }}\n\
         sandbox:\n  images_catalog: {root}/infra/sandbox-images/images.json\n  token_root: {scratch}/tokens\n  workspace_root: {scratch}/workspaces\n  platform: linux/arm64\n  owner: factory-test\n  labels: {{ factory.test: 'true', factory.test.run: '{run}' }}\n\
         broker:\n  listen: '127.0.0.1:0'\n",
        root = root().display(),
        scratch = scratch.display(),
    );
    let config = FactoryConfig::from_yaml(&text).expect("the configuration parses");
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("a redactor"));
    let jobs = Arc::new(ActiveJobs::new());
    let providers = assemble(ProviderInputs {
        config: &config,
        policies: &policies,
        redactor: Arc::clone(&redactor),
        artifacts: world.deps.artifacts.clone(),
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("the random source opens")),
        store: world.store.clone(),
        jobs: Arc::clone(&jobs),
        runner: Arc::new(Printing(system_runner())),
    })
    .expect("the providers assemble");

    // The spec is built from the real policy and the real catalog.
    let catalog_json =
        std::fs::read_to_string(root().join("infra/sandbox-images/images.json")).expect("catalog");
    let catalog =
        factory_sandbox::container::images::ImageCatalog::from_json(&catalog_json, "linux/arm64")
            .expect("a catalog");
    let specs = PolicySpecs::new(
        Arc::clone(&policies.security),
        catalog,
        Arc::new(factory_composition::redaction::RegisteringBroker::new(
            world.deps.broker.clone(),
            Arc::clone(&redactor),
        )),
        scratch.join("scratch"),
    );
    let attempt = AttemptId::from_uuid(RandomIds::new().expect("random").new_uuid());
    let spec = specs
        .verify_spec(
            job,
            attempt,
            WorkspaceMounts {
                workspace: scratch.join("workspace"),
                workspace_read_only: true,
                out: scratch.join("out"),
                protected_overlays: Vec::new(),
                git_masked: true,
            },
        )
        .expect("a verify spec");

    // The loop notes the tenant of the job it works on; the wrapper reads it.
    jobs.enter(job, tenant);
    let cancel = Shutdown::new();
    // Docker Desktop for Mac shares host directories with its VM through a cache, and a directory
    // made a moment ago may not be visible there yet: `docker create` then answers "bind source
    // path does not exist" for a path that exists. The only failure retried is a failed creation,
    // a few times, one second apart; a failure of any other step is final.
    let mut tries = 0;
    let mut session = loop {
        match providers
            .sandbox
            .create_verified(spec.clone(), &cancel)
            .await
        {
            Ok(session) => break session,
            Err(factory_ports::sandbox::SandboxError::ProvisionFailed(stage))
                if tries < 5 && format!("{stage:?}") == "Create" =>
            {
                tries += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => panic!(
                "BLOCKED: the sandbox could not be made on this host ({error:?}); containers left: {:?}",
                mine(&run)
            ),
        }
    };
    assert_eq!(
        mine(&run).len(),
        1,
        "one container carries this run's labels"
    );

    let argv = ExecArgv::new(vec!["cargo".to_owned(), "--version".to_owned()]).expect("an argv");
    let result = session
        .exec(
            ExecRequest {
                argv,
                cwd: None,
                stdin: None,
                timeout: Duration::from_secs(60),
                max_output_bytes: 4096,
            },
            &cancel,
        )
        .await
        .expect("the command runs in the container");
    assert_eq!(result.exit_code, Some(0), "{result:?}");
    // The tenant that owns the job reads what the command printed, because the wrapper indexed it.
    let printed = world
        .deps
        .artifacts
        .get(&TenantScope::new(tenant), &result.stdout)
        .await
        .expect("the tenant reads the standard output");
    assert!(
        String::from_utf8_lossy(&printed).starts_with("cargo 1.98"),
        "{}",
        String::from_utf8_lossy(&printed)
    );

    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("the container is removed");
    assert!(
        mine(&run).is_empty(),
        "nothing carrying this run's labels is left: {:?}",
        mine(&run)
    );
}
