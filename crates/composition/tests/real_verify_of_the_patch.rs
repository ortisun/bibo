//! The builder's patch of the playbook, verified in the real pinned `verify` image.
//!
//! The full run (`apps/api/tests/full_run.rs`) uses the testkit's fake sandbox for every command,
//! and says so. This test is the part of that run that a real container can answer: the
//! fixture `word-count` with the playbook's patch on it is mounted read-only in a `verify`
//! sandbox built from the real policy and the pinned image, with no network, and the project's
//! own gate commands run in it (`cargo build --locked`, `cargo test --locked`) and are expected to
//! pass offline. What the container printed is read back by the tenant through the indexing
//! wrapper, and the test names the requirements the passed tests cover.
//!
//! Docker is shared with other stacks. This test labels everything it makes with
//! `factory.test=true` and a label of its own (`factory.test.run=<pid>`), removes only what carries
//! both, and checks that nothing carrying them is left. It never prunes and never restarts the
//! daemon. When Docker or the pinned image is missing the test panics with `BLOCKED:`; that is
//! never a pass.
//!
//! Like `docker_sandbox.rs` it is ignored by default, for the same reason: it needs the daemon and
//! the pinned images, and on Docker Desktop for Mac the daemon once failed to see a directory made
//! a moment before. Run it with `cargo nextest run -p factory-composition --run-ignored only
//! --test real_verify_of_the_patch`.

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

/// Copies a directory tree, files and directories only.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from)
        .expect("a readable directory")
        .flatten()
    {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a file");
        }
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

#[test]
#[ignore = "needs the Docker daemon and the pinned images; see the header of this file"]
fn the_playbook_patch_passes_the_projects_own_gates_in_the_real_verify_image() {
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

    // Everything this test creates lives under the repository's target directory, which the
    // policy allows as a mount source (the system temporary directory is under /var, which it
    // forbids).
    let scratch = root().join("target/composition-docker").join(&run);
    let _cleanup = Scratch(scratch.clone());
    for dir in ["workspace", "out", "tokens", "workspaces"] {
        std::fs::create_dir_all(scratch.join(dir)).expect("a directory");
    }
    // The fixture with the playbook's patch on it. The fixture directory is never edited: this is a
    // copy under the scratch directory.
    let fixture = root().join("fixtures/repos/word-count");
    copy_tree(&fixture, &scratch.join("workspace"));
    let patch = root().join("fixtures/recordings/playbook/word-count/patch");
    for (from, to) in [
        ("src/lib.rs", "src/lib.rs"),
        ("src/main.rs", "src/main.rs"),
        ("tests/json_output.rs", "tests/json_output.rs"),
    ] {
        std::fs::copy(patch.join(from), scratch.join("workspace").join(to)).expect("a patch file");
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

    let mut report = String::new();
    for words in [
        vec!["cargo", "--version"],
        vec!["cargo", "build", "--locked", "--offline"],
        vec!["cargo", "test", "--locked", "--offline"],
    ] {
        let argv = ExecArgv::new(words.iter().map(|w| (*w).to_owned()).collect()).expect("an argv");
        let result = session
            .exec(
                ExecRequest {
                    argv,
                    cwd: None,
                    stdin: None,
                    timeout: Duration::from_secs(600),
                    max_output_bytes: 1 << 20,
                },
                &cancel,
            )
            .await
            .expect("the command runs in the container");
        let read = |reference| {
            let artifacts = world.deps.artifacts.clone();
            async move {
                String::from_utf8_lossy(
                    &artifacts
                        .get(&TenantScope::new(tenant), &reference)
                        .await
                        .expect("the tenant reads what the command printed"),
                )
                .into_owned()
            }
        };
        let out = read(result.stdout.clone()).await;
        let err = read(result.stderr.clone()).await;
        report.push_str(&format!(
            "{words:?} -> {:?}\nSTDOUT\n{out}\nSTDERR\n{err}\n",
            result.exit_code
        ));
        assert_eq!(
            result.exit_code,
            Some(0),
            "{words:?} did not pass in the real verify image:\n{out}\n{err}"
        );
        if words[1] == "test" {
            for requirement in ["fr_001", "fr_002", "fr_003", "fr_004"] {
                assert!(
                    out.lines().any(|line| line.starts_with("test ")
                        && line.contains(requirement)
                        && line.ends_with("ok")),
                    "no passed test names {requirement}:\n{out}"
                );
            }
        }
    }
    println!("REAL-VERIFY {report}");
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
