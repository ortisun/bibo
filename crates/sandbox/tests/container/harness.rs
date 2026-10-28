//! The real-Docker harness: BLOCKED when there is no daemon or no image, a provider that
//! labels everything for the test run, and a runner that can make the daemon "ignore" a setting.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest};
use factory_ports::sandbox::{
    ExecArgv, ExecRequest, SandboxError, SandboxProfile, SandboxProvider, SandboxSession,
    SandboxSpec,
};
use factory_sandbox::SystemProcessRunner;
use factory_testkit::clock::FakeCancel;
use factory_testkit::contracts::sandbox::DriftPart;
use factory_testkit::fx::docker::{DockerGuard, DockerScope, blocked};

use crate::support::docker_lock::{BACKOFF, DockerLock, is_network_pool_exhausted};
use crate::support::{self, HostWorkspace, Scratch, World};

/// A runner over another one that retries a `docker network create` which finds Docker's address
/// pool full, and nothing else. The pool is small and shared with the user's own stacks, so a
/// create can fail for a moment while another run removes its networks. Every other command, and
/// every other failure of a network create, goes through once and is returned as it is.
pub struct PoolRetryRunner {
    inner: Arc<dyn ProcessRunner>,
    backoff: Vec<Duration>,
}

impl PoolRetryRunner {
    pub fn new(inner: Arc<dyn ProcessRunner>) -> Self {
        Self::with_backoff(inner, BACKOFF.to_vec())
    }

    /// Another series of waits, for a test of the runner itself.
    pub fn with_backoff(inner: Arc<dyn ProcessRunner>, backoff: Vec<Duration>) -> Self {
        Self { inner, backoff }
    }
}

fn creates_a_network(req: &SpawnRequest) -> bool {
    req.program == Program::Docker
        && req.args.first().map(String::as_str) == Some("network")
        && req.args.get(1).map(String::as_str) == Some("create")
}

fn pool_is_full(result: &Result<SpawnOutput, SpawnError>) -> bool {
    matches!(result, Ok(out)
        if out.exit_code != Some(0)
            && is_network_pool_exhausted(&String::from_utf8_lossy(&out.stderr)))
}

#[async_trait]
impl ProcessRunner for PoolRetryRunner {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        if !creates_a_network(&req) {
            return self.inner.run(req, cancel).await;
        }
        for wait in &self.backoff {
            let result = self.inner.run(req.clone(), cancel).await;
            if !pool_is_full(&result) {
                return result;
            }
            tokio::time::sleep(*wait).await;
        }
        self.inner.run(req, cancel).await
    }
}

/// The images this suite runs. A missing one is BLOCKED, never a pass and never a skip.
pub fn require_docker() -> DockerScope {
    let scope = DockerGuard::from_environment().require_or_block();
    let catalog = support::catalog(support::IMAGES_JSON);
    for profile in [SandboxProfile::Agent, SandboxProfile::Verify] {
        let reference = catalog.reference_for(profile).expect("a listed profile");
        let found = scope.cli().run(&[
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            reference.reference(),
        ]);
        if !found.is_ok_and(|out| out.success()) {
            blocked(&format!(
                "the sandbox image {} is not on this host; build it with infra/sandbox-images/build.sh",
                reference.reference()
            ));
        }
    }
    scope
}

/// True when the daemon has no AppArmor, so the posture report says `NotAvailable` by itself.
pub fn daemon_lacks_apparmor(scope: &DockerScope) -> bool {
    scope
        .cli()
        .run(&["info", "--format", "{{.SecurityOptions}}"])
        .map(|out| !out.stdout.contains("apparmor"))
        .unwrap_or(false)
}

/// A runner over the real one that rewrites the next `docker create` of a sandbox container, so
/// that the container really is built differently from its spec.
pub struct DriftRunner {
    inner: SystemProcessRunner,
    pending: Mutex<Option<DriftPart>>,
    other_image: String,
    spare_dir: PathBuf,
}

impl DriftRunner {
    pub fn new(inner: SystemProcessRunner, spare_dir: PathBuf) -> Self {
        let catalog = support::catalog(support::IMAGES_JSON);
        Self {
            inner,
            pending: Mutex::new(None),
            other_image: catalog
                .reference_for(SandboxProfile::Agent)
                .expect("agent")
                .reference()
                .to_owned(),
            spare_dir,
        }
    }

    pub fn arm(&self, part: DriftPart) {
        *self.pending.lock().expect("lock") = Some(part);
    }

    fn rewrite(&self, part: DriftPart, args: &mut Vec<String>) {
        let at = |args: &Vec<String>, flag: &str| args.iter().position(|a| a == flag);
        let image_at = args
            .iter()
            .position(|a| a.contains("@sha256:"))
            .expect("an image");
        match part {
            DriftPart::Hardening => {
                if let Some(i) = at(args, "--cap-drop") {
                    args.drain(i..i + 2);
                }
            }
            DriftPart::Image => {
                let current = args[image_at].clone();
                args[image_at] = if current == self.other_image {
                    support::catalog(support::IMAGES_JSON)
                        .reference_for(SandboxProfile::Verify)
                        .expect("verify")
                        .reference()
                        .to_owned()
                } else {
                    self.other_image.clone()
                };
            }
            DriftPart::Limits => {
                if let Some(i) = at(args, "--pids-limit") {
                    let n: u32 = args[i + 1].parse().expect("a number");
                    args[i + 1] = (n + 1).to_string();
                }
            }
            DriftPart::Network => {
                if let Some(i) = at(args, "--network") {
                    args[i + 1] = "none".to_owned();
                }
            }
            DriftPart::ExtraMount => {
                let mount = format!("type=bind,src={},dst=/host", self.spare_dir.display());
                args.splice(image_at..image_at, ["--mount".to_owned(), mount]);
            }
            DriftPart::WritableMount => {
                if let Some(mount) = args.iter_mut().find(|a| a.ends_with(",readonly")) {
                    *mount = mount.trim_end_matches(",readonly").to_owned();
                }
            }
            DriftPart::Env => {
                args.splice(
                    image_at..image_at,
                    ["--env".to_owned(), "LD_PRELOAD=/evil.so".to_owned()],
                );
            }
            DriftPart::AppArmorNotAvailable => {}
        }
    }
}

#[async_trait]
impl ProcessRunner for DriftRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(
        &self,
        mut req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        let is_main_create = req.args.first().map(String::as_str) == Some("create")
            && !req.args.iter().any(|a| a == "--network-alias");
        if is_main_create {
            let part = self.pending.lock().expect("lock").take();
            if let Some(part) = part {
                self.rewrite(part, &mut req.args);
            }
        }
        self.inner.run(req, cancel).await
    }
}

/// A sandbox provider the tests can swap for one with another policy.
pub struct Switch {
    /// Every provider this switch has had; the last one is current.
    all: Mutex<Vec<Arc<factory_sandbox::DockerSandboxProvider>>>,
}

impl Switch {
    pub fn new(provider: factory_sandbox::DockerSandboxProvider) -> Self {
        Self {
            all: Mutex::new(vec![Arc::new(provider)]),
        }
    }

    pub fn replace(&self, provider: factory_sandbox::DockerSandboxProvider) {
        self.all.lock().expect("lock").push(Arc::new(provider));
    }

    fn get(&self) -> Arc<factory_sandbox::DockerSandboxProvider> {
        Arc::clone(self.all.lock().expect("lock").last().expect("a provider"))
    }

    /// Waits for the background removals of every provider this switch has had.
    pub async fn drain(&self) {
        let all: Vec<_> = self.all.lock().expect("lock").clone();
        for provider in all {
            provider.finish_background_cleanups().await;
        }
    }
}

#[async_trait]
impl SandboxProvider for Switch {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        self.get().create_verified(spec, cancel).await
    }

    async fn sweep_orphans(
        &self,
        live: &[factory_domain::ids::AttemptId],
    ) -> Result<Vec<factory_ports::sandbox::SandboxId>, SandboxError> {
        self.get().sweep_orphans(live).await
    }
}

/// Everything one real-Docker test needs.
pub struct Lab {
    pub scope: DockerScope,
    pub _scratch: Scratch,
    pub token_root: PathBuf,
    pub world: World,
    pub images_json: String,
    pub workspaces: Mutex<Vec<HostWorkspace>>,
    /// Last, so the lock is released after everything above has been cleaned up.
    pub _lock: DockerLock,
}

impl Lab {
    /// A lab whose sidecar is the stand-in (the verify image running `sleep`).
    pub fn new(apparmor_may_be_unavailable: bool) -> Self {
        Self::with_runner(apparmor_may_be_unavailable, None)
    }

    pub fn with_runner(
        apparmor_may_be_unavailable: bool,
        runner: Option<Arc<dyn ProcessRunner>>,
    ) -> Self {
        // One lab at a time on the whole machine: the lock is taken before anything is made and
        // let go after everything is removed. A second lab in the same test would wait for the
        // first and fail with BLOCKED, so a test drops one lab before it makes the next.
        let lock = DockerLock::take();
        let scope = require_docker();
        lock.register_label(scope.label().value());
        let scratch = Scratch::new("lab");
        let token_root = scratch.path().join("tokens");
        let images_json = support::images_json_with_stand_in_sidecar();
        let world = Self::build(
            &scope,
            &images_json,
            &token_root,
            apparmor_may_be_unavailable,
            runner,
            Arc::new(factory_testkit::artifact::InMemoryArtifactStore::new()),
        );
        Self {
            scope,
            _scratch: scratch,
            token_root,
            world,
            images_json,
            workspaces: Mutex::new(Vec::new()),
            _lock: lock,
        }
    }

    pub fn build(
        scope: &DockerScope,
        images_json: &str,
        token_root: &std::path::Path,
        apparmor_may_be_unavailable: bool,
        runner: Option<Arc<dyn ProcessRunner>>,
        artifacts: Arc<factory_testkit::artifact::InMemoryArtifactStore>,
    ) -> World {
        let label = scope.label();
        let mut config = support::config(
            images_json,
            token_root.to_path_buf(),
            vec![(
                factory_testkit::fx::docker::RUN_LABEL_KEY.to_owned(),
                label.value().to_owned(),
            )],
            apparmor_may_be_unavailable,
        );
        // The one named cache the specs of the tests use, next to the token directory.
        let cache = token_root
            .parent()
            .expect("a parent directory")
            .join("caches")
            .join("cargo-registry");
        std::fs::create_dir_all(&cache).expect("a cache directory");
        std::fs::set_permissions(&cache, std::os::unix::fs::PermissionsExt::from_mode(0o777))
            .expect("open the cache directory");
        config.caches = vec![("cargo-registry".to_owned(), cache)];
        let runner = runner.unwrap_or_else(|| Arc::new(SystemProcessRunner::new()));
        // A full address pool is the one transient error of creating a job network.
        let runner = Arc::new(PoolRetryRunner::new(runner));
        support::provider_with(config, runner, artifacts)
    }

    pub fn catalog(&self) -> factory_sandbox::container::images::ImageCatalog {
        support::catalog(&self.images_json)
    }

    /// A workspace that stays until the lab is dropped.
    pub fn workspace(
        &self,
        read_only: bool,
        overlays: &[&str],
    ) -> factory_ports::workspace::WorkspaceMounts {
        let host = support::host_workspace(read_only, overlays);
        let mounts = host.mounts.clone();
        self.workspaces.lock().expect("lock").push(host);
        mounts
    }

    pub fn spec(&self, profile: SandboxProfile, n: u128, wall_clock: Duration) -> SandboxSpec {
        let mounts = self.workspace(profile == SandboxProfile::Verify, &[".github"]);
        support::spec(
            profile,
            &self.catalog(),
            &mounts,
            support::attempt(n),
            wall_clock,
        )
    }

    pub async fn create(&self, spec: SandboxSpec) -> Result<Box<dyn SandboxSession>, SandboxError> {
        self.world
            .provider
            .create_verified(spec, &FakeCancel::new())
            .await
    }

    pub async fn run(
        &self,
        session: &mut dyn SandboxSession,
        words: &[&str],
    ) -> factory_ports::sandbox::ExecResult {
        self.run_with(session, words, Duration::from_secs(30), 1024 * 1024)
            .await
    }

    pub async fn run_with(
        &self,
        session: &mut dyn SandboxSession,
        words: &[&str],
        timeout: Duration,
        cap: u64,
    ) -> factory_ports::sandbox::ExecResult {
        let request = ExecRequest {
            argv: ExecArgv::new(words.iter().map(|w| (*w).to_owned()).collect()).expect("argv"),
            cwd: None,
            stdin: None,
            timeout,
            max_output_bytes: cap,
        };
        session
            .exec(request, &FakeCancel::new())
            .await
            .unwrap_or_else(|error| panic!("{words:?} failed: {error:?}"))
    }

    pub async fn read(&self, reference: &factory_domain::contracts::ArtifactRef) -> Vec<u8> {
        use factory_domain::ids::TenantId;
        use factory_domain::scope::TenantScope;
        use factory_ports::artifact::ArtifactStore;
        let tenant = TenantScope::new(
            TenantId::parse("00000000-0000-7000-8000-00000000000a").expect("a tenant id"),
        );
        self.world
            .artifacts
            .grant(tenant.tenant_id(), &reference.sha256);
        self.world
            .artifacts
            .get(&tenant, reference)
            .await
            .expect("stored output")
    }

    pub async fn text(&self, result: &factory_ports::sandbox::ExecResult) -> (String, String) {
        (
            String::from_utf8_lossy(&self.read(&result.stdout).await).into_owned(),
            String::from_utf8_lossy(&self.read(&result.stderr).await).into_owned(),
        )
    }

    /// Objects of this run that Docker still lists.
    pub fn leftovers(&self) -> Vec<String> {
        let filter = self.scope.label().filter();
        let mut left = Vec::new();
        for args in [
            vec![
                "ps",
                "-a",
                "--filter",
                filter.as_str(),
                "--format",
                "{{.Names}}",
            ],
            vec![
                "network",
                "ls",
                "--filter",
                filter.as_str(),
                "--format",
                "{{.Name}}",
            ],
        ] {
            if let Ok(out) = self.scope.cli().run(&args) {
                left.extend(out.stdout.lines().map(str::to_owned));
            }
        }
        left
    }

    pub fn token_files(&self) -> usize {
        std::fs::read_dir(&self.token_root).map_or(0, Iterator::count)
    }
}
