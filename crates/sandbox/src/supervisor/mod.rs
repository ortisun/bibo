//! The Docker supervisor: [`DockerSandboxProvider`] implements [`SandboxProvider`] and its
//! sessions implement [`SandboxSession`] (ports-v1.1, ADR 0003, sandbox-policy.md section 9).
//!
//! # Lifecycle of one sandbox
//!
//! 1. **Authorize.** The spec is checked against the policy with the pure
//!    [`SandboxSpec::validate`]. Nothing is created for a spec that fails.
//! 2. **Images.** The spec's image must be one the catalog (`images.json`) lists for the profile,
//!    ready to run, and already on the host. Images are never pulled.
//! 3. **Prepare.** For a profile with a network: the per-job `--internal` network and the egress
//!    sidecar (refused while the sidecar image is a skeleton). For an `agent`: the token file.
//! 4. **Create, inspect, compare.** `docker create` with the allow-list arguments, then
//!    `docker inspect`, then the pure [`PostureReport::differences`]. Any difference removes the
//!    container and fails closed. The container has not started.
//! 5. **Start and self-check.** `docker start`, then `cat /proc/self/status` inside it; the
//!    workload is not released unless `Seccomp: 2`, `NoNewPrivs: 1`, empty capability sets and the
//!    right user hold.
//! 6. **Run.** Each command is a `docker exec`. A watchdog task enforces the wall clock and the
//!    disk cap, which Docker enforces neither of, by killing the container.
//! 7. **Tear down.** `stop_and_remove` removes the container, the sidecar, the network and the
//!    token file, on every path. A drop guard does the same if a future is dropped, and
//!    [`SandboxProvider::sweep_orphans`] is the backstop after a crash.
//!
//! # Limits of this adapter
//!
//! * Docker cannot signal one `exec`'d process, and the images carry no helper that could. A
//!   command that passes its timeout, or whose caller cancels, therefore ends by killing the
//!   container: the session is over, and every later call reports why.
//! * The disk cap is polled (`du` inside the container, every few seconds). A fast writer can
//!   overshoot it between polls, which `max_file_mb` and the headroom of the host bound.
//! * Output is cut and then redacted from a capture a little larger than the cap, so that a
//!   secret that straddles the cap is still found. A secret that straddles the end of the larger
//!   capture could leave a prefix in the stored text.

mod cleanup;
mod exec;
mod janitor;
mod provision;
mod session;
mod watchdog;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use factory_domain::ids::AttemptId;
use factory_domain::redaction::Redactor;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock, IdGenerator};
use factory_ports::process::ProcessRunner;
use factory_ports::sandbox::{
    SandboxError, SandboxId, SandboxPolicy, SandboxProvider, SandboxSession, SandboxSpec,
};
use tokio::sync::OnceCell;

use crate::container::docker::{DockerClient, DockerError, DockerSettings};
use crate::container::images::ImageCatalog;
use crate::container::token::TokenStore;
use crate::race::BoxFuture;

pub use session::DockerSession;

/// How the watchdog polls.
#[derive(Debug, Clone)]
pub struct WatchdogSettings {
    /// How often the disk is measured (`sandbox.watchdog.disk_poll_interval_s`).
    pub disk_poll_interval: Duration,
}

impl Default for WatchdogSettings {
    fn default() -> Self {
        Self {
            disk_poll_interval: Duration::from_secs(5),
        }
    }
}

/// Everything the provider is configured with. The numbers come from `policies/security.yaml`
/// through the policy; this crate holds none.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// What every sandbox must satisfy.
    pub policy: SandboxPolicy,
    /// The text of `infra/sandbox-images/images.json`.
    pub images_json: String,
    /// The daemon platform (`linux/arm64`). `None` asks the daemon.
    pub platform: Option<String>,
    /// Where token files are written. A tmpfs on a Linux host.
    pub token_root: PathBuf,
    /// The host directory behind each named cache.
    pub caches: Vec<(String, PathBuf)>,
    /// Labels added to every object this provider creates, and used to find them again. The
    /// janitor touches only objects that carry all of them.
    pub owner_labels: Vec<(String, String)>,
    /// Arguments for the egress sidecar's program.
    pub sidecar_command: Vec<String>,
    /// How control commands are run.
    pub docker: DockerSettings,
    /// How the watchdog polls.
    pub watchdog: WatchdogSettings,
}

/// What the provider shares with its sessions.
pub(crate) struct Shared {
    pub docker: DockerClient,
    pub config: ProviderConfig,
    pub artifacts: Arc<dyn ArtifactStore>,
    pub redactor: Arc<Redactor>,
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdGenerator>,
    pub tokens: TokenStore,
    catalog: OnceCell<ImageCatalog>,
    /// Removals that a drop guard started in the background and that have not finished.
    pub background_cleanups: AtomicUsize,
}

impl Shared {
    /// The image catalog for the daemon's platform. The first call asks the daemon, so a stopped
    /// daemon is found here, before anything is created.
    pub async fn catalog(&self, cancel: &dyn CancelSignal) -> Result<&ImageCatalog, SandboxError> {
        self.catalog
            .get_or_try_init(|| async {
                let platform = match &self.config.platform {
                    Some(platform) => platform.clone(),
                    None => self
                        .docker
                        .server_platform(cancel)
                        .await
                        .map_err(daemon_error)?,
                };
                ImageCatalog::from_json(&self.config.images_json, &platform)
                    .map_err(|_| SandboxError::ImageUnavailable)
            })
            .await
    }
}

/// A docker failure outside provisioning: the daemon or the cancel, or nothing that fits.
pub(crate) fn daemon_error(error: DockerError) -> SandboxError {
    match error {
        DockerError::Cancelled => SandboxError::Cancelled,
        _ => SandboxError::DaemonUnavailable,
    }
}

/// Makes sandboxes with Docker containers.
pub struct DockerSandboxProvider {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for DockerSandboxProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerSandboxProvider")
            .finish_non_exhaustive()
    }
}

impl DockerSandboxProvider {
    /// A provider that reaches Docker through `runner`.
    ///
    /// `artifacts` stores command output after `redactor` has cleaned it. `clock` and `ids`
    /// supply the times and the random part of the names.
    #[must_use]
    pub fn new(
        config: ProviderConfig,
        runner: Arc<dyn ProcessRunner>,
        artifacts: Arc<dyn ArtifactStore>,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        let docker = DockerClient::new(runner, config.docker.clone(), Arc::clone(&redactor));
        let tokens = TokenStore::new(config.token_root.clone());
        Self {
            shared: Arc::new(Shared {
                docker,
                config,
                artifacts,
                redactor,
                clock,
                ids,
                tokens,
                catalog: OnceCell::new(),
                background_cleanups: AtomicUsize::new(0),
            }),
        }
    }

    /// Waits until every removal that a dropped session or a dropped `create_verified` future
    /// started in the background has finished. A worker calls this before it exits, and a test
    /// calls it before it looks at Docker.
    pub async fn finish_background_cleanups(&self) {
        while self.shared.background_cleanups.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

// The signatures below are the ones `#[async_trait]` would write for the port; see `crate::race`.
impl SandboxProvider for DockerSandboxProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn create_verified<'life0, 'life1, 'async_trait>(
        &'life0 self,
        spec: SandboxSpec,
        cancel: &'life1 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<Box<dyn SandboxSession>, SandboxError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            provision::create_verified(&self.shared, spec, cancel)
                .await
                .map(|session| Box::new(session) as Box<dyn SandboxSession>)
        })
    }

    fn sweep_orphans<'life0, 'life1, 'async_trait>(
        &'life0 self,
        live: &'life1 [AttemptId],
    ) -> BoxFuture<'async_trait, Result<Vec<SandboxId>, SandboxError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { janitor::sweep(&self.shared, live).await })
    }
}
