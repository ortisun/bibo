//! A running sandbox: commands, the wall clock, the disk cap and teardown.

use std::sync::Arc;

use factory_domain::redaction::SecretHandle;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    ExecRequest, ExecResult, PostureReport, ProvisionStage, Resource, SandboxError, SandboxId,
    SandboxSession, TeardownReason, TeardownReport,
};
use tokio::sync::watch;
use tokio::time::Instant;

use super::Shared;
use super::cleanup::Guard;
use super::exec::{REDACTION_MARGIN, exec_args, exit_parts, keep};
use super::watchdog::{self, Stop, Watch};
use crate::container::docker::DockerError;
use crate::container::names::SandboxNames;
use crate::race::{BoxFuture, race};

/// Ends a `docker exec` when the caller cancels or the watchdog has stopped the session.
struct ExecCancel<'a> {
    caller: &'a dyn CancelSignal,
    stopped: watch::Receiver<Option<Stop>>,
}

impl CancelSignal for ExecCancel<'_> {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        self.caller.is_cancelled() || self.stopped.borrow().is_some()
    }

    // The signature `#[async_trait]` would write; see `crate::race`.
    fn cancelled<'life0, 'async_trait>(&'life0 self) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut stopped = self.stopped.clone();
            let _ = race(self.caller.cancelled(), stopped.wait_for(Option::is_some)).await;
        })
    }
}

/// One running sandbox container.
pub struct DockerSession {
    shared: Arc<Shared>,
    id: SandboxId,
    posture: PostureReport,
    names: SandboxNames,
    guard: Guard,
    deadline: Instant,
    watch: Watch,
    secret: Option<SecretHandle>,
}

impl std::fmt::Debug for DockerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerSession")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl DockerSession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        shared: Arc<Shared>,
        id: SandboxId,
        posture: PostureReport,
        names: SandboxNames,
        guard: Guard,
        deadline: Instant,
        watch: Watch,
        secret: Option<SecretHandle>,
    ) -> Self {
        Self {
            shared,
            id,
            posture,
            names,
            guard,
            deadline,
            watch,
            secret,
        }
    }

    fn recorded_stop(&self) -> Option<Stop> {
        *self.watch.stop_rx.borrow()
    }

    /// Fails when the session cannot run a command: it stopped for a recorded reason, or the wall
    /// clock has passed (and the watchdog has not yet got to it).
    async fn ensure_alive(&self) -> Result<(), SandboxError> {
        if let Some(stop) = self.recorded_stop() {
            return Err(stop.error());
        }
        if Instant::now() >= self.deadline {
            watchdog::mark(&self.watch.stop_tx, Stop::WallClock);
            watchdog::kill(&self.shared.docker, &self.names.container).await;
            return Err(Stop::WallClock.error());
        }
        Ok(())
    }

    /// Records `stop` and kills the container: a command that cannot be stopped on its own ends
    /// the session.
    async fn end_session(&self, stop: Stop) {
        watchdog::mark(&self.watch.stop_tx, stop);
        watchdog::kill(&self.shared.docker, &self.names.container).await;
    }

    async fn oom_killed(&self) -> bool {
        self.shared
            .docker
            .inspect(
                "container",
                &self.names.container,
                &crate::container::docker::NeverCancel,
            )
            .await
            .ok()
            .and_then(|document| {
                document
                    .get("State")
                    .and_then(|state| state.get("OOMKilled"))
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false)
    }

    /// The error for a container that is no longer running without a cause the supervisor knows.
    async fn container_gone(&self) -> SandboxError {
        if self.oom_killed().await {
            SandboxError::ResourceExceeded(Resource::Memory)
        } else {
            SandboxError::ProvisionFailed(ProvisionStage::Start)
        }
    }
}

impl Drop for DockerSession {
    fn drop(&mut self) {
        if let Some(handle) = self.secret.take() {
            self.shared.redactor.forget(handle);
        }
    }
}

impl DockerSession {
    async fn run_exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        if cancel.is_cancelled() {
            return Err(SandboxError::Cancelled);
        }
        self.ensure_alive().await?;
        let started_at = self.shared.clock.now();
        let capture_cap = req.max_output_bytes.saturating_add(REDACTION_MARGIN);
        let watched = ExecCancel {
            caller: cancel,
            stopped: self.watch.stop_rx.clone(),
        };
        let outcome = self
            .shared
            .docker
            .run_raw(
                exec_args(&self.names.container, &req),
                req.stdin.clone(),
                req.timeout,
                capture_cap,
                &watched,
            )
            .await;

        let (code, signal, stdout, stderr, timed_out) = match outcome {
            Ok(output) => {
                if let Some(stop) = self.recorded_stop() {
                    return Err(stop.error());
                }
                let Some(code) = output.code else {
                    return Err(SandboxError::DaemonUnavailable);
                };
                if code == 125 {
                    // The client itself failed: the container is not running.
                    return Err(self.container_gone().await);
                }
                let (exit_code, signal) = exit_parts(code);
                (exit_code, signal, output.stdout, output.stderr, false)
            }
            Err(DockerError::Timeout) => {
                // The client was killed, and the command goes on inside the container. The only
                // way to stop it is to stop the container.
                self.end_session(Stop::CommandTimeout).await;
                (None, Some(9), Vec::new(), Vec::new(), true)
            }
            Err(DockerError::Cancelled) => {
                if cancel.is_cancelled() {
                    self.end_session(Stop::Cancelled).await;
                    return Err(SandboxError::Cancelled);
                }
                return Err(self
                    .recorded_stop()
                    .map_or(SandboxError::Cancelled, Stop::error));
            }
            Err(_) => return Err(SandboxError::DaemonUnavailable),
        };

        let oom_killed = signal == Some(9) && !timed_out && self.oom_killed().await;
        let finished_at = self.shared.clock.now();
        let full = |bytes: &Vec<u8>| bytes.len() as u64 >= capture_cap;
        let (out_full, err_full) = (full(&stdout), full(&stderr));
        let stdout = keep(&self.shared, stdout, req.max_output_bytes, out_full).await?;
        let stderr = keep(&self.shared, stderr, req.max_output_bytes, err_full).await?;
        Ok(ExecResult {
            exit_code: code,
            signal,
            timed_out,
            oom_killed,
            stdout: stdout.reference,
            stderr: stderr.reference,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            started_at,
            finished_at,
        })
    }

    async fn teardown(
        mut self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        self.watch.stop();
        let oom_killed = self.oom_killed().await;
        let leaked = self.guard.cleanup(false).await;
        if let Some(handle) = self.secret.take() {
            self.shared.redactor.forget(handle);
        }
        if leaked {
            return Err(SandboxError::TeardownFailed { leaked: true });
        }
        Ok(TeardownReport {
            sandbox: self.id.clone(),
            reason,
            oom_killed,
        })
    }
}

// The signatures below are the ones `#[async_trait]` would write for the port; see `crate::race`.
impl SandboxSession for DockerSession {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn posture(&self) -> &PostureReport {
        &self.posture
    }

    fn exec<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        req: ExecRequest,
        cancel: &'life1 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<ExecResult, SandboxError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.run_exec(req, cancel))
    }

    fn stop_and_remove<'async_trait>(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> BoxFuture<'async_trait, Result<TeardownReport, SandboxError>>
    where
        Self: 'async_trait,
    {
        Box::pin(self.teardown(reason))
    }
}
