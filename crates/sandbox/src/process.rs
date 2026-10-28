//! The one file of this crate that starts a host process (rule DEP-10, check ST-03).
//!
//! [`SystemProcessRunner`] implements the [`ProcessRunner`] port. Everything else in the crate,
//! the Docker supervisor and the host-side git code, takes an `Arc<dyn ProcessRunner>` and so
//! reaches the operating system only through here.
//!
//! What a call does, in the order it does it:
//!
//! 1. A cancel that is already set returns `Cancelled` before any process exists.
//! 2. An argument or an environment value with a NUL byte is refused (`Os(Start)`).
//! 3. The child starts with a **cleared environment**: only the names in the request and one
//!    fixed `PATH`. A `PATH` in the request is ignored. It runs in its own process group, with
//!    the three standard streams and no other inherited descriptor, and with no shell between
//!    this file and the program.
//! 4. Standard input is written on its own task and closed. Standard output and standard error are
//!    each read on their own task and kept up to `max_output_bytes`; the rest is read and thrown
//!    away so the child is never blocked on a full pipe.
//! 5. The call ends when the child exits, when `timeout` passes, or when the cancel signal is
//!    set. After a timeout or a cancel the **whole process group is killed before the call
//!    returns**. Dropping the future kills the group too.
//!
//! The program paths are configurable ([`SystemProcessRunner::with_programs`]) so that the
//! spawn recorder of the security harness can put a shim in front of `docker`.

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{
    EnvValue, ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest, SpawnStep,
};
use rustix::process::{Pid, Signal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::race::{BoxFuture, Either, race};

/// The `PATH` every child gets when the runner is not configured with another one.
pub const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// How long the runner waits for the pipes to close after the child itself has exited. A
/// grandchild that kept a pipe open would otherwise hold the call until the timeout.
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Starts real host processes.
#[derive(Debug, Clone)]
pub struct SystemProcessRunner {
    docker: PathBuf,
    git: PathBuf,
    path: String,
}

impl Default for SystemProcessRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemProcessRunner {
    /// `docker` and `git` found on [`DEFAULT_PATH`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            docker: PathBuf::from("docker"),
            git: PathBuf::from("git"),
            path: DEFAULT_PATH.to_owned(),
        }
    }

    /// Runs these executables for [`Program::Docker`] and [`Program::Git`]. A recorder shim goes
    /// here in a test; a production host may name an absolute path.
    #[must_use]
    pub fn with_programs(mut self, docker: PathBuf, git: PathBuf) -> Self {
        self.docker = docker;
        self.git = git;
        self
    }

    /// Replaces the fixed `PATH` of every child.
    #[must_use]
    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    fn executable(&self, program: Program) -> &PathBuf {
        match program {
            Program::Docker => &self.docker,
            Program::Git => &self.git,
        }
    }
}

/// Kills a process group when dropped, unless it was disarmed after the child was reaped.
struct GroupGuard(Option<Pid>);

impl GroupGuard {
    fn kill(&self) {
        if let Some(pid) = self.0 {
            // The group may already be empty (ESRCH). Nothing else can be done about a failure.
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// What a reader task returns: the kept bytes and whether more was read than kept.
type Captured = (Vec<u8>, bool);

async fn capture<R: AsyncReadExt + Unpin>(mut pipe: R, cap: usize) -> Captured {
    let mut kept = Vec::new();
    let mut cut = false;
    let mut chunk = [0_u8; 8192];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let room = cap.saturating_sub(kept.len());
                if read > room {
                    cut = true;
                }
                kept.extend_from_slice(&chunk[..read.min(room)]);
            }
        }
    }
    (kept, cut)
}

fn has_nul(request: &SpawnRequest) -> bool {
    request.args.iter().any(|a| a.contains('\0'))
        || request.env.iter().any(|(name, value)| {
            name.contains('\0')
                || match value {
                    EnvValue::Plain(text) | EnvValue::Secret(text) => text.contains('\0'),
                }
        })
}

fn exit_parts(status: ExitStatus) -> (Option<i32>, Option<i32>) {
    match status.code() {
        Some(code) => (Some(code), None),
        None => (None, status.signal()),
    }
}

impl ProcessRunner for SystemProcessRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    // The signature `#[async_trait]` would write; see `crate::race`.
    fn run<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: SpawnRequest,
        cancel: &'life1 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<SpawnOutput, SpawnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.run_process(req, cancel))
    }
}

impl SystemProcessRunner {
    #[allow(
        clippy::disallowed_methods,
        reason = "this is the one place in the crate that starts a process (DEP-10, ST-03)"
    )]
    async fn run_process(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        if cancel.is_cancelled() {
            return Err(SpawnError::Cancelled);
        }
        if has_nul(&req) {
            return Err(SpawnError::Os(SpawnStep::Start));
        }

        let mut command = Command::new(self.executable(req.program));
        command
            .args(&req.args)
            .env_clear()
            .env("PATH", &self.path)
            .stdin(if req.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        for (name, value) in &req.env {
            if name == "PATH" {
                continue;
            }
            match value {
                EnvValue::Plain(text) | EnvValue::Secret(text) => {
                    command.env(name, text);
                }
            }
        }
        if let Some(cwd) = &req.cwd {
            command.current_dir(cwd);
        }

        let mut child = command.spawn().map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => SpawnError::ProgramMissing(req.program),
            _ => SpawnError::Os(SpawnStep::Start),
        })?;
        let mut group = GroupGuard(
            child
                .id()
                .and_then(|id| i32::try_from(id).ok())
                .and_then(Pid::from_raw),
        );

        let cap = usize::try_from(req.max_output_bytes).unwrap_or(usize::MAX);
        let stdout = child.stdout.take().ok_or(SpawnError::Os(SpawnStep::Read))?;
        let stderr = child.stderr.take().ok_or(SpawnError::Os(SpawnStep::Read))?;
        let out_task = tokio::spawn(capture(stdout, cap));
        let err_task = tokio::spawn(capture(stderr, cap));
        let in_task = child.stdin.take().map(|mut pipe| {
            let bytes = req.stdin.clone().unwrap_or_default();
            tokio::spawn(async move {
                // A child that exits before reading everything closes the pipe: not an error.
                let _ = pipe.write_all(&bytes).await;
                let _ = pipe.shutdown().await;
            })
        });

        let outcome = match race(
            race(child.wait(), tokio::time::sleep(req.timeout)),
            cancel.cancelled(),
        )
        .await
        {
            Either::First(Either::First(status)) => Outcome::Exited(status),
            Either::First(Either::Second(())) => Outcome::TimedOut,
            Either::Second(()) => Outcome::Cancelled,
        };

        match outcome {
            Outcome::Exited(status) => {
                group.disarm();
                let status = status.map_err(|_| SpawnError::Os(SpawnStep::Wait))?;
                if let Some(task) = in_task {
                    task.abort();
                }
                let joined = tokio::time::timeout(PIPE_DRAIN_GRACE, async {
                    let out = out_task.await.unwrap_or_default();
                    let err = err_task.await.unwrap_or_default();
                    (out, err)
                })
                .await;
                let ((stdout, cut_out), (stderr, cut_err)) =
                    joined.map_err(|_| SpawnError::Os(SpawnStep::Read))?;
                let (exit_code, signal) = exit_parts(status);
                Ok(SpawnOutput {
                    exit_code,
                    signal,
                    stdout,
                    stderr,
                    truncated: cut_out || cut_err,
                })
            }
            stopped @ (Outcome::TimedOut | Outcome::Cancelled) => {
                // The child has not been reaped, so its process group id is still ours.
                group.kill();
                let _ = child.wait().await;
                group.disarm();
                out_task.abort();
                err_task.abort();
                if let Some(task) = in_task {
                    task.abort();
                }
                Err(if matches!(stopped, Outcome::TimedOut) {
                    SpawnError::Timeout
                } else {
                    SpawnError::Cancelled
                })
            }
        }
    }
}

enum Outcome {
    Exited(io::Result<ExitStatus>),
    TimedOut,
    Cancelled,
}
