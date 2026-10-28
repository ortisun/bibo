//! The watchdog: the supervisor's own enforcement of the two limits Docker does not have.
//!
//! * **Wall clock.** Docker has no run-time limit (`docker run --help` offers `--stop-timeout`
//!   and `--health-timeout` only, experiment E15). At the deadline the watchdog sends
//!   `docker kill`.
//! * **Disk.** `--storage-opt size` is accepted and not enforced on this setup (E11), and the
//!   workspace is a host directory. Every few seconds the watchdog measures `/workspace` and
//!   `/out` with `du` inside the container and kills the container when the total passes the cap.
//!   Measuring inside means this crate reads no host directory: reads of workspace content belong
//!   to the ingestion module (check ST-09). A measurement that fails (the container is at its
//!   process limit, or already dead) is skipped, not counted as zero.
//!
//! The first cause to be recorded wins, and the session reads it back to tell the caller why.

use std::sync::Arc;
use std::time::Duration;

use factory_ports::sandbox::{OUT_TARGET, SandboxError, WORKSPACE_TARGET};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::Shared;
use crate::container::docker::{DockerClient, NeverCancel};
use crate::race::{Either, race};

/// Why a session cannot run any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The wall clock passed.
    WallClock,
    /// The workspace and output grew past their cap.
    Disk,
    /// A command passed its timeout, so the container was killed.
    CommandTimeout,
    /// The caller cancelled a command, so the container was killed.
    Cancelled,
}

impl Stop {
    /// The error a caller gets for a session that stopped for this reason.
    pub fn error(self) -> SandboxError {
        match self {
            Self::WallClock | Self::CommandTimeout => SandboxError::Timeout,
            Self::Disk => SandboxError::ResourceExceeded(factory_ports::sandbox::Resource::Disk),
            Self::Cancelled => SandboxError::Cancelled,
        }
    }
}

/// The shared record of why a session stopped.
pub(crate) type StopSender = Arc<watch::Sender<Option<Stop>>>;

/// Records `stop` unless an earlier cause is already recorded.
pub(crate) fn mark(sender: &StopSender, stop: Stop) {
    sender.send_if_modified(|current| {
        if current.is_none() {
            *current = Some(stop);
            true
        } else {
            false
        }
    });
}

/// Kills the container with SIGKILL. Failures are ignored: a container that is already gone is
/// the goal, and teardown removes whatever is left.
pub(crate) async fn kill(docker: &DockerClient, container: &str) {
    let _ = docker
        .run(vec!["kill".to_owned(), container.to_owned()], &NeverCancel)
        .await;
}

/// The size of `/workspace` and `/out` together, in KiB, measured inside the container. `None`
/// when the measurement could not be made.
pub(crate) async fn disk_usage_kib(docker: &DockerClient, container: &str) -> Option<u64> {
    let output = docker
        .run_raw(
            vec![
                "exec".to_owned(),
                container.to_owned(),
                "du".to_owned(),
                "-s".to_owned(),
                "-k".to_owned(),
                WORKSPACE_TARGET.to_owned(),
                OUT_TARGET.to_owned(),
            ],
            None,
            Duration::from_secs(30),
            64 * 1024,
            &NeverCancel,
        )
        .await
        .ok()?;
    // `du` prints a total for each path it could read and exits non-zero for one it could not.
    // A line is `<kib>\t<path>`; the paths are the two asked for.
    let text = String::from_utf8_lossy(&output.stdout);
    let sizes: Vec<u64> = text
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(_, path)| *path == WORKSPACE_TARGET || *path == OUT_TARGET)
        .filter_map(|(kib, _)| kib.trim().parse().ok())
        .collect();
    (sizes.len() == 2).then(|| sizes.iter().sum())
}

/// A running watchdog. Dropping it stops the task.
pub(crate) struct Watch {
    handle: JoinHandle<()>,
    shutdown: Arc<Notify>,
    pub stop_tx: StopSender,
    pub stop_rx: watch::Receiver<Option<Stop>>,
}

impl Watch {
    /// Ends the watchdog task. The container is not touched.
    pub fn stop(&self) {
        self.shutdown.notify_one();
        self.handle.abort();
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// What the watchdog enforces.
#[derive(Debug, Clone)]
pub(crate) struct Limits {
    pub deadline: Instant,
    pub disk_cap_kib: u64,
    pub poll_interval: Duration,
}

/// Starts the watchdog for `container`.
pub(crate) fn spawn(shared: Arc<Shared>, container: String, limits: Limits) -> Watch {
    let (tx, rx) = watch::channel(None);
    let stop_tx: StopSender = Arc::new(tx);
    let shutdown = Arc::new(Notify::new());
    let handle = tokio::spawn({
        let stop_tx = Arc::clone(&stop_tx);
        let shutdown = Arc::clone(&shutdown);
        async move {
            loop {
                let step = race(
                    race(
                        tokio::time::sleep_until(limits.deadline),
                        tokio::time::sleep(limits.poll_interval),
                    ),
                    shutdown.notified(),
                )
                .await;
                match step {
                    Either::First(Either::First(())) => {
                        mark(&stop_tx, Stop::WallClock);
                        kill(&shared.docker, &container).await;
                        return;
                    }
                    Either::First(Either::Second(())) => {
                        let measured = disk_usage_kib(&shared.docker, &container).await;
                        if measured.is_some_and(|used| used > limits.disk_cap_kib) {
                            mark(&stop_tx, Stop::Disk);
                            kill(&shared.docker, &container).await;
                            return;
                        }
                    }
                    Either::Second(()) => return,
                }
            }
        }
    });
    Watch {
        handle,
        shutdown,
        stop_tx,
        stop_rx: rx,
    }
}
