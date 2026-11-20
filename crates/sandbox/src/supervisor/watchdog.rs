//! The watchdog: the supervisor's own enforcement of the two limits Docker does not have.
//!
//! * **Wall clock.** Docker has no run-time limit (`docker run --help` offers `--stop-timeout`
//!   and `--health-timeout` only, experiment E15). At the deadline the watchdog sends
//!   `docker kill`.
//! * **Disk.** `--storage-opt size` is accepted and not enforced on this setup (E11), and the
//!   workspace is a host directory. Every few seconds the watchdog measures `/workspace` and
//!   `/out` with `du` inside the container and kills the container when the total passes the cap.
//!   Measuring inside means this crate reads no host directory: reads of workspace content belong
//!   to the ingestion module (check ST-09). A measurement that fails is never counted as zero and
//!   never as "under the cap". One failed poll is skipped, because the container may be at its
//!   process limit for a moment. [`MAX_UNMEASURED_POLLS`] failed polls in a row, in a container
//!   that is still running, are an unknown size that a process of the sandbox can keep up by
//!   holding the process table full (finding SBX-3, a `docker exec` cannot start a `du` then), so
//!   the container is killed and the attempt ends as a resource failure. The rule fails closed:
//!   a size that cannot be read is treated as one that may be over the cap. A container that is
//!   no longer running ends the watchdog without a verdict of its own.
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
    /// The size of the workspace and output could not be read for [`MAX_UNMEASURED_POLLS`] polls
    /// in a row, so the cap could not be enforced.
    DiskUnmeasured,
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
            Self::Disk | Self::DiskUnmeasured => {
                SandboxError::ResourceExceeded(factory_ports::sandbox::Resource::Disk)
            }
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

/// How many polls in a row may fail to measure the disk, in a container that is still running,
/// before the container is killed. With the default poll of five seconds this is fifteen seconds
/// without a reading: longer than a process table that is full for a moment, shorter than a
/// determined fork loop that is held on purpose.
pub(crate) const MAX_UNMEASURED_POLLS: u32 = 3;

/// True unless Docker says the container is not running. Any other answer, including a failed
/// call, counts as running: a watchdog that cannot tell must not decide the container is gone.
pub(crate) async fn is_running(docker: &DockerClient, container: &str) -> bool {
    let answer = docker
        .run_raw(
            vec![
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{.State.Running}}".to_owned(),
                container.to_owned(),
            ],
            None,
            Duration::from_secs(30),
            4096,
            &NeverCancel,
        )
        .await;
    match answer {
        Ok(output) if output.success() => String::from_utf8_lossy(&output.stdout).trim() != "false",
        _ => true,
    }
}

/// What one poll of the disk decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Poll {
    /// Keep watching.
    Continue,
    /// The container must be killed, for this cause.
    Kill(Stop),
    /// The container is gone; the watchdog has nothing left to do.
    Gone,
}

/// Decides what to do after a poll. `measured` is the size in KiB, or `None` when `du` could not
/// run or its answer was not both paths. `unmeasured` counts the failed polls in a row and is
/// changed here. `running` is only asked when the measurement failed.
pub(crate) async fn judge(
    measured: Option<u64>,
    cap_kib: u64,
    unmeasured: &mut u32,
    running: impl std::future::Future<Output = bool>,
) -> Poll {
    match measured {
        Some(used) => {
            *unmeasured = 0;
            if used > cap_kib {
                Poll::Kill(Stop::Disk)
            } else {
                Poll::Continue
            }
        }
        None => {
            if !running.await {
                return Poll::Gone;
            }
            *unmeasured = unmeasured.saturating_add(1);
            if *unmeasured >= MAX_UNMEASURED_POLLS {
                Poll::Kill(Stop::DiskUnmeasured)
            } else {
                Poll::Continue
            }
        }
    }
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
    /// True once the watchdog's own `docker kill` has returned.
    pub killed_rx: watch::Receiver<bool>,
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
    let (killed_tx, killed_rx) = watch::channel(false);
    let stop_tx: StopSender = Arc::new(tx);
    let shutdown = Arc::new(Notify::new());
    let handle = tokio::spawn({
        let stop_tx = Arc::clone(&stop_tx);
        let shutdown = Arc::clone(&shutdown);
        async move {
            let mut unmeasured: u32 = 0;
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
                        killed_tx.send_replace(true);
                        return;
                    }
                    Either::First(Either::Second(())) => {
                        let measured = disk_usage_kib(&shared.docker, &container).await;
                        let verdict = judge(
                            measured,
                            limits.disk_cap_kib,
                            &mut unmeasured,
                            is_running(&shared.docker, &container),
                        )
                        .await;
                        match verdict {
                            Poll::Continue => {}
                            Poll::Gone => return,
                            Poll::Kill(stop) => {
                                mark(&stop_tx, stop);
                                kill(&shared.docker, &container).await;
                                killed_tx.send_replace(true);
                                return;
                            }
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
        killed_rx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn poll(measured: Option<u64>, cap: u64, unmeasured: &mut u32, running: bool) -> Poll {
        judge(measured, cap, unmeasured, async move { running }).await
    }

    #[tokio::test]
    async fn a_size_over_the_cap_kills_and_a_size_under_it_resets_the_count() {
        let mut unmeasured = 2;
        assert_eq!(
            poll(Some(10), 100, &mut unmeasured, true).await,
            Poll::Continue
        );
        assert_eq!(unmeasured, 0);
        assert_eq!(
            poll(Some(100), 100, &mut unmeasured, true).await,
            Poll::Continue
        );
        assert_eq!(
            poll(Some(101), 100, &mut unmeasured, true).await,
            Poll::Kill(Stop::Disk)
        );
    }

    #[tokio::test]
    async fn failed_measurements_in_a_running_container_kill_after_the_limit_and_never_count_as_zero()
     {
        let mut unmeasured = 0;
        for _ in 1..MAX_UNMEASURED_POLLS {
            assert_eq!(poll(None, 100, &mut unmeasured, true).await, Poll::Continue);
        }
        assert_eq!(
            poll(None, 100, &mut unmeasured, true).await,
            Poll::Kill(Stop::DiskUnmeasured)
        );
        // One good reading in between starts the count again.
        let mut unmeasured = 0;
        poll(None, 100, &mut unmeasured, true).await;
        poll(None, 100, &mut unmeasured, true).await;
        assert_eq!(
            poll(Some(1), 100, &mut unmeasured, true).await,
            Poll::Continue
        );
        assert_eq!(poll(None, 100, &mut unmeasured, true).await, Poll::Continue);
        assert_eq!(unmeasured, 1);
    }

    #[tokio::test]
    async fn a_container_that_is_gone_ends_the_watchdog_without_a_verdict_of_its_own() {
        let mut unmeasured = MAX_UNMEASURED_POLLS - 1;
        assert_eq!(poll(None, 100, &mut unmeasured, false).await, Poll::Gone);
    }

    #[test]
    fn an_unmeasurable_disk_ends_the_attempt_as_a_disk_resource_failure() {
        assert_eq!(
            Stop::DiskUnmeasured.error(),
            SandboxError::ResourceExceeded(factory_ports::sandbox::Resource::Disk)
        );
    }
}
