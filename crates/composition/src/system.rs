//! The real clock, the real identifier source, the real `Ticker` and the process-wide shutdown
//! signal: the four ports that only a composition root can implement (the inner crates may not
//! read the time, make an identifier or sleep, rules DEP-05 and ADR 0011).

use std::fs::File;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{CancelSignal, Clock, IdGenerator, Uuid};
use factory_workflow::scheduler::Ticker;
use tokio::sync::watch;

/// The system time, to the microsecond. Fidelity `real`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn now(&self) -> Timestamp {
        Timestamp::from_utc(time::OffsetDateTime::now_utc())
    }
}

/// Random version 4 identifiers from the operating system's random source (`/dev/urandom`).
///
/// The `uuid` crate's generator features are off in this workspace (the DEP-05 resolved-feature
/// rule keeps them away from the inner crates, which share the one `uuid`), so the bytes come from
/// the operating system and `Builder::from_random_bytes` sets the version and variant bits. The
/// file is opened once. A read that fails is a defect of the host and stops the process: an
/// identifier that repeats would corrupt the store, and no caller can recover from it.
#[derive(Debug)]
pub struct RandomIds {
    source: Mutex<File>,
}

impl RandomIds {
    /// Opens the random source.
    ///
    /// # Errors
    /// The I/O error when `/dev/urandom` cannot be opened.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            source: Mutex::new(File::open("/dev/urandom")?),
        })
    }
}

impl IdGenerator for RandomIds {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn new_uuid(&self) -> Uuid {
        let mut bytes = [0_u8; 16];
        let mut source = self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        source
            .read_exact(&mut bytes)
            .expect("the operating system random source can be read");
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    }
}

/// Waits with the tokio timer. Fidelity `real`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioTicker;

#[async_trait]
impl Ticker for TokioTicker {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// The process-wide stop request: set once by SIGTERM, SIGINT or a test, observed by the loop and
/// by every sandbox call that takes a `CancelSignal`.
#[derive(Debug, Clone)]
pub struct Shutdown {
    sender: std::sync::Arc<watch::Sender<bool>>,
    receiver: watch::Receiver<bool>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    /// A signal that has not been raised.
    #[must_use]
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self {
            sender: std::sync::Arc::new(sender),
            receiver,
        }
    }

    /// Raises the signal. Idempotent.
    pub fn raise(&self) {
        self.sender.send_replace(true);
    }

    /// True once raised.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Completes when the signal is raised, at once if it already was.
    pub async fn raised(&self) {
        let mut receiver = self.receiver.clone();
        // An error means every sender is gone, which `Shutdown` never allows: it holds one.
        let _ = receiver.wait_for(|raised| *raised).await;
    }
}

#[async_trait]
impl CancelSignal for Shutdown {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        self.is_raised()
    }

    async fn cancelled(&self) {
        self.raised().await;
    }
}

/// Completes when the process receives SIGTERM or SIGINT, then raises `shutdown`.
///
/// Returns at once, with the signal already raised, when the handlers cannot be installed: a
/// process that cannot be stopped cleanly must not start work (the caller checks
/// [`Shutdown::is_raised`] after installing).
pub async fn raise_on_termination(shutdown: Shutdown) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        tracing::error!("the termination signal handlers could not be installed");
        shutdown.raise();
        return;
    };
    tokio::select! {
        _ = term.recv() => tracing::info!(signal = "SIGTERM", "stop requested"),
        _ = int.recv() => tracing::info!(signal = "SIGINT", "stop requested"),
    }
    shutdown.raise();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_version_four_and_do_not_repeat() {
        let ids = RandomIds::new().expect("the random source opens");
        let first = ids.new_uuid();
        let second = ids.new_uuid();
        assert_ne!(first, second);
        assert_eq!(first.get_version_num(), 4);
        assert_eq!(ids.fidelity(), Fidelity::Real);
    }

    #[test]
    fn the_clock_moves_forward_and_is_real() {
        let clock = SystemClock;
        let (a, b) = (clock.now(), clock.now());
        assert!(a <= b);
        assert_eq!(clock.fidelity(), Fidelity::Real);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_ticker_sleeps_for_the_duration() {
        let started = tokio::time::Instant::now();
        TokioTicker.sleep(Duration::from_secs(5)).await;
        assert!(started.elapsed() >= Duration::from_secs(5));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raising_the_signal_wakes_a_waiter_and_stays_raised() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_cancelled());
        let waiter = shutdown.clone();
        let task = tokio::spawn(async move { waiter.cancelled().await });
        tokio::task::yield_now().await;
        shutdown.raise();
        task.await.expect("the waiter finishes");
        assert!(shutdown.is_cancelled());
        // A late waiter returns at once.
        shutdown.cancelled().await;
    }
}
