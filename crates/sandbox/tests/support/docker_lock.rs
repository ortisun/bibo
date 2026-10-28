//! One lock for every real-Docker test that makes a network, shared by the sandbox and runtime
//! test targets (the runtime includes this file with `#[path]`, so both use the same lock file).
//!
//! # Why
//!
//! Docker hands every user-defined network an address block from a small default pool, and a
//! development machine with a few compose stacks has used most of it. Two tests that make
//! networks at the same moment, in threads of one `cargo test` process or in separate
//! processes (`cargo nextest`, a second checkout, an agent running the suite next to you), can
//! fail with `ProvisionFailed(Network)` or with a name that is already in use. So everything
//! that makes a network holds this lock for as long as it lives.
//!
//! # How
//!
//! * **Across processes:** an exclusive lock on one file in the system temporary directory. The
//!   path does not depend on the checkout or on `target/`, so runs from different working trees
//!   and different crates exclude each other. The holder writes its process id and thread name
//!   into the file, so a waiter can say who it is waiting for.
//! * **Inside one process:** a table of the paths this process holds, so two threads exclude
//!   each other without relying on how the operating system treats two file handles of one
//!   process.
//! * **Never a hang:** a taker waits at most [`WAIT_LIMIT`] and then fails with a message that
//!   starts `BLOCKED:` ([`WaitedTooLong`]), the convention of the security harness.
//! * **A hard limit on the holder:** a watchdog ends a test that holds the lock for more than
//!   [`HOLD_LIMIT`]. It removes only the objects that carry the lab's own label and exits the
//!   process with a message, so one stuck test cannot keep the machine's lock for ever.
//!
//! # The one error that is retried
//!
//! When the pool is full, `docker network create` says so and nothing else is wrong; a moment
//! later, after another run has removed its networks, the same command works.
//! [`is_network_pool_exhausted`] recognises exactly those messages, and
//! [`retry_while_pool_exhausted`] retries only on them, with the waits of [`BACKOFF`]. Any other
//! failure (a name in use, a refused connection, an overlapping subnet) is returned at once.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use factory_testkit::fx::docker::{DockerCli, DockerGuard, RunLabel};

/// How long a taker waits for the lock before it gives up. Long enough for a whole suite in
/// another process to hand the lock from test to test; short enough that a stuck holder is a
/// failure and not an afternoon.
pub const WAIT_LIMIT: Duration = Duration::from_secs(15 * 60);

/// How long one test may hold the lock. The slowest real-Docker test takes well under a minute
/// when it does not wait; this is several times that.
pub const HOLD_LIMIT: Duration = Duration::from_secs(5 * 60);

/// The waits between the tries of a `network create` that finds the pool full. After the last one
/// the error is returned as it is.
pub const BACKOFF: [Duration; 6] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// The exit code of a process that the watchdog ended (the code `timeout(1)` uses).
const HARD_STOP_EXIT_CODE: i32 = 124;

/// The lock file every real-Docker test target uses.
pub fn default_lock_path() -> PathBuf {
    std::env::temp_dir().join("factory-docker-network.lock")
}

/// The paths this process holds, and the thread that holds each. Checked before the file, so
/// threads exclude each other, and a thread that asks twice is told at once.
static HELD_BY_THIS_PROCESS: Mutex<BTreeMap<PathBuf, ThreadId>> = Mutex::new(BTreeMap::new());

/// A taker gave up. Its text starts `BLOCKED:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitedTooLong {
    path: PathBuf,
    waited: Duration,
    holder: String,
    problem: Option<String>,
}

impl std::fmt::Display for WaitedTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.problem {
            Some(problem) => write!(
                f,
                "BLOCKED: cannot use the Docker lock {} ({problem}); the real-Docker tests need it",
                self.path.display()
            ),
            None => write!(
                f,
                "BLOCKED: waited {} s for the Docker lock {} and did not get it. Another run is using the Docker network pool ({}). Wait for it, or remove the file when no test run is alive",
                self.waited.as_secs(),
                self.path.display(),
                self.holder
            ),
        }
    }
}

impl std::error::Error for WaitedTooLong {}

/// What the watchdog shares with the thread that holds the lock.
#[derive(Default)]
struct Shared {
    /// True once the holder has let go.
    released: Mutex<bool>,
    wake: Condvar,
    /// The label of the lab's objects, set once the lab knows it.
    label: Mutex<Option<String>>,
}

/// The right to use the Docker network pool. Dropping it hands the pool on.
pub struct DockerLock {
    path: PathBuf,
    /// Unlocks when closed.
    _file: File,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for DockerLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn held_by_this_process() -> std::sync::MutexGuard<'static, BTreeMap<PathBuf, ThreadId>> {
    HELD_BY_THIS_PROCESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn who_is_holding(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "holder unknown".to_owned())
}

impl DockerLock {
    /// Takes the machine-wide lock and starts the watchdog with [`HOLD_LIMIT`].
    ///
    /// # Panics
    /// With a message that starts `BLOCKED:` when the lock is not free within [`WAIT_LIMIT`].
    #[must_use]
    pub fn take() -> Self {
        let lock = Self::acquire_at(&default_lock_path(), WAIT_LIMIT)
            .unwrap_or_else(|refused| panic!("{refused}"));
        lock.start_watchdog(HOLD_LIMIT, hard_stop);
        lock
    }

    /// Takes the lock at `path`, waiting at most `wait`.
    ///
    /// # Errors
    /// [`WaitedTooLong`] when the lock was not free in time, or when the file cannot be used.
    pub fn acquire_at(path: &Path, wait: Duration) -> Result<Self, WaitedTooLong> {
        let started = Instant::now();
        let refuse = |problem: Option<String>| WaitedTooLong {
            path: path.to_path_buf(),
            waited: started.elapsed(),
            holder: who_is_holding(path),
            problem,
        };
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| refuse(Some(error.to_string())))?;
        let mut pause = Duration::from_millis(20);
        loop {
            if Self::try_once(path, &file).map_err(|error| refuse(Some(error)))? {
                break;
            }
            if started.elapsed() >= wait {
                return Err(refuse(None));
            }
            thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_millis(250));
        }
        let mut file = file;
        let _ = file.set_len(0);
        let _ = write!(
            file,
            "pid {} thread {} since {:?}",
            std::process::id(),
            thread::current().name().unwrap_or("unnamed"),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        Ok(Self {
            path: path.to_path_buf(),
            _file: file,
            shared: Arc::new(Shared::default()),
        })
    }

    /// One try at both layers. `Ok(true)` when this thread now holds the lock.
    fn try_once(path: &Path, file: &File) -> Result<bool, String> {
        let mut held = held_by_this_process();
        match held.get(path) {
            Some(owner) if *owner == thread::current().id() => {
                return Err("this thread already holds it, and waiting for itself would never end; drop the first lab before making the second".to_owned());
            }
            Some(_) => return Ok(false),
            None => {}
        }
        match file.try_lock() {
            Ok(()) => {
                held.insert(path.to_path_buf(), thread::current().id());
                Ok(true)
            }
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error.to_string()),
        }
    }

    /// Records the label that the lab's Docker objects carry, so that the hard stop removes
    /// those and nothing else.
    pub fn register_label(&self, label: &str) {
        *self
            .shared
            .label
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(label.to_owned());
    }

    /// Ends the test with `on_expiry` if the lock is still held after `limit`. The action gets
    /// the registered label. It runs once, on a thread of its own, and the thread ends at once
    /// when the lock is dropped first.
    pub fn start_watchdog<F>(&self, limit: Duration, on_expiry: F)
    where
        F: FnOnce(Option<String>) + Send + 'static,
    {
        let shared = Arc::clone(&self.shared);
        let spawned = thread::Builder::new()
            .name("docker-lock-watchdog".to_owned())
            .spawn(move || {
                let released = shared
                    .released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (released, _) = shared
                    .wake
                    .wait_timeout_while(released, limit, |released| !*released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *released {
                    return;
                }
                drop(released);
                let label = shared
                    .label
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                on_expiry(label);
            });
        // A watchdog that cannot start leaves the test without a hard limit, not without a lock.
        if let Err(error) = spawned {
            let _ = writeln!(
                std::io::stderr(),
                "the Docker lock watchdog could not start: {error}"
            );
        }
    }
}

impl Drop for DockerLock {
    fn drop(&mut self) {
        held_by_this_process().remove(&self.path);
        *self
            .shared
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.shared.wake.notify_all();
        // The file closes after this, and with it the cross-process lock.
    }
}

/// The action of the watchdog in a real run: say what happened, remove what carries the lab's
/// label, and end the process.
fn hard_stop(label: Option<String>) {
    // Written to the real standard error: the test harness captures `eprintln!` and this process
    // is about to exit, so a captured message would never be seen.
    let say = |line: String| {
        let _ = writeln!(std::io::stderr(), "{line}");
    };
    say(format!(
        "TIMEOUT: a real-Docker test held the Docker lock for more than {} s. Removing the objects labelled {} and ending the test process with code {HARD_STOP_EXIT_CODE}.",
        HOLD_LIMIT.as_secs(),
        label.as_deref().unwrap_or("(no label was registered)")
    ));
    if let Some(value) = label {
        match DockerGuard::with_label(DockerCli::new(), RunLabel::new(&value)).require() {
            Ok(scope) => match scope.cleanup() {
                Ok(report) => say(format!("TIMEOUT: removed {report:?}")),
                Err(why) => say(format!("TIMEOUT: cleanup was not complete: {why}")),
            },
            Err(why) => say(format!("TIMEOUT: cleanup was not possible: {why}")),
        }
    }
    std::process::exit(HARD_STOP_EXIT_CODE);
}

/// True for the messages Docker gives when it has no address block left for a new network, and
/// for nothing else. Matching is not case-sensitive.
///
/// The two spellings are those of Docker Engine (`all predefined address pools have been fully
/// subnetted`) and of the older libnetwork (`could not find an available, non-overlapping IPv4
/// address pool among the defaults`). A subnet that clashes with a given one ("Pool overlaps
/// with other one on this address space") is a different, permanent error and is not matched.
#[must_use]
pub fn is_network_pool_exhausted(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.contains("address pools have been fully subnetted")
        || text.contains("non-overlapping ipv4 address pool")
        || text.contains("non-overlapping ipv6 address pool")
}

/// Runs `attempt` again, after the next wait of [`BACKOFF`], for as long as `pool_exhausted`
/// says its result is the full-pool error. Any other result, and the result of the last try, is
/// returned as it is. `sleep` is how the caller waits.
pub fn retry_while_pool_exhausted<T>(
    mut attempt: impl FnMut() -> T,
    pool_exhausted: impl Fn(&T) -> bool,
    mut sleep: impl FnMut(Duration),
) -> T {
    for wait in BACKOFF {
        let result = attempt();
        if !pool_exhausted(&result) {
            return result;
        }
        sleep(wait);
    }
    attempt()
}
