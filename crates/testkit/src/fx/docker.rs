//! FX-DOCKER: finds out whether Docker is there, and cleans up after a test run.
//!
//! # BLOCKED is not PASSED
//!
//! A test that needs a Docker daemon must not pass when there is none, and must not be skipped
//! without a word. A Rust test has only two outcomes, so the project's convention (the same one
//! `xtask/tests/clippy_bans.rs` uses) is a panic whose message starts with `BLOCKED:` and gives
//! the reason. [`DockerGuard::require_or_block`] does that. [`DockerGuard::run_if_available`] is
//! the form for code that wants to report the state as a value ([`TestStatus`]) instead.
//!
//! The probe is a real command, `docker version`, and it must answer with a server version.
//! A client with no daemon behind it, a daemon that is stopped, and a command that hangs all
//! count as absent.
//!
//! # Cleanup
//!
//! Every container, network, volume and image a test creates must carry the run's label
//! (`factory.test_run=<id>`, from [`DockerGuard::label_args`]). [`DockerScope::cleanup`] lists
//! only objects with exactly that label and removes them: containers first, then networks and
//! volumes and images. It never prunes, never removes by a pattern and never touches an object
//! that lacks the label. It checks that each id it got from `docker` looks like an id before it
//! passes it back. When the scope is dropped it cleans up again, and a leftover fails the test.
//!
//! The sandbox adapter's own janitor is a different thing: it removes containers whose attempt is
//! over. This guard exists so that a *test run* leaves the machine as it found it.

use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::rng::FxRng;

/// The label key every test resource carries.
pub const RUN_LABEL_KEY: &str = "factory.test_run";

/// How long one `docker` command may take before the guard gives up on it.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// The label that ties test resources to one test run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLabel {
    value: String,
}

impl RunLabel {
    /// A label with a unique value.
    #[must_use]
    pub fn unique() -> Self {
        Self {
            value: format!(
                "{}-{:08x}",
                std::process::id(),
                FxRng::from_entropy().next_u64() as u32
            ),
        }
    }

    /// A label with a chosen value. Tests of the guard itself use this to script a daemon.
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self {
            value: value.to_owned(),
        }
    }

    /// The value after the `=`.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// `factory.test_run=<value>`, the form `--label` and `--change LABEL` take.
    #[must_use]
    pub fn assignment(&self) -> String {
        format!("{RUN_LABEL_KEY}={}", self.value)
    }

    /// `label=factory.test_run=<value>`, the form `--filter` takes.
    #[must_use]
    pub fn filter(&self) -> String {
        format!("label={}", self.assignment())
    }
}

/// What a `docker` command printed and returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutput {
    /// The exit code, or `None` when the process was ended by a signal.
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl CliOutput {
    /// True for exit code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Why a `docker` command could not be run to the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// There is no such program.
    NotInstalled,
    /// The program could not be started for another reason.
    Spawn(String),
    /// It did not finish in time and was killed.
    TimedOut(Duration),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::NotInstalled => f.write_str("the docker client is not installed"),
            CliError::Spawn(reason) => {
                write!(f, "the docker client could not be started: {reason}")
            }
            CliError::TimedOut(after) => write!(f, "docker did not answer within {after:?}"),
        }
    }
}

/// How to run the `docker` command line client.
#[derive(Debug, Clone)]
pub struct DockerCli {
    program: OsString,
    timeout: Duration,
}

impl Default for DockerCli {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerCli {
    /// The `docker` on the `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_program("docker")
    }

    /// Another program in place of `docker`: a scripted shim, or a path that does not exist.
    #[must_use]
    pub fn with_program(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Changes how long a command may take.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Runs `docker <args>` with an empty standard input.
    ///
    /// # Errors
    /// [`CliError`] when the program is missing, cannot start, or does not finish in time.
    pub fn run(&self, args: &[&str]) -> Result<CliOutput, CliError> {
        self.run_with_input(args, &[])
    }

    /// Runs `docker <args>` and writes `input` to its standard input.
    ///
    /// # Errors
    /// [`CliError`] as for [`run`](Self::run).
    pub fn run_with_input(&self, args: &[&str], input: &[u8]) -> Result<CliOutput, CliError> {
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => CliError::NotInstalled,
                _ => CliError::Spawn(error.to_string()),
            })?;

        // Write the input and read both outputs on their own threads, so a full pipe cannot
        // stall the child while this thread waits for it to exit.
        let mut stdin = child.stdin.take();
        let input = input.to_vec();
        let writer = thread::spawn(move || {
            if let Some(pipe) = stdin.as_mut() {
                let _ = pipe.write_all(&input);
            }
            drop(stdin);
        });
        let reader = |pipe: Option<Box<dyn Read + Send>>| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                if let Some(mut pipe) = pipe {
                    let _ = pipe.read_to_end(&mut bytes);
                }
                String::from_utf8_lossy(&bytes).into_owned()
            })
        };
        let out_thread = reader(
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        );
        let err_thread = reader(
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        );

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() > self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(CliError::TimedOut(self.timeout));
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => break Err(CliError::Spawn(error.to_string())),
            }
        };
        let _ = writer.join();
        let stdout = out_thread.join().unwrap_or_default();
        let stderr = err_thread.join().unwrap_or_default();
        status.map(|status| CliOutput {
            code: status.code(),
            stdout,
            stderr,
        })
    }
}

/// What the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerStatus {
    /// A daemon answered with its version.
    Available {
        /// The server version, such as `29.9.2`.
        server_version: String,
    },
    /// Docker cannot be used, and why.
    Absent {
        /// A plain-English reason, at most about 200 characters.
        reason: String,
    },
}

/// What a Docker-dependent test reports when the daemon is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    /// Why the test could not run.
    pub reason: String,
}

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BLOCKED: {}", self.reason)
    }
}

impl std::error::Error for Blocked {}

/// The state a Docker-dependent check reports. It has no `Skipped`, on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestStatus {
    /// The check ran and held.
    Passed,
    /// The check could not run, and this is why. It is never a pass.
    Blocked(String),
}

impl TestStatus {
    /// True only for `Passed`.
    #[must_use]
    pub fn is_passed(&self) -> bool {
        matches!(self, TestStatus::Passed)
    }
}

/// Ends the test as BLOCKED: a panic whose message starts with `BLOCKED:`.
///
/// # Panics
/// Always.
pub fn blocked(reason: &str) -> ! {
    panic!("BLOCKED: {reason}")
}

/// Checks for Docker and owns the cleanup of one test run.
#[derive(Debug)]
pub struct DockerGuard {
    cli: DockerCli,
    label: RunLabel,
    status: DockerStatus,
}

impl DockerGuard {
    /// Probes the `docker` on the `PATH`, with a fresh label.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::new(DockerCli::new())
    }

    /// Probes this client, with a fresh label.
    #[must_use]
    pub fn new(cli: DockerCli) -> Self {
        Self::with_label(cli, RunLabel::unique())
    }

    /// Probes this client and uses this label.
    #[must_use]
    pub fn with_label(cli: DockerCli, label: RunLabel) -> Self {
        let status = probe(&cli);
        Self { cli, label, status }
    }

    /// What the probe found.
    #[must_use]
    pub fn status(&self) -> &DockerStatus {
        &self.status
    }

    /// The label this run's resources must carry.
    #[must_use]
    pub fn label(&self) -> &RunLabel {
        &self.label
    }

    /// `["--label", "factory.test_run=<id>"]`, to put on a `create`, `run` or `network create`.
    #[must_use]
    pub fn label_args(&self) -> [String; 2] {
        ["--label".to_owned(), self.label.assignment()]
    }

    /// A scope that cleans up when it ends, or the reason the test is blocked.
    ///
    /// # Errors
    /// [`Blocked`] when no daemon answered.
    pub fn require(&self) -> Result<DockerScope, Blocked> {
        match &self.status {
            DockerStatus::Available { .. } => Ok(DockerScope {
                cli: self.cli.clone(),
                label: self.label.clone(),
            }),
            DockerStatus::Absent { reason } => Err(Blocked {
                reason: reason.clone(),
            }),
        }
    }

    /// Like [`require`](Self::require), and ends the test as BLOCKED when Docker is absent.
    ///
    /// # Panics
    /// Panics with a message that starts with `BLOCKED:` when no daemon answered.
    #[must_use]
    pub fn require_or_block(&self) -> DockerScope {
        match self.require() {
            Ok(scope) => scope,
            Err(why) => blocked(&why.reason),
        }
    }

    /// Runs `test` when Docker is available, and reports `Blocked` without running it when not.
    pub fn run_if_available<F: FnOnce(&DockerScope)>(&self, test: F) -> TestStatus {
        match self.require() {
            Ok(scope) => {
                test(&scope);
                TestStatus::Passed
            }
            Err(why) => TestStatus::Blocked(why.reason),
        }
    }
}

fn probe(cli: &DockerCli) -> DockerStatus {
    let absent = |reason: String| DockerStatus::Absent { reason };
    match cli.run(&["version", "--format", "{{.Server.Version}}"]) {
        Err(error) => absent(error.to_string()),
        Ok(output) if output.success() && !output.stdout.trim().is_empty() => {
            DockerStatus::Available {
                server_version: output.stdout.trim().to_owned(),
            }
        }
        Ok(output) => {
            let said = output
                .stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("no message");
            absent(format!(
                "the docker daemon did not answer: {}",
                said.chars().take(160).collect::<String>()
            ))
        }
    }
}

/// What a cleanup removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Containers removed.
    pub containers: Vec<String>,
    /// Networks removed.
    pub networks: Vec<String>,
    /// Volumes removed.
    pub volumes: Vec<String>,
    /// Images removed.
    pub images: Vec<String>,
}

impl CleanupReport {
    /// True when there was nothing to remove.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
            && self.networks.is_empty()
            && self.volumes.is_empty()
            && self.images.is_empty()
    }
}

/// A run that is allowed to use Docker. It cleans up when it ends.
#[derive(Debug)]
pub struct DockerScope {
    cli: DockerCli,
    label: RunLabel,
}

/// One kind of object the cleanup removes.
struct Kind {
    list: &'static [&'static str],
    remove: &'static [&'static str],
}

const CONTAINERS: Kind = Kind {
    list: &["ps", "-aq"],
    remove: &["rm", "-f", "-v"],
};
const NETWORKS: Kind = Kind {
    list: &["network", "ls", "-q"],
    remove: &["network", "rm"],
};
const VOLUMES: Kind = Kind {
    list: &["volume", "ls", "-q"],
    remove: &["volume", "rm", "-f"],
};
const IMAGES: Kind = Kind {
    list: &["image", "ls", "-q"],
    remove: &["image", "rm", "-f"],
};

impl DockerScope {
    /// The client, for the test to create its resources with.
    #[must_use]
    pub fn cli(&self) -> &DockerCli {
        &self.cli
    }

    /// The run's label.
    #[must_use]
    pub fn label(&self) -> &RunLabel {
        &self.label
    }

    /// `["--label", "factory.test_run=<id>"]`.
    #[must_use]
    pub fn label_args(&self) -> [String; 2] {
        ["--label".to_owned(), self.label.assignment()]
    }

    /// Removes everything that carries this run's label, and checks that it is gone.
    ///
    /// # Errors
    /// A message when a command fails, when `docker` returns something that is not an id, or
    /// when an object with the label is still there afterwards.
    pub fn cleanup(&self) -> Result<CleanupReport, String> {
        // The order matters: a network cannot go while a container is attached to it, and an
        // image cannot go while a container uses it.
        let report = CleanupReport {
            containers: self.remove_all(&CONTAINERS)?,
            networks: self.remove_all(&NETWORKS)?,
            volumes: self.remove_all(&VOLUMES)?,
            images: self.remove_all(&IMAGES)?,
        };
        for (name, kind) in [
            ("container", &CONTAINERS),
            ("network", &NETWORKS),
            ("volume", &VOLUMES),
            ("image", &IMAGES),
        ] {
            let left = self.list(kind)?;
            if !left.is_empty() {
                return Err(format!(
                    "{} {name}(s) with the label {} are still there after cleanup: {}",
                    left.len(),
                    self.label.assignment(),
                    left.join(", ")
                ));
            }
        }
        Ok(report)
    }

    fn list(&self, kind: &Kind) -> Result<Vec<String>, String> {
        let filter = self.label.filter();
        let mut args: Vec<&str> = kind.list.to_vec();
        args.extend(["--filter", &filter]);
        let output = self
            .cli
            .run(&args)
            .map_err(|error| format!("docker {}: {error}", kind.list.join(" ")))?;
        if !output.success() {
            return Err(format!(
                "docker {} failed: {}",
                kind.list.join(" "),
                output.stderr.lines().next().unwrap_or("no message")
            ));
        }
        let ids: Vec<String> = output
            .stdout
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if let Some(bad) = ids.iter().find(|id| !looks_like_an_id(id)) {
            return Err(format!(
                "docker {} returned {bad:?}, which is not an object id; nothing was removed",
                kind.list.join(" ")
            ));
        }
        Ok(ids)
    }

    fn remove_all(&self, kind: &Kind) -> Result<Vec<String>, String> {
        let ids = self.list(kind)?;
        if ids.is_empty() {
            return Ok(ids);
        }
        let mut args: Vec<&str> = kind.remove.to_vec();
        args.extend(ids.iter().map(String::as_str));
        let output = self
            .cli
            .run(&args)
            .map_err(|error| format!("docker {}: {error}", kind.remove.join(" ")))?;
        if output.success() {
            Ok(ids)
        } else {
            Err(format!(
                "docker {} failed: {}",
                kind.remove.join(" "),
                output.stderr.lines().next().unwrap_or("no message")
            ))
        }
    }
}

impl Drop for DockerScope {
    fn drop(&mut self) {
        if let Err(problem) = self.cleanup()
            && !thread::panicking()
        {
            panic!(
                "FX-DOCKER: cleanup of the run label {} failed: {problem}",
                self.label.assignment()
            );
        }
    }
}

/// True for the short or long hexadecimal ids Docker prints for containers, networks and images,
/// and for the plain names it prints for volumes.
fn looks_like_an_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && !text.starts_with(['-', '.'])
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'))
}

#[cfg(test)]
mod tests;
