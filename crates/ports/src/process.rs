//! The process runner port: the one funnel through which the factory starts a host process
//! (ADR 0014 decision 6).
//!
//! The Docker supervisor and the host-side git code both start processes, in different
//! directories of the `sandbox` crate. A shared definition gives them one seam, a closed list of
//! programs, a cleared environment and secrets that stay out of `Debug` output. A test replaces
//! the real runner with a scripted one, so no test starts a real process by accident.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;

use crate::clock::CancelSignal;

/// The programs the factory may start on the host. There is no way to name another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Program {
    /// The Docker command line.
    Docker,
    /// Git.
    Git,
}

impl Program {
    /// The name used in logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Git => "git",
        }
    }
}

/// A value for a process environment. A secret is never shown in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub enum EnvValue {
    /// A value that may appear in logs.
    Plain(String),
    /// A value that must not. Git credentials travel this way, through the environment of the
    /// child only, never through arguments.
    Secret(String),
}

impl fmt::Debug for EnvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(text) => write!(f, "Plain({text:?})"),
            Self::Secret(_) => f.write_str("Secret(<redacted>)"),
        }
    }
}

/// One process to run. The environment of the child is exactly `env` plus a fixed `PATH`: the
/// runner clears everything else, so nothing leaks in from the factory's own environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    /// Which program.
    pub program: Program,
    /// The arguments. No NUL byte in any of them.
    pub args: Vec<String>,
    /// The working directory, an absolute host path, when the program needs one.
    pub cwd: Option<PathBuf>,
    /// The environment, as upper-case names and values.
    pub env: Vec<(String, EnvValue)>,
    /// Bytes for standard input.
    pub stdin: Option<Vec<u8>>,
    /// How long the process may run before it is killed.
    pub timeout: Duration,
    /// How many bytes of each of standard output and standard error are kept.
    pub max_output_bytes: u64,
}

/// What a process did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnOutput {
    /// The exit code, when the process exited by itself.
    pub exit_code: Option<i32>,
    /// The signal that ended it, when it was killed.
    pub signal: Option<i32>,
    /// Standard output, cut at `max_output_bytes`. Not redacted: the caller redacts before it
    /// stores or logs.
    pub stdout: Vec<u8>,
    /// Standard error, cut at `max_output_bytes`. Not redacted.
    pub stderr: Vec<u8>,
    /// True when either stream was cut.
    pub truncated: bool,
}

/// What the adapter was doing when the operating system failed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnStep {
    /// Starting the process.
    Start,
    /// Writing standard input.
    Stdin,
    /// Reading its output.
    Read,
    /// Waiting for it to end.
    Wait,
}

/// Why a process could not be run. A process that ran and exited with a failure is not an error:
/// its exit code is in [`SpawnOutput`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    /// The program is not installed on this host.
    #[error("the program {} is not installed", .0.as_str())]
    ProgramMissing(Program),
    /// The process ran past its timeout and was killed.
    #[error("the process timed out and was killed")]
    Timeout,
    /// The caller cancelled and the process was killed.
    #[error("the process was cancelled and killed")]
    Cancelled,
    /// The operating system failed the call.
    #[error("the operating system failed at {0:?}")]
    Os(SpawnStep),
}

/// Starts host processes. **Only the `sandbox` crate holds one**, and exactly one file in that
/// crate (`process.rs`) contains `std::process` or `tokio::process`; the static check ST-03 is
/// written against that file. The Docker supervisor and the host-side git code both take an
/// `Arc<dyn ProcessRunner>`, so a test replaces the real one with a scripted runner and no test
/// starts a real process by accident.
///
/// # Preconditions
/// Arguments are separate strings; there is no shell. A secret goes in `env`, never in `args`.
///
/// # Postconditions
/// The child is started with a cleared environment, no inherited file descriptors but
/// the three standard streams, and in its own process group. After a timeout or a cancel the
/// whole group is killed before the call returns.
///
/// # Errors
/// [`SpawnError`].
///
/// # Idempotency
/// Not idempotent: each call runs the program again.
///
/// # Cancellation and timeouts
/// Takes a cancel signal and `req.timeout`. Dropping the future kills the process group.
#[async_trait]
pub trait ProcessRunner: Send + Sync {
    /// Says whether this runner starts real processes (`real`) or replays a script (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Runs one process to its end.
    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_list_is_closed_and_each_program_has_a_name() {
        assert_eq!(Program::Docker.as_str(), "docker");
        assert_eq!(Program::Git.as_str(), "git");
    }

    #[test]
    fn a_secret_value_never_shows_in_debug_output() {
        // Built at run time so that no credential-shaped literal sits in the source.
        let secret = format!("{}-{}", "credential", "value");
        let shown = format!("{:?}", EnvValue::Secret(secret.clone()));
        assert!(!shown.contains(&secret), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
        assert_eq!(
            format!("{:?}", EnvValue::Plain("main".to_owned())),
            "Plain(\"main\")"
        );
    }

    #[test]
    fn a_request_does_not_leak_its_secret_through_debug() {
        let secret = format!("{}-{}", "another", "credential");
        let request = SpawnRequest {
            program: Program::Git,
            args: vec!["push".to_owned()],
            cwd: None,
            env: vec![("GIT_TOKEN".to_owned(), EnvValue::Secret(secret.clone()))],
            stdin: None,
            timeout: Duration::from_secs(30),
            max_output_bytes: 1024,
        };
        assert!(!format!("{request:?}").contains(&secret));
    }

    #[test]
    fn the_error_set_names_the_program_and_the_step_and_nothing_else() {
        assert_eq!(
            SpawnError::ProgramMissing(Program::Docker).to_string(),
            "the program docker is not installed"
        );
        assert_eq!(
            SpawnError::Os(SpawnStep::Wait).to_string(),
            "the operating system failed at Wait"
        );
    }
}
