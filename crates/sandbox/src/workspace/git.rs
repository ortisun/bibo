//! The one place that builds a `git` command line.
//!
//! Every call gets the same hardening, so a reviewer reads it once:
//!
//! * The configuration comes from `-c` overrides and nothing else. `GIT_CONFIG_NOSYSTEM=1` and
//!   `GIT_CONFIG_GLOBAL=/dev/null` shut the other two files out, and the runner clears the rest of
//!   the environment. Hooks, the file system monitor, attributes files, exclude files, credential
//!   helpers and every transport but one are off.
//! * The repository is named with `--git-dir`, always a store this crate made. No call discovers
//!   a repository, and no call runs with the checkout as its working directory or in its
//!   arguments.
//! * Arguments are separate strings. A path or a name is never spliced into a shell line, because
//!   there is no shell. A secret goes in the environment of the child, never in an argument.
//! * `GIT_TERMINAL_PROMPT=0`: git never waits for a person.
//!
//! The ownership check of git (the directory must belong to the current user) stays on. It is a
//! guard and not an obstacle: the stores are made by this process, so it never trips.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{EnvValue, ProcessRunner, SpawnError, SpawnOutput, SpawnRequest};
use factory_ports::workspace::{GitOperation, WorkspaceError};

use crate::race::BoxFuture;

/// A cancel signal that is never set, for the calls whose port method takes none.
pub(crate) struct NoCancel;

impl CancelSignal for NoCancel {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        false
    }

    fn cancelled<'life0, 'async_trait>(&'life0 self) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::pending())
    }
}

/// The default cap on what git may print for a call that expects a short answer.
pub(crate) const SHORT_OUTPUT: u64 = 1024 * 1024;

/// One git call.
#[derive(Debug, Clone)]
pub(crate) struct Invocation {
    /// The repository, when the subcommand works on one.
    pub git_dir: Option<PathBuf>,
    /// The working directory. Always a host-private directory.
    pub cwd: PathBuf,
    /// The subcommand and its arguments.
    pub args: Vec<String>,
    /// Extra environment, after the fixed one.
    pub env: Vec<(String, EnvValue)>,
    /// Bytes for standard input.
    pub stdin: Option<Vec<u8>>,
    /// The cap on standard output and on standard error.
    pub max_output: u64,
    /// True for a call that talks to the remote, which gets the longer timeout.
    pub network: bool,
}

impl Invocation {
    /// A call on a repository, with the working directory `cwd` and a short output cap.
    pub(crate) fn new(git_dir: &Path, cwd: &Path, args: &[&str]) -> Self {
        Self {
            git_dir: Some(git_dir.to_path_buf()),
            cwd: cwd.to_path_buf(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            env: Vec::new(),
            stdin: None,
            max_output: SHORT_OUTPUT,
            network: false,
        }
    }

    pub(crate) fn with_stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }

    pub(crate) fn with_max_output(mut self, max: u64) -> Self {
        self.max_output = max;
        self
    }

    pub(crate) fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env
            .push((name.to_owned(), EnvValue::Plain(value.to_owned())));
        self
    }

    pub(crate) fn over_network(mut self) -> Self {
        self.network = true;
        self
    }
}

/// Runs git through the process runner.
#[derive(Clone)]
pub(crate) struct Git {
    runner: Arc<dyn ProcessRunner>,
    protocol: &'static str,
    local_timeout: Duration,
    network_timeout: Duration,
}

impl std::fmt::Debug for Git {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Git")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

/// The configuration every call carries. Each pair is passed as `-c key=value`.
fn hardening(protocol: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.attributesFile", "/dev/null"),
        ("core.excludesFile", "/dev/null"),
        ("core.autocrlf", "false"),
        ("core.quotePath", "false"),
        ("core.symlinks", "true"),
        ("core.protectNTFS", "true"),
        ("core.protectHFS", "true"),
        ("credential.helper", ""),
        ("protocol.allow", "never"),
        ("transfer.fsckObjects", "true"),
        ("gc.auto", "0"),
        ("maintenance.auto", "false"),
        ("submodule.recurse", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("push.recurseSubmodules", "no"),
        ("http.followRedirects", "false"),
        ("commit.gpgSign", "false"),
        ("tag.gpgSign", "false"),
        ("advice.detachedHead", "false"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    pairs.push((format!("protocol.{protocol}.allow"), "always".to_owned()));
    pairs
}

impl Git {
    pub(crate) fn new(
        runner: Arc<dyn ProcessRunner>,
        protocol: &'static str,
        local_timeout: Duration,
        network_timeout: Duration,
    ) -> Self {
        Self {
            runner,
            protocol,
            local_timeout,
            network_timeout,
        }
    }

    /// The fixed environment of every call.
    fn environment(&self) -> Vec<(String, EnvValue)> {
        let plain = |name: &str, value: &str| (name.to_owned(), EnvValue::Plain(value.to_owned()));
        vec![
            plain("GIT_CONFIG_NOSYSTEM", "1"),
            plain("GIT_CONFIG_GLOBAL", "/dev/null"),
            plain("GIT_ATTR_NOSYSTEM", "1"),
            plain("GIT_TERMINAL_PROMPT", "0"),
            plain("GIT_OPTIONAL_LOCKS", "0"),
            plain("GIT_ALLOW_PROTOCOL", self.protocol),
            plain("GIT_PAGER", "cat"),
            plain("LC_ALL", "C"),
        ]
    }

    /// The full argument list of a call: the hardening, the repository, then the subcommand.
    fn arguments(&self, inv: &Invocation) -> Vec<String> {
        let mut args = Vec::new();
        for (key, value) in hardening(self.protocol) {
            args.push("-c".to_owned());
            args.push(format!("{key}={value}"));
        }
        args.push("--no-optional-locks".to_owned());
        args.push("--literal-pathspecs".to_owned());
        if let Some(dir) = &inv.git_dir {
            args.push(format!("--git-dir={}", dir.display()));
        }
        args.extend(inv.args.iter().cloned());
        args
    }

    /// Runs one call and returns what git did, whatever its exit code was.
    pub(crate) async fn run(
        &self,
        operation: GitOperation,
        inv: Invocation,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, WorkspaceError> {
        let mut env = self.environment();
        env.extend(inv.env.iter().cloned());
        let request = SpawnRequest {
            program: factory_ports::process::Program::Git,
            args: self.arguments(&inv),
            cwd: Some(inv.cwd.clone()),
            env,
            stdin: inv.stdin.clone(),
            timeout: if inv.network {
                self.network_timeout
            } else {
                self.local_timeout
            },
            max_output_bytes: inv.max_output,
        };
        self.runner
            .run(request, cancel)
            .await
            .map_err(|error| spawn_failed(operation, &error))
    }

    /// Runs one call that must exit with 0 and must not have its output cut.
    pub(crate) async fn run_ok(
        &self,
        operation: GitOperation,
        inv: Invocation,
        cancel: &dyn CancelSignal,
    ) -> Result<Vec<u8>, WorkspaceError> {
        let output = self.run(operation, inv, cancel).await?;
        if output.exit_code != Some(0) {
            return Err(WorkspaceError::Git {
                operation,
                exit: output.exit_code,
            });
        }
        if output.truncated {
            return Err(WorkspaceError::TooLarge);
        }
        Ok(output.stdout)
    }
}

fn spawn_failed(operation: GitOperation, error: &SpawnError) -> WorkspaceError {
    match error {
        SpawnError::Timeout => WorkspaceError::Timeout,
        SpawnError::Cancelled => WorkspaceError::Cancelled,
        SpawnError::ProgramMissing(_) | SpawnError::Os(_) => WorkspaceError::Git {
            operation,
            exit: None,
        },
    }
}

/// The environment entries that give git a credential for an `https` remote: an
/// `Authorization` header through `GIT_CONFIG_COUNT`. The value is a secret, so it is never shown
/// in `Debug` output, and it never reaches an argument.
pub(crate) fn credential_env(secret: &str) -> Vec<(String, EnvValue)> {
    let header = format!(
        "Authorization: Basic {}",
        base64(format!("x-access-token:{secret}").as_bytes())
    );
    vec![
        (
            "GIT_CONFIG_COUNT".to_owned(),
            EnvValue::Plain("1".to_owned()),
        ),
        (
            "GIT_CONFIG_KEY_0".to_owned(),
            EnvValue::Plain("http.extraHeader".to_owned()),
        ),
        ("GIT_CONFIG_VALUE_0".to_owned(), EnvValue::Secret(header)),
    ]
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let symbol = |shift: u32| TABLE[((n >> shift) & 0x3f) as usize] as char;
        out.push(symbol(18));
        out.push(symbol(12));
        out.push(if chunk.len() > 1 { symbol(6) } else { '=' });
        out.push(if chunk.len() > 2 { symbol(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn the_credential_travels_in_the_environment_and_is_redacted_in_debug_output() {
        let secret = format!("{}-{}", "unit", "secret");
        let env = credential_env(&secret);
        let shown = format!("{env:?}");
        assert!(!shown.contains(&secret), "{shown}");
        assert!(
            env.iter().any(|(name, value)| name == "GIT_CONFIG_VALUE_0"
                && matches!(value, EnvValue::Secret(_)))
        );
    }

    #[test]
    fn every_call_names_the_hardening_and_never_a_shell_or_a_wildcard_owner() {
        let git = Git::new(
            Arc::new(crate::SystemProcessRunner::new()),
            "file",
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let inv = Invocation::new(Path::new("/tmp/store.git"), Path::new("/tmp"), &["status"]);
        let args = git.arguments(&inv);
        let has = |pair: &str| args.windows(2).any(|w| w[0] == "-c" && w[1] == pair);
        assert!(has("core.hooksPath=/dev/null"));
        assert!(has("core.fsmonitor=false"));
        assert!(has("protocol.file.allow=always"));
        assert!(has("protocol.allow=never"));
        assert!(args.iter().all(|a| !a.contains("safe.")));
        assert_eq!(args.last().map(String::as_str), Some("status"));
        let env = git.environment();
        let value = |name: &str| {
            env.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| format!("{v:?}"))
        };
        assert_eq!(
            value("GIT_CONFIG_NOSYSTEM").as_deref(),
            Some("Plain(\"1\")")
        );
        assert_eq!(
            value("GIT_CONFIG_GLOBAL").as_deref(),
            Some("Plain(\"/dev/null\")")
        );
    }
}
